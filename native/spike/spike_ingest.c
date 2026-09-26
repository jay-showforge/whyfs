// Native ingestion feasibility spike (diagnostic, not the product path).
//
// Consumes the production whyfs BPF ring buffer (map fd inherited from the process
// that loaded the programs) with libbpf, on the same 50 ms drain cadence as the
// Python collector (the kernel submits without wakeups; see wf_wake()).
//
//   spike_ingest --fd N --mode discard|min --workspace DIR --db PATH --run-id ID
//
//   discard  consume and count records only (floor for any consumer)
//   min      decode hdr_t, file-object -> path map, workspace filter, and persist
//            open/io/exec records plus one process upsert per exec to SQLite in one
//            transaction per drain cycle (WAL, synchronous=NORMAL, like production).
//            NOT the full whyfs semantics: the lower bound for a native pipeline.
//
// On SIGTERM/SIGINT: final drain, commit, then one JSON stats line on stdout.
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define PATH_N 512
enum { EV_OPEN = 1, EV_READ = 2, EV_WRITE = 3, EV_RENAME = 4, EV_UNLINK = 5, EV_EXEC = 6, EV_FORK = 7,
       EV_EXIT = 8, EV_MMAP_READ = 9, EV_CHDIR = 13, EV_FCHDIR = 14, EV_MMAP_WRITE = 15 };

struct hdr_t {  // must match BPF_SOURCE in src/whyfs/ebpf_bcc.py
    uint64_t ts_ns, file, file2;
    uint32_t tgid, tid, aux_pid, type;
    int32_t fd, dirfd, dirfd2;
    uint32_t flags, truncated, ino;
    char comm[16];
};
_Static_assert(sizeof(struct hdr_t) == 80, "hdr_t layout");

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

// ---- file object -> path map (open addressing, u64 keys) ----
#define FM_BITS 20
#define FM_SIZE (1u << FM_BITS)
static uint64_t fm_key[FM_SIZE];
static char *fm_val[FM_SIZE];
static uint32_t fm_count;
static uint32_t fm_slot(uint64_t k) { k ^= k >> 33; k *= 0xff51afd7ed558ccdULL; k ^= k >> 33; return (uint32_t)k & (FM_SIZE - 1); }
static void fm_put(uint64_t k, const char *v) {
    if (fm_count > FM_SIZE / 2) {  // bounded: reset (spike simplification)
        for (uint32_t i = 0; i < FM_SIZE; i++) { free(fm_val[i]); fm_val[i] = 0; fm_key[i] = 0; }
        fm_count = 0;
    }
    uint32_t i = fm_slot(k);
    while (fm_key[i] && fm_key[i] != k) i = (i + 1) & (FM_SIZE - 1);
    if (!fm_key[i]) fm_count++;
    fm_key[i] = k;
    free(fm_val[i]);
    fm_val[i] = strdup(v);
}
static const char *fm_get(uint64_t k) {
    uint32_t i = fm_slot(k);
    while (fm_key[i]) { if (fm_key[i] == k) return fm_val[i]; i = (i + 1) & (FM_SIZE - 1); }
    return 0;
}
static void fm_del(uint64_t k) {  // tombstone-free: overwrite value with empty marker
    uint32_t i = fm_slot(k);
    while (fm_key[i]) { if (fm_key[i] == k) { free(fm_val[i]); fm_val[i] = 0; return; } i = (i + 1) & (FM_SIZE - 1); }
}

// ---- state ----
static int mode_min;
static char ws[4096];
static size_t ws_len;
static const char *run_id;
static int64_t clock_off;
static sqlite3 *db;
static sqlite3_stmt *st_ev, *st_proc;
static int in_tx;
static uint64_t n_received, n_filtered, n_stored, n_tx, tx_ns;

static int within_ws(const char *p) { return !strncmp(p, ws, ws_len) && (p[ws_len] == '/' || p[ws_len] == 0); }

static void tx_begin(void) { if (!in_tx) { sqlite3_exec(db, "BEGIN", 0, 0, 0); in_tx = 1; } }

static void store_event(uint64_t ts, uint32_t pid, const char *kind, const char *path, int r, int w, uint32_t flags,
                        const char *api) {
    tx_begin();
    sqlite3_bind_text(st_ev, 1, run_id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st_ev, 2, (int64_t)ts);
    sqlite3_bind_int64(st_ev, 3, pid);
    sqlite3_bind_text(st_ev, 4, kind, -1, SQLITE_STATIC);
    sqlite3_bind_text(st_ev, 5, path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st_ev, 6, r);
    sqlite3_bind_int(st_ev, 7, w);
    sqlite3_bind_int64(st_ev, 8, flags);
    sqlite3_bind_text(st_ev, 9, api, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st_ev, 10, pid);
    sqlite3_step(st_ev);
    sqlite3_reset(st_ev);
    n_stored++;
}

static int handle(void *ctx, void *data, size_t size) {
    (void)ctx;
    n_received++;
    if (!mode_min || size < sizeof(struct hdr_t)) return 0;
    const struct hdr_t *e = data;
    const char *path = size >= sizeof(*e) + 1 ? (const char *)data + sizeof(*e) : "";
    uint64_t ts = e->ts_ns + clock_off;
    switch (e->type) {
    case EV_OPEN: {
        if (e->truncated || path[0] != '/') { fm_del(e->file); n_filtered++; return 0; }
        char p[PATH_N + 1];
        memcpy(p, path, PATH_N); p[PATH_N] = 0;
        int is_dir = e->fd == 1;
        if (is_dir || within_ws(p)) fm_put(e->file, p); else fm_del(e->file);
        if (is_dir || !within_ws(p)) { n_filtered++; return 0; }
        store_event(ts, e->tgid, "open", p, 0, 0, e->flags, "ebpf:open");
        return 0;
    }
    case EV_READ: case EV_WRITE: case EV_MMAP_READ: case EV_MMAP_WRITE: {
        const char *p = fm_get(e->file);
        if (!p || !within_ws(p)) { n_filtered++; return 0; }
        int w = e->type == EV_WRITE || e->type == EV_MMAP_WRITE;
        store_event(ts, e->tgid, "io", p, !w, w, 0, e->type >= EV_MMAP_READ ? "ebpf:mmap" : "ebpf:rw");
        return 0;
    }
    case EV_EXEC: {
        char argv[PATH_N + 1];
        int n = e->fd > 0 && e->fd < PATH_N ? e->fd : 0;
        memcpy(argv, (const char *)data + sizeof(*e) + PATH_N, n);
        for (int i = 0; i < n; i++) if (!argv[i]) argv[i] = ' ';
        argv[n] = 0;
        char exe[PATH_N + 1];
        memcpy(exe, path, PATH_N); exe[PATH_N] = 0;
        tx_begin();
        sqlite3_bind_text(st_proc, 1, run_id, -1, SQLITE_STATIC);
        sqlite3_bind_int64(st_proc, 2, e->tgid);
        sqlite3_bind_int64(st_proc, 3, e->aux_pid);
        sqlite3_bind_text(st_proc, 4, exe, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st_proc, 5, argv, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st_proc, 6, (int64_t)ts);
        sqlite3_step(st_proc);
        sqlite3_reset(st_proc);
        store_event(ts, e->tgid, "exec", exe, 0, 0, 0, "ebpf:exec");
        return 0;
    }
    default:
        n_filtered++;
        return 0;
    }
}

static uint64_t now_ns(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec; }

static void commit(void) {
    if (!in_tx) return;
    uint64_t t0 = now_ns();
    sqlite3_exec(db, "COMMIT", 0, 0, 0);
    tx_ns += now_ns() - t0;
    in_tx = 0;
    n_tx++;
}

int main(int argc, char **argv) {
    int fd = -1;
    const char *mode = "discard", *dbp = 0;
    run_id = "spike";
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--fd")) fd = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--mode")) mode = argv[i + 1];
        else if (!strcmp(argv[i], "--workspace")) { snprintf(ws, sizeof ws, "%s", argv[i + 1]); ws_len = strlen(ws); }
        else if (!strcmp(argv[i], "--db")) dbp = argv[i + 1];
        else if (!strcmp(argv[i], "--run-id")) run_id = argv[i + 1];
    }
    if (fd < 0) { fprintf(stderr, "--fd required\n"); return 2; }
    mode_min = !strcmp(mode, "min");
    struct timespec rt, mt;
    clock_gettime(CLOCK_REALTIME, &rt); clock_gettime(CLOCK_MONOTONIC, &mt);
    clock_off = ((int64_t)rt.tv_sec * 1000000000LL + rt.tv_nsec) - ((int64_t)mt.tv_sec * 1000000000LL + mt.tv_nsec);
    if (mode_min) {
        if (!dbp || sqlite3_open(dbp, &db) != SQLITE_OK) { fprintf(stderr, "db open failed\n"); return 2; }
        sqlite3_exec(db,
                     "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"
                     "CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, run_id TEXT, ts_ns INTEGER, pid INTEGER, kind TEXT,"
                     " path TEXT, is_read INTEGER, is_write INTEGER, flags INTEGER, api TEXT, source TEXT DEFAULT 'ebpf', os_pid INTEGER);"
                     "CREATE INDEX IF NOT EXISTS events_path ON events(path, ts_ns);"
                     "CREATE INDEX IF NOT EXISTS events_pid ON events(run_id,pid,ts_ns);"
                     "CREATE TABLE IF NOT EXISTS processes(run_id TEXT, pid INTEGER, ppid INTEGER, exe TEXT, command TEXT,"
                     " first_seen_ns INTEGER, PRIMARY KEY(run_id,pid));",
                     0, 0, 0);
        sqlite3_prepare_v2(db, "INSERT INTO events(run_id,ts_ns,pid,kind,path,is_read,is_write,flags,api,os_pid) VALUES(?,?,?,?,?,?,?,?,?,?)",
                           -1, &st_ev, 0);
        sqlite3_prepare_v2(db, "INSERT INTO processes(run_id,pid,ppid,exe,command,first_seen_ns) VALUES(?,?,?,?,?,?)"
                               " ON CONFLICT(run_id,pid) DO UPDATE SET exe=excluded.exe, command=excluded.command",
                           -1, &st_proc, 0);
    }
    struct ring_buffer *rb = ring_buffer__new(fd, handle, 0, 0);
    if (!rb) { fprintf(stderr, "ring_buffer__new failed: %s\n", strerror(errno)); return 2; }
    signal(SIGTERM, on_sig);
    signal(SIGINT, on_sig);
    printf("{\"ready\":true}\n");
    fflush(stdout);
    while (!stop) {
        ring_buffer__poll(rb, 50);
        ring_buffer__consume(rb);
        commit();
    }
    ring_buffer__consume(rb);
    commit();
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("{\"received\":%llu,\"filtered\":%llu,\"stored\":%llu,\"transactions\":%llu,\"commit_ms\":%.3f,"
           "\"user_s\":%.3f,\"sys_s\":%.3f,\"vol_ctx\":%ld,\"invol_ctx\":%ld,\"minflt\":%ld}\n",
           (unsigned long long)n_received, (unsigned long long)n_filtered, (unsigned long long)n_stored,
           (unsigned long long)n_tx, tx_ns / 1e6, ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6,
           ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6, ru.ru_nvcsw, ru.ru_nivcsw, ru.ru_minflt);
    ring_buffer__free(rb);
    if (db) { sqlite3_finalize(st_ev); sqlite3_finalize(st_proc); sqlite3_close(db); }
    return 0;
}
