// macOS Endpoint Security frontend of whyfs-collect.  Built only with -DWHYFS_MACOS and
// #included by whyfs-collect.c, so it feeds the one shared event model (process_event) and
// the shared SQLite writer; nothing of the model is copied here.
//
//   Endpoint Security NOTIFY events -> normalized message (mmsg_t) -> event records in the
//   format the Linux kernel side produces (hdr_t + paths) -> process_event -> writer -> SQLite
//
// The normalized message is the replay boundary.  `--es-record FILE` writes every live message
// as one JSON line; `--es-replay FILE` feeds such lines through the same translation.  Tests use
// hand-written streams and live captures.  A replay is never a live Endpoint Security test.
//
// macOS semantics (docs/MACOS.md):
//   exec, fork, exit, chdir   program image, ancestry (fork: child and parent), cwd (exec)
//   open                      opened with read access = a read, "es:open-read": Endpoint
//                             Security reports opens, not individual reads
//   close, modified set       a write at close time, "es:close-modified"
//   mmap                      a read; MAP_SHARED + PROT_WRITE also a write, "es:mmap"
//   rename, unlink            "es:rename", "es:unlink"
//   clone, copyfile           source read, destination written, "es:clone" / "es:copyfile"
// File identity: "mac:DEV:INO" from the stat Endpoint Security attaches to each file (APFS has
// no inode generation: st_gen is 0).  Lost events: gaps in the message's global sequence number.
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

#define MAC_FREAD 0x0001  // kernel open flags (fflag): FREAD

// ---------------------------------------------------------------- normalized message
typedef struct { const char *path; uint64_t dev, ino; uint32_t mode; int has_stat, truncated; } mfile_t;
typedef struct { uint32_t pid, pidver, ppid, ruid, euid; const char *exe; int64_t start_ns; int valid; } mproc_t;
enum { M_EXEC = 1, M_FORK, M_EXIT, M_OPEN, M_CLOSE, M_RENAME, M_UNLINK, M_MMAP, M_CHDIR, M_CLONE, M_COPYFILE, M_N };
static const char *M_NAME[M_N] = {"", "exec", "fork", "exit", "open", "close", "rename", "unlink", "mmap", "chdir",
                                  "clone", "copyfile"};
typedef struct {
    int type;
    int64_t ts;                      // wall clock, ns
    int has_gseq; uint64_t gseq;     // global sequence number (message version >= 4)
    mproc_t proc, target;            // target: exec's new image, fork's child
    mfile_t f1, f2;                  // f1: the file (source of rename/clone/copyfile); f2: an existing destination
    const char *dst_dir, *dst_name;  // a new destination (rename/clone/copyfile)
    int fflag, modified, prot, mflags;
    char **argv; size_t argc;        // exec
    const char *cwd;                 // exec (message version >= 3)
} mmsg_t;

static int mac_mode;                 // --es or --es-replay given
static int mac_live;                 // live Endpoint Security (libproc may fill what messages lack)
static const char *mac_replay_path;
static FILE *mac_record_fp;
static size_t mac_queue_limit = 65536;
static uint64_t mac_gseq;
static int mac_have_gseq;
static uint64_t mac_by_type[M_N];

static int mac_arg(const char *a, const char *v, int *i) {
    if (!strcmp(a, "--es")) { mac_mode = 1; mac_live = 1; return 1; }
    if (!strcmp(a, "--es-replay") && v) { mac_mode = 1; mac_replay_path = v; (*i)++; return 1; }
    if (!strcmp(a, "--es-record") && v) {
        mac_record_fp = fopen(v, "wx");
        if (!mac_record_fp) die("es-record %s: %s", v, strerror(errno));
        (*i)++;
        return 1;
    }
    if (!strcmp(a, "--es-queue") && v) { mac_queue_limit = (size_t)atol(v); (*i)++; return 1; }
    return 0;
}

// ---------------------------------------------------------------- process facts (no /proc on macOS)
typedef struct { char *exe; int64_t start_ns; uint32_t ruid, pidver; } mfact_t;
static void mfact_free(void *p) { mfact_t *f = p; if (!f) return; free(f->exe); free(f); }
static map_t mfacts;  // pid -> latest facts carried by Endpoint Security messages

static void mac_note(const mproc_t *p) {
    if (!p->valid || !p->pid) return;
    mfact_t *f = calloc(1, sizeof *f);
    f->exe = xstrdup(p->exe); f->start_ns = p->start_ns; f->ruid = p->ruid; f->pidver = p->pidver;
    map_set(&mfacts, p->pid, NULL, f);
}
static char *mac_proc_link(uint32_t pid, const char *item) {
    if (!strcmp(item, "exe")) {
        mfact_t *f = map_get(&mfacts, pid, NULL);
        if (f && f->exe) return xstrdup(f->exe);
        if (!mac_live) return NULL;
        char buf[PROC_PIDPATHINFO_MAXSIZE];
        return proc_pidpath((int)pid, buf, sizeof buf) > 0 ? xstrdup(buf) : NULL;
    }
    if (!strcmp(item, "cwd") && mac_live) {  // messages carry the cwd only at exec
        struct proc_vnodepathinfo vpi;
        if (proc_pidinfo((int)pid, PROC_PIDVNODEPATHINFO, 0, &vpi, sizeof vpi) == (int)sizeof vpi && vpi.pvi_cdir.vip_path[0])
            return xstrdup(vpi.pvi_cdir.vip_path);
    }
    return NULL;
}
static size_t mac_proc_cmdline(uint32_t pid, char ***out) {
    *out = NULL;
    if (!mac_live) return 0;
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, (int)pid};
    size_t sz = 0;
    if (sysctl(mib, 3, NULL, &sz, NULL, 0) || sz < sizeof(int)) return 0;
    char *b = xmalloc(sz);
    if (sysctl(mib, 3, b, &sz, NULL, 0) || sz < sizeof(int)) { free(b); return 0; }
    int argc; memcpy(&argc, b, sizeof argc);
    size_t i = sizeof argc;
    while (i < sz && b[i]) i++;   // the executable path
    while (i < sz && !b[i]) i++;  // its padding
    size_t start = i;
    for (int k = 0; k < argc && i < sz; k++) { while (i < sz && b[i]) i++; i++; }
    if (i > sz) i = sz;
    size_t n = split_argv((const unsigned char *)b + start, i - start, out);
    free(b);
    return n;
}
static int64_t mac_proc_start_ns(uint32_t pid) {
    mfact_t *f = map_get(&mfacts, pid, NULL);
    if (f && f->start_ns) return f->start_ns;
    if (!mac_live) return 0;
    struct proc_bsdinfo bi;
    if (proc_pidinfo((int)pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi) != (int)sizeof bi) return 0;
    return (int64_t)bi.pbi_start_tvsec * 1000000000LL + (int64_t)bi.pbi_start_tvusec * 1000LL;
}
static char *mac_proc_user(uint32_t pid) {
    char u[32];
    mfact_t *f = map_get(&mfacts, pid, NULL);
    if (f) { snprintf(u, sizeof u, "uid:%u", f->ruid); return xstrdup(u); }
    if (!mac_live) return NULL;
    struct proc_bsdinfo bi;
    if (proc_pidinfo((int)pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi) != (int)sizeof bi) return NULL;
    snprintf(u, sizeof u, "uid:%u", bi.pbi_ruid);
    return xstrdup(u);
}
static void mac_file_id(const struct hdr_t *e) {
    if (!e->file2) { map_pop(&fidm, e->file, NULL); return; }  // identity not known (never a guess)
    char id[64];
    snprintf(id, sizeof id, "mac:%u:%llu", (uint32_t)e->dirfd2, (unsigned long long)e->file2);
    map_put(&fidm, e->file, NULL, xstrdup(id));
}

// ---------------------------------------------------------------- translation into the event model
#define MREC (sizeof(struct hdr_t) + 2 * PATH_N)
static unsigned char mrec[MREC];

static void mhdr(struct hdr_t *h, uint32_t pid, uint32_t type, int64_t ts) {
    memset(h, 0, sizeof *h);
    h->ts_ns = (uint64_t)ts; h->tgid = pid; h->tid = pid; h->type = type;
    h->fd = -1; h->dirfd = AT_FDCWD_VALUE; h->dirfd2 = AT_FDCWD_VALUE;
}
static void mcopy(struct hdr_t *h, size_t off, const char *p) {
    if (!p) return;
    size_t n = strlen(p);
    if (n > PATH_N - 1) { n = PATH_N - 1; h->truncated |= 1; }
    memcpy(mrec + off, p, n);
}
static void mput(struct hdr_t *h, const char *p1, const char *p2, const unsigned char *raw2, size_t raw2n) {
    memset(mrec + sizeof *h, 0, 2 * PATH_N);
    mcopy(h, OFF_PATH, p1);
    mcopy(h, OFF_PATH2, p2);
    if (raw2) memcpy(mrec + OFF_PATH2, raw2, raw2n);
    memcpy(mrec, h, sizeof *h);
    process_event(NULL, mrec, MREC);
}
// Per process instance and file: the model's "open file" key (Linux: the kernel file pointer).
static uint64_t mac_fkey(const mproc_t *p, const mfile_t *f) {
    uint64_t k = f->ino ? mix64(f->ino ^ mix64((uint64_t)(uint32_t)f->dev)) : mix64(hstr(f->path ? f->path : ""));
    k ^= mix64(((uint64_t)p->pid << 32) | p->pidver);
    return k ? k : 1;
}
static uint64_t mac_open(const mmsg_t *m, const mfile_t *f, int fflag) {
    struct hdr_t h;
    uint64_t k = mac_fkey(&m->proc, f);
    mhdr(&h, m->proc.pid, EV_OPEN, m->ts);
    h.file = k; h.flags = (uint32_t)fflag;
    h.fd = (f->has_stat && S_ISDIR(f->mode)) ? 1 : 0;
    h.dirfd2 = (int32_t)(uint32_t)f->dev; h.file2 = f->ino; h.dirfd = 0;
    h.truncated = f->truncated ? 1 : 0;
    mput(&h, f->path, NULL, NULL, 0);
    return k;
}
static void mac_io(const mmsg_t *m, uint64_t k, uint32_t type, const char *api, const char *api_dt) {
    struct hdr_t h;
    mhdr(&h, m->proc.pid, type, m->ts);
    h.file = k;
    mac_io_api = api; mac_io_api_dt = api_dt;
    mput(&h, NULL, NULL, NULL, 0);
    mac_io_api = mac_io_api_dt = NULL;
}
static char *mac_dst(const mmsg_t *m) {  // the destination path of rename/clone/copyfile
    if (m->f2.path) return xstrdup(m->f2.path);
    if (m->dst_dir && m->dst_name) return pjoin(m->dst_dir, m->dst_name);
    return NULL;
}
static void mac_handle(const mmsg_t *m) {
    if (m->type <= 0 || m->type >= M_N) return;
    mac_by_type[m->type]++;
    if (m->has_gseq) {  // Endpoint Security numbers every message it sends this client: a gap is loss
        if (mac_have_gseq && m->gseq > mac_gseq + 1) st.kernel_drops += m->gseq - mac_gseq - 1;
        if (!mac_have_gseq || m->gseq > mac_gseq) mac_gseq = m->gseq;
        mac_have_gseq = 1;
    }
    mac_note(&m->proc);
    struct hdr_t h;
    uint32_t pid = m->proc.pid;
    switch (m->type) {
    case M_EXEC: {
        mac_note(&m->target);
        if (m->cwd && *m->cwd) { mhdr(&h, pid, EV_CHDIR, m->ts); mput(&h, m->cwd, NULL, NULL, 0); }
        unsigned char raw[PATH_N];  // argv, NUL-separated, bounded like the kernel side's copy
        size_t n = 0;
        for (size_t i = 0; i < m->argc && n < PATH_N - 1; i++) {
            size_t l = strlen(m->argv[i]);
            if (l > PATH_N - 1 - n) l = PATH_N - 1 - n;
            memcpy(raw + n, m->argv[i], l); n += l;
            if (n < PATH_N - 1) raw[n++] = 0;
        }
        mhdr(&h, pid, EV_EXEC, m->ts);
        h.aux_pid = m->target.valid ? m->target.ppid : m->proc.ppid;
        h.flags = m->target.valid ? m->target.ruid : m->proc.ruid;
        h.fd = (int32_t)n;
        mput(&h, m->target.valid && m->target.exe ? m->target.exe : m->proc.exe, NULL, raw, n);
        break;
    }
    case M_FORK:
        if (!m->target.valid) break;
        mac_note(&m->target);
        mhdr(&h, m->target.pid, EV_FORK, m->ts);
        h.aux_pid = pid; h.flags = m->target.ruid;
        mput(&h, NULL, NULL, NULL, 0);
        break;
    case M_EXIT:
        mhdr(&h, pid, EV_EXIT, m->ts);
        mput(&h, NULL, NULL, NULL, 0);
        map_pop(&mfacts, pid, NULL);
        break;
    case M_OPEN: {
        if (!m->f1.path) break;
        if (m->f1.has_stat && !S_ISREG(m->f1.mode)) { st.filtered++; break; }  // directories, devices, pipes
        uint64_t k = mac_open(m, &m->f1, m->fflag);
        if (m->fflag & MAC_FREAD) mac_io(m, k, EV_READ, "es:open-read", "es:open-read:derived-temp");
        break;
    }
    case M_CLOSE: {
        if (!m->modified || !m->f1.path) break;
        uint64_t k = mac_open(m, &m->f1, 0);
        mac_io(m, k, EV_WRITE, "es:close-modified", "es:close-modified:derived-temp");
        break;
    }
    case M_MMAP: {
        if (!m->f1.path || (m->f1.has_stat && !S_ISREG(m->f1.mode))) break;
        uint64_t k = mac_open(m, &m->f1, 0);
        if ((m->prot & PROT_WRITE) && (m->mflags & MAP_SHARED)) mac_io(m, k, EV_MMAP_WRITE, "es:mmap", "es:mmap:derived-temp");
        mac_io(m, k, EV_MMAP_READ, "es:mmap", "es:mmap:derived-temp");
        break;
    }
    case M_RENAME: {
        char *b = mac_dst(m);
        if (m->f1.path && b) { mhdr(&h, pid, EV_RENAME, m->ts); mput(&h, m->f1.path, b, NULL, 0); }
        free(b);
        break;
    }
    case M_UNLINK:
        if (!m->f1.path) break;
        mhdr(&h, pid, EV_UNLINK, m->ts);
        mput(&h, m->f1.path, NULL, NULL, 0);
        break;
    case M_CHDIR:
        if (!m->f1.path) break;
        mhdr(&h, pid, EV_CHDIR, m->ts);
        mput(&h, m->f1.path, NULL, NULL, 0);
        break;
    case M_CLONE: case M_COPYFILE: {
        char *b = mac_dst(m);
        if (m->f1.path && b) {
            const char *api = m->type == M_CLONE ? "es:clone" : "es:copyfile";
            const char *api_dt = m->type == M_CLONE ? "es:clone:derived-temp" : "es:copyfile:derived-temp";
            uint64_t ks = mac_open(m, &m->f1, MAC_FREAD);
            mac_io(m, ks, EV_READ, api, api_dt);
            mfile_t d = m->f2;  // the destination's identity when known (a copy onto an existing file)
            d.path = b;
            uint64_t kd = mac_open(m, &d, 0);
            mac_io(m, kd, EV_WRITE, api, api_dt);
        }
        free(b);
        break;
    }
    }
}

// ---------------------------------------------------------------- JSON (record and replay)
static void jstr(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        if (*p == '"' || *p == '\\') { fputc('\\', f); fputc(*p, f); }
        else if (*p < 0x20) fprintf(f, "\\u%04x", *p);
        else fputc(*p, f);
    }
    fputc('"', f);
}
static void jproc(FILE *f, const char *key, const mproc_t *p) {
    if (!p->valid) return;
    fprintf(f, ",\"%s\":{\"pid\":%u,\"pidver\":%u,\"ppid\":%u,\"ruid\":%u,\"euid\":%u,\"start\":%lld,\"exe\":", key, p->pid,
            p->pidver, p->ppid, p->ruid, p->euid, (long long)p->start_ns);
    jstr(f, p->exe);
    fputc('}', f);
}
static void jfile(FILE *f, const char *key, const mfile_t *x) {
    if (!x->path) return;
    fprintf(f, ",\"%s\":{\"path\":", key);
    jstr(f, x->path);
    if (x->has_stat) fprintf(f, ",\"dev\":%llu,\"ino\":%llu,\"mode\":%u", (unsigned long long)x->dev, (unsigned long long)x->ino, x->mode);
    if (x->truncated) fputs(",\"trunc\":1", f);
    fputc('}', f);
}
static void mac_record(FILE *f, const mmsg_t *m) {
    fprintf(f, "{\"type\":\"%s\",\"ts\":%lld", M_NAME[m->type], (long long)m->ts);
    if (m->has_gseq) fprintf(f, ",\"gseq\":%llu", (unsigned long long)m->gseq);
    jproc(f, "proc", &m->proc);
    jproc(f, "target", &m->target);
    jfile(f, "f1", &m->f1);
    jfile(f, "f2", &m->f2);
    if (m->dst_dir) { fputs(",\"dir\":", f); jstr(f, m->dst_dir); }
    if (m->dst_name) { fputs(",\"name\":", f); jstr(f, m->dst_name); }
    if (m->type == M_OPEN) fprintf(f, ",\"fflag\":%d", m->fflag);
    if (m->type == M_CLOSE) fprintf(f, ",\"modified\":%d", m->modified);
    if (m->type == M_MMAP) fprintf(f, ",\"prot\":%d,\"mflags\":%d", m->prot, m->mflags);
    if (m->type == M_EXEC) {
        fputs(",\"argv\":[", f);
        for (size_t i = 0; i < m->argc; i++) { if (i) fputc(',', f); jstr(f, m->argv[i]); }
        fputc(']', f);
        if (m->cwd) { fputs(",\"cwd\":", f); jstr(f, m->cwd); }
    }
    fputs("}\n", f);
}

// A small JSON reader for replay lines (objects, arrays, strings, integers, true/false/null).
typedef struct jv { int t; long long i; char *s; struct jv *v; char **k; size_t n; } jv_t;  // t: 0 null 1 bool 2 num 3 str 4 arr 5 obj
typedef struct { const char *p; int err; } jp_t;
static void jws(jp_t *j) { while (*j->p == ' ' || *j->p == '\t' || *j->p == '\r' || *j->p == '\n') j->p++; }
static void jfree(jv_t *v) {
    if (!v) return;
    free(v->s);
    for (size_t i = 0; i < v->n; i++) { if (v->v) jfree(&v->v[i]); if (v->k) free(v->k[i]); }
    free(v->v); free(v->k);
}
static void jutf8(buf_t *o, unsigned cp) {
    if (cp < 0x80) b_ch(o, (char)cp);
    else if (cp < 0x800) { b_ch(o, (char)(0xC0 | cp >> 6)); b_ch(o, (char)(0x80 | (cp & 0x3F))); }
    else if (cp < 0x10000) { b_ch(o, (char)(0xE0 | cp >> 12)); b_ch(o, (char)(0x80 | ((cp >> 6) & 0x3F))); b_ch(o, (char)(0x80 | (cp & 0x3F))); }
    else { b_ch(o, (char)(0xF0 | cp >> 18)); b_ch(o, (char)(0x80 | ((cp >> 12) & 0x3F))); b_ch(o, (char)(0x80 | ((cp >> 6) & 0x3F))); b_ch(o, (char)(0x80 | (cp & 0x3F))); }
}
static int jhex4(const char *p, unsigned *out) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i]; v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return 0;
    }
    *out = v;
    return 1;
}
static char *jstring(jp_t *j) {
    if (*j->p != '"') { j->err = 1; return NULL; }
    j->p++;
    buf_t o = {0};
    while (*j->p && *j->p != '"') {
        if (*j->p == '\\') {
            j->p++;
            char c = *j->p++;
            if (c == 'n') b_ch(&o, '\n'); else if (c == 't') b_ch(&o, '\t'); else if (c == 'r') b_ch(&o, '\r');
            else if (c == 'b') b_ch(&o, '\b'); else if (c == 'f') b_ch(&o, '\f');
            else if (c == 'u') {
                unsigned cp;
                if (!jhex4(j->p, &cp)) { j->err = 1; break; }
                j->p += 4;
                if (cp >= 0xD800 && cp < 0xDC00 && j->p[0] == '\\' && j->p[1] == 'u') {
                    unsigned lo;
                    if (jhex4(j->p + 2, &lo) && lo >= 0xDC00 && lo < 0xE000) { cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00); j->p += 6; }
                }
                jutf8(&o, cp);
            } else if (c) b_ch(&o, c);
            else { j->err = 1; break; }
        } else b_ch(&o, *j->p++);
    }
    if (*j->p != '"') j->err = 1; else j->p++;
    return b_take(&o);
}
static void jvalue(jp_t *j, jv_t *v) {
    memset(v, 0, sizeof *v);
    jws(j);
    char c = *j->p;
    if (c == '{' || c == '[') {
        int obj = c == '{';
        v->t = obj ? 5 : 4;
        j->p++;
        size_t cap = 0;
        jws(j);
        if (*j->p == (obj ? '}' : ']')) { j->p++; return; }
        for (;;) {
            if (v->n == cap) { cap = cap ? cap * 2 : 8; v->v = xrealloc(v->v, cap * sizeof *v->v); if (obj) v->k = xrealloc(v->k, cap * sizeof *v->k); }
            if (obj) { jws(j); v->k[v->n] = jstring(j); jws(j); if (*j->p != ':') { j->err = 1; v->v[v->n] = (jv_t){0}; v->n++; return; } j->p++; }
            jvalue(j, &v->v[v->n]);
            v->n++;
            if (j->err) return;
            jws(j);
            if (*j->p == ',') { j->p++; continue; }
            if (*j->p == (obj ? '}' : ']')) { j->p++; return; }
            j->err = 1;
            return;
        }
    }
    if (c == '"') { v->t = 3; v->s = jstring(j); return; }
    if (!strncmp(j->p, "true", 4)) { v->t = 1; v->i = 1; j->p += 4; return; }
    if (!strncmp(j->p, "false", 5)) { v->t = 1; v->i = 0; j->p += 5; return; }
    if (!strncmp(j->p, "null", 4)) { v->t = 0; j->p += 4; return; }
    if (c == '-' || (c >= '0' && c <= '9')) { char *e; v->t = 2; v->i = strtoll(j->p, &e, 10); j->p = e; return; }
    j->err = 1;
}
static const jv_t *jget(const jv_t *o, const char *k) {
    if (!o || o->t != 5) return NULL;
    for (size_t i = 0; i < o->n; i++) if (o->k[i] && !strcmp(o->k[i], k)) return &o->v[i];
    return NULL;
}
static long long jint(const jv_t *o, const char *k, long long dflt) { const jv_t *v = jget(o, k); return v && (v->t == 2 || v->t == 1) ? v->i : dflt; }
static const char *jtext(const jv_t *o, const char *k) { const jv_t *v = jget(o, k); return v && v->t == 3 ? v->s : NULL; }
static void jto_proc(const jv_t *o, mproc_t *p) {
    if (!o || o->t != 5) return;
    p->valid = 1;
    p->pid = (uint32_t)jint(o, "pid", 0); p->pidver = (uint32_t)jint(o, "pidver", 0); p->ppid = (uint32_t)jint(o, "ppid", 0);
    p->ruid = (uint32_t)jint(o, "ruid", 0); p->euid = (uint32_t)jint(o, "euid", (long long)p->ruid);
    p->start_ns = jint(o, "start", 0); p->exe = jtext(o, "exe");
}
static void jto_file(const jv_t *o, mfile_t *f) {
    if (!o) return;
    if (o->t == 3) { f->path = o->s; return; }
    if (o->t != 5) return;
    f->path = jtext(o, "path");
    f->has_stat = jget(o, "ino") != NULL;
    f->dev = (uint64_t)jint(o, "dev", 0); f->ino = (uint64_t)jint(o, "ino", 0); f->mode = (uint32_t)jint(o, "mode", 0100644);
    f->truncated = (int)jint(o, "trunc", 0);
}
static void mac_replay(const char *path) {
    FILE *f = strcmp(path, "-") ? fopen(path, "r") : stdin;
    if (!f) die("es-replay %s: %s", path, strerror(errno));
    char *line = NULL; size_t cap = 0; ssize_t n; long lineno = 0;
    while ((n = getline(&line, &cap, f)) > 0) {
        lineno++;
        jp_t j = {line, 0};
        jws(&j);
        if (!*j.p || *j.p == '#') continue;
        jv_t v;
        jvalue(&j, &v);
        if (j.err || v.t != 5) die("es-replay %s:%ld: not a JSON object", path, lineno);
        mmsg_t m = {0};
        const char *t = jtext(&v, "type");
        for (int i = 1; i < M_N; i++) if (t && !strcmp(t, M_NAME[i])) m.type = i;
        if (!m.type) die("es-replay %s:%ld: unknown type", path, lineno);
        m.ts = jint(&v, "ts", 0);
        if (jget(&v, "gseq")) { m.has_gseq = 1; m.gseq = (uint64_t)jint(&v, "gseq", 0); }
        jto_proc(jget(&v, "proc"), &m.proc);
        jto_proc(jget(&v, "target"), &m.target);
        jto_file(jget(&v, "f1"), &m.f1);
        jto_file(jget(&v, "f2"), &m.f2);
        m.dst_dir = jtext(&v, "dir"); m.dst_name = jtext(&v, "name");
        m.fflag = (int)jint(&v, "fflag", 0); m.modified = (int)jint(&v, "modified", 0);
        m.prot = (int)jint(&v, "prot", 0); m.mflags = (int)jint(&v, "mflags", 0);
        m.cwd = jtext(&v, "cwd");
        const jv_t *av = jget(&v, "argv");
        char **argv = NULL;
        if (av && av->t == 4) {
            argv = xmalloc((av->n + 1) * sizeof *argv);
            for (size_t i = 0; i < av->n; i++) argv[m.argc++] = av->v[i].t == 3 ? av->v[i].s : "";
        }
        m.argv = argv;
        if (mac_record_fp) mac_record(mac_record_fp, &m);
        mac_handle(&m);
        free(argv);
        jfree(&v);
        maybe_pump();
    }
    free(line);
    if (f != stdin) fclose(f);
}

// ---------------------------------------------------------------- live Endpoint Security client
typedef struct { char **v; size_t n, cap; } arena_t;  // per-message copies of Endpoint Security strings
static const char *acopy(arena_t *a, const char *s, size_t n) {
    if (!s) return NULL;
    char *c = xstrndup(s, n);
    if (a->n == a->cap) { a->cap = a->cap ? a->cap * 2 : 16; a->v = xrealloc(a->v, a->cap * sizeof *a->v); }
    a->v[a->n++] = c;
    return c;
}
static void afree(arena_t *a) { for (size_t i = 0; i < a->n; i++) free(a->v[i]); free(a->v); memset(a, 0, sizeof *a); }
static const char *atok(arena_t *a, es_string_token_t t) { return t.data ? acopy(a, t.data, t.length) : NULL; }
static void ef(arena_t *a, mfile_t *o, const es_file_t *f) {
    if (!f) return;
    o->path = atok(a, f->path);
    o->truncated = f->path_truncated;
    o->has_stat = 1; o->dev = (uint64_t)(uint32_t)f->stat.st_dev; o->ino = f->stat.st_ino; o->mode = f->stat.st_mode;
}
static void ep(arena_t *a, mproc_t *o, const es_process_t *p) {
    if (!p) return;
    o->valid = 1;
    o->pid = (uint32_t)audit_token_to_pid(p->audit_token);
    o->pidver = (uint32_t)audit_token_to_pidversion(p->audit_token);
    o->ruid = audit_token_to_ruid(p->audit_token);
    o->euid = audit_token_to_euid(p->audit_token);
    o->ppid = (uint32_t)p->ppid;
    o->exe = p->executable ? atok(a, p->executable->path) : NULL;
    o->start_ns = (int64_t)p->start_time.tv_sec * 1000000000LL + (int64_t)p->start_time.tv_usec * 1000LL;
}
static void mac_stat_dst(arena_t *a, mmsg_t *m) {  // a new clone/copy destination: its identity, now
    (void)a;
    if (m->f2.path || !m->dst_dir || !m->dst_name) return;
    char *d = pjoin(m->dst_dir, m->dst_name);
    struct stat sb;
    if (lstat(d, &sb) == 0 && S_ISREG(sb.st_mode)) {
        m->f2.has_stat = 1; m->f2.dev = (uint64_t)(uint32_t)sb.st_dev; m->f2.ino = sb.st_ino; m->f2.mode = sb.st_mode;
        m->f2.path = acopy(a, d, strlen(d));
    }
    free(d);
}
static int es_to_mmsg(const es_message_t *e, arena_t *a, mmsg_t *m) {
    memset(m, 0, sizeof *m);
    m->ts = (int64_t)e->time.tv_sec * 1000000000LL + e->time.tv_nsec;
    if (e->version >= 4) { m->has_gseq = 1; m->gseq = e->global_seq_num; }
    ep(a, &m->proc, e->process);
    switch (e->event_type) {
    case ES_EVENT_TYPE_NOTIFY_EXEC: {
        m->type = M_EXEC;
        ep(a, &m->target, e->event.exec.target);
        uint32_t n = es_exec_arg_count(&e->event.exec);
        m->argv = xmalloc((n + 1) * sizeof *m->argv);
        for (uint32_t i = 0; i < n; i++) {
            const char *s = atok(a, es_exec_arg(&e->event.exec, i));
            m->argv[m->argc++] = (char *)(s ? s : "");
        }
        if (e->version >= 3 && e->event.exec.cwd) m->cwd = atok(a, e->event.exec.cwd->path);
        return 1;
    }
    case ES_EVENT_TYPE_NOTIFY_FORK: m->type = M_FORK; ep(a, &m->target, e->event.fork.child); return 1;
    case ES_EVENT_TYPE_NOTIFY_EXIT: m->type = M_EXIT; return 1;
    case ES_EVENT_TYPE_NOTIFY_OPEN: m->type = M_OPEN; m->fflag = e->event.open.fflag; ef(a, &m->f1, e->event.open.file); return 1;
    case ES_EVENT_TYPE_NOTIFY_CLOSE: m->type = M_CLOSE; m->modified = e->event.close.modified; ef(a, &m->f1, e->event.close.target); return 1;
    case ES_EVENT_TYPE_NOTIFY_MMAP:
        m->type = M_MMAP; m->prot = e->event.mmap.protection; m->mflags = e->event.mmap.flags; ef(a, &m->f1, e->event.mmap.source);
        return 1;
    case ES_EVENT_TYPE_NOTIFY_RENAME:
        m->type = M_RENAME; ef(a, &m->f1, e->event.rename.source);
        if (e->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) ef(a, &m->f2, e->event.rename.destination.existing_file);
        else if (e->event.rename.destination.new_path.dir) {
            m->dst_dir = atok(a, e->event.rename.destination.new_path.dir->path);
            m->dst_name = atok(a, e->event.rename.destination.new_path.filename);
        }
        return 1;
    case ES_EVENT_TYPE_NOTIFY_UNLINK: m->type = M_UNLINK; ef(a, &m->f1, e->event.unlink.target); return 1;
    case ES_EVENT_TYPE_NOTIFY_CHDIR: m->type = M_CHDIR; ef(a, &m->f1, e->event.chdir.target); return 1;
    case ES_EVENT_TYPE_NOTIFY_CLONE:
        m->type = M_CLONE; ef(a, &m->f1, e->event.clone.source);
        if (e->event.clone.target_dir) m->dst_dir = atok(a, e->event.clone.target_dir->path);
        m->dst_name = atok(a, e->event.clone.target_name);
        mac_stat_dst(a, m);
        return 1;
    case ES_EVENT_TYPE_NOTIFY_COPYFILE:
        m->type = M_COPYFILE; ef(a, &m->f1, e->event.copyfile.source);
        if (e->event.copyfile.target_file) ef(a, &m->f2, e->event.copyfile.target_file);
        else {
            if (e->event.copyfile.target_dir) m->dst_dir = atok(a, e->event.copyfile.target_dir->path);
            m->dst_name = atok(a, e->event.copyfile.target_name);
            mac_stat_dst(a, m);
        }
        return 1;
    default:
        return 0;
    }
}

static pthread_mutex_t mq_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t mq_cv = PTHREAD_COND_INITIALIZER;
static const es_message_t **mq;
static size_t mq_head, mq_n, mq_cap;

static const char *es_result_name(es_new_client_result_t r) {
    switch (r) {
    case ES_NEW_CLIENT_RESULT_SUCCESS: return "SUCCESS";
    case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: return "ERR_INVALID_ARGUMENT";
    case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: return "ERR_INTERNAL";
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: return "ERR_NOT_ENTITLED";
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: return "ERR_NOT_PERMITTED";
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return "ERR_NOT_PRIVILEGED";
    case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return "ERR_TOO_MANY_CLIENTS";
    default: return "UNKNOWN";
    }
}

static void mac_consume(const es_message_t *e) {
    arena_t a = {0};
    mmsg_t m;
    if (es_to_mmsg(e, &a, &m)) {
        if (mac_record_fp) mac_record(mac_record_fp, &m);
        mac_handle(&m);
    }
    free(m.argv);
    afree(&a);
}

static void mac_run_live(void) {
    mq_cap = mac_queue_limit ? mac_queue_limit : 65536;
    mq = xmalloc(mq_cap * sizeof *mq);
    es_client_t *client = NULL;
    es_new_client_result_t r = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        (void)c;
        pthread_mutex_lock(&mq_mu);
        if (mq_n >= mq_cap) st.queue_drops++;  // the consumer fell behind: counted, never silent
        else { es_retain_message(msg); mq[(mq_head + mq_n++) % mq_cap] = msg; }
        pthread_cond_signal(&mq_cv);
        pthread_mutex_unlock(&mq_mu);
    });
    if (r != ES_NEW_CLIENT_RESULT_SUCCESS) {
        // Machine-readable: the supervisor reports it (an entitlement or permission problem is
        // not a collector failure) and exits 3 so it is told apart from a crash.
        printf("{\"error\":\"es_new_client\",\"result\":%d,\"name\":\"%s\"}\n", (int)r, es_result_name(r));
        fflush(stdout);
        exit(3);
    }
    char self[PATH_MAX]; uint32_t sz = sizeof self;
    if (_NSGetExecutablePath(self, &sz) == 0) {
        char real[PATH_MAX];
        es_mute_path(client, realpath(self, real) ? real : self, ES_MUTE_PATH_TYPE_LITERAL);  // this collector and its writer
    }
    es_event_type_t ev[] = {ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT,
                            ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_MMAP,
                            ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_NOTIFY_CHDIR,
                            ES_EVENT_TYPE_NOTIFY_CLONE, ES_EVENT_TYPE_NOTIFY_COPYFILE};
    if (es_subscribe(client, ev, sizeof ev / sizeof *ev) != ES_RETURN_SUCCESS) {
        printf("{\"error\":\"es_subscribe\"}\n");
        fflush(stdout);
        es_delete_client(client);
        exit(4);
    }
    struct sigaction sa = {0};
    sa.sa_handler = on_sig;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    struct sigaction su = {0};
    su.sa_handler = on_usr1;
    sigaction(SIGUSR1, &su, NULL);
    pid_t parent = getppid();
    printf("{\"ready\":true,\"pid\":%d,\"writer_pid\":%d,\"source\":\"endpoint-security\"}\n", getpid(), (int)writer_pid);
    fflush(stdout);
    const es_message_t *batch[256];
    for (;;) {
        size_t n = 0;
        pthread_mutex_lock(&mq_mu);
        if (!mq_n && !stop_flag) {
            struct timeval tv; gettimeofday(&tv, NULL);
            struct timespec until = {tv.tv_sec, (long)tv.tv_usec * 1000 + 50000000L};
            if (until.tv_nsec >= 1000000000L) { until.tv_sec++; until.tv_nsec -= 1000000000L; }
            pthread_cond_timedwait(&mq_cv, &mq_mu, &until);
        }
        while (n < 256 && mq_n) { batch[n++] = mq[mq_head]; mq_head = (mq_head + 1) % mq_cap; mq_n--; }
        pthread_mutex_unlock(&mq_mu);
        for (size_t i = 0; i < n; i++) { mac_consume(batch[i]); es_release_message(batch[i]); }
        flush_pending();
        maybe_pump();
        if (stats_flag) { stats_flag = 0; print_stats(0, 0, 0, 0); }
        if (getppid() != parent) stop_flag = 1;  // never outlive the supervisor
        if (stop_flag && !n) {
            es_unsubscribe_all(client);
            pthread_mutex_lock(&mq_mu);
            int empty = mq_n == 0;
            pthread_mutex_unlock(&mq_mu);
            if (empty) break;
        }
    }
    es_delete_client(client);
    flush_pending();
}

static void mac_main(void) {
    clock_offset = 0;  // Endpoint Security timestamps are wall-clock already
    map_init(&mfacts, 0, 0, mfact_free);
    if (mac_live) mac_run_live();
    else { mac_replay(mac_replay_path); flush_pending(); }
    if (mac_record_fp) fclose(mac_record_fp);
    if (getenv("WHYFS_ES_TYPE_COUNTS")) {  // diagnostics: messages per type, on stderr
        for (int i = 1; i < M_N; i++) fprintf(stderr, "es %s %llu\n", M_NAME[i], (unsigned long long)mac_by_type[i]);
    }
}
