// whyfs-collect: native user-space ingestion for the whyfs eBPF daemon.
//
// The Python daemon loads the BPF programs (BCC) and hands this process the ring
// buffer map fd; everything on the per-event path runs here:
//
//   ring buffer (libbpf) -> event model -> ordered handoff batches -> pipe ->
//   writer child (dropped to the workspace owner) -> SQLite
//
// The event model is a line-by-line port of BCCCollector._process_event in
// ebpf_bcc.py, which remains the executable specification: tests replay the same
// synthetic and captured streams through both and require identical records
// (tests/test_native_collect.py).  Python semantics that matter are reproduced
// exactly: os.path.realpath (non-strict), normpath, commonpath-based
// containment, shlex.join, bytes.decode('utf-8', 'replace'), and the bounded
// insertion-ordered maps.
//
// Usage
//   live:   whyfs-collect --ring-fd N --drop-fd N --root DIR --run-id ID
//                         [--temp-root DIR]... [--capture-all] [--uid U --gid G]
//           [--record FILE]  (tee raw ring payloads, for differential replay)
//   replay: whyfs-collect --replay FILE (--emit | --root DIR ...) [--seed PID:CWD]...
//                         [--clock-offset NS]
// Replay input: records framed as u32 size + bytes (the ring-buffer payload).
// --emit prints each handed-off record as a JSON line (string fields hex-encoded)
// instead of writing SQLite.  On exit one JSON stats line goes to stdout.
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PATH_N 512
#define PID_BITS 22
#define AT_FDCWD_VALUE (-100)
#define QUEUE_RECORDS 262144
#define HANDOFF_BATCH 512
#define MAX_ANCESTORS 8
#define MACHINE_MAX_ANCESTORS 24  // ebpf_bcc.MACHINE_MAX_ANCESTORS
#define FILES_LIMIT 400000
#define PROC_ROWS_LIMIT 200000
#define DERIVED_LIMIT 200000
#define DEFER_LIMIT 200000  // machine mode: deferred temporary-bridge records (ebpf_bcc.DEFER_LIMIT)

enum { EV_OPEN = 1, EV_READ = 2, EV_WRITE = 3, EV_RENAME = 4, EV_UNLINK = 5, EV_EXEC = 6, EV_FORK = 7,
       EV_EXIT = 8, EV_MMAP_READ = 9, EV_CHDIR = 13, EV_FCHDIR = 14, EV_MMAP_WRITE = 15 };

struct hdr_t {  // must match BPF_SOURCE / EventHeader in ebpf_bcc.py
    uint64_t ts_ns, file, file2;
    uint32_t tgid, tid, aux_pid, type;
    int32_t fd, dirfd, dirfd2;
    uint32_t flags, truncated, ino;
    char comm[16];
};
_Static_assert(sizeof(struct hdr_t) == 80, "hdr_t layout");

// Diagnostics for cost decomposition (never used by the daemon):
//   --diag-discard  count records and drop them (kernel evidence + native ring consumption)
//   --diag-no-store full event model, handed-off batches discarded (no persistence)
static int diag_discard, diag_nostore;
#define OFF_PATH 80
#define OFF_PATH2 (80 + PATH_N)

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "whyfs-collect: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(2);
}
static void *xmalloc(size_t n) { void *p = malloc(n ? n : 1); if (!p) die("out of memory"); return p; }
static void *xrealloc(void *p, size_t n) { p = realloc(p, n ? n : 1); if (!p) die("out of memory"); return p; }
static char *xstrdup(const char *s) { return s ? strcpy(xmalloc(strlen(s) + 1), s) : NULL; }
static char *xstrndup(const char *s, size_t n) { char *p = xmalloc(n + 1); memcpy(p, s, n); p[n] = 0; return p; }

// ---------------------------------------------------------------- growable string
typedef struct { char *p; size_t n, cap; } buf_t;
static void b_reserve(buf_t *b, size_t add) {
    if (b->n + add + 1 > b->cap) { b->cap = (b->n + add + 1) * 2; b->p = xrealloc(b->p, b->cap); }
}
static void b_add(buf_t *b, const void *s, size_t n) { b_reserve(b, n); memcpy(b->p + b->n, s, n); b->n += n; b->p[b->n] = 0; }
static void b_str(buf_t *b, const char *s) { b_add(b, s, strlen(s)); }
static void b_ch(buf_t *b, char c) { b_add(b, &c, 1); }
static char *b_take(buf_t *b) { if (!b->p) return xstrdup(""); char *p = b->p; b->p = 0; b->n = b->cap = 0; return p; }

static int64_t mono_ns(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec; }

// ---------------------------------------------------------------- hash maps
// Chained hash map with an insertion-order list (for Python's OrderedDict-based
// _BoundedMap: put() moves a key to the end; eviction drops the oldest).
typedef struct ent {
    struct ent *chain, *prev, *next;
    uint64_t h, k;  // k: integer key (int maps)
    char *s;        // string key (string maps)
    void *v;
    uint64_t u;
} ent_t;
typedef struct {
    ent_t **b;
    size_t nb, count, limit;  // limit 0: unbounded
    int strkeys;
    ent_t *head, *tail;
    void (*free_v)(void *);
} map_t;

static uint64_t mix64(uint64_t k) { k ^= k >> 33; k *= 0xff51afd7ed558ccdULL; k ^= k >> 33; k *= 0xc4ceb9fe1a85ec53ULL; k ^= k >> 33; return k; }
static uint64_t hstr(const char *s) { uint64_t h = 1469598103934665603ULL; while (*s) { h ^= (unsigned char)*s++; h *= 1099511628211ULL; } return h; }
static void map_init(map_t *m, int strkeys, size_t limit, void (*free_v)(void *)) {
    memset(m, 0, sizeof *m);
    m->nb = 1024; m->b = calloc(m->nb, sizeof(ent_t *)); if (!m->b) die("out of memory");
    m->strkeys = strkeys; m->limit = limit; m->free_v = free_v;
}
static ent_t *map_find(map_t *m, uint64_t k, const char *s) {
    uint64_t h = m->strkeys ? hstr(s) : mix64(k);
    for (ent_t *e = m->b[h & (m->nb - 1)]; e; e = e->chain)
        if (e->h == h && (m->strkeys ? !strcmp(e->s, s) : e->k == k)) return e;
    return NULL;
}
static void order_unlink(map_t *m, ent_t *e) {
    if (e->prev) e->prev->next = e->next; else m->head = e->next;
    if (e->next) e->next->prev = e->prev; else m->tail = e->prev;
    e->prev = e->next = NULL;
}
static void order_append(map_t *m, ent_t *e) { e->prev = m->tail; e->next = NULL; if (m->tail) m->tail->next = e; else m->head = e; m->tail = e; }
static void map_remove_ent(map_t *m, ent_t *e) {
    ent_t **pp = &m->b[e->h & (m->nb - 1)];
    while (*pp != e) pp = &(*pp)->chain;
    *pp = e->chain;
    order_unlink(m, e);
    if (m->free_v && e->v) m->free_v(e->v);
    free(e->s);
    free(e);
    m->count--;
}
static void map_grow(map_t *m) {
    size_t nb = m->nb * 2;
    ent_t **b = calloc(nb, sizeof(ent_t *)); if (!b) die("out of memory");
    for (size_t i = 0; i < m->nb; i++)
        for (ent_t *e = m->b[i], *n; e; e = n) { n = e->chain; e->chain = b[e->h & (nb - 1)]; b[e->h & (nb - 1)] = e; }
    free(m->b); m->b = b; m->nb = nb;
}
// dict[k] = v (existing key keeps its position, as a plain dict assignment does)
static ent_t *map_set(map_t *m, uint64_t k, const char *s, void *v) {
    ent_t *e = map_find(m, k, s);
    if (e) { if (m->free_v && e->v && e->v != v) m->free_v(e->v); e->v = v; return e; }
    e = calloc(1, sizeof *e); if (!e) die("out of memory");
    e->k = k; e->s = m->strkeys ? xstrdup(s) : NULL; e->h = m->strkeys ? hstr(s) : mix64(k); e->v = v;
    e->chain = m->b[e->h & (m->nb - 1)]; m->b[e->h & (m->nb - 1)] = e;
    order_append(m, e);
    if (++m->count > m->nb) map_grow(m);
    return e;
}
// _BoundedMap.put: assign, move to end, evict the oldest past the limit
static ent_t *map_put(map_t *m, uint64_t k, const char *s, void *v) {
    ent_t *e = map_set(m, k, s, v);
    order_unlink(m, e); order_append(m, e);
    while (m->limit && m->count > m->limit) map_remove_ent(m, m->head);
    return e;
}
static void *map_get(map_t *m, uint64_t k, const char *s) { ent_t *e = map_find(m, k, s); return e ? e->v : NULL; }
static int map_has(map_t *m, uint64_t k, const char *s) { return map_find(m, k, s) != NULL; }
static void map_pop(map_t *m, uint64_t k, const char *s) { ent_t *e = map_find(m, k, s); if (e) map_remove_ent(m, e); }

// ---------------------------------------------------------------- Python path semantics
static int is_abs(const char *p) { return p[0] == '/'; }
// os.path.join(a, b)
static char *pjoin(const char *a, const char *b) {
    buf_t o = {0};
    if (is_abs(b) || !*a) b_str(&o, b);
    else { b_str(&o, a); if (a[strlen(a) - 1] != '/') b_ch(&o, '/'); b_str(&o, b); }
    return b_take(&o);
}
// os.path.split(p) -> (head, tail)
static void psplit(const char *p, char **head, char **tail) {
    const char *slash = strrchr(p, '/');
    size_t i = slash ? (size_t)(slash - p) + 1 : 0;
    *tail = xstrdup(p + i);
    size_t hn = i;
    int all = 1;
    for (size_t j = 0; j < hn; j++) if (p[j] != '/') { all = 0; break; }
    if (hn && !all) while (hn > 0 && p[hn - 1] == '/') hn--;
    *head = xstrndup(p, hn);
}
// os.path.normpath (POSIX)
static char *pnormpath(const char *path) {
    if (!*path) return xstrdup(".");
    size_t ns = 0;
    while (path[ns] == '/') ns++;
    const char *init = ns == 2 ? "//" : ns ? "/" : "";
    const char *rest = path + ns;
    char **comps = NULL; size_t n = 0, cap = 0;
    char *copy = xstrdup(rest);
    for (char *save = NULL, *c = strtok_r(copy, "/", &save); c; c = strtok_r(NULL, "/", &save)) {
        if (!strcmp(c, ".")) continue;
        if (strcmp(c, "..") || (!*init && !n) || (n && !strcmp(comps[n - 1], ".."))) {
            if (n == cap) { cap = cap ? cap * 2 : 16; comps = xrealloc(comps, cap * sizeof *comps); }
            comps[n++] = c;
        } else if (n) n--;
    }
    buf_t o = {0};
    b_str(&o, init);
    for (size_t i = 0; i < n; i++) { if (i) b_ch(&o, '/'); b_str(&o, comps[i]); }
    free(comps); free(copy);
    if (!o.n) { free(o.p); return xstrdup("."); }
    return b_take(&o);
}
// os.path.abspath
static char *pabspath(const char *p) {
    if (is_abs(p)) return pnormpath(p);
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof cwd)) strcpy(cwd, "/");
    char *j = pjoin(cwd, p), *r = pnormpath(j);
    free(j);
    return r;
}

// os.path.realpath(filename, strict=False) -- posixpath._joinrealpath, Python 3.12
typedef struct { char **k; char **v; size_t n, cap; } seen_t;
static long seen_idx(seen_t *s, const char *k) { for (size_t i = 0; i < s->n; i++) if (!strcmp(s->k[i], k)) return (long)i; return -1; }
static void seen_set(seen_t *s, const char *k, const char *v) {
    long i = seen_idx(s, k);
    if (i < 0) {
        if (s->n == s->cap) { s->cap = s->cap ? s->cap * 2 : 8; s->k = xrealloc(s->k, s->cap * sizeof(char *)); s->v = xrealloc(s->v, s->cap * sizeof(char *)); }
        i = (long)s->n++; s->k[i] = xstrdup(k); s->v[i] = NULL;
    }
    free(s->v[i]); s->v[i] = v ? xstrdup(v) : NULL;
}
// *path is owned and replaced; returns ok
static int joinrealpath(char **path, const char *rest_in, seen_t *seen) {
    char *restbuf = xstrdup(rest_in), *rest = restbuf;
    if (is_abs(rest)) { rest++; free(*path); *path = xstrdup("/"); }
    while (*rest) {
        char *sl = strchr(rest, '/');
        char *name;
        if (sl) { name = xstrndup(rest, sl - rest); rest = sl + 1; }
        else { name = xstrdup(rest); rest += strlen(rest); }
        if (!*name || !strcmp(name, ".")) { free(name); continue; }
        if (!strcmp(name, "..")) {
            if (**path) {
                char *h, *t;
                psplit(*path, &h, &t);
                free(*path); *path = h;
                if (!strcmp(t, "..")) { char *a = pjoin(*path, ".."), *b = pjoin(a, ".."); free(a); free(*path); *path = b; }
                free(t);
            } else { free(*path); *path = xstrdup(".."); }
            free(name);
            continue;
        }
        char *newpath = pjoin(*path, name);
        free(name);
        struct stat st;
        int is_link = lstat(newpath, &st) == 0 && S_ISLNK(st.st_mode);
        if (!is_link) { free(*path); *path = newpath; continue; }
        long si = seen_idx(seen, newpath);
        if (si >= 0) {
            if (seen->v[si]) { free(*path); *path = xstrdup(seen->v[si]); free(newpath); continue; }
            free(*path); *path = pjoin(newpath, rest); free(newpath); free(restbuf);
            return 0;  // symlink loop: resolved part + rest unchanged
        }
        seen_set(seen, newpath, NULL);
        char target[PATH_MAX + 1];
        ssize_t tn = readlink(newpath, target, PATH_MAX);
        if (tn < 0) { free(*path); *path = newpath; continue; }  // vanished between lstat and readlink
        target[tn] = 0;
        int ok = joinrealpath(path, target, seen);
        if (!ok) { char *j = pjoin(*path, rest); free(*path); *path = j; free(newpath); free(restbuf); return 0; }
        seen_set(seen, newpath, *path);
        free(newpath);
    }
    free(restbuf);
    return 1;
}
static char *canon(const char *p) {  // _canon == os.path.realpath
    char *path = xstrdup("");
    seen_t seen = {0};
    joinrealpath(&path, p, &seen);
    for (size_t i = 0; i < seen.n; i++) { free(seen.k[i]); free(seen.v[i]); }
    free(seen.k); free(seen.v);
    char *r = pabspath(path);
    free(path);
    return r;
}

// _within: os.path.commonpath((path, root)) == root
typedef struct { char **c; size_t n; char *store; } comps_t;
static comps_t split_comps(const char *p) {
    comps_t r = {0};
    r.store = xstrdup(p);
    size_t cap = 0;
    for (char *save = NULL, *c = strtok_r(r.store, "/", &save); c; c = strtok_r(NULL, "/", &save)) {
        if (!strcmp(c, ".")) continue;
        if (r.n == cap) { cap = cap ? cap * 2 : 16; r.c = xrealloc(r.c, cap * sizeof(char *)); }
        r.c[r.n++] = c;
    }
    return r;
}
typedef struct { char *s; comps_t c; } root_t;
static root_t mkroot(const char *s) { root_t r = {xstrdup(s), split_comps(s)}; return r; }
static int within(const char *path, const root_t *root) {
    if (!path || !*path) return 0;
    if (!is_abs(path) != !is_abs(root->s)) return 0;  // ValueError: mixing absolute and relative
    comps_t pc = split_comps(path);
    size_t common = 0;
    while (common < pc.n && common < root->c.n && !strcmp(pc.c[common], root->c.c[common])) common++;
    free(pc.c); free(pc.store);
    // commonpath returns prefix + '/'.join(common components); equal to root only if
    // every root component matched (root is resolved, hence normalized)
    if (common != root->c.n) return 0;
    buf_t o = {0};
    b_str(&o, is_abs(path) ? "/" : "");
    for (size_t i = 0; i < common; i++) { if (i) b_ch(&o, '/'); b_str(&o, root->c.c[i]); }
    int eq = !strcmp(o.p ? o.p : "", root->s);
    free(o.p);
    return eq;
}

// ---------------------------------------------------------------- text: utf-8 'replace', redaction, shlex
static void utf8_replace(buf_t *o, const unsigned char *s, size_t n) {  // bytes.decode('utf-8', 'replace')
    static const char R[] = "\xEF\xBF\xBD";
    size_t i = 0;
    while (i < n) {
        unsigned char c = s[i];
        if (c < 0x80) { b_ch(o, (char)c); i++; continue; }
        int len; unsigned char lo = 0x80, hi = 0xBF;
        if (c >= 0xC2 && c <= 0xDF) len = 2;
        else if (c >= 0xE0 && c <= 0xEF) { len = 3; if (c == 0xE0) lo = 0xA0; if (c == 0xED) hi = 0x9F; }
        else if (c >= 0xF0 && c <= 0xF4) { len = 4; if (c == 0xF0) lo = 0x90; if (c == 0xF4) hi = 0x8F; }
        else { b_add(o, R, 3); i++; continue; }
        size_t k = 1;
        while ((int)k < len) {
            if (i + k >= n) break;
            unsigned char cc = s[i + k];
            if (k == 1 ? (cc < lo || cc > hi) : (cc < 0x80 || cc > 0xBF)) break;
            k++;
        }
        if ((int)k == len) b_add(o, (const char *)s + i, len);
        else b_add(o, R, 3);
        i += k;
    }
}
// str.lower() as far as matching ASCII keywords is concerned: ASCII, plus
// U+212A KELVIN SIGN -> 'k' (the only non-ASCII code point lowering to ASCII alone)
static char *lower_for_match(const char *a) {
    buf_t o = {0};
    for (const unsigned char *p = (const unsigned char *)a; *p;) {
        if (p[0] == 0xE2 && p[1] == 0x84 && p[2] == 0xAA) { b_ch(&o, 'k'); p += 3; continue; }
        b_ch(&o, (*p >= 'A' && *p <= 'Z') ? (char)(*p + 32) : (char)*p);
        p++;
    }
    return b_take(&o);
}
static void shlex_quote(buf_t *o, const char *s) {
    if (!*s) { b_str(o, "''"); return; }
    int unsafe = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strchr("_@%+=:,./-", c))) { unsafe = 1; break; }
    }
    if (!unsafe) { b_str(o, s); return; }
    b_ch(o, '\'');
    for (const char *p = s; *p; p++) { if (*p == '\'') b_str(o, "'\"'\"'"); else b_ch(o, *p); }
    b_ch(o, '\'');
}
static const char *SENSITIVE[] = {"password", "passwd", "token", "secret", "api-key", "apikey", "api_key", "access-key", "access_key", "private-key", "private_key", "credential", "authorization"};
// Command-text pass: whyfs/redact.py redact_text, rule for rule (both collectors carry this
// same block; tests/redaction_vectors.json holds the shared expected outputs).  Finds secrets
// that argv tokenization cannot isolate -- `sh -c '... --token x'`, `cmd /c ""tool" --password x
// API_KEY=y"`, PowerShell `$env:API_KEY='x'` -- and replaces only their values.
#define RX_MARK "<redacted>"
static int rx_ws(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'; }
static int rx_quote(char c) { return c == '"' || c == '\''; }
static int rx_sep(char c) { return c == ';' || c == '&' || c == '|'; }
static int rx_boundary(char c) { return rx_ws(c) || rx_quote(c) || rx_sep(c) || c == '(' || c == '`'; }
static int rx_keych(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
}
static char rx_low(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }
static int rx_ieq(const char *a, const char *lower, size_t n) {
    for (size_t i = 0; i < n; i++) if (rx_low(a[i]) != lower[i]) return 0;
    return 1;
}
static int rx_key_sensitive(const char *k, size_t n) {  // redact.key_is_sensitive: contains a name
    for (size_t s = 0; s < sizeof SENSITIVE / sizeof *SENSITIVE; s++) {
        size_t sl = strlen(SENSITIVE[s]);
        for (size_t i = 0; i + sl <= n; i++) if (rx_ieq(k + i, SENSITIVE[s], sl)) return 1;
    }
    return 0;
}
static int rx_switch_sensitive(const char *k, size_t n) {  // redact.switch_is_sensitive: is, or ends in -/_/. + name
    for (size_t s = 0; s < sizeof SENSITIVE / sizeof *SENSITIVE; s++) {
        size_t sl = strlen(SENSITIVE[s]);
        if (n < sl || !rx_ieq(k + n - sl, SENSITIVE[s], sl)) continue;
        if (n == sl || k[n - sl - 1] == '-' || k[n - sl - 1] == '_' || k[n - sl - 1] == '.') return 1;
    }
    return 0;
}
static size_t rx_value_end(const char *t, size_t n, size_t j) {
    size_t k = j;
    while (k < n && !rx_ws(t[k]) && !rx_sep(t[k])) {
        char c = t[k];
        if (rx_quote(c)) {
            if (k > j && (k + 1 == n || rx_ws(t[k + 1]) || rx_sep(t[k + 1]))) return k;  // closes an outer quoting
            const char *close = memchr(t + k + 1, c, n - k - 1);
            if (!close) return k == j ? n : k;
            k = (size_t)(close - t) + 1;
        } else k++;
    }
    return k;
}
static size_t rx_skip_ws(const char *t, size_t n, size_t k) { while (k < n && rx_ws(t[k])) k++; return k; }
static int rx_match(const char *t, size_t n, size_t i, size_t *vs, size_t *ve) {
    static const char *SCHEMES[] = {"bearer", "basic", "token", "digest"};
    size_t p = i, prefix = 0;
    int dollar = 0;
    if (t[p] == '$') {
        dollar = 1; p++;
        if (p + 4 <= n && rx_ieq(t + p, "env:", 4)) p += 4;
    } else if (p + 1 < n && t[p] == '-' && t[p + 1] == '-') prefix = 2;
    else if (t[p] == '-' || t[p] == '/') prefix = 1;
    size_t ks = p + prefix, ke = ks;
    while (ke < n && rx_keych(t[ke])) ke++;
    if (ke == ks) return 0;
    const char *key = t + ks;
    size_t kl = ke - ks;
    char sep = ke < n ? t[ke] : 0;
    if (sep == '=') {
        if (!rx_key_sensitive(key, kl)) return 0;
        *vs = ke + 1; *ve = rx_value_end(t, n, *vs); return 1;
    }
    if (dollar) {  // PowerShell: $name = value
        size_t q = rx_skip_ws(t, n, ke);
        if (q < n && t[q] == '=' && rx_key_sensitive(key, kl)) { *vs = rx_skip_ws(t, n, q + 1); *ve = rx_value_end(t, n, *vs); return 1; }
        return 0;
    }
    if (sep == ':') {
        if (prefix) {
            if (!rx_key_sensitive(key, kl)) return 0;
            *vs = ke + 1; *ve = rx_value_end(t, n, *vs); return 1;
        }
        if (ke + 1 < n && rx_ws(t[ke + 1]) && rx_switch_sensitive(key, kl)) {  // header text
            *vs = rx_skip_ws(t, n, ke + 1); *ve = rx_value_end(t, n, *vs);
            for (size_t s = 0; s < sizeof SCHEMES / sizeof *SCHEMES; s++) {
                if (*ve - *vs == strlen(SCHEMES[s]) && rx_ieq(t + *vs, SCHEMES[s], *ve - *vs)) {
                    *vs = rx_skip_ws(t, n, *ve); *ve = rx_value_end(t, n, *vs); break;
                }
            }
            return 1;
        }
        return 0;
    }
    if (prefix && (sep == 0 || rx_ws(sep)) && rx_switch_sensitive(key, kl)) {
        *vs = rx_skip_ws(t, n, ke);
        if (*vs >= n) return 0;
        *ve = rx_value_end(t, n, *vs); return 1;
    }
    return 0;
}
static char *redact_text(const char *t) {
    size_t n = strlen(t), i = 0, lit = 0, vs, ve;
    buf_t o = {0};
    while (i < n) {
        if ((i == 0 || rx_boundary(t[i - 1])) && rx_match(t, n, i, &vs, &ve) && ve > vs) {
            int whole = ve - vs >= 2 && rx_quote(t[vs]) && t[ve - 1] == t[vs] && memchr(t + vs + 1, t[vs], ve - vs - 1) == t + ve - 1;
            b_add(&o, t + lit, vs - lit);
            if (whole) b_ch(&o, t[vs]);
            b_str(&o, RX_MARK);
            if (whole) b_ch(&o, t[vs]);
            i = lit = ve;
            continue;
        }
        i++;
    }
    b_add(&o, t + lit, n - lit);
    return b_take(&o);
}
static int rx_is_switch(const char *a) {  // redact._is_switch: -name / --name with a sensitive name
    const char *name = a[0] == '-' ? (a[1] == '-' ? a + 2 : a + 1) : NULL;
    if (!name || !*name) return 0;
    for (const char *p = name; *p; p++) if (!rx_keych(*p)) return 0;
    return rx_switch_sensitive(name, strlen(name));
}
static int rx_has_ws(const char *s, size_t n) { for (size_t i = 0; i < n; i++) if (rx_ws(s[i])) return 1; return 0; }
static int rx_is_script_flag(const char *a) {  // redact._is_script_flag: -c -lc ... /c /k -Command
    size_t n = strlen(a);
    if ((n == 2 && (a[0] == '/') && (rx_low(a[1]) == 'c' || rx_low(a[1]) == 'k')) || (n == 8 && rx_ieq(a, "-command", 8))
        || (n == 9 && rx_ieq(a, "--command", 9))) return 1;
    if (n < 2 || n > 5 || a[0] != '-' || rx_low(a[n - 1]) != 'c') return 0;
    for (size_t i = 1; i < n; i++) { char c = rx_low(a[i]); if (c < 'a' || c > 'z') return 0; }
    return 1;
}
static char *redact_cmdline(char **argv, size_t argc) {  // whyfs/redact.py redact_argv
    buf_t o = {0};
    int secret_next = 0;
    for (size_t i = 0; i < argc; i++) {
        const char *a = argv[i];
        char *low = lower_for_match(a);
        char *item = NULL;
        if (secret_next) { item = xstrdup("<redacted>"); secret_next = 0; }
        else if (i && rx_is_script_flag(argv[i - 1])) item = redact_text(a);  // a shell script is command text
        else {
            int exact = 0;
            for (size_t s = 0; s < sizeof SENSITIVE / sizeof *SENSITIVE; s++) {
                if (!strcmp(low, SENSITIVE[s]) || (!strncmp(low, "--", 2) && !strcmp(low + 2, SENSITIVE[s]))) exact = 1;
            }
            if (!exact) exact = rx_is_switch(a);
            if (exact) { item = xstrdup(a); secret_next = 1; }
            else if (strchr(a, '=') && !rx_has_ws(a, (size_t)(strchr(a, '=') - a))) {  // redact.redact_argv: one-word KEY
                char *key = xstrndup(low, strchr(low, '=') - low);
                int hit = 0;
                for (size_t s = 0; s < sizeof SENSITIVE / sizeof *SENSITIVE; s++) if (strstr(key, SENSITIVE[s])) hit = 1;
                free(key);
                if (hit) {
                    buf_t r = {0};
                    b_add(&r, a, strchr(a, '=') - a);
                    b_str(&r, "=<redacted>");
                    item = b_take(&r);
                } else item = redact_text(a);
            } else item = redact_text(a);
        }
        if (i) b_ch(&o, ' ');
        shlex_quote(&o, item);
        free(item); free(low);
    }
    return b_take(&o);  // whyfs's own quoting: not rescanned (redact.redact_argv)
}

// ---------------------------------------------------------------- /proc helpers
static char *safe_proc_link(uint32_t pid, const char *item) {
    char p[64], t[PATH_MAX + 1];
    snprintf(p, sizeof p, "/proc/%u/%s", pid, item);
    ssize_t n = readlink(p, t, PATH_MAX);
    if (n < 0) return NULL;
    return xstrndup(t, n);
}
static char *clean_link(char *p) {  // takes ownership
    if (!p || !*p) { free(p); return NULL; }
    size_t n = strlen(p), d = strlen(" (deleted)");
    if (n >= d && !strcmp(p + n - d, " (deleted)")) p[n - d] = 0;
    if (p[0] != '/') { free(p); return NULL; }
    return p;
}
// decoded argv from raw NUL-separated bytes (empty items dropped)
static size_t split_argv(const unsigned char *raw, size_t n, char ***out) {
    char **v = NULL; size_t c = 0, cap = 0, i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && raw[j]) j++;
        if (j > i) {
            buf_t o = {0};
            utf8_replace(&o, raw + i, j - i);
            if (c == cap) { cap = cap ? cap * 2 : 8; v = xrealloc(v, cap * sizeof *v); }
            v[c++] = b_take(&o);
        }
        i = j + 1;
    }
    *out = v;
    return c;
}
static void free_argv(char **v, size_t n) { for (size_t i = 0; i < n; i++) free(v[i]); free(v); }
static size_t proc_cmdline(uint32_t pid, char ***out) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%u/cmdline", pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { *out = NULL; return 0; }
    buf_t b = {0};
    char tmp[4096];
    ssize_t r;
    while ((r = read(fd, tmp, sizeof tmp)) > 0) b_add(&b, tmp, r);
    close(fd);
    size_t n = split_argv((const unsigned char *)(b.p ? b.p : ""), b.n, out);
    free(b.p);
    return n;
}

// ---------------------------------------------------------------- collector state
typedef struct { uint64_t submitted, filtered, unresolved_fd, truncated_paths, kernel_drops, queue_drops, received,
                 proc_fallbacks, unreadable_paths, excluded_image, bridge_evicted; } stats_t;
static stats_t st;

typedef struct {  // process row (kind 'process'); has_* mark non-None
    int64_t ts, pid, os_pid, ppid, parent_key;
    int has_ppid, has_parent_key;
    char *exe, *cwd, *command, *user;  // user: "uid:N" (ebpf_bcc: fork/exec uid, /proc for existing)
} prow_t;
static void prow_free(void *p) { prow_t *r = p; if (!r) return; free(r->exe); free(r->cwd); free(r->command); free(r->user); free(r); }
typedef struct { char *exe, *cmd; } image_t;
static void image_free(void *p) { image_t *i = p; if (!i) return; free(i->exe); free(i->cmd); free(i); }
typedef struct { int64_t ts, pid, os_pid; char *path; } pexec_t;
typedef struct { pexec_t v[16]; int n; } pexecs_t;
static void pexecs_free(void *p) { pexecs_t *x = p; if (!x) return; for (int i = 0; i < x->n; i++) free(x->v[i].path); free(x); }

static root_t ws_root, state_root;  // state_root: <workspace>/.whyfs (never evidence)
static root_t temp_roots[8];
static int n_temp_roots;
static int capture_all;
static int machine_mode, max_ancestors = MAX_ANCESTORS;  // --machine (docs/MACHINE_MODE.md)
static const char *run_id = "run";
static int64_t clock_offset;
static uint64_t seq;

static map_t files, cwdm, image, pkey, proc_rows, pending_exec, relevant, read_workspace, derived, fidm;
// Machine mode (ebpf_bcc._defer/_bridge): derived-temporary records wait here until they bridge into
// an in-scope file.  deferred: owner process key -> dlist_t; temp_writers: temp path -> wlist_t.
static map_t deferred, temp_writers;
static size_t n_deferred;
static int64_t defer_seq;

// ---------------------------------------------------------------- output (ordered handoff batches)
// Record encoding shared by the writer pipe and --emit:
//   'P' i64 ts, pid, os_pid; opt-i64 ppid, parent_key; str exe, cwd, command, user
//   'E' i64 ts, pid, os_pid; u8 kind; opt-i64 flags; u8 has_rw, read, write; str path, path2, api; u8 has_path2; str file_id
// str: u32 length (0xffffffff = None) + bytes.  opt-i64: u8 present + i64.
enum { K_OPEN = 1, K_IO, K_RENAME, K_UNLINK, K_EXEC };
static const char *KIND_NAME[] = {"", "open", "io", "rename", "unlink", "exec"};

static buf_t pending;     // current handoff batch (records)
static uint32_t pending_n;
static buf_t outq;        // framed batches waiting for the writer pipe
static size_t outq_off;   // bytes of outq already written
typedef struct { size_t end; uint32_t n; int64_t queued_ns; } frame_t;
static frame_t *frames; static size_t nframes, frames_cap, frames_head;
static uint64_t outq_records;
static int emit_json;
static FILE *emit_fp;
static int writer_fd = -1;

static void w_i64(buf_t *b, int64_t v) { b_add(b, &v, 8); }
static void w_u8(buf_t *b, uint8_t v) { b_add(b, &v, 1); }
static void w_opt(buf_t *b, int has, int64_t v) { w_u8(b, (uint8_t)has); w_i64(b, has ? v : 0); }
static void w_str(buf_t *b, const char *s) {
    uint32_t n = s ? (uint32_t)strlen(s) : 0xffffffffu;
    b_add(b, &n, 4);
    if (s) b_add(b, s, n);
}

static void flush_pending(void);
static void put_bump(void) { pending_n++; if (pending_n >= HANDOFF_BATCH) flush_pending(); }
static void put_process(const prow_t *r) {
    w_u8(&pending, 'P'); w_i64(&pending, r->ts); w_i64(&pending, r->pid); w_i64(&pending, r->os_pid);
    w_opt(&pending, r->has_ppid, r->ppid); w_opt(&pending, r->has_parent_key, r->parent_key);
    w_str(&pending, r->exe); w_str(&pending, r->cwd); w_str(&pending, r->command); w_str(&pending, r->user);
    put_bump();
}
static const char *cur_fid;  // identity of the file of the I/O event being recorded (NULL otherwise)
static void put_event(int64_t ts, int64_t key, int64_t os_pid, int kind, int has_flags, int64_t flags, int has_rw, int rd, int wr,
                      const char *path, int has_path2, const char *path2, const char *api) {
    w_u8(&pending, 'E'); w_i64(&pending, ts); w_i64(&pending, key); w_i64(&pending, os_pid); w_u8(&pending, (uint8_t)kind);
    w_opt(&pending, has_flags, flags); w_u8(&pending, (uint8_t)has_rw); w_u8(&pending, (uint8_t)rd); w_u8(&pending, (uint8_t)wr);
    w_str(&pending, path); w_str(&pending, path2); w_str(&pending, api); w_u8(&pending, (uint8_t)has_path2);
    w_str(&pending, kind == K_IO ? cur_fid : NULL);
    put_bump();
}

// --emit: JSON line per record (the dict BCCCollector hands to its writer; strings hex)
typedef struct { const unsigned char *p, *e; } rd_t;
static int64_t r_i64(rd_t *r) { int64_t v; memcpy(&v, r->p, 8); r->p += 8; return v; }
static uint8_t r_u8(rd_t *r) { return *r->p++; }
static const char *r_str(rd_t *r, uint32_t *len) {
    uint32_t n; memcpy(&n, r->p, 4); r->p += 4;
    if (n == 0xffffffffu) { *len = 0; return NULL; }
    const char *s = (const char *)r->p; r->p += n; *len = n; return s;
}
static void j_hex(FILE *f, const char *key, const char *s, uint32_t n) {
    if (!s) { fprintf(f, ",\"%s\":null", key); return; }
    fprintf(f, ",\"%s\":\"", key);
    for (uint32_t i = 0; i < n; i++) fprintf(f, "%02x", (unsigned char)s[i]);
    fputc('"', f);
}
static void j_opt(FILE *f, const char *key, int has, int64_t v) { if (has) fprintf(f, ",\"%s\":%lld", key, (long long)v); else fprintf(f, ",\"%s\":null", key); }
static void emit_records(const unsigned char *p, size_t n) {
    rd_t r = {p, p + n};
    while (r.p < r.e) {
        uint8_t t = r_u8(&r);
        int64_t ts = r_i64(&r), pid = r_i64(&r), os_pid = r_i64(&r);
        if (t == 'P') {
            int hp = r_u8(&r); int64_t pp = r_i64(&r); int hk = r_u8(&r); int64_t pk = r_i64(&r);
            uint32_t l1, l2, l3, l4; const char *exe = r_str(&r, &l1), *cwd = r_str(&r, &l2), *cmd = r_str(&r, &l3);
            const char *user = r_str(&r, &l4);
            fprintf(emit_fp, "{\"run_id\":\"%s\",\"ts_ns\":%lld,\"kind\":\"process\",\"pid\":%lld,\"os_pid\":%lld", run_id,
                    (long long)ts, (long long)pid, (long long)os_pid);
            j_opt(emit_fp, "ppid", hp, pp); j_opt(emit_fp, "parent_key", hk, pk);
            j_hex(emit_fp, "exe", exe, l1); j_hex(emit_fp, "cwd", cwd, l2); j_hex(emit_fp, "command", cmd, l3);
            if (user) fprintf(emit_fp, ",\"user\":\"%.*s\"", (int)l4, user); else fprintf(emit_fp, ",\"user\":null");
            fprintf(emit_fp, ",\"source\":\"ebpf\"}\n");
        } else {
            int kind = r_u8(&r); int hf = r_u8(&r); int64_t fl = r_i64(&r);
            int hrw = r_u8(&r), rdv = r_u8(&r), wrv = r_u8(&r);
            uint32_t l1, l2, l3; const char *path = r_str(&r, &l1), *path2 = r_str(&r, &l2), *api = r_str(&r, &l3);
            int hp2 = r_u8(&r);
            uint32_t l5; const char *fid = r_str(&r, &l5);
            fprintf(emit_fp, "{\"run_id\":\"%s\",\"ts_ns\":%lld,\"kind\":\"%s\",\"pid\":%lld,\"os_pid\":%lld", run_id,
                    (long long)ts, KIND_NAME[kind], (long long)pid, (long long)os_pid);
            j_hex(emit_fp, "path", path, l1);
            if (hp2) j_hex(emit_fp, "path2", path2, l2);
            if (hrw) fprintf(emit_fp, ",\"read\":%s,\"write\":%s", rdv ? "true" : "false", wrv ? "true" : "false");
            if (hf) fprintf(emit_fp, ",\"flags\":%lld", (long long)fl);
            if (fid) fprintf(emit_fp, ",\"file_id\":\"%.*s\"", (int)l5, fid);
            fprintf(emit_fp, ",\"api\":\"%.*s\",\"source\":\"ebpf\"}\n", (int)l3, api);
        }
    }
}

static void flush_pending(void) {  // BCCCollector.flush_pending
    if (!pending_n) return;
    if (diag_nostore) {
        st.submitted += pending_n;
    } else if (emit_json) {
        emit_records((const unsigned char *)pending.p, pending.n);
        st.submitted += pending_n;
    } else if (outq_records + pending_n > QUEUE_RECORDS) {
        // Do not backpressure the observed workload: count the loss, never hide it.
        st.queue_drops += pending_n;
    } else {
        uint32_t len = (uint32_t)pending.n;
        b_add(&outq, &len, 4); b_add(&outq, &pending_n, 4); b_add(&outq, pending.p, pending.n);
        if (nframes == frames_cap) { frames_cap = frames_cap ? frames_cap * 2 : 64; frames = xrealloc(frames, frames_cap * sizeof *frames); }
        frames[nframes++] = (frame_t){outq.n, pending_n, mono_ns()};
        outq_records += pending_n;
        st.submitted += pending_n;
    }
    pending.n = 0; pending_n = 0;
}
static int writer_broken;
// Persistence is deferred while the workload is active: queued batches go to the
// writer once the ring has been quiet for QUIET_NS, or the oldest batch has waited
// MAX_DELAY_NS, or FLUSH_RECORDS records are queued (all within QUEUE_RECORDS).
// Writing concurrently with the observed workload measurably slowed it
// (results/v02-native-decomp); nothing is dropped or reordered by deferring.
#define QUIET_NS 200000000LL
#define MAX_DELAY_NS 2000000000LL
#define FLUSH_RECORDS 65536
static void pump_output(int block);
static int flush_immediate;  // --flush-immediate: hand batches over every drain cycle (diagnostics)
static uint64_t last_submitted;
static int64_t last_activity_ns;
static void maybe_pump(void) {
    int64_t now = mono_ns();
    // Activity = evidence handed off for this workspace, not unrelated system traffic.
    if (st.submitted != last_submitted) { last_submitted = st.submitted; last_activity_ns = now; }
    if (frames_head >= nframes) return;
    if (flush_immediate || now - last_activity_ns >= QUIET_NS || now - frames[frames_head].queued_ns >= MAX_DELAY_NS ||
        outq_records >= FLUSH_RECORDS)
        pump_output(0);
}
static void pump_output(int block) {  // move queued batches into the writer pipe
    if (writer_fd < 0) return;
    while (outq_off < outq.n) {
        if (!block) { struct pollfd p = {writer_fd, POLLOUT, 0}; if (poll(&p, 1, 0) <= 0 || !(p.revents & POLLOUT)) break; }
        ssize_t w = write(writer_fd, outq.p + outq_off, outq.n - outq_off);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) { if (block) { struct pollfd p = {writer_fd, POLLOUT, 0}; poll(&p, 1, 100); continue; } break; }
            writer_broken = 1;  // writer died: surfaced at exit
            outq_off = outq.n;
            break;
        }
        outq_off += w;
    }
    while (frames_head < nframes && frames[frames_head].end <= outq_off) outq_records -= frames[frames_head++].n;
    if (outq_off == outq.n) { outq.n = 0; outq_off = 0; nframes = frames_head = 0; }
}

// ---------------------------------------------------------------- event model (port of _process_event)
static int64_t wall_ns(void) { struct timespec t; clock_gettime(CLOCK_REALTIME, &t); return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec; }
// ---------------------------------------------------------------- machine scope policy
// whyfs/scope.py, rule for rule (both collectors carry this block; tests/scope_vectors.json).
// Rules: exclude|include|temp <pattern>, exclude-image <pattern>; component-wise prefix
// patterns, `*`/`pre*suf` per component, `~` = every user's home.  Precedence:
// include > temp > exclude > in scope.
enum { SC_IN = 0, SC_TEMP = 1, SC_OUT = 2 };
enum { SCR_EXCLUDE, SCR_INCLUDE, SCR_TEMP, SCR_IMAGE_PATH, SCR_IMAGE_NAME };
typedef struct { int kind; char **c; int n; } sc_rule_t;
static sc_rule_t *sc_rules;
static int sc_n, sc_cap;
#ifdef SC_NT
#define SC_SEP '\\'
static char sc_fold(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }
#else
#define SC_SEP '/'
static char sc_fold(char c) { return c; }
#endif
static int sc_is_sep(char c) {
#ifdef SC_NT
    return c == '\\' || c == '/';
#else
    return c == '/';
#endif
}
// split into folded components (no empty ones)
static int sc_split(const char *p, char ***out) {
    int n = 0, cap = 8;
    char **v = xmalloc(cap * sizeof *v);
    while (*p) {
        while (*p && sc_is_sep(*p)) p++;
        if (!*p) break;
        const char *q = p;
        while (*q && !sc_is_sep(*q)) q++;
        if (n == cap) { cap *= 2; v = xrealloc(v, cap * sizeof *v); }
        char *c = xstrndup(p, (size_t)(q - p));
        for (char *s = c; *s; s++) *s = sc_fold(*s);
        v[n++] = c;
        p = q;
    }
    *out = v;
    return n;
}
static void sc_push(int kind, const char *pat) {
    if (sc_n == sc_cap) { sc_cap = sc_cap ? sc_cap * 2 : 32; sc_rules = xrealloc(sc_rules, sc_cap * sizeof *sc_rules); }
    sc_rule_t *r = &sc_rules[sc_n++];
    r->kind = kind;
    if (kind == SCR_IMAGE_NAME) {
        r->c = xmalloc(sizeof *r->c); r->c[0] = xstrdup(pat); r->n = 1;
        for (char *s = r->c[0]; *s; s++) *s = sc_fold(*s);
    } else r->n = sc_split(pat, &r->c);
}
static void sc_add_pattern(int kind, const char *pat) {
    if (pat[0] == '~' && (pat[1] == 0 || sc_is_sep(pat[1]))) {
        const char *rest = pat[1] ? pat + 2 : "";
#ifdef SC_NT
        const char *homes[] = {"*:\\Users\\*"};
#else
        const char *homes[] = {"/home/*", "/root"};
#endif
        for (size_t i = 0; i < sizeof homes / sizeof *homes; i++) {
            buf_t o = {0};
            b_str(&o, homes[i]);
            if (*rest) { b_ch(&o, SC_SEP); b_str(&o, rest); }
            char *full = b_take(&o);
            sc_push(kind, full);
            free(full);
        }
        return;
    }
    sc_push(kind, pat);
}
// parse rule text (returns number of rules added)
static int sc_parse(const char *text) {
    int added = 0;
    const char *p = text;
    while (*p) {
        const char *e = p; while (*e && *e != '\n') e++;
        char *line = xstrndup(p, (size_t)(e - p));
        p = *e ? e + 1 : e;
        char *s = line; while (*s == ' ' || *s == '\t') s++;
        size_t L = strlen(s); while (L && (s[L - 1] == ' ' || s[L - 1] == '\t' || s[L - 1] == '\r')) s[--L] = 0;
        if (!*s || *s == '#') { free(line); continue; }
        char *sp = strchr(s, ' ');
        if (!sp) { free(line); continue; }
        *sp = 0;
        char *pat = sp + 1; while (*pat == ' ' || *pat == '\t') pat++;
        if (!*pat) { free(line); continue; }
        if (!strcmp(s, "exclude")) sc_add_pattern(SCR_EXCLUDE, pat);
        else if (!strcmp(s, "include")) sc_add_pattern(SCR_INCLUDE, pat);
        else if (!strcmp(s, "temp")) sc_add_pattern(SCR_TEMP, pat);
        else if (!strcmp(s, "exclude-image")) sc_push(strchr(pat, '/') || strchr(pat, '\\') ? SCR_IMAGE_PATH : SCR_IMAGE_NAME, pat);
        else { free(line); continue; }
        added++;
        free(line);
    }
    return added;
}
static int sc_load(const char *file) {  // -1: unreadable
    FILE *f = fopen(file, "rb");
    if (!f) return -1;
    buf_t o = {0};
    char tmp[4096]; size_t n;
    while ((n = fread(tmp, 1, sizeof tmp, f)) > 0) b_add(&o, tmp, n);
    fclose(f);
    char *t = b_take(&o);
    int r = sc_parse(t);
    free(t);
    return r;
}
// allocation-free matching: every classified path is walked in place
static int sc_eq_n(const char *a, const char *pat, size_t n) {  // a (raw) vs pat (folded)
    for (size_t i = 0; i < n; i++) if (sc_fold(a[i]) != pat[i]) return 0;
    return 1;
}
static int sc_comp_match_raw(const char *pc, const char *c, size_t cl) {
    const char *star = strchr(pc, '*');
    if (!star) return strlen(pc) == cl && sc_eq_n(c, pc, cl);
    size_t pre = (size_t)(star - pc), suf = strlen(star + 1);
    return cl >= pre + suf && sc_eq_n(c, pc, pre) && sc_eq_n(c + cl - suf, star + 1, suf);
}
static int sc_match_raw(const char *p, const sc_rule_t *r) {
    for (int i = 0; i < r->n; i++) {
        while (*p && sc_is_sep(*p)) p++;
        if (!*p) return 0;
        const char *q = p;
        while (*q && !sc_is_sep(*q)) q++;
        if (!sc_comp_match_raw(r->c[i], p, (size_t)(q - p))) return 0;
        p = q;
    }
    return 1;
}
static const char *sc_last_comp(const char *p, size_t *len) {
    const char *end = p + strlen(p);
    while (end > p && sc_is_sep(end[-1])) end--;
    const char *b = end;
    while (b > p && !sc_is_sep(b[-1])) b--;
    *len = (size_t)(end - b);
    return b;
}
// The rules are fixed for the collector's lifetime, so a path's class never changes: a small
// direct-mapped memo spares the rule scan for paths seen again (an input read on every iteration,
// the open and its I/O, the in-scope and temp tests of one event).
#define SC_MEMO 1024
static struct { char *path; int cls; } sc_memo[SC_MEMO];
static int sc_classify_rules(const char *path);
static int sc_classify(const char *path) {
    uint64_t h = hstr(path) & (SC_MEMO - 1);
    if (sc_memo[h].path && !strcmp(sc_memo[h].path, path)) return sc_memo[h].cls;
    int c = sc_classify_rules(path);
    free(sc_memo[h].path);
    sc_memo[h].path = xstrdup(path);
    sc_memo[h].cls = c;
    return c;
}
static int sc_classify_rules(const char *path) {
    int inc = 0, tmp = 0, exc = 0;
    for (int i = 0; i < sc_n && !inc; i++) {
        const sc_rule_t *r = &sc_rules[i];
        if (r->kind == SCR_INCLUDE) { if (sc_match_raw(path, r)) inc = 1; }
        else if (r->kind == SCR_TEMP) { if (!tmp && sc_match_raw(path, r)) tmp = 1; }
        else if (r->kind == SCR_EXCLUDE) { if (!exc && sc_match_raw(path, r)) exc = 1; }
    }
    return inc ? SC_IN : tmp ? SC_TEMP : exc ? SC_OUT : SC_IN;
}
static int sc_image_excluded(const char *exe) {
    if (!exe || !*exe) return 0;
    size_t nl; const char *name = sc_last_comp(exe, &nl);
    for (int i = 0; i < sc_n; i++) {
        const sc_rule_t *r = &sc_rules[i];
        if (r->kind == SCR_IMAGE_NAME) { if (nl && sc_comp_match_raw(r->c[0], name, nl)) return 1; }
        else if (r->kind == SCR_IMAGE_PATH) { if (sc_match_raw(exe, r)) return 1; }
    }
    return 0;
}
static int is_temp(const char *p) {
    if (machine_mode) return sc_classify(p) == SC_TEMP;
    for (int i = 0; i < n_temp_roots; i++) if (within(p, &temp_roots[i])) return 1;
    return 0;
}
static int within_ws(const char *p, int cap_all) {  // BCCCollector._in_ws
    if (!p || !*p || within(p, &state_root)) return 0;
    if (machine_mode) return sc_classify(p) == SC_IN;
    return cap_all ? 1 : within(p, &ws_root);
}
static int64_t proc_start_ns(uint32_t pid) {  // agents.proc_start_ns: btime + starttime ticks (0: unknown)
    char p[64], buf[1024];
    snprintf(p, sizeof p, "/proc/%u/stat", pid);
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *q = strrchr(buf, ')');
    if (!q) return 0;
    unsigned long long ticks = 0;
    int field = 2;
    for (char *t = strtok(q + 1, " "); t; t = strtok(NULL, " ")) {
        if (++field == 22) { ticks = strtoull(t, NULL, 10); break; }
    }
    if (field != 22) return 0;
    long long btime = -1;
    FILE *s = fopen("/proc/stat", "r");
    if (!s) return 0;
    char line[256];
    while (fgets(line, sizeof line, s)) if (!strncmp(line, "btime ", 6)) { btime = atoll(line + 6); break; }
    fclose(s);
    long hz = sysconf(_SC_CLK_TCK);
    if (btime < 0 || hz <= 0) return 0;
    return btime * 1000000000LL + (int64_t)(ticks * 1000000000ULL / (unsigned long long)hz);
}
static char *proc_user(uint32_t pid) {  // ebpf_bcc._proc_user
    char p[64], line[256];
    snprintf(p, sizeof p, "/proc/%u/status", pid);
    FILE *f = fopen(p, "r");
    if (!f) return NULL;
    char *r = NULL;
    while (fgets(line, sizeof line, f)) {
        unsigned long a, b;
        if (!strncmp(line, "Uid:", 4) && sscanf(line + 4, "%lu %lu", &a, &b) == 2) {
            char u[32]; snprintf(u, sizeof u, "uid:%lu", b); r = xstrdup(u); break;
        }
    }
    fclose(f);
    return r;
}

static const char *cwd_of(uint32_t pid) {  // _cwd
    const char *c = map_get(&cwdm, pid, NULL);
    if (!c) {
        char *link = safe_proc_link(pid, "cwd");
        if (link && *link) {
            st.proc_fallbacks++;
            ent_t *e = map_set(&cwdm, pid, NULL, canon(link));
            c = e->v;
        }
        free(link);
    }
    return c;
}
static void record_process(prow_t *row);
static void announce_existing(uint32_t pid) {
    char *exe = clean_link(safe_proc_link(pid, "exe"));
    char **argv; size_t argc = proc_cmdline(pid, &argv);
    image_t *im = xmalloc(sizeof *im);
    im->exe = xstrdup(exe);
    im->cmd = argc ? redact_cmdline(argv, argc) : xstrdup(exe);
    free_argv(argv, argc);
    map_set(&image, pid, NULL, im);
    prow_t *r = calloc(1, sizeof *r);
    int64_t started = proc_start_ns(pid);  // a process that predates the collector: its OS start time
    r->ts = started ? started : wall_ns(); r->pid = pid; r->os_pid = pid;
    r->exe = exe; r->cwd = xstrdup(cwd_of(pid)); r->command = xstrdup(im->cmd);
    r->user = proc_user(pid);
    record_process(r);
}
static uint64_t key_of(uint32_t pid) {
    ent_t *e = map_find(&pkey, pid, NULL);
    if (e) return e->u;
    e = map_set(&pkey, pid, NULL, NULL);
    e->u = pid;
    announce_existing(pid);
    return pid;
}
static void record_process(prow_t *row) {  // takes ownership of row
    prow_t *old = map_get(&proc_rows, row->pid, NULL);
    if (old) {
        prow_t *m = calloc(1, sizeof *m);
        *m = *old;
        m->exe = xstrdup(row->exe ? row->exe : old->exe);
        m->cwd = xstrdup(row->cwd ? row->cwd : old->cwd);
        m->command = xstrdup(row->command ? row->command : old->command);
        m->user = xstrdup(row->user ? row->user : old->user);
        if (row->has_ppid) { m->has_ppid = 1; m->ppid = row->ppid; }
        if (row->has_parent_key) { m->has_parent_key = 1; m->parent_key = row->parent_key; }
        m->os_pid = row->os_pid;
        m->ts = old->ts;
        prow_free(row);
        row = m;
    }
    map_put(&proc_rows, row->pid, NULL, row);
    if (map_has(&relevant, row->pid, NULL)) put_process(row);
}
static void record_exec(int64_t ts, uint64_t k, uint32_t pid, const char *exe) {
    if (map_has(&relevant, k, NULL)) { put_event(ts, k, pid, K_EXEC, 0, 0, 0, 0, 0, exe, 0, NULL, "ebpf:exec"); return; }
    ent_t *e = map_find(&pending_exec, k, NULL);
    if (!e) e = map_set(&pending_exec, k, NULL, calloc(1, sizeof(pexecs_t)));
    pexecs_t *l = e->v;
    if (l->n < 16) l->v[l->n++] = (pexec_t){ts, (int64_t)k, pid, xstrdup(exe)};
}
static void make_relevant(uint64_t k) {
    int has_k = 1;
    for (int i = 0; i < max_ancestors + 1; i++) {
        if (!has_k || map_has(&relevant, k, NULL)) return;
        map_set(&relevant, k, NULL, NULL);
        prow_t *row = map_get(&proc_rows, k, NULL);
        if (row) put_process(row);
        ent_t *pe = map_find(&pending_exec, k, NULL);
        if (pe) {
            pexecs_t *l = pe->v;
            for (int j = 0; j < l->n; j++) put_event(l->v[j].ts, l->v[j].pid, l->v[j].os_pid, K_EXEC, 0, 0, 0, 0, 0, l->v[j].path, 0, NULL, "ebpf:exec");
            map_remove_ent(&pending_exec, pe);
        }
        has_k = row && row->has_parent_key;
        if (has_k) k = (uint64_t)row->parent_key;
    }
}
// ---------------------------------------------------------------- deferred temporary bridges (machine mode)
typedef struct {
    int64_t seq, ts, key, os_pid;
    int kind, has_rw, rd, wr, has_path2;
    char *path, *path2, *fid, *consumed;
    const char *api;  // string literals only
} drec_t;
typedef struct { drec_t **v; size_t n, cap; } dlist_t;
typedef struct { uint64_t *v; size_t n, cap; } wlist_t;
static void drec_free(drec_t *r) { if (!r) return; free(r->path); free(r->path2); free(r->fid); free(r->consumed); free(r); }
static void dlist_free(void *p) { dlist_t *l = p; if (!l) return; for (size_t i = 0; i < l->n; i++) drec_free(l->v[i]); free(l->v); free(l); }
static void wlist_free(void *p) { wlist_t *l = p; if (!l) return; free(l->v); free(l); }
static void make_relevant(uint64_t k);
static void defer_rec(uint32_t pid, int64_t ts, int kind, const char *path, int has_rw, int rd, int wr,
                      int has_path2, const char *path2, const char *api, const char *consumed, const char *wrote) {
    uint64_t k = key_of(pid);
    image_t *im = map_get(&image, pid, NULL);
    if (im && sc_image_excluded(im->exe)) { st.excluded_image++; return; }
    drec_t *r = calloc(1, sizeof *r); if (!r) die("out of memory");
    r->seq = ++defer_seq; r->ts = ts; r->key = (int64_t)k; r->os_pid = pid; r->kind = kind;
    r->has_rw = has_rw; r->rd = rd; r->wr = wr; r->has_path2 = has_path2;
    r->path = path ? xstrdup(path) : NULL; r->path2 = path2 ? xstrdup(path2) : NULL; r->api = api;
    r->fid = kind == K_IO && cur_fid ? xstrdup(cur_fid) : NULL;
    r->consumed = consumed && *consumed ? xstrdup(consumed) : NULL;
    ent_t *e = map_find(&deferred, k, NULL);
    if (!e) e = map_set(&deferred, k, NULL, calloc(1, sizeof(dlist_t)));
    dlist_t *l = e->v;
    if (l->n == l->cap) { l->cap = l->cap ? l->cap * 2 : 4; l->v = realloc(l->v, l->cap * sizeof *l->v); if (!l->v) die("out of memory"); }
    l->v[l->n++] = r;
    n_deferred++;
    if (wrote && *wrote) {
        wlist_t *w = map_get(&temp_writers, 0, wrote);
        if (!w) { w = calloc(1, sizeof *w); if (!w) die("out of memory"); }
        int have = 0;
        for (size_t i = 0; i < w->n; i++) if (w->v[i] == k) { have = 1; break; }
        if (!have) {
            if (w->n == w->cap) { w->cap = w->cap ? w->cap * 2 : 2; w->v = realloc(w->v, w->cap * sizeof *w->v); if (!w->v) die("out of memory"); }
            w->v[w->n++] = k;
        }
        map_put(&temp_writers, 0, wrote, w);
    }
    while (n_deferred > DEFER_LIMIT && deferred.head) {  // the oldest owner's records go first
        dlist_t *old = deferred.head->v;
        n_deferred -= old->n; st.bridge_evicted += old->n;
        map_remove_ent(&deferred, deferred.head);
    }
}
static int drec_cmp(const void *a, const void *b) {
    int64_t x = (*(drec_t *const *)a)->seq, y = (*(drec_t *const *)b)->seq;
    return x < y ? -1 : x > y;
}
typedef struct { uint64_t *v; size_t n, cap; } u64v_t;
static void u64v_push(u64v_t *s, uint64_t x) {
    if (s->n == s->cap) { s->cap = s->cap ? s->cap * 2 : 16; s->v = realloc(s->v, s->cap * sizeof *s->v); if (!s->v) die("out of memory"); }
    s->v[s->n++] = x;
}
static void push_writers(u64v_t *todo, const char *temp) {
    wlist_t *w = temp ? map_get(&temp_writers, 0, temp) : NULL;
    if (w) for (size_t i = 0; i < w->n; i++) u64v_push(todo, w->v[i]);
}
// Hand over, in their original order, the deferred records of k and of every process whose
// derived temporaries k consumed (recursively), plus the writers of rename_src.
static void bridge(uint64_t k, const char *rename_src) {
    if (!n_deferred) return;
    u64v_t todo = {0};
    map_t seen; map_init(&seen, 0, 0, NULL);
    drec_t **out = NULL; size_t no = 0, co = 0;
    u64v_push(&todo, k);
    push_writers(&todo, rename_src);
    while (todo.n) {
        uint64_t o = todo.v[--todo.n];
        if (map_has(&seen, o, NULL)) continue;
        map_set(&seen, o, NULL, NULL);
        ent_t *e = map_find(&deferred, o, NULL);
        if (!e) continue;
        dlist_t *l = e->v;
        for (size_t i = 0; i < l->n; i++) {
            if (no == co) { co = co ? co * 2 : 16; out = realloc(out, co * sizeof *out); if (!out) die("out of memory"); }
            out[no++] = l->v[i];
            n_deferred--;
            push_writers(&todo, l->v[i]->consumed);
        }
        l->n = 0;  // the records now belong to out
        map_remove_ent(&deferred, e);
    }
    free(todo.v);
    for (ent_t *x = seen.head, *nx; x; x = nx) { nx = x->next; map_remove_ent(&seen, x); }
    free(seen.b);
    if (no > 1) qsort(out, no, sizeof *out, drec_cmp);
    const char *saved = cur_fid;
    for (size_t i = 0; i < no; i++) {
        drec_t *r = out[i];
        make_relevant((uint64_t)r->key);
        cur_fid = r->fid;
        put_event(r->ts, r->key, r->os_pid, r->kind, 0, 0, r->has_rw, r->rd, r->wr, r->path, r->has_path2, r->path2, r->api);
        cur_fid = saved;
        drec_free(r);
    }
    free(out);
}
static void file_event(uint32_t pid, int64_t ts, int kind, const char *path, int has_flags, int64_t flags, int has_rw, int rd, int wr,
                       int has_path2, const char *path2, const char *api) {
    uint64_t k = key_of(pid);
    if (machine_mode) {
        image_t *im = map_get(&image, pid, NULL);
        if (im && sc_image_excluded(im->exe)) { st.excluded_image++; return; }
        bridge(k, kind == K_RENAME ? path : NULL);  // an in-scope event: consumed temporaries now matter
    }
    make_relevant(k);
    put_event(ts, k, pid, kind, has_flags, flags, has_rw, rd, wr, path, has_path2, path2, api);
}

// _resolve(pid, dirfd, dir_file, raw, follow_final)
static char *resolve(uint32_t pid, int32_t dirfd, uint64_t dir_file, const char *raw, int follow_final) {
    if (!raw || !*raw) return NULL;
    const char *base = NULL;
    if (!is_abs(raw)) {
        base = dirfd == AT_FDCWD_VALUE ? cwd_of(pid) : map_get(&files, dir_file, NULL);
        if (!base || !*base) return NULL;
    }
    // parts = [p for p in rel.split("/") if p not in ("", ".")]
    size_t nparts = 0;
    const char *only = NULL; size_t only_len = 0;
    for (const char *p = raw; *p;) {
        const char *q = strchr(p, '/');
        size_t len = q ? (size_t)(q - p) : strlen(p);
        if (len && !(len == 1 && p[0] == '.')) { nparts++; only = p; only_len = len; }
        p += len; if (*p == '/') p++;
    }
    char *path;
    if (base && nparts == 1 && !(only_len == 2 && !strncmp(only, "..", 2))) {
        char *name = xstrndup(only, only_len);
        path = pjoin(base, name);
        free(name);
    } else {
        char *full = base ? pjoin(base, raw) : xstrdup(raw);
        char *stripped = xstrdup(full);
        size_t n = strlen(stripped);
        while (n && stripped[n - 1] == '/') stripped[--n] = 0;
        if (!n) { free(stripped); stripped = xstrdup("/"); }
        char *parent, *name;
        psplit(stripped, &parent, &name);
        free(stripped);
        if (!*name || !strcmp(name, ".") || !strcmp(name, "..")) {
            char *r = canon(full);
            free(full); free(parent); free(name);
            return r;
        }
        char *cp = canon(parent);
        path = pjoin(cp, name);
        free(cp); free(full); free(parent); free(name);
    }
    if (follow_final) {
        struct stat sb;
        if (lstat(path, &sb) == 0 && S_ISLNK(sb.st_mode)) { char *r = canon(path); free(path); return r; }
    }
    return path;
}

static char *cstr_field(const unsigned char *data, size_t size, size_t off, size_t n) {  // _cstr(_field_bytes(...))
    if (size <= off) return xstrdup("");
    size_t avail = size - off, m = n < avail ? n : avail;
    const unsigned char *z = memchr(data + off, 0, m);
    return xstrndup((const char *)data + off, z ? (size_t)(z - (data + off)) : m);
}

static FILE *record_fp;  // --record: raw ring payloads, framed as for --replay

// libbpf's ring_buffer__consume() keeps consuming while producers keep producing, so
// under sustained load it never returned and the main loop (handoff to the writer)
// starved.  Past the cycle deadline the callback returns YIELD *before* processing:
// libbpf then stops without advancing past this record, which is redelivered next cycle.
#define YIELD (-EAGAIN)
static int64_t cycle_deadline_ns = INT64_MAX;
static uint64_t yields;

static int process_event(void *ctx, void *vdata, size_t size) {
    (void)ctx;
    if (cycle_deadline_ns != INT64_MAX && mono_ns() > cycle_deadline_ns) { yields++; return YIELD; }
    const unsigned char *data = vdata;
    if (record_fp) { uint32_t n = (uint32_t)size; fwrite(&n, 4, 1, record_fp); fwrite(data, 1, size, record_fp); }
    if (size < sizeof(struct hdr_t)) return 0;
    struct hdr_t e;
    memcpy(&e, data, sizeof e);
    st.received++;
    if (diag_discard) return 0;
    uint32_t pid = e.tgid;
    uint32_t typ = e.type;
    int64_t ts = (int64_t)e.ts_ns + clock_offset;
    if (e.truncated & 1) st.truncated_paths++;
    if (e.truncated & 2) st.unreadable_paths++;

    if (typ == EV_OPEN) {
        char *raw = cstr_field(data, size, OFF_PATH, PATH_N);
        if (raw[0] != '/' || e.truncated) { map_pop(&files, e.file, NULL); st.filtered++; free(raw); return 0; }
        char *path = pnormpath(raw);
        free(raw);
        int is_dir = e.fd == 1;
        if (is_dir || within_ws(path, capture_all) || is_temp(path)) {
            map_put(&files, e.file, NULL, xstrdup(path));
            if (!is_dir) {  // ebpf_bcc._file_id: kernel identity (dev major:minor, inode, generation)
                char id[96]; uint32_t dev = (uint32_t)e.dirfd2;
                snprintf(id, sizeof id, "lnx:%u:%u:%llu:%u", dev >> 20, dev & 0xFFFFF, (unsigned long long)e.file2, (uint32_t)e.dirfd);
                map_put(&fidm, e.file, NULL, xstrdup(id));
            }
        } else { map_pop(&files, e.file, NULL); map_pop(&fidm, e.file, NULL); }
        if (is_dir || !within_ws(path, capture_all)) { st.filtered++; free(path); return 0; }
        if (machine_mode) { free(path); return 0; }  // an open is not evidence in machine mode
        file_event(pid, ts, K_OPEN, path, 1, e.flags, 1, 0, 0, 0, NULL, "ebpf:open");
        free(path);
        return 0;
    }
    if (typ == EV_READ || typ == EV_MMAP_READ || typ == EV_WRITE || typ == EV_MMAP_WRITE) {
        const char *fp = map_get(&files, e.file, NULL);
        if (!fp || !*fp) { st.filtered++; return 0; }
        char *path = xstrdup(fp);  // the map may change below (announce never touches files, but stay safe)
        int is_write = typ == EV_WRITE || typ == EV_MMAP_WRITE;
        int mm = typ == EV_MMAP_READ || typ == EV_MMAP_WRITE;
        cur_fid = map_get(&fidm, e.file, NULL);
        if (within_ws(path, capture_all)) {
            if (!is_write && within_ws(path, 0)) map_set(&read_workspace, key_of(pid), NULL, NULL);
            file_event(pid, ts, K_IO, path, 0, 0, 1, !is_write, is_write, 0, NULL, mm ? "ebpf:mmap" : "ebpf:rw");
        } else if (is_write && map_has(&read_workspace, key_of(pid), NULL) && is_temp(path)) {
            map_put(&derived, 0, path, NULL);
            const char *api = mm ? "ebpf:mmap:derived-temp" : "ebpf:rw:derived-temp";
            if (machine_mode) defer_rec(pid, ts, K_IO, path, 1, 0, 1, 0, NULL, api, NULL, path);
            else file_event(pid, ts, K_IO, path, 0, 0, 1, 0, 1, 0, NULL, api);
        } else if (!is_write && map_has(&derived, 0, path)) {
            map_set(&read_workspace, key_of(pid), NULL, NULL);
            const char *api = mm ? "ebpf:mmap:derived-temp" : "ebpf:rw:derived-temp";
            if (machine_mode) defer_rec(pid, ts, K_IO, path, 1, 1, 0, 0, NULL, api, path, NULL);
            else file_event(pid, ts, K_IO, path, 0, 0, 1, 1, 0, 0, NULL, api);
        } else st.filtered++;
        cur_fid = NULL;
        free(path);
        return 0;
    }
    if (typ == EV_FORK) {
        uint32_t parent = e.aux_pid;
        seq++;
        uint64_t child_key = (seq << PID_BITS) | pid;
        int has_pk = parent != 0;
        uint64_t parent_key = parent ? key_of(parent) : 0;
        ent_t *pe = map_set(&pkey, pid, NULL, NULL);
        pe->u = child_key;
        const char *pc = parent ? cwd_of(parent) : NULL;
        if (pc && *pc) map_set(&cwdm, pid, NULL, xstrdup(pc));
        else map_pop(&cwdm, pid, NULL);
        image_t *pim = map_get(&image, parent, NULL);
        image_t *im = xmalloc(sizeof *im);
        im->exe = xstrdup(pim ? pim->exe : NULL);
        im->cmd = xstrdup(pim ? pim->cmd : NULL);
        map_set(&image, pid, NULL, im);
        prow_t *r = calloc(1, sizeof *r);
        r->ts = ts; r->pid = child_key; r->os_pid = pid;
        r->has_ppid = parent != 0; r->ppid = parent;
        r->has_parent_key = has_pk; r->parent_key = parent_key;
        r->exe = xstrdup(im->exe); r->cwd = xstrdup(map_get(&cwdm, pid, NULL)); r->command = xstrdup(im->cmd);
        { char u[32]; snprintf(u, sizeof u, "uid:%u", e.flags); r->user = xstrdup(u); }
        record_process(r);
        return 0;
    }
    if (typ == EV_EXEC) {
        uint64_t k = key_of(pid);
        char *filename = cstr_field(data, size, OFF_PATH, PATH_N);
        char *exe = *filename ? resolve(pid, AT_FDCWD_VALUE, 0, filename, 1) : NULL;
        free(filename);
        if (!exe || !*exe) { free(exe); exe = clean_link(safe_proc_link(pid, "exe")); }
        int n = e.fd < 0 ? 0 : e.fd > PATH_N - 1 ? PATH_N - 1 : e.fd;
        size_t avail = size > OFF_PATH2 ? size - OFF_PATH2 : 0;
        size_t m = (size_t)n < avail ? (size_t)n : avail;
        char **argv; size_t argc = split_argv(data + OFF_PATH2, m, &argv);
        char *command = argc ? redact_cmdline(argv, argc) : xstrdup(exe);
        free_argv(argv, argc);
        image_t *im = xmalloc(sizeof *im);
        im->exe = xstrdup(exe); im->cmd = xstrdup(command);
        map_set(&image, pid, NULL, im);
        uint32_t ppid = e.aux_pid;
        prow_t *r = calloc(1, sizeof *r);
        r->ts = ts; r->pid = k; r->os_pid = pid;
        r->has_ppid = ppid != 0; r->ppid = ppid;
        if (ppid) { ent_t *pk = map_find(&pkey, ppid, NULL); r->has_parent_key = 1; r->parent_key = pk ? (int64_t)pk->u : ppid; }
        r->exe = xstrdup(exe); r->cwd = xstrdup(cwd_of(pid)); r->command = command;
        { char u[32]; snprintf(u, sizeof u, "uid:%u", e.flags); r->user = xstrdup(u); }
        record_process(r);
        record_exec(ts, k, pid, exe);
        free(exe);
        return 0;
    }
    if (typ == EV_EXIT) {
        ent_t *pk = map_find(&pkey, pid, NULL);
        if (pk && !map_has(&relevant, pk->u, NULL)) map_pop(&pending_exec, pk->u, NULL);
        map_pop(&cwdm, pid, NULL);
        map_pop(&image, pid, NULL);
        return 0;
    }
    if (typ == EV_CHDIR) {
        char *raw = cstr_field(data, size, OFF_PATH, PATH_N);
        char *c = resolve(pid, AT_FDCWD_VALUE, 0, raw, 1);
        free(raw);
        if (c && *c) map_set(&cwdm, pid, NULL, c); else free(c);
        return 0;
    }
    if (typ == EV_FCHDIR) {
        const char *c = map_get(&files, e.file, NULL);
        if (c && *c) map_set(&cwdm, pid, NULL, xstrdup(c));
        else map_pop(&cwdm, pid, NULL);
        return 0;
    }
    if (typ == EV_RENAME) {
        char *r1 = cstr_field(data, size, OFF_PATH, PATH_N), *r2 = cstr_field(data, size, OFF_PATH2, PATH_N);
        char *a = resolve(pid, e.dirfd, e.file, r1, 0);
        char *b = resolve(pid, e.dirfd2, e.file2, r2, 0);
        free(r1); free(r2);
        int a_derived = a && map_has(&derived, 0, a);
        if (!(capture_all || within_ws(a, 0) || within_ws(b, 0) || a_derived)) {
            st.filtered++; free(a); free(b); return 0;
        }
        if (a_derived && b && *b && is_temp(b)) map_put(&derived, 0, b, NULL);
        int defer_it = machine_mode && a_derived && !within_ws(a, 0) && !within_ws(b, 0);
        if (a && *a && b && *b) {  // keep file-pointer paths consistent with the move
            size_t al = strlen(a);
            for (ent_t *x = files.head; x; x = x->next) {
                char *p = x->v;
                if (!strcmp(p, a)) { x->v = xstrdup(b); free(p); }
                else if (!strncmp(p, a, al) && p[al] == '/') {
                    buf_t o = {0}; b_str(&o, b); b_str(&o, p + al);
                    x->v = b_take(&o); free(p);
                }
            }
        }
        if (defer_it) defer_rec(pid, ts, K_RENAME, a, 0, 0, 0, 1, b, "ebpf:rename", a, b);
        else file_event(pid, ts, K_RENAME, a, 0, 0, 0, 0, 0, 1, b, "ebpf:rename");
        free(a); free(b);
        return 0;
    }
    if (typ == EV_UNLINK) {
        char *raw = cstr_field(data, size, OFF_PATH, PATH_N);
        char *a = resolve(pid, e.dirfd, e.file, raw, 0);
        free(raw);
        if (a && map_has(&derived, 0, a)) {
            map_pop(&derived, 0, a);
            if (machine_mode) defer_rec(pid, ts, K_UNLINK, a, 0, 0, 0, 0, NULL, "ebpf:unlink:derived-temp", NULL, NULL);
            else file_event(pid, ts, K_UNLINK, a, 0, 0, 0, 0, 0, 0, NULL, "ebpf:unlink:derived-temp");
        } else if (!within_ws(a, capture_all)) st.filtered++;
        else file_event(pid, ts, K_UNLINK, a, 0, 0, 0, 0, 0, 0, NULL, "ebpf:unlink");
        free(a);
        return 0;
    }
    return 0;
}

// ---------------------------------------------------------------- writer child (SQLite as the workspace owner)
static int read_full(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return got ? -1 : 0;
        got += r;
    }
    return 1;
}
static char *norm_for_store(const char *p, uint32_t n) {  // store.normalize: normpath(abspath(path))
    char *s = xstrndup(p, n), *r = pabspath(s);
    free(s);
    return r;
}
static int sq_ok(sqlite3 *db, int rc, const char *what) {
    if (rc == SQLITE_OK || rc == SQLITE_DONE || rc == SQLITE_ROW) return 1;
    fprintf(stderr, "whyfs-collect writer: %s: %s\n", what, sqlite3_errmsg(db));
    return 0;
}
static void bind_text_or_null(sqlite3_stmt *s, int i, const char *p, uint32_t n) {
    if (p) sqlite3_bind_text(s, i, p, (int)n, SQLITE_TRANSIENT); else sqlite3_bind_null(s, i);
}
static int writer_main(const char *root, int rfd, int reply_fd, long uid, long gid) {
    if (uid >= 0) {
        if (setgroups(0, NULL) || setgid((gid_t)gid) || setuid((uid_t)uid)) { perror("whyfs-collect writer: privilege drop"); return 1; }
        if (getuid() != (uid_t)uid || geteuid() != (uid_t)uid || getgid() != (gid_t)gid) { fprintf(stderr, "privilege drop failed\n"); return 1; }
        umask(077);
    }
    // Refuse a symlinked state directory or database file (store._check_state_paths).
    char dir[PATH_MAX], db_path[PATH_MAX + 16];
    snprintf(dir, sizeof dir, "%s/.whyfs", root);
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) { fprintf(stderr, "whyfs-collect writer: refusing state directory %s: %s\n", dir, strerror(errno)); return 1; }
    const char *names[] = {"whyfs.db", "whyfs.db-wal", "whyfs.db-shm", "whyfs.db-journal"};
    for (int i = 0; i < 4; i++) {
        struct stat sb;
        if (fstatat(dfd, names[i], &sb, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(sb.st_mode)) {
            fprintf(stderr, "whyfs-collect writer: refusing symlinked database file %s/%s\n", dir, names[i]);
            return 1;
        }
    }
    close(dfd);
    snprintf(db_path, sizeof db_path, "%s/whyfs.db", dir);
    sqlite3 *db;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, NULL) != SQLITE_OK) {
        fprintf(stderr, "whyfs-collect writer: open %s: %s\n", db_path, sqlite3_errmsg(db));
        return 1;
    }
    sqlite3_busy_timeout(db, 30000);
    sqlite3_exec(db, "PRAGMA synchronous=NORMAL", 0, 0, 0);
    sqlite3_stmt *sp, *se;
    if (!sq_ok(db, sqlite3_prepare_v2(db,
            "INSERT INTO processes(run_id,pid,ppid,exe,cwd,command,source,first_seen_ns,os_pid,parent_key,user) VALUES(?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(run_id,pid) DO UPDATE SET ppid=COALESCE(excluded.ppid,processes.ppid), user=COALESCE(excluded.user,processes.user),"
            " os_pid=COALESCE(excluded.os_pid,processes.os_pid), parent_key=COALESCE(excluded.parent_key,processes.parent_key),"
            " exe=COALESCE(excluded.exe,processes.exe), cwd=COALESCE(excluded.cwd,processes.cwd),"
            " command=COALESCE(excluded.command,processes.command), source=COALESCE(excluded.source,processes.source)",
            -1, &sp, 0), "prepare processes") ||
        !sq_ok(db, sqlite3_prepare_v2(db,
            "INSERT INTO events(run_id,ts_ns,pid,ppid,kind,path,path2,is_read,is_write,flags,api,source,os_pid,file_id)"
            " VALUES(?,?,?,NULL,?,?,?,?,?,?,?,?,?,?)", -1, &se, 0), "prepare events"))
        return 1;
    uint64_t rows = 0, batches = 0, max_batch = 0;
    int failed = 0, eof = 0;
    unsigned char *buf = NULL; size_t cap = 0;
    while (!eof && !failed) {
        uint32_t hdr[2];
        int r = read_full(rfd, hdr, 8);
        if (r <= 0) break;
        if (!sq_ok(db, sqlite3_exec(db, "BEGIN", 0, 0, 0), "begin")) { failed = 1; break; }
        uint64_t in_tx = 0;
        int64_t tx_start = mono_ns();
        for (;;) {  // what is already queued joins this transaction, bounded like the Python writer
                    // (512 records / 100 ms there): a continuous inflow must still commit
            if (hdr[0] > cap) { cap = hdr[0]; buf = xrealloc(buf, cap); }
            if (read_full(rfd, buf, hdr[0]) <= 0) { failed = 1; break; }
            rd_t rd = {buf, buf + hdr[0]};
            while (rd.p < rd.e && !failed) {
                uint8_t t = r_u8(&rd);
                int64_t ts = r_i64(&rd), pid = r_i64(&rd), os_pid = r_i64(&rd);
                if (t == 'P') {
                    int hp = r_u8(&rd); int64_t pp = r_i64(&rd); int hk = r_u8(&rd); int64_t pk = r_i64(&rd);
                    uint32_t l1, l2, l3, l4; const char *exe = r_str(&rd, &l1), *cwd = r_str(&rd, &l2), *cmd = r_str(&rd, &l3);
                    const char *user = r_str(&rd, &l4);
                    bind_text_or_null(sp, 11, user, l4);
                    sqlite3_bind_text(sp, 1, run_id, -1, SQLITE_STATIC);
                    sqlite3_bind_int64(sp, 2, pid);
                    if (hp) sqlite3_bind_int64(sp, 3, pp); else sqlite3_bind_null(sp, 3);
                    bind_text_or_null(sp, 4, exe, l1); bind_text_or_null(sp, 5, cwd, l2); bind_text_or_null(sp, 6, cmd, l3);
                    sqlite3_bind_text(sp, 7, "ebpf", -1, SQLITE_STATIC);
                    sqlite3_bind_int64(sp, 8, ts);
                    sqlite3_bind_int64(sp, 9, os_pid);
                    if (hk) sqlite3_bind_int64(sp, 10, pk); else sqlite3_bind_null(sp, 10);
                    if (!sq_ok(db, sqlite3_step(sp), "insert process")) failed = 1;
                    sqlite3_reset(sp);
                } else {
                    int kind = r_u8(&rd); int hf = r_u8(&rd); int64_t fl = r_i64(&rd);
                    int hrw = r_u8(&rd), rdv = r_u8(&rd), wrv = r_u8(&rd);
                    uint32_t l1, l2, l3; const char *path = r_str(&rd, &l1), *path2 = r_str(&rd, &l2), *api = r_str(&rd, &l3);
                    r_u8(&rd);
                    uint32_t l5; const char *fid = r_str(&rd, &l5);
                    bind_text_or_null(se, 13, fid, l5);
                    char *np = path && l1 ? norm_for_store(path, l1) : NULL;
                    char *np2 = path2 && l2 ? norm_for_store(path2, l2) : NULL;
                    sqlite3_bind_text(se, 1, run_id, -1, SQLITE_STATIC);
                    sqlite3_bind_int64(se, 2, ts);
                    sqlite3_bind_int64(se, 3, pid);
                    sqlite3_bind_text(se, 4, KIND_NAME[kind], -1, SQLITE_STATIC);
                    bind_text_or_null(se, 5, np, np ? (uint32_t)strlen(np) : 0);
                    bind_text_or_null(se, 6, np2, np2 ? (uint32_t)strlen(np2) : 0);
                    sqlite3_bind_int(se, 7, hrw && rdv);
                    sqlite3_bind_int(se, 8, hrw && wrv);
                    if (hf) sqlite3_bind_int64(se, 9, fl); else sqlite3_bind_null(se, 9);
                    bind_text_or_null(se, 10, api, l3);
                    sqlite3_bind_text(se, 11, "ebpf", -1, SQLITE_STATIC);
                    sqlite3_bind_int64(se, 12, os_pid);
                    if (!sq_ok(db, sqlite3_step(se), "insert event")) failed = 1;
                    sqlite3_reset(se);
                    free(np); free(np2);
                }
            }
            in_tx += hdr[1];
            if (failed) break;
            if (in_tx >= 4096 || mono_ns() - tx_start >= 100000000LL) break;
            struct pollfd p = {rfd, POLLIN, 0};
            if (poll(&p, 1, 0) <= 0 || !(p.revents & (POLLIN | POLLHUP))) break;
            r = read_full(rfd, hdr, 8);
            if (r <= 0) { eof = 1; break; }
        }
        if (failed) { sqlite3_exec(db, "ROLLBACK", 0, 0, 0); break; }
        if (!sq_ok(db, sqlite3_exec(db, "COMMIT", 0, 0, 0), "commit")) { failed = 1; break; }
        rows += in_tx; batches++; if (in_tx > max_batch) max_batch = in_tx;
    }
    sqlite3_finalize(sp); sqlite3_finalize(se);
    sqlite3_close(db);
    char line[128];
    int n = snprintf(line, sizeof line, "%llu %llu %llu %d\n", (unsigned long long)rows, (unsigned long long)batches,
                     (unsigned long long)max_batch, failed);
    if (write(reply_fd, line, n) < 0) return 1;
    return failed;
}

static pid_t writer_pid = -1;
static int writer_reply = -1;
static void start_writer(const char *root, long uid, long gid) {
    int req[2], rep[2];
    if (pipe2(req, O_CLOEXEC) || pipe2(rep, O_CLOEXEC)) die("pipe: %s", strerror(errno));
    fcntl(req[1], F_SETPIPE_SZ, 1 << 20);  // best effort: a larger in-kernel queue
    pid_t p = fork();
    if (p < 0) die("fork: %s", strerror(errno));
    if (p == 0) {
        close(req[1]); close(rep[0]);
        signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN);  // exits at EOF, after the parent's final drain
        _exit(writer_main(root, req[0], rep[1], uid, gid));
    }
    close(req[0]); close(rep[1]);
    writer_fd = req[1]; writer_reply = rep[0]; writer_pid = p;
    fcntl(writer_fd, F_SETFL, O_NONBLOCK);
}

// ---------------------------------------------------------------- main
static volatile sig_atomic_t stop_flag, stats_flag;
static void on_sig(int s) { (void)s; stop_flag = 1; }
static void on_usr1(int s) { (void)s; stats_flag = 1; }
static void print_stats(unsigned long long w_rows, unsigned long long w_batches, unsigned long long w_max, int w_failed) {
    printf("{\"submitted\":%llu,\"filtered\":%llu,\"unresolved_fd\":%llu,\"truncated_paths\":%llu,\"kernel_drops\":%llu,"
           "\"queue_drops\":%llu,\"received\":%llu,\"proc_fallbacks\":%llu,\"unreadable_paths\":%llu,\"excluded_image\":%llu,"
           "\"bridge_evicted\":%llu,"
           "\"writer_rows\":%llu,\"writer_batches\":%llu,\"writer_max_batch\":%llu,\"writer_failed\":%d,"
           "\"pending_exec\":%zu,\"consumer_yields\":%llu}\n",
           (unsigned long long)st.submitted, (unsigned long long)st.filtered, (unsigned long long)st.unresolved_fd,
           (unsigned long long)st.truncated_paths, (unsigned long long)st.kernel_drops, (unsigned long long)st.queue_drops,
           (unsigned long long)st.received, (unsigned long long)st.proc_fallbacks, (unsigned long long)st.unreadable_paths,
           (unsigned long long)st.excluded_image, (unsigned long long)st.bridge_evicted, w_rows, w_batches, w_max, w_failed,
           pending_exec.count, (unsigned long long)yields);
    fflush(stdout);
}

int main(int argc, char **argv) {
    int ring_fd = -1, drop_fd = -1;
    const char *root = NULL, *replay = NULL;
    long uid = -1, gid = -1;
    int have_offset = 0;
    char *seeds[64]; int nseeds = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
#define ARG(name) (!strcmp(a, name) && v && (i++, 1))
        if (ARG("--ring-fd")) ring_fd = atoi(v);
        else if (ARG("--drop-fd")) drop_fd = atoi(v);
        else if (ARG("--root")) root = v;
        else if (ARG("--run-id")) run_id = v;
        else if (ARG("--temp-root")) { if (n_temp_roots < 8) temp_roots[n_temp_roots++] = mkroot(v); }
        else if (ARG("--uid")) uid = atol(v);
        else if (ARG("--gid")) gid = atol(v);
        else if (ARG("--replay")) replay = v;
        else if (ARG("--record")) { record_fp = fopen(v, "wbx"); if (!record_fp) die("record %s: %s", v, strerror(errno)); }
        else if (ARG("--seed")) { if (nseeds < 64) seeds[nseeds++] = (char *)v; }
        else if (ARG("--clock-offset")) { clock_offset = atoll(v); have_offset = 1; }
        else if (!strcmp(a, "--capture-all")) capture_all = 1;
        else if (!strcmp(a, "--machine")) { machine_mode = 1; max_ancestors = MACHINE_MAX_ANCESTORS; }
        else if (ARG("--scope")) { if (sc_load(v) < 0) die("cannot read scope file %s", v); }
        else if (ARG("--scope-classify")) {  // test hook: scope.Scope.classify over the rules loaded so far
            int c = sc_classify(v); fputs(c == SC_IN ? "in" : c == SC_TEMP ? "temp" : "out", stdout); return 0;
        }
        else if (ARG("--scope-image")) { fputs(sc_image_excluded(v) ? "1" : "0", stdout); return 0; }
        else if (!strcmp(a, "--emit")) emit_json = 1;
        else if (!strcmp(a, "--diag-discard")) diag_discard = 1;
        else if (!strcmp(a, "--diag-no-store")) diag_nostore = 1;
        else if (!strcmp(a, "--flush-immediate")) flush_immediate = 1;
        else if (!strcmp(a, "--redact-text") && v) { char *r = redact_text(v); fputs(r, stdout); free(r); return 0; }  // test hooks
        else if (!strcmp(a, "--redact-argv")) { char *r = redact_cmdline(argv + i + 1, (size_t)(argc - i - 1)); fputs(r, stdout); free(r); return 0; }
        else die("unknown argument %s", a);
#undef ARG
    }
    if (!root) die("--root required");
    if ((uid < 0) != (gid < 0)) die("--uid and --gid go together");
    ws_root = mkroot(root);
    { char *sd = pjoin(root, ".whyfs"); state_root = mkroot(sd); free(sd); }
    if (!have_offset) {
        struct timespec rt, mt;
        clock_gettime(CLOCK_REALTIME, &rt); clock_gettime(CLOCK_MONOTONIC, &mt);
        clock_offset = ((int64_t)rt.tv_sec * 1000000000LL + rt.tv_nsec) - ((int64_t)mt.tv_sec * 1000000000LL + mt.tv_nsec);
    }
    map_init(&files, 0, FILES_LIMIT, free);
    map_init(&fidm, 0, FILES_LIMIT, free);
    map_init(&cwdm, 0, 0, free);
    map_init(&image, 0, 0, image_free);
    map_init(&pkey, 0, 0, NULL);
    map_init(&proc_rows, 0, PROC_ROWS_LIMIT, prow_free);
    map_init(&pending_exec, 0, 0, pexecs_free);
    map_init(&relevant, 0, 0, NULL);
    map_init(&read_workspace, 0, 0, NULL);
    map_init(&derived, 1, DERIVED_LIMIT, NULL);
    map_init(&deferred, 0, 0, dlist_free);
    map_init(&temp_writers, 1, DEFER_LIMIT, wlist_free);
    for (int i = 0; i < nseeds; i++) {  // tests: a pre-existing process with a known cwd
        char *c = strchr(seeds[i], ':');
        if (!c) die("--seed PID:CWD");
        uint32_t p = (uint32_t)atol(seeds[i]);
        map_set(&pkey, p, NULL, NULL)->u = p;
        map_set(&cwdm, p, NULL, xstrdup(c + 1));
    }
    signal(SIGPIPE, SIG_IGN);
    emit_fp = stdout;
    if (!emit_json && !diag_discard && !diag_nostore) start_writer(root, uid, gid);

    if (replay) {
        FILE *f = strcmp(replay, "-") ? fopen(replay, "rb") : stdin;
        if (!f) die("replay %s: %s", replay, strerror(errno));
        unsigned char *rec = xmalloc(80 + 2 * PATH_N + 16);
        uint32_t n;
        while (fread(&n, 4, 1, f) == 1) {
            if (n > 80 + 2 * PATH_N + 16) die("replay record too large");
            if (fread(rec, 1, n, f) != n) die("truncated replay record");
            process_event(NULL, rec, n);
        }
        free(rec);
        flush_pending();
    } else {
        if (ring_fd < 0) die("--ring-fd or --replay required");
        // Never outlive the daemon that holds the BPF programs.
        pid_t parent = getppid();
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (getppid() != parent) stop_flag = 1;
        struct ring_buffer *rb = ring_buffer__new(ring_fd, process_event, NULL, NULL);
        if (!rb) die("ring_buffer__new: %s", strerror(errno));
        struct sigaction sa = {0};
        sa.sa_handler = on_sig;
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
        struct sigaction su = {0};
        su.sa_handler = on_usr1;
        sigaction(SIGUSR1, &su, NULL);  // counters snapshot on stdout (diagnostics)
        printf("{\"ready\":true,\"pid\":%d,\"writer_pid\":%d}\n", getpid(), (int)writer_pid);
        fflush(stdout);
        while (!stop_flag) {
            // Kernel side submits without wakeups (see wf_wake): wait up to 50 ms for
            // a forced wakeup, then drain whatever has been committed.
            cycle_deadline_ns = mono_ns() + 100000000LL;  // poll waits <= 50 ms, then drains
            ring_buffer__poll(rb, 50);
            cycle_deadline_ns = mono_ns() + 50000000LL;
            ring_buffer__consume(rb);
            cycle_deadline_ns = INT64_MAX;
            flush_pending();
            maybe_pump();
            if (stats_flag) { stats_flag = 0; print_stats(0, 0, 0, 0); }
        }
        for (int i = 0; i < 1000; i++) {  // drain: everything already committed
            uint64_t before = st.received;
            ring_buffer__consume(rb);
            if (st.received == before) break;
        }
        flush_pending();
        if (drop_fd >= 0) {
            uint32_t k = 0; uint64_t v = 0;
            if (bpf_map_lookup_elem(drop_fd, &k, &v) == 0) st.kernel_drops += v;
        }
        ring_buffer__free(rb);
    }
    if (record_fp) fclose(record_fp);
    unsigned long long w_rows = 0, w_batches = 0, w_max = 0;
    int w_failed = 0;
    if (writer_pid > 0) {
        fcntl(writer_fd, F_SETFL, 0);
        pump_output(1);
        close(writer_fd);
        char line[128] = {0};
        ssize_t r = read(writer_reply, line, sizeof line - 1);
        if (r <= 0 || sscanf(line, "%llu %llu %llu %d", &w_rows, &w_batches, &w_max, &w_failed) != 4) w_failed = 1;
        int status = 0;
        waitpid(writer_pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status)) w_failed = 1;
    }
    if (writer_broken) w_failed = 1;
    print_stats(w_rows, w_batches, w_max, w_failed);
    fflush(stdout);
    return w_failed ? 1 : 0;
}
