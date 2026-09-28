// whyfs-collect-win: native Windows collector for whyfs (ETW -> canonical whyfs records).
//
// Kernel sources (verified on this Windows build: native/windows/probe/FINDINGS.md):
//   session "<name>"      Microsoft-Windows-Kernel-File (Create, Cleanup, Close, Read, Write,
//                         QueryInformation, DeletePath, RenamePath, NameDelete)
//                         Microsoft-Windows-Kernel-Process (ProcessStart/Stop: image path)
//   session "<name>-sys"  system logger: Process (command line, parent, user SID, rundown
//                         of existing processes) + VAMAP (memory-mapped file views)
// Two real-time sessions need two ProcessTrace threads; their records are merged in
// timestamp order through a reorder window before the event model sees them.
//
// The event model is the whyfs model used on Linux (ebpf_bcc.BCCCollector._process_event /
// whyfs-collect.c): per-run process keys and parent links, file object -> path, first
// read/write per open per process, rename rewrites, derived temporaries, relevance +
// bounded ancestors, argv redaction.  Output: the same canonical records and SQLite rows.
//
// Usage
//   live:   whyfs-collect-win --root DIR --run-id ID --sqlite PATH\sqlite3.dll
//                             [--temp-root DIR]... [--user-sid SID] [--capture-all]
//                             [--record FILE] [--session NAME]
//   replay: whyfs-collect-win --replay FILE --root DIR (--emit | --sqlite DLL) ...
// Windows-specific: paths are compared case-insensitively (ASCII, like SQLite NOCASE),
// 8.3 short names are expanded, cwd is not observable.  Only processes of --user-sid
// (the requesting user) are recorded.
#define _CRT_SECURE_NO_WARNINGS
#define INITGUID
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <sddl.h>
#include <shellapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "shell32.lib")

// ---------------------------------------------------------------- utilities
static void die(const char *msg) { fprintf(stderr, "whyfs-collect-win: %s\n", msg); exit(2); }
static void *xmalloc(size_t n) { void *p = malloc(n ? n : 1); if (!p) die("out of memory"); return p; }
static void *xrealloc(void *p, size_t n) { p = realloc(p, n ? n : 1); if (!p) die("out of memory"); return p; }
static char *xstrdup(const char *s) { if (!s) return NULL; size_t n = strlen(s) + 1; return memcpy(xmalloc(n), s, n); }
static char *xstrndup(const char *s, size_t n) { char *p = xmalloc(n + 1); memcpy(p, s, n); p[n] = 0; return p; }

typedef struct { char *p; size_t n, cap; } buf_t;
static void b_reserve(buf_t *b, size_t add) { if (b->n + add + 1 > b->cap) { b->cap = (b->n + add + 1) * 2; b->p = xrealloc(b->p, b->cap); } }
static void b_add(buf_t *b, const void *s, size_t n) { b_reserve(b, n); memcpy(b->p + b->n, s, n); b->n += n; b->p[b->n] = 0; }
static void b_str(buf_t *b, const char *s) { b_add(b, s, strlen(s)); }
static void b_ch(buf_t *b, char c) { b_add(b, &c, 1); }
static char *b_take(buf_t *b) { char *p = b->p ? b->p : xstrdup(""); b->p = NULL; b->n = b->cap = 0; return p; }

static char *utf8_from_w(const wchar_t *w, int wlen) {
    if (!w) return NULL;
    int n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, NULL, 0, NULL, NULL);
    char *s = xmalloc((size_t)n + 1);
    WideCharToMultiByte(CP_UTF8, 0, w, wlen, s, n, NULL, NULL);
    s[n] = 0;
    return s;
}
static wchar_t *w_from_utf8(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = xmalloc(sizeof(wchar_t) * (size_t)n);
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}
static char lower_ascii(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }
static int ieq_n(const char *a, const char *b, size_t n) { for (size_t i = 0; i < n; i++) if (lower_ascii(a[i]) != lower_ascii(b[i])) return 0; return 1; }
static int ieq(const char *a, const char *b) { size_t n = strlen(a); return n == strlen(b) && ieq_n(a, b, n); }
static uint64_t hstr_i(const char *s) { uint64_t h = 1469598103934665603ULL; while (*s) { h ^= (unsigned char)lower_ascii(*s++); h *= 1099511628211ULL; } return h; }
static uint64_t mix64(uint64_t k) { k ^= k >> 33; k *= 0xff51afd7ed558ccdULL; k ^= k >> 33; k *= 0xc4ceb9fe1a85ec53ULL; k ^= k >> 33; return k; }

// ---------------------------------------------------------------- hash maps (insertion-ordered, optional bound)
typedef struct ent { struct ent *chain, *prev, *next; uint64_t h, k; char *s; void *v; uint64_t u; } ent_t;
typedef struct { ent_t **b; size_t nb, count, limit; int strkeys; ent_t *head, *tail; void (*free_v)(void *); } map_t;
static void map_init(map_t *m, int strkeys, size_t limit, void (*free_v)(void *)) {
    memset(m, 0, sizeof *m); m->nb = 1024; m->b = calloc(m->nb, sizeof(ent_t *)); if (!m->b) die("out of memory");
    m->strkeys = strkeys; m->limit = limit; m->free_v = free_v;
}
static ent_t *map_find(map_t *m, uint64_t k, const char *s) {
    uint64_t h = m->strkeys ? hstr_i(s) : mix64(k);
    for (ent_t *e = m->b[h & (m->nb - 1)]; e; e = e->chain)
        if (e->h == h && (m->strkeys ? ieq(e->s, s) : e->k == k)) return e;
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
    *pp = e->chain; order_unlink(m, e);
    if (m->free_v && e->v) m->free_v(e->v);
    free(e->s); free(e); m->count--;
}
static void map_grow(map_t *m) {
    size_t nb = m->nb * 2; ent_t **b = calloc(nb, sizeof(ent_t *)); if (!b) die("out of memory");
    for (size_t i = 0; i < m->nb; i++) for (ent_t *e = m->b[i], *n; e; e = n) { n = e->chain; e->chain = b[e->h & (nb - 1)]; b[e->h & (nb - 1)] = e; }
    free(m->b); m->b = b; m->nb = nb;
}
static ent_t *map_set(map_t *m, uint64_t k, const char *s, void *v) {
    ent_t *e = map_find(m, k, s);
    if (e) { if (m->free_v && e->v && e->v != v) m->free_v(e->v); e->v = v; return e; }
    e = calloc(1, sizeof *e); if (!e) die("out of memory");
    e->k = k; e->s = m->strkeys ? xstrdup(s) : NULL; e->h = m->strkeys ? hstr_i(s) : mix64(k); e->v = v;
    e->chain = m->b[e->h & (m->nb - 1)]; m->b[e->h & (m->nb - 1)] = e;
    order_append(m, e);
    if (++m->count > m->nb) map_grow(m);
    return e;
}
static ent_t *map_put(map_t *m, uint64_t k, const char *s, void *v) {
    ent_t *e = map_set(m, k, s, v); order_unlink(m, e); order_append(m, e);
    while (m->limit && m->count > m->limit) map_remove_ent(m, m->head);
    return e;
}
static void *map_get(map_t *m, uint64_t k, const char *s) { ent_t *e = map_find(m, k, s); return e ? e->v : NULL; }
static int map_has(map_t *m, uint64_t k, const char *s) { return map_find(m, k, s) != NULL; }
static void map_pop(map_t *m, uint64_t k, const char *s) { ent_t *e = map_find(m, k, s); if (e) map_remove_ent(m, e); }

// ---------------------------------------------------------------- Windows paths
typedef struct { char *s; size_t n; } root_t;  // canonical DOS path, no trailing separator
static root_t mkroot(const char *s) {
    root_t r; r.s = xstrdup(s); r.n = strlen(r.s);
    while (r.n > 3 && (r.s[r.n - 1] == '\\' || r.s[r.n - 1] == '/')) r.s[--r.n] = 0;
    return r;
}
// path == root or below root (case-insensitive ASCII, component boundary)
static int within(const char *p, const root_t *r) {
    if (!p || !*p) return 0;
    size_t n = strlen(p);
    if (n < r->n || !ieq_n(p, r->s, r->n)) return 0;
    return n == r->n || p[r->n] == '\\' || r->s[r->n - 1] == '\\';
}

typedef struct { char dev[260]; size_t n; char dos[8]; } devmap_t;
static devmap_t devs[64];
static int ndevs;
static void load_devices(void) {
    ndevs = 0;
    wchar_t drive[3] = L"A:", target[1024];
    for (wchar_t c = L'A'; c <= L'Z'; c++) {
        drive[0] = c;
        if (QueryDosDeviceW(drive, target, 1024)) {
            char *t = utf8_from_w(target, -1);
            if (ndevs < 64) { strncpy(devs[ndevs].dev, t, 259); devs[ndevs].n = strlen(devs[ndevs].dev); sprintf(devs[ndevs].dos, "%c:", (char)c); ndevs++; }
            free(t);
        }
    }
}
// NT device path -> DOS path (drive letter or UNC); NULL if not mappable.
static char *dos_path(const char *nt) {
    if (!nt || !*nt) return NULL;
    if (nt[1] == ':') return xstrdup(nt);
    if (!_strnicmp(nt, "\\Device\\Mup\\", 12)) { buf_t o = {0}; b_str(&o, "\\\\"); b_str(&o, nt + 12); return b_take(&o); }
    for (int i = 0; i < ndevs; i++)
        if (!_strnicmp(nt, devs[i].dev, devs[i].n) && (nt[devs[i].n] == '\\' || !nt[devs[i].n])) {
            buf_t o = {0}; b_str(&o, devs[i].dos); b_str(&o, nt[devs[i].n] ? nt + devs[i].n : "\\"); return b_take(&o);
        }
    return NULL;
}
// Normalize a DOS path: collapse "\\", ".", ".."; expand 8.3 short names when present.
// A path component in 8.3 form (BASE~N or BASE~N.EXT, BASE up to 6 characters): only these
// need the file system to recover the long name.  "~$doc.docx" or "file~" do not.
static int has_short_name(const char *p) {
    for (const char *c = p; *c; ) {
        const char *e = c; while (*e && *e != '\\') e++;
        const char *t = memchr(c, '~', (size_t)(e - c));
        if (t && t > c && t - c <= 6 && t + 1 < e && t[1] >= '0' && t[1] <= '9') {
            const char *q = t + 1; while (q < e && *q >= '0' && *q <= '9') q++;
            if (q == e || (*q == '.' && e - q <= 4)) return 1;
        }
        c = *e ? e + 1 : e;
    }
    return 0;
}
static map_t longnames;  // short path -> long path (bounded)
static int norm_needed(const char *p) {  // anything norm_path would change beyond the drive letter's case
    if (strchr(p, '/') || has_short_name(p)) return 1;
    for (const char *q = p + 2; *q; q++) {
        if (q[0] == '\\' && (q[1] == '\\' || q[1] == 0)) return 1;
        if (q[0] == '\\' && q[1] == '.' && (q[2] == '\\' || q[2] == 0 || (q[2] == '.' && (q[3] == '\\' || q[3] == 0)))) return 1;
    }
    return 0;
}
// The long form of a path with 8.3 components, or NULL.  Records are processed after a reorder
// delay, when the file itself may already be gone (renamed away, deleted: atomic saves, temp
// files), so a path that no longer exists is expanded through its longest existing directory
// and keeps its tail as given.  Directory expansions are memoized.
static char *long_name(const char *r) {
    char *hit = map_get(&longnames, 0, r);
    if (hit) return xstrdup(hit);
    size_t n = strlen(r);
    for (size_t cut = n; cut > 3; ) {  // cut: length of the prefix tried (the whole path first)
        char *prefix = xstrndup(r, cut);
        if (!has_short_name(prefix)) { free(prefix); return NULL; }  // the 8.3 part is in the tail
        char *pl = map_get(&longnames, 0, prefix);
        char *lp = pl ? xstrdup(pl) : NULL;
        if (!lp) {
            wchar_t *w = w_from_utf8(prefix), longp[1024];
            DWORD m = GetLongPathNameW(w, longp, 1024);
            free(w);
            if (m > 0 && m < 1024) {
                lp = utf8_from_w(longp, -1);
                map_put(&longnames, 0, prefix, xstrdup(lp));
            }
        }
        free(prefix);
        if (lp) {
            if (cut == n) return lp;
            buf_t o = {0}; b_str(&o, lp); b_str(&o, r + cut);
            free(lp);
            return b_take(&o);
        }
        while (cut > 3 && r[cut - 1] != '\\') cut--;  // drop the last component
        if (cut > 3) cut--;                            // and its separator
    }
    return NULL;
}
static char *norm_path(const char *p) {
    if (!p) return NULL;
    if (p[0] && p[1] == ':' && p[2] == '\\' && !norm_needed(p)) {  // fast path: an already-clean drive path
        char *r = xstrdup(p);
        r[0] = (char)toupper((unsigned char)r[0]);
        return r;
    }
    size_t n = strlen(p);
    buf_t o = {0};
    size_t i = 0;
    if (n >= 2 && p[0] == '\\' && p[1] == '\\') { b_str(&o, "\\\\"); i = 2; }
    else if (n >= 2 && p[1] == ':') { b_ch(&o, (char)toupper((unsigned char)p[0])); b_ch(&o, ':'); i = 2; }
    char **comps = NULL; size_t nc = 0, cap = 0;
    char *copy = xstrdup(p + i);
    for (char *ctx = NULL, *c = strtok_s(copy, "\\/", &ctx); c; c = strtok_s(NULL, "\\/", &ctx)) {
        if (!strcmp(c, ".")) continue;
        if (!strcmp(c, "..")) { if (nc) nc--; continue; }
        if (nc == cap) { cap = cap ? cap * 2 : 16; comps = xrealloc(comps, cap * sizeof *comps); }
        comps[nc++] = c;
    }
    int is_unc = o.n == 2 && o.p[0] == '\\';
    for (size_t k = 0; k < nc; k++) { if (k || !is_unc) b_ch(&o, '\\'); b_str(&o, comps[k]); }
    if (!nc && !is_unc) b_ch(&o, '\\');
    free(comps); free(copy);
    char *r = b_take(&o);
    if (has_short_name(r)) {  // an 8.3 short name component: ask the file system (memoized)
        char *l = long_name(r);
        if (l) { free(r); r = l; }
    }
    return r;
}

// ---------------------------------------------------------------- command lines (argv, redaction, quoting)
static const char *SENSITIVE[] = {"password", "passwd", "token", "secret", "api-key", "apikey", "api_key", "access-key", "access_key", "private-key", "private_key", "credential", "authorization"};
static char *lower_dup(const char *a) { char *l = xstrdup(a); for (char *p = l; *p; p++) *p = lower_ascii(*p); return l; }
// Same rule as ebpf_bcc._redact_cmdline, plus Windows switches: /name value, /name:value,
// /name=value.  Windows programs parse their own raw command line (cmd.exe does not use
// argv rules), so the displayed command is the raw line with only the secret values
// replaced -- never a re-quoted argv, which could change what the command appears to be.
static void replace_all(buf_t *line, const char *secret) {
    size_t sl = strlen(secret);
    if (!sl) return;
    buf_t o = {0};
    const char *p = line->p, *hit;
    while ((hit = strstr(p, secret))) { b_add(&o, p, (size_t)(hit - p)); b_str(&o, "<redacted>"); p = hit + sl; }
    b_str(&o, p);
    free(line->p); *line = o;
}
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
static int rx_is_script_flag(const char *a) {  // redact._is_script_flag: -c -lc ... /c /k -Command
    size_t n = strlen(a);
    if ((n == 2 && (a[0] == '/') && (rx_low(a[1]) == 'c' || rx_low(a[1]) == 'k')) || (n == 8 && rx_ieq(a, "-command", 8))
        || (n == 9 && rx_ieq(a, "--command", 9))) return 1;
    if (n < 2 || n > 5 || a[0] != '-' || rx_low(a[n - 1]) != 'c') return 0;
    for (size_t i = 1; i < n; i++) { char c = rx_low(a[i]); if (c < 'a' || c > 'z') return 0; }
    return 1;
}
static int rx_has_ws(const char *s, size_t n) { for (size_t i = 0; i < n; i++) if (rx_ws(s[i])) return 1; return 0; }
static char *redact_cmdline_w(const wchar_t *cmd) {
    if (!cmd || !*cmd) return NULL;
    buf_t line = {0};
    { char *raw = utf8_from_w(cmd, -1); b_str(&line, raw); free(raw); }
    int argc = 0;
    LPWSTR *argvw = CommandLineToArgvW(cmd, &argc);
    if (!argvw) { char *raw = b_take(&line), *shown = redact_text(raw); free(raw); return shown; }
    int secret_next = 0, script = 0;
    for (int i = 0; i < argc; i++) {
        char *a = utf8_from_w(argvw[i], -1), *low = lower_dup(a);
        if (secret_next) { replace_all(&line, a); secret_next = 0; }
        else if (script) script = 0;  // a shell script is command text: the text pass reads it in the raw line
        else {
            const char *name = low;
            if (name[0] == '-' && name[1] == '-') name += 2;
            else if (name[0] == '/' || name[0] == '-') name += 1;
            int exact = 0;
            for (size_t s = 0; s < sizeof SENSITIVE / sizeof *SENSITIVE; s++) if (!strcmp(name, SENSITIVE[s])) exact = 1;
            char *sep = strpbrk(a, "=:");
            if (!exact) exact = rx_is_switch(a);
            if (exact) secret_next = 1;
            else if (sep && sep != a && sep[1] && !(sep == a + 1 && *sep == ':')  // "C:\..." is a path, not key:value
                     && !rx_has_ws(a, (size_t)(sep - a))) {  // a merged command is left to the text pass
                char *key = lower_dup(a); key[sep - a] = 0;
                int hit = 0;
                for (size_t s = 0; s < sizeof SENSITIVE / sizeof *SENSITIVE; s++) if (strstr(key, SENSITIVE[s])) hit = 1;
                free(key);
                if (hit) replace_all(&line, sep + 1);
            }
        }
        if (!secret_next) script = rx_is_script_flag(a);
        free(low); free(a);
    }
    LocalFree(argvw);
    char *raw = b_take(&line), *shown = redact_text(raw);  // text pass: secrets argv parsing cannot isolate
    free(raw);
    return shown;
}

// ---------------------------------------------------------------- decoded kernel records (the Windows contract)
enum { R_PROC_START = 1, R_PROC_INFO, R_PROC_END, R_CREATE, R_CLEANUP, R_KEYINFO, R_READ, R_WRITE, R_DELETE_PATH,
       R_RENAME_PATH, R_NAME_DELETE, R_MAP, R_CLOSE, R_FO_RESET };
typedef struct {
    int64_t ts;       // wall-clock ns
    uint64_t order;   // arrival order (stable tie-break)
    uint32_t type, pid, ppid, flags, user_ok;
    uint64_t fo, key;
    char *s1;         // DOS path / image path
    char *s2;         // command line (redacted)
    char *s3;         // user SID string (process start/info)
} rec_t;
// Records are recycled through a lock-free pool: the ETW callbacks allocate one per kernel event
// (thousands per second machine-wide), and calloc/free per event was a measurable part of the
// idle cost.  rec_t allocations are 16-byte aligned (MEMORY_ALLOCATION_ALIGNMENT on x64/ARM64).
typedef union { SLIST_ENTRY link; rec_t rec; } rec_slot_t;
static SLIST_HEADER rec_pool;
#define REC_POOL_MAX 65536
static rec_t *rec_alloc(void) {
    rec_slot_t *s = (rec_slot_t *)InterlockedPopEntrySList(&rec_pool);
    if (!s) s = _aligned_malloc(sizeof *s, MEMORY_ALLOCATION_ALIGNMENT);
    if (!s) die("out of memory");
    memset(s, 0, sizeof *s);
    return &s->rec;
}
static void rec_free(rec_t *r) {
    free(r->s1); free(r->s2); free(r->s3);
    if (QueryDepthSList(&rec_pool) < REC_POOL_MAX) InterlockedPushEntrySList(&rec_pool, &((rec_slot_t *)r)->link);
    else _aligned_free(r);
}

// ---------------------------------------------------------------- model state
typedef struct { uint64_t submitted, filtered, unresolved_fo, other_user, received, kernel_lost, queue_drops, unmapped_paths,
                 proc_fallbacks, user_unresolved, foreign_fo, excluded_image, user_late; } stats_t;
static stats_t st;
typedef struct { int64_t ts, pid, os_pid, ppid, parent_key; int has_ppid, has_parent_key; char *exe, *command, *user; } prow_t;
static void prow_free(void *p) { prow_t *r = p; if (r) { free(r->exe); free(r->command); free(r->user); free(r); } }
typedef struct { int64_t ts, pid, os_pid; char *path; } pexec_t;
typedef struct { pexec_t v[16]; int n; } pexecs_t;
static void pexecs_free(void *p) { pexecs_t *x = p; if (x) { for (int i = 0; i < x->n; i++) free(x->v[i].path); free(x); } }
// creator: process key that opened it.  seen: process keys that already reported first read/write.
typedef struct { char *path; uint32_t opts; uint64_t creator; uint64_t seen[4]; uint8_t bits[4]; int nseen; } fobj_t;
static void fobj_free(void *p) { fobj_t *f = p; if (f) { free(f->path); free(f); } }
typedef struct { char *exe, *cmd; } image_t;
static void image_free(void *p) { image_t *i = p; if (i) { free(i->exe); free(i->cmd); free(i); } }

static root_t ws_root, state_root, temp_roots[8];
static int n_temp_roots, capture_all;
static int machine_mode, max_ancestors = 8, live_mode;  // --machine (docs/MACHINE_MODE.md); live: not a replay
static const char *run_id = "run";
static uint64_t seq;
static map_t fobjs, fkeys, pkey, proc_rows, pending_exec, relevant, read_workspace, derived, image, users_ok, early_cmd, users_sid;
#define MAX_ANCESTORS 8

#define SC_NT 1
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
static int sc_classify(const char *path) {
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
static int in_ws(const char *p, int cap_all) {
    if (!p || !*p || within(p, &state_root)) return 0;
    if (machine_mode) return sc_classify(p) == SC_IN;
    return cap_all ? 1 : within(p, &ws_root);
}

// ---------------------------------------------------------------- output: canonical records (same encoding as Linux)
enum { K_OPEN = 1, K_IO, K_RENAME, K_UNLINK, K_EXEC };
static const char *KIND_NAME[] = {"", "open", "io", "rename", "unlink", "exec"};
static buf_t pending; static uint32_t pending_n;
static void w_i64(buf_t *b, int64_t v) { b_add(b, &v, 8); }
static void w_u8(buf_t *b, uint8_t v) { b_add(b, &v, 1); }
static void w_opt(buf_t *b, int has, int64_t v) { w_u8(b, (uint8_t)has); w_i64(b, has ? v : 0); }
static void w_str(buf_t *b, const char *s) { uint32_t n = s ? (uint32_t)strlen(s) : 0xffffffffu; b_add(b, &n, 4); if (s) b_add(b, s, n); }
static void flush_pending(void);
#define HANDOFF_BATCH 512
static void put_bump(void) { if (++pending_n >= HANDOFF_BATCH) flush_pending(); }
static void put_process(const prow_t *r) {
    w_u8(&pending, 'P'); w_i64(&pending, r->ts); w_i64(&pending, r->pid); w_i64(&pending, r->os_pid);
    w_opt(&pending, r->has_ppid, r->ppid); w_opt(&pending, r->has_parent_key, r->parent_key);
    w_str(&pending, r->exe); w_str(&pending, NULL); w_str(&pending, r->command); w_str(&pending, r->user);
    put_bump();
}
static const char *cur_fid;  // identity of the file of the I/O record being written (first writes, machine mode)
static void put_event(int64_t ts, int64_t key, int64_t os_pid, int kind, int has_flags, int64_t flags, int has_rw, int rd, int wr,
                      const char *path, int has_path2, const char *path2, const char *api) {
    w_u8(&pending, 'E'); w_i64(&pending, ts); w_i64(&pending, key); w_i64(&pending, os_pid); w_u8(&pending, (uint8_t)kind);
    w_opt(&pending, has_flags, flags); w_u8(&pending, (uint8_t)has_rw); w_u8(&pending, (uint8_t)rd); w_u8(&pending, (uint8_t)wr);
    w_str(&pending, path); w_str(&pending, path2); w_str(&pending, api); w_u8(&pending, (uint8_t)has_path2);
    w_str(&pending, kind == K_IO || kind == K_RENAME ? cur_fid : NULL);
    put_bump();
}

// ---- model (port of the whyfs event model, Windows flavour)
static void record_process(prow_t *row) {  // takes ownership
    prow_t *old = map_get(&proc_rows, (uint64_t)row->pid, NULL);
    if (old) {
        prow_t *m = calloc(1, sizeof *m);
        *m = *old;
        m->exe = xstrdup(row->exe ? row->exe : old->exe);
        m->command = xstrdup(row->command ? row->command : old->command);
        m->user = xstrdup(row->user ? row->user : old->user);
        if (row->has_ppid) { m->has_ppid = 1; m->ppid = row->ppid; }
        if (row->has_parent_key) { m->has_parent_key = 1; m->parent_key = row->parent_key; }
        m->os_pid = row->os_pid; m->ts = old->ts;
        prow_free(row); row = m;
    }
    map_put(&proc_rows, (uint64_t)row->pid, NULL, row);
    if (map_has(&relevant, (uint64_t)row->pid, NULL)) put_process(row);
}
static void record_exec(int64_t ts, uint64_t k, uint32_t pid, const char *exe) {
    if (map_has(&relevant, k, NULL)) { put_event(ts, (int64_t)k, pid, K_EXEC, 0, 0, 0, 0, 0, exe, 0, NULL, "etw:exec"); return; }
    ent_t *e = map_find(&pending_exec, k, NULL);
    if (!e) e = map_set(&pending_exec, k, NULL, calloc(1, sizeof(pexecs_t)));
    pexecs_t *l = e->v;
    if (l->n < 16) { l->v[l->n].ts = ts; l->v[l->n].pid = (int64_t)k; l->v[l->n].os_pid = pid; l->v[l->n].path = xstrdup(exe); l->n++; }
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
            for (int j = 0; j < l->n; j++) put_event(l->v[j].ts, l->v[j].pid, l->v[j].os_pid, K_EXEC, 0, 0, 0, 0, 0, l->v[j].path, 0, NULL, "etw:exec");
            map_remove_ent(&pending_exec, pe);
        }
        has_k = row && row->has_parent_key;
        if (has_k) k = (uint64_t)row->parent_key;
    }
}
// Existing process (started before the collector): announced once, like Linux /proc.
static char *proc_image(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return NULL;
    wchar_t buf[1024]; DWORD n = 1024; char *r = NULL;
    if (QueryFullProcessImageNameW(h, 0, buf, &n)) r = utf8_from_w(buf, (int)n);
    CloseHandle(h);
    return r;
}
static uint64_t key_of(uint32_t pid, int64_t ts);
static void announce_existing(uint32_t pid, int64_t ts) {
    char *exe = proc_image(pid);
    if (exe) st.proc_fallbacks++;
    image_t *im = xmalloc(sizeof *im); im->exe = xstrdup(exe); im->cmd = NULL;
    map_set(&image, pid, NULL, im);
    prow_t *r = calloc(1, sizeof *r);
    r->ts = ts; r->pid = pid; r->os_pid = pid; r->exe = exe;
    if (live_mode) {  // a process that predates the collector: its OS start time
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        FILETIME c, e, k, u;
        if (h && GetProcessTimes(h, &c, &e, &k, &u))
            r->ts = (int64_t)(((((uint64_t)c.dwHighDateTime) << 32) | c.dwLowDateTime) - 116444736000000000ULL) * 100;
        if (h) CloseHandle(h);
    }
    r->user = xstrdup(map_get(&users_sid, pid, NULL));
    record_process(r);
}
static uint64_t key_of(uint32_t pid, int64_t ts) {
    ent_t *e = map_find(&pkey, pid, NULL);
    if (e) return e->u;
    e = map_set(&pkey, pid, NULL, NULL); e->u = pid;
    announce_existing(pid, ts);
    return pid;
}
static int user_ok(uint32_t pid) {  // privacy: only the requesting user's processes are recorded
    ent_t *e = map_find(&users_ok, pid, NULL);
    return e ? (int)e->u : -1;  // -1: unknown (started before rundown); treated as not ok
}
static void file_event(uint32_t pid, int64_t ts, int kind, const char *path, int has_rw, int rd, int wr, int has_path2,
                       const char *path2, const char *api, int has_flags, int64_t flags) {
    uint64_t k = key_of(pid, ts);
    if (machine_mode) {
        image_t *im = map_get(&image, pid, NULL);
        if (im && sc_image_excluded(im->exe)) { st.excluded_image++; return; }
    }
    make_relevant(k);
    put_event(ts, (int64_t)k, pid, kind, has_flags, flags, has_rw, rd, wr, path, has_path2, path2, api);
}
// first read / first write per (open file object, process): like Linux io_seen, reset by each Create
static int first_io(fobj_t *f, uint64_t k, int is_write) {
    uint8_t bit = is_write ? 2 : 1;
    for (int i = 0; i < f->nseen; i++) if (f->seen[i] == k) { if (f->bits[i] & bit) return 0; f->bits[i] |= bit; return 1; }
    if (f->nseen < 4) { f->seen[f->nseen] = k; f->bits[f->nseen++] = bit; return 1; }
    // more than 4 processes share this open: rotate (rarely duplicates a record, never loses one)
    memmove(f->seen, f->seen + 1, 3 * sizeof f->seen[0]); memmove(f->bits, f->bits + 1, 3);
    f->seen[3] = k; f->bits[3] = bit;
    return 1;
}
// Native identity (volume serial + 128-bit file ID) of the file now at `path`, read at its first
// observed write (live collection only).  Best effort: a file already renamed or deleted keeps
// no ID, and the query falls back to the event sequence (docs/MACHINE_MODE.md "File identity").
static char *capture_file_id(const char *path) {
    wchar_t *w = w_from_utf8(path);
    HANDLE h = CreateFileW(w, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    FILE_ID_INFO info;
    char *r = NULL;
    if (GetFileInformationByHandleEx(h, FileIdInfo, &info, sizeof info)) {
        char b[96]; int n = snprintf(b, sizeof b, "win:%016llx:", (unsigned long long)info.VolumeSerialNumber);
        for (int i = 15; i >= 0; i--) n += snprintf(b + n, sizeof b - n, "%02x", info.FileId.Identifier[i]);
        r = xstrdup(b);
    }
    CloseHandle(h);
    return r;
}
static void io_event(uint32_t pid, int64_t ts, const char *path, int is_write, const char *api, const char *api_temp) {
    if (in_ws(path, capture_all)) {
        if (!is_write && in_ws(path, 0)) map_set(&read_workspace, key_of(pid, ts), NULL, NULL);
        char *fid = machine_mode && live_mode && is_write ? capture_file_id(path) : NULL;
        cur_fid = fid;
        file_event(pid, ts, K_IO, path, 1, !is_write, is_write, 0, NULL, api, 0, 0);
        cur_fid = NULL;
        free(fid);
    } else if (is_write && map_has(&read_workspace, key_of(pid, ts), NULL) && is_temp(path)) {
        map_put(&derived, 0, path, NULL);
        file_event(pid, ts, K_IO, path, 1, 0, 1, 0, NULL, api_temp, 0, 0);
    } else if (!is_write && map_has(&derived, 0, path)) {
        map_set(&read_workspace, key_of(pid, ts), NULL, NULL);
        file_event(pid, ts, K_IO, path, 1, 1, 0, 0, NULL, api_temp, 0, 0);
    } else st.filtered++;
}
// ---- privacy gate with ordering: a process's user comes from the system-logger session,
// which can be delivered later than the file session.  Evidence of a process whose user is
// not known yet is held (with its path resolved now) and emitted or dropped once it is.
typedef struct { int fn; int64_t ts; int kind, has_rw, rd, wr, has_path2, is_write, has_flags; int64_t flags; char *path, *path2; const char *api, *api_temp; } held_t;
typedef struct { held_t *v; size_t n, cap; int64_t first_ts; } heldlist_t;
static map_t held_by_pid;
static size_t held_total;
#define HELD_LIMIT 200000
#define HELD_MAX_AGE_NS 10000000000LL
static void heldlist_free(void *p) {
    heldlist_t *l = p;
    if (!l) return;
    for (size_t i = 0; i < l->n; i++) { free(l->v[i].path); free(l->v[i].path2); }
    held_total -= l->n;
    free(l->v); free(l);
}
static void deliver(uint32_t pid, held_t *h) {
    if (h->fn == 2) io_event(pid, h->ts, h->path, h->is_write, h->api, h->api_temp);
    else file_event(pid, h->ts, h->kind, h->path, h->has_rw, h->rd, h->wr, h->has_path2, h->path2, h->api, h->has_flags, h->flags);
}
// fn 1: file_event(kind...), fn 2: io_event(is_write...)
static void emit_gated(int uok, uint32_t pid, int fn, int64_t ts, int kind, const char *path, int has_rw, int rd, int wr,
                       int has_path2, const char *path2, int is_write, const char *api, const char *api_temp, int has_flags, int64_t flags) {
    held_t h = {fn, ts, kind, has_rw, rd, wr, has_path2, is_write, has_flags, flags, (char *)path, (char *)path2, api, api_temp};
    if (uok == 1) { deliver(pid, &h); return; }
    if (uok == 0) { st.other_user++; return; }
    if (held_total >= HELD_LIMIT) { st.user_unresolved++; return; }
    ent_t *e = map_find(&held_by_pid, pid, NULL);
    if (!e) { heldlist_t *l = calloc(1, sizeof *l); l->first_ts = ts; e = map_set(&held_by_pid, pid, NULL, l); }
    heldlist_t *l = e->v;
    if (l->n == l->cap) { l->cap = l->cap ? l->cap * 2 : 16; l->v = xrealloc(l->v, l->cap * sizeof *l->v); }
    h.path = xstrdup(path); h.path2 = xstrdup(path2);
    l->v[l->n++] = h;
    held_total++;
}
#define GATE_FILE(uok, pid, ts, kind, path, has_path2, path2, api, has_flags, flags, rw, rd, wr) \
    emit_gated(uok, pid, 1, ts, kind, path, rw, rd, wr, has_path2, path2, 0, api, NULL, has_flags, flags)
#define GATE_IO(uok, pid, ts, path, is_write, api, api_temp) \
    emit_gated(uok, pid, 2, ts, K_IO, path, 1, !(is_write), is_write, 0, NULL, is_write, api, api_temp, 0, 0)
static void release_held(uint32_t pid) {
    ent_t *e = map_find(&held_by_pid, pid, NULL);
    if (!e) return;
    heldlist_t *l = e->v;
    int uok = user_ok(pid);
    if (uok == 1) for (size_t i = 0; i < l->n; i++) deliver(pid, &l->v[i]);
    else st.other_user += l->n;
    map_remove_ent(&held_by_pid, e);
}
static void sweep_held(int64_t now_ts) {  // user never resolved: count, never guess
    for (ent_t *e = held_by_pid.head, *n; e; e = n) {
        n = e->next;
        heldlist_t *l = e->v;
        if (now_ts - l->first_ts > HELD_MAX_AGE_NS) {
            if (machine_mode) {  // no requester to protect: keep the evidence, its user stays unknown
                uint32_t pid = (uint32_t)e->k;
                for (size_t i = 0; i < l->n; i++) deliver(pid, &l->v[i]);
                st.user_late += l->n;
            } else st.user_unresolved += l->n;
            map_remove_ent(&held_by_pid, e);
        }
    }
}

#define FILE_DIRECTORY_FILE 0x1
#define FILE_DELETE_ON_CLOSE 0x1000
static int descends_from(uint64_t k, uint64_t ancestor) {
    for (int hop = 0; hop < 32; hop++) {
        prow_t *row = map_get(&proc_rows, k, NULL);
        if (!row || !row->has_parent_key) return 0;
        k = (uint64_t)row->parent_key;
        if (k == ancestor) return 1;
    }
    return 0;
}
// ---- WHYFS_PROF: time spent per record type (diagnostics; off by default)
static int prof_on;
static int64_t prof_ticks[16], prof_n[16], prof_cb_ticks[2];
static void process_rec_inner(rec_t *r);
static void process_rec(rec_t *r) {
    if (!prof_on) { process_rec_inner(r); return; }
    LARGE_INTEGER a, b; QueryPerformanceCounter(&a);
    uint32_t t = r->type & 15;
    process_rec_inner(r);
    QueryPerformanceCounter(&b);
    prof_ticks[t] += b.QuadPart - a.QuadPart; prof_n[t]++;
}
static void process_rec_inner(rec_t *r) {
    st.received++;
    uint32_t pid = r->pid;
    int64_t ts = r->ts;
    switch (r->type) {
    case R_PROC_START: {  // new process: pid, parent, image (+ command line if already known)
        if (r->user_ok != 2) { map_set(&users_ok, pid, NULL, NULL)->u = r->user_ok; }
        if (r->s3) map_put(&users_sid, pid, NULL, xstrdup(r->s3));
        uint32_t parent = r->ppid;
        seq++;
        uint64_t child_key = (seq << 32) | pid;
        int has_pk = parent != 0 && parent != pid;
        uint64_t parent_key = has_pk ? key_of(parent, ts) : 0;
        map_set(&pkey, pid, NULL, NULL)->u = child_key;
        const char *cmd = r->s2;
        ent_t *ec = map_find(&early_cmd, pid, NULL);  // command line that arrived before this start
        if (!cmd && ec) cmd = ec->v;
        image_t *im = xmalloc(sizeof *im); im->exe = xstrdup(r->s1); im->cmd = xstrdup(cmd);
        map_set(&image, pid, NULL, im);
        prow_t *row = calloc(1, sizeof *row);
        row->ts = ts; row->pid = (int64_t)child_key; row->os_pid = pid;
        if ((r->flags & 1) && live_mode) {  // rundown: the process's OS start time, not the rundown's
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            FILETIME c, e, k, u;
            if (h && GetProcessTimes(h, &c, &e, &k, &u))
                row->ts = (int64_t)(((((uint64_t)c.dwHighDateTime) << 32) | c.dwLowDateTime) - 116444736000000000ULL) * 100;
            if (h) CloseHandle(h);
        }
        row->has_ppid = parent != 0; row->ppid = parent;
        row->has_parent_key = has_pk; row->parent_key = (int64_t)parent_key;
        row->exe = xstrdup(r->s1); row->command = xstrdup(cmd);
        row->user = xstrdup(map_get(&users_sid, pid, NULL));
        if (ec) map_remove_ent(&early_cmd, ec);
        record_process(row);
        // The image boundary is raw evidence, as exec is on Linux (one image per Windows process).
        record_exec(ts, child_key, pid, r->s1);
        if (r->user_ok != 2) release_held(pid);
        return;
    }
    case R_PROC_INFO: {  // second source for the same process: command line, user; image if missing
        if (r->user_ok != 2) map_set(&users_ok, pid, NULL, NULL)->u = r->user_ok;
        if (r->s3) map_put(&users_sid, pid, NULL, xstrdup(r->s3));
        release_held(pid);
        ent_t *e = map_find(&pkey, pid, NULL);
        if (!e || !map_has(&image, pid, NULL)) {  // start not processed yet (or pid of an exited instance)
            if (r->s2) map_put(&early_cmd, pid, NULL, xstrdup(r->s2));
            return;
        }
        image_t *im = map_get(&image, pid, NULL);
        if (r->s2 && !im->cmd) im->cmd = xstrdup(r->s2);
        prow_t *row = calloc(1, sizeof *row);
        row->ts = ts; row->pid = (int64_t)e->u; row->os_pid = pid;
        row->exe = xstrdup(r->s1); row->command = xstrdup(r->s2);
        row->user = xstrdup(r->s3);
        record_process(row);
        return;
    }
    case R_PROC_END: {
        ent_t *pk = map_find(&pkey, pid, NULL);
        if (pk && !map_has(&relevant, pk->u, NULL)) map_pop(&pending_exec, pk->u, NULL);
        map_pop(&image, pid, NULL);
        if (!map_has(&held_by_pid, pid, NULL)) map_pop(&users_ok, pid, NULL);  // late user info still pending
        return;  // keep pkey: late events of this pid still belong to this instance
    }
    default: break;
    }
    int uok = user_ok(pid);
    if (r->type == R_CREATE) {  // file object opened (every open, in or out of scope: resets its state)
        char *path = r->s1;
        int is_dir = (r->flags & FILE_DIRECTORY_FILE) != 0;
        if (!path) { map_pop(&fobjs, r->fo, NULL); st.unmapped_paths++; return; }
        if ((is_dir && !machine_mode) || in_ws(path, capture_all) || is_temp(path)) {
            fobj_t *f = calloc(1, sizeof *f); f->path = xstrdup(path); f->opts = r->flags; f->creator = key_of(pid, ts);
            map_put(&fobjs, r->fo, NULL, f);
        } else map_pop(&fobjs, r->fo, NULL);
        // No "open" record on Windows: Kernel-File logs a Create when it is issued, so it
        // cannot tell a successful open from a failed probe (e.g. debuggers and runtimes
        // probing for *.pdb files).  Evidence is read/write/map/rename/delete/exec only.
        return;
    }
    fobj_t *f = r->fo ? map_get(&fobjs, r->fo, NULL) : NULL;
    if (f && r->key) map_set(&fkeys, r->key, NULL, xstrdup(f->path))->u = f->creator;  // FileKey -> path, owning lineage
    switch (r->type) {
    case R_KEYINFO: return;
    case R_CLOSE: map_pop(&fobjs, r->fo, NULL); return;  // IRP_MJ_CLOSE: the file object is freed
    case R_FO_RESET: map_pop(&fobjs, r->fo, NULL); st.filtered++; return;  // an out-of-scope Create reused the pointer
    case R_NAME_DELETE: map_pop(&fkeys, r->key, NULL); return;
    case R_CLEANUP:
        if (f && (f->opts & FILE_DELETE_ON_CLOSE) && uok != 0) {
            char *p = xstrdup(f->path);
            if (map_has(&derived, 0, p)) { map_pop(&derived, 0, p); GATE_FILE(uok, pid, ts, K_UNLINK, p, 0, NULL, "etw:delete-on-close:derived-temp", 0, 0, 0, 0, 0); }
            else if (in_ws(p, capture_all)) GATE_FILE(uok, pid, ts, K_UNLINK, p, 0, NULL, "etw:delete-on-close", 0, 0, 0, 0, 0);
            free(p);
        }
        return;
    case R_READ: case R_WRITE: {
        if (!f) { st.filtered++; return; }
        if (uok == 0) { st.other_user++; return; }
        if (f->opts & FILE_DIRECTORY_FILE) return;
        uint64_t k = key_of(pid, ts);
        // A file object is used by the process that opened it or by a descendant that
        // inherited the handle.  In an unrelated process the pointer is a reused object
        // whose own creation Kernel-File does not log (a pipe, a socket) or whose create
        // failed: never attribute it.
        if (k != f->creator && !descends_from(k, f->creator)) { st.foreign_fo++; return; }
        int is_write = r->type == R_WRITE;
        if (!first_io(f, k, is_write)) return;
        char *p = xstrdup(f->path);
        GATE_IO(uok, pid, ts, p, is_write, "etw:rw", "etw:rw:derived-temp");
        free(p);
        return;
    }
    case R_MAP: {  // memory-mapped view: flags = protection (MM_*: 4/6 writable, shared)
        ent_t *ke = map_find(&fkeys, r->key, NULL);
        if (!ke) { st.filtered++; return; }
        const char *kp = ke->v;
        if (uok == 0) { st.other_user++; return; }
        {  // like the file-object guard: a FileKey is reused after its file's control block is freed,
           // so a mapping counts only in the lineage that opened the file it was learned from
            uint64_t k = key_of(pid, ts);
            if (ke->u && k != ke->u && !descends_from(k, ke->u)) { st.foreign_fo++; return; }
        }
        uint32_t prot = r->flags & 7;
        int is_write = prot == 4 || prot == 6;
        char *p = xstrdup(kp);
        GATE_IO(uok, pid, ts, p, is_write, "etw:mmap", "etw:mmap:derived-temp");
        free(p);
        return;
    }
    case R_DELETE_PATH: {
        char *a = r->s1;
        if (uok == 0) { st.other_user++; return; }
        if (a && map_has(&derived, 0, a)) { map_pop(&derived, 0, a); GATE_FILE(uok, pid, ts, K_UNLINK, a, 0, NULL, "etw:delete:derived-temp", 0, 0, 0, 0, 0); }
        else if (!in_ws(a, capture_all)) st.filtered++;
        else GATE_FILE(uok, pid, ts, K_UNLINK, a, 0, NULL, "etw:delete", 0, 0, 0, 0, 0);
        return;
    }
    case R_RENAME_PATH: {  // old name: the file object's path; new name: the event's path
        char *a = f ? xstrdup(f->path) : NULL, *b = r->s1;
        if (!b) { free(a); st.filtered++; return; }
        int a_derived = a && map_has(&derived, 0, a);
        if (!(capture_all || in_ws(a, 0) || in_ws(b, 0) || a_derived)) { free(a); st.filtered++; return; }
        if (a_derived && is_temp(b)) map_put(&derived, 0, b, NULL);
        if (a) {  // keep file-object and file-key paths consistent with the move
            size_t al = strlen(a);
            map_t *ms[2] = {&fobjs, &fkeys};
            for (int mi = 0; mi < 2; mi++)
                for (ent_t *x = ms[mi]->head; x; x = x->next) {
                    char **pp = mi == 0 ? &((fobj_t *)x->v)->path : (char **)&x->v;
                    char *p = *pp;
                    if (ieq(p, a)) { *pp = xstrdup(b); free(p); }
                    else if (strlen(p) > al && ieq_n(p, a, al) && p[al] == '\\') {
                        buf_t o = {0}; b_str(&o, b); b_str(&o, p + al); *pp = b_take(&o); free(p);
                    }
                }
        }
        if (uok == 0) st.other_user++;
        else {
            // the moved file's identity at its destination (the source name is gone by now)
            char *fid = machine_mode && live_mode && uok == 1 && in_ws(b, 0) ? capture_file_id(b) : NULL;
            cur_fid = fid;
            GATE_FILE(uok, pid, ts, K_RENAME, a, 1, b, "etw:rename", 0, 0, 0, 0, 0);
            cur_fid = NULL;
            free(fid);
        }
        free(a);
        return;
    }
    default: return;
    }
}

// ---------------------------------------------------------------- emit (tests) and SQLite writer
static int emit_json;
static FILE *emit_fp;
typedef struct { const unsigned char *p; } rd_t;
static int64_t r_i64(rd_t *r) { int64_t v; memcpy(&v, r->p, 8); r->p += 8; return v; }
static uint8_t r_u8(rd_t *r) { return *r->p++; }
static const char *r_str(rd_t *r, uint32_t *len) { uint32_t n; memcpy(&n, r->p, 4); r->p += 4; if (n == 0xffffffffu) { *len = 0; return NULL; } const char *s = (const char *)r->p; r->p += n; *len = n; return s; }
static void j_hex(FILE *f, const char *key, const char *s, uint32_t n) {
    if (!s) { fprintf(f, ",\"%s\":null", key); return; }
    fprintf(f, ",\"%s\":\"", key);
    for (uint32_t i = 0; i < n; i++) fprintf(f, "%02x", (unsigned char)s[i]);
    fputc('"', f);
}
static void j_opt(FILE *f, const char *key, int has, int64_t v) { if (has) fprintf(f, ",\"%s\":%lld", key, (long long)v); else fprintf(f, ",\"%s\":null", key); }
static void emit_records(const unsigned char *p, size_t n) {
    rd_t r = {p};
    const unsigned char *e = p + n;
    while (r.p < e) {
        uint8_t t = r_u8(&r);
        int64_t ts = r_i64(&r), pid = r_i64(&r), os_pid = r_i64(&r);
        if (t == 'P') {
            int hp = r_u8(&r); int64_t pp = r_i64(&r); int hk = r_u8(&r); int64_t pk = r_i64(&r);
            uint32_t l1, l2, l3, l4; const char *exe = r_str(&r, &l1), *cwd = r_str(&r, &l2), *cmd = r_str(&r, &l3);
            const char *user = r_str(&r, &l4);
            fprintf(emit_fp, "{\"run_id\":\"%s\",\"ts_ns\":%lld,\"kind\":\"process\",\"pid\":%lld,\"os_pid\":%lld", run_id, (long long)ts, (long long)pid, (long long)os_pid);
            j_opt(emit_fp, "ppid", hp, pp); j_opt(emit_fp, "parent_key", hk, pk);
            j_hex(emit_fp, "exe", exe, l1); j_hex(emit_fp, "cwd", cwd, l2); j_hex(emit_fp, "command", cmd, l3);
            if (user) fprintf(emit_fp, ",\"user\":\"%.*s\"", (int)l4, user); else fprintf(emit_fp, ",\"user\":null");
            fprintf(emit_fp, ",\"source\":\"etw\"}\n");
        } else {
            int kind = r_u8(&r); int hf = r_u8(&r); int64_t fl = r_i64(&r);
            int hrw = r_u8(&r), rdv = r_u8(&r), wrv = r_u8(&r);
            uint32_t l1, l2, l3; const char *path = r_str(&r, &l1), *path2 = r_str(&r, &l2), *api = r_str(&r, &l3);
            int hp2 = r_u8(&r);
            uint32_t l5; const char *fid = r_str(&r, &l5);
            fprintf(emit_fp, "{\"run_id\":\"%s\",\"ts_ns\":%lld,\"kind\":\"%s\",\"pid\":%lld,\"os_pid\":%lld", run_id, (long long)ts, KIND_NAME[kind], (long long)pid, (long long)os_pid);
            j_hex(emit_fp, "path", path, l1);
            if (hp2) j_hex(emit_fp, "path2", path2, l2);
            if (hrw) fprintf(emit_fp, ",\"read\":%s,\"write\":%s", rdv ? "true" : "false", wrv ? "true" : "false");
            if (hf) fprintf(emit_fp, ",\"flags\":%lld", (long long)fl);
            if (fid) fprintf(emit_fp, ",\"file_id\":\"%.*s\"", (int)l5, fid);
            fprintf(emit_fp, ",\"api\":\"%.*s\",\"source\":\"etw\"}\n", (int)l3, api);
        }
    }
}

// SQLite through the sqlite3.dll that ships with the Python runtime whyfs uses (or bundled)
typedef struct sqlite3 sqlite3; typedef struct sqlite3_stmt sqlite3_stmt;
static int (*sq_open_v2)(const char *, sqlite3 **, int, const char *);
static int (*sq_exec)(sqlite3 *, const char *, void *, void *, char **);
static int (*sq_prepare_v2)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
static int (*sq_bind_int64)(sqlite3_stmt *, int, long long);
static int (*sq_bind_text)(sqlite3_stmt *, int, const char *, int, void (*)(void *));
static int (*sq_bind_null)(sqlite3_stmt *, int);
static int (*sq_step)(sqlite3_stmt *);
static int (*sq_reset)(sqlite3_stmt *);
static int (*sq_finalize)(sqlite3_stmt *);
static int (*sq_close)(sqlite3 *);
static int (*sq_busy_timeout)(sqlite3 *, int);
static const char *(*sq_errmsg)(sqlite3 *);
#define SQ_TRANSIENT ((void (*)(void *))-1)
// Default: Windows' own SQLite (System32\winsqlite3.dll, present on x64 and ARM64 Windows 10+),
// loaded from System32 only -- never through the DLL search path.
static void load_sqlite(const char *dll) {
    HMODULE h;
    if (dll) { wchar_t *w = w_from_utf8(dll); h = LoadLibraryExW(w, NULL, LOAD_WITH_ALTERED_SEARCH_PATH); free(w); }
    else h = LoadLibraryExW(L"winsqlite3.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!h) die("cannot load SQLite (winsqlite3.dll)");
#define SYM(v, n) if (!(*(FARPROC *)&v = GetProcAddress(h, n))) die("sqlite3.dll lacks " n)
    SYM(sq_open_v2, "sqlite3_open_v2"); SYM(sq_exec, "sqlite3_exec"); SYM(sq_prepare_v2, "sqlite3_prepare_v2");
    SYM(sq_bind_int64, "sqlite3_bind_int64"); SYM(sq_bind_text, "sqlite3_bind_text"); SYM(sq_bind_null, "sqlite3_bind_null");
    SYM(sq_step, "sqlite3_step"); SYM(sq_reset, "sqlite3_reset"); SYM(sq_finalize, "sqlite3_finalize"); SYM(sq_close, "sqlite3_close");
    SYM(sq_busy_timeout, "sqlite3_busy_timeout"); SYM(sq_errmsg, "sqlite3_errmsg");
    int (*sq_initialize)(void) = NULL;
    SYM(sq_initialize, "sqlite3_initialize");
#undef SYM
    // Python's bundled sqlite3.dll is built without auto-initialization
    if (sq_initialize() != 0) die("sqlite3_initialize failed");
}

// Writer thread: batches handed off under a lock; SQLite runs impersonating the requesting
// user when a token is given (the service never writes a user's workspace as SYSTEM).
typedef struct wbatch { struct wbatch *next; buf_t b; uint32_t n; } wbatch_t;
static CRITICAL_SECTION wlock;
static CONDITION_VARIABLE wcond;
static wbatch_t *whead, *wtail;
static uint64_t wq_records;
static int writer_stop, writer_failed;
static uint64_t w_rows, w_batches, w_max;
static HANDLE user_token;
static char db_path[4096];
#define QUEUE_RECORDS 262144

static void flush_pending(void) {
    if (!pending_n) return;
    if (emit_json) { emit_records((unsigned char *)pending.p, pending.n); st.submitted += pending_n; }
    else {
        EnterCriticalSection(&wlock);
        if (wq_records + pending_n > QUEUE_RECORDS) st.queue_drops += pending_n;  // never backpressure the workload
        else {
            wbatch_t *wb = calloc(1, sizeof *wb);
            b_add(&wb->b, pending.p, pending.n); wb->n = pending_n;
            if (wtail) wtail->next = wb; else whead = wb;
            wtail = wb; wq_records += pending_n; st.submitted += pending_n;
            WakeConditionVariable(&wcond);
        }
        LeaveCriticalSection(&wlock);
    }
    pending.n = 0; pending_n = 0;
}
static char *norm_store(const char *p, uint32_t n) { char *s = xmalloc(n + 1); memcpy(s, p, n); s[n] = 0; char *r = norm_path(s); free(s); return r; }
static DWORD WINAPI writer_main(LPVOID arg) {
    (void)arg;
    if (user_token && !ImpersonateLoggedOnUser(user_token)) { writer_failed = 1; fprintf(stderr, "impersonation failed %lu\n", GetLastError()); return 1; }
    sqlite3 *db = NULL;
    // 0x2 READWRITE, 0x01000000 NOFOLLOW (refuse a symlinked database file)
    if (sq_open_v2(db_path, &db, 0x2 | 0x01000000, NULL) != 0) { fprintf(stderr, "open %s: %s\n", db_path, db ? sq_errmsg(db) : "?"); writer_failed = 1; return 1; }
    sq_busy_timeout(db, 30000);
    sq_exec(db, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);
    sqlite3_stmt *sp = NULL, *se = NULL;
    if (sq_prepare_v2(db, "INSERT INTO processes(run_id,pid,ppid,exe,cwd,command,source,first_seen_ns,os_pid,parent_key,user) VALUES(?,?,?,?,?,?,?,?,?,?,?)"
                          " ON CONFLICT(run_id,pid) DO UPDATE SET ppid=COALESCE(excluded.ppid,processes.ppid), user=COALESCE(excluded.user,processes.user),"
                          " os_pid=COALESCE(excluded.os_pid,processes.os_pid), parent_key=COALESCE(excluded.parent_key,processes.parent_key),"
                          " exe=COALESCE(excluded.exe,processes.exe), cwd=COALESCE(excluded.cwd,processes.cwd),"
                          " command=COALESCE(excluded.command,processes.command), source=COALESCE(excluded.source,processes.source)", -1, &sp, NULL) ||
        sq_prepare_v2(db, "INSERT INTO events(run_id,ts_ns,pid,ppid,kind,path,path2,is_read,is_write,flags,api,source,os_pid,file_id)"
                          " VALUES(?,?,?,NULL,?,?,?,?,?,?,?,?,?,?)", -1, &se, NULL)) {
        fprintf(stderr, "prepare: %s\n", sq_errmsg(db)); writer_failed = 1; return 1;
    }
    for (;;) {
        EnterCriticalSection(&wlock);
        while (!whead && !writer_stop) SleepConditionVariableCS(&wcond, &wlock, INFINITE);
        wbatch_t *list = whead; whead = wtail = NULL;
        uint64_t nrec = 0; for (wbatch_t *x = list; x; x = x->next) nrec += x->n;
        wq_records -= nrec;
        int done = writer_stop && !list;
        LeaveCriticalSection(&wlock);
        if (done) break;
        if (!list) continue;
        sq_exec(db, "BEGIN", NULL, NULL, NULL);
        uint64_t in_tx = 0;
        for (wbatch_t *x = list, *nx; x; x = nx) {
            nx = x->next;
            rd_t r = {(unsigned char *)x->b.p};
            const unsigned char *e = r.p + x->b.n;
            while (r.p < e && !writer_failed) {
                uint8_t t = r_u8(&r);
                int64_t ts = r_i64(&r), pid = r_i64(&r), os_pid = r_i64(&r);
                if (t == 'P') {
                    int hp = r_u8(&r); int64_t pp = r_i64(&r); int hk = r_u8(&r); int64_t pk = r_i64(&r);
                    uint32_t l1, l2, l3, l4; const char *exe = r_str(&r, &l1), *cwd = r_str(&r, &l2), *cmd = r_str(&r, &l3);
                    const char *user = r_str(&r, &l4);
                    if (user) sq_bind_text(sp, 11, user, (int)l4, SQ_TRANSIENT); else sq_bind_null(sp, 11);
                    sq_bind_text(sp, 1, run_id, -1, SQ_TRANSIENT); sq_bind_int64(sp, 2, pid);
                    if (hp) sq_bind_int64(sp, 3, pp); else sq_bind_null(sp, 3);
                    if (exe) sq_bind_text(sp, 4, exe, (int)l1, SQ_TRANSIENT); else sq_bind_null(sp, 4);
                    if (cwd) sq_bind_text(sp, 5, cwd, (int)l2, SQ_TRANSIENT); else sq_bind_null(sp, 5);
                    if (cmd) sq_bind_text(sp, 6, cmd, (int)l3, SQ_TRANSIENT); else sq_bind_null(sp, 6);
                    sq_bind_text(sp, 7, "etw", -1, SQ_TRANSIENT); sq_bind_int64(sp, 8, ts); sq_bind_int64(sp, 9, os_pid);
                    if (hk) sq_bind_int64(sp, 10, pk); else sq_bind_null(sp, 10);
                    if (sq_step(sp) != 101) { fprintf(stderr, "insert process: %s\n", sq_errmsg(db)); writer_failed = 1; }
                    sq_reset(sp);
                } else {
                    int kind = r_u8(&r); int hf = r_u8(&r); int64_t fl = r_i64(&r);
                    int hrw = r_u8(&r), rdv = r_u8(&r), wrv = r_u8(&r);
                    uint32_t l1, l2, l3; const char *path = r_str(&r, &l1), *path2 = r_str(&r, &l2), *api = r_str(&r, &l3);
                    r_u8(&r);
                    uint32_t l5; const char *fid = r_str(&r, &l5);
                    if (fid) sq_bind_text(se, 13, fid, (int)l5, SQ_TRANSIENT); else sq_bind_null(se, 13);
                    char *np = path && l1 ? norm_store(path, l1) : NULL, *np2 = path2 && l2 ? norm_store(path2, l2) : NULL;
                    sq_bind_text(se, 1, run_id, -1, SQ_TRANSIENT); sq_bind_int64(se, 2, ts); sq_bind_int64(se, 3, pid);
                    sq_bind_text(se, 4, KIND_NAME[kind], -1, SQ_TRANSIENT);
                    if (np) sq_bind_text(se, 5, np, -1, SQ_TRANSIENT); else sq_bind_null(se, 5);
                    if (np2) sq_bind_text(se, 6, np2, -1, SQ_TRANSIENT); else sq_bind_null(se, 6);
                    sq_bind_int64(se, 7, hrw && rdv); sq_bind_int64(se, 8, hrw && wrv);
                    if (hf) sq_bind_int64(se, 9, fl); else sq_bind_null(se, 9);
                    if (api) sq_bind_text(se, 10, api, (int)l3, SQ_TRANSIENT); else sq_bind_null(se, 10);
                    sq_bind_text(se, 11, "etw", -1, SQ_TRANSIENT); sq_bind_int64(se, 12, os_pid);
                    if (sq_step(se) != 101) { fprintf(stderr, "insert event: %s\n", sq_errmsg(db)); writer_failed = 1; }
                    sq_reset(se);
                    free(np); free(np2);
                }
            }
            in_tx += x->n;
            free(x->b.p); free(x);
        }
        if (writer_failed) { sq_exec(db, "ROLLBACK", NULL, NULL, NULL); break; }
        if (sq_exec(db, "COMMIT", NULL, NULL, NULL) != 0) { fprintf(stderr, "commit: %s\n", sq_errmsg(db)); writer_failed = 1; break; }
        w_rows += in_tx; w_batches++; if (in_tx > w_max) w_max = in_tx;
    }
    sq_finalize(sp); sq_finalize(se); sq_close(db);
    if (user_token) RevertToSelf();
    return 0;
}

// ---------------------------------------------------------------- record / replay of decoded records
static FILE *record_fp;
static void rec_write(FILE *f, const rec_t *r) {
    uint32_t l1 = r->s1 ? (uint32_t)strlen(r->s1) : 0xffffffffu, l2 = r->s2 ? (uint32_t)strlen(r->s2) : 0xffffffffu;
    fwrite(&r->ts, 8, 1, f); fwrite(&r->type, 4, 1, f); fwrite(&r->pid, 4, 1, f); fwrite(&r->ppid, 4, 1, f);
    fwrite(&r->flags, 4, 1, f); fwrite(&r->user_ok, 4, 1, f); fwrite(&r->fo, 8, 1, f); fwrite(&r->key, 8, 1, f);
    fwrite(&l1, 4, 1, f); if (r->s1) fwrite(r->s1, 1, l1, f);
    fwrite(&l2, 4, 1, f); if (r->s2) fwrite(r->s2, 1, l2, f);
    uint32_t l3 = r->s3 ? (uint32_t)strlen(r->s3) : 0xffffffffu;
    fwrite(&l3, 4, 1, f); if (r->s3) fwrite(r->s3, 1, l3, f);
}
static char *read_str(FILE *f) {
    uint32_t n; if (fread(&n, 4, 1, f) != 1) die("truncated replay");
    if (n == 0xffffffffu) return NULL;
    char *s = xmalloc((size_t)n + 1); if (n && fread(s, 1, n, f) != n) die("truncated replay"); s[n] = 0; return s;
}
static rec_t *rec_read(FILE *f) {
    rec_t *r = rec_alloc();
    if (fread(&r->ts, 8, 1, f) != 1) { rec_free(r); return NULL; }
    if (fread(&r->type, 4, 1, f) != 1 || fread(&r->pid, 4, 1, f) != 1 || fread(&r->ppid, 4, 1, f) != 1 || fread(&r->flags, 4, 1, f) != 1 ||
        fread(&r->user_ok, 4, 1, f) != 1 || fread(&r->fo, 8, 1, f) != 1 || fread(&r->key, 8, 1, f) != 1) die("truncated replay");
    r->s1 = read_str(f); r->s2 = read_str(f); r->s3 = read_str(f);
    return r;
}

// ---------------------------------------------------------------- ETW sessions and decoding
static const GUID KFILE = {0xEDD08927, 0x9CC4, 0x4E65, {0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}};
static const GUID KPROC = {0x22FB2CD6, 0x0E7B, 0x422B, {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}};
static const GUID SYS_PROCESS = {0x3d6fa8d0, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
static const GUID SYS_FILEIO = {0x90cbdc39, 0x4a3e, 0x11d1, {0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3}};
#define KFILE_KEYWORDS 0x1FB0ULL  // FILENAME FILEIO CREATE READ WRITE DELETE_PATH RENAME_SETLINK_PATH CREATE_NEW_FILE
static const USHORT KFILE_IDS[] = {11, 12, 13, 14, 15, 16, 22, 26, 27, 30};

static LARGE_INTEGER qpc_freq, qpc0;
static int64_t wall0;
static int64_t wall_now_ns(void) { FILETIME ft; GetSystemTimePreciseAsFileTime(&ft); return ((int64_t)(((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime) - 116444736000000000LL) * 100; }
// ProcessTrace delivers timestamps as FILETIME (system time, 100 ns since 1601; QPC precision).
static int64_t qpc_to_wall(int64_t ft) { return (ft - 116444736000000000LL) * 100; }

static PSID requester_sid;
static CRITICAL_SECTION qlock;
static rec_t **inq; static size_t ninq, capinq;
static uint64_t arrival;
static void push_rec(rec_t *r) {
    EnterCriticalSection(&qlock);
    r->order = arrival++;
    if (record_fp) rec_write(record_fp, r);  // recorded in arrival order; replay re-sorts the same way
    if (ninq == capinq) { capinq = capinq ? capinq * 2 : 4096; inq = xrealloc(inq, capinq * sizeof *inq); }
    inq[ninq++] = r;
    LeaveCriticalSection(&qlock);
}

// Field offsets per (provider, id, version), learned from TDH once.
typedef struct { GUID g; USHORT id; UCHAR ver; int ok; int off_fo, off_key, off_opts, off_str; } layout_t;
static layout_t layouts[64]; static int nlayouts;
static layout_t *layout_for(PEVENT_RECORD ev) {
    for (int i = 0; i < nlayouts; i++)
        if (layouts[i].id == ev->EventHeader.EventDescriptor.Id && layouts[i].ver == ev->EventHeader.EventDescriptor.Version &&
            IsEqualGUID(&layouts[i].g, &ev->EventHeader.ProviderId)) return &layouts[i];
    if (nlayouts >= 64) return NULL;
    layout_t *L = &layouts[nlayouts++];
    memset(L, 0, sizeof *L);
    L->g = ev->EventHeader.ProviderId; L->id = ev->EventHeader.EventDescriptor.Id; L->ver = ev->EventHeader.EventDescriptor.Version;
    L->off_fo = L->off_key = L->off_opts = L->off_str = -1;
    ULONG sz = 0;
    TdhGetEventInformation(ev, 0, NULL, NULL, &sz);
    PTRACE_EVENT_INFO info = xmalloc(sz);
    if (TdhGetEventInformation(ev, 0, NULL, info, &sz) == ERROR_SUCCESS) {
        int off = 0, fixed = 1;
        for (ULONG i = 0; i < info->TopLevelPropertyCount && fixed; i++) {
            EVENT_PROPERTY_INFO *p = &info->EventPropertyInfoArray[i];
            const wchar_t *name = (wchar_t *)((BYTE *)info + p->NameOffset);
            USHORT in = p->nonStructType.InType;
            int size = -1;
            if (in == TDH_INTYPE_POINTER || in == TDH_INTYPE_SIZET) size = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
            else if (in == TDH_INTYPE_UINT32 || in == TDH_INTYPE_INT32 || in == TDH_INTYPE_HEXINT32) size = 4;
            else if (in == TDH_INTYPE_UINT64 || in == TDH_INTYPE_INT64 || in == TDH_INTYPE_HEXINT64) size = 8;
            else if (in == TDH_INTYPE_UINT16) size = 2;
            if (!wcscmp(name, L"FileObject")) L->off_fo = off;
            else if (!wcscmp(name, L"FileKey")) L->off_key = off;
            else if (!wcscmp(name, L"CreateOptions")) L->off_opts = off;
            else if ((!wcscmp(name, L"FileName") || !wcscmp(name, L"FilePath")) && in == TDH_INTYPE_UNICODESTRING) L->off_str = off;
            if (size < 0 || (p->Flags & (PropertyStruct | PropertyParamLength | PropertyParamCount))) fixed = 0;
            else off += size;
        }
        L->ok = 1;
    }
    free(info);
    return L;
}
static uint64_t rd_ptr(PEVENT_RECORD ev, int off) {
    if (off < 0) return 0;
    int psz = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
    if (off + psz > ev->UserDataLength) return 0;
    if (psz == 4) return *(uint32_t *)((BYTE *)ev->UserData + off);
    return *(uint64_t *)((BYTE *)ev->UserData + off);
}
static uint32_t rd_u32(PEVENT_RECORD ev, int off) { return (off >= 0 && off + 4 <= ev->UserDataLength) ? *(uint32_t *)((BYTE *)ev->UserData + off) : 0; }
static char *rd_path(PEVENT_RECORD ev, int off) {  // NT path string at off -> normalized DOS path (NULL if unmappable)
    if (off < 0 || off >= ev->UserDataLength) return NULL;
    const wchar_t *w = (const wchar_t *)((BYTE *)ev->UserData + off);
    int maxc = (ev->UserDataLength - off) / 2, n = 0;
    while (n < maxc && w[n]) n++;
    char *nt = utf8_from_w(w, n), *dos = dos_path(nt);
    free(nt);
    if (!dos) return NULL;
    char *r = norm_path(dos);
    free(dos);
    return r;
}
static int get_prop(PEVENT_RECORD ev, const wchar_t *name, void *out, ULONG outsz, ULONG *got) {
    PROPERTY_DATA_DESCRIPTOR d = {(ULONGLONG)name, ULONG_MAX, 0};
    ULONG sz = 0;
    if (TdhGetPropertySize(ev, 0, NULL, 1, &d, &sz) != ERROR_SUCCESS || sz > outsz) return 0;
    if (TdhGetProperty(ev, 0, NULL, 1, &d, sz, (PBYTE)out) != ERROR_SUCCESS) return 0;
    if (got) *got = sz;
    return 1;
}

static volatile LONG64 n_cb_file, n_cb_sys, early_filtered, image_maps_skipped;
// ---- process records without TDH name lookups
// Every process start costs one Kernel-Process and one system-logger record; decoding them with
// TdhGetProperty (by property name) cost ~100 us per short-lived process on a 1-core runner
// (results/native-ci: win-diag).  The two layouts are fixed and versioned, so they are decoded
// directly, with bounds checks; any other version, or anything unexpected, falls back to TDH.
// WHYFS_DIAG_CHECK_PROC=1 decodes every record both ways and counts disagreements.
static int check_proc;
static volatile LONG64 proc_fast, proc_slow, proc_mismatch;
typedef struct { ULONG pid, ppid; const BYTE *sid; ULONG sidlen; int has_sid_field; wchar_t *cmd; int has_cmd; } sysproc_t;
static uint64_t rd_uint(const BYTE *p, int n) { uint64_t v = 0; memcpy(&v, p, (size_t)n); return v; }
// Wide NUL-terminated string at p (possibly unaligned): a fresh copy, or NULL if it runs past e.
static wchar_t *copy_wstr(const BYTE *p, const BYTE *e, const BYTE **after) {
    size_t n = 0;
    for (;;) {
        if (p + 2 * n + 2 > e) return NULL;
        if (p[2 * n] == 0 && p[2 * n + 1] == 0) break;
        n++;
    }
    wchar_t *w = xmalloc((n + 1) * sizeof(wchar_t));
    memcpy(w, p, n * 2); w[n] = 0;
    if (after) *after = p + 2 * n + 2;
    return w;
}
// System logger Process (v4): UniqueProcessKey, ProcessId, ParentId, SessionId, ExitStatus,
// DirectoryTableBase, Flags, UserSID (TOKEN_USER then the SID; a NULL pointer: no SID),
// ImageFileName (ANSI), CommandLine (UTF-16), ...
static int decode_sys_process(PEVENT_RECORD ev, int with_details, sysproc_t *o) {
    memset(o, 0, sizeof *o);
    if (ev->EventHeader.EventDescriptor.Version != 4) return 0;
    int psz = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
    const BYTE *p = ev->UserData, *e = p + ev->UserDataLength;
    if (!p || e - p < psz + 16 + psz + 4 + psz) return 0;
    p += psz;
    o->pid = (ULONG)rd_uint(p, 4); p += 4;
    o->ppid = (ULONG)rd_uint(p, 4); p += 4;
    p += 8 + psz + 4;
    if (!with_details) return 1;
    uint64_t sidptr = rd_uint(p, psz);
    o->has_sid_field = 1;
    if (sidptr == 0) p += psz;
    else {
        if (e - p < 2 * psz + 8) return 0;
        const BYTE *sid = p + 2 * psz;
        size_t sl = 8 + 4 * (size_t)sid[1];
        if (sid[0] != 1 || sid[1] > 15 || sid + sl > e) return 0;
        o->sid = sid; o->sidlen = (ULONG)sl;
        p = sid + sl;
    }
    const BYTE *z = memchr(p, 0, (size_t)(e - p));
    if (!z) return 0;
    p = z + 1;
    o->cmd = copy_wstr(p, e, NULL);
    if (!o->cmd) return 0;
    o->has_cmd = 1;
    return 1;
}
// Kernel-Process ProcessStart: ProcessID first; ParentProcessID and ImageName follow at offsets
// that depend on the manifest version (alignment).  They are learned from TDH per version: the
// first records of a version are decoded with TDH and the offsets located by value; the fast path
// is used only once three records agree on the same offsets.  ProcessStop: ProcessID first.
typedef struct { int learned, samples, ppid_off, img_off; } kproc_layout_t;
static kproc_layout_t kproc_layouts[16];  // by version (callback thread only)
static int decode_kproc(PEVENT_RECORD ev, int start, ULONG *pid, ULONG *ppid, wchar_t **img_out) {
    UCHAR v = ev->EventHeader.EventDescriptor.Version;
    const BYTE *p = ev->UserData, *e = p + ev->UserDataLength;
    if (!p || e - p < 4) return 0;
    *pid = (ULONG)rd_uint(p, 4);
    if (!start) return 1;
    kproc_layout_t *L = v < 16 ? &kproc_layouts[v] : NULL;
    if (!L || L->learned != 1) return 0;
    if (L->ppid_off + 4 > e - p || L->img_off >= e - p) return 0;
    *ppid = (ULONG)rd_uint(p + L->ppid_off, 4);
    *img_out = copy_wstr(p + L->img_off, e, NULL);
    return *img_out != NULL;
}
// Called with TDH's values for a start record whose layout is not learned yet.
static void learn_kproc(PEVENT_RECORD ev, ULONG ppid, const wchar_t *img) {
    UCHAR v = ev->EventHeader.EventDescriptor.Version;
    if (v >= 16 || kproc_layouts[v].learned) return;
    kproc_layout_t *L = &kproc_layouts[v];
    const BYTE *p = ev->UserData; size_t n = ev->UserDataLength;
    size_t il = wcslen(img) * 2 + 2;
    int po = -1, io = -1;
    for (size_t o = 4; o + 4 <= n && o < 64; o += 4) if (rd_uint(p + o, 4) == ppid) { po = (int)o; break; }
    for (size_t o = 4; o + il <= n && o < 128; o += 2) if (!memcmp(p + o, img, il)) { io = (int)o; break; }
    if (po < 0 || io < 0 || (L->samples && (po != L->ppid_off || io != L->img_off))) { L->learned = -1; return; }
    L->ppid_off = po; L->img_off = io;
    if (++L->samples >= 3) L->learned = 1;
}
static uint32_t maplog_pid; static FILE *maplog_fp;
static ULONG lost_a, lost_b, bufs_lost_a, bufs_lost_b;
static volatile LONG64 max_lag_file, max_lag_sys;  // delivery lag (arrival - event time), ns
static void note_lag(volatile LONG64 *m, int64_t ts) {
    int64_t lag = wall_now_ns() - ts;
    LONG64 cur = *m;
    while (lag > cur) { LONG64 prev = InterlockedCompareExchange64(m, lag, cur); if (prev == cur) break; cur = prev; }
}
static int diag_discard;
// WHYFS_PROF also counts callbacks per process (pid / 4 buckets) to show where event volume comes from
static volatile LONG diag_pid_file[1 << 16], diag_pid_sys[1 << 16];
static void on_file_event_inner(PEVENT_RECORD ev);
static void WINAPI on_file_event(PEVENT_RECORD ev) {
    if (!prof_on) { on_file_event_inner(ev); return; }
    LARGE_INTEGER a, b; QueryPerformanceCounter(&a);
    on_file_event_inner(ev);
    QueryPerformanceCounter(&b);
    prof_cb_ticks[0] += b.QuadPart - a.QuadPart;
}
static DWORD self_pid;
static void on_file_event_inner(PEVENT_RECORD ev) {
    InterlockedIncrement64(&n_cb_file);
    if (prof_on) InterlockedIncrement(&diag_pid_file[(ev->EventHeader.ProcessId >> 2) & 0xFFFF]);
    if (diag_discard) return;
    if (ev->EventHeader.ProcessId == self_pid) return;  // our own I/O (e.g. 8.3 name lookups) is never evidence
    const GUID *g = &ev->EventHeader.ProviderId;
    uint32_t pid = ev->EventHeader.ProcessId;
    int64_t ts = qpc_to_wall(ev->EventHeader.TimeStamp.QuadPart);
    note_lag(&max_lag_file, ts);
    if (IsEqualGUID(g, &KPROC)) {
        USHORT id = ev->EventHeader.EventDescriptor.Id;
        if (id != 1 && id != 2) return;
        ULONG child = 0, parent = 0; ULONG got;
        wchar_t *fast_img = NULL;
        int fast = decode_kproc(ev, id == 1, &child, &parent, &fast_img);
        if (!fast || check_proc) {
            ULONG c2 = 0, p2 = 0;
            get_prop(ev, L"ProcessID", &c2, 4, &got);
            wchar_t img[1024] = {0}; ULONG isz = 0;
            int have_img = 0;
            if (id == 1) { get_prop(ev, L"ParentProcessID", &p2, 4, &got); have_img = get_prop(ev, L"ImageName", img, sizeof img - 2, &isz); }
            if (fast && (c2 != child || (id == 1 && (p2 != parent || !have_img || wcscmp(img, fast_img))))) {
                if (InterlockedIncrement64(&proc_mismatch) <= 5)
                    fprintf(stderr, "kproc mismatch v%u id%u: pid %lu/%lu ppid %lu/%lu img [%ls]/[%ls]\n",
                            ev->EventHeader.EventDescriptor.Version, id, child, c2, parent, p2, fast_img ? fast_img : L"-", have_img ? img : L"-");
            }
            if (!fast) {
                child = c2; parent = p2; free(fast_img); fast_img = have_img ? _wcsdup(img) : NULL;
                if (id == 1 && have_img) learn_kproc(ev, p2, img);
            }
        }
        InterlockedIncrement64(fast ? &proc_fast : &proc_slow);
        rec_t *r = rec_alloc();
        r->ts = ts; r->pid = child; r->user_ok = 2;  // 2: unknown here (the system-logger record says)
        if (id == 1) {
            if (fast_img) {
                char *nt = utf8_from_w(fast_img, -1), *dos = dos_path(nt);
                r->s1 = dos ? norm_path(dos) : NULL; free(nt); free(dos);
            }
            r->type = R_PROC_START; r->ppid = parent;
        } else r->type = R_PROC_END;
        free(fast_img);
        push_rec(r);
        return;
    }
    if (!IsEqualGUID(g, &KFILE)) return;
    if (pid == 4 || pid == 0) return;  // System: lazy writer / paging I/O, not user-attributable
    USHORT id = ev->EventHeader.EventDescriptor.Id;
    layout_t *L = layout_for(ev);
    if (!L || !L->ok) return;
    rec_t *r = rec_alloc();
    r->ts = ts; r->pid = pid;
    r->fo = rd_ptr(ev, L->off_fo); r->key = rd_ptr(ev, L->off_key);
    switch (id) {
    case 12: case 30:
        r->type = R_CREATE; r->flags = rd_u32(ev, L->off_opts); r->s1 = rd_path(ev, L->off_str);
        // Machine mode: a Create outside the scope policy can never become evidence, so it is
        // dropped here, before the reorder queue (most Creates on a machine are OS and cache
        // paths).  Safe for FileObject reuse: a tracked object is retired by its Close event
        // before its pointer can be reused, and Close events are always processed.
        if (machine_mode && r->s1 && sc_classify(r->s1) == SC_OUT) {
            // Still a record, but a tiny one: a Create that fails gets no Close event, so the
            // FileObject pointer's previous entry must be reset whenever the pointer is reused --
            // by any Create, in scope or not (else a stale path is learned for the new object).
            InterlockedIncrement64(&early_filtered);
            free(r->s1); r->s1 = NULL;
            r->type = R_FO_RESET;
        }
        break;
    case 13: r->type = R_CLEANUP; break;
    case 14: r->type = R_CLOSE; break;
    case 22: r->type = R_KEYINFO; break;
    case 15: r->type = R_READ; break;
    case 16: r->type = R_WRITE; break;
    case 26: r->type = R_DELETE_PATH; r->s1 = rd_path(ev, L->off_str); break;
    case 27: r->type = R_RENAME_PATH; r->s1 = rd_path(ev, L->off_str); break;
    case 11: r->type = R_NAME_DELETE; r->key = rd_ptr(ev, 0); break;
    default: rec_free(r); return;
    }
    push_rec(r);
}

static void on_sys_event_inner(PEVENT_RECORD ev);
static void WINAPI on_sys_event(PEVENT_RECORD ev) {
    if (!prof_on) { on_sys_event_inner(ev); return; }
    LARGE_INTEGER a, b; QueryPerformanceCounter(&a);
    on_sys_event_inner(ev);
    QueryPerformanceCounter(&b);
    prof_cb_ticks[1] += b.QuadPart - a.QuadPart;
}
static void on_sys_event_inner(PEVENT_RECORD ev) {
    InterlockedIncrement64(&n_cb_sys);
    if (prof_on) InterlockedIncrement(&diag_pid_sys[(ev->EventHeader.ProcessId >> 2) & 0xFFFF]);
    if (diag_discard) return;
    if (ev->EventHeader.ProcessId == self_pid && ev->EventHeader.EventDescriptor.Opcode == 37) return;
    const GUID *g = &ev->EventHeader.ProviderId;
    UCHAR op = ev->EventHeader.EventDescriptor.Opcode;
    int64_t ts = qpc_to_wall(ev->EventHeader.TimeStamp.QuadPart);
    if (op != 3 && op != 4 && op != 39 && op != 40) note_lag(&max_lag_sys, ts);  // rundowns replay old events
    if (IsEqualGUID(g, &SYS_FILEIO) && op == 37 && ev->UserDataLength >= 44) {  // MapFile
        BYTE *d = ev->UserData;
        if (maplog_pid && *(uint32_t *)(d + 40) == maplog_pid && maplog_fp) {  // diagnostics: WHYFS_DIAG_MAPLOG=pid,file
            fprintf(maplog_fp, "len=%u", ev->UserDataLength);
            for (unsigned i = 0; i + 8 <= ev->UserDataLength && i < 64; i += 8) fprintf(maplog_fp, " %u:%016llx", i, *(unsigned long long *)(d + i));
            fprintf(maplog_fp, "\n"); fflush(maplog_fp);
        }
        // An image section (MiscInfo bit 54: set for every DLL/EXE the loader maps, clear for data
        // views -- measured, see docs/WINDOWS.md) is code being loaded, not a data input or output;
        // the process's own image is recorded by its start event.  Most MapFile events are these.
        if ((*(uint64_t *)(d + 16) >> 54) & 1) { InterlockedIncrement64(&image_maps_skipped); return; }
        rec_t *r = rec_alloc();
        r->ts = ts; r->type = R_MAP; r->key = *(uint64_t *)(d + 8);
        r->flags = (uint32_t)((*(uint64_t *)(d + 16) >> 48) & 0xFF); r->pid = *(uint32_t *)(d + 40);
        if (r->pid == 4 || r->pid == 0) { rec_free(r); return; }
        push_rec(r);
        return;
    }
    if (!IsEqualGUID(g, &SYS_PROCESS)) return;
    if (op != 1 && op != 3 && op != 2) return;  // Start, DCStart (rundown of existing processes), End
    ULONG pid = 0, parent = 0, got;
    sysproc_t fp;
    int fast = decode_sys_process(ev, op != 2, &fp);
    if (fast && !check_proc) { pid = fp.pid; parent = fp.ppid; }
    else get_prop(ev, L"ProcessId", &pid, 4, &got);
    if (fast && check_proc && pid != fp.pid) InterlockedIncrement64(&proc_mismatch);
    InterlockedIncrement64(fast ? &proc_fast : &proc_slow);
    rec_t *r = rec_alloc();
    r->ts = ts; r->pid = pid;
    if (op == 2) { r->type = R_PROC_END; push_rec(r); return; }
    r->user_ok = 0;
    if (fast && !check_proc) {
        if (fp.sid && IsValidSid((PSID)fp.sid)) {
            PSID sid = (PSID)fp.sid;
            if (!requester_sid || EqualSid(sid, requester_sid)) r->user_ok = 1;
            char *ss = NULL;
            if (ConvertSidToStringSidA(sid, &ss)) { r->s3 = xstrdup(ss); LocalFree(ss); }
        } else if (!fp.has_sid_field && !requester_sid) r->user_ok = 1;
        if (fp.has_cmd) r->s2 = redact_cmdline_w(fp.cmd);
    } else {
        get_prop(ev, L"ParentId", &parent, 4, &got);
        BYTE sidbuf[512]; ULONG sidsz = 0;
        if (get_prop(ev, L"UserSID", sidbuf, sizeof sidbuf, &sidsz)) {
            int psz = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
            PSID sid = sidbuf + 2 * psz;  // TOKEN_USER prefix, then the SID
            if (sidsz > (ULONG)(2 * psz) && IsValidSid(sid)) {
                if (!requester_sid || EqualSid(sid, requester_sid)) r->user_ok = 1;
                char *ss = NULL;
                if (ConvertSidToStringSidA(sid, &ss)) { r->s3 = xstrdup(ss); LocalFree(ss); }
            }
        } else if (!requester_sid) r->user_ok = 1;
        ULONG csz = 0;
        wchar_t *cmd = xmalloc(65536);
        if (get_prop(ev, L"CommandLine", cmd, 65534, &csz) && csz >= 2) { cmd[csz / 2] = 0; r->s2 = redact_cmdline_w(cmd); }
        if (fast && check_proc) {  // the fast decode must agree with TDH on every field it provides
            int same = parent == fp.ppid && (fp.has_cmd ? (csz >= 2 && !wcscmp(cmd, fp.cmd)) : csz < 2);
            if (fp.sid) same = same && sidsz > 16 && !memcmp(sidbuf + 2 * ((ev->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8), fp.sid, fp.sidlen);
            if (!same) { if (InterlockedIncrement64(&proc_mismatch) <= 5)
                fprintf(stderr, "sysproc mismatch v%u op%u: pid %lu ppid %lu/%lu sid %u cmd csz=%lu tdh=[%.80ls] fast=[%.80ls]\n",
                        ev->EventHeader.EventDescriptor.Version, op, pid, parent, fp.ppid, fp.sidlen, csz, csz >= 2 ? cmd : L"-", fp.cmd ? fp.cmd : L"-"); }
        }
        free(cmd);
    }
    free(fp.cmd);
    r->ppid = parent;
    // Start: the Kernel-Process record creates the process; this one completes it (and its user).
    // DCStart: an existing process (rundown) -- create it here if nothing else did.
    r->type = op == 3 ? R_PROC_START : R_PROC_INFO;
    if (op == 3) r->flags |= 1;  // rundown (DCStart): a process that predates the session
    if (op == 3) {
        char *img = proc_image(pid);
        r->s1 = img ? norm_path(img) : NULL; free(img);
    }
    push_rec(r);
}

static EVENT_TRACE_PROPERTIES *mkprops(ULONG mode, ULONG flags) {
    size_t psz = sizeof(EVENT_TRACE_PROPERTIES) + 2048;
    EVENT_TRACE_PROPERTIES *p = calloc(1, psz);
    p->Wnode.BufferSize = (ULONG)psz; p->Wnode.Flags = WNODE_FLAG_TRACED_GUID; p->Wnode.ClientContext = 1;  // QPC
    p->LogFileMode = mode; p->EnableFlags = flags; p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    p->BufferSize = 256; p->MinimumBuffers = 64;
    p->MaximumBuffers = getenv("WHYFS_MAXBUF") ? (ULONG)atoi(getenv("WHYFS_MAXBUF")) : 512;
    p->FlushTimer = getenv("WHYFS_FLUSH") ? (ULONG)atoi(getenv("WHYFS_FLUSH")) : 1;
    return p;
}
static TRACEHANDLE start_session(const wchar_t *name, EVENT_TRACE_PROPERTIES *p) {
    EVENT_TRACE_PROPERTIES *stop = mkprops(0, 0);
    ControlTraceW(0, name, stop, EVENT_TRACE_CONTROL_STOP);
    free(stop);
    TRACEHANDLE s;
    ULONG rc = StartTraceW(&s, name, p);
    if (rc != ERROR_SUCCESS) { fprintf(stderr, "StartTrace %ls: %lu\n", name, rc); exit(3); }
    return s;
}
static TRACEHANDLE open_rt(const wchar_t *name, PEVENT_RECORD_CALLBACK cb) {
    EVENT_TRACE_LOGFILEW lf = {0};
    lf.LoggerName = (LPWSTR)name;
    lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = cb;
    TRACEHANDLE h = OpenTraceW(&lf);
    if (h == INVALID_PROCESSTRACE_HANDLE) { fprintf(stderr, "OpenTrace %ls: %lu\n", name, GetLastError()); exit(3); }
    return h;
}
static DWORD WINAPI consume(LPVOID h) {
    ULONG rc = ProcessTrace((TRACEHANDLE *)h, 1, NULL, NULL);
    if (rc != ERROR_SUCCESS && rc != ERROR_CANCELLED) fprintf(stderr, "ProcessTrace failed: %lu\n", rc);
    return 0;
}

// ---------------------------------------------------------------- merge (timestamp order) and main
#define REORDER_WINDOW_NS 5000000000LL
static int64_t last_processed_ts;
static uint64_t late_records;
static rec_t **held; static size_t nheld, capheld;
static int cmp_rec(const void *a, const void *b) {
    const rec_t *x = *(rec_t *const *)a, *y = *(rec_t *const *)b;
    if (x->ts != y->ts) return x->ts < y->ts ? -1 : 1;
    return x->order < y->order ? -1 : x->order > y->order;
}
// move everything queued into the held set; process held records older than `upto`
static void merge_step(int64_t upto) {
    EnterCriticalSection(&qlock);
    if (nheld + ninq > capheld) { capheld = (nheld + ninq) * 2 + 1024; held = xrealloc(held, capheld * sizeof *held); }
    for (size_t j = 0; j < ninq; j++) if (inq[j]->ts < last_processed_ts) late_records++;
    // The held window is already sorted: sort only the new batch, then merge it in linearly
    // (re-sorting the whole ~5 s window ten times a second dominated the idle cost).
    size_t nb = ninq;
    rec_t **batch = nb ? xmalloc(nb * sizeof *batch) : NULL;
    if (nb) memcpy(batch, inq, nb * sizeof *inq);
    ninq = 0;
    LeaveCriticalSection(&qlock);
    if (nb) {
        qsort(batch, nb, sizeof *batch, cmp_rec);
        if (nheld && cmp_rec(&held[nheld - 1], &batch[0]) <= 0) {  // common case: all newer
            memcpy(held + nheld, batch, nb * sizeof *batch);
        } else {
            rec_t **m = xmalloc((nheld + nb) * sizeof *m);
            size_t x = 0, y = 0, z = 0;
            while (x < nheld && y < nb) m[z++] = cmp_rec(&held[x], &batch[y]) <= 0 ? held[x++] : batch[y++];
            while (x < nheld) m[z++] = held[x++];
            while (y < nb) m[z++] = batch[y++];
            memcpy(held, m, z * sizeof *m);
            free(m);
        }
        nheld += nb;
        free(batch);
    }
    size_t i = 0;
    while (i < nheld && held[i]->ts <= upto) { if (held[i]->ts > last_processed_ts) last_processed_ts = held[i]->ts; process_rec(held[i]); rec_free(held[i]); i++; }
    sweep_held(upto == INT64_MAX ? INT64_MAX : upto);
    memmove(held, held + i, (nheld - i) * sizeof *held); nheld -= i;
    flush_pending();
}

static volatile LONG stop_requested;
static BOOL WINAPI on_ctrl(DWORD t) { (void)t; InterlockedExchange(&stop_requested, 1); return TRUE; }
static volatile LONG stats_requested;
static DWORD WINAPI stdin_watch(LPVOID arg) {  // a "stats" line: live counters; anything else, EOF or a broken pipe: stop
    (void)arg;
    char line[64]; DWORD len = 0;
    for (;;) {
        char c; DWORD n = 0;
        if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), &c, 1, &n, NULL) || n == 0) break;
        if (c == '\n') {
            line[len] = 0;
            if (len >= 5 && !strncmp(line, "stats", 5)) { InterlockedExchange(&stats_requested, 1); len = 0; continue; }
            break;
        }
        if (c != '\r' && len < sizeof line - 1) line[len++] = c;
    }
    InterlockedExchange(&stop_requested, 1);
    return 0;
}

static void print_prof(void) {
    if (!prof_on) return;
    LARGE_INTEGER f; QueryPerformanceFrequency(&f);
    fprintf(stderr, "{\"prof\":true,\"cb_file_ms\":%.1f,\"cb_sys_ms\":%.1f", prof_cb_ticks[0] * 1e3 / f.QuadPart, prof_cb_ticks[1] * 1e3 / f.QuadPart);
    for (int t = 0; t < 16; t++) if (prof_n[t]) fprintf(stderr, ",\"t%d_ms\":%.1f,\"t%d_n\":%lld", t, prof_ticks[t] * 1e3 / f.QuadPart, t, (long long)prof_n[t]);
    fprintf(stderr, ",\"fobjs\":%zu,\"fkeys\":%zu,\"proc_rows\":%zu,\"pkey\":%zu,\"image\":%zu,\"users_sid\":%zu",
            fobjs.count, fkeys.count, proc_rows.count, pkey.count, image.count, users_sid.count);
    fprintf(stderr, ",\"top_pids\":[");
    for (int k = 0, first = 1; k < 12; k++) {  // the busiest pids (file + sys callbacks), with their image if still running
        int best = -1; long bv = 0;
        for (int i = 0; i < (1 << 16); i++) { long v = diag_pid_file[i] + diag_pid_sys[i]; if (v > bv) { bv = v; best = i; } }
        if (best < 0) break;
        wchar_t img[MAX_PATH] = L"(exited)"; DWORD n = MAX_PATH;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)best << 2);
        if (h) { if (!QueryFullProcessImageNameW(h, 0, img, &n)) wcscpy_s(img, MAX_PATH, L"?"); CloseHandle(h); }
        char *u = utf8_from_w(img, -1);
        for (char *c = u; *c; c++) if (*c == '\\' || *c == '"') *c = '/';
        fprintf(stderr, "%s{\"pid\":%d,\"file\":%ld,\"sys\":%ld,\"image\":\"%s\"}", first ? "" : ",", best << 2,
                (long)diag_pid_file[best], (long)diag_pid_sys[best], u);
        free(u); first = 0;
        diag_pid_file[best] = diag_pid_sys[best] = 0;
    }
    fprintf(stderr, "]}\n");
    fflush(stderr);
}
static void print_stats(void) {
    print_prof();
    printf("{\"received\":%llu,\"submitted\":%llu,\"filtered\":%llu,\"other_user\":%llu,\"unmapped_paths\":%llu,"
           "\"kernel_drops\":%llu,\"queue_drops\":%llu,\"proc_fallbacks\":%llu,\"writer_rows\":%llu,\"writer_batches\":%llu,"
           "\"writer_max_batch\":%llu,\"writer_failed\":%d,\"pending_exec\":%zu,\"user_unresolved\":%llu,\"foreign_file_object\":%llu,\"cb_file\":%lld,\"cb_sys\":%lld,"
           "\"lost_file\":%lu,\"lost_sys\":%lu,\"buffers_lost_file\":%lu,\"buffers_lost_sys\":%lu,\"max_lag_file_ms\":%.1f,\"max_lag_sys_ms\":%.1f,\"late_records\":%llu,\"excluded_image\":%llu,\"user_late\":%llu,\"image_maps_skipped\":%lld,\"proc_fast\":%lld,\"proc_slow\":%lld,\"proc_mismatch\":%lld}\n",
           st.received, st.submitted, st.filtered, st.other_user, st.unmapped_paths, st.kernel_lost, st.queue_drops, st.proc_fallbacks,
           w_rows, w_batches, w_max, writer_failed, pending_exec.count, st.user_unresolved, st.foreign_fo, (long long)n_cb_file, (long long)n_cb_sys,
           lost_a, lost_b, bufs_lost_a, bufs_lost_b, max_lag_file / 1e6, max_lag_sys / 1e6, late_records,
           st.excluded_image, st.user_late, (long long)image_maps_skipped, (long long)proc_fast, (long long)proc_slow, (long long)proc_mismatch);
    fflush(stdout);
}

#ifdef WHYFS_DEBUG_CRASH
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
static LONG WINAPI crash_filter(EXCEPTION_POINTERS *e) {
    HANDLE proc = GetCurrentProcess();
    SymSetOptions(SYMOPT_LOAD_LINES);
    SymInitialize(proc, NULL, TRUE);
    CONTEXT *c = e->ContextRecord;
    STACKFRAME64 f = {0};
    f.AddrPC.Offset = c->Rip; f.AddrFrame.Offset = c->Rbp; f.AddrStack.Offset = c->Rsp;
    f.AddrPC.Mode = f.AddrFrame.Mode = f.AddrStack.Mode = AddrModeFlat;
    fprintf(stderr, "CRASH code 0x%08lx at %p\n", e->ExceptionRecord->ExceptionCode, e->ExceptionRecord->ExceptionAddress);
    for (int i = 0; i < 20 && StackWalk64(IMAGE_FILE_MACHINE_AMD64, proc, GetCurrentThread(), &f, c, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL); i++) {
        char sb[sizeof(SYMBOL_INFO) + 256]; SYMBOL_INFO *si = (SYMBOL_INFO *)sb; si->SizeOfStruct = sizeof(SYMBOL_INFO); si->MaxNameLen = 255;
        DWORD64 d = 0; DWORD dl = 0; IMAGEHLP_LINE64 ln = {sizeof ln};
        const char *fn = SymFromAddr(proc, f.AddrPC.Offset, &d, si) ? si->Name : "?";
        if (SymGetLineFromAddr64(proc, f.AddrPC.Offset, &dl, &ln)) fprintf(stderr, "  %s  line %lu\n", fn, ln.LineNumber);
        else fprintf(stderr, "  %s\n", fn);
    }
    fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

int main(int argc, char **argv) {
    InitializeSListHead(&rec_pool);
    self_pid = GetCurrentProcessId();
    map_init(&longnames, 1, 4096, free);
    prof_on = getenv("WHYFS_PROF") != NULL;
    check_proc = getenv("WHYFS_DIAG_CHECK_PROC") != NULL;
    if (getenv("WHYFS_DIAG_MAPLOG")) {
        char *spec = xstrdup(getenv("WHYFS_DIAG_MAPLOG")), *comma = strchr(spec, ',');
        if (comma) { *comma = 0; maplog_pid = (uint32_t)atoi(spec); maplog_fp = fopen(comma + 1, "a"); }
        free(spec);
    }
#ifdef WHYFS_DEBUG_CRASH
    SetUnhandledExceptionFilter(crash_filter);
#endif
    const char *root = NULL, *replay = NULL, *sqlite_dll = NULL, *sid_str = NULL, *session = "whyfs";
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
#define ARG(n) (!strcmp(a, n) && v && (i++, 1))
        if (ARG("--root")) root = v;
        else if (ARG("--run-id")) run_id = v;
        else if (ARG("--temp-root")) { if (n_temp_roots < 8) { char *n = norm_path(v); temp_roots[n_temp_roots++] = mkroot(n); free(n); } }
        else if (ARG("--sqlite")) sqlite_dll = v;
        else if (ARG("--user-sid")) sid_str = v;
        else if (ARG("--user-token")) user_token = (HANDLE)(uintptr_t)_strtoui64(v, NULL, 0);
        else if (ARG("--replay")) replay = v;
        else if (ARG("--record")) { record_fp = fopen(v, "wb"); if (!record_fp) die("cannot open record file"); }
        else if (ARG("--session")) session = v;
        else if (!strcmp(a, "--capture-all")) capture_all = 1;
        else if (!strcmp(a, "--machine")) { machine_mode = 1; max_ancestors = 24; }
        else if (ARG("--scope")) { if (sc_load(v) < 0) die("cannot read scope file"); }
        else if (ARG("--scope-classify")) {  // test hooks: scope.Scope over the rules loaded so far
            int c = sc_classify(v); fputs(c == SC_IN ? "in" : c == SC_TEMP ? "temp" : "out", stdout); return 0;
        }
        else if (ARG("--scope-image")) { fputs(sc_image_excluded(v) ? "1" : "0", stdout); return 0; }
        else if (!strcmp(a, "--emit")) emit_json = 1;
        else if (!strcmp(a, "--redact-text") && v) {  // test hook: the command-text pass alone (shared vectors)
            int wc = 0;
            LPWSTR *wv = CommandLineToArgvW(GetCommandLineW(), &wc);
            char *u = wv && i + 1 < wc ? utf8_from_w(wv[i + 1], -1) : NULL, *red = u ? redact_text(u) : NULL;
            fwrite(red ? red : "", 1, red ? strlen(red) : 0, stdout);
            return 0;
        }
        else if (!strcmp(a, "--redact") && v) {  // test hook: the stored form of a command line
            int wc = 0;
            LPWSTR *wv = CommandLineToArgvW(GetCommandLineW(), &wc);
            char *red = wv && i + 1 < wc ? redact_cmdline_w(wv[i + 1]) : NULL;
            fwrite(red ? red : "", 1, red ? strlen(red) : 0, stdout);
            return 0;
        }
        else { fprintf(stderr, "unknown argument %s\n", a); return 2; }
#undef ARG
    }
    if (!root) die("--root required");
    live_mode = replay == NULL;
    load_devices();
    { char *n = norm_path(root); ws_root = mkroot(n); buf_t o = {0}; b_str(&o, ws_root.s); b_str(&o, "\\.whyfs"); char *s = b_take(&o); state_root = mkroot(s); free(s); free(n); }
    snprintf(db_path, sizeof db_path, "%s\\.whyfs\\whyfs.db", ws_root.s);
    if (sid_str && !ConvertStringSidToSidA(sid_str, &requester_sid)) die("bad --user-sid");
    map_init(&users_sid, 0, 0, free); map_init(&fobjs, 0, 400000, fobj_free); map_init(&fkeys, 0, 400000, free); map_init(&pkey, 0, 0, NULL);
    map_init(&proc_rows, 0, 200000, prow_free); map_init(&pending_exec, 0, 0, pexecs_free); map_init(&relevant, 0, 0, NULL);
    map_init(&read_workspace, 0, 0, NULL); map_init(&derived, 1, 200000, NULL); map_init(&image, 0, 0, image_free);
    map_init(&users_ok, 0, 0, NULL); map_init(&early_cmd, 0, 4096, free); map_init(&held_by_pid, 0, 0, heldlist_free);
    InitializeCriticalSection(&qlock); InitializeCriticalSection(&wlock); InitializeConditionVariable(&wcond);
    emit_fp = stdout;
    HANDLE writer = NULL;
    if (!emit_json) {
        load_sqlite(sqlite_dll);  // NULL: System32\winsqlite3.dll
        writer = CreateThread(NULL, 0, writer_main, NULL, 0, NULL);
    }
    QueryPerformanceFrequency(&qpc_freq); QueryPerformanceCounter(&qpc0); wall0 = wall_now_ns();

    if (replay) {
        FILE *f = fopen(replay, "rb");
        if (!f) die("cannot open replay file");
        rec_t *r;
        while ((r = rec_read(f))) { r->order = arrival++; EnterCriticalSection(&qlock);
            if (ninq == capinq) { capinq = capinq ? capinq * 2 : 4096; inq = xrealloc(inq, capinq * sizeof *inq); }
            inq[ninq++] = r; LeaveCriticalSection(&qlock); }
        fclose(f);
        merge_step(INT64_MAX);
    } else {
        wchar_t name_a[256], name_b[256];
        swprintf(name_a, 256, L"%hs", session); swprintf(name_b, 256, L"%hs-sys", session);
        // Diagnostics for cost decomposition only (never set by the service):
        //   WHYFS_DIAG_DISCARD  callbacks count and return   WHYFS_DIAG_NO_VAMAP  no mapped-view events
        //   WHYFS_DIAG_NO_SYS   system logger without flags  WHYFS_DIAG_NO_KFILE  Kernel-File not enabled
        //   WHYFS_DIAG_KFILE_KW=hex  Kernel-File keywords instead of KFILE_KEYWORDS
        diag_discard = getenv("WHYFS_DIAG_DISCARD") != NULL;
        ULONG sys_flags = getenv("WHYFS_DIAG_NO_SYS") ? 0 : EVENT_TRACE_FLAG_PROCESS | (getenv("WHYFS_DIAG_NO_VAMAP") ? 0 : EVENT_TRACE_FLAG_VAMAP);
        EVENT_TRACE_PROPERTIES *pa = mkprops(EVENT_TRACE_REAL_TIME_MODE, 0);
        EVENT_TRACE_PROPERTIES *pb = mkprops(EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE, sys_flags);
        TRACEHANDLE sa = start_session(name_a, pa), sb = start_session(name_b, pb);
        // Kernel-File: only the event ids the model uses, filtered in the kernel
        BYTE fbuf[sizeof(EVENT_FILTER_EVENT_ID) + sizeof(KFILE_IDS)];
        EVENT_FILTER_EVENT_ID *fid = (EVENT_FILTER_EVENT_ID *)fbuf;
        fid->FilterIn = TRUE; fid->Reserved = 0; fid->Count = (USHORT)(sizeof KFILE_IDS / sizeof *KFILE_IDS);
        memcpy(fid->Events, KFILE_IDS, sizeof KFILE_IDS);
        EVENT_FILTER_DESCRIPTOR fd = {(ULONGLONG)fid, (ULONG)(sizeof(EVENT_FILTER_EVENT_ID) + sizeof(USHORT) * (fid->Count - 1)), EVENT_FILTER_TYPE_EVENT_ID};
        ENABLE_TRACE_PARAMETERS ep = {0};
        ep.Version = ENABLE_TRACE_PARAMETERS_VERSION_2; ep.EnableFilterDesc = &fd; ep.FilterDescCount = 1;
        ULONG rc = getenv("WHYFS_DIAG_NO_KFILE") ? ERROR_SUCCESS
                   : EnableTraceEx2(sa, &KFILE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
                                    getenv("WHYFS_DIAG_KFILE_KW") ? _strtoui64(getenv("WHYFS_DIAG_KFILE_KW"), NULL, 16) : KFILE_KEYWORDS, 0, 0,
                                    getenv("WHYFS_NO_ID_FILTER") ? NULL : &ep);
        if (rc != ERROR_SUCCESS) { fprintf(stderr, "enable Kernel-File: %lu\n", rc); return 3; }
        rc = EnableTraceEx2(sa, &KPROC, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0x10, 0, 0, NULL);
        if (rc != ERROR_SUCCESS) { fprintf(stderr, "enable Kernel-Process: %lu\n", rc); return 3; }
        TRACEHANDLE ha = open_rt(name_a, on_file_event), hb = open_rt(name_b, on_sys_event);
        HANDLE ta = CreateThread(NULL, 0, consume, &ha, 0, NULL), tb = CreateThread(NULL, 0, consume, &hb, 0, NULL);
        SetConsoleCtrlHandler(on_ctrl, TRUE);
        printf("{\"ready\":true,\"pid\":%lu}\n", GetCurrentProcessId());
        fflush(stdout);
        // Any input on stdin, or its end, is a stop request (the CLI / service holds the other end).
        CreateThread(NULL, 0, stdin_watch, NULL, 0, NULL);
        while (!stop_requested) {
            Sleep(100);
            // Reorder window: sessions flush every second per CPU buffer; delivery lag measured
            // up to ~3 s under load (max_lag_*_ms).  Records arriving later are counted (late_records).
            merge_step(wall_now_ns() - REORDER_WINDOW_NS);
            if (stats_requested) {
                InterlockedExchange(&stats_requested, 0);
                EVENT_TRACE_PROPERTIES *qa = mkprops(0, 0), *qb = mkprops(0, 0);
                if (ControlTraceW(sa, NULL, qa, EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS &&
                    ControlTraceW(sb, NULL, qb, EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS) {
                    lost_a = qa->EventsLost; lost_b = qb->EventsLost; bufs_lost_a = qa->RealTimeBuffersLost; bufs_lost_b = qb->RealTimeBuffersLost;
                    st.kernel_lost = (uint64_t)lost_a + lost_b + bufs_lost_a + bufs_lost_b;
                }
                free(qa); free(qb);
                print_stats();
            }
        }
        ControlTraceW(sa, NULL, pa, EVENT_TRACE_CONTROL_FLUSH);
        ControlTraceW(sb, NULL, pb, EVENT_TRACE_CONTROL_FLUSH);
        Sleep(300);
        ControlTraceW(sa, NULL, pa, EVENT_TRACE_CONTROL_STOP);
        ControlTraceW(sb, NULL, pb, EVENT_TRACE_CONTROL_STOP);
        WaitForSingleObject(ta, 10000); WaitForSingleObject(tb, 10000);
        CloseTrace(ha); CloseTrace(hb);
        lost_a = pa->EventsLost; lost_b = pb->EventsLost; bufs_lost_a = pa->RealTimeBuffersLost; bufs_lost_b = pb->RealTimeBuffersLost;
        st.kernel_lost = (uint64_t)pa->EventsLost + pb->EventsLost + pa->RealTimeBuffersLost + pb->RealTimeBuffersLost;
        merge_step(INT64_MAX);
    }
    if (record_fp) fclose(record_fp);
    if (writer) {
        EnterCriticalSection(&wlock); writer_stop = 1; WakeConditionVariable(&wcond); LeaveCriticalSection(&wlock);
        WaitForSingleObject(writer, INFINITE);
    }
    print_stats();
    return writer_failed ? 1 : 0;
}
