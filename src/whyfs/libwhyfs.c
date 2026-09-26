#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

static __thread int in_hook = 0;
static int log_fd = -1;
static const char *log_path = NULL;
static const char *run_id = NULL;
static const char *root_path = NULL;
static int capture_all = 0;
static pthread_mutex_t buf_mu = PTHREAD_MUTEX_INITIALIZER;
static char out_buf[262144];
static size_t out_used = 0;

static long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void json_escape(const char *src, char *dst, size_t n) {
    size_t j = 0;
    if (!src) src = "";
    for (size_t i = 0; src[i] && j + 2 < n; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= n) break;
            dst[j++]='\\'; dst[j++]=(char)c;
        } else if (c == '\n') {
            if (j + 2 >= n) break;
            dst[j++]='\\'; dst[j++]='n';
        } else if (c == '\r') {
            if (j + 2 >= n) break;
            dst[j++]='\\'; dst[j++]='r';
        } else if (c == '\t') {
            if (j + 2 >= n) break;
            dst[j++]='\\'; dst[j++]='t';
        } else if (c < 0x20) {
            continue;
        } else {
            dst[j++]=(char)c;
        }
    }
    dst[j]='\0';
}

static int raw_open_log(void) {
    if (log_fd >= 0) return log_fd;
    if (!log_path || !*log_path) return -1;
    log_fd = (int)syscall(SYS_openat, AT_FDCWD, log_path, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0600);
    return log_fd;
}

static void flush_buffer_locked(void) {
    if (!out_used) return;
    int fd = raw_open_log();
    if (fd >= 0) (void)syscall(SYS_write, fd, out_buf, out_used);
    out_used = 0;
}

static void flush_buffer(void) {
    if (in_hook) return;
    in_hook = 1;
    pthread_mutex_lock(&buf_mu);
    flush_buffer_locked();
    pthread_mutex_unlock(&buf_mu);
    in_hook = 0;
}

static void emit_raw(const char *buf, size_t len) {
    if (in_hook) return;
    in_hook = 1;
    pthread_mutex_lock(&buf_mu);
    if (len >= sizeof(out_buf)) {
        flush_buffer_locked();
        int fd = raw_open_log();
        if (fd >= 0) (void)syscall(SYS_write, fd, buf, len);
    } else {
        if (out_used + len > sizeof(out_buf)) flush_buffer_locked();
        memcpy(out_buf + out_used, buf, len);
        out_used += len;
    }
    pthread_mutex_unlock(&buf_mu);
    in_hook = 0;
}

static void resolve_path_at(int dirfd, const char *path, char *out, size_t n) {
    if (!path || !*path) { if (n) out[0]='\0'; return; }
    if (path[0] == '/') { snprintf(out, n, "%s", path); return; }
    char base[PATH_MAX] = {0};
    if (dirfd == AT_FDCWD) {
        if (!getcwd(base, sizeof(base))) snprintf(base, sizeof(base), ".");
    } else {
        char proc[64];
        snprintf(proc, sizeof(proc), "/proc/self/fd/%d", dirfd);
        ssize_t r = readlink(proc, base, sizeof(base)-1);
        if (r > 0) base[r] = '\0'; else snprintf(base, sizeof(base), ".");
    }
    snprintf(out, n, "%s/%s", base, path);
}

static int should_log_path(const char *path) {
    if (!path || !*path) return 0;
    if (capture_all) return 1;
    if (!root_path || !*root_path) return 1;
    size_t n = strlen(root_path);
    if (strncmp(path, root_path, n) != 0) return 0;
    return path[n] == '\0' || path[n] == '/';
}

static void emit_open_event(const char *path, int flags, const char *api) {
    if (!log_path || !path || strcmp(path, log_path) == 0 || !should_log_path(path)) return;
    char p[PATH_MAX*2], pe[PATH_MAX*4], ap[64];
    snprintf(p, sizeof(p), "%s", path);
    json_escape(p, pe, sizeof(pe));
    json_escape(api ? api : "open", ap, sizeof(ap));
    int acc = flags & O_ACCMODE;
    int rd = (acc == O_RDONLY || acc == O_RDWR) ? 1 : 0;
    int wr = (acc == O_WRONLY || acc == O_RDWR || (flags & (O_CREAT|O_TRUNC|O_APPEND))) ? 1 : 0;
    char buf[PATH_MAX*5 + 512];
    int m = snprintf(buf, sizeof(buf),
        "{\"ts_ns\":%lld,\"run_id\":\"%s\",\"pid\":%d,\"ppid\":%d,\"kind\":\"open\",\"api\":\"%s\",\"path\":\"%s\",\"read\":%s,\"write\":%s,\"flags\":%d}\n",
        now_ns(), run_id ? run_id : "", getpid(), getppid(), ap, pe, rd?"true":"false", wr?"true":"false", flags);
    if (m > 0) emit_raw(buf, (size_t)m);
}

static void emit_path2(const char *kind, const char *a, const char *b) {
    if (!log_path) return;
    if (!capture_all && !should_log_path(a) && !should_log_path(b)) return;
    char ae[PATH_MAX*4], be[PATH_MAX*4], ke[64];
    json_escape(a ? a : "", ae, sizeof(ae));
    json_escape(b ? b : "", be, sizeof(be));
    json_escape(kind, ke, sizeof(ke));
    char buf[PATH_MAX*9 + 512];
    int m = snprintf(buf, sizeof(buf),
      "{\"ts_ns\":%lld,\"run_id\":\"%s\",\"pid\":%d,\"ppid\":%d,\"kind\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\"}\n",
      now_ns(), run_id ? run_id : "", getpid(), getppid(), ke, ae, be);
    if (m > 0) emit_raw(buf, (size_t)m);
}

static void emit_process_start(void) {
    if (!log_path) return;
    char exe[PATH_MAX] = {0}, cwd[PATH_MAX] = {0};
    ssize_t r = readlink("/proc/self/exe", exe, sizeof(exe)-1); if (r > 0) exe[r]='\0';
    if (!getcwd(cwd, sizeof(cwd))) cwd[0]='\0';
    char ee[PATH_MAX*4], ce[PATH_MAX*4];
    json_escape(exe, ee, sizeof(ee)); json_escape(cwd, ce, sizeof(ce));
    char buf[PATH_MAX*9 + 512];
    int m = snprintf(buf, sizeof(buf),
      "{\"ts_ns\":%lld,\"run_id\":\"%s\",\"pid\":%d,\"ppid\":%d,\"kind\":\"process\",\"exe\":\"%s\",\"cwd\":\"%s\"}\n",
      now_ns(), run_id ? run_id : "", getpid(), getppid(), ee, ce);
    if (m > 0) emit_raw(buf, (size_t)m);
}

__attribute__((destructor)) static void fini_whyfs(void) { flush_buffer(); }

__attribute__((constructor)) static void init_whyfs(void) {
    log_path = getenv("WHYFS_LOG");
    run_id = getenv("WHYFS_RUN_ID");
    root_path = getenv("WHYFS_ROOT");
    capture_all = getenv("WHYFS_CAPTURE_ALL") && strcmp(getenv("WHYFS_CAPTURE_ALL"), "1") == 0;
    if (log_path && *log_path) emit_process_start();
}

typedef pid_t (*fork_fn)(void);
pid_t fork(void) {
    static fork_fn real_fork = NULL;
    if (!real_fork) real_fork = dlsym(RTLD_NEXT, "fork");
    flush_buffer();
    pid_t rc = real_fork();
    if (rc == 0) { log_fd = -1; out_used = 0; }
    return rc;
}

typedef int (*execve_fn)(const char*, char *const[], char *const[]);
int execve(const char *path, char *const argv[], char *const envp[]) {
    static execve_fn real_execve = NULL;
    if (!real_execve) real_execve = dlsym(RTLD_NEXT, "execve");
    flush_buffer();
    return real_execve(path, argv, envp);
}

#define RESOLVE(sym) do { if (!real_##sym) real_##sym = dlsym(RTLD_NEXT, #sym); } while(0)

typedef int (*open_fn)(const char*, int, ...);
int open(const char *path, int flags, ...) {
    static open_fn real_open = NULL; RESOLVE(open);
    mode_t mode=0; if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode=(mode_t)va_arg(ap,int); va_end(ap); }
    int rc = (flags & O_CREAT) ? real_open(path,flags,mode) : real_open(path,flags);
    if (rc >= 0 && !in_hook) { char full[PATH_MAX*2]; resolve_path_at(AT_FDCWD,path,full,sizeof(full)); emit_open_event(full,flags,"open"); }
    return rc;
}

int open64(const char *path, int flags, ...) {
    static open_fn real_open64 = NULL; RESOLVE(open64);
    mode_t mode=0; if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode=(mode_t)va_arg(ap,int); va_end(ap); }
    int rc = (flags & O_CREAT) ? real_open64(path,flags,mode) : real_open64(path,flags);
    if (rc >= 0 && !in_hook) { char full[PATH_MAX*2]; resolve_path_at(AT_FDCWD,path,full,sizeof(full)); emit_open_event(full,flags,"open64"); }
    return rc;
}

typedef int (*openat_fn)(int,const char*,int,...);
int openat(int dirfd, const char *path, int flags, ...) {
    static openat_fn real_openat = NULL; RESOLVE(openat);
    mode_t mode=0; if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode=(mode_t)va_arg(ap,int); va_end(ap); }
    int rc = (flags & O_CREAT) ? real_openat(dirfd,path,flags,mode) : real_openat(dirfd,path,flags);
    if (rc >= 0 && !in_hook) { char full[PATH_MAX*2]; resolve_path_at(dirfd,path,full,sizeof(full)); emit_open_event(full,flags,"openat"); }
    return rc;
}

int openat64(int dirfd, const char *path, int flags, ...) {
    static openat_fn real_openat64 = NULL; RESOLVE(openat64);
    mode_t mode=0; if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode=(mode_t)va_arg(ap,int); va_end(ap); }
    int rc = (flags & O_CREAT) ? real_openat64(dirfd,path,flags,mode) : real_openat64(dirfd,path,flags);
    if (rc >= 0 && !in_hook) { char full[PATH_MAX*2]; resolve_path_at(dirfd,path,full,sizeof(full)); emit_open_event(full,flags,"openat64"); }
    return rc;
}

typedef FILE* (*fopen_fn)(const char*,const char*);
FILE *fopen(const char *path, const char *mode) {
    static fopen_fn real_fopen = NULL; RESOLVE(fopen);
    FILE *f = real_fopen(path,mode);
    if (f && !in_hook) {
      int flags = 0; if (strchr(mode,'r')) flags|=O_RDONLY; if (strchr(mode,'w')) flags|=O_WRONLY|O_CREAT|O_TRUNC; if (strchr(mode,'a')) flags|=O_WRONLY|O_CREAT|O_APPEND; if (strchr(mode,'+')) flags=O_RDWR|O_CREAT;
      char full[PATH_MAX*2]; resolve_path_at(AT_FDCWD,path,full,sizeof(full)); emit_open_event(full,flags,"fopen");
    }
    return f;
}
FILE *fopen64(const char *path, const char *mode) {
    static fopen_fn real_fopen64 = NULL; RESOLVE(fopen64);
    FILE *f = real_fopen64(path,mode);
    if (f && !in_hook) {
      int flags = 0; if (strchr(mode,'r')) flags|=O_RDONLY; if (strchr(mode,'w')) flags|=O_WRONLY|O_CREAT|O_TRUNC; if (strchr(mode,'a')) flags|=O_WRONLY|O_CREAT|O_APPEND; if (strchr(mode,'+')) flags=O_RDWR|O_CREAT;
      char full[PATH_MAX*2]; resolve_path_at(AT_FDCWD,path,full,sizeof(full)); emit_open_event(full,flags,"fopen64");
    }
    return f;
}

typedef int (*rename_fn)(const char*,const char*);
int rename(const char *oldp, const char *newp) {
    static rename_fn real_rename=NULL; RESOLVE(rename);
    int rc=real_rename(oldp,newp);
    if (rc==0 && !in_hook) { char a[PATH_MAX*2],b[PATH_MAX*2]; resolve_path_at(AT_FDCWD,oldp,a,sizeof(a)); resolve_path_at(AT_FDCWD,newp,b,sizeof(b)); emit_path2("rename",a,b); }
    return rc;
}

typedef int (*unlink_fn)(const char*);
int unlink(const char *path) {
    static unlink_fn real_unlink=NULL; RESOLVE(unlink);
    int rc=real_unlink(path);
    if (rc==0 && !in_hook) { char a[PATH_MAX*2]; resolve_path_at(AT_FDCWD,path,a,sizeof(a)); emit_path2("unlink",a,""); }
    return rc;
}
