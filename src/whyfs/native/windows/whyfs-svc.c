// whyfs-svc: the Windows service that runs whyfs collectors on behalf of ordinary users.
//
// Kernel tracing (ETW) needs administrator rights; asking a question about a file should
// not.  The service (LocalSystem, installed once) serves a named pipe to local
// authenticated users.  Requests are one JSON line each:
//   {"op":"start","workspace":"C:\\...","run_id":"...","temp_roots":["..."],"capture_all":false}
//   {"op":"stop","workspace":"C:\\..."}      {"op":"status","workspace":"C:\\..."}
// Replies are one JSON line.
//
// Security model (the Windows counterpart of the Linux daemon's privilege separation):
//  * The requester is identified by impersonating the pipe client; the workspace is
//    canonicalized (junctions resolved) and must be openable for writing *by that user*;
//    a reparse-point .whyfs is refused.
//  * The collector records only that user's processes (--user-sid), and its SQLite writer
//    impersonates the user (--user-token): SYSTEM never writes into a user's directory.
//  * Only the user who started a collection, or an administrator, can stop it.
//  * Orphaned whyfs ETW sessions (a crashed collector) are stopped at service start: they
//    would otherwise keep consuming the same kernel providers and starve new sessions.
//
//   whyfs-svc install | uninstall | console      (install/uninstall need elevation)
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <aclapi.h>
#include <evntrace.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "advapi32.lib")

#define SERVICE_NAME L"whyfs"
#define PIPE_NAME L"\\\\.\\pipe\\whyfs-service"
#define MAX_RUNS 64

static SERVICE_STATUS_HANDLE status_handle;
static SERVICE_STATUS svc_status;
static HANDLE stop_event;
static FILE *svc_log;
static CRITICAL_SECTION runs_lock;

static void logmsg(const char *fmt, ...) {
    if (!svc_log) return;
    SYSTEMTIME t; GetLocalTime(&t);
    fprintf(svc_log, "%04d-%02d-%02d %02d:%02d:%02d ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    va_list ap; va_start(ap, fmt); vfprintf(svc_log, fmt, ap); va_end(ap);
    fputc('\n', svc_log); fflush(svc_log);
}

// ---------------------------------------------------------------- tiny JSON (flat objects we produce)
static char *json_str(const char *js, const char *key) {  // "key":"value" (with \\ and \" escapes)
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(js, pat);
    if (!p) return NULL;
    p = strchr(p + strlen(pat), ':'); if (!p) return NULL;
    while (*++p == ' ') {}
    if (*p != '"') return NULL;
    p++;
    char *out = malloc(strlen(p) + 1), *o = out;
    while (*p && *p != '"') { if (*p == '\\' && p[1]) { p++; *o++ = *p == 'n' ? '\n' : *p; p++; } else *o++ = *p++; }
    *o = 0;
    return out;
}
static int json_bool(const char *js, const char *key) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(js, pat);
    if (!p) return 0;
    p = strchr(p, ':');
    return p && !strncmp(p + 1 + strspn(p + 1, " "), "true", 4);
}
static int json_str_array(const char *js, const char *key, char **out, int max) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(js, pat);
    if (!p || !(p = strchr(p, '['))) return 0;
    int n = 0;
    p++;
    while (n < max) {
        while (*p == ' ' || *p == ',') p++;
        if (*p != '"') break;  // ']' or malformed: done
        const char *e = p + 1; char *o = malloc(strlen(e) + 1), *w = o;
        while (*e && *e != '"') { if (*e == '\\' && e[1]) { e++; *w++ = *e++; } else *w++ = *e++; }
        *w = 0; out[n++] = o;
        if (!*e) break;
        p = e + 1;
    }
    return n;
}
static void json_escape(char *dst, size_t cap, const char *s) {
    size_t o = 0;
    for (; *s && o + 3 < cap; s++) { if (*s == '"' || *s == '\\') dst[o++] = '\\'; dst[o++] = *s; }
    dst[o] = 0;
}

// ---------------------------------------------------------------- utf8 <-> wide
static wchar_t *W(const char *s) { int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0); wchar_t *w = malloc(n * sizeof(wchar_t)); MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n); return w; }
static char *U(const wchar_t *w) { int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL); char *s = malloc(n); WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL); return s; }

// ---------------------------------------------------------------- runs
typedef struct {
    int used;
    char workspace[1024];   // canonical
    char session[64];
    char sid[256];
    HANDLE proc, stdin_w, stdout_r;
    DWORD pid;
} run_t;
static run_t runs[MAX_RUNS];

static run_t *find_run(const char *ws) {
    for (int i = 0; i < MAX_RUNS; i++) if (runs[i].used && !_stricmp(runs[i].workspace, ws)) return &runs[i];
    return NULL;
}

// Stop every ETW session whose name starts with "whyfs-" and that no live run owns.
static void cleanup_orphan_sessions(void) {
    EVENT_TRACE_PROPERTIES *props[64];
    ULONG count = 0;
    for (int i = 0; i < 64; i++) {
        props[i] = calloc(1, sizeof(EVENT_TRACE_PROPERTIES) + 2048);
        props[i]->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 2048;
        props[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        props[i]->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    }
    if (QueryAllTracesW(props, 64, &count) == ERROR_SUCCESS) {
        for (ULONG i = 0; i < count; i++) {
            wchar_t *name = (wchar_t *)((BYTE *)props[i] + props[i]->LoggerNameOffset);
            if (wcsncmp(name, L"whyfs-", 6)) continue;
            char *n = U(name);
            int owned = 0;
            for (int r = 0; r < MAX_RUNS; r++)
                if (runs[r].used && (!strcmp(runs[r].session, n) || (!strncmp(n, runs[r].session, strlen(runs[r].session)) && !strcmp(n + strlen(runs[r].session), "-sys")))) owned = 1;
            if (!owned) {
                EVENT_TRACE_PROPERTIES *p = calloc(1, sizeof(EVENT_TRACE_PROPERTIES) + 2048);
                p->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 2048; p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
                ULONG rc = ControlTraceW(0, name, p, EVENT_TRACE_CONTROL_STOP);
                logmsg("stopped orphaned ETW session %s (rc %lu)", n, rc);
                free(p);
            }
            free(n);
        }
    }
    for (int i = 0; i < 64; i++) free(props[i]);
}

static void exe_dir(wchar_t *out, size_t cap) {
    GetModuleFileNameW(NULL, out, (DWORD)cap);
    wchar_t *slash = wcsrchr(out, L'\\');
    if (slash) *slash = 0;
}

// ---------------------------------------------------------------- request handling (impersonating the client)
static void reply(HANDLE pipe, const char *s) { DWORD n; WriteFile(pipe, s, (DWORD)strlen(s), &n, NULL); WriteFile(pipe, "\n", 1, &n, NULL); FlushFileBuffers(pipe); }
static void reply_err(HANDLE pipe, const char *msg) { char e[1200], b[1400]; json_escape(e, sizeof e, msg); snprintf(b, sizeof b, "{\"ok\":false,\"error\":\"%s\"}", e); reply(pipe, b); }

// As the client: canonical workspace path, and a writable, non-redirected store inside it.
static int client_workspace(const char *ws_in, char *canon, size_t cap, char *err, size_t errcap) {
    wchar_t *w = W(ws_in);
    HANDLE h = CreateFileW(w, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) { snprintf(err, errcap, "cannot open workspace %s (error %lu)", ws_in, GetLastError()); return 0; }
    wchar_t fin[1024];
    DWORD n = GetFinalPathNameByHandleW(h, fin, 1024, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    CloseHandle(h);
    if (!n || n >= 1024) { snprintf(err, errcap, "cannot canonicalize workspace"); return 0; }
    wchar_t *p = fin;
    if (!wcsncmp(p, L"\\\\?\\UNC\\", 8)) { p += 6; p[0] = L'\\'; }
    else if (!wcsncmp(p, L"\\\\?\\", 4)) p += 4;
    char *c = U(p); snprintf(canon, cap, "%s", c); free(c);
    char state[1200]; snprintf(state, sizeof state, "%s\\.whyfs", canon);
    wchar_t *ws = W(state);
    DWORD attr = GetFileAttributesW(ws);
    free(ws);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) { snprintf(err, errcap, "%s is not a whyfs workspace (run `whyfs init`)", canon); return 0; }
    if (attr & FILE_ATTRIBUTE_REPARSE_POINT) { snprintf(err, errcap, "refusing redirected state directory %s", state); return 0; }
    char db[1300]; snprintf(db, sizeof db, "%s\\whyfs.db", state);
    wchar_t *wdb = W(db);
    HANDLE f = CreateFileW(wdb, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(wdb);
    if (f == INVALID_HANDLE_VALUE) { snprintf(err, errcap, "the whyfs store in %s is not writable by you (error %lu)", canon, GetLastError()); return 0; }
    BY_HANDLE_FILE_INFORMATION bi;
    int ok = GetFileInformationByHandle(f, &bi) && !(bi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && bi.nNumberOfLinks == 1;
    CloseHandle(f);
    if (!ok) { snprintf(err, errcap, "refusing linked or redirected store file %s", db); return 0; }
    return 1;
}

static int token_is_admin(HANDLE tok) {
    BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD sz = sizeof sid; BOOL member = FALSE;
    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sid, &sz);
    CheckTokenMembership(tok, sid, &member);
    return member;
}

static void handle_start(HANDLE pipe, const char *req, HANDLE tok, const char *sid, const char *canon) {
    EnterCriticalSection(&runs_lock);
    run_t *r = find_run(canon);
    if (r && WaitForSingleObject(r->proc, 0) == WAIT_TIMEOUT) {
        char e[1100], b[1400]; json_escape(e, sizeof e, canon);
        snprintf(b, sizeof b, "{\"ok\":true,\"already\":true,\"pid\":%lu,\"workspace\":\"%s\",\"session\":\"%s\"}", r->pid, e, r->session);
        LeaveCriticalSection(&runs_lock); reply(pipe, b); return;
    }
    if (r) { CloseHandle(r->proc); CloseHandle(r->stdin_w); CloseHandle(r->stdout_r); r->used = 0; }
    int slot = -1;
    for (int i = 0; i < MAX_RUNS; i++) if (!runs[i].used) { slot = i; break; }
    if (slot < 0) { LeaveCriticalSection(&runs_lock); reply_err(pipe, "too many active workspaces"); return; }
    r = &runs[slot];
    memset(r, 0, sizeof *r);
    snprintf(r->workspace, sizeof r->workspace, "%s", canon);
    snprintf(r->sid, sizeof r->sid, "%s", sid);
    unsigned long long h = 1469598103934665603ULL;
    for (const char *p = canon; *p; p++) { h ^= (unsigned char)tolower((unsigned char)*p); h *= 1099511628211ULL; }
    snprintf(r->session, sizeof r->session, "whyfs-%016llx", h);

    char *run_id = json_str(req, "run_id");
    char *temps[8]; int ntemps = json_str_array(req, "temp_roots", temps, 8);
    int cap_all = json_bool(req, "capture_all");
    // inheritable impersonation token for the collector's SQLite writer
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    HANDLE itok = NULL;
    DuplicateTokenEx(tok, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &sa, SecurityImpersonation, TokenImpersonation, &itok);
    HANDLE in_r, in_w, out_r, out_w;
    CreatePipe(&in_r, &in_w, &sa, 0); SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
    CreatePipe(&out_r, &out_w, &sa, 0); SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    wchar_t dir[MAX_PATH]; exe_dir(dir, MAX_PATH);
    wchar_t logpath[MAX_PATH];
    wchar_t pd[MAX_PATH]; GetEnvironmentVariableW(L"ProgramData", pd, MAX_PATH);
    swprintf(logpath, MAX_PATH, L"%s\\whyfs\\logs", pd);
    CreateDirectoryW(logpath, NULL);
    wchar_t *wsess = W(r->session);
    swprintf(logpath, MAX_PATH, L"%s\\whyfs\\logs\\%s.log", pd, wsess);
    free(wsess);
    HANDLE errf = CreateFileW(logpath, FILE_APPEND_DATA, FILE_SHARE_READ, &sa, OPEN_ALWAYS, 0, NULL);

    char cmd[8192];
    int n = snprintf(cmd, sizeof cmd, "\"%s\\whyfs-collect-win.exe\" --root \"%s\" --run-id \"%s\" --user-sid %s --user-token %llu --session %s%s",
                     U(dir), canon, run_id ? run_id : "run", sid, (unsigned long long)(uintptr_t)itok, r->session, cap_all ? " --capture-all" : "");
    for (int i = 0; i < ntemps && n < (int)sizeof cmd - 600; i++) n += snprintf(cmd + n, sizeof cmd - n, " --temp-root \"%s\"", temps[i]);
    wchar_t *wcmd = W(cmd);

    SIZE_T asz = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &asz);
    LPPROC_THREAD_ATTRIBUTE_LIST al = malloc(asz);
    InitializeProcThreadAttributeList(al, 1, 0, &asz);
    HANDLE inherit[4] = {in_r, out_w, errf, itok};
    UpdateProcThreadAttribute(al, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit, sizeof inherit, NULL, NULL);
    STARTUPINFOEXW si = {0};
    si.StartupInfo.cb = sizeof si; si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = in_r; si.StartupInfo.hStdOutput = out_w; si.StartupInfo.hStdError = errf;
    si.lpAttributeList = al;
    PROCESS_INFORMATION pi;
    BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, NULL, dir, &si.StartupInfo, &pi);
    DWORD cerr = GetLastError();
    DeleteProcThreadAttributeList(al); free(al); free(wcmd);
    CloseHandle(in_r); CloseHandle(out_w); CloseHandle(errf); CloseHandle(itok);
    for (int i = 0; i < ntemps; i++) free(temps[i]);
    free(run_id);
    if (!ok) {
        CloseHandle(in_w); CloseHandle(out_r); LeaveCriticalSection(&runs_lock);
        char e[200]; snprintf(e, sizeof e, "cannot start collector (error %lu)", cerr); reply_err(pipe, e); return;
    }
    CloseHandle(pi.hThread);
    r->used = 1; r->proc = pi.hProcess; r->pid = pi.dwProcessId; r->stdin_w = in_w; r->stdout_r = out_r;
    // wait for {"ready":true,...}
    char line[512]; DWORD got = 0, total = 0; int ready = 0;
    for (int tries = 0; tries < 300 && !ready; tries++) {
        DWORD avail = 0;
        if (PeekNamedPipe(out_r, NULL, 0, NULL, &avail, NULL) && avail) {
            if (ReadFile(out_r, line + total, (DWORD)(sizeof line - 1 - total), &got, NULL)) { total += got; line[total] = 0; if (strstr(line, "\"ready\"")) ready = 1; }
        } else if (WaitForSingleObject(pi.hProcess, 100) != WAIT_TIMEOUT) break;
    }
    if (!ready) {
        DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(r->proc); CloseHandle(r->stdin_w); CloseHandle(r->stdout_r); r->used = 0;
        LeaveCriticalSection(&runs_lock);
        char e[300]; snprintf(e, sizeof e, "collector did not become ready (exit %lu); see %%ProgramData%%\\whyfs\\logs", code); reply_err(pipe, e);
        cleanup_orphan_sessions();
        return;
    }
    char e[1100], b[1500]; json_escape(e, sizeof e, canon);
    snprintf(b, sizeof b, "{\"ok\":true,\"pid\":%lu,\"workspace\":\"%s\",\"session\":\"%s\"}", r->pid, e, r->session);
    logmsg("start %s pid %lu session %s user %s", canon, r->pid, r->session, sid);
    LeaveCriticalSection(&runs_lock);
    reply(pipe, b);
}

static void handle_stop(HANDLE pipe, HANDLE tok, const char *sid, const char *canon) {
    EnterCriticalSection(&runs_lock);
    run_t *r = find_run(canon);
    if (!r) { LeaveCriticalSection(&runs_lock); reply(pipe, "{\"ok\":true,\"running\":false}"); return; }
    if (strcmp(r->sid, sid) && !token_is_admin(tok)) { LeaveCriticalSection(&runs_lock); reply_err(pipe, "this collection was started by another user"); return; }
    DWORD n;
    WriteFile(r->stdin_w, "stop\n", 5, &n, NULL);
    CloseHandle(r->stdin_w); r->stdin_w = NULL;
    DWORD wr = WaitForSingleObject(r->proc, 180000);
    char buf[65536]; DWORD total = 0, got;
    while (total < sizeof buf - 1 && ReadFile(r->stdout_r, buf + total, (DWORD)(sizeof buf - 1 - total), &got, NULL) && got) total += got;
    buf[total] = 0;
    DWORD code = 0; GetExitCodeProcess(r->proc, &code);
    if (wr == WAIT_TIMEOUT) TerminateProcess(r->proc, 1);
    CloseHandle(r->proc); CloseHandle(r->stdout_r);
    r->used = 0;
    // last JSON line = final statistics
    char *last = NULL;
    for (char *line = strtok(buf, "\r\n"); line; line = strtok(NULL, "\r\n")) if (line[0] == '{' && !strstr(line, "\"ready\"")) last = line;
    char b[70000];
    snprintf(b, sizeof b, "{\"ok\":%s,\"exit_code\":%lu,\"stats\":%s}", code == 0 && wr != WAIT_TIMEOUT ? "true" : "false", code, last ? last : "{}");
    logmsg("stop %s exit %lu", canon, code);
    LeaveCriticalSection(&runs_lock);
    cleanup_orphan_sessions();
    reply(pipe, b);
}

static void handle_status(HANDLE pipe, const char *canon) {
    EnterCriticalSection(&runs_lock);
    run_t *r = find_run(canon);
    char b[2000];
    if (r && WaitForSingleObject(r->proc, 0) == WAIT_TIMEOUT) {
        char e[1100]; json_escape(e, sizeof e, canon);
        snprintf(b, sizeof b, "{\"ok\":true,\"running\":true,\"pid\":%lu,\"workspace\":\"%s\",\"session\":\"%s\"}", r->pid, e, r->session);
    } else if (r) {
        DWORD code = 0; GetExitCodeProcess(r->proc, &code);
        snprintf(b, sizeof b, "{\"ok\":true,\"running\":false,\"crashed\":true,\"exit_code\":%lu}", code);
    } else snprintf(b, sizeof b, "{\"ok\":true,\"running\":false}");
    LeaveCriticalSection(&runs_lock);
    reply(pipe, b);
}

static DWORD WINAPI client_thread(LPVOID arg) {
    HANDLE pipe = arg;
    char req[16384]; DWORD total = 0, got;
    while (total < sizeof req - 1 && ReadFile(pipe, req + total, (DWORD)(sizeof req - 1 - total), &got, NULL) && got) {
        total += got; req[total] = 0;
        if (strchr(req, '\n')) break;
    }
    req[total] = 0;
    char *op = json_str(req, "op"), *ws = json_str(req, "workspace");
    if (!op || !ws) { reply_err(pipe, "bad request"); goto done; }
    if (!ImpersonateNamedPipeClient(pipe)) { reply_err(pipe, "cannot identify client"); goto done; }
    HANDLE tok = NULL;
    OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, TRUE, &tok);
    char canon[1024], err[1200];
    int ok = client_workspace(ws, canon, sizeof canon, err, sizeof err);
    RevertToSelf();
    if (!tok) { reply_err(pipe, "cannot read client token"); goto done; }
    BYTE tu[512]; DWORD tsz = 0;
    char *sid = NULL;
    if (GetTokenInformation(tok, TokenUser, tu, sizeof tu, &tsz)) ConvertSidToStringSidA(((TOKEN_USER *)tu)->User.Sid, &sid);
    if (!sid) { reply_err(pipe, "cannot read client identity"); CloseHandle(tok); goto done; }
    if (!ok) reply_err(pipe, err);
    else if (!strcmp(op, "start")) handle_start(pipe, req, tok, sid, canon);
    else if (!strcmp(op, "stop")) handle_stop(pipe, tok, sid, canon);
    else if (!strcmp(op, "status")) handle_status(pipe, canon);
    else reply_err(pipe, "unknown op");
    LocalFree(sid);
    CloseHandle(tok);
done:
    free(op); free(ws);
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return 0;
}

// ---------------------------------------------------------------- machine-wide labels
// The machine service (docs/MACHINE_MODE.md): `runtime\python.exe -B -m whyfs machine serve`,
// running as SYSTEM, supervises the machine-mode ETW collector, serves the local API pipe
// (\\.\pipe\whyfs-api) and applies retention.  Restarted with backoff if it exits; asked
// to drain ("stop" on its stdin) when the service stops.
static DWORD WINAPI machine_thread(LPVOID arg) {
    (void)arg;
    wchar_t dir[MAX_PATH]; exe_dir(dir, MAX_PATH);
    wchar_t py[MAX_PATH + 32]; swprintf(py, MAX_PATH + 32, L"%s\\runtime\\python.exe", dir);
    if (GetFileAttributesW(py) == INVALID_FILE_ATTRIBUTES) {
        logmsg("machine labels unavailable: no bundled runtime at %ls (install with the MSI)", py);
        return 0;
    }
    DWORD backoff = 5000;
    while (WaitForSingleObject(stop_event, 0) == WAIT_TIMEOUT) {
        SECURITY_ATTRIBUTES isa = {sizeof isa, NULL, TRUE};
        HANDLE in_r, in_w;
        if (!CreatePipe(&in_r, &in_w, &isa, 0)) { logmsg("machine: CreatePipe %lu", GetLastError()); Sleep(5000); continue; }
        SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
        wchar_t pd[MAX_PATH], logp[MAX_PATH + 64];
        GetEnvironmentVariableW(L"ProgramData", pd, MAX_PATH);
        swprintf(logp, MAX_PATH + 64, L"%s\\whyfs\\logs\\machine-output.log", pd);
        HANDLE out = CreateFileW(logp, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, &isa, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        STARTUPINFOW si = {sizeof si};
        si.dwFlags = STARTF_USESTDHANDLES; si.hStdInput = in_r; si.hStdOutput = out; si.hStdError = out;
        PROCESS_INFORMATION pi;
        wchar_t cmd[MAX_PATH + 96]; swprintf(cmd, MAX_PATH + 96, L"\"%s\" -B -m whyfs machine serve", py);
        DWORD started = GetTickCount();
        BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, dir, &si, &pi);
        CloseHandle(in_r);
        if (out != INVALID_HANDLE_VALUE) CloseHandle(out);
        if (!ok) { logmsg("machine: CreateProcess %lu", GetLastError()); CloseHandle(in_w); Sleep(backoff); continue; }
        CloseHandle(pi.hThread);
        logmsg("machine labels: service process %lu started", pi.dwProcessId);
        HANDLE hs[2] = {pi.hProcess, stop_event};
        DWORD w = WaitForMultipleObjects(2, hs, FALSE, INFINITE);
        if (w == WAIT_OBJECT_0 + 1) {  // service stopping: let it drain the collector
            DWORD n; WriteFile(in_w, "stop\n", 5, &n, NULL);
            if (WaitForSingleObject(pi.hProcess, 150000) == WAIT_TIMEOUT) { TerminateProcess(pi.hProcess, 1); logmsg("machine: terminated after 150 s"); }
        }
        DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hProcess); CloseHandle(in_w);
        logmsg("machine labels: service process exited %lu", code);
        if (WaitForSingleObject(stop_event, 0) != WAIT_TIMEOUT) break;
        backoff = GetTickCount() - started > 300000 ? 5000 : (backoff < 300000 ? backoff * 2 : 300000);
        WaitForSingleObject(stop_event, backoff);
    }
    return 0;
}

static void serve(void) {
    cleanup_orphan_sessions();
    HANDLE machine = CreateThread(NULL, 0, machine_thread, NULL, 0, NULL);
    // SYSTEM and Administrators: full; authenticated local users: read/write (connect + requests)
    PSECURITY_DESCRIPTOR sd = NULL;
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)", SDDL_REVISION_1, &sd, NULL);
    SECURITY_ATTRIBUTES sa = {sizeof sa, sd, FALSE};
    logmsg("whyfs service listening on %s", "\\\\.\\pipe\\whyfs-service");
    while (WaitForSingleObject(stop_event, 0) == WAIT_TIMEOUT) {
        HANDLE pipe = CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                       PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                       PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, &sa);
        if (pipe == INVALID_HANDLE_VALUE) { logmsg("CreateNamedPipe failed %lu", GetLastError()); Sleep(1000); continue; }
        OVERLAPPED ov = {0}; ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        BOOL c = ConnectNamedPipe(pipe, &ov);
        DWORD e = GetLastError();
        if (!c && e == ERROR_IO_PENDING) {
            HANDLE hs[2] = {ov.hEvent, stop_event};
            if (WaitForMultipleObjects(2, hs, FALSE, INFINITE) != WAIT_OBJECT_0) { CancelIo(pipe); CloseHandle(pipe); CloseHandle(ov.hEvent); break; }
        } else if (!c && e != ERROR_PIPE_CONNECTED) { CloseHandle(pipe); CloseHandle(ov.hEvent); continue; }
        CloseHandle(ov.hEvent);
        // synchronous I/O from here on
        HANDLE t = CreateThread(NULL, 0, client_thread, pipe, 0, NULL);
        if (t) CloseHandle(t); else CloseHandle(pipe);
    }
    // service stopping: drain every collector
    EnterCriticalSection(&runs_lock);
    for (int i = 0; i < MAX_RUNS; i++) if (runs[i].used) {
        DWORD n; if (runs[i].stdin_w) { WriteFile(runs[i].stdin_w, "stop\n", 5, &n, NULL); CloseHandle(runs[i].stdin_w); }
        WaitForSingleObject(runs[i].proc, 120000);
        CloseHandle(runs[i].proc); CloseHandle(runs[i].stdout_r); runs[i].used = 0;
        logmsg("stopped collector for %s at service shutdown", runs[i].workspace);
    }
    LeaveCriticalSection(&runs_lock);
    if (machine) { WaitForSingleObject(machine, 180000); CloseHandle(machine); }
    cleanup_orphan_sessions();
    LocalFree(sd);
}

// ---------------------------------------------------------------- service plumbing
static void set_state(DWORD s) { svc_status.dwCurrentState = s; SetServiceStatus(status_handle, &svc_status); }
static DWORD WINAPI ctrl(DWORD c, DWORD t, LPVOID d, LPVOID x) {
    (void)t; (void)d; (void)x;
    if (c == SERVICE_CONTROL_STOP || c == SERVICE_CONTROL_SHUTDOWN) { set_state(SERVICE_STOP_PENDING); SetEvent(stop_event); }
    return NO_ERROR;
}
static void open_log(void) {
    wchar_t pd[MAX_PATH], p[MAX_PATH];
    GetEnvironmentVariableW(L"ProgramData", pd, MAX_PATH);
    swprintf(p, MAX_PATH, L"%s\\whyfs", pd); CreateDirectoryW(p, NULL);
    swprintf(p, MAX_PATH, L"%s\\whyfs\\logs", pd); CreateDirectoryW(p, NULL);
    swprintf(p, MAX_PATH, L"%s\\whyfs\\logs\\service.log", pd);
    svc_log = _wfopen(p, L"a");
}
static void WINAPI svc_main(DWORD argc, LPWSTR *argv) {
    (void)argc; (void)argv;
    status_handle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, ctrl, NULL);
    svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    set_state(SERVICE_RUNNING);
    serve();
    set_state(SERVICE_STOPPED);
}

static int install(void) {
    wchar_t path[MAX_PATH]; GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t quoted[MAX_PATH + 4]; swprintf(quoted, MAX_PATH + 4, L"\"%s\"", path);
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { fprintf(stderr, "OpenSCManager failed %lu (run elevated)\n", GetLastError()); return 1; }
    SC_HANDLE s = CreateServiceW(scm, SERVICE_NAME, L"whyfs file provenance collector", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                 SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, quoted, NULL, NULL, NULL, NULL, NULL);
    if (!s && GetLastError() == ERROR_SERVICE_EXISTS) s = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!s) { fprintf(stderr, "CreateService failed %lu\n", GetLastError()); CloseServiceHandle(scm); return 1; }
    SERVICE_DESCRIPTIONW d = {L"Labels files with their provenance: which process (and, when known, which AI agent session) created or changed them, from which inputs. Local only; file contents are never read. `whyfs label FILE`."};
    ChangeServiceConfig2W(s, SERVICE_CONFIG_DESCRIPTION, &d);
    SERVICE_FAILURE_ACTIONSW fa = {0}; SC_ACTION act[2] = {{SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 30000}};
    fa.dwResetPeriod = 86400; fa.cActions = 2; fa.lpsaActions = act;
    ChangeServiceConfig2W(s, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
    if (!StartServiceW(s, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) fprintf(stderr, "StartService failed %lu\n", GetLastError());
    CloseServiceHandle(s); CloseServiceHandle(scm);
    printf("installed and started service %ls\n", SERVICE_NAME);
    return 0;
}
static int uninstall(void) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { fprintf(stderr, "OpenSCManager failed %lu\n", GetLastError()); return 1; }
    SC_HANDLE s = OpenServiceW(scm, SERVICE_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!s) { fprintf(stderr, "service not installed\n"); CloseServiceHandle(scm); return 0; }
    SERVICE_STATUS st;
    ControlService(s, SERVICE_CONTROL_STOP, &st);
    for (int i = 0; i < 100 && QueryServiceStatus(s, &st) && st.dwCurrentState != SERVICE_STOPPED; i++) Sleep(200);
    DeleteService(s);
    CloseServiceHandle(s); CloseServiceHandle(scm);
    printf("removed service %ls\n", SERVICE_NAME);
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    InitializeCriticalSection(&runs_lock);
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (argc > 1 && !wcscmp(argv[1], L"install")) return install();
    if (argc > 1 && !wcscmp(argv[1], L"uninstall")) return uninstall();
    open_log();
    if (argc > 1 && !wcscmp(argv[1], L"console")) { svc_log = stderr; serve(); return 0; }
    SERVICE_TABLE_ENTRYW table[] = {{(LPWSTR)SERVICE_NAME, svc_main}, {NULL, NULL}};
    if (!StartServiceCtrlDispatcherW(table)) { fprintf(stderr, "run as a service, or: whyfs-svc install | uninstall | console\n"); return 1; }
    return 0;
}
