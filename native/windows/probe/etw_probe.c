// ETW field probe (diagnostic): which Kernel-File / Kernel-Process events does this
// Windows build emit for a workload, and with which fields?  Launches the workload
// itself so it knows the root pid, follows its process tree, and dumps every event of
// tracked processes with all TDH-decoded properties.
//
//   etw_probe.exe OUT.txt "command line"
#define INITGUID
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

static const GUID KFILE = {0xEDD08927, 0x9CC4, 0x4E65, {0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}};
static const GUID KPROC = {0x22FB2CD6, 0x0E7B, 0x422B, {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}};
static const wchar_t *SESSION = L"whyfs-etw-probe";
static const GUID PROCESS_GUID = {0x3d6fa8d0, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
static const GUID FILEIO_GUID = {0x90cbdc39, 0x4a3e, 0x11d1, {0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3}};
static long nmap_dumped;
static const GUID PAGEFAULT_GUID = {0x3d6fa8d3, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
static ULONGLONG KFILE_KW = 0x1FB0;  // FILEIO(cleanup/close) CREATE READ WRITE DELETE_PATH RENAME_SETLINK_PATH CREATE_NEW_FILE

static FILE *out;
static DWORD tracked[4096];
static int ntracked;
static int is_tracked(DWORD pid) { for (int i = 0; i < ntracked; i++) if (tracked[i] == pid) return 1; return 0; }
static void track(DWORD pid) { if (!is_tracked(pid) && ntracked < 4096) tracked[ntracked++] = pid; }

static int get_u32(PEVENT_RECORD ev, const wchar_t *name, ULONG *v) {
    PROPERTY_DATA_DESCRIPTOR d = {(ULONGLONG)name, ULONG_MAX, 0};
    ULONG sz = 0;
    if (TdhGetPropertySize(ev, 0, NULL, 1, &d, &sz) != ERROR_SUCCESS || sz != 4) return 0;
    return TdhGetProperty(ev, 0, NULL, 1, &d, 4, (PBYTE)v) == ERROR_SUCCESS;
}

static void dump(PEVENT_RECORD ev) {
    ULONG sz = 0;
    TdhGetEventInformation(ev, 0, NULL, NULL, &sz);
    PTRACE_EVENT_INFO info = malloc(sz);
    if (TdhGetEventInformation(ev, 0, NULL, info, &sz) != ERROR_SUCCESS) { free(info); return; }
    const wchar_t *task = info->TaskNameOffset ? (wchar_t *)((BYTE *)info + info->TaskNameOffset) : L"";
    const wchar_t *opc = info->OpcodeNameOffset ? (wchar_t *)((BYTE *)info + info->OpcodeNameOffset) : L"";
    const GUID *g = &ev->EventHeader.ProviderId;
    const wchar_t *tag = IsEqualGUID(g, &KFILE) ? L"FILE" : IsEqualGUID(g, &KPROC) ? L"PROC" : IsEqualGUID(g, &PROCESS_GUID) ? L"SYSP"
                         : IsEqualGUID(g, &PAGEFAULT_GUID) ? L"SYSM" : L"OTHER";
    if (tag[0] == L'O') { wchar_t gs[64]; StringFromGUID2(g, gs, 64); fwprintf(out, L"[%s] ", gs); }
    fwprintf(out, L"%s id=%u v=%u task=%s op=%s opc=%u pid=%lu tid=%lu ts=%lld |", tag, ev->EventHeader.EventDescriptor.Id,
             ev->EventHeader.EventDescriptor.Version, task, opc, ev->EventHeader.EventDescriptor.Opcode, ev->EventHeader.ProcessId, ev->EventHeader.ThreadId,
             ev->EventHeader.TimeStamp.QuadPart);
    BYTE *data = ev->UserData, *end = data + ev->UserDataLength;
    ULONG ptrsz = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
    for (ULONG i = 0; i < info->TopLevelPropertyCount && data < end; i++) {
        EVENT_PROPERTY_INFO *p = &info->EventPropertyInfoArray[i];
        const wchar_t *name = (wchar_t *)((BYTE *)info + p->NameOffset);
        wchar_t buf[2048];
        ULONG bsz = sizeof buf;
        USHORT used = 0;
        if (p->Flags & (PropertyStruct | PropertyParamCount)) { fwprintf(out, L" %s=<complex>", name); break; }
        ULONG len = p->length;
        if ((p->Flags & PropertyParamLength)) { fwprintf(out, L" %s=<paramlen>", name); break; }
        ULONG st = TdhFormatProperty(info, NULL, ptrsz, p->nonStructType.InType, p->nonStructType.OutType, (USHORT)len,
                                     (USHORT)(end - data), data, &bsz, buf, &used);
        if (st != ERROR_SUCCESS) { fwprintf(out, L" %s=<err %lu>", name, st); break; }
        fwprintf(out, L" %s=%s", name, buf);
        data += used;
    }
    fwprintf(out, L"\n");
    free(info);
}

static void WINAPI on_event(PEVENT_RECORD ev) {
    DWORD pid = ev->EventHeader.ProcessId;
    if (IsEqualGUID(&ev->EventHeader.ProviderId, &KPROC) && ev->EventHeader.EventDescriptor.Id == 1) {
        ULONG child = 0, parent = 0;
        if (get_u32(ev, L"ProcessID", &child) && get_u32(ev, L"ParentProcessID", &parent) && is_tracked(parent)) track(child);
    }
    if (IsEqualGUID(&ev->EventHeader.ProviderId, &PROCESS_GUID) && ev->EventHeader.EventDescriptor.Opcode == 1) {
        ULONG child = 0, parent = 0;
        if (get_u32(ev, L"ProcessId", &child) && get_u32(ev, L"ParentId", &parent) && is_tracked(parent)) { track(child); dump(ev); return; }
    }
    if (IsEqualGUID(&ev->EventHeader.ProviderId, &PAGEFAULT_GUID)) {
        ULONG p = 0;
        if (get_u32(ev, L"ProcessId", &p) && is_tracked(p)) { dump(ev); return; }
    }
    if (IsEqualGUID(&ev->EventHeader.ProviderId, &KFILE) && (ev->EventHeader.EventDescriptor.Id == 10 || ev->EventHeader.EventDescriptor.Id == 11)) {
        // NameCreate / NameDelete: FileKey (8) then FileName (wide string)
        if (ev->UserDataLength > 8 && wcsstr((wchar_t *)((BYTE *)ev->UserData + 8), L"whyfsprobe")) dump(ev);
        return;
    }
    if (is_tracked(pid)) dump(ev);
}

static long n_sysp, n_sysm, n_other_sys, n_file, n_proc;
static CRITICAL_SECTION lock;
static struct { GUID g; UCHAR op; long n; } kinds[64]; static int nkinds;
static void count_kind(PEVENT_RECORD ev) {
    for (int i = 0; i < nkinds; i++) if (IsEqualGUID(&kinds[i].g, &ev->EventHeader.ProviderId) && kinds[i].op == ev->EventHeader.EventDescriptor.Opcode) { kinds[i].n++; return; }
    if (nkinds < 64) { kinds[nkinds].g = ev->EventHeader.ProviderId; kinds[nkinds].op = ev->EventHeader.EventDescriptor.Opcode; kinds[nkinds++].n = 1; }
}
static void WINAPI on_event_counted(PEVENT_RECORD ev) {
    const GUID *g = &ev->EventHeader.ProviderId;
    if (IsEqualGUID(g, &PROCESS_GUID)) n_sysp++;
    else if (IsEqualGUID(g, &PAGEFAULT_GUID)) n_sysm++;
    else if (IsEqualGUID(g, &KFILE)) n_file++;
    else if (IsEqualGUID(g, &KPROC)) n_proc++;
    else if (IsEqualGUID(g, &FILEIO_GUID) && (ev->EventHeader.EventDescriptor.Opcode == 37 || ev->EventHeader.EventDescriptor.Opcode == 38)) {
        EnterCriticalSection(&lock); count_kind(ev);
        DWORD mpid = ev->UserDataLength >= 44 ? *(DWORD *)((BYTE *)ev->UserData + 40) : 0;
        if (is_tracked(mpid)) {
            nmap_dumped++;
            fwprintf(out, L"MAP opc=%u hpid=%lu len=%u flags=0x%x ts=%lld raw=", ev->EventHeader.EventDescriptor.Opcode, ev->EventHeader.ProcessId,
                     ev->UserDataLength, ev->EventHeader.Flags, ev->EventHeader.TimeStamp.QuadPart);
            for (USHORT i = 0; i < ev->UserDataLength; i++) fwprintf(out, L"%02x", ((BYTE *)ev->UserData)[i]);
            fwprintf(out, L"\n");
        }
        LeaveCriticalSection(&lock);
    }
    else { n_other_sys++; EnterCriticalSection(&lock); count_kind(ev); LeaveCriticalSection(&lock); if (n_other_sys < 40 || (n_other_sys % 5000) == 0) { EnterCriticalSection(&lock); dump(ev); LeaveCriticalSection(&lock); } }
    EnterCriticalSection(&lock);
    on_event(ev);
    LeaveCriticalSection(&lock);
}

static DWORD WINAPI consume(LPVOID h) { ULONG r = ProcessTrace((TRACEHANDLE *)h, 1, NULL, NULL); fwprintf(stderr, L"ProcessTrace -> %lu\n", r); return 0; }

static EVENT_TRACE_PROPERTIES *mkprops(ULONG mode, ULONG flags) {
    size_t psz = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    EVENT_TRACE_PROPERTIES *p = calloc(1, psz);
    p->Wnode.BufferSize = (ULONG)psz; p->Wnode.Flags = WNODE_FLAG_TRACED_GUID; p->Wnode.ClientContext = 1;  // QPC
    p->LogFileMode = mode; p->EnableFlags = flags; p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    p->BufferSize = 256; p->MinimumBuffers = 64; p->MaximumBuffers = 256;
    return p;
}

static TRACEHANDLE start_session(const wchar_t *name, EVENT_TRACE_PROPERTIES *p) {
    EVENT_TRACE_PROPERTIES *stop = mkprops(0, 0);
    ControlTraceW(0, name, stop, EVENT_TRACE_CONTROL_STOP);  // stale session from an earlier run
    TRACEHANDLE s;
    ULONG st = StartTraceW(&s, name, p);
    if (st != ERROR_SUCCESS) { fwprintf(stderr, L"StartTrace %s %lu\n", name, st); exit(1); }
    return s;
}

static TRACEHANDLE open_rt(const wchar_t *name) {
    EVENT_TRACE_LOGFILEW lf = {0};
    lf.LoggerName = (LPWSTR)name;
    lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = on_event_counted;
    return OpenTraceW(&lf);
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 3) { fwprintf(stderr, L"usage: etw_probe OUT.txt \"command\"\n"); return 2; }
    out = _wfopen(argv[1], L"w, ccs=UTF-8");
    const wchar_t *SYS = L"whyfs-etw-probe-sys";
    EVENT_TRACE_PROPERTIES *pa = mkprops(EVENT_TRACE_REAL_TIME_MODE, 0);
    EVENT_TRACE_PROPERTIES *pb = mkprops(EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE,
                                         EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_VAMAP);
    TRACEHANDLE sa = start_session(SESSION, pa), sb = start_session(SYS, pb);
    ULONG st = EnableTraceEx2(sa, &KFILE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, KFILE_KW, 0, 0, NULL);
    if (st != ERROR_SUCCESS) fwprintf(stderr, L"enable file %lu\n", st);
    st = EnableTraceEx2(sa, &KPROC, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0x10, 0, 0, NULL);
    if (st != ERROR_SUCCESS) fwprintf(stderr, L"enable proc %lu\n", st);
    TRACEHANDLE th[2] = {open_rt(SESSION), open_rt(SYS)};
    fwprintf(stderr, L"handles %llx %llx (invalid=%llx)\n", th[0], th[1], (ULONGLONG)INVALID_PROCESSTRACE_HANDLE);
    InitializeCriticalSection(&lock);
    HANDLE thr = CreateThread(NULL, 0, consume, &th[0], 0, NULL);
    HANDLE thr2 = CreateThread(NULL, 0, consume, &th[1], 0, NULL);
    Sleep(1500);
    STARTUPINFOW si = {sizeof si};
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(NULL, argv[2], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fwprintf(stderr, L"CreateProcess %lu\n", GetLastError()); return 1;
    }
    track(pi.dwProcessId);
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, 120000);
    Sleep(3000);
    ControlTraceW(sa, NULL, pa, EVENT_TRACE_CONTROL_STOP);
    ControlTraceW(sb, NULL, pb, EVENT_TRACE_CONTROL_STOP);
    WaitForSingleObject(thr, 10000); WaitForSingleObject(thr2, 10000);
    CloseTrace(th[0]); CloseTrace(th[1]);
    fwprintf(stderr, L"done; lost %lu/%lu, tracked %d; all events: sysproc %ld sysmap %ld sysother %ld file %ld proc %ld\n",
             pa->EventsLost, pb->EventsLost, ntracked, n_sysp, n_sysm, n_other_sys, n_file, n_proc);
    for (int i = 0; i < nkinds; i++) { wchar_t gs[64]; StringFromGUID2(&kinds[i].g, gs, 64); fwprintf(stderr, L"  other %s opcode %u: %ld\n", gs, kinds[i].op, kinds[i].n); }
    fclose(out);
    return 0;
}







