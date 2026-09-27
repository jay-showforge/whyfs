// whyfs.exe: the command a user types on Windows.  Runs the whyfs package with the private
// Python runtime installed next to it (<install dir>\runtime), passing the command line and
// the console through unchanged, and returns its exit code.
//
// Built with /DWHYFS_GUI as whyfsw.exe: the same, for Explorer's menu entries and the Start
// menu -- a windows-subsystem program running runtime\pythonw.exe, so no console flashes up.
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static const wchar_t *skip_argv0(const wchar_t *cmd) {
    if (*cmd == L'"') { cmd++; while (*cmd && *cmd != L'"') cmd++; if (*cmd) cmd++; }
    else while (*cmd && *cmd != L' ' && *cmd != L'\t') cmd++;
    while (*cmd == L' ' || *cmd == L'\t') cmd++;
    return cmd;
}

#ifdef WHYFS_GUI
#define RUNTIME L"pythonw.exe"
#else
#define RUNTIME L"python.exe"
#endif

static int run(void) {
    wchar_t dir[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, dir, MAX_PATH);
    if (!n || n >= MAX_PATH) return 1;
    wchar_t *slash = wcsrchr(dir, L'\\');
    if (slash) *slash = 0;
    const wchar_t *rest = skip_argv0(GetCommandLineW());
    size_t cap = wcslen(dir) + wcslen(rest) + 64;
    wchar_t *cmd = malloc(cap * sizeof(wchar_t));
    if (!cmd) return 1;
    // -B: never write bytecode into the install directory (it is read-only for users, and
    // files the installer did not install would survive an uninstall).
    swprintf(cmd, cap, L"\"%s\\runtime\\" RUNTIME L"\" -B -m whyfs %s", dir, rest);
    STARTUPINFOW si = {sizeof si};
    PROCESS_INFORMATION pi;
#ifndef WHYFS_GUI
    SetConsoleCtrlHandler(NULL, TRUE);  // Ctrl+C goes to the child; the launcher waits for it
#endif
    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
#ifdef WHYFS_GUI
        wchar_t msg[MAX_PATH + 128];
        swprintf(msg, MAX_PATH + 128, L"Cannot start the WhyFS runtime in %s\\runtime (error %lu).", dir, GetLastError());
        MessageBoxW(NULL, msg, L"WhyFS", MB_ICONERROR | MB_OK);
#else
        fwprintf(stderr, L"whyfs: cannot start the bundled runtime in %s\\runtime (error %lu)\n", dir, GetLastError());
#endif
        return 1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    return (int)code;
}

#ifdef WHYFS_GUI
int WINAPI wWinMain(HINSTANCE h, HINSTANCE p, PWSTR c, int s) {
    (void)h; (void)p; (void)c; (void)s;
    return run();
}
#else
int wmain(void) { return run(); }
#endif
