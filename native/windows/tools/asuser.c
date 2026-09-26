// asuser: run a command as a standard (non-elevated) user from an elevated session.
// Test tool: proves that everyday whyfs use needs no administrator rights.
// The token is the caller's own token reduced by SAFER to "normal user" (Administrators
// disabled) with Medium integrity -- what an ordinary non-elevated process gets.
//   asuser.exe "command line"      -> exit code of the command
#include <windows.h>
#include <winsafer.h>
#include <sddl.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) { fwprintf(stderr, L"usage: asuser \"command\"\n"); return 2; }
    SAFER_LEVEL_HANDLE lvl;
    if (!SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, &lvl, NULL)) { fwprintf(stderr, L"SaferCreateLevel %lu\n", GetLastError()); return 3; }
    HANDLE tok;
    if (!SaferComputeTokenFromLevel(lvl, NULL, &tok, 0, NULL)) { fwprintf(stderr, L"SaferComputeTokenFromLevel %lu\n", GetLastError()); return 3; }
    PSID medium; ConvertStringSidToSidW(L"S-1-16-8192", &medium);
    TOKEN_MANDATORY_LABEL tml = {{medium, SE_GROUP_INTEGRITY}};
    if (!SetTokenInformation(tok, TokenIntegrityLevel, &tml, sizeof tml + GetLengthSid(medium))) { fwprintf(stderr, L"SetTokenInformation %lu\n", GetLastError()); return 3; }
    STARTUPINFOW si = {sizeof si};
    PROCESS_INFORMATION pi;
    if (!CreateProcessAsUserW(tok, NULL, argv[1], NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) { fwprintf(stderr, L"CreateProcessAsUser %lu\n", GetLastError()); return 3; }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);
    return (int)code;
}
