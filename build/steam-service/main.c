/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2026 125hz
 * Madeira Converter Exception: see LICENSE-EXCEPTION.md */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <wchar.h>
#include "prepare.h"

static SC_HANDLE manager;
static wchar_t root[32768];
static const wchar_t service_name[] = L"Steam Client Service";
static void event(const char *name, DWORD value)
{
    fprintf(stderr, "[steam-service] %s=%lu\n", name, (unsigned long)value);
}
static DWORD last_error(void) { DWORD e = GetLastError(); return e ? e : ERROR_GEN_FAILURE; }

static uint32_t open_manager(void)
{
    ULONGLONG begin = GetTickCount64();
    HANDLE process = NULL, started = NULL;
    BOOL other = FALSE;
    for (;;) {
        manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        if (manager) { if (process) CloseHandle(process); if (started) CloseHandle(started); event("scm", 0); return 0; }
        DWORD error = last_error();
        if (error != RPC_S_SERVER_UNAVAILABLE && error != RPC_S_SERVER_TOO_BUSY) {
            if (process) CloseHandle(process);
            if (started) CloseHandle(started);
            return error;
        }
        if (!started) {
            started = CreateEventW(NULL, TRUE, FALSE, L"__wine_SvcctlStartedEvent");
            if (!started) return last_error();
            other = GetLastError() == ERROR_ALREADY_EXISTS;
            event("scm-other-launcher", other);
        }
        if (!process && !other && error == RPC_S_SERVER_UNAVAILABLE) {
            wchar_t path[MAX_PATH + 16];
            UINT n = GetSystemDirectoryW(path, MAX_PATH);
            if (!n || n >= MAX_PATH) { CloseHandle(started); return ERROR_PATH_NOT_FOUND; }
            wcscat(path, L"\\services.exe");
            STARTUPINFOW si = {0}; PROCESS_INFORMATION pi = {0}; si.cb = sizeof(si);
            if (!CreateProcessW(path, NULL, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
                DWORD spawn_error = last_error(); CloseHandle(started); return spawn_error;
            }
            CloseHandle(pi.hThread); process = pi.hProcess;
            event("scm-started", 1);
        }
        if (process && WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
            CloseHandle(process); CloseHandle(started); return ERROR_PROCESS_ABORTED;
        }
        if (GetTickCount64() - begin >= 30000) {
            if (process) CloseHandle(process);
            if (started) CloseHandle(started);
            return ERROR_TIMEOUT;
        }
        Sleep(100); /* RPC reachability, not a guessed startup delay. */
    }
}
static void registry_diagnostics(void)
{
    for (unsigned i = 0; i < 2; i++) {
        HKEY key;
        LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\Steam Client Service", 0,
            KEY_QUERY_VALUE | (i ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &key);
        event(i ? "registry32" : "registry64", (DWORD)status);
        if (!status) {
            DWORD type, kind, size = sizeof(type);
            if (RegQueryValueExW(key, L"WOW64", NULL, &kind, (BYTE *)&type, &size) == ERROR_SUCCESS && kind == REG_DWORD && size == sizeof(type))
                event("registration-wow64", type);
            RegCloseKey(key);
        }
    }
}
static uint32_t query_service(void)
{
    SC_HANDLE service = OpenServiceW(manager, service_name, SERVICE_QUERY_STATUS);
    DWORD error = service ? 0 : last_error();
    event("open-service", error);
    registry_diagnostics();
    if (service) CloseServiceHandle(service);
    return error;
}
static uint32_t install_service(void)
{
    event("installer-attempt", 1);
    if (!root[0]) { event("installer-root-error", ERROR_PATH_NOT_FOUND); return ERROR_PATH_NOT_FOUND; }
    wchar_t path[32768], command[32768];
    if (wcslen(root) + 64 >= 32768) return ERROR_FILENAME_EXCED_RANGE;
    swprintf(path, 32768, L"%ls\\bin\\SteamService.exe", root);
    DWORD type;
    if (!GetBinaryTypeW(path, &type)) { DWORD error = last_error(); event("installer-inspect-error", error); return error; }
    event("installer-binary-type", type); /* 0=x86, 6=x64; Wine handles WoW64. */
    if (type != SCS_32BIT_BINARY && type != SCS_64BIT_BINARY) return ERROR_BAD_EXE_FORMAT;
    swprintf(command, 32768, L"\"%ls\" /install", path);
    STARTUPINFOW si = {0}; PROCESS_INFORMATION pi = {0}; si.cb = sizeof(si);
    if (!CreateProcessW(path, command, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, root, &si, &pi)) {
        DWORD error = last_error(); event("installer-spawn-error", error); return error;
    }
    CloseHandle(pi.hThread);
    DWORD wait = WaitForSingleObject(pi.hProcess, 60000), code;
    DWORD error = 0;
    if (wait == WAIT_TIMEOUT) error = ERROR_TIMEOUT;
    else if (wait != WAIT_OBJECT_0) error = last_error();
    else if (!GetExitCodeProcess(pi.hProcess, &code)) error = last_error();
    else { event("installer-exit", code); error = code; }
    /* Never terminate Valve's installer or edit its service keys. */
    CloseHandle(pi.hProcess);
    if (error) event("installer-error", error);
    return error;
}
static void pipe_diagnostics(const char *stage)
{
    WIN32_FIND_DATAW data;
    HANDLE search = FindFirstFileW(L"\\\\.\\pipe\\*", &data);
    DWORD count = 0;
    if (search == INVALID_HANDLE_VALUE) { event("pipe-enumeration-error", last_error()); return; }
    do {
        /* Count only; pipe names can contain account identifiers. No opening,
         * creation, protocol traffic, or inference of authentication/readiness. */
        if (!_wcsnicmp(data.cFileName, L"Steam", 5)) count++;
    } while (FindNextFileW(search, &data));
    DWORD error = GetLastError();
    FindClose(search);
    if (error != ERROR_NO_MORE_FILES) event("pipe-enumeration-error", error);
    else event(stage, count);
}
static uint32_t start_service(void)
{
    SC_HANDLE service = OpenServiceW(manager, service_name, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service) return last_error();
    DWORD needed = 0;
    SC_HANDLE detail = OpenServiceW(manager, service_name, SERVICE_QUERY_CONFIG);
    if (!detail) event("config-error", last_error());
    else QueryServiceConfigW(detail, NULL, 0, &needed);
    if (detail && needed >= sizeof(QUERY_SERVICE_CONFIGW) && needed < 1024 * 1024) {
        QUERY_SERVICE_CONFIGW *config = HeapAlloc(GetProcessHeap(), 0, needed);
        if (config) {
            if (QueryServiceConfigW(detail, config, needed, &needed)) {
                event("service-type", config->dwServiceType);
                event("service-start-type", config->dwStartType);
                event("image-path-present", config->lpBinaryPathName && config->lpBinaryPathName[0]);
            }
            HeapFree(GetProcessHeap(), 0, config);
        }
    }
    if (detail) CloseServiceHandle(detail);
    pipe_diagnostics("steam-pipes-before");
    DWORD error = 0;
    if (!StartServiceW(service, 0, NULL) && (error = last_error()) != ERROR_SERVICE_ALREADY_RUNNING) {
        CloseServiceHandle(service); return error;
    }
    ULONGLONG begin = GetTickCount64();
    DWORD previous_state = MAXDWORD, previous_checkpoint = MAXDWORD;
    for (;;) {
        SERVICE_STATUS_PROCESS status;
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&status, sizeof(status), &needed)) {
            error = last_error(); break;
        }
        if (status.dwCurrentState != previous_state || status.dwCheckPoint != previous_checkpoint) {
            event("service-state", status.dwCurrentState);
            event("service-checkpoint", status.dwCheckPoint);
            event("service-wait-hint", status.dwWaitHint);
            previous_state = status.dwCurrentState; previous_checkpoint = status.dwCheckPoint;
        }
        if (status.dwCurrentState == SERVICE_RUNNING) { error = 0; break; }
        if (status.dwCurrentState == SERVICE_STOPPED) {
            event("service-specific-exit", status.dwServiceSpecificExitCode);
            error = status.dwWin32ExitCode ? status.dwWin32ExitCode : ERROR_SERVICE_NOT_ACTIVE; break;
        }
        if (GetTickCount64() - begin >= 30000) { error = ERROR_TIMEOUT; break; }
        Sleep(250);
    }
    pipe_diagnostics("steam-pipes-after");
    CloseServiceHandle(service);
    return error;
}
int wmain(int argc, wchar_t **argv)
{
    /* Serialize our launchers; do not race two genuine /install invocations. */
    HANDLE mutex = CreateMutexW(NULL, FALSE, L"Local\\MadeiraSteamServicePreparation");
    if (!mutex) { DWORD error = last_error(); event("result", error); return (int)error; }
    DWORD wait = WaitForSingleObject(mutex, 125000);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
        DWORD error = wait == WAIT_FAILED ? last_error() : ERROR_TIMEOUT;
        event("result", error); CloseHandle(mutex); return (int)error;
    }
    if (argc == 2 && wcslen(argv[1]) < 32768) wcscpy(root, argv[1]);
    else {
        for (unsigned i = 0; i < 2 && !root[0]; i++) {
            HKEY key; DWORD type, bytes = sizeof(root);
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Valve\\Steam", 0,
                KEY_QUERY_VALUE | (i ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &key) == ERROR_SUCCESS) {
                if (RegQueryValueExW(key, L"InstallPath", NULL, &type, (BYTE *)root, &bytes) != ERROR_SUCCESS ||
                    type != REG_SZ || bytes < sizeof(wchar_t) || bytes % sizeof(wchar_t) || bytes > sizeof(root) || root[bytes / sizeof(wchar_t) - 1]) root[0] = 0;
                RegCloseKey(key);
            }
        }
    }
    const struct service_ops ops = {open_manager, query_service, install_service, start_service};
    DWORD error = prepare_service(&ops);
    event("result", error);
    if (manager) CloseServiceHandle(manager);
    ReleaseMutex(mutex); CloseHandle(mutex);
    return (int)error;
}
