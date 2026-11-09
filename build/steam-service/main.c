/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2026 125hz
 * Madeira Converter Exception: see LICENSE-EXCEPTION.md */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include "prepare.h"
#include "update_handoff.h"

static SC_HANDLE manager;
static wchar_t root[32768];
static const wchar_t service_name[] = L"Steam Client Service";
static void event(const char *name, DWORD value)
{
    DWORD incoming = GetLastError(), written;
    char record[128];
    int length = snprintf(record, sizeof(record), "[steam-service] %s=%lu\r\n", name, (unsigned long)value);
    /* Unbuffered Wine printf emits format pieces separately. Concurrent native
     * diagnostics can split even the tag/key/value across physical rows. Send
     * one bounded record to our inherited stderr, never a Valve endpoint.
     * Logging failure/short writes neither retry a fragment nor change SCM. */
    if (length > 0 && (size_t)length < sizeof(record)) {
        HANDLE output = GetStdHandle(STD_ERROR_HANDLE);
        if (output && output != INVALID_HANDLE_VALUE)
            WriteFile(output, record, (DWORD)length, &written, NULL);
    }
    SetLastError(incoming);
}
static DWORD last_error(void) { DWORD e = GetLastError(); return e ? e : ERROR_GEN_FAILURE; }

static uint32_t open_manager(void)
{
    ULONGLONG begin = GetTickCount64();
    HANDLE process = NULL, started = NULL;
    BOOL other = FALSE;
    unsigned traces = 0;
    for (;;) {
        if (traces++ < 4) event("scm-call", SC_MANAGER_CONNECT);
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
            static const wchar_t *values[] = {L"Type", L"Start", L"WOW64"};
            static const char *labels[] = {"registry-type", "registry-start", "registration-wow64"};
            for (unsigned j = 0; j < 3; j++) {
                DWORD value, kind, size = sizeof(value);
                if (RegQueryValueExW(key, values[j], NULL, &kind, (BYTE *)&value, &size) == ERROR_SUCCESS &&
                    kind == REG_DWORD && size == sizeof(value)) event(labels[j], value);
            }
            DWORD kind, bytes = 0;
            LSTATUS image = RegQueryValueExW(key, L"ImagePath", NULL, &kind, NULL, &bytes);
            event("registry-image-query", (DWORD)image);
            if (!image) { event("registry-image-kind", kind); event("registry-image-bytes", bytes); }
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
    event("installer-binary-type", type); /* 0=32-bit, 6=64-bit; CPU selection remains the Windows loader's job. */
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
static struct {
    wchar_t service_path[32768], updater_path[32768];
    HANDLE parent, updater;
    struct steam_update_witness witness;
    ULONGLONG next_updater_scan;
    unsigned attempts;
} update;

static uint64_t filetime_value(FILETIME time)
{
    return ((uint64_t)time.dwHighDateTime << 32) | time.dwLowDateTime;
}
static BOOL process_identity(HANDLE process, const wchar_t *expected, uint64_t *created)
{
    wchar_t path[32768], canonical[32768];
    DWORD length = 32768;
    FILETIME creation, exit, kernel, user;
    if (!QueryFullProcessImageNameW(process, 0, path, &length) ||
        !GetProcessTimes(process, &creation, &exit, &kernel, &user)) return FALSE;
    DWORD n = GetFullPathNameW(path, 32768, canonical, NULL);
    if (!n || n >= 32768 || _wcsicmp(canonical, expected)) return FALSE;
    *created = filetime_value(creation);
    return TRUE;
}
static void configured_paths(const wchar_t *command)
{
    wchar_t image[32768], *filename;
    const wchar_t *begin, *end;
    update.service_path[0] = update.updater_path[0] = 0;
    if (!command) return;
    begin = command;
    while (*begin == L' ' || *begin == L'\t') begin++;
    if (*begin == L'"') {
        begin++;
        end = wcschr(begin, L'"');
    } else {
        /* ImagePath may contain an unquoted path with spaces. The held
         * process image must subsequently match this entire executable. */
        for (end = begin; *end; end++)
            if (!_wcsnicmp(end, L".exe", 4) &&
                (!end[4] || end[4] == L' ' || end[4] == L'\t')) { end += 4; break; }
    }
    if (!end || end == begin || (size_t)(end - begin) >= 32768) return;
    wmemcpy(image, begin, end - begin); image[end - begin] = 0;
    DWORD n = GetFullPathNameW(image, 32768, update.service_path, &filename);
    if (!n || n >= 32768 || !filename || _wcsicmp(filename, L"SteamService.exe")) {
        update.service_path[0] = 0; return;
    }
    size_t prefix = filename - update.service_path;
    if (prefix + wcslen(L"SteamServiceTmp.exe") >= 32768) { update.service_path[0] = 0; return; }
    wmemcpy(update.updater_path, update.service_path, prefix);
    wcscpy(update.updater_path + prefix, L"SteamServiceTmp.exe");
}
static void observe_updater(void)
{
    if (!update.parent || update.updater) return;
    ULONGLONG now = GetTickCount64();
    if (now < update.next_updater_scan) return;
    update.next_updater_scan = now + 100;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W entry = {0}; entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) do {
        if (entry.th32ParentProcessID != update.witness.parent_pid ||
            _wcsicmp(entry.szExeFile, L"SteamServiceTmp.exe")) continue;
        HANDLE child = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
        if (!child) continue;
        struct steam_update_witness candidate = update.witness;
        candidate.child_parent_pid = entry.th32ParentProcessID;
        candidate.child_handle_valid = 1;
        candidate.child_path_matches = process_identity(child, update.updater_path, &candidate.child_created);
        if (steam_update_child_matches(&candidate)) {
            update.updater = child; update.witness = candidate;
            event("update-child-held", entry.th32ProcessID); break;
        }
        CloseHandle(child);
    } while (Process32NextW(snapshot, &entry));
    CloseHandle(snapshot);
}
static void observe_service_owner(const SERVICE_STATUS_PROCESS *status)
{
    if (!update.service_path[0] || update.attempts != 1) return;
    if (!update.parent && status->dwProcessId) {
        HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, status->dwProcessId);
        uint64_t created;
        if (process && process_identity(process, update.service_path, &created)) {
            update.parent = process;
            update.witness.parent_pid = status->dwProcessId;
            update.witness.parent_handle_valid = update.witness.parent_path_matches = 1;
            update.witness.parent_created = created;
            event("update-parent-held", status->dwProcessId);
        } else if (process) CloseHandle(process);
    }
    observe_updater();
}
static void observe_pending_start(SC_HANDLE service)
{
    if (update.attempts != 1) return;
    /* Once pinned, the original process identity is immutable. Repeated SCM
     * queries cannot improve that witness and keep creating RPC/section work
     * while the real service is initializing. Continue observing its child. */
    if (update.parent) { observe_updater(); return; }
    SERVICE_STATUS_PROCESS status;
    DWORD needed;
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&status, sizeof(status), &needed))
        observe_service_owner(&status);
}
struct start_call { SC_HANDLE service; LONG references; DWORD error; };
static void release_start_call(struct start_call *call)
{
    if (!InterlockedDecrement(&call->references)) HeapFree(GetProcessHeap(), 0, call);
}
static DWORD WINAPI call_start_service(void *argument)
{
    struct start_call *call = argument;
    call->error = StartServiceW(call->service, 0, NULL) ? 0 : last_error();
    CloseServiceHandle(call->service);
    release_start_call(call);
    return 0;
}
static uint32_t start_attempt(void)
{
    update.attempts++;
    SC_HANDLE service = OpenServiceW(manager, service_name, SERVICE_QUERY_STATUS);
    if (!service) return last_error();
    SC_HANDLE starter = OpenServiceW(manager, service_name, SERVICE_START);
    if (!starter) { DWORD error = last_error(); CloseServiceHandle(service); return error; }
    struct start_call *call = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*call));
    if (!call) { CloseServiceHandle(starter); CloseServiceHandle(service); return ERROR_NOT_ENOUGH_MEMORY; }
    call->service = starter; call->references = 2;
    FILETIME now; GetSystemTimeAsFileTime(&now);
    if (update.attempts == 1) update.witness.attempt_started = filetime_value(now);
    HANDLE worker = CreateThread(NULL, 0, call_start_service, call, 0, NULL);
    if (!worker) {
        DWORD error = last_error(); HeapFree(GetProcessHeap(), 0, call);
        CloseServiceHandle(starter); CloseServiceHandle(service); return error;
    }
    /* StartService waits for the service control pipe. Query through a separate
     * handle while it waits so the original SCM process cannot disappear before
     * we hold and validate its identity. Neither path invents readiness. */
    ULONGLONG begin = GetTickCount64();
    DWORD error = 0, needed = 0, wait;
    for (;;) {
        observe_pending_start(service);
        wait = WaitForSingleObject(worker, 10);
        if (wait == WAIT_OBJECT_0) { error = call->error; break; }
        if (wait == WAIT_FAILED) { error = last_error(); break; }
        if (GetTickCount64() - begin >= 35000) { error = ERROR_TIMEOUT; break; }
    }
    CloseHandle(worker);
    /* A timed-out worker retains its own SCM handle and context until it
     * returns. Closing our observer cannot leave a dangling stack argument. */
    release_start_call(call);
    if (error && error != ERROR_SERVICE_ALREADY_RUNNING) {
        event("start-error", error); CloseServiceHandle(service); return error;
    }
    begin = GetTickCount64();
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
    CloseServiceHandle(service);
    return error;
}
static int capture_verified_updater(void)
{
    update.next_updater_scan = 0;
    observe_updater();
    if (!update.parent || WaitForSingleObject(update.parent, 0) != WAIT_OBJECT_0) {
        event("update-witness", 0); return 0;
    }
    DWORD code;
    if (!GetExitCodeProcess(update.parent, &code)) return 0;
    update.witness.parent_exited = 1;
    update.witness.parent_exit_code = code;
    event("update-parent-exit", code);
    int verified = steam_update_witness_matches(&update.witness);
    event("update-witness", verified);
    return verified;
}
static uint32_t wait_updater(void)
{
    DWORD wait = WaitForSingleObject(update.updater, 60000), code;
    if (wait == WAIT_TIMEOUT) { event("update-wait-error", ERROR_TIMEOUT); return ERROR_TIMEOUT; }
    if (wait != WAIT_OBJECT_0 || !GetExitCodeProcess(update.updater, &code)) return last_error();
    event("update-child-exit", code);
    return code;
}
static uint32_t start_service(void)
{
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
                if (config->dwServiceType == SERVICE_WIN32_OWN_PROCESS) configured_paths(config->lpBinaryPathName);
            }
            HeapFree(GetProcessHeap(), 0, config);
        }
    }
    if (detail) CloseServiceHandle(detail);
    pipe_diagnostics("steam-pipes-before");
    const struct steam_update_ops ops = {start_attempt, capture_verified_updater, wait_updater};
    DWORD error = service_start_with_update_handoff(&ops);
    pipe_diagnostics("steam-pipes-after");
    if (update.updater) CloseHandle(update.updater);
    if (update.parent) CloseHandle(update.parent);
    return error;
}
int wmain(int argc, wchar_t **argv)
{
    event("update-handoff-v1", 1);
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
