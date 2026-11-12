/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Independent native Windows memory-write reference. Only this test's own DLL,
 * process handles and allocations are used. The exported marker is never run.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>

#ifdef OWNED_MARKER_DLL
#pragma section(".text$madeira", read, execute)
__declspec(allocate(".text$madeira")) __declspec(align(16))
const unsigned char MadeiraOwnedMarker[16] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf1, 0xf2
};
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef LONG (WINAPI *nt_write_t)(HANDLE, PVOID, const VOID *, SIZE_T, SIZE_T *);
static nt_write_t nt_write;
static unsigned checks;
static const BYTE original[16] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf1, 0xf2
};
static const BYTE changed[5] = {0xa1, 0xb2, 0xc3, 0xd4, 0xe5};

static void require(BOOL result, const char *name)
{
    ++checks;
    if (!result) {
        printf("{\"event\":\"failure\",\"case\":\"%s\",\"lastError\":%lu}\n", name, GetLastError());
        exit(1);
    }
}

static DWORD protection(const void *address)
{
    MEMORY_BASIC_INFORMATION information;
    require(VirtualQuery(address, &information, sizeof(information)) == sizeof(information), "query-owned-mapping");
    return information.Protect;
}

static LONG attempt_nt(const char *name, HANDLE process, void *destination, const void *source,
                       SIZE_T *written)
{
    LONG status;
    DWORD exception = 0;
    __try {
        status = nt_write(process, destination, source, sizeof(changed), written);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        exception = GetExceptionCode(); status = (LONG)exception;
    }
    printf("{\"event\":\"nt-write\",\"case\":\"%s\",\"status\":\"%08lx\",\"written\":%llu,\"countPointer\":%s,\"caughtException\":\"%08lx\"}\n",
           name, (ULONG)status, (unsigned long long)(written ? *written : 0), written ? "true" : "false", exception);
    return status;
}

static BOOL attempt_wpm(const char *name, HANDLE process, void *destination, const void *source,
                       SIZE_T *written)
{
    BOOL okay = FALSE;
    DWORD exception = 0, error;
    SetLastError(ERROR_SUCCESS);
    __try {
        okay = WriteProcessMemory(process, destination, source, sizeof(changed), written);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        exception = GetExceptionCode();
    }
    error = GetLastError();
    printf("{\"event\":\"write-process-memory\",\"case\":\"%s\",\"success\":%s,\"error\":%lu,\"written\":%llu,\"caughtException\":\"%08lx\"}\n",
           name, okay ? "true" : "false", error, (unsigned long long)*written, exception);
    return okay;
}

static void verify_patch(BYTE *marker)
{
    require(!memcmp(marker, changed, sizeof(changed)), "actual-five-byte-update");
    require(!memcmp(marker + sizeof(changed), original + sizeof(changed), sizeof(original) - sizeof(changed)),
            "neighboring-eleven-bytes-unchanged");
}

static void restore_marker(BYTE *marker)
{
    SIZE_T written = (SIZE_T)-1;
    require(attempt_nt("restore-while-writecopy", GetCurrentProcess(), marker, original, &written) == 0 &&
            written == sizeof(changed) && !memcmp(marker, original, sizeof(original)), "restore-real-marker-bytes");
}

int wmain(int argc, WCHAR **argv)
{
    static const struct { const char *name; DWORD access; BOOL must_deny; } handles[] = {
        {"real-self-vm-write-only", PROCESS_VM_WRITE, FALSE},
        {"real-self-write-and-operation", PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE},
        {"real-self-query-only", PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, TRUE},
        {"real-self-write-operation-query", PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE},
    };
    HMODULE module;
    BYTE *marker, *private_page;
    DWORD initial, prior, discard, i;
    SIZE_T written;
    LONG status;
    BOOL okay;
    SYSTEM_INFO system;
    setvbuf(stdout, NULL, _IONBF, 0);
    require(argc == 2, "one-owned-DLL-path-required");
    nt_write = (nt_write_t)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory");
    require(nt_write != NULL, "resolve-native-NtWriteVirtualMemory");
    module = LoadLibraryExW(argv[1], NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    require(module != NULL, "load-owned-compiled-marker-DLL");
    marker = (BYTE *)(void *)GetProcAddress(module, "MadeiraOwnedMarker");
    require(marker && !memcmp(marker, original, sizeof(original)), "exported-owned-marker-bytes");
    initial = protection(marker);
    require((initial & 0xff) == PAGE_EXECUTE_READ, "marker-section-is-really-execute-read");
    printf("{\"event\":\"environment\",\"pointerBits\":%u,\"markerBytes\":16,\"markerExecuted\":false,\"initialProtection\":%lu}\n",
           (unsigned)(sizeof(void *) * 8), initial);

    written = (SIZE_T)-1;
    status = attempt_nt("pseudo-self-direct-RX", GetCurrentProcess(), marker, changed, &written);
    require(status < 0 && !memcmp(marker, original, sizeof(original)) && protection(marker) == initial,
            "native-direct-RX-write-rejected-without-change");
    require(VirtualProtect(marker, sizeof(original), PAGE_EXECUTE_WRITECOPY, &prior), "real-PE-writecopy-transition");
    require(prior == initial && (protection(marker) & 0xff) == PAGE_EXECUTE_WRITECOPY, "real-writecopy-protection");
    written = (SIZE_T)-1;
    require(attempt_nt("pseudo-self-writecopy", GetCurrentProcess(), marker, changed, &written) == 0 &&
            written == sizeof(changed), "native-writecopy-write-count-five");
    verify_patch(marker);
    restore_marker(marker);
    require(VirtualProtect(marker, sizeof(original), initial, &discard) && protection(marker) == initial,
            "restore-execute-read-protection");

    written = (SIZE_T)-1;
    require(attempt_wpm("pseudo-self-auto-RX", GetCurrentProcess(), marker, changed, &written) &&
            written == sizeof(changed), "WPM-auto-writes-owned-RX-image");
    verify_patch(marker);
    require(protection(marker) == initial, "WPM-preserves-RX-protection");
    written = (SIZE_T)-1;
    require(attempt_wpm("pseudo-self-restore-RX", GetCurrentProcess(), marker, original, &written) &&
            written == sizeof(changed) && !memcmp(marker, original, sizeof(original)) && protection(marker) == initial,
            "WPM-restores-bytes-and-preserves-RX");

    for (i = 0; i < sizeof(handles) / sizeof(*handles); ++i) {
        HANDLE process = OpenProcess(handles[i].access, FALSE, GetCurrentProcessId());
        require(process != NULL, "open-actual-self-process-handle");
        printf("{\"event\":\"handle-access\",\"case\":\"%s\",\"grantedRequest\":%lu}\n", handles[i].name, handles[i].access);
        require(VirtualProtect(marker, sizeof(original), PAGE_EXECUTE_WRITECOPY, &prior), "handle-test-writecopy");
        written = (SIZE_T)-1;
        status = attempt_nt(handles[i].name, process, marker, changed, &written);
        if (status == 0) {
            require(!handles[i].must_deny && written == sizeof(changed), "native-real-handle-success-has-write-rights-and-count");
            verify_patch(marker); restore_marker(marker);
        } else require(!memcmp(marker, original, sizeof(original)), "failed-real-handle-write-does-not-change-bytes");
        require(VirtualProtect(marker, sizeof(original), initial, &discard), "restore-after-real-handle-test");
        written = (SIZE_T)-1;
        okay = attempt_wpm(handles[i].name, process, marker, changed, &written);
        if (okay) {
            require(!handles[i].must_deny && written == sizeof(changed), "WPM-real-handle-success-has-write-rights-and-count");
            verify_patch(marker);
            written = (SIZE_T)-1;
            require(attempt_wpm("restore-after-real-WPM", GetCurrentProcess(), marker, original, &written) &&
                    written == sizeof(changed), "restore-after-real-WPM");
        }
        require(!memcmp(marker, original, sizeof(original)) && protection(marker) == initial,
                "real-handle-WPM-retains-original-protection-and-neighbors");
        CloseHandle(process);
    }

    GetSystemInfo(&system);
    private_page = VirtualAlloc(NULL, system.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    require(private_page != NULL, "allocate-one-owned-private-page");
    memcpy(private_page, original, sizeof(original));
    written = (SIZE_T)-1;
    require(attempt_nt("owned-private-RW", GetCurrentProcess(), private_page, changed, &written) == 0 &&
            written == sizeof(changed), "native-owned-private-write");
    verify_patch(private_page); memcpy(private_page, original, sizeof(original));
    written = (SIZE_T)-1;
    status = attempt_nt("invalid-source-address-one", GetCurrentProcess(), private_page, (const void *)1, &written);
    require(status < 0 && !memcmp(private_page, original, sizeof(original)), "invalid-source-is-honest-failure");
    written = (SIZE_T)-1;
    require(attempt_nt("invalid-destination-address-one", GetCurrentProcess(), (void *)1, changed, &written) < 0,
            "invalid-destination-is-honest-failure");
    written = (SIZE_T)-1;
    require(attempt_nt("invalid-null-process-handle", NULL, private_page, changed, &written) < 0 &&
            !memcmp(private_page, original, sizeof(original)), "invalid-handle-is-honest-failure");
    require(VirtualProtect(private_page, system.dwPageSize, PAGE_READONLY, &prior), "owned-private-readonly");
    written = (SIZE_T)-1;
    status = attempt_nt("owned-private-readonly", GetCurrentProcess(), private_page, changed, &written);
    require(status < 0 && !memcmp(private_page, original, sizeof(original)), "readonly-direct-write-is-rejected");
    written = (SIZE_T)-1;
    okay = attempt_wpm("owned-private-readonly", GetCurrentProcess(), private_page, changed, &written);
    if (okay) { require(written == sizeof(changed), "readonly-WPM-reports-real-count"); verify_patch(private_page); }
    else require(!memcmp(private_page, original, sizeof(original)), "failed-readonly-WPM-is-unchanged");
    require(protection(private_page) == PAGE_READONLY, "readonly-WPM-preserves-protection");
    require(VirtualProtect(private_page, system.dwPageSize, PAGE_READWRITE, &prior), "restore-owned-private-RW");
    memcpy(private_page, original, sizeof(original));
    require(VirtualProtect(private_page, system.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &prior), "owned-private-guard");
    written = (SIZE_T)-1;
    status = attempt_nt("owned-private-guard", GetCurrentProcess(), private_page, changed, &written);
    printf("{\"event\":\"guard-after-attempt\",\"protection\":%lu}\n", protection(private_page));
    require(VirtualProtect(private_page, system.dwPageSize, PAGE_READWRITE, &prior), "remove-owned-guard-for-inspection");
    require(status < 0 && !memcmp(private_page, original, sizeof(original)), "guard-write-failure-keeps-bytes");
    require(VirtualFree(private_page, 0, MEM_RELEASE), "release-owned-private-page");
    require(!memcmp(marker, original, sizeof(original)) && protection(marker) == initial, "final-marker-state-restored");
    require(FreeLibrary(module), "unload-only-owned-DLL");
    printf("{\"event\":\"complete\",\"checks\":%u,\"markerExecuted\":false,\"ValveCodeAccessed\":false}\n", checks);
    return 0;
}
#endif
