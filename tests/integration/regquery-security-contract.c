/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Native-Windows contract research only. No Wine replacement, Steam state,
 * service request, credential or application security decision is modified.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <aclapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#define SENTINEL 0xfeedbeefUL
#define BASIC_SECURITY (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
typedef LONG (WINAPI *query_security_t)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, PULONG);
static query_security_t query_security;
static HKEY owned_key;
static WCHAR relative_name[192];
static BOOL owned;
static unsigned rows;

static void cleanup(void)
{
    RevertToSelf();
    if (owned_key) {
        /* The already granted handle is retained even during the empty-DACL
         * phase. Restore ordinary owner access before deleting our own key. */
        SetSecurityInfo(owned_key, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL);
        RegCloseKey(owned_key);
    }
    if (owned) {
        LSTATUS status = RegDeleteKeyExW(HKEY_LOCAL_MACHINE, relative_name, KEY_WOW64_64KEY, 0);
        if (status) {
            printf("{\"event\":\"cleanup-failed\",\"status\":%ld}\n", status);
            ExitProcess(2);
        }
    }
}

static void require(BOOL okay, const char *operation)
{
    if (!okay) {
        printf("{\"event\":\"infrastructure-failed\",\"operation\":\"%s\",\"lastError\":%lu}\n",
               operation, GetLastError());
        exit(1);
    }
}

static void query(const char *phase, const char *name, HKEY key, DWORD rights)
{
    DWORD a = SENTINEL, w = SENTINEL, meta_a = SENTINEL, meta_w = SENTINEL;
    DWORD count_a = SENTINEL, count_w = SENTINEL, reserved = 0;
    DWORD invalid_a_size = SENTINEL, invalid_w_size = SENTINEL;
    DWORD native_size = SENTINEL, all_size = SENTINEL, reg_size = 0;
    LONG nt, all_nt, fill = (LONG)SENTINEL, fill_all = (LONG)SENTINEL;
    DWORD actual_length = 0, actual_all_length = 0;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    WCHAR class_buffer[2] = {0};
    CHAR class_a[2] = {0};
    LSTATUS ra, rw, ma, mw, null_a, null_w, invalid_class_a, invalid_class_w, reserved_a, reserved_w, reg;
    ra = RegQueryInfoKeyA(key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &a, NULL);
    rw = RegQueryInfoKeyW(key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &w, NULL);
    ma = RegQueryInfoKeyA(key, NULL, NULL, NULL, &count_a, NULL, NULL, NULL, NULL, NULL, &meta_a, NULL);
    mw = RegQueryInfoKeyW(key, NULL, NULL, NULL, &count_w, NULL, NULL, NULL, NULL, NULL, &meta_w, NULL);
    null_a = RegQueryInfoKeyA(key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    null_w = RegQueryInfoKeyW(key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    invalid_class_a = RegQueryInfoKeyA(key, class_a, NULL, NULL, NULL, NULL, NULL,
                                      NULL, NULL, NULL, &invalid_a_size, NULL);
    invalid_class_w = RegQueryInfoKeyW(key, class_buffer, NULL, NULL, NULL, NULL, NULL,
                                      NULL, NULL, NULL, &invalid_w_size, NULL);
    reserved_a = RegQueryInfoKeyA(key, NULL, NULL, &reserved, NULL, NULL, NULL,
                                  NULL, NULL, NULL, NULL, NULL);
    reserved_w = RegQueryInfoKeyW(key, NULL, NULL, &reserved, NULL, NULL, NULL,
                                  NULL, NULL, NULL, NULL, NULL);
    nt = query_security(key, BASIC_SECURITY, NULL, 0, &native_size);
    all_nt = query_security(key, BASIC_SECURITY | SACL_SECURITY_INFORMATION, NULL, 0, &all_size);
    /* The bounded second query records genuine descriptor bytes/lengths only
     * as numeric evidence. Raw descriptors and SIDs are never exported. */
    if (native_size && native_size != SENTINEL && native_size <= 65536) {
        descriptor = malloc(native_size);
        require(descriptor != NULL, "allocate-native-security-buffer");
        fill = query_security(key, BASIC_SECURITY, descriptor, native_size, &native_size);
        if (!fill && IsValidSecurityDescriptor(descriptor)) actual_length = GetSecurityDescriptorLength(descriptor);
        free(descriptor);
    }
    if (all_size && all_size != SENTINEL && all_size <= 65536) {
        descriptor = malloc(all_size);
        require(descriptor != NULL, "allocate-native-full-security-buffer");
        fill_all = query_security(key, BASIC_SECURITY | SACL_SECURITY_INFORMATION, descriptor, all_size, &all_size);
        if (!fill_all && IsValidSecurityDescriptor(descriptor)) actual_all_length = GetSecurityDescriptorLength(descriptor);
        free(descriptor);
    }
    reg = RegGetKeySecurity(key, BASIC_SECURITY, NULL, &reg_size);
    printf("{\"event\":\"query\",\"phase\":\"%s\",\"handle\":\"%s\",\"rights\":%lu,"
           "\"aStatus\":%ld,\"aSize\":%lu,\"wStatus\":%ld,\"wSize\":%lu,"
           "\"metadataAStatus\":%ld,\"metadataASize\":%lu,\"subkeysA\":%lu,"
           "\"metadataWStatus\":%ld,\"metadataWSize\":%lu,\"subkeysW\":%lu,"
           "\"nullOutputsAStatus\":%ld,\"nullOutputsWStatus\":%ld,"
           "\"classWithoutSizeAStatus\":%ld,\"classWithoutSizeASecurity\":%lu,"
           "\"classWithoutSizeWStatus\":%ld,\"classWithoutSizeWSecurity\":%lu,\"nonnullReservedAStatus\":%ld,\"nonnullReservedWStatus\":%ld,"
           "\"ntSecurityStatus\":\"%08lx\",\"ntSecuritySize\":%lu,\"ntFillStatus\":\"%08lx\",\"descriptorLength\":%lu,"
           "\"ntWithSaclStatus\":\"%08lx\",\"ntWithSaclSize\":%lu,\"ntWithSaclFillStatus\":\"%08lx\",\"descriptorWithSaclLength\":%lu,"
           "\"regGetSecurityStatus\":%ld,\"regGetSecuritySize\":%lu}\n",
           phase, name, rights, ra, a, rw, w, ma, meta_a, count_a, mw, meta_w, count_w,
           null_a, null_w, invalid_class_a, invalid_a_size, invalid_class_w, invalid_w_size, reserved_a, reserved_w,
           (ULONG)nt, native_size, (ULONG)fill, actual_length,
           (ULONG)all_nt, all_size, (ULONG)fill_all, actual_all_length, reg, reg_size);
    ++rows;
}

static void matrix(const char *phase)
{
    static const struct { const char *name; REGSAM rights; } cases[] = {
        {"query-value-only", KEY_QUERY_VALUE}, {"read-control-only", READ_CONTROL},
        {"zero-rights", 0}, {"full-key-rights", KEY_ALL_ACCESS},
        {"query-and-read-control", KEY_QUERY_VALUE | READ_CONTROL},
        {"query-and-system-security", KEY_QUERY_VALUE | ACCESS_SYSTEM_SECURITY},
    };
    unsigned i;
    for (i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        HKEY key = NULL;
        LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, relative_name, 0,
                                       cases[i].rights | KEY_WOW64_64KEY, &key);
        printf("{\"event\":\"open\",\"phase\":\"%s\",\"handle\":\"%s\",\"rights\":%lu,\"status\":%ld}\n",
               phase, cases[i].name, cases[i].rights, status);
        if (!status) { query(phase, cases[i].name, key, cases[i].rights); RegCloseKey(key); }
    }
    query(phase, "held-full-before-DACL-change", owned_key, KEY_ALL_ACCESS);
}

static BOOL enable_security_privilege(void)
{
    HANDLE token;
    TOKEN_PRIVILEGES privileges;
    DWORD error;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return FALSE;
    privileges.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(NULL, SE_SECURITY_NAME, &privileges.Privileges[0].Luid)) {
        CloseHandle(token); return FALSE;
    }
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL)) {
        CloseHandle(token); return FALSE;
    }
    error = GetLastError();
    CloseHandle(token);
    return error == ERROR_SUCCESS;
}

int main(void)
{
    HANDLE token;
    TOKEN_USER *user;
    DWORD bytes = 0, disposition, length, compact_length;
    FILETIME time;
    BYTE world[SECURITY_MAX_SID_SIZE], users[SECURITY_MAX_SID_SIZE];
    DWORD world_length = sizeof(world), users_length = sizeof(users);
    PACL compact, expanded, empty, audit;
    HKEY missing = NULL, held_query = NULL, sacl_key = NULL, closed;
    LSTATUS status;
    WCHAR missing_name[240];
    BOOL privilege;
    setvbuf(stdout, NULL, _IONBF, 0);
    atexit(cleanup);
    query_security = (query_security_t)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySecurityObject");
    require(query_security != NULL, "resolve-native-NtQuerySecurityObject");
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token), "query-own-token");
    GetTokenInformation(token, TokenUser, NULL, 0, &bytes);
    user = malloc(bytes);
    require(user && GetTokenInformation(token, TokenUser, user, bytes, &bytes), "read-own-user-SID-in-memory-only");
    CloseHandle(token);
    require(CreateWellKnownSid(WinWorldSid, NULL, world, &world_length) &&
            CreateWellKnownSid(WinBuiltinUsersSid, NULL, users, &users_length), "create-known-test-SIDs");
    length = sizeof(ACL) + 3 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) +
        GetLengthSid(user->User.Sid) + world_length + users_length;
    compact_length = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(user->User.Sid);
    compact = calloc(1, compact_length); expanded = calloc(1, length);
    empty = calloc(1, sizeof(ACL)); audit = calloc(1, compact_length);
    require(compact && expanded && empty && audit, "allocate-bounded-test-ACLs");
    require(InitializeAcl(compact, compact_length, ACL_REVISION) && InitializeAcl(expanded, length, ACL_REVISION) &&
            InitializeAcl(empty, sizeof(ACL), ACL_REVISION) && InitializeAcl(audit, compact_length, ACL_REVISION),
            "initialize-test-ACLs");
    require(AddAccessAllowedAce(compact, ACL_REVISION, KEY_ALL_ACCESS, user->User.Sid) &&
            AddAccessAllowedAce(expanded, ACL_REVISION, KEY_ALL_ACCESS, user->User.Sid) &&
            AddAccessAllowedAce(expanded, ACL_REVISION, KEY_READ, world) &&
            AddAccessAllowedAce(expanded, ACL_REVISION, KEY_QUERY_VALUE, users) &&
            AddAuditAccessAce(audit, ACL_REVISION, KEY_QUERY_VALUE, user->User.Sid, TRUE, TRUE), "populate-test-ACLs");
    GetSystemTimeAsFileTime(&time);
    swprintf(relative_name, sizeof(relative_name) / sizeof(*relative_name),
             L"SOFTWARE\\MadeiraRegQueryContract_%lu_%08lx%08lx", GetCurrentProcessId(), time.dwHighDateTime, time.dwLowDateTime);
    status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, relative_name, 0, L"MadeiraContractClass", 0,
                             KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &owned_key, &disposition);
    printf("{\"event\":\"owned-key-create\",\"status\":%ld}\n", status);
    require(status == ERROR_SUCCESS, "create-owned-test-key-requires-administrator-runner");
    require(disposition == REG_CREATED_NEW_KEY, "exclusive-test-key-ownership");
    owned = TRUE;
    printf("{\"event\":\"environment\",\"pointerBits\":%u,\"api\":\"native-Windows-only\",\"securitySentinel\":%lu,\"rawDescriptorsExported\":false}\n",
           (unsigned)(sizeof(void *) * 8), SENTINEL);
    require(SetSecurityInfo(owned_key, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                            NULL, NULL, compact, NULL) == ERROR_SUCCESS, "set-owned-compact-DACL");
    matrix("compact-DACL");
    require(RegOpenKeyExW(HKEY_LOCAL_MACHINE, relative_name, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &held_query)
            == ERROR_SUCCESS, "open-held-query-only-handle");
    require(ImpersonateAnonymousToken(GetCurrentThread()), "impersonate-anonymous-for-reopen-distinction");
    query("anonymous-with-preopened-handle", "held-query-only", held_query, KEY_QUERY_VALUE);
    require(RevertToSelf(), "revert-test-impersonation");
    RegCloseKey(held_query);
    require(SetSecurityInfo(owned_key, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                            NULL, NULL, expanded, NULL) == ERROR_SUCCESS, "set-owned-expanded-DACL");
    matrix("expanded-DACL");
    privilege = enable_security_privilege();
    printf("{\"event\":\"security-privilege\",\"available\":%s}\n", privilege ? "true" : "false");
    if (privilege) {
        status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, relative_name, 0,
                               KEY_ALL_ACCESS | ACCESS_SYSTEM_SECURITY | KEY_WOW64_64KEY, &sacl_key);
        require(status == ERROR_SUCCESS, "open-owned-SACL-handle");
        status = SetSecurityInfo(sacl_key, SE_REGISTRY_KEY, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, audit);
        require(status == ERROR_SUCCESS, "set-owned-audit-SACL");
        matrix("expanded-DACL-with-SACL");
        query("expanded-DACL-with-SACL", "held-system-security-handle", sacl_key, KEY_ALL_ACCESS | ACCESS_SYSTEM_SECURITY);
        RegCloseKey(sacl_key);
    }
    swprintf(missing_name, sizeof(missing_name) / sizeof(*missing_name), L"%ls\\missing", relative_name);
    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, missing_name, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &missing);
    printf("{\"event\":\"missing-key-open\",\"status\":%ld,\"handleProduced\":%s}\n", status, missing ? "true" : "false");
    if (missing) RegCloseKey(missing);
    require(SetSecurityInfo(owned_key, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                            NULL, NULL, empty, NULL) == ERROR_SUCCESS, "set-owned-empty-DACL");
    matrix("empty-DACL");
    query("invalid-handles", "null", NULL, 0);
    query("invalid-handles", "invalid-unaligned", (HKEY)(ULONG_PTR)0x123, 0);
    require(DuplicateHandle(GetCurrentProcess(), owned_key, GetCurrentProcess(), (HANDLE *)&closed,
                             0, FALSE, DUPLICATE_SAME_ACCESS), "duplicate-owned-handle-to-close");
    RegCloseKey(closed);
    query("invalid-handles", "closed-handle", closed, KEY_ALL_ACCESS);
    free(compact); free(expanded); free(empty); free(audit); free(user);
    printf("{\"event\":\"complete\",\"queryRows\":%u,\"contractOutcomes\":\"observed-not-assumed\",\"SteamData\":\"untouched\"}\n", rows);
    return 0;
}
