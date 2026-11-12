/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Native Windows backend for the exact staged Wine named-registry functions.
 * Uses exclusively created, owned temporary keys. No Steam data is accessed.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <aclapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static unsigned checks;
static HKEY keys[2];
static BOOL owned[2];
static WCHAR relative_name[256], object_name[280];
static const REGSAM views[2] = {KEY_WOW64_32KEY, KEY_WOW64_64KEY};
static const SE_OBJECT_TYPE selectors[2] = {(SE_OBJECT_TYPE)12, (SE_OBJECT_TYPE)13};

static void check(BOOL value, const char *name)
{
    ++checks;
    if (!value) {
        printf("[registry-security] FAIL case=%s last-error=%lu\n", name, GetLastError());
        exit(1);
    }
}

static void cleanup(void)
{
    unsigned i;
    RevertToSelf();
    for (i = 0; i < 2; ++i) {
        if (keys[i]) RegCloseKey(keys[i]);
        if (owned[i]) {
            LSTATUS status = RegDeleteKeyExW(HKEY_LOCAL_MACHINE, relative_name, views[i], 0);
            if (status) {
                fprintf(stderr, "[registry-security] FAIL cleanup-view=%u status=%ld\n", i, status);
                /* Cleanup must be observable to the native test runner. */
                ExitProcess(2);
            }
        }
    }
}

/* The full production bodies retain these unrelated switch branches. They
 * must never be reached by a registry test; fail closed instead of mocking an
 * object-opening result. All tested registry/backend APIs are real Windows. */
static DWORD get_security_file(LPCWSTR name, DWORD access, HANDLE *handle)
{
    (void)name; (void)access; (void)handle;
    check(FALSE, "unexpected-file-branch");
    return ERROR_INVALID_FUNCTION;
}
static DWORD get_security_service(const WCHAR *name, DWORD access, HANDLE *handle)
{
    (void)name; (void)access; (void)handle;
    check(FALSE, "unexpected-service-branch");
    return ERROR_INVALID_FUNCTION;
}

#define TRACE(...) ((void)0)
#define FIXME(...) ((void)0)
#include "production-registry-security.h"
#undef TRACE
#undef FIXME

#define SECURITY_PARTS (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
#define SET_DACL (DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION)

struct snapshot {
    PSID owner, group;
    PACL dacl;
    PSECURITY_DESCRIPTOR descriptor;
};

static BOOL same_acl(const ACL *left, const ACL *right)
{
    DWORD i;
    if (!left || !right) return left == right;
    if (left->AclRevision != right->AclRevision || left->AceCount != right->AceCount) return FALSE;
    for (i = 0; i < left->AceCount; ++i) {
        ACE_HEADER *a, *b;
        if (!GetAce((PACL)left, i, (void **)&a) || !GetAce((PACL)right, i, (void **)&b) ||
            a->AceSize != b->AceSize || memcmp(a, b, a->AceSize)) return FALSE;
    }
    return TRUE;
}

static BOOL same_identity(const struct snapshot *left, const struct snapshot *right)
{
    return left->owner && right->owner && left->group && right->group &&
        EqualSid(left->owner, right->owner) && EqualSid(left->group, right->group);
}

static BOOL same_snapshot(const struct snapshot *left, const struct snapshot *right)
{
    SECURITY_DESCRIPTOR_CONTROL a, b;
    DWORD revision;
    return same_identity(left, right) && same_acl(left->dacl, right->dacl) &&
        GetSecurityDescriptorControl(left->descriptor, &a, &revision) &&
        GetSecurityDescriptorControl(right->descriptor, &b, &revision) &&
        !((a ^ b) & (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ));
}

static struct snapshot snapshot_handle(HKEY key)
{
    struct snapshot out = {0};
    check(GetSecurityInfo(key, SE_REGISTRY_KEY, SECURITY_PARTS, &out.owner, &out.group,
                          &out.dacl, NULL, &out.descriptor) == ERROR_SUCCESS,
          "native-handle-security-read");
    check(IsValidSecurityDescriptor(out.descriptor), "native-descriptor-valid");
    return out;
}

static void free_snapshot(struct snapshot *value)
{
    if (value->descriptor) LocalFree(value->descriptor);
    memset(value, 0, sizeof(*value));
}

static PACL make_acl(PSID user, PSID world, DWORD world_access)
{
    DWORD size = sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) +
        GetLengthSid(user) + GetLengthSid(world);
    PACL acl = calloc(1, size);
    check(acl != NULL, "fixture-acl-allocation");
    check(InitializeAcl(acl, size, ACL_REVISION) &&
          AddAccessAllowedAce(acl, ACL_REVISION, KEY_ALL_ACCESS, user) &&
          AddAccessAllowedAce(acl, ACL_REVISION, world_access, world), "fixture-acl-construction");
    return acl;
}

static void reset_acl(unsigned index, PACL acl)
{
    check(SetSecurityInfo(keys[index], SE_REGISTRY_KEY, SET_DACL, NULL, NULL, acl, NULL) == ERROR_SUCCESS,
          "native-handle-security-write");
}

static void verify_named_read(unsigned index)
{
    struct snapshot actual = {0}, reference = {0}, direct = snapshot_handle(keys[index]);
    check(after_GetNamedSecurityInfoW(object_name, selectors[index], SECURITY_PARTS,
                                     &actual.owner, &actual.group, &actual.dacl, NULL,
                                     &actual.descriptor) == ERROR_SUCCESS,
          "staged-named-security-read");
    check(GetNamedSecurityInfoW(object_name, selectors[index], SECURITY_PARTS,
                               &reference.owner, &reference.group, &reference.dacl, NULL,
                               &reference.descriptor) == ERROR_SUCCESS,
          "stock-windows-named-security-read");
    check(actual.descriptor && IsValidSecurityDescriptor(actual.descriptor) &&
          same_snapshot(&actual, &reference) && same_snapshot(&actual, &direct),
          "staged-stock-and-handle-descriptors-agree");
    free_snapshot(&actual); free_snapshot(&reference); free_snapshot(&direct);
}

static void verify_write(unsigned index, PACL wanted)
{
    struct snapshot other = snapshot_handle(keys[1 - index]), before = snapshot_handle(keys[index]);
    struct snapshot updated, other_after;
    check(after_SetNamedSecurityInfoW(object_name, selectors[index], SET_DACL,
                                     NULL, NULL, wanted, NULL) == ERROR_SUCCESS,
          "staged-named-security-write");
    updated = snapshot_handle(keys[index]); other_after = snapshot_handle(keys[1 - index]);
    check(same_acl(updated.dacl, wanted), "staged-applies-requested-real-dacl");
    check(same_identity(&before, &updated), "owner-and-group-preserved");
    check(same_snapshot(&other, &other_after), "other-registry-view-unchanged");
    verify_named_read(index);
    free_snapshot(&other); free_snapshot(&before); free_snapshot(&updated); free_snapshot(&other_after);
}

struct worker { unsigned index; PACL acl; DWORD error; };
static DWORD WINAPI concurrent_worker(void *opaque)
{
    struct worker *work = opaque;
    unsigned i;
    for (i = 0; i < 64; ++i) {
        PACL got = NULL;
        PSECURITY_DESCRIPTOR descriptor = NULL;
        work->error = after_SetNamedSecurityInfoW(object_name, selectors[work->index], SET_DACL,
                                                  NULL, NULL, work->acl, NULL);
        if (work->error) return 1;
        work->error = after_GetNamedSecurityInfoW(object_name, selectors[work->index], DACL_SECURITY_INFORMATION,
                                                 NULL, NULL, &got, NULL, &descriptor);
        if (!work->error && (!descriptor || !same_acl(got, work->acl))) work->error = ERROR_INVALID_DATA;
        if (descriptor) LocalFree(descriptor);
        if (work->error) return 1;
    }
    return 0;
}

int main(void)
{
    HANDLE token;
    DWORD length = 0, i, disposition, value, type, bytes;
    TOKEN_USER *user;
    BYTE world_buffer[SECURITY_MAX_SID_SIZE];
    DWORD world_length = sizeof(world_buffer);
    PACL a, b, c;
    FILETIME now;
    SYSTEM_INFO system;
    struct snapshot baseline, got;
    PSECURITY_DESCRIPTOR missing = NULL;
    WCHAR absent[320];
    DWORD native_error, staged_error, old_error, native_get, staged_get;
    struct worker work[2];
    HANDLE threads[2];
    DWORD thread_exit;

    atexit(cleanup);
    GetNativeSystemInfo(&system);
    check(system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
          system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64, "native-64-bit-windows-required");
    printf("[registry-security] backend=native-windows pointer-bits=%u native-architecture=%u\n",
           (unsigned)(sizeof(void *) * 8), (unsigned)system.wProcessorArchitecture);
    check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token), "fixture-token-query");
    GetTokenInformation(token, TokenUser, NULL, 0, &length);
    user = malloc(length);
    check(user && GetTokenInformation(token, TokenUser, user, length, &length), "fixture-user-sid");
    CloseHandle(token);
    check(CreateWellKnownSid(WinWorldSid, NULL, world_buffer, &world_length), "fixture-world-sid");
    a = make_acl(user->User.Sid, world_buffer, KEY_READ);
    b = make_acl(user->User.Sid, world_buffer, KEY_QUERY_VALUE);
    c = make_acl(user->User.Sid, world_buffer, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS);
    GetSystemTimeAsFileTime(&now);
    swprintf(relative_name, sizeof(relative_name) / sizeof(*relative_name),
             L"SOFTWARE\\MadeiraRegistrySecurityFixture_%lu_%08lx%08lx", GetCurrentProcessId(),
             now.dwHighDateTime, now.dwLowDateTime);
    swprintf(object_name, sizeof(object_name) / sizeof(*object_name), L"MACHINE\\%ls", relative_name);
    for (i = 0; i < 2; ++i) {
        LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, relative_name, 0, NULL, 0,
                                        KEY_ALL_ACCESS | views[i], NULL, &keys[i], &disposition);
        check(status == ERROR_SUCCESS, "create-owned-hklm-key-requires-admin-runner");
        check(disposition == REG_CREATED_NEW_KEY, "exclusive-registry-fixture-ownership");
        owned[i] = TRUE;
        value = 32 + 32 * i;
        check(RegSetValueExW(keys[i], L"ViewMarker", 0, REG_DWORD, (BYTE *)&value, sizeof(value)) == ERROR_SUCCESS,
              "write-view-marker");
        reset_acl(i, a);
    }
    for (i = 0; i < 2; ++i) {
        value = 0; bytes = sizeof(value);
        check(RegQueryValueExW(keys[i], L"ViewMarker", NULL, &type, (BYTE *)&value, &bytes) == ERROR_SUCCESS &&
              type == REG_DWORD && value == 32 + 32 * i, "distinct-32-and-64-registry-views");
    }

    baseline = snapshot_handle(keys[1]);
    old_error = before_SetNamedSecurityInfoW(object_name, selectors[1], SET_DACL, NULL, NULL, b, NULL);
    got = snapshot_handle(keys[1]);
    check(old_error == ERROR_SUCCESS && same_snapshot(&baseline, &got), "old-type13-false-success-reproduced");
    check(before_GetNamedSecurityInfoW(object_name, selectors[1], DACL_SECURITY_INFORMATION,
                                      NULL, NULL, NULL, NULL, &missing) == ERROR_SUCCESS && !missing,
          "old-type13-empty-descriptor-reproduced");
    free_snapshot(&baseline); free_snapshot(&got);
    printf("[registry-security] PASS old-production-type13-reproduces-false-success-no-dacl-write\n");

    /* Independent stock Windows write establishes that the requested explicit
     * view selector really changes the target and leaves the other view alone. */
    baseline = snapshot_handle(keys[0]);
    check(SetNamedSecurityInfoW(object_name, selectors[1], SET_DACL, NULL, NULL, c, NULL) == ERROR_SUCCESS,
          "stock-windows-type13-write");
    got = snapshot_handle(keys[1]);
    check(same_acl(got.dacl, c), "stock-windows-type13-updates-64-bit-view");
    free_snapshot(&got); got = snapshot_handle(keys[0]);
    check(same_snapshot(&baseline, &got), "stock-windows-type13-preserves-32-bit-view");
    free_snapshot(&baseline); free_snapshot(&got);
    verify_write(1, b);
    verify_write(0, c);
    printf("[registry-security] PASS staged-explicit-32-and-64-view-updates-match-stock-Windows\n");

    /* Preserve the production getter's existing null/output validation. These
     * calls must fail before any real registry handle is opened. */
    for (i = 0; i < 2; ++i) {
        PSID unused_owner = NULL;
        check(after_GetNamedSecurityInfoW(NULL, selectors[i], DACL_SECURITY_INFORMATION,
                                          NULL, NULL, NULL, NULL, &missing) == ERROR_INVALID_PARAMETER,
              "null-object-validation-preserved");
        check(after_GetNamedSecurityInfoW(object_name, selectors[i], DACL_SECURITY_INFORMATION,
                                          NULL, NULL, NULL, NULL, NULL) == ERROR_INVALID_PARAMETER,
              "null-all-outputs-validation-preserved");
        check(after_GetNamedSecurityInfoW(object_name, selectors[i], DACL_SECURITY_INFORMATION,
                                          &unused_owner, NULL, NULL, NULL, NULL) == ERROR_INVALID_PARAMETER,
              "missing-requested-output-validation-preserved");
        check(after_SetNamedSecurityInfoW(NULL, selectors[i], SET_DACL, NULL, NULL, a, NULL)
              == ERROR_INVALID_PARAMETER, "setter-null-object-validation-preserved");
    }

    swprintf(absent, sizeof(absent) / sizeof(*absent), L"%ls\\does-not-exist", object_name);
    for (i = 0; i < 2; ++i) {
        native_error = SetNamedSecurityInfoW(absent, selectors[i], SET_DACL, NULL, NULL, a, NULL);
        staged_error = after_SetNamedSecurityInfoW(absent, selectors[i], SET_DACL, NULL, NULL, a, NULL);
        native_get = GetNamedSecurityInfoW(absent, selectors[i], DACL_SECURITY_INFORMATION,
                                          NULL, NULL, NULL, NULL, &missing);
        if (missing) { LocalFree(missing); missing = NULL; }
        staged_get = after_GetNamedSecurityInfoW(absent, selectors[i], DACL_SECURITY_INFORMATION,
                                                 NULL, NULL, NULL, NULL, &missing);
        check(native_error != ERROR_SUCCESS && native_error == staged_error &&
              native_get != ERROR_SUCCESS && native_get == staged_get && !missing,
              "missing-key-errors-match-stock-no-fabricated-success");
    }
    printf("[registry-security] PASS nonexistent-key-set/get-errors-match-native-Windows\n");

    baseline = snapshot_handle(keys[1]);
    check(ImpersonateAnonymousToken(GetCurrentThread()), "ordinary-anonymous-permission-test");
    native_error = SetNamedSecurityInfoW(object_name, selectors[1], SET_DACL, NULL, NULL, a, NULL);
    staged_error = after_SetNamedSecurityInfoW(object_name, selectors[1], SET_DACL, NULL, NULL, a, NULL);
    native_get = GetNamedSecurityInfoW(object_name, selectors[1], DACL_SECURITY_INFORMATION,
                                      NULL, NULL, NULL, NULL, &missing);
    if (missing) { LocalFree(missing); missing = NULL; }
    staged_get = after_GetNamedSecurityInfoW(object_name, selectors[1], DACL_SECURITY_INFORMATION,
                                             NULL, NULL, NULL, NULL, &missing);
    check(RevertToSelf(), "permission-test-reverts-impersonation");
    check(native_error != ERROR_SUCCESS && native_error == staged_error &&
          native_get != ERROR_SUCCESS && native_get == staged_get && !missing,
          "permission-errors-preserved-and-match-stock");
    got = snapshot_handle(keys[1]);
    check(same_snapshot(&baseline, &got), "denied-update-leaves-real-descriptor-unchanged");
    free_snapshot(&baseline); free_snapshot(&got);
    printf("[registry-security] PASS genuine-permission-failures set=%lu get=%lu unchanged=1\n",
           native_error, native_get);

    work[0].index = 0; work[0].acl = c; work[0].error = 0;
    work[1].index = 1; work[1].acl = b; work[1].error = 0;
    for (i = 0; i < 2; ++i) {
        threads[i] = CreateThread(NULL, 0, concurrent_worker, &work[i], 0, NULL);
        check(threads[i] != NULL, "concurrent-registry-worker-created");
    }
    check(WaitForMultipleObjects(2, threads, TRUE, 30000) == WAIT_OBJECT_0, "concurrent-registry-workers-finish");
    for (i = 0; i < 2; ++i) {
        check(GetExitCodeThread(threads[i], &thread_exit) && !thread_exit && !work[i].error,
              "concurrent-staged-view-isolation");
        CloseHandle(threads[i]);
        verify_named_read(i);
    }
    printf("[registry-security] PASS concurrent-explicit-view-security-updates iterations=128\n");
    free(a); free(b); free(c); free(user);
    printf("[registry-security] PASS checks=%u pointer-bits=%u real-registry=1 Steam-data=untouched\n",
           checks, (unsigned)(sizeof(void *) * 8));
    return 0;
}
