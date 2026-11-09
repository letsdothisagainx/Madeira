/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Bounded observation of Wine's real WinVerifyTrust. This header is included
 * after the renamed, otherwise unchanged verifier by the owned build stage.
 * No verifier call or result is replaced, and no path or URL is printed. */
#ifndef MADEIRA_TRUST_DIAGNOSTICS_H
#define MADEIRA_TRUST_DIAGNOSTICS_H

#ifndef MADEIRA_TRUST_READ
#include "wine/exception.h"
static BOOL madeira_trust_read(void *dest, const void *source, SIZE_T size)
{
    BOOL ok = FALSE;
    if (!source) return FALSE;
    __TRY
    {
        memcpy(dest, source, size);
        ok = TRUE;
    }
    __EXCEPT_PAGE_FAULT { }
    __ENDTRY
    return ok;
}
#define MADEIRA_TRUST_READ madeira_trust_read
#endif

struct madeira_trust_observation
{
    DWORD choice, state;
    const char *kind, *path;
    char name[65], action[37];
};

static unsigned madeira_trust_lower(unsigned c)
{
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

static BOOL madeira_trust_equal(const WCHAR *value, const char *literal)
{
    unsigned i;
    for (i = 0; literal[i]; i++)
        if (madeira_trust_lower(value[i]) != (unsigned char)literal[i]) return FALSE;
    return !value[i];
}

/* Read at most 1024 UTF-16 code units, stopping at the first terminator.
 * The fixed output alphabet excludes whitespace, controls, URL delimiters,
 * non-ASCII text, and anything that could inject another diagnostic field. */
static void madeira_trust_path(const WCHAR *source, struct madeira_trust_observation *out)
{
    WCHAR path[1024];
    unsigned i, leaf = 0, length, c;
    BOOL url = FALSE;
    for (i = 0; i < ARRAY_SIZE(path); i++)
    {
        if (!MADEIRA_TRUST_READ(path + i, source ? source + i : NULL, sizeof(*path))) return;
        if (!(c = path[i])) break;
        if (c == '/' || c == '\\') leaf = i + 1;
        if (c == '?' || c == '#' || c == '@' || c == '%' ||
            (c == ':' && !(i == 1 && ((path[0] >= 'a' && path[0] <= 'z') ||
                                      (path[0] >= 'A' && path[0] <= 'Z'))))) url = TRUE;
    }
    if (!i || i == ARRAY_SIZE(path)) return;
    if (url) { out->path = "nonfile"; return; }
    length = i - leaf;
    if (!length || length >= sizeof(out->name)) return;
    for (i = 0; i < length; i++)
    {
        c = path[leaf + i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) return;
    }
    for (i = 0; i < length; i++) out->name[i] = (char)path[leaf + i];
    out->name[length] = 0;
    if (!leaf) out->path = "bare";
    else if (path[0] == '\\' && path[1] == '\\') out->path = "unc";
    else if (path[1] == ':') out->path = "drive";
    else out->path = "other";
}

static BOOL madeira_trust_enabled(void)
{
    WCHAR enabled[8], image[512];
    DWORD length;
    const WCHAR *base;
    unsigned i;
    length = GetEnvironmentVariableW(L"MADEIRA_TRUST_DIAGNOSTICS", enabled, ARRAY_SIZE(enabled));
    if (length != 1 || enabled[0] != '1') return FALSE;
    length = GetModuleFileNameW(NULL, image, ARRAY_SIZE(image));
    if (!length || length >= ARRAY_SIZE(image)) return FALSE;
    base = image;
    for (i = 0; i < length; i++) if (image[i] == '\\' || image[i] == '/') base = image + i + 1;
    return madeira_trust_equal(base, "cs2.exe") || madeira_trust_equal(base, "steam.exe") ||
           madeira_trust_equal(base, "steamservice.exe");
}

/* One ordinary CAS attempt, never a retry loop. A concurrent reservation may
 * drop an observation. The counter saturates at 64, including under contention.
 * The counter is process/module data; it does not infer any trust state. */
#if defined(__aarch64__) && defined(__clang__)
/* Use the existing supported LSE CAS family, rather than introducing a new
 * native exclusive-load/store sequence into the protected image alias. The
 * build checks the actual controlled function's COFF instructions. */
__attribute__((target("lse"), noinline))
#elif defined(__GNUC__)
__attribute__((noinline))
#endif
static BOOL madeira_trust_reserve(void)
{
    static LONG reports;
    LONG previous = InterlockedCompareExchange(&reports, 0, 0);
    if (previous >= 64) return FALSE;
    return InterlockedCompareExchange(&reports, previous + 1, previous) == previous;
}

static void madeira_trust_metadata(const GUID *action, const WINTRUST_DATA *data,
                                  struct madeira_trust_observation *out)
{
    DWORD size;
    const WCHAR *path = NULL;
    const void *subject = NULL;
    GUID guid;
    memset(out, 0, sizeof(*out));
    out->kind = out->path = "unknown";
    strcpy(out->name, "unknown");
    strcpy(out->action, "unknown");
    if (MADEIRA_TRUST_READ(&guid, action, sizeof(guid)))
        snprintf(out->action, sizeof(out->action), "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 (unsigned long)guid.Data1, (unsigned)guid.Data2, (unsigned)guid.Data3,
                 (unsigned)guid.Data4[0], (unsigned)guid.Data4[1], (unsigned)guid.Data4[2],
                 (unsigned)guid.Data4[3], (unsigned)guid.Data4[4], (unsigned)guid.Data4[5],
                 (unsigned)guid.Data4[6], (unsigned)guid.Data4[7]);
    if (!MADEIRA_TRUST_READ(&size, data, sizeof(size))) return;
    /* Read fields individually: a short cbStruct never licenses a later read. */
    if (size >= FIELD_OFFSET(WINTRUST_DATA, dwUnionChoice) + sizeof(data->dwUnionChoice))
        MADEIRA_TRUST_READ(&out->choice, &data->dwUnionChoice, sizeof(data->dwUnionChoice));
    if (size >= FIELD_OFFSET(WINTRUST_DATA, dwStateAction) + sizeof(data->dwStateAction))
        MADEIRA_TRUST_READ(&out->state, &data->dwStateAction, sizeof(data->dwStateAction));
    if (size < FIELD_OFFSET(WINTRUST_DATA, pFile) + sizeof(data->pFile) ||
        !MADEIRA_TRUST_READ(&subject, &data->pFile, sizeof(data->pFile))) return;
    switch (out->choice)
    {
    case WTD_CHOICE_FILE:
        out->kind = "file";
        if (!MADEIRA_TRUST_READ(&size, subject, sizeof(size)) ||
            size < FIELD_OFFSET(WINTRUST_FILE_INFO, pcwszFilePath) + sizeof(path)) return;
        if (!MADEIRA_TRUST_READ(&path, &((const WINTRUST_FILE_INFO *)subject)->pcwszFilePath, sizeof(path))) return;
        break;
    case WTD_CHOICE_CATALOG:
        out->kind = "catalog";
        if (!MADEIRA_TRUST_READ(&size, subject, sizeof(size)) ||
            size < FIELD_OFFSET(WINTRUST_CATALOG_INFO, pcwszMemberFilePath) + sizeof(path)) return;
        if (!MADEIRA_TRUST_READ(&path, &((const WINTRUST_CATALOG_INFO *)subject)->pcwszMemberFilePath, sizeof(path))) return;
        break;
    case WTD_CHOICE_BLOB: out->kind = "blob"; return;
    case WTD_CHOICE_SIGNER: out->kind = "signer"; return;
    case WTD_CHOICE_CERT: out->kind = "cert"; return;
    default: return;
    }
    madeira_trust_path(path, out);
}

LONG WINAPI WinVerifyTrust(HWND hwnd, GUID *action, LPVOID data)
{
    DWORD incoming = GetLastError(), outgoing;
    LONG result;
    BOOL observe = madeira_trust_enabled() && madeira_trust_reserve();
    struct madeira_trust_observation metadata;
    if (observe) madeira_trust_metadata(action, data, &metadata);
    SetLastError(incoming);
    /* Deliberately outside every diagnostic exception guard. */
    result = madeira_real_WinVerifyTrust(hwnd, action, data);
    outgoing = GetLastError();
    if (observe)
        ERR("[trust-result-v1] pid=%lu action=%s choice=%lu kind=%s state=%lu result=%08lx error=%lu path=%s name=%s limit=64-per-process-module\n",
            GetCurrentProcessId(), metadata.action, metadata.choice, metadata.kind, metadata.state,
            (DWORD)result, outgoing, metadata.path, metadata.name);
    SetLastError(outgoing);
    return result;
}
#endif
