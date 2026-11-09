#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <wchar.h>

typedef uint32_t DWORD;
typedef int32_t LONG;
typedef int BOOL;
typedef size_t SIZE_T;
typedef wchar_t WCHAR;
typedef void *HWND;
typedef void *LPVOID;
typedef struct { DWORD Data1; uint16_t Data2, Data3; unsigned char Data4[8]; } GUID;
typedef struct { DWORD cbStruct; const WCHAR *pcwszFilePath; void *hFile; GUID *pgKnownSubject; } WINTRUST_FILE_INFO;
typedef struct {
    DWORD cbStruct, dwCatalogVersion;
    const WCHAR *pcwszCatalogFilePath, *pcwszMemberTag, *pcwszMemberFilePath;
    void *hMemberFile;
} WINTRUST_CATALOG_INFO;
typedef struct {
    DWORD cbStruct;
    void *pPolicyCallbackData, *pSIPClientData;
    DWORD dwUIChoice, fdwRevocationChecks, dwUnionChoice;
    union { WINTRUST_FILE_INFO *pFile; WINTRUST_CATALOG_INFO *pCatalog; };
    DWORD dwStateAction;
    void *hWVTStateData;
} WINTRUST_DATA;
#define WINAPI
#define TRUE 1
#define FALSE 0
#define WTD_CHOICE_FILE 1
#define WTD_CHOICE_CATALOG 2
#define WTD_CHOICE_BLOB 3
#define WTD_CHOICE_SIGNER 4
#define WTD_CHOICE_CERT 5
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define FIELD_OFFSET(type,field) offsetof(type,field)

static __thread DWORD last_error;
static const WCHAR *configured_image = L"C:\\games\\cs2.exe";
static const WCHAR *configured_flag = L"1";
static __thread LONG verifier_result;
static __thread DWORD verifier_error, expected_incoming;
static __thread unsigned verifier_calls;
static __thread int throw_original;
static __thread jmp_buf exception_target;
static pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned output_lines;
static char output[131072];

static DWORD GetLastError(void) { return last_error; }
static void SetLastError(DWORD value) { last_error = value; }
static DWORD GetCurrentProcessId(void) { SetLastError(0xeeee); return 42; }
static DWORD GetEnvironmentVariableW(const WCHAR *key, WCHAR *dest, DWORD cap)
{
    size_t length = wcslen(configured_flag);
    assert(!wcscmp(key, L"MADEIRA_TRUST_DIAGNOSTICS"));
    SetLastError(0xdddd);
    if (length >= cap) return length + 1;
    wcscpy(dest, configured_flag);
    return length;
}
static DWORD GetModuleFileNameW(void *module, WCHAR *dest, DWORD cap)
{
    size_t length = wcslen(configured_image);
    assert(!module);
    SetLastError(0xcccc);
    if (length >= cap) return cap;
    wcscpy(dest, configured_image);
    return length;
}
static LONG InterlockedCompareExchange(LONG *dest, LONG exchange, LONG compare)
{
    __atomic_compare_exchange_n(dest, &compare, exchange, FALSE, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return compare;
}
static __thread sigjmp_buf read_target;
static __thread volatile sig_atomic_t reading;
static void read_fault(int signal)
{
    if (reading) { reading = 0; siglongjmp(read_target, 1); }
    _exit(128 + signal);
}
/* Real guard-page faults exercise the same narrowly scoped copy boundary as
 * production Wine's page-fault SEH. The original verifier is outside it. */
static BOOL guarded_read(void *dest, const void *source, SIZE_T size)
{
    if (!source || sigsetjmp(read_target, 1)) return FALSE;
    reading = 1;
    memcpy(dest, source, size);
    reading = 0;
    return TRUE;
}
#define MADEIRA_TRUST_READ guarded_read
static void capture(const char *format, ...)
{
    /* Wine DWORD is unsigned long on its Windows targets. Match printf's
     * native LP64 varargs only in this host harness's output adapter. */
    char fixed[1024];
    unsigned i, n = 0;
    va_list args;
    for (i = 0; format[i]; i++)
    {
        if (format[i] == 'l' && (format[i + 1] == 'u' || format[i + 1] == 'x')) continue;
        fixed[n++] = format[i];
    }
    fixed[n] = 0;
    pthread_mutex_lock(&output_lock);
    va_start(args, format);
    vsnprintf(output + strlen(output), sizeof(output) - strlen(output), fixed, args);
    va_end(args);
    output_lines++;
    pthread_mutex_unlock(&output_lock);
    SetLastError(0xbbbb);
}
#define ERR capture
static LONG WINAPI madeira_real_WinVerifyTrust(HWND window, GUID *action, LPVOID opaque)
{
    WINTRUST_DATA *data = opaque;
    (void)window; (void)action;
    assert(GetLastError() == expected_incoming);
    verifier_calls++;
    if (throw_original) { SetLastError(0xabcd); longjmp(exception_target, 1); }
    if (data && guarded_read(&(DWORD){0}, data, sizeof(DWORD)) &&
        data->cbStruct == sizeof(*data)) data->hWVTStateData = (void *)(uintptr_t)0x12345678;
    SetLastError(verifier_error);
    return verifier_result;
}
#include "../../build/wine-pe/trust_diagnostics.h"

static GUID action = {0xaac56b, 1, 2, {3}};
static WINTRUST_FILE_INFO file;
static WINTRUST_DATA data;
static void setup(const WCHAR *name)
{
    memset(&data, 0, sizeof(data)); memset(&file, 0, sizeof(file));
    file.cbStruct = sizeof(file); file.pcwszFilePath = name;
    data.cbStruct = sizeof(data); data.dwUnionChoice = WTD_CHOICE_FILE;
    data.dwStateAction = 1; data.pFile = &file;
    verifier_result = (LONG)0x800b0100; verifier_error = 0x9876;
    expected_incoming = 0x7654; SetLastError(expected_incoming);
}
static void call(void)
{
    LONG actual = WinVerifyTrust(NULL, &action, &data);
    assert(actual == verifier_result && GetLastError() == verifier_error);
    assert(data.hWVTStateData == (void *)(uintptr_t)0x12345678);
}
static void *worker(void *unused)
{
    unsigned i;
    (void)unused;
    expected_incoming = 0x7654; verifier_error = 0x5555; verifier_result = 0;
    for (i = 0; i < 200; i++)
    {
        SetLastError(expected_incoming);
        assert(WinVerifyTrust(NULL, &action, NULL) == 0);
        assert(GetLastError() == verifier_error);
    }
    assert(verifier_calls == 200);
    return NULL;
}
int main(int argc, char **argv)
{
    unsigned i;
    struct sigaction handler;
    assert(argc == 2);
    memset(&handler, 0, sizeof(handler)); handler.sa_handler = read_fault;
    sigemptyset(&handler.sa_mask);
    assert(!sigaction(SIGSEGV, &handler, NULL) && !sigaction(SIGBUS, &handler, NULL));
    setup(L"C:\\private-user\\steamapps\\cs2.exe");
    if (!strcmp(argv[1], "behavior"))
    {
        static const LONG results[] = {0, 1, (LONG)0x800b0100, (LONG)0x80096010, -1};
        for (i = 0; i < ARRAY_SIZE(results); i++)
        {
            verifier_result = results[i]; verifier_error = 19 * i; data.dwStateAction = i;
            SetLastError(expected_incoming); call();
        }
        assert(verifier_calls == ARRAY_SIZE(results) && output_lines == ARRAY_SIZE(results));
        assert(strstr(output, "name=cs2.exe") && !strstr(output, "private-user"));
        throw_original = 1; SetLastError(expected_incoming);
        if (!setjmp(exception_target)) { WinVerifyTrust(NULL, &action, &data); abort(); }
        assert(GetLastError() == 0xabcd && output_lines == ARRAY_SIZE(results));
    }
    else if (!strcmp(argv[1], "inaccessible"))
    {
        size_t page = sysconf(_SC_PAGESIZE);
        char *guard = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        DWORD *short_data = (DWORD *)(guard + page - sizeof(DWORD));
        WCHAR *short_name = (WCHAR *)(guard + page - sizeof(WCHAR));
        assert(guard != MAP_FAILED && !mprotect(guard + page, page, PROT_NONE));
        *short_data = sizeof(DWORD);
        assert(WinVerifyTrust(NULL, (GUID *)(guard + page), short_data) == verifier_result);
        assert(GetLastError() == verifier_error && strstr(output, "kind=unknown"));
        *short_name = 'x'; file.pcwszFilePath = short_name; SetLastError(expected_incoming); call();
        assert(strstr(output, "name=unknown"));
        file.cbStruct = sizeof(DWORD); file.pcwszFilePath = (void *)1;
        SetLastError(expected_incoming); call();
        assert(output_lines == 3);
        munmap(guard, page * 2);
    }
    else if (!strcmp(argv[1], "privacy"))
    {
        WCHAR unterminated[1024], oversized[80];
        const WCHAR *names[] = {L"https://private-user:secret@host/private-token.exe?access=secret",
            L"C:\\secret\\bad\nname.dll", L"C:\\secret\\snow\x2603.dll", L"C:\\secret\\name with spaces.dll",
            L"C:\\secret\\fine-name_1.dll"};
        for (i = 0; i < ARRAY_SIZE(names); i++)
        { file.pcwszFilePath = names[i]; SetLastError(expected_incoming); call(); }
        assert(!strstr(output, "private-user") && !strstr(output, "private-token") && !strstr(output, "secret"));
        assert(strstr(output, "path=nonfile name=unknown") && strstr(output, "name=fine-name_1.dll"));
        assert(!strstr(output, "bad") && !strstr(output, "snow") && !strstr(output, "spaces"));
        for (i = 0; i < ARRAY_SIZE(unterminated); i++) unterminated[i] = 'q';
        for (i = 0; i < ARRAY_SIZE(oversized) - 1; i++) oversized[i] = 'z';
        oversized[ARRAY_SIZE(oversized) - 1] = 0;
        file.pcwszFilePath = unterminated; SetLastError(expected_incoming); call();
        file.pcwszFilePath = oversized; SetLastError(expected_incoming); call();
        assert(output_lines == 7 && !strstr(output, "qqq") && !strstr(output, "zzz"));
    }
    else if (!strcmp(argv[1], "catalog"))
    {
        WINTRUST_CATALOG_INFO cat = {sizeof(cat), 0, L"C:\\secret\\catalog.cat", L"private-tag",
                                    L"C:\\private\\member.dll", NULL};
        data.dwUnionChoice = WTD_CHOICE_CATALOG; data.pCatalog = &cat; call();
        assert(strstr(output, "kind=catalog") && strstr(output, "name=member.dll"));
        assert(!strstr(output, "catalog.cat") && !strstr(output, "private"));
    }
    else if (!strcmp(argv[1], "gate"))
    {
        configured_flag = L"0"; call();
        configured_flag = L"1"; configured_image = L"C:\\other.exe"; SetLastError(expected_incoming); call();
        assert(!output_lines && verifier_calls == 2);
        configured_image = L"C:\\sTeAmSeRvIcE.ExE"; SetLastError(expected_incoming); call();
        configured_image = L"C:\\STEAM.EXE"; SetLastError(expected_incoming); call();
        assert(output_lines == 2);
    }
    else if (!strcmp(argv[1], "concurrency"))
    {
        pthread_t threads[16];
        for (i = 0; i < ARRAY_SIZE(threads); i++) assert(!pthread_create(&threads[i], NULL, worker, NULL));
        for (i = 0; i < ARRAY_SIZE(threads); i++) assert(!pthread_join(threads[i], NULL));
        assert(output_lines && output_lines <= 64);
        for (i = 0; i < 100; i++) { SetLastError(expected_incoming); call(); }
        assert(output_lines == 64);
    }
    else abort();
    puts("trust diagnostics: PASS");
    return 0;
}
