#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static char output[131072];
static size_t output_size;
static void capture(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int size = vsnprintf(output + output_size, sizeof(output) - output_size, format, ap);
    va_end(ap);
    assert(size > 0 && (size_t)size < sizeof(output) - output_size);
    output_size += size;
    errno = EIO; /* Native output is allowed to change errno internally. */
}
#define MADEIRA_CS2_EMIT(...) capture(__VA_ARGS__)
#define MADEIRA_CS2_OBSERVATION_IMPLEMENTATION
#include "cs2_observation.h"
typedef struct { unsigned short Length, MaximumLength; uint16_t *Buffer; } UNICODE_STRING;
typedef struct { UNICODE_STRING ImagePathName, CommandLine; } RTL_USER_PROCESS_PARAMETERS;
typedef struct { RTL_USER_PROCESS_PARAMETERS *ProcessParameters; unsigned char BeingDebugged; uint32_t NtGlobalFlag; } PEB;
typedef uintptr_t ULONG_PTR;
typedef uint32_t DWORD;
typedef struct { void *UniqueProcess, *UniqueThread; } CLIENT_ID;
typedef struct { DWORD UniqueProcess, UniqueThread; } CLIENT_ID32;
typedef struct { CLIENT_ID32 ClientId, RealClientId; } WOW_TEB;
typedef struct { PEB *Peb; CLIENT_ID ClientId, RealClientId; unsigned LastErrorValue; } TEB;
#define ULongToHandle(value) ((void *)(uintptr_t)(value))
static WOW_TEB *get_wow_teb(TEB *teb) { (void)teb; return NULL; }
static TEB current_teb;
static TEB *NtCurrentTeb(void) { return &current_teb; }
static sigjmp_buf read_fault;
static volatile sig_atomic_t reading;
static const void *partial_source;
static unsigned read_calls;
static void read_signal(int signal)
{
    if (reading) siglongjmp(read_fault, 1);
    _exit(128 + signal);
}
static int native_read(const void *source, void *target, size_t size)
{
    read_calls++;
    /* Mach's fault-safe copy contract, exercised against real protected host
     * pages. Linux process_vm_readv is unavailable in some CI sandboxes. */
    if (sigsetjmp(read_fault, 1)) { reading = 0; return 0; }
    reading = 1;
    if (source == partial_source)
    {
        memcpy(target, source, size - 1);
        reading = 0;
        return 0;
    }
    memcpy(target, source, size);
    reading = 0;
    return 1;
}
#define MADEIRA_CS2_READ(source, target, size) native_read(source, target, size)
#include "cs2_observation_native.h"

/* The runner supplies the actual production try-snapshot body, unmodified. */
#include "cs2_observation_lease_under_test.h"

static uint16_t image[1024], command[1024], path[1024];
static RTL_USER_PROCESS_PARAMETERS parameters;
static PEB peb;
static UNICODE_STRING string(uint16_t *wide, const char *text)
{
    size_t n = strlen(text);
    assert(n < 1024);
    for (size_t i = 0; i < n; i++) wide[i] = (unsigned char)text[i];
    return (UNICODE_STRING){(unsigned short)(n * 2), (unsigned short)(n * 2), wide};
}
static void reset(void)
{
    memset(ios_cs2_processes, 0, sizeof(ios_cs2_processes));
    memset(ios_thread_groups, 0, sizeof(ios_thread_groups));
    output[0] = 0; output_size = 0;
    partial_source = NULL;
    read_calls = 0;
    parameters.ImagePathName = string(image, "C:\\Steam\\steamapps\\common\\Counter-Strike Global Offensive\\game\\bin\\win64\\cs2.exe");
    parameters.CommandLine = string(command, "\"C:\\games\\cs2.exe\" -steam -condebug -joy");
    peb.ProcessParameters = &parameters;
    peb.BeingDebugged = 0;
    peb.NtGlobalFlag = 0;
    current_teb = (TEB){.Peb = &peb, .LastErrorValue = 0x12345678};
    ios_thread_next_lease = 70;
    memset(&ios_native_current, 0, sizeof(ios_native_current));
    ios_retired_thread_owner = NULL;
    /* Execute the actual server-startup lifecycle operations before the
     * observation: these existing operations establish owner lease and PID. */
    set_thread_id(&current_teb, 0x334, 0x338);
    assert(ios_thread_process_lease(&peb, 1) == 71);
    assert(ios_thread_groups[0].pid == 0x334 && ios_thread_groups[0].count == 1);
    assert(ios_native_current.owner == &peb && ios_native_current.lease == 71);
    errno = EDOM;
}
static void observe_start(unsigned machine)
{
    ios_cs2_observe_current_start(machine);
    ios_cs2_observe_current_debug();
}
static void unchanged(void)
{
    assert(errno == EDOM);
    assert(current_teb.LastErrorValue == 0x12345678);
}
int main(void)
{
    struct sigaction action = {0};
    action.sa_handler = read_signal;
    sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGSEGV, &action, NULL));
    assert(!sigaction(SIGBUS, &action, NULL));
    long page_size = sysconf(_SC_PAGESIZE);
    void *guard = mmap(NULL, (size_t)page_size * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(guard != MAP_FAILED);
    assert(!mprotect((char *)guard + page_size, page_size, PROT_NONE));
    reset();
    observe_start(0x8664); unchanged();
    assert(strstr(output, "argument-count=3 unknown-count=0 known-sequence=0,1,2 parse-complete=1"));
    assert(strstr(output, "path-class=game relative=game/bin/win64/cs2.exe machine=8664 hybrid=unmeasured"));
    assert(strstr(output, "[cs2-guest-debug-v1] pid=0334 tid=0338 being-debugged=0 nt-global-flag=00000000"));
    size_t accepted_start_size = output_size;
    observe_start(0x8664); unchanged(); assert(output_size == accepted_start_size);
    UNICODE_STRING module = string(path, "\\??\\C:\\windows\\sysx64\\wintrust.dll");
    ios_cs2_observe_current_map(&module, 0x8664, 1, 1); unchanged();
    assert(strstr(output, "path-class=system relative=sysx64/wintrust.dll machine=8664 hybrid=1"));
    module = string(path, "C:\\private\\auth-secret-token\\wintrust.dll");
    ios_cs2_observe_current_map(&module, 0x14c, 0, 1); unchanged();
    assert(strstr(output, "path-class=private relative=redacted machine=014c hybrid=0"));
    assert(!strstr(output, "auth-secret") && !strstr(output, "Counter-Strike") && !strstr(output, "C:\\"));
    ios_cs2_observe_current_map((char *)guard + page_size, 0xaa64, 0, 1); unchanged();
    assert(strstr(output, "path-class=unknown relative=redacted machine=aa64 hybrid=0"));
    module = (UNICODE_STRING){4, 4, (uint16_t *)((char *)guard + page_size - 2)};
    ios_cs2_observe_current_map(&module, 0x1234, -1, 1); unchanged();
    assert(strstr(output, "machine=unknown hybrid=unmeasured"));

    /* Read-only registry observation cannot adopt owners or follow a reused
     * thread ID, PID, PEB, or stale lease into the previous game's roots. */
    size_t before = output_size;
    struct ios_thread_group original[4];
    memcpy(original, ios_thread_groups, sizeof(original));
    assert(!pthread_mutex_lock(&ios_thread_group_mutex));
    assert(!ios_thread_process_try_observation_lease(&peb, 0x334));
    ios_cs2_observe_current_map(&module, 0x8664, 0, 1); unchanged();
    pthread_mutex_unlock(&ios_thread_group_mutex);
    assert(output_size == before && !memcmp(original, ios_thread_groups, sizeof(original)));
    ios_thread_groups[0].lease++;
    ios_cs2_observe_current_map(&module, 0x8664, 0, 1); unchanged(); assert(output_size == before);
    ios_thread_groups[0].lease--;
    current_teb.ClientId.UniqueProcess = (void *)0x440;
    ios_cs2_observe_current_map(&module, 0x8664, 0, 1); unchanged(); assert(output_size == before);
    current_teb.ClientId.UniqueProcess = (void *)0x334;
    ios_thread_groups[0].exiting = 1;
    ios_cs2_observe_current_map(&module, 0x8664, 0, 1); unchanged(); assert(output_size == before);
    ios_thread_groups[0].exiting = 0; ios_thread_groups[0].reclaimed = 1;
    ios_cs2_observe_current_map(&module, 0x8664, 0, 1); unchanged(); assert(output_size == before);

    /* Guest debugger observations are source bytes, not host attachment or a
     * security verdict. Noncanonical nonzero BOOLEAN values remain true;
     * faults and partial copies remain unmeasured independently per field. */
    reset(); peb.BeingDebugged = 0x98; peb.NtGlobalFlag = 0x12345670;
    PEB source_peb = peb;
    observe_start(0x8664); unchanged();
    assert(strstr(output, "being-debugged=1 nt-global-flag=12345670"));
    assert(!memcmp(&source_peb, &peb, sizeof(peb)));
    before = output_size;
    peb.BeingDebugged = 0; peb.NtGlobalFlag = 0;
    observe_start(0x8664); unchanged(); assert(output_size == before);
    reset(); partial_source = &peb.BeingDebugged;
    observe_start(0x8664); unchanged();
    assert(strstr(output, "being-debugged=unmeasured nt-global-flag=00000000"));
    reset(); partial_source = &peb.NtGlobalFlag;
    observe_start(0x8664); unchanged();
    assert(strstr(output, "being-debugged=0 nt-global-flag=unmeasured"));
    /* Exercise the actual helper against an unreadable field address while
     * keeping a valid current role/owner/lease context in the fixture. */
    reset();
    struct ios_cs2_context debug_context;
    assert(ios_cs2_current_context(&debug_context, 0));
    ios_cs2_record_start(debug_context.owner, debug_context.pid, debug_context.tid, debug_context.lease,
        debug_context.image, debug_context.image_length, command, parameters.CommandLine.Length / 2, NULL);
    PEB *unreadable_peb = (PEB *)((char *)guard + page_size);
    ios_cs2_processes[0].owner = unreadable_peb;
    debug_context.owner = unreadable_peb;
    ios_cs2_observe_debug(&debug_context);
    assert(strstr(output, "being-debugged=unmeasured nt-global-flag=unmeasured"));
    assert(!native_read((char *)guard + page_size, &source_peb, sizeof(source_peb)));
    before = output_size; debug_context.lease++;
    ios_cs2_observe_debug(&debug_context); assert(output_size == before);

    /* Actual adapters accept only readable bounded metadata. Their failed
     * reads never alter source page protections or infer a complete argv. */
    reset();
    parameters.CommandLine = (UNICODE_STRING){20, 20, (uint16_t *)((char *)guard + page_size)};
    observe_start(0x8664); unchanged();
    assert(strstr(output, "known-sequence=- parse-complete=0"));
    reset(); partial_source = &parameters.CommandLine;
    observe_start(0x8664); unchanged();
    assert(strstr(output, "known-sequence=- parse-complete=0"));
    reset();
    parameters.CommandLine = (UNICODE_STRING){IOS_CS2_COMMAND * 2, IOS_CS2_COMMAND * 2,
        (uint16_t *)((char *)guard + page_size)};
    observe_start(0x8664); unchanged();
    assert(strstr(output, "known-sequence=- parse-complete=0"));
    reset();
    /* Independent bounded pre-PE observation recovers a busy initial
     * snapshot without creating a group or replaying successful records. */
    pthread_mutex_lock(&ios_thread_group_mutex);
    observe_start(0x8664); unchanged(); assert(!output_size);
    pthread_mutex_unlock(&ios_thread_group_mutex);
    observe_start(0x8664); unchanged();
    assert(strstr(output, "known-sequence=0,1,2 parse-complete=1"));
    reset();
    pthread_mutex_lock(&ios_cs2_mutex);
    observe_start(0x8664); unchanged(); assert(!output_size);
    pthread_mutex_unlock(&ios_cs2_mutex);
    observe_start(0x8664); unchanged();
    assert(strstr(output, "known-sequence=0,1,2 parse-complete=1"));
    reset(); parameters.ImagePathName.Length |= 1;
    observe_start(0x8664); unchanged(); assert(!output_size);
    reset(); parameters.ImagePathName.MaximumLength = 0;
    observe_start(0x8664); unchanged(); assert(!output_size);
    reset(); parameters.ImagePathName.Buffer = (uint16_t *)((char *)guard + page_size);
    observe_start(0x8664); unchanged(); assert(!output_size);
    reset(); parameters.ImagePathName = string(image, "C:\\Steam\\steam.exe");
    observe_start(0x8664); unchanged(); assert(!output_size);
    reset(); current_teb.ClientId.UniqueThread = NULL;
    observe_start(0x8664); unchanged(); assert(!output_size && !read_calls);
    reset(); current_teb.Peb = (PEB *)((char *)guard + page_size);
    observe_start(0x8664); unchanged(); assert(!output_size);
    reset();
    /* No registered observer: no guest copy or owner-registry acquisition. */
    assert(!pthread_mutex_lock(&ios_thread_group_mutex));
    ios_cs2_observe_current_map(&module, 0x8664, 0, 1); unchanged();
    pthread_mutex_unlock(&ios_thread_group_mutex);
    assert(!read_calls && !output_size);
    observe_start(0x8664); unchanged();
    module = string(path, "C:\\windows\\sysx64\\kernelbase.dll");
    for (unsigned i = 0; i < 255; i++) ios_cs2_observe_current_map(&module, 0x8664, 1, 1);
    unchanged();
    before = output_size;
    unsigned copies = read_calls;
    assert(!pthread_mutex_lock(&ios_thread_group_mutex));
    for (unsigned i = 0; i < 1000; i++) ios_cs2_observe_current_map(&module, 0x8664, 1, 1);
    pthread_mutex_unlock(&ios_thread_group_mutex);
    unchanged(); assert(output_size == before && read_calls == copies);
    uint16_t check;
    assert(!native_read((char *)guard + page_size, &check, sizeof(check)));
    assert(!munmap(guard, (size_t)page_size * 2));
    puts("CS2 native adapters: protected/short metadata, lease ownership, redaction, errno: PASS");
}
