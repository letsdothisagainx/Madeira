/* Hosted backends for the real staged native fastsync/public wait functions. */
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define madeira_fast_park unused_platform_park
#include "wine/madeira_fastsync.h"
#undef madeira_fast_park

typedef uint32_t DWORD, UINT;
typedef int32_t NTSTATUS;
typedef int BOOLEAN;
typedef void *HANDLE;
typedef struct { int64_t QuadPart; } LARGE_INTEGER;
typedef enum { WaitAll, WaitAny } WAIT_TYPE;
union select_op { struct { unsigned int op, handles[64]; } wait; };
#define WINAPI
#define WINE_IOS 1
#define TRUE 1
#define FALSE 0
#define MAXIMUM_WAIT_OBJECTS 64
#define SYNCHRONIZE 0x100000
#define SELECT_INTERRUPTIBLE 1
#define SELECT_ALERTABLE 2
#define SELECT_WAIT 3
#define SELECT_WAIT_ALL 4
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_TIMEOUT ((NTSTATUS)0x102)
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xc0000002)
#define STATUS_INVALID_HANDLE ((NTSTATUS)0xc0000008)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022)
#define STATUS_INVALID_PARAMETER_1 ((NTSTATUS)0xc00000ef)
#define STATUS_ABANDONED_WAIT_0 ((NTSTATUS)0x80)
#define STATUS_USER_APC ((NTSTATUS)0xc0)
#define TRACE(...) ((void)0)
#define FIXME(...) ((void)0)
#define TRACE_ON(channel) 0
#define IOS_ECO_POLL() ((void)0)

static struct madeira_sync_cell cell;
static unsigned long long now_ns, lookup_cost, enabled_cost, barrier_cost, signal_at;
static unsigned long long park_ns, park_extra, enabled_calls, lookup_calls, park_calls, clock_calls, try_calls;
static int enabled, have_cell, peek, recycle_park;
static int madeira_fast_peek = 1, madeira_fast_spin_credit = 64;
static unsigned int madeira_fast_spin_probe_seq;
static unsigned long long madeira_fast_cap_ns = 2000000, madeira_fast_spin_ns = 40000;
static unsigned server_calls, inproc_calls, server_flags, server_size;
static NTSTATUS server_status, inproc_status;
static int64_t server_timeout;
static const LARGE_INTEGER *server_timeout_pointer;
static unsigned long long server_signal_at;
static int consume_server_time;
static int production_fast_try(struct madeira_sync_cell *, unsigned int, unsigned int, unsigned int);

static unsigned long long madeira_now_ns(void) { ++clock_calls; return now_ns; }
static void host_isb(void) { now_ns += barrier_cost; }
static int madeira_fastsync_enabled(void) { ++enabled_calls; now_ns += enabled_cost; return enabled; }
static int madeira_fast_cells_enabled(void) { return 1; }
static int madeira_fast_armed(void) { return 0; }
static struct madeira_sync_cell *madeira_fast_lookup(HANDLE handle, unsigned access, unsigned *manual, unsigned *gen, unsigned *kind)
{
    (void)handle; assert(access == SYNCHRONIZE);
    ++lookup_calls; now_ns += lookup_cost;
    *manual = cell.manual; *gen = 1; *kind = cell.kind;
    return have_cell ? &cell : NULL;
}
static int madeira_peek_cell(struct madeira_sync_cell *c, unsigned gen)
{
    return peek && MADEIRA_SG_GEN(c->sg) == gen && MADEIRA_SG_STATE(c->sg) == MADEIRA_CELL_RESET;
}
static int madeira_fast_try(struct madeira_sync_cell *c, unsigned manual, unsigned gen, unsigned kind)
{
    ++try_calls;
    if (signal_at && now_ns >= signal_at && MADEIRA_SG_GEN(c->sg) == gen)
    {
        c->sg = MADEIRA_SG(gen, MADEIRA_CELL_SET);
        signal_at = 0;
    }
    return production_fast_try(c, manual, gen, kind);
}
static void madeira_fast_park(const int *address, int value, uint64_t duration)
{
    assert(address == madeira_cell_futex(&cell) && value == MADEIRA_CELL_RESET && duration);
    ++park_calls; park_ns += duration; now_ns += duration + park_extra;
    if (recycle_park)
    {
        cell.sg = MADEIRA_SG(2, MADEIRA_CELL_SET);
        cell.waiters = 0; /* allocator resets the new generation's waiter count */
    }
}
static int is_pseudo_handle(HANDLE h) { return (intptr_t)h < 0; }
static unsigned wine_server_obj_handle(HANDLE h) { return (unsigned)(uintptr_t)h; }
static NTSTATUS inproc_wait(DWORD count, const HANDLE *handles, WAIT_TYPE type, BOOLEAN alertable, const LARGE_INTEGER *timeout)
{
    (void)count; (void)handles; (void)type; (void)alertable; (void)timeout;
    ++inproc_calls; return inproc_status;
}
static NTSTATUS server_wait(union select_op *op, unsigned size, unsigned flags, const LARGE_INTEGER *timeout)
{
    (void)op; ++server_calls; server_size = size; server_flags = flags;
    server_timeout_pointer = timeout; server_timeout = timeout ? timeout->QuadPart : INT64_MAX;
    /* A server response is authoritative for errors, abandoned waits and APCs.
     * For a readiness race the real server checks the object before its timer. */
    if (server_status != STATUS_TIMEOUT) return server_status;
    if (server_signal_at && now_ns >= server_signal_at) return STATUS_SUCCESS;
    if (consume_server_time && timeout && timeout->QuadPart < 0)
        now_ns += (0ull - (unsigned long long)timeout->QuadPart) * 100;
    return STATUS_TIMEOUT;
}
static NTSTATUS madeira_fast_watched_wait(union select_op *op, unsigned size, unsigned flags, HANDLE handle)
{
    (void)handle; return server_wait(op, size, flags, NULL);
}
static long long ios_xp_wait_single, ios_xp_wait_multi, ios_xp_wait_zero, ios_xp_wait_zero_timeout;

#include "production-fastsync-timeout.h"

static unsigned checks, failures;
#define CHECK(condition, name) do { ++checks; if (!(condition)) { ++failures; printf("REGRESSION: %s (line %d)\n", name, __LINE__); } } while (0)
static void reset(void)
{
    memset(&cell, 0, sizeof(cell)); cell.sg = MADEIRA_SG(1, MADEIRA_CELL_RESET); cell.kind = MADEIRA_CELL_KIND_EVENT;
    now_ns = 1000000; lookup_cost = enabled_cost = 0; barrier_cost = 100;
    signal_at = park_ns = park_extra = enabled_calls = lookup_calls = park_calls = clock_calls = try_calls = 0;
    enabled = have_cell = peek = 1; recycle_park = 0;
    madeira_fast_spin_credit = 64; madeira_fast_spin_probe_seq = 0;
    madeira_fast_cap_ns = 2000000; madeira_fast_spin_ns = 40000;
    server_calls = inproc_calls = server_flags = server_size = 0;
    server_timeout = 12345; server_timeout_pointer = NULL; server_signal_at = 0; consume_server_time = 0;
    server_status = STATUS_TIMEOUT; inproc_status = STATUS_NOT_IMPLEMENTED;
    ios_xp_wait_single = ios_xp_wait_multi = ios_xp_wait_zero = ios_xp_wait_zero_timeout = 0;
}
static NTSTATUS wait_for(int64_t ticks)
{
    LARGE_INTEGER timeout = {ticks};
    return NtWaitForSingleObject((HANDLE)4, FALSE, &timeout);
}
static void fallback_contract(void)
{
    const int64_t values[] = {-5, -10000, 0, 123456789};
    const NTSTATUS results[] = {STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_INVALID_HANDLE,
                               STATUS_ACCESS_DENIED, STATUS_ABANDONED_WAIT_0, STATUS_USER_APC};
    HANDLE handle = (HANDLE)4;

    for (unsigned missing = 0; missing < 2; ++missing)
    for (unsigned value = 0; value <= sizeof(values) / sizeof(values[0]); ++value)
    {
        LARGE_INTEGER timeout = {value < sizeof(values) / sizeof(values[0]) ? values[value] : 0};
        const LARGE_INTEGER *input = value < sizeof(values) / sizeof(values[0]) ? &timeout : NULL;
        int64_t saved = timeout.QuadPart;
        const LARGE_INTEGER *fallback = NULL;
        LARGE_INTEGER store = {0x11223344};

        reset(); enabled = missing; have_cell = !missing; peek = 0;
        enabled_cost = lookup_cost = 20000;
        CHECK(madeira_fast_wait(handle, input, &fallback, &store) == STATUS_NOT_IMPLEMENTED &&
              fallback == input && timeout.QuadPart == saved && store.QuadPart == 0x11223344 &&
              !clock_calls && !park_calls,
              "inactive fallback retains original pointer/value with zero clock calls");

        for (unsigned result = 0; result < sizeof(results) / sizeof(results[0]); ++result)
        for (unsigned multi = 0; multi < 2; ++multi)
        {
            reset(); enabled = missing; have_cell = !missing; peek = 0;
            enabled_cost = lookup_cost = 20000; server_status = results[result];
            NTSTATUS status = multi ? NtWaitForMultipleObjects(1, &handle, WaitAny, FALSE, input) :
                                      NtWaitForSingleObject(handle, FALSE, input);
            CHECK(status == results[result] && server_calls == 1 && server_timeout_pointer == input &&
                  server_timeout == (input ? saved : INT64_MAX) && timeout.QuadPart == saved &&
                  !clock_calls && !park_calls,
                  "inactive public dispatch preserves original server timeout and status/APC route");
        }
    }
}
int main(int argc, char **argv)
{
    int original = argc > 1 && !strcmp(argv[1], "original");
    fallback_contract();
    if (argc > 1 && !strcmp(argv[1], "fallback-contract"))
    {
        printf("%s: %u inactive fallback checks, %u failures\n", failures ? "FAIL" : "PASS", checks, failures);
        return failures ? 1 : 0;
    }
    reset();
    CHECK(wait_for(-5) == STATUS_TIMEOUT && !park_calls && now_ns == 1009600 && server_timeout == 0,
          "initial spin exceeded relative deadline");

    reset();
    CHECK(wait_for(-100) == STATUS_TIMEOUT && !park_calls && now_ns == 1019200 && server_timeout == 0,
          "adaptive spin must not be followed by another full relative park");

    reset(); lookup_cost = 3000; enabled_cost = 2000; consume_server_time = 1;
    CHECK(wait_for(-10000) == STATUS_TIMEOUT && park_ns == 942400 && now_ns == 2005000 && server_timeout == 0,
          "active initial spin, adaptive spin and park share one deadline after cell admission");

    reset(); lookup_cost = 3000; enabled_cost = 2000; madeira_fast_cap_ns = 100000;
    CHECK(wait_for(-10000) == STATUS_TIMEOUT && park_ns == 100000 && server_timeout == -8424 && now_ns == 1162600,
          "active fallback debits spin and park elapsed, beyond the park cap");

    reset(); madeira_fast_spin_ns = 0; barrier_cost = 0; park_extra = 2000000;
    CHECK(wait_for(-10000) == STATUS_TIMEOUT && server_timeout == 0 && server_calls == 1,
          "park overshoot expires through the real server poll");

    reset(); signal_at = now_ns + 9600;
    CHECK(wait_for(-5) == STATUS_SUCCESS && !park_calls && !server_calls && MADEIRA_SG_STATE(cell.sg) == MADEIRA_CELL_RESET,
          "signaled auto-reset object wins at an elapsed deadline and consumes once");

    reset(); signal_at = now_ns + 15000;
    CHECK(wait_for(-100) == STATUS_SUCCESS && now_ns == 1015000 && !park_calls && !server_calls,
          "signal during adaptive spin wins before an expired fallback");

    reset(); signal_at = now_ns + 100000;
    CHECK(wait_for(-1000) == STATUS_SUCCESS && now_ns == 1100000 && park_calls == 1 && !server_calls,
          "signal during park wins at the original deadline");

    reset(); cell.manual = 1; signal_at = now_ns + 9600;
    CHECK(wait_for(-5) == STATUS_SUCCESS && MADEIRA_SG_STATE(cell.sg) == MADEIRA_CELL_SET,
          "manual-reset readiness remains signaled");

    reset(); cell.kind = MADEIRA_CELL_KIND_SEM; signal_at = now_ns + 9600;
    CHECK(wait_for(-5) == STATUS_SUCCESS && MADEIRA_SG_STATE(cell.sg) == 0,
          "semaphore readiness consumes one real token");

    reset(); server_signal_at = now_ns + 9600;
    CHECK(wait_for(-5) == STATUS_SUCCESS && server_calls == 1 && server_timeout == 0,
          "readiness racing timeout remains the server's decision");

    const NTSTATUS results[] = {STATUS_INVALID_HANDLE, STATUS_ACCESS_DENIED, STATUS_ABANDONED_WAIT_0, STATUS_USER_APC};
    for (unsigned i = 0; i < sizeof(results) / sizeof(results[0]); ++i)
    {
        reset(); have_cell = 0; lookup_cost = 20000; server_status = results[i];
        CHECK(wait_for(-100) == results[i] && server_calls == 1 && server_timeout == -100 && !park_calls && !clock_calls,
              "lookup miss preserves original timeout and server error/abandoned/APC response");
        reset(); server_status = results[i];
        CHECK(wait_for(-5) == results[i] && server_calls == 1 && server_timeout == 0 && !park_calls,
              "expired spin preserves server error/abandoned/APC response");
    }

    reset(); have_cell = 0; lookup_cost = 2000;
    CHECK(wait_for(-100) == STATUS_TIMEOUT && server_timeout == -100 && !park_calls && !clock_calls,
          "lookup miss retains original timeout without a clock read");

    reset(); enabled = 0; enabled_cost = 2000;
    CHECK(wait_for(-100) == STATUS_TIMEOUT && server_timeout == -100 && !lookup_calls && !clock_calls,
          "disabled fast path retains original timeout without a clock read");

    reset();
    CHECK(wait_for(0) == STATUS_TIMEOUT && !clock_calls && !park_calls && !server_calls,
          "explicit zero-timeout negative peek has no deadline or park");
    reset(); peek = 0;
    CHECK(wait_for(0) == STATUS_TIMEOUT && !clock_calls && !park_calls && server_timeout == 0 && server_calls == 1,
          "explicit zero-timeout server probe keeps its route");
    reset(); cell.sg = MADEIRA_SG(1, MADEIRA_CELL_SET);
    CHECK(wait_for(0) == STATUS_SUCCESS && !clock_calls && !park_calls && !server_calls,
          "explicit zero-timeout signaled object succeeds");
    reset(); enabled = 0;
    CHECK(wait_for(0) == STATUS_TIMEOUT && !clock_calls && !park_calls && !server_calls,
          "disabled fast path retains its read-only zero-timeout peek");

    reset(); LARGE_INTEGER absolute = {123456789};
    CHECK(NtWaitForSingleObject((HANDLE)4, FALSE, &absolute) == STATUS_TIMEOUT &&
          server_timeout_pointer == &absolute && server_timeout == absolute.QuadPart && park_ns == 2000000,
          "absolute deadline reaches server unchanged with existing fast park cap");
    reset();
    CHECK(NtWaitForSingleObject((HANDLE)4, FALSE, NULL) == STATUS_TIMEOUT && !server_timeout_pointer && park_ns == 2000000,
          "infinite wait remains NULL with existing fast park cap");

    reset(); LARGE_INTEGER timeout = {-5}; HANDLE handles[2] = {(HANDLE)4, (HANDLE)8};
    CHECK(NtWaitForMultipleObjects(1, handles, WaitAny, FALSE, &timeout) == STATUS_TIMEOUT &&
          !park_calls && server_timeout == 0 && ios_xp_wait_multi == 1,
          "one-handle multiple wait uses the corrected production function");
    reset();
    CHECK(NtWaitForSingleObject((HANDLE)4, TRUE, &timeout) == STATUS_TIMEOUT &&
          !enabled_calls && !park_calls && server_timeout == -5 && (server_flags & SELECT_ALERTABLE),
          "alertable wait keeps original server/APC path");
    reset();
    CHECK(NtWaitForMultipleObjects(1, handles, WaitAll, FALSE, &timeout) == STATUS_TIMEOUT &&
          !enabled_calls && !park_calls && server_timeout == -5,
          "wait-all keeps original server path");
    reset();
    CHECK(NtWaitForMultipleObjects(2, handles, WaitAny, FALSE, &timeout) == STATUS_TIMEOUT &&
          !enabled_calls && !park_calls && server_timeout == -5,
          "multiple handles keep original server path");
    reset(); inproc_status = STATUS_ABANDONED_WAIT_0;
    CHECK(wait_for(-5) == STATUS_ABANDONED_WAIT_0 && !enabled_calls && !server_calls && !clock_calls,
          "in-process synchronisation response retains priority");

    reset(); madeira_fast_spin_ns = 0; recycle_park = 1;
    CHECK(wait_for(-10000) == STATUS_TIMEOUT && cell.waiters == 0 && MADEIRA_SG_GEN(cell.sg) == 2 &&
          MADEIRA_SG_STATE(cell.sg) == MADEIRA_CELL_SET && server_calls == 1,
          "recycled generation preserves new owner's token and waiter count");

    if (!original)
    {
        reset(); server_status = STATUS_ACCESS_DENIED;
        CHECK(wait_for(INT64_MIN) == STATUS_ACCESS_DENIED && park_ns == 2000000 &&
              server_timeout == INT64_MIN + 20576,
              "largest relative duration avoids signed negation and ns conversion overflow");
    }
    printf("%s: %u production fastsync timeout checks, %u failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
