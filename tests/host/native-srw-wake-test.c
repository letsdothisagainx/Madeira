/* Production SRW methods and Win32 futex queue code, portable kernel alerts. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "wine/list.h"

typedef int32_t LONG, NTSTATUS;
typedef uint32_t ULONG, DWORD;
typedef uint64_t ULONG64;
typedef int64_t LONG64;
typedef uintptr_t ULONG_PTR, DWORD_PTR;
typedef unsigned char UCHAR, BOOLEAN;
typedef unsigned short USHORT;
typedef size_t SIZE_T;
typedef int BOOL, SYSTEM_INFORMATION_CLASS;
typedef void *HANDLE;
typedef union { int64_t QuadPart; } LARGE_INTEGER;
typedef struct { void *Ptr; } RTL_SRWLOCK;
#define WINAPI
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS 0
#define STATUS_ALERTED 0x101
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define ARRAY_SIZE(value) (sizeof(value) / sizeof((value)[0]))
#define TRACE(...) ((void)0)
static void unexpected_diagnostic(const char *format, ...)
{
    (void)format;
    assert(!"unexpected production SRW diagnostic");
}
#define ERR(...) unexpected_diagnostic(__VA_ARGS__)

static _Thread_local unsigned long cas_calls, exchange_calls, history_calls;
static LONG interlocked_compare_exchange(LONG *target, LONG value, LONG expected)
{
    cas_calls++;
    __atomic_compare_exchange_n(target, &expected, value, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return expected;
}
static LONG interlocked_exchange(LONG *target, LONG value)
{
    exchange_calls++;
    return __atomic_exchange_n(target, value, __ATOMIC_SEQ_CST);
}
#define InterlockedCompareExchange(target,value,expected) interlocked_compare_exchange(target,value,expected)
#define InterlockedExchange(target,value) interlocked_exchange(target,value)
#define InterlockedExchangeAdd16(target,value) __atomic_fetch_add(target,value,__ATOMIC_SEQ_CST)
#define InterlockedIncrement(target) __atomic_add_fetch(target,1,__ATOMIC_SEQ_CST)
#define InterlockedIncrement64(target) __atomic_add_fetch(target,1,__ATOMIC_SEQ_CST)
static void YieldProcessor(void)
{
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("pause");
#elif defined(__aarch64__)
    __asm__ volatile("yield");
#else
    sched_yield();
#endif
}
static void ios_srw_note(const void *lock, unsigned mode)
{
    (void)lock;
    assert(mode < 4);
    history_calls++;
}
static void ios_srw_dump_park(const void *address) { (void)address; }
static BOOL ios_sync_lean;
static struct { LONG64 woa_waits, woa_wake_all, woa_wake_single; } diagnostic;
#define ios_xp_nt_writer() (&diagnostic)
struct test_teb { void *Instrumentation[16]; struct { HANDLE UniqueThread; } ClientId; };
static _Thread_local struct test_teb teb;
static struct test_teb *NtCurrentTeb(void) { return &teb; }
static NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS cls, void *out, ULONG size, ULONG *length)
{
    (void)cls; (void)out; (void)size; (void)length;
    return STATUS_INVALID_PARAMETER; /* production's ordinary private-table fallback */
}

/* Kernel thread alerts preserve one pending alert even if wake precedes park. */
struct alert { pthread_mutex_t mutex; pthread_cond_t condition; int pending; };
static struct alert alerts[32];
static _Thread_local DWORD current_tid;
static DWORD next_tid;
static int pause_before_park, at_park_gate, open_park_gate;
static DWORD GetCurrentThreadId(void)
{
    if (!current_tid)
    {
        current_tid = __atomic_add_fetch(&next_tid, 1, __ATOMIC_SEQ_CST);
        assert(current_tid < ARRAY_SIZE(alerts));
        teb.ClientId.UniqueThread = (HANDLE)(uintptr_t)current_tid;
    }
    return current_tid;
}
static uint64_t now_ns(void)
{
    struct timespec now;
    assert(!clock_gettime(CLOCK_MONOTONIC, &now));
    return (uint64_t)now.tv_sec * 1000000000u + now.tv_nsec;
}
static void await_flag(int *flag)
{
    uint64_t deadline = now_ns() + 10000000000u;
    while (!__atomic_load_n(flag, __ATOMIC_ACQUIRE))
    {
        assert(now_ns() < deadline);
        sched_yield();
    }
}
static NTSTATUS NtAlertThreadByThreadId(HANDLE id)
{
    uintptr_t tid = (uintptr_t)id;
    assert(tid && tid < ARRAY_SIZE(alerts));
    struct alert *alert = &alerts[tid];
    assert(!pthread_mutex_lock(&alert->mutex));
    alert->pending = 1;
    assert(!pthread_cond_signal(&alert->condition));
    assert(!pthread_mutex_unlock(&alert->mutex));
    return STATUS_SUCCESS;
}
static NTSTATUS NtAlertMultipleThreadByThreadId(HANDLE *ids, unsigned count, void *a, void *b)
{
    (void)a; (void)b;
    for (unsigned i = 0; i < count; i++) NtAlertThreadByThreadId(ids[i]);
    return STATUS_SUCCESS;
}
static NTSTATUS NtWaitForAlertByThreadId(const void *address, const LARGE_INTEGER *timeout)
{
    (void)address;
    assert(!timeout);
    if (__atomic_exchange_n(&pause_before_park, 0, __ATOMIC_ACQ_REL))
    {
        __atomic_store_n(&at_park_gate, 1, __ATOMIC_RELEASE);
        await_flag(&open_park_gate);
    }
    struct alert *alert = &alerts[GetCurrentThreadId()];
    assert(!pthread_mutex_lock(&alert->mutex));
    while (!alert->pending)
    {
        struct timespec deadline;
        assert(!clock_gettime(CLOCK_REALTIME, &deadline));
        deadline.tv_sec += 10;
        assert(!pthread_cond_timedwait(&alert->condition, &alert->mutex, &deadline));
    }
    alert->pending = 0;
    assert(!pthread_mutex_unlock(&alert->mutex));
    return STATUS_ALERTED;
}
NTSTATUS RtlWaitOnAddress(const void *, const void *, SIZE_T, const LARGE_INTEGER *);
void RtlWakeAddressSingle(const void *);
void RtlWakeAddressAll(const void *);
#include "production-srw-wake.h"

static RTL_SRWLOCK lock;
static unsigned shared_value;
static int readers_inside, writer_inside, reader_ready, release_reader, writer_done;
static void *writer_once(void *unused)
{
    (void)unused;
    RtlAcquireSRWLockExclusive(&lock);
    assert(!__atomic_load_n(&readers_inside, __ATOMIC_SEQ_CST));
    assert(!__atomic_exchange_n(&writer_inside, 1, __ATOMIC_SEQ_CST));
    shared_value++;
    __atomic_store_n(&writer_inside, 0, __ATOMIC_SEQ_CST);
    RtlReleaseSRWLockExclusive(&lock);
    __atomic_store_n(&writer_done, 1, __ATOMIC_RELEASE);
    return NULL;
}
static void *reader_hold(void *unused)
{
    (void)unused;
    RtlAcquireSRWLockShared(&lock);
    __atomic_store_n(&reader_ready, 1, __ATOMIC_RELEASE);
    await_flag(&release_reader);
    RtlReleaseSRWLockShared(&lock);
    return NULL;
}
static void reset(void)
{
    RtlInitializeSRWLock(&lock);
    shared_value = 0;
    reader_ready = release_reader = writer_done = 0;
    at_park_gate = open_park_gate = pause_before_park = 0;
}
static unsigned queued(const void *address)
{
    struct futex_queue *queue = get_futex_queue(address);
    struct futex_entry *entry;
    unsigned count = 0;
    spin_lock(&queue->lock);
    if (queue->queue.next)
        LIST_FOR_EACH_ENTRY(entry, &queue->queue, struct futex_entry, entry)
            count += entry->addr == address;
    spin_unlock(&queue->lock);
    return count;
}
static void await_writer(void)
{
    uint64_t deadline = now_ns() + 10000000000u;
    const struct srw_lock *state = (const void *)&lock;
    while (!queued(&state->owners))
    {
        assert(now_ns() < deadline);
        sched_yield();
    }
    assert(state->exclusive_waiters == 2);
}
static LONG64 wakes(void) { return __atomic_load_n(&diagnostic.woa_wake_single, __ATOMIC_SEQ_CST); }
static void no_waiters(void)
{
    const unsigned rounds = 20000;
    reset();
    LONG64 before = wakes();
    cas_calls = exchange_calls = history_calls = 0;
    for (unsigned i = 0; i < rounds; i++)
    {
        RtlAcquireSRWLockShared(&lock);
        RtlReleaseSRWLockSharedOriginal(&lock);
    }
    assert(wakes() - before == rounds);
    assert(cas_calls == rounds * 3 && exchange_calls == rounds && history_calls == rounds * 2);
    before = wakes();
    cas_calls = exchange_calls = history_calls = 0;
    for (unsigned i = 0; i < rounds; i++)
    {
        RtlAcquireSRWLockShared(&lock);
        RtlReleaseSRWLockShared(&lock);
    }
    assert(wakes() == before);
    assert(cas_calls == rounds * 2 && !exchange_calls && history_calls == rounds * 2);
    assert(!lock.Ptr);
    printf("PASS %u no-waiter releases: wake calls %u -> 0, queue atomic operations %u -> 0, all history events retained\n",
           rounds, rounds, rounds * 2);
}
static void writer_before_last_reader(int early_alert)
{
    reset();
    RtlAcquireSRWLockShared(&lock);
    if (early_alert) pause_before_park = 1;
    pthread_t writer;
    LONG64 before = wakes();
    assert(!pthread_create(&writer, NULL, writer_once, NULL));
    await_writer();
    if (early_alert) await_flag(&at_park_gate);
    RtlReleaseSRWLockShared(&lock);
    assert(wakes() == before + 1);
    if (early_alert) __atomic_store_n(&open_park_gate, 1, __ATOMIC_RELEASE);
    assert(!pthread_join(writer, NULL));
    assert(writer_done && shared_value == 1 && !lock.Ptr);
}
static void multiple_readers(void)
{
    reset();
    RtlAcquireSRWLockShared(&lock);
    pthread_t reader, writer;
    assert(!pthread_create(&reader, NULL, reader_hold, NULL));
    await_flag(&reader_ready);
    LONG64 before = wakes();
    assert(!pthread_create(&writer, NULL, writer_once, NULL));
    await_writer();
    RtlReleaseSRWLockShared(&lock);
    assert(wakes() == before && !__atomic_load_n(&writer_done, __ATOMIC_ACQUIRE));
    __atomic_store_n(&release_reader, 1, __ATOMIC_RELEASE);
    assert(!pthread_join(reader, NULL) && !pthread_join(writer, NULL));
    assert(wakes() == before + 1 && shared_value == 1 && !lock.Ptr);
}
static void writer_after_last_reader(void)
{
    reset();
    LONG64 before = wakes();
    LONG64 waits = __atomic_load_n(&diagnostic.woa_waits, __ATOMIC_SEQ_CST);
    RtlAcquireSRWLockShared(&lock);
    RtlReleaseSRWLockShared(&lock);
    pthread_t writer;
    assert(!pthread_create(&writer, NULL, writer_once, NULL) && !pthread_join(writer, NULL));
    assert(wakes() == before && diagnostic.woa_waits == waits);
    assert(writer_done && shared_value == 1 && !lock.Ptr);
}
static int stress_start;
static void *mixed_worker(void *argument)
{
    unsigned writer = (uintptr_t)argument < 2;
    unsigned previous = 0;
    await_flag(&stress_start);
    for (unsigned i = 0; i < 6000; i++)
    {
        if (writer)
        {
            RtlAcquireSRWLockExclusive(&lock);
            assert(!__atomic_load_n(&readers_inside, __ATOMIC_SEQ_CST));
            assert(!__atomic_exchange_n(&writer_inside, 1, __ATOMIC_SEQ_CST));
            shared_value++;
            if (!(i & 31)) sched_yield();
            __atomic_store_n(&writer_inside, 0, __ATOMIC_SEQ_CST);
            RtlReleaseSRWLockExclusive(&lock);
        }
        else
        {
            RtlAcquireSRWLockShared(&lock);
            __atomic_add_fetch(&readers_inside, 1, __ATOMIC_SEQ_CST);
            assert(!__atomic_load_n(&writer_inside, __ATOMIC_SEQ_CST));
            assert(shared_value >= previous);
            previous = shared_value;
            if (!(i & 31)) sched_yield();
            __atomic_sub_fetch(&readers_inside, 1, __ATOMIC_SEQ_CST);
            RtlReleaseSRWLockShared(&lock);
        }
    }
    return NULL;
}
static void mixed_readers_writers(void)
{
    reset();
    pthread_t threads[8];
    for (uintptr_t i = 0; i < ARRAY_SIZE(threads); i++)
        assert(!pthread_create(&threads[i], NULL, mixed_worker, (void *)i));
    __atomic_store_n(&stress_start, 1, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < ARRAY_SIZE(threads); i++) assert(!pthread_join(threads[i], NULL));
    assert(shared_value == 12000 && !readers_inside && !writer_inside && !lock.Ptr);
    puts("PASS actual SRW and futex queues: 6 readers/2 writers,48000 acquire/release pairs,mutual exclusion and all updates retained");
}
int main(void)
{
    for (unsigned i = 0; i < ARRAY_SIZE(alerts); i++)
    {
        assert(!pthread_mutex_init(&alerts[i].mutex, NULL));
        assert(!pthread_cond_init(&alerts[i].condition, NULL));
    }
    (void)GetCurrentThreadId();
    (void)ios_get_futex_table(); /* establish the production table before concurrency */
    no_waiters();
    writer_before_last_reader(0);
    writer_before_last_reader(1);
    multiple_readers();
    writer_after_last_reader();
    puts("PASS writer before/after last-reader release,final-owner wake only,and alert delivered before kernel park");
    mixed_readers_writers();
    return 0;
}
