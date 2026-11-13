#!/usr/bin/env python3
"""Execute staged RtlSizeHeap and Wine's LFH algorithms with hosted OS shims.

The real handle/pointer checks, header helpers, size function, LFH allocation,
free and group-selection functions are compiled unchanged from pinned Wine.
Only OS atomics/critical sections/SLISTs and slow backing-allocation services are
hosted. This is a correctness/serialization regression, not an FPS benchmark.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("lfh_size", ROOT / "tools/build/stage-native-lfh-size.py")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
original = (ROOT / "wine/dlls/ntdll/heap.c").read_text()
staged = stage.stage(original)
assert staged.replace(stage.FAST, "", 1) == original
for bad in (staged, original.replace(stage.ANCHOR, "", 1)):
    try:
        stage.stage(bad)
    except ValueError:
        pass
    else:
        raise AssertionError("ambiguous or already staged source accepted")


def function(signature, source=staged):
    start = source.index(signature)
    while ";" in source[start:source.index("\n{", start)]:
        start = source.index(signature, start + len(signature))
    return source[start:source.index("\n}\n", start) + 3]


def between(start, end):
    a = original.index(start)
    return original[a:original.index(end, a)]


harness = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD, ULONG, UINT;
typedef int32_t LONG, NTSTATUS;
typedef uint64_t ULONGLONG;
typedef uintptr_t DWORD_PTR, ULONG_PTR, UINT_PTR;
typedef size_t SIZE_T;
typedef int BOOL;
typedef void *HANDLE, *LPVOID;
struct list { struct list *next, *prev; };
typedef struct __attribute__((aligned(16))) _SLIST_ENTRY { struct _SLIST_ENTRY *Next; } SLIST_ENTRY;
typedef struct { pthread_mutex_t mutex; SLIST_ENTRY *head; unsigned depth; } SLIST_HEADER;
typedef struct { pthread_mutex_t mutex; } RTL_CRITICAL_SECTION;
#define DECLSPEC_ALIGN(x) __attribute__((aligned(x)))
#define WINAPI
#define TRUE 1
#define FALSE 0
#define C_ASSERT(x) _Static_assert(x, #x)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define CONTAINING_RECORD(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
#define HEAP_GENERATE_EXCEPTIONS 4
#define HEAP_NO_SERIALIZE 1
#define HEAP_ZERO_MEMORY 8
#define HEAP_REALLOC_IN_PLACE_ONLY 0x10
#define HEAP_TAIL_CHECKING_ENABLED 0x20
#define HEAP_FREE_CHECKING_ENABLED 0x40
#define STATUS_SUCCESS 0
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_NO_MEMORY ((NTSTATUS)0xc0000017)
#define RUNNING_ON_VALGRIND 0
#define TRACE(...) ((void)0)
#define WARN(...) ((void)0)
#define ERR(...) ((void)0)
#define TRACE_ON(x) 0
#define ReadNoFence(p) __atomic_load_n((p), __ATOMIC_RELAXED)
#define ReadAcquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define WriteRelease(p,v) __atomic_store_n((p),(v), __ATOMIC_RELEASE)
#define InterlockedIncrement(p) (__atomic_add_fetch((p),1,__ATOMIC_SEQ_CST))
#define InterlockedAnd(p,v) __atomic_fetch_and((p),(v),__ATOMIC_SEQ_CST)
#define InterlockedOr(p,v) __atomic_fetch_or((p),(v),__ATOMIC_SEQ_CST)
#define InterlockedExchangePointer(p,v) __atomic_exchange_n((void **)(p),(v),__ATOMIC_SEQ_CST)
static LONG InterlockedCompareExchange(LONG *p, LONG value, LONG compare) {
    __atomic_compare_exchange_n(p,&compare,value,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST); return compare;
}
static void *InterlockedCompareExchangePointer(void **p, void *value, void *compare) {
    __atomic_compare_exchange_n(p,&compare,value,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST); return compare;
}
static void BitScanForward(ULONG *index, ULONG bits) { assert(bits); *index = __builtin_ctz(bits); }
static SLIST_ENTRY *RtlInterlockedPopEntrySList(SLIST_HEADER *s) {
    pthread_mutex_lock(&s->mutex); SLIST_ENTRY *e=s->head;
    if(e) { s->head=e->Next; s->depth--; } pthread_mutex_unlock(&s->mutex); return e;
}
static void RtlInterlockedPushEntrySList(SLIST_HEADER *s, SLIST_ENTRY *e) {
    pthread_mutex_lock(&s->mutex); e->Next=s->head; s->head=e; s->depth++; pthread_mutex_unlock(&s->mutex);
}
static unsigned RtlQueryDepthSList(SLIST_HEADER *s) {
    pthread_mutex_lock(&s->mutex); unsigned d=s->depth; pthread_mutex_unlock(&s->mutex); return d;
}
static _Thread_local struct { ULONG HeapVirtualAffinity; } teb;
#define NtCurrentTeb() (&teb)
static _Atomic unsigned locks, unlocks, ptr_validations, heap_validations;
static _Thread_local unsigned last_error;
static _Thread_local NTSTATUS last_status;
static int validation_ok=1;
static void RtlEnterCriticalSection(RTL_CRITICAL_SECTION *cs) {
    atomic_fetch_add(&locks,1); assert(!pthread_mutex_lock(&cs->mutex));
}
static void RtlLeaveCriticalSection(RTL_CRITICAL_SECTION *cs) {
    atomic_fetch_add(&unlocks,1); assert(!pthread_mutex_unlock(&cs->mutex));
}
static void RtlRaiseStatus(NTSTATUS status) { (void)status; abort(); }
static void RtlSetLastWin32ErrorAndNtStatusFromNtStatus(NTSTATUS status) {
    last_error=status==STATUS_INVALID_PARAMETER ? 87 : 8; last_status=status;
}
''' + between("/* HeapCompatibilityInformation values */", "#ifdef __i386__\n/* Madeira:") + r'''
static BOOL heap_validate(const struct heap *heap) {
    (void)heap; atomic_fetch_add(&heap_validations,1); return validation_ok;
}
static BOOL heap_validate_ptr(const struct heap *heap, const void *ptr) {
    (void)heap; (void)ptr; atomic_fetch_add(&ptr_validations,1); return validation_ok;
}
static void heap_dump(const struct heap *heap) { (void)heap; }
'''
for signature in (
    "static inline BOOL contains(", "static inline UINT block_get_flags(",
    "static inline UINT block_get_type(", "static inline void block_set_type(",
    "static inline SUBHEAP *block_get_subheap(", "static inline UINT block_get_overhead(",
    "static inline UINT block_get_size(", "static inline void block_set_size(",
    "static inline void block_set_flags(", "static inline void *subheap_base(",
    "static inline const void *subheap_commit_end(", "static inline void valgrind_make_noaccess(",
    "static inline void valgrind_make_writable(",
    "static inline void mark_block_free(", "static inline void mark_block_tail(",
    "static inline void initialize_block(", "static inline ULONG heap_get_flags(",
    "static inline void heap_lock(", "static inline void heap_unlock(",
    "static void heap_set_status(", "static struct heap *unsafe_heap_from_handle(",
    "static inline struct block *unsafe_block_from_ptr(", "static NTSTATUS heap_size(",
):
    harness += function(signature)
harness += function(stage.SIGNATURE, original).replace("RtlSizeHeap(", "OriginalRtlSizeHeap(", 1)
harness += function(stage.SIGNATURE)
harness += between("/* header for every LFH block group */", "/* allocate a new group block using non-LFH allocation")
harness += r'''
/* The test pre-seeds real groups; exhausting them or releasing to backing
 * storage is unexpected and must not silently substitute an allocator. */
static struct group *group_allocate(struct heap *h, ULONG f, SIZE_T s) {
    (void)h; (void)f; (void)s; abort();
}
static NTSTATUS group_release(struct heap *h, ULONG f, struct bin *b, struct group *g) {
    (void)h; (void)f; (void)b; (void)g; abort();
}
'''
for signature in (
    "static inline ULONG heap_current_thread_affinity(",
    "static struct group *heap_acquire_bin_group(",
    "static NTSTATUS heap_release_bin_group(",
    "static struct block *find_free_bin_block(",
    "static NTSTATUS heap_allocate_block_lfh(",
    "static NTSTATUS heap_free_block_lfh(",
):
    harness += function(signature)
harness += r'''
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); abort(); } } while(0)
static unsigned cases;
static struct heap *new_heap(void) {
    struct heap *h; CHECK(!posix_memalign((void **)&h,REGION_ALIGN,REGION_ALIGN));
    memset(h,0,REGION_ALIGN); h->magic=HEAP_MAGIC; pthread_mutex_init(&h->cs.mutex,NULL);
    h->subheap.user_value=h; h->subheap.block_size=REGION_ALIGN-((char *)&h->subheap.block-(char *)h);
    h->subheap.data_size=REGION_ALIGN-((char *)(&h->subheap+1)-(char *)h); return h;
}
static void compare(struct heap *h, ULONG flags, void *ptr, unsigned wanted_locks) {
    locks=unlocks=0; last_error=0x1234; last_status=0x5678;
    SIZE_T before=OriginalRtlSizeHeap(h,flags,ptr);
    unsigned error=last_error; NTSTATUS status=last_status;
    locks=unlocks=0; last_error=0x1234; last_status=0x5678;
    SIZE_T after=RtlSizeHeap(h,flags,ptr);
    CHECK(after==before && error==last_error && status==last_status);
    CHECK(locks==wanted_locks && unlocks==wanted_locks); cases++;
}
static void add_groups(struct heap *h, SIZE_T size) {
    h->bins=calloc(BLOCK_SIZE_BIN_COUNT,sizeof(*h->bins)); CHECK(h->bins);
    struct group **slots=calloc(BLOCK_SIZE_BIN_COUNT*ARRAY_SIZE(affinity_mapping),sizeof(*slots)); CHECK(slots);
    for(unsigned i=0;i<BLOCK_SIZE_BIN_COUNT;i++) {
        pthread_mutex_init(&h->bins[i].groups.mutex,NULL);
        h->bins[i].affinity_group_base=slots+i;
    }
    struct bin *bin=h->bins+BLOCK_SIZE_BIN(size); bin->enabled=1;
    for(unsigned n=0;n<12;n++) {
        struct group *g; SIZE_T bytes=offsetof(struct group,first_block)+GROUP_BLOCK_COUNT*size;
        CHECK(!posix_memalign((void **)&g,BLOCK_ALIGN,bytes)); memset(g,0,bytes); g->free_bits=~GROUP_FLAG_FREE;
        for(unsigned i=0;i<GROUP_BLOCK_COUNT;i++) {
            struct block *b=group_get_block(g,size,i);
            block_set_type(b,BLOCK_TYPE_FREE); block_set_flags(b,~0,BLOCK_FLAG_FREE|BLOCK_FLAG_LFH);
            block_set_group(b,size,g); block_set_size(b,size);
        }
        RtlInterlockedPushEntrySList(&bin->groups,&g->entry);
    }
}
struct worker { struct heap *heap; void *target; unsigned id; };
static _Atomic unsigned ready, start;
static void *churn(void *arg) {
    struct worker *w=arg; teb.HeapVirtualAffinity=w->id+1; atomic_fetch_add(&ready,1);
    while(!atomic_load_explicit(&start,memory_order_acquire)) {}
    for(unsigned i=0;i<12000;i++) {
        void *ptr=NULL; SIZE_T size=17+(i%60);
        CHECK(!heap_allocate_block_lfh(w->heap,0,128,size,&ptr)); CHECK(ptr);
        memset(ptr,w->id,size);
        CHECK(RtlSizeHeap(w->heap,0,ptr)==size);
        CHECK(RtlSizeHeap(w->heap,0,w->target)==53);
        for(SIZE_T j=0;j<size;j++) CHECK(((BYTE *)ptr)[j]==w->id);
        CHECK(!heap_free_block_lfh(w->heap,0,(struct block *)ptr-1));
    }
    return NULL;
}
int main(void) {
    struct heap *h=new_heap(), *foreign=new_heap(); add_groups(h,128);
    void *ptr=NULL; CHECK(!heap_allocate_block_lfh(h,0,128,53,&ptr));
    CHECK(RtlSizeHeap(h,0,ptr)==53);
    compare(h,0,ptr,0); compare(h,HEAP_NO_SERIALIZE,ptr,0);
    /* Querying another live heap's LFH block already succeeds in Wine;
     * preserve that result, without pretending to strengthen validation. */
    compare(foreign,0,ptr,0);
    const ULONG debug[]={HEAP_VALIDATE,HEAP_VALIDATE_ALL,HEAP_VALIDATE_PARAMS,
        HEAP_CHECKING_ENABLED,HEAP_TAIL_CHECKING_ENABLED,HEAP_FREE_CHECKING_ENABLED,HEAP_PAGE_ALLOCS};
    for(unsigned i=0;i<ARRAY_SIZE(debug);i++) {
        h->flags=debug[i]; compare(h,0,ptr,(debug[i]==HEAP_VALIDATE||debug[i]==HEAP_VALIDATE_ALL)?2:1);
    }
    h->flags=0;
    compare(h,HEAP_TAIL_CHECKING_ENABLED,ptr,1); compare(h,HEAP_FREE_CHECKING_ENABLED,ptr,1);
    h->flags=HEAP_VALIDATE; validation_ok=0; compare(h,0,ptr,1); validation_ok=1; h->flags=0;
    h->flags=HEAP_VALIDATE_ALL; validation_ok=0; compare(h,0,ptr,1); validation_ok=1; h->flags=0;
    CHECK(ptr_validations && heap_validations);
    struct block *b=(struct block *)ptr-1; BYTE saved=b->block_type;
    b->block_type=BLOCK_TYPE_FREE; compare(h,0,ptr,0);
    b->block_type=BLOCK_TYPE_DEAD; compare(h,0,ptr,0); b->block_type=saved;
    compare(h,0,(char *)ptr+1,0); compare(NULL,0,ptr,0);
    foreign->magic=0; compare(foreign,0,ptr,0); foreign->magic=HEAP_MAGIC;
    /* Even contradictory LFH flags retain the old serialized behavior. */
    WORD tail=b->tail_size; b->tail_size=0; b->block_flags|=BLOCK_FLAG_FREE; compare(h,0,ptr,1);
    b->block_flags&=~BLOCK_FLAG_FREE; b->tail_size=tail;
    struct block *standard=(struct block *)((char *)h+8192)-1;
    standard->block_type=BLOCK_TYPE_USED; standard->block_size=8; standard->tail_size=23;
    compare(h,0,standard+1,1); compare(foreign,0,standard+1,0);
    void *large_region; CHECK(!posix_memalign(&large_region,REGION_ALIGN,REGION_ALIGN));
    memset(large_region,0,REGION_ALIGN); ARENA_LARGE *large=large_region;
    large->block.block_type=BLOCK_TYPE_LARGE; large->block.block_flags=BLOCK_FLAG_LARGE; large->data_size=777;
    compare(h,0,&large->block+1,1);
    large->block.block_type=BLOCK_TYPE_USED; large->block.block_flags|=BLOCK_FLAG_LFH;
    compare(h,0,&large->block+1,1); free(large_region);

    /* Hold the real hosted heap CS throughout concurrent LFH operations.
     * An accidental fallback deadlocks and the Python timeout rejects it. */
    enum {THREADS=6}; pthread_t threads[THREADS]; struct worker work[THREADS];
    RtlEnterCriticalSection(&h->cs); unsigned held_locks=locks;
    for(unsigned i=0;i<THREADS;i++) { work[i]=(struct worker){h,ptr,i+1}; CHECK(!pthread_create(threads+i,NULL,churn,work+i)); }
    while(atomic_load(&ready)!=THREADS) {}
    atomic_store_explicit(&start,1,memory_order_release);
    for(unsigned i=0;i<THREADS;i++) CHECK(!pthread_join(threads[i],NULL));
    CHECK(locks==held_locks); RtlLeaveCriticalSection(&h->cs);
    CHECK(!heap_free_block_lfh(h,0,b));
    printf("PASS %u API cases; 72000 real LFH allocate/size/free cycles; held heap lock never entered\n",cases);
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="madeira-lfh-size-") as scratch:
    tmp = Path(scratch)
    source = tmp / "heap.c"
    source.write_text(harness)
    compiler = os.environ.get("CC", "cc")
    common = [compiler, "-std=gnu11", "-O2", "-g", "-pthread", "-Wall", "-Wextra", "-Werror",
              "-Wno-unused-function", "-Wno-unused-variable", "-Wno-unused-parameter"]
    binary = tmp / "heap"
    subprocess.run(common + [str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
    # Run memory/undefined-behavior checking separately from the plain execution.
    sanitized = tmp / "heap-sanitized"
    subprocess.run(common + ["-fsanitize=address,undefined", str(source), "-o", str(sanitized)], check=True)
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")  # fixture retains its seeded backing groups
    subprocess.run([str(sanitized)], check=True, timeout=30, env=env)
    # The original production function must fail the held-lock test; this is a
    # mutation control that proves the regression detects serialization.
    mutation = harness.replace(function(stage.SIGNATURE), function(stage.SIGNATURE, original), 1)
    source.write_text(mutation)
    subprocess.run(common + [str(source), "-o", str(binary)], check=True)
    result = subprocess.run([str(binary)], capture_output=True, timeout=10)
    assert result.returncode != 0, "original serialized LFH size read escaped the regression"
print("PASS LFH size source overlay and serialization mutation control")
