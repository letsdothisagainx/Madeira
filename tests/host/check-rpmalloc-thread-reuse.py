#!/usr/bin/env python3
"""Run unchanged, pinned rpmalloc ownership code under ASan and UBSan.

This is a native POSIX lifecycle test: its spans are 256 MiB. The iOS Windows
16 MiB span geometry and arena placement are covered separately by
check-fex-arena-placement.py. No production allocator source is rewritten or
extracted, and no assertion here claims to execute Windows TLS or PE callbacks.

Requires the FEX and FEX/External/rpmalloc submodules, Python 3 and a C compiler.
"""
from pathlib import Path
import hashlib
import os
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
ALLOCATOR = ROOT / 'FEX/External/rpmalloc'
PIN = '812c2b9cf4310ffacf14e6b64066e78ab0c394b5'
SOURCE_HASHES = {
    'rpmalloc.c': 'd810c3695daab1c74e92ba971f1f068b44b3d6172e0a69c5a0c6f8a07234f96b',
    'rpmalloc.h': '81c4970f89951c177cd83f29ec7c1989e14c31f3bb5e2eda4a2b84e1dd338fb6',
    'malloc.c': '9e25e61023743121f62c5480a5bc78c9eeee2fedcd3c17ef8880ce875705e317',
}


def git(directory, *arguments):
    return subprocess.check_output(['git', '-C', str(directory), *arguments], text=True).strip()


entry = git(ROOT / 'FEX', 'ls-tree', 'HEAD', 'External/rpmalloc').split()
assert entry[:3] == ['160000', 'commit', PIN], 'FEX rpmalloc pin changed; review this lifecycle regression'
assert (ALLOCATOR / 'rpmalloc/rpmalloc.c').is_file(), (
    'Initialize the pinned submodule: git -C FEX submodule update --init External/rpmalloc'
)
assert git(ALLOCATOR, 'rev-parse', 'HEAD') == PIN, 'rpmalloc checkout differs from the FEX gitlink'
for name, expected in SOURCE_HASHES.items():
    path = ALLOCATOR / 'rpmalloc' / name
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, f'Unreviewed rpmalloc source: {path}'


HARNESS = r'''
#define _GNU_SOURCE
#include <stddef.h>
#include <unistd.h>

/* These two Windows diagnostics are present even in the pinned POSIX source.
 * Supply only their output ABI; allocator, heap, TLS and mapping code below
 * are compiled unchanged from the production translation unit. */
static void* GetStdHandle(unsigned long value) { (void)value; return (void*)2; }
static int WriteFile(void* handle, const void* bytes, unsigned long size,
                     unsigned long* written, void* overlapped) {
    (void)handle; (void)overlapped;
    ssize_t result = write(2, bytes, size);
    *written = result < 0 ? 0 : (unsigned long)result;
    return result >= 0;
}
#include "rpmalloc/rpmalloc.c"
#include <assert.h>

volatile int FEX_AllocWatch_Armed;
void FEX_AllocWatch_Event(const void* pointer, unsigned event) { (void)pointer; (void)event; }

_Static_assert(PLATFORM_POSIX && !PLATFORM_WINDOWS, "This test executes the native POSIX branch");
_Static_assert(SPAN_SIZE == (256 * 1024 * 1024), "Do not confuse native spans with iOS 16 MiB spans");

static unsigned maps, unmaps, live_blocks, outstanding_workers, allow_unmap;
static heap_t* original;
static unsigned char* shared;

static void* counted_map(size_t size, size_t alignment, size_t* offset, size_t* mapped_size) {
    void* pointer = os_mmap(size, alignment, offset, mapped_size);
    if (pointer) ++maps;
    return pointer;
}

static void counted_unmap(void* pointer, size_t offset, size_t mapped_size) {
    /* A thread exit or a live payload must never release an entire heap. */
    assert(allow_unmap && !outstanding_workers && !live_blocks && !shared);
    assert(!global_heap_used);
    ++unmaps;
    os_munmap(pointer, offset, mapped_size);
}

static void* allocate(size_t size) {
    void* pointer = rpmalloc(size);
    assert(pointer);
    ++live_blocks;
    return pointer;
}

static void release(void* pointer) {
    assert(pointer && live_blocks);
    rpfree(pointer);
    --live_blocks;
}

static void check_payload(void) {
    assert(shared);
    for (unsigned i = 0; i < 64; ++i) assert(shared[i] == 0x6b);
}

static void* origin(void* unused) {
    (void)unused;
    rpmalloc_thread_initialize();
    original = get_thread_heap();
    shared = allocate(64);
    void* medium = allocate(20000);
    void* large = allocate(1 << 20);
    memset(shared, 0x6b, 64);
    release(medium);
    release(large);
    for (unsigned type = 0; type < 3; ++type)
        assert(original->span_partial[type] || original->span_used[type]);
    unsigned before = unmaps;
    rpmalloc_thread_finalize();
    assert(unmaps == before && !rpmalloc_is_thread_initialized());
    assert(global_heap_queue == original);
    check_payload();
    return NULL;
}

static void* successor(void* unused) {
    (void)unused;
    unsigned before = maps;
    rpmalloc_thread_initialize();
    assert(get_thread_heap() == original && original->owner_thread == get_thread_id());
    assert(global_heap_queue != original);
    void* small = allocate(64);
    void* medium = allocate(20000);
    void* large = allocate(1 << 20);
    assert(maps == before);
    memset(small, 0x3c, 64);
    if (shared) check_payload();
    release(small);
    release(medium);
    release(large);
    rpmalloc_thread_finalize();
    assert(global_heap_queue == original && !rpmalloc_is_thread_initialized());
    return NULL;
}

static void joined_worker(void* (*entry)(void*)) {
    pthread_t worker;
    assert(!outstanding_workers);
    outstanding_workers = 1;
    assert(!pthread_create(&worker, NULL, entry, NULL));
    assert(!pthread_join(worker, NULL));
    outstanding_workers = 0;
}

int main(void) {
    rpmalloc_interface_t interface = {
        .memory_map = counted_map,
        .memory_commit = os_mcommit,
        .memory_decommit = os_mdecommit,
        .memory_unmap = counted_unmap,
    };
    /* Enable the allocator's explicit process finalizer for the last step only.
     * Production uses unmap_on_finalize=0 and a separate owner/lease VM reaper;
     * this fixture does not claim to execute that native process reaper. */
    rpmalloc_config_t config = {.page_size = 4096, .unmap_on_finalize = 1};
    assert(!rpmalloc_initialize_config(&interface, &config));
    heap_t* main_heap = get_thread_heap();
    unsigned baseline = maps;
    joined_worker(origin);
    assert(maps == baseline + 4 && !unmaps && live_blocks == 1);
    check_payload();

    /* The payload remains live after its original thread exits and while the
     * original heap is adopted by 100 other native pthread lifetimes. */
    for (unsigned i = 0; i < 100; ++i) {
        joined_worker(successor);
        assert(maps == baseline + 4 && !unmaps && live_blocks == 1);
        check_payload();
    }

    assert(get_thread_heap() == main_heap && main_heap != original);
    assert(!page_is_thread_heap(span_get_page_from_block(block_get_span((block_t*)shared), shared)));
    release(shared); /* A remote free into a queued heap must survive adoption. */
    shared = NULL;
    joined_worker(successor);
    assert(maps == baseline + 4 && !unmaps && !live_blocks);
    rpmalloc_thread_collect();
    assert(!unmaps); /* The pinned collect function does not release span VA. */

    /* Every worker has joined, every payload was freed, and both heap owners
     * relinquished their heaps before the first explicit process-wide unmap. */
    assert(global_heap_used == main_heap && !main_heap->next);
    rpmalloc_thread_finalize();
    assert(!global_heap_used && !rpmalloc_is_thread_initialized());
    assert(!unmaps && !outstanding_workers && !live_blocks && !shared);
    allow_unmap = 1;
    rpmalloc_finalize();
    assert(unmaps == maps && !global_heap_queue && !global_heap_used);
    puts("PASS unchanged pinned rpmalloc (native POSIX 256MiB spans): origin exits with shared payload alive; 100 successors reuse its heap with zero new maps; queued remote free drains; final unmap waits for all workers/payloads/heaps to quiesce");
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-rpmalloc-reuse-') as directory:
    path = Path(directory)
    source = path / 'reuse.c'
    executable = path / 'reuse'
    source.write_text(HARNESS)
    command = shlex.split(os.environ.get('CC', 'cc')) + [
        '-std=c11', '-O1', '-g', '-pthread', '-fno-omit-frame-pointer',
        '-DENABLE_OVERRIDE=0', '-DENABLE_DYNAMIC_LINK=0', '-DENABLE_DECOMMIT=1',
        '-DENABLE_ASSERTS=1', '-DENABLE_STATISTICS=0',
        '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
        '-I' + str(ALLOCATOR), str(source), '-o', str(executable),
    ]
    subprocess.run(command, check=True)
    subprocess.run([str(executable)], check=True)

print(f'PASS rpmalloc source pin {PIN}; all three compiled source hashes match')
