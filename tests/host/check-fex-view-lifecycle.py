#!/usr/bin/env python3
"""Execute native FEX-view ownership and pre-CRT arena handoff policies.

The harness extracts production C helpers. Synthetic Wine VAD/native mappings
let it verify process quiescence and generation reuse without a device, a Wine
prefix, or changes to installed games.
"""
import os
from pathlib import Path
import re
import subprocess
import struct
import tempfile

root = Path(__file__).resolve().parents[2]
virtual = (root / 'build/ntdll-unix/virtual_ios.c').read_text()
thread = (root / 'build/ntdll-unix/thread_ios.c').read_text()
loader = (root / 'build/ntdll-unix/loader_ios.c').read_text()
server = (root / 'build/ntdll-unix/server_ios.c').read_text()


def body(source, marker):
    start = source.index(marker)
    opening = source.index('{', start)
    depth = 0
    tokens = r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]'
    for token in re.finditer(tokens, source[opening:], re.S):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if not depth:
                return source[start:opening + token.end()]
    raise AssertionError('Unclosed production helper: ' + marker)


def run(label, code):
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary) / 'lifecycle.c'
        executable = Path(temporary) / 'lifecycle'
        source.write_text(code)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-g', '-O1',
                        '-Wall', '-Wextra', '-Werror=implicit-function-declaration',
                        '-Wno-unused-function', '-fsanitize=address,undefined',
                        '-fno-sanitize-recover=undefined', '-pthread',
                        '-I'+str(root/'build/ntdll-unix'), str(source), '-o', str(executable)], check=True)
        result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30,
                                env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
        if result.returncode:
            print(result.stdout + result.stderr)
            raise AssertionError(f'{label}: exit {result.returncode}')
    print('PASS: ' + label)
    return result


common = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define ERR(...) ((void)0)
typedef uintptr_t ULONG_PTR;
typedef uint64_t ULONG64;
typedef unsigned int ULONG;
typedef unsigned int UINT;
typedef uint32_t DWORD;
typedef int BOOL;
typedef uint32_t NTSTATUS;
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER 0xc000000d
#define STATUS_NO_MEMORY 0xc0000017
'''

common += '#include \"native_thread_lifetime.h\"\n#include \"fex_hold_release_abi.h\"\n'

lease_code = common + body(thread, 'struct ios_thread_group\n{') + ';\n' + r'''
static struct ios_thread_group ios_thread_groups[64];
static unsigned long long ios_thread_next_lease;
static pthread_mutex_t ios_thread_group_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ios_thread_reapers[64];
static pthread_once_t ios_thread_reapers_once = PTHREAD_ONCE_INIT;
static _Thread_local void *ios_retired_thread_owner;
struct fake_teb { void *Peb; struct {void *UniqueProcess,*UniqueThread;} ClientId; };
typedef struct fake_teb TEB;
static _Thread_local struct fake_teb current;
static struct fake_teb *NtCurrentTeb(void) { return &current; }
static void ios_thread_finish_fex(void) {}
static void ios_native_link_current_locked(struct ios_thread_group *g){(void)g;}
static _Thread_local struct madeira_native_thread ios_native_current;
static _Thread_local int ios_native_finishing;
'''
for marker in ('static void ios_thread_reapers_init(void)',
               'static struct ios_thread_group *ios_thread_group_locked(void *owner)',
               'unsigned long long ios_thread_process_lease(void *owner, int create)',
               'unsigned long long ios_thread_process_quiescent_lease(void *owner)',
               'unsigned long long ios_thread_process_snapshot(void *owner, unsigned *threads, int *exiting, int *reclaimed)',
               'static int ios_thread_count_add(void *owner, int delta)',
               'static unsigned ios_thread_retire_current(void)',
               'int ios_thread_process_exit_ready(void *owner)',
               'int ios_thread_process_forget(void *owner)'):
    lease_code += body(thread, marker) + '\n'
lease_code += r'''
int main(void) {
    void *a = (void *)(uintptr_t)0x500310000, *b = (void *)(uintptr_t)0x600310000;
    void *unknown = (void *)(uintptr_t)0x700310000;
    unsigned threads = 99;
    int exiting = 99, reclaimed = 99;
    assert(!ios_thread_process_snapshot(NULL, &threads, &exiting, &reclaimed));
    assert(!threads && !exiting && !reclaimed);
    threads = 99; exiting = reclaimed = 99;
    assert(!ios_thread_process_snapshot(unknown, &threads, &exiting, &reclaimed));
    assert(!threads && !exiting && !reclaimed);
    assert(!ios_thread_process_lease(NULL, 0));
    assert(!ios_thread_process_lease(NULL, 1));
    assert(!ios_thread_process_lease(unknown, 0));
    assert(!ios_thread_process_quiescent_lease(unknown));
    for (unsigned i = 0; i < ARRAY_SIZE(ios_thread_groups); ++i) assert(!ios_thread_groups[i].owner);
    unsigned long long first = ios_thread_process_lease(a, 1);
    unsigned long long sibling = ios_thread_process_lease(b, 1);
    assert(first && sibling && first != sibling);
    assert(ios_thread_process_snapshot(a, &threads, &exiting, &reclaimed) == first);
    assert(threads == 1 && !exiting && !reclaimed);
    assert(ios_thread_process_lease(a, 0) == first);
    assert(!ios_thread_process_quiescent_lease(a));
    assert(ios_thread_count_add(a, 1) == 2);
    assert(ios_thread_process_snapshot(a, &threads, &exiting, &reclaimed) == first);
    assert(threads == 2 && !exiting && !reclaimed);
    current.Peb = a;
    assert(!ios_thread_process_exit_ready(a));
    assert(ios_thread_process_snapshot(a, &threads, &exiting, &reclaimed) == first);
    assert(threads == 1 && exiting && !reclaimed);
    assert(!ios_thread_process_quiescent_lease(a)); /* another native Wine thread alive */
    assert(!ios_thread_process_lease(a, 1)); /* don't mint a new lease during shutdown */
    ios_retired_thread_owner = NULL; /* the owner's second native pthread */
    assert(ios_thread_process_exit_ready(a));
    assert(ios_thread_process_quiescent_lease(a) == first);
    assert(ios_thread_process_snapshot(a, &threads, &exiting, &reclaimed) == first);
    assert(!threads && exiting && reclaimed);
    assert(ios_thread_process_lease(b, 0) == sibling && !ios_thread_process_quiescent_lease(b));
    assert(!ios_thread_process_exit_ready(a)); /* idempotent completion; no count underflow */
    assert(ios_thread_process_quiescent_lease(a) == first);
    assert(ios_thread_process_forget(a));
    assert(!ios_thread_process_lease(a, 0) && !ios_thread_process_quiescent_lease(a));
    assert(!ios_thread_process_snapshot(a, &threads, &exiting, &reclaimed));
    assert(!threads && !exiting && !reclaimed);
    unsigned long long reused = ios_thread_process_lease(a, 1);
    assert(reused && reused != first); /* same PEB address, different process lifetime */
    assert(ios_thread_process_snapshot(a, &threads, &exiting, &reclaimed) == reused);
    assert(threads == 1 && !exiting && !reclaimed); /* current generation, never stale shutdown state */
    assert(!ios_thread_process_quiescent_lease(a));
    assert(ios_thread_process_lease(b, 0) == sibling);
    for (unsigned i = 0; i < ARRAY_SIZE(ios_thread_groups); ++i) {
        void *owner = (void *)(uintptr_t)(0x1000000000ull + 0x10000ull * i);
        (void)ios_thread_process_lease(owner, 1);
    }
    assert(!ios_thread_process_lease(unknown, 1)); /* full ownership registry fails closed */
    assert(!ios_thread_process_quiescent_lease(unknown));
    threads = 99; exiting = reclaimed = 99;
    assert(!ios_thread_process_snapshot(unknown, &threads, &exiting, &reclaimed));
    assert(!threads && !exiting && !reclaimed);
    /* Zero count without a completed exiting/reclaimed lifecycle isn't proof. */
    ios_thread_groups[0].count = 0;
    ios_thread_groups[0].exiting = 0;
    ios_thread_groups[0].reclaimed = 1;
    assert(!ios_thread_process_quiescent_lease(a));
    ios_thread_groups[0].exiting = 1;
    ios_thread_groups[0].reclaimed = 0;
    assert(!ios_thread_process_quiescent_lease(a));
    assert(!pthread_mutex_trylock(&ios_thread_group_mutex));
    pthread_mutex_unlock(&ios_thread_group_mutex);
    return 0;
}
'''
run('FEX process leases require completed native-thread quiescence, preserve siblings and reject stale PEB generations', lease_code)

callback_code = common + body(thread, 'struct ios_thread_group\n{') + ';\n' + r'''
static struct ios_thread_group ios_thread_groups[64];
static unsigned long long ios_thread_next_lease;
static pthread_mutex_t ios_thread_group_mutex = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local void *ios_retired_thread_owner;
struct fake_teb {
    void *Peb;
    struct { void *UniqueProcess, *UniqueThread; } ClientId;
    unsigned char remaining[0x1800];
};
typedef struct fake_teb TEB;
static void ios_native_link_current_locked(struct ios_thread_group *g){(void)g;}
static _Thread_local struct madeira_native_thread ios_native_current;
static _Thread_local int ios_native_finishing;
static _Thread_local struct fake_teb current;
static struct fake_teb *NtCurrentTeb(void) { return &current; }
static void *const a = (void *)(uintptr_t)0x500310000;
static void *const b = (void *)(uintptr_t)0x600310000;
static pthread_mutex_t callback_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t callback_cond = PTHREAD_COND_INITIALIZER;
static int callback_entered, callback_can_return, callback_calls;
static void ios_thread_finish_fex(void);
typedef unsigned int (*hold_callback)(void *, unsigned long long *, unsigned int *, unsigned int *);
static unsigned int finish_callback(void *teb, unsigned long long *stamp, unsigned int *depth, unsigned int *flags) {
    assert(teb == NtCurrentTeb() && NtCurrentTeb()->Peb == a);
    assert(!pthread_mutex_trylock(&ios_thread_group_mutex)); /* callback executes outside registry lock */
    pthread_mutex_unlock(&ios_thread_group_mutex);
    ios_thread_finish_fex(); /* recursive fault/abort must not reenter CPU callback */
    pthread_mutex_lock(&callback_mutex);
    ++callback_calls;
    callback_entered = 1;
    pthread_cond_broadcast(&callback_cond);
    while (!callback_can_return) pthread_cond_wait(&callback_cond, &callback_mutex);
    pthread_mutex_unlock(&callback_mutex);
    *stamp = 0; *depth = 0; *flags = 0;
    return 1;
}
hold_callback ios_hold_release_lookup(void *owner) { return owner == a ? finish_callback : NULL; }
hold_callback ios_wow_thread_retire_lookup(void *owner,unsigned long long lease){(void)owner;(void)lease;return NULL;}
/* This fixture isolates owner quiescence. The separate native-callback test
 * executes the production stack/frame transition. */
unsigned int ios_call_fex_callback(hold_callback cb,void *teb,unsigned long long *stamp,
                                   unsigned int *depth,unsigned int *flags) {
    return cb(teb,stamp,depth,flags);
}
'''
for marker in ('static struct ios_thread_group *ios_thread_group_locked(void *owner)',
               'unsigned long long ios_thread_process_lease(void *owner, int create)',
               'unsigned long long ios_thread_process_quiescent_lease(void *owner)',
               'unsigned long long ios_thread_process_snapshot(void *owner, unsigned *threads, int *exiting, int *reclaimed)',
               'static int ios_thread_count_add(void *owner, int delta)',
               'static void ios_thread_finish_fex(void)\n{',
               'static unsigned ios_thread_retire_current(void)',
               'int ios_thread_process_exit_ready(void *owner)'):
    callback_code += body(thread, marker) + '\n'
callback_code += r'''
static void *held_worker(void *unused) {
    (void)unused; current.Peb = a; current.ClientId.UniqueThread = (void *)(uintptr_t)0x24;
    *(unsigned long long *)((char *)&current + 0x16f8) = 0x1234;
    assert(ios_thread_process_exit_ready(a));
    return NULL;
}
static void *plain_worker(void *unused) {
    (void)unused; current.Peb = a; current.ClientId.UniqueThread = (void *)(uintptr_t)0x28;
    assert(!ios_thread_process_exit_ready(a));
    return NULL;
}
int main(void) {
    unsigned long long lease = ios_thread_process_lease(a, 1);
    unsigned long long sibling = ios_thread_process_lease(b, 1);
    assert(lease && sibling && ios_thread_count_add(a, 1) == 2);
    pthread_t held, plain;
    assert(!pthread_create(&held, NULL, held_worker, NULL));
    pthread_mutex_lock(&callback_mutex);
    while (!callback_entered) pthread_cond_wait(&callback_cond, &callback_mutex);
    pthread_mutex_unlock(&callback_mutex);
    assert(!pthread_create(&plain, NULL, plain_worker, NULL));
    assert(!pthread_join(plain, NULL));
    assert(!ios_thread_process_quiescent_lease(a)); /* held CPU callback still contributes a native thread */
    unsigned native_threads = 99;
    int exiting = 99, reclaimed = 99;
    assert(ios_thread_process_snapshot(a, &native_threads, &exiting, &reclaimed) == lease);
    assert(native_threads == 1 && exiting && !reclaimed);
    assert(ios_thread_process_lease(b, 0) == sibling && !ios_thread_process_quiescent_lease(b));
    assert(ios_thread_process_snapshot(b, &native_threads, &exiting, &reclaimed) == sibling);
    assert(native_threads == 1 && !exiting && !reclaimed);
    pthread_mutex_lock(&callback_mutex);
    callback_can_return = 1;
    pthread_cond_broadcast(&callback_cond);
    pthread_mutex_unlock(&callback_mutex);
    assert(!pthread_join(held, NULL));
    assert(ios_thread_process_quiescent_lease(a) == lease);
    assert(ios_thread_process_snapshot(a, &native_threads, &exiting, &reclaimed) == lease);
    assert(!native_threads && exiting && reclaimed);
    assert(callback_calls == 1);
    return 0;
}
'''
run('CPU exit callbacks finish before native-thread retirement; a paused callback blocks process reclamation without blocking siblings', callback_code)
exit_tail = body(thread, 'static DECLSPEC_NORETURN void pthread_exit_wrapper( int status )')
assert 'ios_hold_release_lookup' not in exit_tail
assert 'ios_thread_finish_fex' not in exit_tail
retire = body(thread, 'static unsigned ios_thread_retire_current(void)')
assert retire.index('ios_thread_finish_fex()') < retire.index('pthread_mutex_lock(&ios_thread_group_mutex)')

# Reuse the real lease implementation for the VAD tests; only VM operations
# and the tree's backing mappings are synthetic. Wine's own RB tree executes.
vad_code = lease_code[:lease_code.index('int main(void) {')]
vad_code += f'#include "{root / "wine/include/wine/rbtree.h"}"\n'
vad_code += r'''
/* Keep Wine's null iteration sentinel portable under Clang's UBSan while
 * executing its unchanged RB tree and production ownership/reaping code. */
#undef RB_ENTRY_VALUE
#define RB_ENTRY_VALUE(element,type,field) ((type *)((uintptr_t)(element) - offsetof(type,field)))
'''
vad_code += body(virtual, 'struct file_view\n{') + ';\n'
for macro in ('IOS_VIEW_QUARANTINED', 'VPROT_READ', 'VPROT_WRITE', 'VPROT_EXEC',
              'VPROT_WRITEWATCH', 'VPROT_COMMITTED', 'VPROT_ARM64EC', 'VPROT_SYSTEM', 'VPROT_PLACEHOLDER', 'VPROT_FREE_PLACEHOLDER'):
    vad_code += re.search(r'^#define ' + macro + r'\s+[^\n]+', virtual, re.M).group() + '\n'
nt = (root / 'wine/include/winnt.h').read_text()
for macro in ('SEC_FILE', 'SEC_IMAGE', 'SEC_RESERVE', 'SEC_COMMIT'):
    vad_code += re.search(r'^#define ' + macro + r'\s+[^\n]+', nt, re.M).group() + '\n'
vad_code += r'''
typedef uintptr_t UINT_PTR;
typedef unsigned char BYTE;
#define TRACE(...) ((void)0)
#define FIXME(...) ((void)0)
#define VIRTUAL_DEBUG_DUMP_VIEW(...) ((void)0)
static pthread_mutex_t virtual_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct wine_rb_tree views_tree;
static _Thread_local void *current_peb;
static ULONG_PTR ios_fex_arena_base_unix = 0xb40000000ull;
static ULONG_PTR ios_fex_arena_end_unix = 0xd40000000ull;
static ULONG_PTR guest_window = 0x500000000ull;
static void *ios_jit_current_peb(void) { return current_peb; }
static ULONG_PTR ios_wow_base(void) { return guest_window; }
static struct file_view storage[256];
static int allocated[256], deleted[256], unmapped[256], restored[256];
static unsigned deleted_total;
static int lock_reuse, use_kernel_writewatch, ios_retire_trace_armed;
static unsigned host_page_mask = 0x3fff, page_mask = 0xfff;
static struct file_view *alloc_view(void) {
    for (unsigned i = 0; i < ARRAY_SIZE(storage); ++i)
        if (!allocated[i]) { allocated[i] = 1; return &storage[i]; }
    return NULL;
}
static void free_view(struct file_view *view) {
    size_t i = view - storage; assert(i < ARRAY_SIZE(storage));
    allocated[i] = 0; deleted[i] = 1; ++deleted_total;
}
static int mmap_is_in_reserved_area(const void *base, size_t size) {
    ULONG_PTR p = (ULONG_PTR)base;
    return p >= ios_fex_arena_base_unix && p < ios_fex_arena_end_unix && size <= ios_fex_arena_end_unix - p;
}
static void free_ranges_insert_view(struct file_view *view) { (void)view; }
static void free_ranges_remove_view(struct file_view *view) { (void)view; }
static void unmap_area(void *base, size_t size) {
    for (unsigned i = 0; i < ARRAY_SIZE(storage); ++i)
        if (allocated[i] && storage[i].base == base && storage[i].size == size) {
            if (mmap_is_in_reserved_area(base, size)) restored[i] = 1;
            else unmapped[i] = 1;
            return;
        }
    assert(!"delete_view tried to unmap an unknown mapping");
}
static int alloc_pages_vprot(void *base, size_t size) { (void)base; (void)size; return 1; }
static void set_page_vprot(void *base, size_t size, BYTE prot) { (void)base; (void)size; (void)prot; }
static void kernel_writewatch_register_range(struct file_view *v, void *base, size_t size) { (void)v; (void)base; (void)size; }
static void ios_af_set(int n, int error, void *base, size_t size) { (void)n; (void)error; (void)base; (void)size; }
static void ios_vh_note(char c, const struct file_view *view) { (void)c; (void)view; }
static void ios_retire_mark(const char *s) { (void)s; }
static int ios_jit_image_retire_enabled(void) { return 0; }
static void ios_jit_retire_image(void *base, size_t size) { (void)base; (void)size; }
static void ios_jit_note_image_unmapped(void *base, size_t size) { (void)base; (void)size; }
static void ios_swap_release_range(void *base, size_t size, int arg) { (void)base; (void)size; (void)arg; }
/* This allocator fixture has no image/JIT aliases; their actual retirement
 * and physical rebinding are exercised by check-image-alias-lifetime.py. */
#define ROUND_SIZE(b,s,m) (((size_t)(s)+((uintptr_t)(b)&(m))+(m))&~(size_t)(m))
static int ios_jit_anon_alias_overlaps(void *base,size_t size,uintptr_t *lo,uintptr_t *hi)
{ (void)base;(void)size;(void)lo;(void)hi;return 0; }
static void ios_jit_anon_alias_retire_range(void *base,size_t size) { (void)base;(void)size; }
static void clear_arm64ec_range(void *base, size_t size) { (void)base; (void)size; }
'''
for marker in ('static int compare_view( const void *addr, const struct wine_rb_entry *entry )',
               'static inline int is_view_valloc( const struct file_view *view )',
               'static struct file_view *find_view( const void *addr, size_t size )\n{',
               'static struct file_view *find_view_range( const void *addr, size_t size )\n{',
               'static void unregister_view( struct file_view *view )',
               'static void register_view( struct file_view *view )',
               'static void delete_view( struct file_view *view )',
               'static NTSTATUS create_view( struct file_view **view_ret, void *base, size_t size, unsigned int vprot )',
               'static NTSTATUS remove_pages_from_view( struct file_view *view, char *base, size_t size )'):
    vad_code += body(virtual, marker) + '\n'
vad_code += r'''
#include <signal.h>
#include <strings.h>
typedef uint16_t WORD;
typedef struct { DWORD VirtualAddress, Size; } IMAGE_DATA_DIRECTORY;
typedef struct {
    struct { WORD Machine, NumberOfSections; } FileHeader;
    struct { WORD Magic; DWORD NumberOfRvaAndSizes; IMAGE_DATA_DIRECTORY DataDirectory[16]; } OptionalHeader;
} IMAGE_NT_HEADERS64;
typedef struct {
    union { DWORD PhysicalAddress, VirtualSize; } Misc;
    DWORD VirtualAddress, SizeOfRawData, Characteristics;
} IMAGE_SECTION_HEADER;
typedef struct {
    DWORD Characteristics, TimeDateStamp;
    WORD MajorVersion, MinorVersion;
    DWORD Name, Base, NumberOfFunctions, NumberOfNames;
    DWORD AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;
_Static_assert(sizeof(IMAGE_EXPORT_DIRECTORY) == 40, "PE export directory ABI");
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
#define IMAGE_FILE_MACHINE_ARM64EC 0xa641
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_SCN_MEM_WRITE 0x80000000u
#define IMAGE_SCN_MEM_READ 0x40000000u
#define IMAGE_SCN_MEM_SHARED 0x10000000u
#define IMAGE_SCN_MEM_EXECUTE 0x20000000u
#define STATUS_INVALID_IMAGE_FORMAT 0xc000007b
#define STATUS_CONFLICTING_ADDRESSES 0xc0000018
static const char *module_name = "libwow64fex.dll";
static const char *ios_pe_module_name(const void *base, size_t size) { (void)base; (void)size; return module_name; }
static void *race_owner;
static unsigned page_size = 0x1000;
static unsigned drops;
static void ios_hold_release_drop(void *owner) { assert(owner); ++drops; }
static void server_enter_uninterrupted_section(pthread_mutex_t *lock, sigset_t *sigset) {
    (void)sigset; assert(lock == &virtual_mutex);
    if (lock_reuse) {
        lock_reuse = 0;
        assert(ios_thread_process_forget(race_owner));
        assert(ios_thread_process_lease(race_owner, 1));
    }
    assert(!pthread_mutex_lock(lock));
}
static void server_leave_uninterrupted_section(pthread_mutex_t *lock, sigset_t *sigset) {
    (void)sigset; assert(lock == &virtual_mutex); assert(!pthread_mutex_unlock(lock));
}
static BYTE get_page_vprot(const void *base) {
    struct file_view *view = find_view(base, 1);
    return view ? view->protect & 0xff : 0;
}
'''
vad_code += body(virtual, 'static int fex_arena_covers( const void *limit_low, const void *limit_high )') + '\n'
vad_code += f'#include "{root / "build/ntdll-unix/fex_view_ownership.h"}"\n'
vad_code += r'''
struct image_fixture {
    _Alignas(16) char bytes[0x10000];
    IMAGE_NT_HEADERS64 nt;
    IMAGE_SECTION_HEADER section[2];
};
static void init_image(struct image_fixture *image) {
    memset(image, 0, sizeof(*image));
    image->nt.FileHeader.Machine = IMAGE_FILE_MACHINE_ARM64;
    image->nt.FileHeader.NumberOfSections = 1;
    image->nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    image->nt.OptionalHeader.NumberOfRvaAndSizes = 16;
    image->nt.OptionalHeader.DataDirectory[0] = (IMAGE_DATA_DIRECTORY){ 0x1000, 0x300 };
    IMAGE_EXPORT_DIRECTORY *dir = (void *)(image->bytes + 0x1000);
    dir->NumberOfNames = dir->NumberOfFunctions = 2;
    dir->AddressOfNames = 0x1100; dir->AddressOfNameOrdinals = 0x1140; dir->AddressOfFunctions = 0x1180;
    DWORD *names = (void *)(image->bytes + 0x1100), *functions = (void *)(image->bytes + 0x1180);
    WORD *ordinals = (void *)(image->bytes + 0x1140);
    names[0] = 0x1200; names[1] = 0x1220; ordinals[0] = 0; ordinals[1] = 1;
    functions[0] = 0x4000; functions[1] = 0x4008;
    strcpy(image->bytes + 0x1200, "ios_fex_band_base"); strcpy(image->bytes + 0x1220, "ios_fex_band_end");
    image->section[0].VirtualAddress = 0x4000; image->section[0].Misc.VirtualSize = 0x1000;
    image->section[0].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
}
static NTSTATUS prepare(struct image_fixture *image) {
    return ios_fex_prepare_image(image->bytes, sizeof(image->bytes), &image->nt, image->section, 0);
}
static ULONG_PTR *first(struct image_fixture *image) { return (void *)(image->bytes + 0x4000); }
static ULONG_PTR *last(struct image_fixture *image) { return (void *)(image->bytes + 0x4008); }
static struct file_view *add_view(ULONG_PTR base, size_t size, unsigned protect) {
    struct file_view *view = NULL;
    assert(create_view(&view, (void *)base, size, protect) == STATUS_SUCCESS);
    return view;
}
static void finish(void *owner) {
    current.Peb = owner; ios_retired_thread_owner = NULL;
    assert(ios_thread_process_exit_ready(owner));
}
static int live(const struct file_view *view) { return allocated[view - storage]; }
static unsigned owned(void *owner) {
    unsigned n = 0;
    for (unsigned i = 0; i < ARRAY_SIZE(storage); ++i)
        if (allocated[i] && storage[i].ios_fex_owner == owner) ++n;
    return n;
}
static int sibling_stop, sibling_started;
static unsigned sibling_allocations;
static pthread_mutex_t sibling_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sibling_cond = PTHREAD_COND_INITIALIZER;
static void *surviving_allocator(void *owner) {
    current_peb = owner; current.Peb = owner;
    do {
        assert(!pthread_mutex_lock(&virtual_mutex));
        struct file_view *temporary = add_view(0xc20000000ull, 0x10000, VPROT_READ | VPROT_WRITE);
        ios_fex_tag_view(temporary, ios_fex_arena_base_unix, ios_fex_arena_end_unix - 1);
        assert(temporary->ios_fex_owner == owner);
        delete_view(temporary); /* normal MEM_RELEASE must remain usable concurrently */
        ++sibling_allocations;
        assert(!pthread_mutex_unlock(&virtual_mutex));
        pthread_mutex_lock(&sibling_mutex);
        sibling_started = 1; pthread_cond_broadcast(&sibling_cond);
        pthread_mutex_unlock(&sibling_mutex);
    } while (!__atomic_load_n(&sibling_stop, __ATOMIC_ACQUIRE));
    assert(ios_thread_retire_current() == 1); /* surviving process still owns its initial thread */
    return NULL;
}
int main(void) {
    void *a = (void *)(uintptr_t)0x500310000, *b = (void *)(uintptr_t)0x600310000;
    void *unknown = (void *)(uintptr_t)0x700310000;
    struct image_fixture image, sibling, bad;
    wine_rb_init(&views_tree, compare_view);
    init_image(&image); init_image(&sibling);
    current_peb = a;
    assert(prepare(&image) == STATUS_SUCCESS);
    unsigned long long lease = ios_thread_process_lease(a, 0);
    assert(lease && *first(&image) == ios_fex_arena_base_unix && *last(&image) == ios_fex_arena_end_unix - 1);
    assert(ios_fex_owners[0].owner == a && ios_fex_owners[0].image == image.bytes && ios_fex_owners[0].lease == lease);
    assert(prepare(&image) == STATUS_SUCCESS); /* same already-published band is idempotent */

    /* Exact bounded private DATA exports only; no guessed PE addresses. */
    const DWORD forbidden[] = { 0, IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
                                IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_SHARED };
    for (unsigned i = 0; i < ARRAY_SIZE(forbidden); ++i) {
        init_image(&bad); bad.section[0].Characteristics = forbidden[i];
        assert(!ios_fex_private_export(bad.bytes, sizeof(bad.bytes), &bad.nt, bad.section, "ios_fex_band_base"));
        assert(!*first(&bad) && !*last(&bad));
    }
    init_image(&bad); ((DWORD *)(bad.bytes + 0x1180))[0] = 0x4001;
    assert(!ios_fex_private_export(bad.bytes, sizeof(bad.bytes), &bad.nt, bad.section, "ios_fex_band_base"));
    init_image(&bad); ((DWORD *)(bad.bytes + 0x1180))[0] = 0x1200; /* PE forwarder */
    assert(!ios_fex_private_export(bad.bytes, sizeof(bad.bytes), &bad.nt, bad.section, "ios_fex_band_base"));
    init_image(&bad); ((WORD *)(bad.bytes + 0x1140))[0] = 2;
    assert(!ios_fex_private_export(bad.bytes, sizeof(bad.bytes), &bad.nt, bad.section, "ios_fex_band_base"));
    init_image(&bad); ((IMAGE_EXPORT_DIRECTORY *)(bad.bytes + 0x1000))->AddressOfNames = sizeof(bad.bytes) - 1;
    assert(!ios_fex_private_export(bad.bytes, sizeof(bad.bytes), &bad.nt, bad.section, "ios_fex_band_base"));
    init_image(&bad); ((DWORD *)(bad.bytes + 0x1100))[0] = sizeof(bad.bytes) - 1; bad.bytes[sizeof(bad.bytes) - 1] = 'x';
    assert(!ios_fex_private_export(bad.bytes, sizeof(bad.bytes), &bad.nt, bad.section, "ios_fex_band_base"));
    init_image(&bad); bad.nt.FileHeader.Machine = 0x14c;
    assert(prepare(&bad) == STATUS_INVALID_IMAGE_FORMAT && !*first(&bad));
    init_image(&bad); module_name = "libarm64ecfex.dll"; bad.nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    assert(prepare(&bad) == STATUS_INVALID_IMAGE_FORMAT && !*first(&bad));
    assert(ios_fex_prepare_image(bad.bytes, sizeof(bad.bytes), &bad.nt, bad.section, 1) == STATUS_SUCCESS);
    assert(*first(&bad) == ios_fex_arena_base_unix);
    module_name = "libwow64fex.dll";
    init_image(&bad); bad.nt.FileHeader.NumberOfSections = 2;
    bad.section[1].Characteristics = IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_WRITE;
    assert(prepare(&bad) == STATUS_INVALID_IMAGE_FORMAT && !*first(&bad));
    init_image(&bad); *first(&bad) = 0xc00000000ull;
    assert(prepare(&bad) == STATUS_CONFLICTING_ADDRESSES && !*last(&bad));
    ULONG_PTR arena_end = ios_fex_arena_end_unix;
    init_image(&bad); ios_fex_arena_end_unix = ios_fex_arena_base_unix + 0x1000;
    assert(prepare(&bad) == STATUS_INVALID_PARAMETER && !*first(&bad));
    ios_fex_arena_end_unix = arena_end;
    init_image(&bad); module_name = "unrelated.dll";
    assert(prepare(&bad) == STATUS_SUCCESS && !*first(&bad)); module_name = "libwow64fex.dll";

    struct file_view *plain = add_view(0xc00000000ull, 0x1000000, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED);
    ios_fex_tag_view(plain, ios_fex_arena_base_unix, ios_fex_arena_end_unix - 1);
    assert(plain->ios_fex_owner == a && plain->ios_fex_lease == lease);
    struct file_view *outside = add_view(0xe00000000ull, 0x1000000, VPROT_READ | VPROT_WRITE);
    ios_fex_tag_view(outside, 0xc00000000ull, 0xeffffffffull);
    assert(outside->ios_fex_owner == a); /* old producer's native views outside held arena */
    struct file_view *unowned = add_view(0xc02000000ull, 0x10000, VPROT_READ | VPROT_WRITE);
    current_peb = unknown;
    assert(ios_thread_process_lease(unknown, 1)); /* known native process, no validated CPU image */
    ios_fex_tag_view(unowned, ios_fex_arena_base_unix, ios_fex_arena_end_unix - 1);
    assert(!unowned->ios_fex_owner && !unowned->ios_fex_lease);
    current_peb = b; assert(prepare(&sibling) == STATUS_SUCCESS);
    struct file_view *foreign = add_view(0xc03000000ull, 0x10000, VPROT_READ | VPROT_WRITE);
    ios_fex_tag_view(foreign, ios_fex_arena_base_unix, ios_fex_arena_end_unix - 1);
    assert(foreign->ios_fex_owner == b);
    current_peb = a;
    ios_fex_tag_view(foreign, ios_fex_arena_base_unix, ios_fex_arena_end_unix - 1);
    assert(foreign->ios_fex_owner == b); /* never overwrite another process's allocation owner */

    const unsigned unsafe[] = { VPROT_SYSTEM, SEC_IMAGE, SEC_FILE, SEC_RESERVE, SEC_COMMIT,
        VPROT_PLACEHOLDER, VPROT_FREE_PLACEHOLDER, VPROT_EXEC, VPROT_ARM64EC };
    struct file_view *protected[ARRAY_SIZE(unsafe) + 1];
    for (unsigned i = 0; i < ARRAY_SIZE(unsafe); ++i) {
        protected[i] = add_view(0xc04000000ull + 0x10000ull * i, 0x10000, VPROT_READ | VPROT_WRITE | unsafe[i]);
        ios_fex_tag_view(protected[i], ios_fex_arena_base_unix, ios_fex_arena_end_unix - 1);
        assert(!protected[i]->ios_fex_owner);
        protected[i]->ios_fex_owner = a; protected[i]->ios_fex_lease = lease;
    }
    protected[ARRAY_SIZE(unsafe)] = add_view(0xc05000000ull, 0x10000, VPROT_READ | VPROT_WRITE);
    protected[ARRAY_SIZE(unsafe)]->ios_flags = IOS_VIEW_QUARANTINED;
    ios_fex_tag_view(protected[ARRAY_SIZE(unsafe)], ios_fex_arena_base_unix, ios_fex_arena_end_unix - 1);
    assert(!protected[ARRAY_SIZE(unsafe)]->ios_fex_owner);
    protected[ARRAY_SIZE(unsafe)]->ios_fex_owner = a; protected[ARRAY_SIZE(unsafe)]->ios_fex_lease = lease;
    struct file_view *stale = add_view(0xc06000000ull, 0x10000, VPROT_READ | VPROT_WRITE);
    stale->ios_fex_owner = a; stale->ios_fex_lease = lease + 1000;

    /* Split metadata follows both live fragments; MEM_RELEASE + view-slot
     * reuse clears it before assigning any later allocation. */
    assert(remove_pages_from_view(plain, (char *)plain->base + 0x10000, 0x10000) == STATUS_SUCCESS);
    struct file_view *split = find_view((char *)plain->base + 0x20000, 1);
    assert(split && split != plain && split->ios_fex_owner == a && split->ios_fex_lease == lease);
    struct file_view *released = add_view(0xc07000000ull, 0x10000, VPROT_READ | VPROT_WRITE);
    ios_fex_tag_view(released, ios_fex_arena_base_unix, ios_fex_arena_end_unix - 1);
    delete_view(released);
    struct file_view *reused = add_view(0xc07000000ull, 0x10000, VPROT_READ | VPROT_WRITE);
    assert(reused == released && !reused->ios_fex_owner && !reused->ios_fex_lease);
    unsigned before = deleted_total;
    ios_fex_reclaim_process_views(unknown); ios_fex_reclaim_process_views(NULL); ios_fex_reclaim_process_views(a);
    assert(deleted_total == before && live(plain) && live(outside)); /* native process still live */
    assert(ios_thread_count_add(a, 1) == 2);
    current.Peb = a; ios_retired_thread_owner = NULL;
    assert(!ios_thread_process_exit_ready(a));
    ios_fex_reclaim_process_views(a); assert(deleted_total == before); /* remaining native callback/thread */
    finish(a); ios_fex_reclaim_process_views(a);
    assert(deleted_total == before + 3 && !live(plain) && !live(split) && !live(outside));
    assert(restored[plain - storage] && restored[split - storage] && unmapped[outside - storage]);
    assert(live(foreign) && foreign->ios_fex_owner == b && live(unowned) && live(reused) && live(stale));
    for (unsigned i = 0; i < ARRAY_SIZE(protected); ++i) assert(live(protected[i]));
    assert(drops == 1 && owned(b) == 1);

    /* A new process at the same PEB address never inherits the dead owner's
     * lease, nor can a stale cleanup remove newly owned data. */
    assert(ios_thread_process_forget(a));
    init_image(&image); current_peb = a; assert(prepare(&image) == STATUS_SUCCESS);
    unsigned long long replacement = ios_thread_process_lease(a, 0);
    assert(replacement != lease);
    struct file_view *new_view = add_view(0xc08000000ull, 0x10000, VPROT_READ | VPROT_WRITE);
    ios_fex_tag_view(new_view, ios_fex_arena_base_unix, ios_fex_arena_end_unix - 1);
    assert(new_view->ios_fex_owner == a && new_view->ios_fex_lease == replacement);
    ios_fex_reclaim_process_views(a); assert(live(new_view) && live(foreign));
    finish(a); race_owner = a; lock_reuse = 1;
    before = deleted_total; ios_fex_reclaim_process_views(a);
    assert(deleted_total == before && live(new_view)); /* generation changed while acquiring VM lock */
    assert(live(foreign) && !ios_thread_process_quiescent_lease(b));
    /* Repeated helper/restart generations return to exactly the same VAD
     * count. Existing foreign/unsafe/unknown mappings stay untouched. */
    unsigned plateau = 0;
    struct file_view *iter;
    WINE_RB_FOR_EACH_ENTRY(iter, &views_tree, struct file_view, entry) ++plateau;
    unsigned long long previous_lease = 0;
    struct image_fixture cycle_image;
    assert(ios_thread_count_add(b, 1) == 2);
    pthread_t survivor;
    assert(!pthread_create(&survivor, NULL, surviving_allocator, b));
    pthread_mutex_lock(&sibling_mutex);
    while (!sibling_started) pthread_cond_wait(&sibling_cond, &sibling_mutex);
    pthread_mutex_unlock(&sibling_mutex);
    for (unsigned cycle = 0; cycle < 64; ++cycle) {
        assert(!pthread_mutex_lock(&virtual_mutex));
        current_peb = unknown; init_image(&cycle_image);
        assert(prepare(&cycle_image) == STATUS_SUCCESS);
        unsigned long long cycle_lease = ios_thread_process_lease(unknown, 0);
        assert(cycle_lease && cycle_lease != previous_lease);
        previous_lease = cycle_lease;
        struct file_view *cycle_view = add_view(0xc10000000ull, 0x1000000, VPROT_READ | VPROT_WRITE);
        ios_fex_tag_view(cycle_view, ios_fex_arena_base_unix, ios_fex_arena_end_unix - 1);
        assert(remove_pages_from_view(cycle_view, (char *)cycle_view->base + 0x10000, 0x10000) == STATUS_SUCCESS);
        unsigned extra = cycle ? 0 : 130; /* exceed the reaper's fixed-size batch */
        for (unsigned i = 0; i < extra; ++i) {
            struct file_view *many = add_view(0xc11000000ull + 0x10000ull * i, 0x10000, VPROT_READ | VPROT_WRITE);
            ios_fex_tag_view(many, ios_fex_arena_base_unix, ios_fex_arena_end_unix - 1);
        }
        assert(owned(unknown) == 2 + extra);
        assert(!pthread_mutex_unlock(&virtual_mutex));
        finish(unknown); ios_fex_reclaim_process_views(unknown);
        assert(!pthread_mutex_lock(&virtual_mutex));
        assert(!owned(unknown));
        unsigned after = 0;
        WINE_RB_FOR_EACH_ENTRY(iter, &views_tree, struct file_view, entry) ++after;
        assert(after == plateau);
        assert(live(foreign) && foreign->ios_fex_owner == b && !ios_thread_process_quiescent_lease(b));
        for (unsigned i = 0; i < ARRAY_SIZE(protected); ++i) assert(live(protected[i]));
        assert(ios_thread_process_forget(unknown));
        assert(!pthread_mutex_unlock(&virtual_mutex));
    }
    __atomic_store_n(&sibling_stop, 1, __ATOMIC_RELEASE);
    assert(!pthread_join(survivor, NULL) && sibling_allocations);
    assert(live(foreign) && owned(b) == 1 && !ios_thread_process_quiescent_lease(b));
    assert(!pthread_mutex_trylock(&virtual_mutex)); pthread_mutex_unlock(&virtual_mutex);
    return 0;
}
'''
vad_result = run('Private pre-CRT FEX DATA exports, process-owned VAD splitting/reuse and quiescent reclamation preserve foreign/system/placeholder/quarantined mappings', vad_code)

# The retirement diagnostics explicitly distinguish what was freed from the
# protected residuals. Nonzero freed totals must never read as leaked views.
retirements = []
for line in vad_result.stderr.splitlines():
    if '[fex-owner-v1] retired ' not in line:
        continue
    fields = dict(re.findall(r'([a-z-]+)=([^\s]+)', line))
    retirements.append(fields)
assert retirements
first_retirement = retirements[0]
expected_first = {
    'before-views': 13, 'before-reserved': 0x2090000,
    'freed-views': 3, 'freed-reserved': 0x1ff0000,
    'freed-logical-committed': 0xff0000,
    'remaining-views': 10, 'remaining-reserved': 0xa0000,
    'remaining-reclaimable': 0, 'retained-unsafe': 10,
}
for key, value in expected_first.items():
    assert int(first_retirement[key], 0) == value, (key, value, first_retirement)
for fields in retirements:
    assert int(fields['before-views'], 0) == int(fields['freed-views'], 0) + int(fields['remaining-views'], 0)
    assert int(fields['before-reserved'], 0) == int(fields['freed-reserved'], 0) + int(fields['remaining-reserved'], 0)
    assert int(fields['remaining-reclaimable'], 0) == 0
assert any(int(fields['freed-views'], 0) >= 132 and int(fields['remaining-views'], 0) == 0 for fields in retirements)
print('PASS retirement totals distinguish freed mappings from protected residuals; fully reclaimed helper generations report zero remaining views')

# The shipped 64-bit CPU image is an AMD64 ARM64X hybrid, rather than carrying
# the ARM64EC machine value. Keep this real image variant in the acceptance
# coverage above; Wine's independently validated hybrid bit is still required.
machines = {}
for image in (root / 'app/Madeira/aarch64-windows/xtajit.dll', root / 'app/Madeira/arm64ec-windows/xtajit64.dll'):
    with image.open('rb') as handle:
        dos = handle.read(64)
        assert dos[:2] == b'MZ'
        handle.seek(struct.unpack_from('<I', dos, 0x3c)[0])
        header = handle.read(26)
        assert header[:4] == b'PE\0\0'
        machines[image.name] = struct.unpack_from('<H', header, 4)[0]
        assert struct.unpack_from('<H', header, 24)[0] == 0x20b
assert machines['xtajit.dll'] == 0xaa64
assert machines['xtajit64.dll'] in (0x8664, 0xa641)
assert 'image_info->is_hybrid' in virtual[virtual.index('if ((status = ios_fex_prepare_image('):][:220]
print('PASS actual bundled CPU machine variants covered; AMD64 acceptance requires Wine-validated hybrid metadata')

mapping = body(virtual, 'static NTSTATUS map_image_into_view(')
assert mapping.index('ios_fex_prepare_image(') < mapping.index('mprotect_exec(sec_addr, sec_size, prot)')
assert 'view->ios_fex_owner = NULL;' in body(virtual, 'static NTSTATUS create_view(')
split_body = body(virtual, 'static NTSTATUS remove_pages_from_view(')
assert 'new_view->ios_fex_owner = view->ios_fex_owner;' in split_body
assert 'new_view->ios_fex_lease = view->ios_fex_lease;' in split_body
finish_memory = body(server, 'static void ios_finish_process_memory(void *dead_peb)')
assert finish_memory.index('ios_jit_reclaim_process(dead_peb)') < finish_memory.index('ios_fex_reclaim_process_views(dead_peb)')
assert finish_memory.index('ios_fex_reclaim_process_views(dead_peb)') < finish_memory.index('ios_wow_window_release(dead_peb)')
print('PASS FEX arena publication precedes JIT copy; metadata survives splits and clears on reuse; JIT aliases retire before native FEX data and guest-window recycling')

# The session's original process has no child socket record. Its exit-42
# successor wait needs root presentation/TEB/JIT resources, while its private
# FEX heap reservations can go after native CPU callbacks finish. Execute that
# actual branch hook together with the real registry and bridge wait.
bridge = (root / 'app/Madeira/WineProcessBridge.m').read_text()
wrapper = body(server, 'void process_exit_wrapper( int status )')
root_start = wrapper.index('        /* No slot: this is the session\'s initial process')
root_end = wrapper.index('        close( fd_socket );', root_start)
root_hook = wrapper[root_start:root_end]
orphan_start = wrapper.index('if (caller && session && caller != session)')
assert orphan_start < root_start and 'pthread_exit( NULL );' in wrapper[orphan_start:root_start]
assert 'ios_finish_process_memory' not in root_hook
assert 'ios_jit_reclaim_process' not in root_hook and 'ios_wow_window_release' not in root_hook
root_code = vad_code[:vad_code.index('int main(void) {')]
root_code += r'''
typedef uint16_t WCHAR;
typedef struct { unsigned short Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
'''
root_code += f'#include "{root / "build/ntdll-unix/steam_handoff.h"}"\n'
root_code += 'static void root_session_hook(void *caller_peb, int status, int memory_ready) {\n' + root_hook + '\n}\n'
root_code += r'''
static int root_report, native_running = 1, server_running = 1, ui_attached = 1, jit_alive = 1;
void wine_launched_process_did_exit(int status) { root_report = status; }
static struct file_view *root_fex, *replacement_fex, *root_window, *root_jit;
static void *root_owner, *replacement_owner;
static int wait_ticks;
static int wineserver_is_running(void) { return server_running; }
static int handoff_tick(unsigned usec) {
    assert(usec == 200000 && ++wait_ticks <= 2);
    assert(native_running && server_running && ui_attached && jit_alive);
    assert(!live(root_fex) && live(replacement_fex) && live(root_window) && live(root_jit));
    finish(replacement_owner);
    ios_fex_reclaim_process_views(replacement_owner);
    madeira_child_server_exited(0x294, 0);
    return 0;
}
#define usleep handoff_tick
'''
root_code += body(bridge, 'static int madeira_wait_steam_handoff(int initial_status)') + '\n#undef usleep\n'
root_code += r'''
int main(void) {
    root_owner = (void *)(uintptr_t)0x400310000;
    replacement_owner = (void *)(uintptr_t)0x500310000;
    wine_rb_init(&views_tree, compare_view);
    struct image_fixture original_image, replacement_image;
    init_image(&original_image); init_image(&replacement_image);
    current_peb = root_owner; assert(prepare(&original_image) == STATUS_SUCCESS);
    root_fex = add_view(0xc00000000ull, 0x1000000, VPROT_READ | VPROT_WRITE);
    ios_fex_tag_view(root_fex, ios_fex_arena_base_unix, ios_fex_arena_end_unix - 1);
    root_window = add_view(0x400000000ull, 0x100000000ull, VPROT_SYSTEM);
    root_jit = add_view(0x300000000ull, 0x100000, SEC_IMAGE | VPROT_EXEC);
    current_peb = replacement_owner; assert(prepare(&replacement_image) == STATUS_SUCCESS);
    replacement_fex = add_view(0xc02000000ull, 0x1000000, VPROT_READ | VPROT_WRITE);
    ios_fex_tag_view(replacement_fex, ios_fex_arena_base_unix, ios_fex_arena_end_unix - 1);

    madeira_child_session_begin(1, 1);
    static WCHAR path[] = { 'C',':','\\','S','t','e','a','m','\\','s','t','e','a','m','.','e','x','e',0 };
    UNICODE_STRING image = {sizeof(path)-sizeof(WCHAR), sizeof(path), path};
    struct ios_child_token successor = ios_child_slot_take(&image,0x294,0x20,root_owner,root_owner,&image);
    ios_current_child = successor;
    madeira_child_process_started(replacement_owner, 0x294);
    assert(madeira_live_steam_successors(NULL) == 1);
    madeira_child_process_exited(root_owner, 0x20, 42);

    /* A root with another executing native Wine thread must retain its heaps. */
    assert(ios_thread_count_add(root_owner, 1) == 2);
    current_peb = root_owner; current.Peb = root_owner;
    assert(!ios_thread_process_exit_ready(root_owner));
    root_session_hook(root_owner, 42, 0);
    assert(live(root_fex) && live(replacement_fex) && live(root_window) && live(root_jit));
    /* The last callback/thread completes: execute the actual root-only hook. */
    finish(root_owner);
    root_session_hook(root_owner, 42, 1);
    assert(root_report == 42 && !owned(root_owner) && !live(root_fex));
    assert(live(replacement_fex) && live(root_window) && live(root_jit));
    assert(madeira_wait_steam_handoff(42) == 0 && wait_ticks == 1);
    assert(!madeira_live_steam_successors(NULL) && !live(replacement_fex));
    assert(native_running && ui_attached && jit_alive && live(root_window) && live(root_jit));
    return 0;
}
'''
run('Root exit42 reclaims only quiescent root FEX data and preserves TEB/window/JIT/UI across the actual Steam successor wait to final status0', root_code)
