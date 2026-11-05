#!/usr/bin/env python3
"""Exercise the real Steam publication and WoW64 reservation/release policies.

The November 5 run held windows at B=4,6,8 (hex billions), then refused its
fourth 32-bit child at the configured three-window limit. A generated native
Steam wrapper must publish the consumed Steam-session flag before Wine starts.

The fixture compiles production publication, window registry/placement,
teardown, native reaper and signal thread-registry probes. Only the kernel's
VM map, thread-port answers and unrelated cleanup callbacks are supplied here;
reservation, guard ownership, cap decisions and reuse are production code.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
virtual = (root / 'build/ntdll-unix/virtual_ios.c').read_text()
signal = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
thread = (root / 'build/ntdll-unix/thread_ios.c').read_text()
bridge = (root / 'app/Madeira/WineProcessBridge.m').read_text()


def body(source, signature):
    start = source.index(signature)
    while source.index(';', start) < source.index('{', start):
        start = source.index(signature, start + len(signature))
    return source[start:source.index('\n}', start) + 2] + '\n'


begin = virtual.index('/* ==== WoW64 guest windows: registry and placement ==== */')
end = virtual.index('/* ==== end of WoW64 guest windows ==== */', begin)
windows = virtual[begin:end]
laa_begin = windows.index('/***********************************************************************\n *           ios_laa_forced')
laa_end = windows.index('/* Clamp [*start, *end) off the reserved slot [wb, we).', laa_begin)
windows = windows[:laa_begin] + windows[laa_end:]
diagnostic = windows.index('void ios_wow_gl_attach_trace(')
windows = windows[:diagnostic] + windows[windows.index('\n}\n', diagnostic) + 3:]
windows = windows.replace(body(virtual, 'void __attribute__((weak)) d3d9_native_window_teardown('), '')

native_begin = bridge.index('const char *native_launch = getenv("MADEIRA_NATIVE_STEAM_LAUNCH");')
native_end = bridge.index('\n', bridge.index('unsetenv("MADEIRA_NATIVE_STEAM_LAUNCH");', native_begin))
native_publication = bridge[native_begin:native_end]
client = re.search(r'^\s*const int steam_client = madeira_is_steam_client_image\(getenv\("MADEIRA_EXE"\)\);', bridge, re.M).group()
session = re.search(r'^\s*const int steam_session = native_steam \|\| steam_client;', bridge, re.M).group()
publication = re.search(r'^\s*ios_main_image_steam = [^;]+;', bridge, re.M).group()
assert 'ios_main_image_steam = steam_session;' in publication
assert bridge.index(publication) < bridge.index('madeira_child_session_begin(steam_session, steam_client);')
assert bridge.index(publication) < bridge.index('__wine_main(argc, argv);')

registry_start = signal.index('#define IOS_MAX_WINE_THREADS ')
registry = signal[registry_start:signal.index('\n', registry_start) + 1]
registry_start = signal.index('struct ios_thread_entry {')
registry_end = signal.index('static pthread_mutex_t ios_thread_registry_lock = PTHREAD_MUTEX_INITIALIZER;', registry_start)
registry += signal[registry_start:registry_end] + 'static pthread_mutex_t ios_thread_registry_lock = PTHREAD_MUTEX_INITIALIZER;\n'
registry += ''.join(body(signal, marker) for marker in (
    'int ios_thread_registry_count(void)',
    'int ios_thread_registry_purge_range(',
    'static int ios_thread_port_gone(',
    'int ios_thread_registry_range_busy(',
))
reapers = body(thread, 'struct ios_thread_group\n{') + ';\n'
reapers += r'''
static struct ios_thread_group ios_thread_groups[64];
static pthread_mutex_t ios_thread_group_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ios_thread_reapers[64];
static pthread_once_t ios_thread_reapers_once = PTHREAD_ONCE_INIT;
'''
reapers += body(thread, 'static void ios_thread_reapers_init(') + body(thread, 'int ios_thread_process_forget(')

code = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
typedef uintptr_t ULONG_PTR;
typedef unsigned ULONG;
typedef int BOOL, NTSTATUS;
typedef struct { int unused; } PEB;
typedef unsigned int thread_t, mach_port_t, mach_msg_type_number_t;
typedef uint64_t mach_vm_address_t, mach_vm_size_t;
typedef int kern_return_t, task_t;
typedef int *task_info_t, *thread_info_t;
typedef void *vm_region_info_t;
typedef struct { int protection, max_protection, shared; } vm_region_basic_info_data_64_t;
typedef struct { unsigned long long max_address; } task_vm_info_data_t;
struct thread_basic_info { int words[10]; };
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define CONTAINING_RECORD(p,t,f) ((t *)((uintptr_t)(p) - offsetof(t,f)))
#define STATUS_SUCCESS 0
#define STATUS_NO_MEMORY ((NTSTATUS)0xc0000017)
#define PtrToUlong(p) ((ULONG)(ULONG_PTR)(p))
#define KERN_SUCCESS 0
#define KERN_INVALID_ARGUMENT 4
#define KERN_FAILURE 5
#define KERN_TERMINATED 37
#define MACH_SEND_INVALID_DEST 0x10000003
#define THREAD_BASIC_INFO 3
#define THREAD_BASIC_INFO_COUNT 10
#define TASK_VM_INFO 22
#define TASK_VM_INFO_COUNT 1
#define VM_REGION_BASIC_INFO_64 9
#define VM_REGION_BASIC_INFO_COUNT_64 1
#define VM_PROT_NONE 0
#define MACH_PORT_NULL 0
#define IOS_WOW_WINDOW_SIZE ((ULONG_PTR)1 << 32)
#define IOS_CAGE_BASE 0x7200000000ULL
#define IOS_CAGE_REAL_SIZE 0x1ffff0000ULL
#define ERR(...) ((void)0)
static void note(int fd, const char *format, ...)
{ (void)format; assert(fd == 2); }
#define dprintf note
static const ULONG_PTR host_page_size = 0x4000;
static ULONG_PTR ios_usable_va_floor = 0x7038000000ULL, ios_furniture_ceiling = 0x73ffff0000ULL;
static void *user_space_limit = (void *)0x7fffffff0000ULL;
static int ios_cage_holdback_live, ios_cage_window_tail_live;
unsigned long long ios_layerkit_lo, ios_layerkit_hi;
static _Thread_local void *current_peb;
static void *ios_jit_current_peb(void) { return current_peb; }
static time_t now = 100;
static time_t test_time(time_t *out) { if (out) *out = now; return now; }
static int test_nanosleep(const struct timespec *delay, struct timespec *remaining)
{ (void)remaining; assert(delay->tv_sec <= 3); now += delay->tv_sec; return 0; }
#define time test_time
#define nanosleep test_nanosleep

/* Kernel VM answers: non-overlapping intervals. All fixed reservations are
 * no-clobber; only production teardown may atomically replace window pages. */
enum region_owner { SYSTEM, POOL_RX, POOL_RW, FEX, FOREIGN, WINDOW };
struct region { ULONG_PTR lo, hi; int prot; enum region_owner owner; };
static struct region map[512];
static unsigned region_count, fresh_maps, replacements, unmaps, reserved_areas;
static ULONG_PTR map_end;
static void add_region(ULONG_PTR lo, ULONG_PTR hi, int prot, enum region_owner owner)
{
    assert(lo < hi && hi <= map_end && region_count < ARRAY_SIZE(map));
    unsigned at = 0;
    while (at < region_count && map[at].lo < lo) at++;
    if (at) assert(map[at - 1].hi <= lo);
    if (at < region_count) assert(hi <= map[at].lo);
    memmove(&map[at + 1], &map[at], (region_count - at) * sizeof(map[0]));
    map[at] = (struct region){lo, hi, prot, owner}; region_count++;
}
static int overlaps(ULONG_PTR lo, ULONG_PTR hi)
{
    for (unsigned i = 0; i < region_count; i++) if (map[i].lo < hi && lo < map[i].hi) return 1;
    return 0;
}
static task_t mach_task_self(void) { return 1; }
static kern_return_t task_info(task_t task, int flavor, task_info_t raw, mach_msg_type_number_t *count)
{
    (void)task; (void)count; assert(flavor == TASK_VM_INFO);
    ((task_vm_info_data_t *)raw)->max_address = map_end; return KERN_SUCCESS;
}
static kern_return_t mach_vm_region(task_t task, mach_vm_address_t *addr, mach_vm_size_t *size,
                                    int flavor, vm_region_info_t raw, mach_msg_type_number_t *count, mach_port_t *object)
{
    (void)task; (void)count; assert(flavor == VM_REGION_BASIC_INFO_64); *object = MACH_PORT_NULL;
    for (unsigned i = 0; i < region_count; i++) if (map[i].hi > *addr)
    {
        *addr = map[i].lo; *size = map[i].hi - map[i].lo;
        *(vm_region_basic_info_data_64_t *)raw = (vm_region_basic_info_data_64_t){map[i].prot, 7, 0};
        return KERN_SUCCESS;
    }
    return KERN_INVALID_ARGUMENT;
}
static void *anon_mmap_tryfixed(void *address, size_t size, int prot, int flags)
{
    ULONG_PTR lo = (ULONG_PTR)address;
    assert(prot == PROT_NONE && flags == MAP_NORESERVE);
    if (!size || lo >= map_end || size > map_end - lo || overlaps(lo, lo + size))
    { errno = EEXIST; return MAP_FAILED; }
    add_region(lo, lo + size, prot, WINDOW); fresh_maps++; return address;
}
static void *anon_mmap_fixed(void *address, size_t size, int prot, int flags)
{
    ULONG_PTR lo = (ULONG_PTR)address, hi = lo + size;
    assert(size == IOS_WOW_WINDOW_SIZE && prot == PROT_NONE && flags == MAP_NORESERVE);
    struct region previous[512]; unsigned count = region_count;
    memcpy(previous, map, sizeof previous); region_count = 0;
    for (unsigned i = 0; i < count; i++)
    {
        struct region r = previous[i];
        if (r.lo >= hi || r.hi <= lo) { add_region(r.lo, r.hi, r.prot, r.owner); continue; }
        assert(r.owner == WINDOW);  /* cannot replace FEX, pool aliases or furniture */
        if (r.lo < lo) add_region(r.lo, lo, r.prot, r.owner);
        if (r.hi > hi) add_region(hi, r.hi, r.prot, r.owner);
    }
    add_region(lo, hi, prot, WINDOW); replacements++; return address;
}
static int test_munmap(void *address, size_t size)
{
    assert(size == host_page_size); /* guest-window teardown must never open a hole */
    for (unsigned i = 0; i < region_count; i++) if (map[i].lo == (ULONG_PTR)address && map[i].hi == (ULONG_PTR)address + size)
    {
        assert(map[i].owner == WINDOW);
        memmove(&map[i], &map[i + 1], (--region_count - i) * sizeof(map[0])); unmaps++; return 0;
    }
    assert(!"released a mapping the reservation attempt does not own"); return -1;
}
#define munmap test_munmap
static void mmap_add_reserved_area(void *base, size_t size)
{ assert(base && size); reserved_areas++; }
static void ios_va_describe_range(void *base, ULONG_PTR size, char *text, size_t capacity)
{ (void)base; (void)size; snprintf(text, capacity, "synthetic kernel map"); }

/* Mach thread existence is the only supplied thread-liveness fact. Production
 * registry probes distinguish exited ports from unknown/error answers. */
static unsigned char port_state[64]; /* 1 live, 2 exited, 3 unexpected query error */
static kern_return_t thread_info(thread_t port, int flavor, thread_info_t raw, mach_msg_type_number_t *count)
{
    (void)raw; (void)count; assert(port < ARRAY_SIZE(port_state) && flavor == THREAD_BASIC_INFO);
    if (port_state[port] == 1) return KERN_SUCCESS;
    if (port_state[port] == 3) return KERN_FAILURE;
    return MACH_SEND_INVALID_DEST;
}
'''
code += registry + reapers
code += f'#include "{root / "wine/include/wine/list.h"}"\n'
code += f'#include "{root / "wine/include/wine/rbtree.h"}"\n'
code += r'''
/* The focused reservation workload has no Wine views or TEB list nodes. The
 * actual teardown walks those empty structures and executes its remaining VM,
 * registry and owner cleanup. VAD deletion is covered by the arena fixture. */
#undef RB_ENTRY_VALUE
#define RB_ENTRY_VALUE(p,t,f) ((t *)((uintptr_t)(p) - offsetof(t,f)))
struct ntdll_thread_data { struct list entry; };
typedef struct { struct ntdll_thread_data GdiTebBatch; } TEB;
struct file_view { void *base; size_t size; struct wine_rb_entry entry; };
static struct list teb_list = LIST_INIT(teb_list);
static struct wine_rb_tree views_tree;
static pthread_mutex_t virtual_mutex = PTHREAD_MUTEX_INITIALIZER;
static PEB *peb, *wow_peb;
static ULONG_PTR user_space_wow_limit;
static int ios_wow_laa_synth;
static unsigned d3d_drops, jit_drops, registry_drops, ident_drops, fd_drops;
static void *last_dead_owner;
static void server_enter_uninterrupted_section(pthread_mutex_t *lock, sigset_t *set)
{ (void)set; pthread_mutex_lock(lock); }
static void server_leave_uninterrupted_section(pthread_mutex_t *lock, sigset_t *set)
{ (void)set; pthread_mutex_unlock(lock); }
static void delete_view(struct file_view *view) { (void)view; assert(!"fixture has no Wine views"); }
static int alloc_pages_vprot(void *base, size_t size) { assert(base && size); return 1; }
static void set_page_vprot(void *base, size_t size, int prot) { assert(base && size && !prot); }
static void d3d9_native_window_teardown(unsigned long base) { assert(base); d3d_drops++; }
void ios_jit_reclaim_process(void *owner) { assert(owner); last_dead_owner = owner; jit_drops++; }
static void ios_jit_purge_window(ULONG_PTR base, size_t size) { assert(base && size); registry_drops++; }
void ios_proc_ident_release(void *owner) { assert(owner == last_dead_owner); ident_drops++; }
void ios_fd_cache_release(void *owner) { assert(owner == last_dead_owner); fd_drops++; }
'''
code += windows + body(virtual, 'static int ios_wow_window_teardown( ULONG_PTR base, void *dead_peb, unsigned guard_owned )')
code += f'#include "{root / "app/Madeira/steam_client_identity.h"}"\n'
code += 'static void publish_launch(void)\n{\n' + native_publication + client + session + publication + '\n}\n'
code += r'''

struct proc
{
    pthread_t thread;
    NTSTATUS status;
    ULONG_PTR base;
    void *owner;
    struct ios_wow_window *slot;
    unsigned ready, stop;
};
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static void *boot(void *context)
{
    struct proc *p = context;
    p->status = ios_wow_window_reserve();
    if (!p->status)
    {
        p->base = ios_wow_base(); p->owner = (void *)(p->base + 0x310000);
        current_peb = p->owner; ios_wow_window_bind(p->owner); p->slot = ios_wow_slot_current();
        unsigned before = fresh_maps;
        assert(!ios_wow_window_reserve() && ios_wow_base() == p->base && fresh_maps == before);
    }
    pthread_mutex_lock(&gate); p->ready = 1; pthread_cond_broadcast(&changed);
    while (!p->stop) pthread_cond_wait(&changed, &gate);
    pthread_mutex_unlock(&gate); return NULL;
}
static void start(struct proc *p)
{
    memset(p, 0, sizeof(*p)); assert(!pthread_create(&p->thread, NULL, boot, p));
    pthread_mutex_lock(&gate);
    while (!p->ready) pthread_cond_wait(&changed, &gate);
    pthread_mutex_unlock(&gate);
}
static void stop(struct proc *p)
{
    pthread_mutex_lock(&gate); p->stop = 1; pthread_cond_broadcast(&changed); pthread_mutex_unlock(&gate);
    assert(!pthread_join(p->thread, NULL));
}
static void register_port(unsigned index, struct proc *p)
{
    assert(!p->status && index < ARRAY_SIZE(port_state));
    ios_thread_registry[index] = (struct ios_thread_entry){index, p->base + 0x300000, NULL};
    port_state[index] = 1;
    if (ios_thread_count <= (int)index) ios_thread_count = index + 1;
}
static void reset(void)
{
    memset(ios_wow_windows, 0, sizeof ios_wow_windows); memset(ios_wow_placeholders, 0, sizeof ios_wow_placeholders);
    memset(ios_thread_registry, 0, sizeof ios_thread_registry); memset(port_state, 0, sizeof port_state);
    memset(ios_thread_groups, 0, sizeof ios_thread_groups);
    ios_wow_window_count = ios_wow_placeholder_count = ios_thread_count = 0;
    ios_wow_boot_slot = NULL; ios_wow_boot_generation = 0; current_peb = NULL;
    ios_main_image_steam = 0; ios_main_image_i386 = 0; ios_wow_armed = 0;
    fresh_maps = replacements = unmaps = reserved_areas = region_count = 0;
    d3d_drops = jit_drops = registry_drops = ident_drops = fd_drops = 0;
    now = 100;
    add_region(0x100000000, 0x200000000, PROT_READ, SYSTEM);
    add_region(0x300000000, 0x348000000, PROT_READ | PROT_EXEC, POOL_RX);
    add_region(0x348000000, 0x390000000, PROT_READ | PROT_WRITE, POOL_RW);
    if (map_end >= 0xd60000000) add_region(0xb60000000, 0xd60000000, PROT_NONE, FEX);
    setenv("MADEIRA_WOW_SMALL_VA_SLOTS", "3", 1);
    unsetenv("MADEIRA_WOW_ELASTIC"); unsetenv("MADEIRA_WOW_LIVE_WINDOW_GUARD");
    unsetenv("MADEIRA_WOW_MIN_MAP_GB"); unsetenv("MADEIRA_WOW_MIN_FREE_GB");
    unsetenv("MADEIRA_NATIVE_STEAM_LAUNCH");
    setenv("MADEIRA_EXE", "C:\\windows\\sysx64\\cmd.exe", 1);
}
static void begin_captured_three(struct proc processes[3])
{
    publish_launch(); assert(!ios_main_image_steam);
    for (unsigned i = 0; i < 3; i++)
    {
        start(&processes[i]); assert(!processes[i].status);
        assert(processes[i].base == 0x400000000 + (ULONG_PTR)i * 0x200000000);
        assert(processes[i].slot->guard_owned); register_port(i + 1, &processes[i]);
    }
    assert(ios_wow_live_window_count() == 3 && ios_wow_small_va_slots == 3);
    struct proc fourth; unsigned before = fresh_maps;
    start(&fourth); assert(fourth.status == STATUS_NO_MEMORY && !fourth.base && fresh_maps == before); stop(&fourth);
}
static void check_release_quiescence(void)
{
    reset(); struct proc p[3]; begin_captured_three(p);
    unsigned guard_unmaps = unmaps;
    /* GL32's eventual exit follows the failed fourth boot. It remains held
     * while an actual registry port is live, unknown, or its native reaper busy. */
    struct proc *gl32 = &p[2]; ios_wow_window_release(gl32->owner);
    assert(gl32->slot->dead == 1 && gl32->slot->base == 0x800000000);
    for (unsigned state = 1; state <= 3; state += 2)
    {
        port_state[3] = state; struct proc next; start(&next);
        assert(next.status == STATUS_NO_MEMORY && !replacements && gl32->slot->dead == 1); stop(&next);
    }
    port_state[3] = 2;
    ios_thread_groups[0].owner = gl32->owner;
    pthread_once(&ios_thread_reapers_once, ios_thread_reapers_init);
    pthread_mutex_lock(&ios_thread_reapers[0]);
    struct proc waiting; start(&waiting);
    assert(waiting.status == STATUS_NO_MEMORY && !replacements && gl32->slot->dead == 1); stop(&waiting);
    pthread_mutex_unlock(&ios_thread_reapers[0]);
    unsigned before = fresh_maps; struct proc replacement; start(&replacement);
    assert(!replacement.status && replacement.base == gl32->base && replacements == 1 && fresh_maps == before);
    assert(!ios_thread_registry[3].teb && !ios_thread_registry[3].mach_thread && !ios_thread_groups[0].owner);
    assert(jit_drops == 1 && registry_drops == 1 && ident_drops == 1 && fd_drops == 1);
    assert(p[0].slot->peb == p[0].owner && p[1].slot->peb == p[1].owner);
    assert(unmaps == guard_unmaps && ios_wow_guard_neighbour_blocked(gl32->base + IOS_WOW_WINDOW_SIZE, host_page_size));
    stop(&replacement); for (unsigned i = 0; i < 3; i++) stop(&p[i]);
    puts("PASS: captured B=4,6,8 / cap3 failure; GL32 release waits for exited ports and native reaper, then reuses only its own retained reservation");
}
static void check_wrapper_expansion(void)
{
    reset(); struct proc p[3]; begin_captured_three(p);
    unsigned guard_unmaps = unmaps;
    /* Keep the captured nonadjacent windows and occupy the intervening bodies.
     * B=9 can still share B=8's owned 16 KB overrun/NULL boundary safely. */
    add_region(0x500004000, 0x600000000, PROT_READ, FOREIGN);
    add_region(0x700004000, 0x800000000, PROT_READ, FOREIGN);
    setenv("MADEIRA_NATIVE_STEAM_LAUNCH", "1", 1); publish_launch();
    assert(ios_main_image_steam && !getenv("MADEIRA_NATIVE_STEAM_LAUNCH"));
    setenv("MADEIRA_WOW_ELASTIC", "0", 1);
    struct proc capped; start(&capped); assert(capped.status == STATUS_NO_MEMORY); stop(&capped);
    unsetenv("MADEIRA_WOW_ELASTIC");
    struct proc probe; start(&probe); register_port(4, &probe);
    assert(!probe.status && probe.base == 0x900000000 && probe.slot->guard_owned);
    assert(ios_wow_live_window_count() == 4 && ios_wow_guard_neighbour_blocked(probe.base, host_page_size));
    assert(ios_wow_guard_conflicts(probe.base, host_page_size));
    assert(ios_wow_guard_conflicts(probe.base + IOS_WOW_WINDOW_SIZE, host_page_size));
    assert(!ios_wow_guard_conflicts(probe.base + host_page_size, host_page_size));
    unsigned owned = 0, before = fresh_maps;
    assert(!ios_wow_window_try(probe.base, &owned) && fresh_maps == before);
    unsigned generation = probe.slot->generation;
    for (unsigned cycle = 0; cycle < 24; cycle++)
    {
        ios_wow_window_release(probe.owner); port_state[4] = 2;
        now += IOS_WOW_SETTLE_SEC; stop(&probe);
        before = fresh_maps; start(&probe); register_port(4, &probe);
        assert(!probe.status && probe.base == 0x900000000 && fresh_maps == before);
        assert(probe.slot->generation > generation); generation = probe.slot->generation;
        assert(ios_wow_guard_neighbour_blocked(probe.base, host_page_size));
        assert(ios_wow_guard_neighbour_blocked(probe.base + IOS_WOW_WINDOW_SIZE, host_page_size));
        assert(unmaps == guard_unmaps && p[2].slot->peb == p[2].owner && p[2].slot->guard_owned);
    }
    assert(replacements == 24 && jit_drops == 24 && ident_drops == 24);
    /* Existing bounds and reservations remain authoritative after expansion. */
    before = fresh_maps;
    assert(!ios_wow_window_try(0x300000000, &owned));
    assert(!ios_wow_window_try(0xb00000000, &owned));
    assert(!ios_wow_window_try(0xf00000000, &owned));
    assert(!ios_wow_window_try(0x7c00000000, &owned));
    assert(fresh_maps == before);
    stop(&probe); for (unsigned i = 0; i < 3; i++) stop(&p[i]);

    setenv("MADEIRA_NATIVE_STEAM_LAUNCH", "true", 1); publish_launch();
    assert(!ios_main_image_steam && !getenv("MADEIRA_NATIVE_STEAM_LAUNCH"));
    setenv("MADEIRA_EXE", "C:\\Program Files (x86)\\Steam\\STEAM.EXE", 1); publish_launch();
    assert(ios_main_image_steam);
    setenv("MADEIRA_EXE", "C:\\Games\\game.exe", 1); publish_launch(); assert(!ios_main_image_steam);
    puts("PASS: actual consumed native-Steam publication unlocks safe B=9 with owned shared guards; 24 helper replacements reuse VA, pool/FEX/map bounds remain intact");
}
static void check_small_map(void)
{
    reset(); setenv("MADEIRA_NATIVE_STEAM_LAUNCH", "1", 1); publish_launch();
    struct proc p; start(&p);
    assert(p.status == STATUS_NO_MEMORY && !fresh_maps); stop(&p);
    puts("PASS: Steam session publication does not bypass the measured minimum address-map budget");
}
static void check_free_va_budget(void)
{
    reset();
    add_region(0x500004000, 0xb00000000, PROT_READ, FOREIGN);
    add_region(0xd60000000, map_end, PROT_READ, FOREIGN);
    assert(!overlaps(0x400000000, 0x500004000)); /* a complete guarded candidate is free */
    assert(!ios_wow_map_allows_window());
    setenv("MADEIRA_NATIVE_STEAM_LAUNCH", "1", 1); publish_launch();
    struct proc p; start(&p);
    assert(p.status == STATUS_NO_MEMORY && !fresh_maps); stop(&p);
    puts("PASS: a free guarded slot is refused when its reservation would violate the existing free-VA margin");
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    map_end = !strcmp(argv[1], "small-map") ? 0xa00000000 : 0xfc0000000;
    if (!strcmp(argv[1], "small-map")) check_small_map();
    else if (!strcmp(argv[1], "free-va")) check_free_va_budget();
    else { check_release_quiescence(); check_wrapper_expansion(); }
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-wow-capacity-') as directory:
    temporary = Path(directory)
    unit, executable = temporary / 'capacity.c', temporary / 'capacity'
    unit.write_text(code)
    command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
               '-Werror=implicit-function-declaration', '-Wno-unused-function', '-Wno-unused-variable',
               '-Wno-unused-but-set-variable', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
               '-fno-omit-frame-pointer', '-pthread', str(unit), '-o', str(executable)]
    if os.uname().sysname == 'Linux':
        command.insert(1, '-no-pie')
    subprocess.run(command, check=True)
    for mode in ('captured', 'small-map', 'free-va'):
        result = subprocess.run([str(executable), mode], capture_output=True, text=True, timeout=30)
        print(result.stdout, end='')
        if result.returncode:
            print(result.stderr, end='')
            result.check_returncode()
