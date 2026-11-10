#include "JITAllocator.h"
#if __has_include(".build-provenance/JITAllocator.generated.h")
#include ".build-provenance/JITAllocator.generated.h"
#endif
#ifndef MADEIRA_JIT_ALLOCATOR_SOURCE_SHA256
#define MADEIRA_JIT_ALLOCATOR_SOURCE_SHA256 "unknown"
#endif
#ifndef MADEIRA_JIT_BUILD_REVISION
#define MADEIRA_JIT_BUILD_REVISION "unknown"
#endif
const char *jit_allocator_build_provenance(void) {
    return "MadeiraJITAllocator:v1:" MADEIRA_JIT_ALLOCATOR_SOURCE_SHA256 ":" MADEIRA_JIT_BUILD_REVISION;
}
#include "../../build/madeira_cfg.h"   /* metal-validation (ml1249) */

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <setjmp.h>
#include <time.h>
#include <sys/ucontext.h>
#include <mach-o/dyld.h>
#include <os/log.h>
#include <os/proc.h>

// csops syscall - used to check CS_DEBUGGED flag
#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000
#endif
#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS 0
#endif
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

/* ml748: <mach/mach_vm.h> is "unsupported" on the iOS SDK, but these are
 * exported by libsystem_kernel and are the only calls that report a region's
 * max_protection -- which the W^X probe needs, since the failure mode is a
 * successful-looking call whose W was silently stripped. */
extern kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *,
                                    vm_region_flavor_t, vm_region_info_t,
                                    mach_msg_type_number_t *, mach_port_t *);
extern kern_return_t mach_vm_protect(vm_map_t, mach_vm_address_t, mach_vm_size_t,
                                     boolean_t, vm_prot_t);

// Page size on iOS is 16KB
#define JIT_PAGE_SIZE 0x4000

// VM_LEDGER_TAG_DEFAULT and VM_LEDGER_FLAG_NO_FOOTPRINT
// These are private Mach APIs used by MeloNX to make JIT memory
// not count against the app's Jetsam memory limit.
#ifndef VM_LEDGER_TAG_DEFAULT
#define VM_LEDGER_TAG_DEFAULT 0
#endif
#ifndef VM_LEDGER_FLAG_NO_FOOTPRINT
#define VM_LEDGER_FLAG_NO_FOOTPRINT (1 << 0)
#endif

// Private Mach API declarations
extern kern_return_t mach_memory_entry_ownership(
    mach_port_t mem_entry,
    mach_port_t owner,
    int ledger_tag,
    int ledger_flags
);

struct JITRegion {
    void *rw_ptr;       // Read-Write view (for writing code)
    void *rx_ptr;       // Read-Execute view (for executing code)
    size_t size;        // Size of the region
    mach_port_t mem_entry;  // Memory entry port for cleanup
};

static jit_log_callback_t g_log_callback = NULL;

void jit_set_log_callback(jit_log_callback_t callback) {
    g_log_callback = callback;
}

static void jit_log(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (g_log_callback) {
        g_log_callback(buf);
    }
    // Log to os_log (visible in Console.app) and stderr (Xcode)
    os_log(OS_LOG_DEFAULT, "[JIT] %{public}s", buf);
    fprintf(stderr, "[JIT] %s\n", buf);
}

static size_t align_to_page(size_t size) {
    return (size + JIT_PAGE_SIZE - 1) & ~(JIT_PAGE_SIZE - 1);
}

JITRegion *jit_region_create(size_t size) {
    size = align_to_page(size);

    JITRegion *region = calloc(1, sizeof(JITRegion));
    if (!region) {
        jit_log("Failed to allocate JITRegion struct");
        return NULL;
    }
    region->size = size;
    region->mem_entry = MACH_PORT_NULL;

    kern_return_t kr;
    mach_port_t task = mach_task_self();

    // Strategy: MeloNX dual-mapping approach
    //
    // 1. Create a named memory entry with RWX max protection
    // 2. Mark it as no-footprint (doesn't count against Jetsam limit)
    // 3. Map two views of it:
    //    - RW view for writing generated code
    //    - RX view for executing generated code

    // Step 1: Create a named memory entry
    memory_object_size_t entry_size = (memory_object_size_t)size;
    mach_port_t mem_entry = MACH_PORT_NULL;

    kr = mach_make_memory_entry_64(
        task,
        &entry_size,
        0,  // offset
        MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        &mem_entry,
        MACH_PORT_NULL  // parent entry
    );

    if (kr != KERN_SUCCESS) {
        jit_log("mach_make_memory_entry_64 failed: %s (kr=%d)", mach_error_string(kr), kr);
        free(region);
        return NULL;
    }

    jit_log("Created memory entry: port=%d, size=%zu", mem_entry, (size_t)entry_size);
    region->mem_entry = mem_entry;

    // Step 2: Mark as no-footprint (MeloNX trick)
    // This makes the memory not count against the app's Jetsam memory limit.
    kr = mach_memory_entry_ownership(
        mem_entry,
        TASK_NULL,  // No owner task = system-owned
        VM_LEDGER_TAG_DEFAULT,
        VM_LEDGER_FLAG_NO_FOOTPRINT
    );

    if (kr != KERN_SUCCESS) {
        // Non-fatal: memory will just count against the limit
        jit_log("mach_memory_entry_ownership failed (non-fatal): %s (kr=%d)", mach_error_string(kr), kr);
    } else {
        jit_log("Memory entry marked as no-footprint");
    }

    // Step 3a: Map RW view (for writing code)
    mach_vm_address_t rw_addr = 0;
    kr = vm_map(
        task,
        (vm_address_t *)&rw_addr,
        size,
        0,  // mask
        VM_FLAGS_ANYWHERE,
        mem_entry,
        0,  // offset
        FALSE,  // copy
        VM_PROT_READ | VM_PROT_WRITE,      // current protection
        VM_PROT_READ | VM_PROT_WRITE,      // max protection
        VM_INHERIT_DEFAULT
    );

    if (kr != KERN_SUCCESS) {
        jit_log("vm_map (RW) failed: %s (kr=%d)", mach_error_string(kr), kr);
        mach_port_deallocate(task, mem_entry);
        free(region);
        return NULL;
    }

    region->rw_ptr = (void *)rw_addr;
    jit_log("Mapped RW view at %p", region->rw_ptr);

    // Step 3b: Map RX view (for executing code)
    mach_vm_address_t rx_addr = 0;
    kr = vm_map(
        task,
        (vm_address_t *)&rx_addr,
        size,
        0,  // mask
        VM_FLAGS_ANYWHERE,
        mem_entry,
        0,  // offset
        FALSE,  // copy
        VM_PROT_READ | VM_PROT_EXECUTE,                  // current protection
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,  // max protection
        // Wider max so vm_protect can grant temporary W (e.g. FEX
        // PatchCallChecker writes to its __ImageBase + RVA, which lands
        // on the RX alias). vm_protect+VM_PROT_COPY then COW-flips the
        // page R/W. W^X still enforced via the actual current protection.
        VM_INHERIT_DEFAULT
    );

    if (kr != KERN_SUCCESS) {
        jit_log("vm_map (RX) failed: %s (kr=%d)", mach_error_string(kr), kr);
        // Clean up RW mapping
        vm_deallocate(task, (vm_address_t)region->rw_ptr, size);
        mach_port_deallocate(task, mem_entry);
        free(region);
        return NULL;
    }

    region->rx_ptr = (void *)rx_addr;
    jit_log("Mapped RX view at %p", region->rx_ptr);
    jit_log("Dual-mapped JIT region created: size=%zu, RW=%p, RX=%p", size, region->rw_ptr, region->rx_ptr);

    return region;
}

// ml358: make an ALREADY-MAPPED region jetsam-exempt.
//
// jit_region_create() marks its memory entry NO_FOOTPRINT, but the production
// pool never goes through it — allocatePool() gets its RX pages from StikDebug
// (jit26_prepare_region) and vm_remaps the RW alias, so the 896MB pool has
// been counting against phys_footprint in full this whole time. ml357 died of
// exactly that ("Terminated due to memory issue" with 848MB of pool written
// and PartitionAlloc's reserves at 0% committed).
//
// mach_make_memory_entry_64 over an existing range hands back an entry for the
// SAME vm_object both aliases share, so ownership applied to it should re-account
// resident pages as well as future ones. This is private API on a beta OS: every
// step is logged, failure is non-fatal, and phys_footprint is sampled either
// side so the log says whether it actually WORKED rather than whether it was
// merely attempted.
bool jit_make_region_no_footprint(void *addr, size_t size, const char *label) {
    mach_port_t task = mach_task_self();
    kern_return_t kr;

    uint64_t fp_before = 0, fp_after = 0;
    task_vm_info_data_t vmi;
    mach_msg_type_number_t vmi_cnt = TASK_VM_INFO_COUNT;
    if (task_info(task, TASK_VM_INFO, (task_info_t)&vmi, &vmi_cnt) == KERN_SUCCESS) {
        fp_before = vmi.phys_footprint;
    }

    /* ml458 (#75): the original single attempt used MAP_MEM_VM_SHARE and always
     * came back "ownership failed kr=4" (KERN_INVALID_ARGUMENT) — so the 896MB
     * pool has counted against phys_footprint every run, which is what pins the
     * pool at a size that now exhausts (ml455/ml456 both died there) and what
     * jetsam'd the 1024MB attempt at ml421-422.
     *
     * kr=4 is a REJECTED ENTRY KIND, not a permissions refusal (that would be
     * KERN_NO_ACCESS / KERN_PROTECTION_FAILURE): MAP_MEM_VM_SHARE hands back a
     * copy-style named entry, while the ownership call wants an entry that
     * names the VM object itself — which is exactly the difference from
     * jit_region_create()'s MAP_MEM_NAMED_CREATE entry, where this same
     * ownership call succeeds.
     *
     * This is undocumented private API on a beta OS, so instead of betting the
     * run on one guess, walk a small ladder of (entry-flags, owner) pairs and
     * let the log say which pair the kernel accepts.  Every step prints its kr;
     * the winner prints the phys_footprint delta, which is the only honest
     * proof the exemption took effect (a delta of ≈ the resident pool bytes
     * means real relief; ≈0 means the kernel accepted the call but kept
     * charging us). Non-fatal throughout: worst case we are exactly as
     * jetsam-counted as before. */
    struct { unsigned int flags; int own_self; const char *name; } variants[] = {
        { VM_PROT_READ | VM_PROT_WRITE,                    0, "plain/TASK_NULL" },
        { VM_PROT_READ | VM_PROT_WRITE,                    1, "plain/self" },
        { MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE, 1, "share/self" },
        { MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE, 0, "share/TASK_NULL" },
    };

    for (unsigned v = 0; v < sizeof(variants) / sizeof(variants[0]); v++) {
        memory_object_size_t entry_size = (memory_object_size_t)size;
        mach_port_t entry = MACH_PORT_NULL;
        kr = mach_make_memory_entry_64(
            task,
            &entry_size,
            (memory_object_offset_t)(uintptr_t)addr,
            variants[v].flags,
            &entry,
            MACH_PORT_NULL
        );
        if (kr != KERN_SUCCESS || entry == MACH_PORT_NULL) {
            jit_log("[no-footprint] %s: [%s] make_memory_entry failed kr=%d (%s) rev=ml458",
                    label, variants[v].name, kr, mach_error_string(kr));
            continue;
        }
        if ((size_t)entry_size < size) {
            jit_log("[no-footprint] %s: [%s] entry covers only %llu of %zu bytes (partial)",
                    label, variants[v].name, (unsigned long long)entry_size, size);
        }

        kr = mach_memory_entry_ownership(entry,
                                         variants[v].own_self ? task : TASK_NULL,
                                         VM_LEDGER_TAG_DEFAULT,
                                         VM_LEDGER_FLAG_NO_FOOTPRINT);
        mach_port_deallocate(task, entry);
        if (kr != KERN_SUCCESS) {
            jit_log("[no-footprint] %s: [%s] ownership failed kr=%d (%s) rev=ml458",
                    label, variants[v].name, kr, mach_error_string(kr));
            continue;
        }

        vmi_cnt = TASK_VM_INFO_COUNT;
        if (task_info(task, TASK_VM_INFO, (task_info_t)&vmi, &vmi_cnt) == KERN_SUCCESS) {
            fp_after = vmi.phys_footprint;
        }
        jit_log("[no-footprint] %s: [%s] ownership OK for %zu MB | phys_footprint %llu MB -> %llu MB "
                "(delta %lld MB) rev=ml458",
                label, variants[v].name, size >> 20,
                (unsigned long long)(fp_before >> 20), (unsigned long long)(fp_after >> 20),
                ((long long)fp_after - (long long)fp_before) >> 20);
        return true;
    }

    jit_log("[no-footprint] %s: ALL %zu variants refused — pool stays jetsam-counted rev=ml458",
            label, sizeof(variants) / sizeof(variants[0]));
    return false;
}

void jit_region_destroy(JITRegion *region) {
    if (!region) return;

    mach_port_t task = mach_task_self();

    if (region->rw_ptr) {
        vm_deallocate(task, (vm_address_t)region->rw_ptr, region->size);
        jit_log("Unmapped RW view at %p", region->rw_ptr);
    }
    if (region->rx_ptr) {
        vm_deallocate(task, (vm_address_t)region->rx_ptr, region->size);
        jit_log("Unmapped RX view at %p", region->rx_ptr);
    }
    if (region->mem_entry != MACH_PORT_NULL) {
        mach_port_deallocate(task, region->mem_entry);
    }

    free(region);
}

void *jit_region_rw_ptr(JITRegion *region) {
    return region ? region->rw_ptr : NULL;
}

void *jit_region_rx_ptr(JITRegion *region) {
    return region ? region->rx_ptr : NULL;
}

size_t jit_region_size(JITRegion *region) {
    return region ? region->size : 0;
}

void jit_region_invalidate(JITRegion *region, size_t offset, size_t size) {
    if (!region || !region->rx_ptr) return;
    sys_icache_invalidate((char *)region->rx_ptr + offset, size);
}

void *jit_region_write(JITRegion *region, size_t offset, const void *code, size_t code_size) {
    if (!region) return NULL;
    if (offset + code_size > region->size) {
        jit_log("Write out of bounds: offset=%zu, code_size=%zu, region_size=%zu",
                offset, code_size, region->size);
        return NULL;
    }

    // Write to the RW view
    memcpy((char *)region->rw_ptr + offset, code, code_size);

    // Invalidate icache on the RX view
    sys_icache_invalidate((char *)region->rx_ptr + offset, code_size);

    // Return the RX pointer for execution
    return (char *)region->rx_ptr + offset;
}

// SIGTRAP handler: skips BRK instruction (PC += 4) and zeros x0.
// This prevents crashes when BRK is executed without a debugger attached.
// ml1233: only the JIT protocol's BRK #0xf00d (as Wine's handler does). Any other
// trap is not ours -- a Swift runtime trap (precondition, force unwrap, overflow)
// is BRK #1 -- and was skipped too, running on past it with x0 = 0. The handler
// stays installed for the rest of the app run (from start-up without CS_DEBUGGED,
// or from jit_arm_trap_fallback before a launch that then fails and keeps the app
// up), so put the default action back and return: the instruction traps again and
// the app crashes with a report.
static void sigtrap_handler(int sig, siginfo_t *info, void *context) {
    (void)info;
    ucontext_t *uc = (ucontext_t *)context;
    uint64_t pc = uc->uc_mcontext->__ss.__pc;
    if ((pc & 3) || *(const uint32_t *)(uintptr_t)pc != 0xd43e01a0u /* brk #0xf00d */) {
        struct sigaction dfl;
        memset(&dfl, 0, sizeof(dfl));
        dfl.sa_handler = SIG_DFL;
        sigaction(sig, &dfl, NULL);
        return;
    }
    uc->uc_mcontext->__ss.__pc += 4;
    uc->uc_mcontext->__ss.__x[0] = 0;
}

void jit_install_trap_handler(void) {
    /* madeira: install unconditionally.
     *
     * The original returned early when jit_check_debugged() was already true,
     * to avoid stealing traps from StikDebug. But a debugger holds the Mach
     * exception port, which gets first refusal; a BSD SIGTRAP handler only
     * runs for traps the Mach layer declined. So this cannot pre-empt a
     * debugger that is actually servicing the protocol -- and when one is
     * attached but NOT servicing it (a generic JIT-enabler script), the early
     * return left an unserviced BRK to kill the process. */
    if (jit_check_debugged()) {
        jit_log("Debugger attached — installing SIGTRAP handler anyway (fallback only)");
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigtrap_handler;
    sigaction(SIGTRAP, &sa, NULL);
    jit_log("SIGTRAP handler installed (no debugger)");
}

void jit_arm_trap_fallback(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigtrap_handler;
    sigaction(SIGTRAP, &sa, NULL);
    jit_log("SIGTRAP handler installed (CS_DEBUGGED set, no debugger attached)");
}

bool jit_cs_status(uint32_t *flags) {
    uint32_t value = 0;
    if (csops(getpid(), CS_OPS_STATUS, &value, sizeof(value)) != 0) return false;
    *flags = value;
    return true;
}

bool jit_task_map_range(uint64_t *min_address, uint64_t *max_address) {
    task_vm_info_data_t vmi;
    mach_msg_type_number_t cnt = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vmi, &cnt) != KERN_SUCCESS ||
        !vmi.max_address) return false;
    *min_address = vmi.min_address;
    *max_address = vmi.max_address;
    return true;
}

uint64_t jit_available_memory(void) {
    return (uint64_t)os_proc_available_memory();
}

bool jit_memory_snapshot(uint64_t *available_bytes, uint64_t *footprint_bytes) {
    task_vm_info_data_t vmi;
    mach_msg_type_number_t cnt = TASK_VM_INFO_COUNT;
    if (available_bytes) *available_bytes = 0;
    if (footprint_bytes) *footprint_bytes = 0;
    if (!available_bytes || !footprint_bytes) return false;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vmi, &cnt) != KERN_SUCCESS)
        return false;
    *footprint_bytes = vmi.phys_footprint;
    *available_bytes = (uint64_t)os_proc_available_memory();
    return true;
}

/* CS2's measured 1024MB run had 476.8MB of image head and 512.1MB of
 * retained code buffers when phonon.dll needed a contiguous 51.1MB. Merely
 * adding 128MB lets the next FEX generation consume that whole increase.
 * Pair 1152MB with 240MB of image headroom. The November 8 rotation arrives
 * earlier than the November 7 replay: 208MB still admits another 32MB code
 * generation. CS2 now partitions the existing 1152MB pool into a low 768MB
 * image arena and a high 384MB code arena. The native allocator enforces that
 * boundary for fresh allocations, reuse and minimum-size fallbacks. The 240MB
 * legacy image-headroom target is retained separately. These are startup
 * choices, never a request to resize a live pool.
 *
 * All bytes are charged once physically, even though RX/RW need two virtual
 * ranges. No no-footprint exemption is assumed. The observed 3818MB peak,
 * 128MB growth and a further 2GB reserve must fit the measured process budget;
 * a RAM value or an entitlement alone is not evidence of that budget. */
bool jit_cs2_pool_plan(uint64_t requested_pool_mb, uint64_t available_bytes,
                       uint64_t footprint_bytes, uint64_t physical_bytes,
                       uint64_t map_min, uint64_t map_max,
                       uint64_t *pool_mb, uint64_t *head_reserve_mb) {
    const uint64_t mb = UINT64_C(1) << 20;
    const uint64_t selected = UINT64_C(1152) << 20;
    const uint64_t reserve = UINT64_C(2048) << 20;
    const uint64_t peak_with_growth = (UINT64_C(3818) + 128) << 20;
    const uint64_t budget_cap = UINT64_C(6144) << 20;
    uint64_t budget;

    if (pool_mb) *pool_mb = 0;
    if (head_reserve_mb) *head_reserve_mb = 0;
    if (!pool_mb || !head_reserve_mb || requested_pool_mb < 256 || requested_pool_mb > 1152 ||
        !available_bytes || !footprint_bytes || !physical_bytes || physical_bytes > INT64_MAX ||
        available_bytes > physical_bytes || footprint_bytes > physical_bytes - available_bytes)
        return false;
    budget = available_bytes + footprint_bytes;
    if (budget > budget_cap) budget = budget_cap;
    if (budget <= peak_with_growth + reserve || available_bytes < selected + reserve ||
        map_min >= map_max || map_max > INT64_MAX || map_max - map_min < selected * 2)
        return false;
    *pool_mb = selected / mb;
    *head_reserve_mb = 240;
    return true;
}

/* Hard arena sizes inside the same verified 1152MB physical backing. Code,
 * including private dispatcher pages and 16KB guards, cannot enter the image
 * arena; retired code reservations remain code reservations. Native placement
 * enforces this policy, rather than relying on a large-allocation-only limit. */
uint64_t jit_cs2_image_arena_mb(void) {
    return 768;
}

uint64_t jit_cs2_code_tail_limit_mb(void) {
    return 384;
}

bool jit_pool_alias_layout_valid(uint64_t rx, uint64_t rw, uint64_t size,
                                 uint64_t map_min, uint64_t map_max,
                                 uint64_t exe_base, uint64_t exe_size) {
    const uint64_t good_low = UINT64_C(0x119000000);
    const uint64_t host_low = UINT64_C(0x7c00000000);
    const uint64_t host_high = UINT64_C(0x8000000000);
    const uint64_t cpu_high = UINT64_C(0x1000000000);
    uint64_t rx_end, rw_end, exe_end;

    if (!size || ((rx | rw | size) & UINT64_C(0x3fff)) || map_min >= map_max ||
        map_max > INT64_MAX || rx < map_min || rx >= map_max || rw < map_min || rw >= map_max ||
        size > map_max - rx || size > map_max - rw || exe_size > UINT64_MAX - exe_base)
        return false;
    rx_end = rx + size;
    rw_end = rw + size;
    exe_end = exe_base + exe_size;
    if (rx < good_low ||
        (rx_end > cpu_high && !(rx >= host_low && rx_end <= host_high)) ||
        (rx < rw_end && rw < rx_end) ||
        (exe_size && ((rx < exe_end && rx_end > exe_base) || (rw < exe_end && rw_end > exe_base))))
        return false;
    return true;
}

// iOS 26 BRK-based JIT syscalls.
// These use BRK #0xf00d with x16 indicating the command.
// When a debugger (StikDebug) is attached, it intercepts the BRK,
// reads x16/x0/x1, performs the operation, and resumes.
// When no debugger is attached, the SIGTRAP handler skips the BRK.

__attribute__((noinline, optnone))
void *jit26_prepare_region(void *addr, size_t len) {
    register void *x0 __asm__("x0") = addr;
    register size_t x1 __asm__("x1") = len;
    __asm__ volatile(
        "mov x16, #1\n"
        "brk #0xf00d\n"
        : "+r"(x0)
        : "r"(x1)
        : "x16", "memory"
    );
    return x0;
}

__attribute__((noinline, optnone))
void jit26_detach(void) {
    __asm__ volatile(
        "mov x16, #0\n"
        "brk #0xf00d\n"
        ::: "x16", "memory"
    );
}

/* Unlike the legacy command, allocation does not first prepare an unknown
 * address. New scripts write full-width addresses only after our owned final
 * destinations have been installed. x0 starts at zero so an old script cannot
 * accidentally advertise these operations. */
__attribute__((noinline, optnone))
uint64_t jit26_pool_capabilities(void) {
    register uint64_t x0 __asm__("x0") = 0;
    register size_t x1 __asm__("x1") = 0;
    __asm__ volatile("mov x16, #8\n" "brk #0xf00d\n"
                     : "+r"(x0) : "r"(x1) : "x16", "memory");
    return x0;
}

__attribute__((noinline, optnone))
void *jit26_pool_allocate(size_t size) {
    register void *x0 __asm__("x0") = NULL;
    register size_t x1 __asm__("x1") = size;
    __asm__ volatile("mov x16, #9\n" "brk #0xf00d\n"
                     : "+r"(x0) : "r"(x1) : "x16", "memory");
    return x0;
}

__attribute__((noinline, optnone))
void *jit26_pool_prepare(void *address, size_t size) {
    register void *x0 __asm__("x0") = address;
    register size_t x1 __asm__("x1") = size;
    __asm__ volatile("mov x16, #10\n" "brk #0xf00d\n"
                     : "+r"(x0) : "r"(x1) : "x16", "memory");
    return x0;
}

/* BEGIN REQUIRED POOL EXECUTION PROBE */
#if defined(__aarch64__) || defined(__arm64__)
static _Thread_local sigjmp_buf jit_required_probe_jump;
static _Thread_local volatile sig_atomic_t jit_required_probe_armed;
static _Thread_local uintptr_t jit_required_probe_pc;
static struct sigaction jit_required_probe_previous[3];
static volatile sig_atomic_t jit_required_probe_was_reset[3];
static const int jit_required_probe_signals[3] = { SIGBUS, SIGSEGV, SIGILL };
static pthread_mutex_t jit_required_probe_mutex = PTHREAD_MUTEX_INITIALIZER;

static void jit_required_probe_signal(int signal_number, siginfo_t *information, void *context)
{
    ucontext_t *uc = (ucontext_t *)context;
    uintptr_t pc = (uintptr_t)uc->uc_mcontext->__ss.__pc;
    unsigned i;
    if (jit_required_probe_armed && information && information->si_code > 0 &&
        information->si_code < 0x10000 && pc >= jit_required_probe_pc && pc - jit_required_probe_pc < 12) {
        jit_required_probe_armed = 0;
        siglongjmp(jit_required_probe_jump, 1);
    }
    /* Other threads, other instructions and genuine unrelated faults retain
     * their original disposition. No PC is advanced and no fault is skipped. */
    for (i = 0; i < 3; i++) if (jit_required_probe_signals[i] == signal_number) {
        struct sigaction *previous = &jit_required_probe_previous[i];
        if (previous->sa_handler == SIG_IGN) return;
        if (previous->sa_handler == SIG_DFL ||
            ((previous->sa_flags & SA_RESETHAND) &&
             __atomic_exchange_n(&jit_required_probe_was_reset[i], 1, __ATOMIC_RELAXED))) {
            struct sigaction reset;
            memset(&reset, 0, sizeof(reset));
            reset.sa_handler = SIG_DFL;
            sigaction(signal_number, &reset, NULL);
            raise(signal_number);
            return;
        }
        if (previous->sa_flags & SA_SIGINFO) previous->sa_sigaction(signal_number, information, context);
        else previous->sa_handler(signal_number);
        return;
    }
}
#endif

static int jit_required_execute_pages(uint64_t rx, uint64_t rw, uint64_t size)
{
#if defined(__aarch64__) || defined(__arm64__)
    /* BTI C is a harmless HINT on older CPUs and permits a guarded call
     * landing on newer devices; it changes no data or return semantics. */
    const uint32_t code[3] = { UINT32_C(0xd503245f), UINT32_C(0xd2800540), UINT32_C(0xd65f03c0) };
    unsigned installed = 0, i;
    uint64_t offset;
    volatile int ok = 1;
    if (!size || ((rx | rw | size) & UINT64_C(0x3fff))) return 0;
    pthread_mutex_lock(&jit_required_probe_mutex);
    for (i = 0; i < 3; i++) {
        struct sigaction action;
        if (sigaction(jit_required_probe_signals[i], NULL, &jit_required_probe_previous[i])) { ok = 0; break; }
        jit_required_probe_was_reset[i] = 0;
        memset(&action, 0, sizeof(action));
        action.sa_sigaction = jit_required_probe_signal;
        action.sa_flags = SA_SIGINFO | (jit_required_probe_previous[i].sa_flags & (SA_ONSTACK | SA_NODEFER | SA_RESTART));
        action.sa_mask = jit_required_probe_previous[i].sa_mask;
        if (sigaction(jit_required_probe_signals[i], &action, NULL)) { ok = 0; break; }
        installed++;
    }
    for (offset = 0; ok && offset < size; offset += UINT64_C(0x4000)) {
        uint32_t original[3];
        memcpy(original, (const void *)(uintptr_t)(rw + offset), sizeof(original));
        memcpy((void *)(uintptr_t)(rw + offset), code, sizeof(code));
        sys_dcache_flush((void *)(uintptr_t)(rw + offset), sizeof(code));
        sys_icache_invalidate((void *)(uintptr_t)(rx + offset), sizeof(code));
        jit_required_probe_pc = (uintptr_t)(rx + offset);
        if (sigsetjmp(jit_required_probe_jump, 1)) ok = 0;
        else {
            int64_t (*function)(void) = (int64_t (*)(void))(uintptr_t)(rx + offset);
            jit_required_probe_armed = 1;
            if (function() != 42) ok = 0;
            jit_required_probe_armed = 0;
        }
        memcpy((void *)(uintptr_t)(rw + offset), original, sizeof(original));
        sys_dcache_flush((void *)(uintptr_t)(rw + offset), sizeof(original));
        sys_icache_invalidate((void *)(uintptr_t)(rx + offset), sizeof(original));
    }
    jit_required_probe_armed = 0;
    while (installed) {
        struct sigaction current;
        i = --installed;
        if (sigaction(jit_required_probe_signals[i], NULL, &current) ||
            !(current.sa_flags & SA_SIGINFO) || current.sa_sigaction != jit_required_probe_signal) {
            ok = 0; /* Do not overwrite a handler another subsystem installed. */
        } else {
            struct sigaction restore = jit_required_probe_previous[i];
            if (__atomic_load_n(&jit_required_probe_was_reset[i], __ATOMIC_RELAXED)) {
                memset(&restore, 0, sizeof(restore));
                restore.sa_handler = SIG_DFL;
            }
            if (sigaction(jit_required_probe_signals[i], &restore, NULL)) ok = 0;
        }
    }
    pthread_mutex_unlock(&jit_required_probe_mutex);
    return ok != 0;
#else
    (void)rx; (void)rw; (void)size;
    return 0;
#endif
}
/* END REQUIRED POOL EXECUTION PROBE */

bool jit_check_debugged(void) {
    uint32_t flags = 0;
    int result = csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
    if (result != 0) {
        jit_log("csops failed, assuming not debugged");
        return false;
    }
    bool debugged = (flags & CS_DEBUGGED) != 0;
    jit_log("CS_DEBUGGED flag: %s (flags=0x%x)", debugged ? "SET" : "NOT SET", flags);
    return debugged;
}

bool jit_test_mapping(void) {
    jit_log("=== JIT Mapping Test (non-executing) ===");

    // Test 1: Can we create a dual-mapped region?
    JITRegion *region = jit_region_create(JIT_PAGE_SIZE);
    if (!region) {
        jit_log("FAIL: Could not create dual-mapped region");
        return false;
    }
    jit_log("OK: Dual-mapped region created");

    // Test 2: Are RW and RX at different virtual addresses?
    if (region->rw_ptr == region->rx_ptr) {
        jit_log("FAIL: RW and RX are at the same address");
        jit_region_destroy(region);
        return false;
    }
    jit_log("OK: RW=%p != RX=%p", region->rw_ptr, region->rx_ptr);

    // Test 3: Write to RW, read from RX to verify shared backing
    uint32_t pattern = 0xDEADBEEF;
    memcpy(region->rw_ptr, &pattern, sizeof(pattern));
    uint32_t readback = 0;
    memcpy(&readback, region->rx_ptr, sizeof(readback));

    if (readback != pattern) {
        jit_log("FAIL: Write 0x%x to RW, read 0x%x from RX", pattern, readback);
        jit_region_destroy(region);
        return false;
    }
    jit_log("OK: Dual-map coherent (wrote 0x%x, read 0x%x)", pattern, readback);

    // Test 4: Check RX page has execute permission via vm_region
    vm_address_t addr = (vm_address_t)region->rx_ptr;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    kern_return_t kr = vm_region_64(
        mach_task_self(), &addr, &region_size,
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info,
        &info_count, &object_name
    );

    if (kr == KERN_SUCCESS && (info.protection & VM_PROT_EXECUTE)) {
        jit_log("OK: RX page has execute permission");
    } else {
        jit_log("WARN: RX page may lack execute permission (prot=0x%x)", info.protection);
    }

    jit_region_destroy(region);
    jit_log("=== Mapping test passed ===");
    return true;
}

// Check page protection via vm_region
static void jit_check_page_protection(void *addr, const char *label) {
    vm_address_t query_addr = (vm_address_t)addr;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    kern_return_t kr = vm_region_64(
        mach_task_self(), &query_addr, &region_size,
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info,
        &info_count, &object_name
    );

    if (kr == KERN_SUCCESS) {
        jit_log("%s at %p: prot=0x%x (R%s%s), max_prot=0x%x, size=%zu",
                label, addr,
                info.protection,
                (info.protection & VM_PROT_WRITE) ? "W" : "-",
                (info.protection & VM_PROT_EXECUTE) ? "X" : "-",
                info.max_protection,
                (size_t)region_size);
    } else {
        jit_log("%s at %p: vm_region failed (kr=%d)", label, addr, kr);
    }
}

int64_t jit_test_execute(void) {
    jit_log("=== JIT Execution Test ===");

    // Check CS_DEBUGGED first
    if (!jit_check_debugged()) {
        jit_log("FAIL: CS_DEBUGGED not set. Attach debugger first.");
        return -2;
    }

    // ARM64 machine code for: int64_t test_func(void) { return 42; }
    uint32_t code[] = {
        0xD2800540,  // mov x0, #42
        0xD65F03C0,  // ret
    };

    // Strategy 1: Dual-mapped region, write FIRST then prepare
    // (TXM may authorize page content at preparation time)
    jit_log("--- Strategy 1: Dual-map, write-then-prepare ---");
    {
        JITRegion *region = jit_region_create(JIT_PAGE_SIZE);
        if (!region) {
            jit_log("FAIL: Could not create JIT region");
            return -1;
        }

        // Write code FIRST (before prepare)
        jit_log("Writing ARM64 code (%zu bytes) to RW view BEFORE prepare", sizeof(code));
        void *exec_ptr = jit_region_write(region, 0, code, sizeof(code));
        if (!exec_ptr) {
            jit_log("FAIL: Could not write code to JIT region");
            jit_region_destroy(region);
            return -1;
        }

        jit_check_page_protection(region->rx_ptr, "RX page BEFORE prepare");

        // NOW ask debugger to prepare (authorize) the pages
        jit_log("Requesting debugger to prepare RX region at %p (%zu bytes)...",
                region->rx_ptr, region->size);
        void *prepared = jit26_prepare_region(region->rx_ptr, region->size);
        jit_log("prepare_region returned: %p", prepared);

        jit_check_page_protection(region->rx_ptr, "RX page AFTER prepare");

        jit_log("Executing from RX view at %p...", exec_ptr);

        typedef int64_t (*jit_func_t)(void);
        jit_func_t func = (jit_func_t)exec_ptr;
        int64_t result = func();

        jit_log("Result: %lld (expected 42)", result);

        if (result == -3) {
            jit_log("Strategy 1: FAULT LOOP detected — TXM rejected self-mapped RX pages");
            jit_region_destroy(region);
        } else if (result == 42) {
            jit_log("SUCCESS: Strategy 1 works! JIT is functional.");

            // Run additional tests
            uint32_t add_code[] = {
                0x8B010000,  // add x0, x0, x1
                0xD65F03C0,  // ret
            };
            void *add_ptr = jit_region_write(region, sizeof(code), add_code, sizeof(add_code));
            if (add_ptr) {
                // Re-prepare after writing new code
                jit26_prepare_region(region->rx_ptr, region->size);
                typedef int64_t (*add_func_t)(int64_t, int64_t);
                int64_t add_result = ((add_func_t)add_ptr)(100, 200);
                jit_log("add(100, 200) = %lld (expected 300)", add_result);
            }

            jit_region_destroy(region);
            jit_log("=== JIT tests passed (strategy 1) ===");
            return 42;
        } else {
            jit_log("Strategy 1 failed with result: %lld", result);
            jit_region_destroy(region);
        }
    }

    // If strategy 1 fault-looped, try strategy 2 automatically
    jit_log("Strategy 1 did not succeed, trying strategy 2...");
    return jit_test_execute_strategy2();
}

int64_t jit_test_execute_strategy2(void) {
    jit_log("--- Strategy 2: Debugger-allocated RX + vm_remap RW (MeloNX approach) ---");

    if (!jit_check_debugged()) {
        jit_log("FAIL: CS_DEBUGGED not set. Attach debugger first.");
        return -2;
    }

    uint32_t code[] = {
        0xD2800540,  // mov x0, #42
        0xD65F03C0,  // ret
    };

    size_t size = JIT_PAGE_SIZE;
    mach_port_t task = mach_task_self();

    // Step 1: Let StikDebug allocate RX pages via _M command (x0=0)
    jit_log("Requesting debugger to allocate %zu bytes of RX memory (x0=0)...", size);
    void *rx_ptr = jit26_prepare_region(NULL, size);
    jit_log("Debugger allocated RX at: %p", rx_ptr);

    if (!rx_ptr) {
        jit_log("FAIL: Debugger allocation returned NULL");
        return -1;
    }

    jit_check_page_protection(rx_ptr, "Debugger-allocated RX page");

    // Step 2: Use vm_remap to create a second view of the same pages (MeloNX approach)
    vm_address_t rw_addr = 0;
    vm_prot_t cur_prot = 0;
    vm_prot_t max_prot = 0;

    kern_return_t kr = vm_remap(
        task,
        &rw_addr,
        size,
        0,                              // mask
        VM_FLAGS_ANYWHERE,
        task,
        (vm_address_t)rx_ptr,           // source = debugger-allocated RX pages
        FALSE,                          // copy = false (share the pages)
        &cur_prot,
        &max_prot,
        VM_INHERIT_NONE
    );

    if (kr != KERN_SUCCESS) {
        jit_log("FAIL: vm_remap failed: %s (kr=%d)", mach_error_string(kr), kr);
        return -1;
    }

    jit_log("vm_remap succeeded: RW at %p (cur_prot=0x%x, max_prot=0x%x)",
            (void *)rw_addr, cur_prot, max_prot);

    // Step 3: Set the remapped view to RW (MeloNX does this)
    kr = vm_protect(task, rw_addr, size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        jit_log("FAIL: vm_protect(RW) failed: %s (kr=%d)", mach_error_string(kr), kr);
        vm_deallocate(task, rw_addr, size);
        return -1;
    }

    jit_log("Set remapped view to RW");
    jit_check_page_protection((void *)rw_addr, "Remapped RW view");
    jit_check_page_protection(rx_ptr, "Original RX view after remap");

    // Step 4: Write code to RW view
    jit_log("Writing ARM64 code (%zu bytes) to RW view at %p", sizeof(code), (void *)rw_addr);
    memcpy((void *)rw_addr, code, sizeof(code));
    sys_icache_invalidate(rx_ptr, sizeof(code));

    // Verify coherence: read from RX should show what we wrote to RW
    uint32_t readback = *(uint32_t *)rx_ptr;
    jit_log("Coherence check: wrote 0x%x to RW, read 0x%x from RX %s",
            code[0], readback, readback == code[0] ? "(OK)" : "(MISMATCH!)");

    // Step 5: Execute from debugger-allocated RX
    jit_log("Executing from debugger RX at %p...", rx_ptr);
    typedef int64_t (*jit_func_t)(void);
    int64_t result = ((jit_func_t)rx_ptr)();
    jit_log("Result: %lld (expected 42)", result);

    if (result == 42) {
        jit_log("SUCCESS: Strategy 2 (debugger alloc + vm_remap) works!");

        // Additional test: add function
        uint32_t add_code[] = {
            0x8B010000,  // add x0, x0, x1
            0xD65F03C0,  // ret
        };
        memcpy((void *)(rw_addr + sizeof(code)), add_code, sizeof(add_code));
        sys_icache_invalidate((char *)rx_ptr + sizeof(code), sizeof(add_code));

        typedef int64_t (*add_func_t)(int64_t, int64_t);
        int64_t add_result = ((add_func_t)((char *)rx_ptr + sizeof(code)))(100, 200);
        jit_log("add(100, 200) = %lld (expected 300)", add_result);
    }

    // Cleanup
    vm_deallocate(task, rw_addr, size);

    if (result == 42) {
        jit_log("=== JIT tests passed (strategy 2) ===");
        return 42;
    }

    jit_log("=== All JIT strategies failed ===");
    return result;
}

/* ============================================================================
 * ml748 -- W^X A/B PROBE: does PROT_WRITE survive on FILE-BACKED image pages?
 *
 * Loading xtajit64.dll on the jailbroken research VM faults writing its .rdata
 * (off=0x207000, kr=2 PROTECTION_FAILURE, prot=1 max=7) during the ARM64EC
 * hybrid-metadata / TLS-index fixups. The identical build loads it fine on the
 * iPhone 13 Pro. The fault reproduced with the debugger FULLY ATTACHED, so
 * CS_DEBUGGED being live is not the variable.
 *
 * Two explanations remain and reasoning cannot separate them:
 *   (a) the VM is STRICTER than a real CS_DEBUGGED device, because its
 *       patchVmMapProtect() was removed and that patch is what forced W to
 *       stick on file-backed pages. Then hardware keeps W, the VM strips it,
 *       and this is a false failure local to the VM.
 *   (b) hardware masks a GENUINE portability bug some other way, both strip W,
 *       and the loader's reliance on holding RWX over image pages is wrong.
 *
 * Run the SAME binary in BOTH places and compare. This must live inside
 * Madeira, not in a standalone tool: the 13 Pro has no root, so an arbitrary
 * CLI cannot run there at all, and a platform binary over SSH already gave a
 * misleading answer once (it reported mprotect(RWX) succeeding while Madeira in
 * its real container saw the opposite). Same process, same sandbox, same
 * cs_wx_enabled map, or it proves nothing.
 *
 * THE READBACK IS THE ANSWER, NOT THE RETURN CODE. The failure signature is a
 * call that reports success while W is silently stripped, so every case reads
 * protection AND max_protection back via mach_vm_region.
 * ==========================================================================*/

static void wxprobe_readback(const char *tag, void *addr, int rc, int err) {
    mach_vm_address_t a = (mach_vm_address_t)(uintptr_t)addr;
    mach_vm_size_t sz = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &a, &sz,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info, &cnt, &obj);
    if (kr != KERN_SUCCESS) {
        jit_log("[wx-probe] ml748 %-22s rc=%d errno=%d  region=UNREADABLE kr=%d",
                tag, rc, err, kr);
        return;
    }
    /* W_KEPT is the whole verdict: the call may have returned 0 and still lost W. */
    jit_log("[wx-probe] ml748 %-22s rc=%d errno=%-3d prot=%d max=%d  [R=%d W=%d X=%d]  W_KEPT=%s",
            tag, rc, err, info.protection, info.max_protection,
            !!(info.protection & VM_PROT_READ),
            !!(info.protection & VM_PROT_WRITE),
            !!(info.protection & VM_PROT_EXECUTE),
            (info.protection & VM_PROT_WRITE) ? "YES" : "NO");
}

void jit_wx_probe(void) {
    const size_t len = JIT_PAGE_SIZE * 4;

    jit_log("[wx-probe] ml748 BEGIN  CS_DEBUGGED=%d pagesize=%d",
            (int)jit_check_debugged(), (int)JIT_PAGE_SIZE);

    /* A file-backed PRIVATE mapping is the shape that actually fails: PE images
     * are mapped from the container, not allocated anonymously. Map our own
     * executable -- guaranteed present and readable in both environments. */
    const char *self = "/proc/self/exe";
    int fd = open(self, O_RDONLY);
    if (fd < 0) {
        /* No procfs on iOS; any readable file in the bundle serves the purpose. */
        extern int _NSGetExecutablePath(char *, uint32_t *);
        char path[4096]; uint32_t psz = sizeof(path);
        if (_NSGetExecutablePath(path, &psz) == 0)
            fd = open(path, O_RDONLY);
    }
    if (fd < 0) {
        jit_log("[wx-probe] ml748 ABORT: no file to map (errno=%d)", errno);
        return;
    }

    /* --- Cases 1-3: FILE-BACKED. This is the shape that faults. --- */
    for (int c = 1; c <= 3; c++) {
        void *p = mmap(NULL, len, PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
        if (p == MAP_FAILED) {
            jit_log("[wx-probe] ml748 case%d mmap FAILED errno=%d", c, errno);
            continue;
        }
        int rc, err;
        if (c == 1) {
            rc = mprotect(p, len, PROT_READ | PROT_WRITE); err = errno;
            wxprobe_readback("1 file mprotect RW", p, rc, err);
        } else if (c == 2) {
            /* Exactly what the loader does today. */
            rc = mprotect(p, len, PROT_READ | PROT_WRITE | PROT_EXEC); err = errno;
            wxprobe_readback("2 file mprotect RWX", p, rc, err);
        } else {
            /* VM_PROT_COPY forces a private writable copy of a file-backed page
             * instead of asking to write through the shared mapping -- the
             * mechanism the RW-window fix would rely on, and the one that should
             * remain legal under an ENFORCING W^X. */
            kern_return_t kr = mach_vm_protect(mach_task_self(),
                                               (mach_vm_address_t)(uintptr_t)p, len, FALSE,
                                               VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE);
            wxprobe_readback("3 file vm_protect COPY", p, (int)kr, 0);
        }
        munmap(p, len);
    }
    close(fd);

    /* --- Case 4: ANONYMOUS control. If anon keeps W|X and file-backed does not,
     * the constraint is file backing, not W^X in general. --- */
    void *a = mmap(NULL, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    if (a != MAP_FAILED) {
        int rc = mprotect(a, len, PROT_READ | PROT_WRITE | PROT_EXEC);
        wxprobe_readback("4 anon mprotect RWX", a, rc, errno);
        munmap(a, len);
    } else {
        jit_log("[wx-probe] ml748 case4 anon mmap FAILED errno=%d", errno);
    }

    jit_log("[wx-probe] ml748 END");
}


/* BEGIN REQUIRED POOL PLACEMENT */
/* A full-size pool needs two virtual destinations, but only one VM object.
 * Never infer usability from TASK_VM_INFO's address ceiling. Every selected
 * gap is checked by a fixed, non-overwriting kernel reservation. Anonymous
 * PROT_NONE reservations have no committed pool pages at image load.
 *
 * The upper 64 GiB on an extended map is not a general-purpose hole: guest
 * Windows/CEF use [448,496) GiB. Only Wine's managed host-furniture band
 * [496,512) may be used as a last resort; Wine excludes both aliases there and
 * reserves its bounded FEX host arena separately. GPU [64,448) is never used.
 * On a small map, >=16 GiB remains available for its WoW64/FEX fallback bands.
 *
 * State 1 is an unused early pair; 2 is a single in-progress transaction;
 * 3 is published and never resized/reclaimed here; 4 quarantines a failed
 * cleanup. No mutex is held while the debugger services a BRK request. */
#define JIT_REQUIRED_BYTES (UINT64_C(1152) << 20)
#define JIT_REQUIRED_PAGE UINT64_C(0x4000)
#define JIT_REQUIRED_RX_TAG 251
#define JIT_REQUIRED_RW_TAG 252
#define JIT_REQUIRED_FEX_TAG 253
#define JIT_REQUIRED_CAPABILITY UINT64_C(0x4d4a5031)

struct jit_required_pool {
    uint64_t rx, rw, size, temporary, generation, fex, fex_size;
    uint64_t rx_object, rw_object, fex_object;
    unsigned state, rx_installed, rw_installed, rx_tag, rw_tag;
    unsigned temporary_tag, temporary_owned;
    uint64_t temporary_object;
    struct jit_required_snapshot *rx_snapshot, *rw_snapshot;
};
struct jit_required_snapshot_entry {
    uint64_t offset, length, backing_offset;
    unsigned object, maximum, tag;
};
struct jit_required_snapshot {
    unsigned count, capacity;
    struct jit_required_snapshot_entry entries[];
};
struct jit_required_avoid { uint64_t address, size; };
static struct jit_required_pool jit_required_pool;
static pthread_mutex_t jit_required_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t jit_required_generation;
static int jit_required_drop(struct jit_required_pool *pool);

/* Recursion is needed for the leaf protection/tag, not just a parent submap's
 * enormous apparent extent. An exhausted child submap is conservatively
 * occupied through its own end; resume the top-level walk afterwards. */
static kern_return_t jit_required_region(uint64_t wanted, vm_address_t *address,
                                         vm_size_t *size,
                                         vm_region_submap_info_data_64_t *info)
{
    natural_t depth = 0;
    uint64_t parent_end = UINT64_MAX;
    unsigned visits;
    for (visits = 0; visits < 64; visits++) {
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr;
        *address = (vm_address_t)wanted;
        *size = 0;
        memset(info, 0, sizeof(*info));
        kr = vm_region_recurse_64(mach_task_self(), address, size, &depth,
                                  (vm_region_recurse_info_t)info, &count);
        if (kr == KERN_INVALID_ADDRESS && parent_end != UINT64_MAX && parent_end > wanted) {
            *address = (vm_address_t)wanted;
            *size = (vm_size_t)(parent_end - wanted);
            info->protection = VM_PROT_NONE;
            info->max_protection = VM_PROT_NONE;
            return KERN_SUCCESS;
        }
        if (kr != KERN_SUCCESS) return kr;
        if (!*size || *address > UINT64_MAX - *size) return KERN_FAILURE;
        if (!info->is_submap) return KERN_SUCCESS;
        if ((uint64_t)*address + *size < parent_end) parent_end = (uint64_t)*address + *size;
        if ((uint64_t)*address > wanted) wanted = (uint64_t)*address;
        depth++;
    }
    return KERN_FAILURE;
}

static int jit_required_overlap(uint64_t a, uint64_t n, uint64_t b, uint64_t m)
{
    return n && m && a < b + m && b < a + n;
}

static int jit_required_range(uint64_t address, uint64_t size, int tag,
                              vm_prot_t protection, uint64_t *object)
{
    uint64_t cursor = address, end;
    unsigned visits = 0;
    if (!address || !size || ((address | size) & (JIT_REQUIRED_PAGE - 1)) ||
        size > UINT64_MAX - address) return 0;
    end = address + size;
    while (cursor < end && visits++ < size / JIT_REQUIRED_PAGE + 64) {
        vm_address_t at;
        vm_size_t length;
        vm_region_submap_info_data_64_t info;
        if (jit_required_region(cursor, &at, &length, &info) != KERN_SUCCESS ||
            (uint64_t)at > cursor || length > UINT64_MAX - (uint64_t)at ||
            (uint64_t)at + length <= cursor || (protection >= 0 && info.protection != protection) ||
            (tag >= 0 && info.user_tag != (unsigned)tag) ||
            (tag == JIT_REQUIRED_FEX_TAG && protection >= 0 &&
             (info.max_protection & (VM_PROT_READ | VM_PROT_WRITE)) != (VM_PROT_READ | VM_PROT_WRITE))) return 0;
        if (object && *object != info.object_id) return 0;
        cursor = (uint64_t)at + length;
    }
    return cursor >= end;
}

static int jit_required_capture(uint64_t address, uint64_t size, int tag,
                                vm_prot_t protection, uint64_t *object)
{
    vm_address_t at;
    vm_size_t length;
    vm_region_submap_info_data_64_t info;
    if (jit_required_region(address, &at, &length, &info) != KERN_SUCCESS ||
        (uint64_t)at > address || !length || (uint64_t)at + length <= address) return 0;
    *object = info.object_id; /* zero is also an exact identity, never a wildcard */
    return jit_required_range(address, size, tag, protection, object);
}

static int jit_required_snapshot_capture(uint64_t address, uint64_t size, int tag,
                                         vm_prot_t protection,
                                         struct jit_required_snapshot **result)
{
    uint64_t cursor = address, end;
    unsigned capacity = (unsigned)(size / JIT_REQUIRED_PAGE + 64);
    struct jit_required_snapshot *snapshot;
    if (!address || !size || size > UINT64_MAX - address) return 0;
    end = address + size;
    snapshot = calloc(1, sizeof(*snapshot) + (size_t)capacity * sizeof(snapshot->entries[0]));
    if (!snapshot) return 0;
    snapshot->capacity = capacity;
    while (cursor < end && snapshot->count < capacity) {
        vm_address_t at;
        vm_size_t length;
        vm_region_submap_info_data_64_t info;
        struct jit_required_snapshot_entry *entry;
        uint64_t next;
        if (jit_required_region(cursor, &at, &length, &info) != KERN_SUCCESS ||
            (uint64_t)at > cursor || !length || (uint64_t)at > UINT64_MAX - length ||
            (uint64_t)at + length <= cursor || (tag >= 0 && info.user_tag != (unsigned)tag) ||
            (protection >= 0 && info.protection != protection) || info.offset > UINT64_MAX - (cursor - (uint64_t)at)) {
            free(snapshot); return 0;
        }
        next = (uint64_t)at + length;
        if (next > end) next = end;
        entry = &snapshot->entries[snapshot->count++];
        entry->offset = cursor - address;
        entry->length = next - cursor;
        entry->backing_offset = info.offset + cursor - (uint64_t)at;
        entry->object = info.object_id;
        entry->maximum = (unsigned)info.max_protection;
        entry->tag = info.user_tag;
        cursor = next;
    }
    if (cursor != end) { free(snapshot); return 0; }
    free(*result);
    *result = snapshot;
    return 1;
}

static int jit_required_snapshot_matches(uint64_t address, uint64_t size, int tag,
                                         vm_prot_t protection,
                                         const struct jit_required_snapshot *snapshot)
{
    unsigned i;
    uint64_t expected = 0;
    if (!snapshot || !snapshot->count || snapshot->count > snapshot->capacity) return 0;
    for (i = 0; i < snapshot->count; i++) {
        const struct jit_required_snapshot_entry *entry = &snapshot->entries[i];
        uint64_t cursor = address + entry->offset, end;
        unsigned visits = 0;
        if (entry->offset != expected || expected > size || !entry->length || entry->length > size - expected) return 0;
        expected += entry->length;
        end = address + expected;
        while (cursor < end && visits++ < size / JIT_REQUIRED_PAGE + 64) {
            vm_address_t at;
            vm_size_t length;
            vm_region_submap_info_data_64_t info;
            uint64_t actual_offset, wanted_offset;
            if (jit_required_region(cursor, &at, &length, &info) != KERN_SUCCESS ||
                (uint64_t)at > cursor || !length || (uint64_t)at > UINT64_MAX - length ||
                (uint64_t)at + length <= cursor || info.user_tag != entry->tag ||
                (tag >= 0 && info.user_tag != (unsigned)tag) ||
                (protection >= 0 && info.protection != protection) || info.object_id != entry->object ||
                (protection >= 0 && (unsigned)info.max_protection != entry->maximum) ||
                info.offset > UINT64_MAX - (cursor - (uint64_t)at) ||
                entry->backing_offset > UINT64_MAX - (cursor - address - entry->offset)) return 0;
            actual_offset = info.offset + cursor - (uint64_t)at;
            wanted_offset = entry->backing_offset + cursor - address - entry->offset;
            if (actual_offset != wanted_offset) return 0;
            cursor = (uint64_t)at + length;
            if (cursor > end) cursor = end;
        }
        if (cursor != end) return 0;
    }
    return expected == size;
}

static int jit_required_allowed(uint64_t address, uint64_t size,
                                uint64_t map_min, uint64_t map_max,
                                uint64_t exe_base, uint64_t exe_size)
{
    uint64_t end;
    if (!size || (address | size) & (JIT_REQUIRED_PAGE - 1) ||
        map_min >= map_max || map_max > INT64_MAX || address < map_min || address >= map_max ||
        size > map_max - address || exe_size > UINT64_MAX - exe_base)
        return 0;
    end = address + size;
    if (jit_required_overlap(address, size, exe_base, exe_size)) return 0;
    if (address >= UINT64_C(0x119000000) && end <= UINT64_C(0x1000000000)) {
        /* Small-map guest windows and FEX own the remaining low CPU band. */
        /* The future CoreAnimation/LayerKit home includes 20..30 GiB even on
         * an extended map. Keep all unleased CPU space >=16 GiB available. */
        return end <= UINT64_C(0x400000000);
    }
    return map_max >= UINT64_C(0x8000000000) && address >= UINT64_C(0x7c00000000) &&
           end <= UINT64_C(0x8000000000);
}

static int jit_required_reserve_gap(uint64_t start, uint64_t end, uint64_t size,
                                    uint64_t map_min, uint64_t map_max,
                                    uint64_t exe_base, uint64_t exe_size, int tag,
                                    const struct jit_required_avoid *avoid, unsigned avoid_count,
                                    uint64_t *result, int32_t *last_error)
{
    const uint64_t step = UINT64_C(16) << 20;
    unsigned attempts = 0;
    uint64_t at = (start + JIT_REQUIRED_PAGE - 1) & ~(JIT_REQUIRED_PAGE - 1);
    while (at < end && size <= end - at && attempts++ < 8192) {
        unsigned i;
        vm_address_t address;
        kern_return_t kr;
        int skip = 0;
        if (!jit_required_allowed(at, size, map_min, map_max, exe_base, exe_size)) {
            if (jit_required_overlap(at, size, exe_base, exe_size)) {
                at = (exe_base + exe_size + JIT_REQUIRED_PAGE - 1) & ~(JIT_REQUIRED_PAGE - 1);
                continue;
            }
            return 0;
        }
        for (i = 0; i < avoid_count; i++)
            if (jit_required_overlap(at, size, avoid[i].address, avoid[i].size)) {
                at = (avoid[i].address + avoid[i].size + JIT_REQUIRED_PAGE - 1) & ~(JIT_REQUIRED_PAGE - 1);
                skip = 1; break;
            }
        if (skip) continue;
        address = (vm_address_t)at;
        kr = vm_allocate(mach_task_self(), &address, (vm_size_t)size,
                          VM_FLAGS_FIXED | VM_MAKE_TAG((unsigned)tag));
        *last_error = kr;
        if (kr == KERN_SUCCESS) {
            *result = (uint64_t)address;
            /* A FIXED call may not silently move. Deallocate only the fresh
             * allocation returned by that successful call. */
            if ((uint64_t)address != at) {
                *last_error = vm_deallocate(mach_task_self(), address, (vm_size_t)size);
                if (*last_error == KERN_SUCCESS) *result = 0;
                return 0;
            }
            /* A zero-backed untouched reservation can report object_id=0.
             * Materialize only one fresh page so its later ownership checks
             * bind a real unique object, not an indistinguishable zero object.
             * At most three 16 KiB pages are charged for the early group. */
            {
                unsigned char zero = 0;
                kr = vm_write(mach_task_self(), address, (vm_offset_t)(uintptr_t)&zero, 1);
            }
            if (kr == KERN_SUCCESS)
                kr = vm_protect(mach_task_self(), address, (vm_size_t)size, FALSE, VM_PROT_NONE);
            if (kr == KERN_SUCCESS && jit_required_range(at, size, tag, VM_PROT_NONE, NULL)) {
                *result = at;
                return 1;
            }
            *last_error = kr == KERN_SUCCESS ? KERN_FAILURE : kr;
            if (vm_deallocate(mach_task_self(), address, (vm_size_t)size) != KERN_SUCCESS)
                return -1;
            *result = 0;
        }
        /* A concurrent allocation can win between the snapshot and this
         * non-overwriting attempt. Try another aligned destination. */
        if (end - at < step) break;
        at += step;
    }
    return 0;
}

static int jit_required_reserve_band(uint64_t low, uint64_t high, uint64_t size,
                                     uint64_t map_min, uint64_t map_max,
                                     uint64_t exe_base, uint64_t exe_size, int tag,
                                     const struct jit_required_avoid *avoid, unsigned avoid_count,
                                     uint64_t *result, int32_t *last_error)
{
    uint64_t cursor = low < map_min ? map_min : low;
    unsigned visits = 0;
    if (high > map_max) high = map_max;
    while (cursor < high && visits++ < 16384) {
        vm_address_t at;
        vm_size_t length;
        vm_region_submap_info_data_64_t info;
        kern_return_t kr = jit_required_region(cursor, &at, &length, &info);
        uint64_t next = high;
        int found;
        if (kr != KERN_SUCCESS && kr != KERN_INVALID_ADDRESS) {
            *last_error = kr; return 0;
        }
        if (kr == KERN_SUCCESS) {
            if (!length || (uint64_t)at > UINT64_MAX - length || (uint64_t)at + length <= cursor) {
                *last_error = KERN_FAILURE; return 0;
            }
            if ((uint64_t)at < next) next = (uint64_t)at;
        }
        if (next > cursor && size <= next - cursor) {
            found = jit_required_reserve_gap(cursor, next, size, map_min, map_max,
                                              exe_base, exe_size, tag, avoid, avoid_count,
                                              result, last_error);
            if (found) return found;
        }
        if (kr == KERN_INVALID_ADDRESS) break; /* Includes the genuine trailing gap. */
        cursor = (uint64_t)at + length;
    }
    return 0;
}

static int jit_required_reserve_one(uint64_t size, uint64_t map_min, uint64_t map_max,
                                    uint64_t exe_base, uint64_t exe_size, int tag,
                                    const struct jit_required_avoid *avoid, unsigned avoid_count,
                                    uint64_t *result, int32_t *error)
{
    uint64_t cpu_end = UINT64_C(0x400000000);
    int found;
    /* Preserve the proven iOS 26 layout when this actual kernel accepts it.
     * This is a search preference, not a required or assumed fixed base. */
    found = jit_required_reserve_band(UINT64_C(0x300000000), cpu_end, size, map_min, map_max,
                                      exe_base, exe_size, tag, avoid, avoid_count, result, error);
    if (found) return found;
    found = jit_required_reserve_band(UINT64_C(0x119000000), UINT64_C(0x300000000), size, map_min, map_max,
                                      exe_base, exe_size, tag, avoid, avoid_count, result, error);
    if (found) return found;
    if (map_max >= UINT64_C(0x8000000000))
        return jit_required_reserve_band(UINT64_C(0x7c00000000), UINT64_C(0x7e00000000), size,
                                          map_min, map_max, exe_base, exe_size, tag,
                                          avoid, avoid_count, result, error);
    return 0;
}

static int jit_required_hold(struct jit_required_pool *pool, uint64_t size,
                              uint64_t exe_base, uint64_t exe_size,
                              const struct jit_required_avoid *avoid, unsigned avoid_count,
                              int32_t *error)
{
    uint64_t map_min = 0, map_max = 0;
    int found;
    memset(pool, 0, sizeof(*pool));
    pool->rx_tag = JIT_REQUIRED_RX_TAG;
    pool->rw_tag = JIT_REQUIRED_RW_TAG;
    pool->size = size;
    if (!jit_task_map_range(&map_min, &map_max) || map_min >= map_max ||
        map_max > INT64_MAX || size > (map_max - map_min) / 2) {
        *error = KERN_FAILURE; return 0;
    }
    found = jit_required_reserve_one(size, map_min, map_max, exe_base, exe_size,
                                     JIT_REQUIRED_RX_TAG, avoid, avoid_count, &pool->rx, error);
    if (found <= 0) return found;
    pool->size = size;
    if (!jit_required_capture(pool->rx, size, JIT_REQUIRED_RX_TAG, VM_PROT_NONE, &pool->rx_object) || !pool->rx_object) {
        *error = KERN_INVALID_ADDRESS; return -1;
    }
    found = jit_required_reserve_one(size, map_min, map_max, exe_base, exe_size,
                                     JIT_REQUIRED_RW_TAG, avoid, avoid_count, &pool->rw, error);
    if (found <= 0) {
        if (!jit_required_range(pool->rx, size, JIT_REQUIRED_RX_TAG, VM_PROT_NONE, &pool->rx_object) ||
            vm_deallocate(mach_task_self(), (vm_address_t)pool->rx, (vm_size_t)size) != KERN_SUCCESS)
            return -1;
        memset(pool, 0, sizeof(*pool));
        return found;
    }
    if (!jit_required_capture(pool->rw, size, JIT_REQUIRED_RW_TAG, VM_PROT_NONE, &pool->rw_object) || !pool->rw_object) {
        *error = KERN_INVALID_ADDRESS; return -1;
    }
    if (pool->rx >= UINT64_C(0x7c00000000) || pool->rw >= UINT64_C(0x7c00000000)) {
        /* Protect a genuinely contiguous FEX home in the same early
         * transaction, rather than merely counting 13.75 GiB of free space.
         * The slot is adopted by Wine with no later release/reallocation. */
        pool->fex_size = UINT64_C(8) << 30;
        found = jit_required_reserve_band(UINT64_C(0x7c00000000), UINT64_C(0x8000000000),
                                          pool->fex_size, map_min, map_max,
                                          exe_base, exe_size, JIT_REQUIRED_FEX_TAG,
                                          NULL, 0, &pool->fex, error);
        if (found <= 0) {
            if (!jit_required_drop(pool)) return -1;
            memset(pool, 0, sizeof(*pool));
            return found;
        }
        if (!jit_required_capture(pool->fex, pool->fex_size, JIT_REQUIRED_FEX_TAG,
                                  VM_PROT_NONE, &pool->fex_object) || !pool->fex_object) {
            *error = KERN_INVALID_ADDRESS; return -1;
        }
    }
    pool->state = 1;
    return 1;
}

static int jit_required_drop(struct jit_required_pool *pool)
{
    int ok = 1;
    if (pool->fex) {
        if (!jit_required_range(pool->fex, pool->fex_size, JIT_REQUIRED_FEX_TAG, -1, &pool->fex_object) ||
            vm_deallocate(mach_task_self(), (vm_address_t)pool->fex, (vm_size_t)pool->fex_size) != KERN_SUCCESS)
            ok = 0;
        else pool->fex = 0;
    }
    if (pool->temporary) {
        uint64_t object = pool->temporary_object;
        if (!pool->temporary_owned ||
            !jit_required_range(pool->temporary, pool->size, (int)pool->temporary_tag,
                                -1, &object) ||
            vm_deallocate(mach_task_self(), (vm_address_t)pool->temporary, (vm_size_t)pool->size) != KERN_SUCCESS)
            ok = 0;
        else pool->temporary = 0;
    }
    if (pool->rw) {
        int owned = pool->rw_snapshot ?
                    jit_required_snapshot_matches(pool->rw, pool->size, -1,
                                                   -1, pool->rw_snapshot) :
                    jit_required_range(pool->rw, pool->size, (int)pool->rw_tag, -1, &pool->rw_object);
        if (!owned ||
            vm_deallocate(mach_task_self(), (vm_address_t)pool->rw, (vm_size_t)pool->size) != KERN_SUCCESS)
            ok = 0;
        else { pool->rw = 0; free(pool->rw_snapshot); pool->rw_snapshot = NULL; }
    }
    if (pool->rx) {
        int owned = pool->rx_snapshot ?
                    jit_required_snapshot_matches(pool->rx, pool->size, -1,
                                                   -1, pool->rx_snapshot) :
                    jit_required_range(pool->rx, pool->size, (int)pool->rx_tag, -1, &pool->rx_object);
        if (!owned ||
            vm_deallocate(mach_task_self(), (vm_address_t)pool->rx, (vm_size_t)pool->size) != KERN_SUCCESS)
            ok = 0;
        else { pool->rx = 0; free(pool->rx_snapshot); pool->rx_snapshot = NULL; }
    }
    return ok;
}

bool jit_required_pool_release_early(void)
{
    struct jit_required_pool pool;
    int ok;
    pthread_mutex_lock(&jit_required_mutex);
    if (!jit_required_pool.state) { pthread_mutex_unlock(&jit_required_mutex); return true; }
    if (jit_required_pool.state != 1) { pthread_mutex_unlock(&jit_required_mutex); return false; }
    pool = jit_required_pool;
    jit_required_pool.state = 2;
    pthread_mutex_unlock(&jit_required_mutex);
    ok = jit_required_drop(&pool);
    pthread_mutex_lock(&jit_required_mutex);
    if (ok) memset(&jit_required_pool, 0, sizeof(jit_required_pool));
    else { pool.state = 4; jit_required_pool = pool; }
    pthread_mutex_unlock(&jit_required_mutex);
    return ok != 0;
}

bool jit_required_pool_fex_reservation(uint64_t *base, uint64_t *size, uint64_t *object_id)
{
    int valid = 0;
    if (base) *base = 0;
    if (size) *size = 0;
    if (object_id) *object_id = 0;
    if (!base || !size || !object_id) return false;
    pthread_mutex_lock(&jit_required_mutex);
    if (jit_required_pool.state == 3 && jit_required_pool.fex &&
        jit_required_pool.fex_size == (UINT64_C(8) << 30) &&
        jit_required_range(jit_required_pool.fex, jit_required_pool.fex_size,
                            JIT_REQUIRED_FEX_TAG, VM_PROT_NONE, &jit_required_pool.fex_object)) {
        *base = jit_required_pool.fex;
        *size = jit_required_pool.fex_size;
        *object_id = jit_required_pool.fex_object;
        valid = 1;
    }
    pthread_mutex_unlock(&jit_required_mutex);
    return valid != 0;
}

/* The debugger's prepare command writes 0x69 at every 16 KiB page. Reading
 * every such marker through RW proves the whole remap shares the prepared RX
 * object. A reversible write/read test independently checks both directions.
 * This touches no extra backing beyond the original debugger prepare. */
static int jit_required_aliases_match(const struct jit_required_pool *pool)
{
    uint64_t offset;
    uint32_t original = 0, readback = 0, pattern = UINT32_C(0x4d4a5031);
    vm_size_t copied = 0;
    kern_return_t kr;
    for (offset = 0; offset < pool->size; offset += JIT_REQUIRED_PAGE)
        if (*(const volatile unsigned char *)(uintptr_t)(pool->rw + offset) != 0x69) return 0;
    memcpy(&original, (const void *)(uintptr_t)pool->rw, sizeof(original));
    memcpy((void *)(uintptr_t)pool->rw, &pattern, sizeof(pattern));
    sys_dcache_flush((void *)(uintptr_t)pool->rw, sizeof(pattern));
    kr = vm_read_overwrite(mach_task_self(), (vm_address_t)pool->rx, sizeof(readback),
                           (vm_address_t)(uintptr_t)&readback, &copied);
    memcpy((void *)(uintptr_t)pool->rw, &original, sizeof(original));
    sys_dcache_flush((void *)(uintptr_t)pool->rw, sizeof(original));
    sys_icache_invalidate((void *)(uintptr_t)pool->rx, sizeof(original));
    return kr == KERN_SUCCESS && copied == sizeof(readback) && readback == pattern;
}

bool jit_required_pool_create(uint64_t size, uint64_t exe_base, uint64_t exe_size,
                              uint64_t *rx, uint64_t *rw, uint32_t *stage, int32_t *error)
{
    struct jit_required_pool pool;
    struct jit_required_avoid avoid[6];
    unsigned attempt, avoid_count = 0;
    uint64_t map_min = 0, map_max = 0;
    if (rx) *rx = 0; if (rw) *rw = 0;
    if (stage) *stage = 1; if (error) *error = KERN_INVALID_ARGUMENT;
    if (!rx || !rw || !stage || !error || size != JIT_REQUIRED_BYTES ||
        exe_size > UINT64_MAX - exe_base) return false;
    pthread_mutex_lock(&jit_required_mutex);
    if (jit_required_pool.state > 1) {
        *stage = 11; *error = KERN_ABORTED;
        pthread_mutex_unlock(&jit_required_mutex); return false;
    }
    pool = jit_required_pool;
    jit_required_pool.state = 2;
    pthread_mutex_unlock(&jit_required_mutex);

    /* Must happen before any allocating request: an older installed script
     * cannot safely implement allocation-only or full-width final prepare. */
    if (jit26_pool_capabilities() != JIT_REQUIRED_CAPABILITY) {
        *stage = 1; *error = KERN_NOT_SUPPORTED;
        pthread_mutex_lock(&jit_required_mutex);
        jit_required_pool = pool;
        pthread_mutex_unlock(&jit_required_mutex);
        return false;
    }
    for (attempt = 0; attempt < 3; attempt++) {
        vm_prot_t current = 0, maximum = 0;
        vm_address_t address;
        vm_address_t source;
        vm_size_t length;
        vm_region_submap_info_data_64_t info;
        kern_return_t kr;
        int held;
        if (!pool.rx || !pool.rw || pool.size != size ||
            !jit_task_map_range(&map_min, &map_max) ||
            !jit_required_allowed(pool.rx, size, map_min, map_max, exe_base, exe_size) ||
            !jit_required_allowed(pool.rw, size, map_min, map_max, exe_base, exe_size) ||
            !jit_required_range(pool.rx, size, JIT_REQUIRED_RX_TAG, VM_PROT_NONE, &pool.rx_object) ||
            !jit_required_range(pool.rw, size, JIT_REQUIRED_RW_TAG, VM_PROT_NONE, &pool.rw_object)) {
            if ((pool.rx || pool.rw) && !jit_required_drop(&pool)) {
                *stage = 9; *error = KERN_FAILURE; goto failed;
            }
            *stage = 2; *error = KERN_NO_SPACE;
            held = jit_required_hold(&pool, size, exe_base, exe_size, avoid, avoid_count, error);
            if (held <= 0) { if (held < 0) *stage = 9; goto failed; }
        }
        pool.state = 2;
        pool.generation = ++jit_required_generation;
        jit_log("[jit-placement-v1] attempt=%u band=%s RX=0x%llx RW=0x%llx bytes=0x%llx held=both",
                attempt + 1, pool.rx >= UINT64_C(0x7c00000000) ? "managed-host-furniture" : "low-host",
                (unsigned long long)pool.rx, (unsigned long long)pool.rw, (unsigned long long)size);
        *stage = 3;
        pool.temporary = (uint64_t)(uintptr_t)jit26_pool_allocate((size_t)size);
        if (!pool.temporary) { *error = KERN_NO_SPACE; goto attempt_failed; }
        if (pool.temporary & (JIT_REQUIRED_PAGE - 1) ||
            !jit_task_map_range(&map_min, &map_max) || pool.temporary < map_min ||
            pool.temporary >= map_max || size > map_max - pool.temporary ||
            jit_required_overlap(pool.temporary, size, pool.rx, size) ||
            jit_required_overlap(pool.temporary, size, pool.rw, size) ||
            jit_required_overlap(pool.temporary, size, pool.fex, pool.fex_size)) {
            /* A malformed protocol reply does not grant ownership of some
             * unrelated address. Never deallocate that alleged source. */
            *error = KERN_INVALID_ADDRESS; goto attempt_failed;
        }
        kr = jit_required_region(pool.temporary, &source, &length, &info);
        if (kr != KERN_SUCCESS ||
            (uint64_t)source > pool.temporary || (uint64_t)source + length < pool.temporary + size ||
            !length || (uint64_t)source > UINT64_MAX - length) {
            *error = kr == KERN_SUCCESS ? KERN_INVALID_ADDRESS : kr; goto attempt_failed;
        }
        pool.temporary_tag = info.user_tag;
        pool.temporary_object = info.object_id;
        if (!jit_required_range(pool.temporary, size, (int)pool.temporary_tag,
                                 info.protection, &pool.temporary_object)) {
            *error = KERN_INVALID_ADDRESS; goto attempt_failed;
        }
        /* The trusted allocation-only RPC grants this exact fresh range. Keep
         * that receipt even if its actual permissions are unusable, so failure
         * releases it instead of silently allocating another 1152 MiB source. */
        pool.temporary_owned = 1;
        if (info.protection != (VM_PROT_READ | VM_PROT_EXECUTE) ||
            !(info.max_protection & VM_PROT_WRITE)) {
            *error = KERN_PROTECTION_FAILURE; goto attempt_failed;
        }
        *stage = 4;
        if (!jit_required_range(pool.rx, size, JIT_REQUIRED_RX_TAG, VM_PROT_NONE, &pool.rx_object)) {
            *error = KERN_INVALID_ADDRESS; goto attempt_failed;
        }
        address = (vm_address_t)pool.rx;
        kr = vm_remap(mach_task_self(), &address, (vm_size_t)size, 0,
                       VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                       mach_task_self(), (vm_address_t)pool.temporary, FALSE,
                       &current, &maximum, VM_INHERIT_NONE);
        *error = kr;
        if (kr != KERN_SUCCESS || (uint64_t)address != pool.rx) goto attempt_failed;
        pool.rx_installed = 1;
        /* User remap flags cannot request a VM alias tag. Record the actual
         * tag of this known atomic replacement (some kernels inherit the
         * source tag, others use their own), then bind its object identity. */
        kr = jit_required_region(pool.rx, &source, &length, &info);
        if (kr != KERN_SUCCESS || (uint64_t)source > pool.rx) {
            *error = kr == KERN_SUCCESS ? KERN_INVALID_ADDRESS : kr; goto attempt_failed;
        }
        pool.rx_tag = info.user_tag;
        if (!jit_required_capture(pool.rx, size, (int)pool.rx_tag,
                                  VM_PROT_READ | VM_PROT_EXECUTE, &pool.rx_object) ||
            !jit_required_capture(pool.temporary, size, (int)pool.temporary_tag,
                                  VM_PROT_READ | VM_PROT_EXECUTE, &pool.temporary_object) ||
            pool.rx_object != pool.temporary_object) {
            *error = KERN_FAILURE; goto attempt_failed;
        }
        *stage = 7;
        {
            struct timespec begin_time = {0}, end_time = {0};
            uint64_t prepared;
            uint64_t elapsed = 0;
            int clock_ok = clock_gettime(CLOCK_MONOTONIC, &begin_time) == 0;
            prepared = (uint64_t)(uintptr_t)jit26_pool_prepare((void *)(uintptr_t)pool.rx, (size_t)size);
            clock_ok = (clock_gettime(CLOCK_MONOTONIC, &end_time) == 0) && clock_ok;
            if (clock_ok && (end_time.tv_sec > begin_time.tv_sec ||
                            (end_time.tv_sec == begin_time.tv_sec && end_time.tv_nsec >= begin_time.tv_nsec))) {
                int64_t nanoseconds = (int64_t)(end_time.tv_sec - begin_time.tv_sec) * INT64_C(1000000000)
                                      + end_time.tv_nsec - begin_time.tv_nsec;
                elapsed = (uint64_t)nanoseconds / 1000000;
            } else clock_ok = 0;
            jit_log("[jit-placement-v1] prepare mode=%s pages=%llu elapsed-ms=%llu clock=%s result=%s",
                    pool.rx + size <= UINT64_C(0x1000000000) ? "native-batched" : "wide-serial",
                    (unsigned long long)(size / JIT_REQUIRED_PAGE), (unsigned long long)elapsed,
                    clock_ok ? "monotonic" : "unavailable",
                    prepared == pool.rx ? "accepted" : "failed");
            /* A debugger write may legitimately COW each RX page. Capture
             * that authorized outcome, including partial failed prepares,
             * before making RW aliases. No pointer is published yet. */
            if (!jit_required_snapshot_capture(pool.rx, size, -1, -1, &pool.rx_snapshot)) {
                *error = KERN_INVALID_ADDRESS; goto attempt_failed;
            }
            if (prepared != pool.rx ||
                !jit_required_snapshot_matches(pool.rx, size, -1,
                                                VM_PROT_READ | VM_PROT_EXECUTE, pool.rx_snapshot)) {
                *error = KERN_FAILURE; goto attempt_failed;
            }
        }
        *stage = 5;
        if (!jit_required_range(pool.rw, size, JIT_REQUIRED_RW_TAG, VM_PROT_NONE, &pool.rw_object) ||
            !jit_required_snapshot_matches(pool.rx, size, -1,
                                            VM_PROT_READ | VM_PROT_EXECUTE, pool.rx_snapshot)) {
            *error = KERN_INVALID_ADDRESS; goto attempt_failed;
        }
        address = (vm_address_t)pool.rw;
        kr = vm_remap(mach_task_self(), &address, (vm_size_t)size, 0,
                       VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                       mach_task_self(), (vm_address_t)pool.rx, FALSE,
                       &current, &maximum, VM_INHERIT_NONE);
        *error = kr;
        if (kr != KERN_SUCCESS || (uint64_t)address != pool.rw) goto attempt_failed;
        /* Until the protect succeeds, this destination still has RX rights. */
        pool.rw_installed = 2;
        kr = jit_required_region(pool.rw, &source, &length, &info);
        if (kr != KERN_SUCCESS || (uint64_t)source > pool.rw) {
            *error = kr == KERN_SUCCESS ? KERN_INVALID_ADDRESS : kr; goto attempt_failed;
        }
        pool.rw_tag = info.user_tag;
        pool.rw_object = info.object_id;
        /* vm_remap may materialize shadow objects. Both snapshots describe the
         * result of this known atomic operation, not a guessed single object. */
        if (!jit_required_snapshot_capture(pool.rx, size, -1, -1, &pool.rx_snapshot) ||
            !jit_required_snapshot_capture(pool.rw, size, -1, -1, &pool.rw_snapshot) ||
            !jit_required_snapshot_matches(pool.rx, size, -1,
                                            VM_PROT_READ | VM_PROT_EXECUTE, pool.rx_snapshot) ||
            !jit_required_snapshot_matches(pool.rw, size, -1,
                                            VM_PROT_READ | VM_PROT_EXECUTE, pool.rw_snapshot)) {
            *error = KERN_FAILURE; goto attempt_failed;
        }
        *stage = 6;
        kr = vm_protect(mach_task_self(), (vm_address_t)pool.rw, (vm_size_t)size, FALSE,
                        VM_PROT_READ | VM_PROT_WRITE);
        *error = kr;
        if (kr != KERN_SUCCESS) goto attempt_failed;
        pool.rw_installed = 1;
        if (!jit_required_snapshot_matches(pool.rx, size, -1, VM_PROT_READ | VM_PROT_EXECUTE, pool.rx_snapshot) ||
            !jit_required_snapshot_matches(pool.rw, size, -1, VM_PROT_READ | VM_PROT_WRITE, pool.rw_snapshot)) {
            *error = KERN_PROTECTION_FAILURE; goto attempt_failed;
        }
        *stage = 8;
        if (!jit_required_snapshot_matches(pool.rx, size, -1, VM_PROT_READ | VM_PROT_EXECUTE, pool.rx_snapshot) ||
            !jit_required_snapshot_matches(pool.rw, size, -1, VM_PROT_READ | VM_PROT_WRITE, pool.rw_snapshot) ||
            !jit_required_aliases_match(&pool)) {
            *error = KERN_PROTECTION_FAILURE; goto attempt_failed;
        }
        *stage = 12;
        if (!jit_required_execute_pages(pool.rx, pool.rw, pool.size)) {
            *error = KERN_PROTECTION_FAILURE; goto attempt_failed;
        }
        *stage = 9;
        if (!jit_required_range(pool.temporary, size, (int)pool.temporary_tag,
                                VM_PROT_READ | VM_PROT_EXECUTE, &pool.temporary_object)) {
            *error = KERN_INVALID_ADDRESS; goto attempt_failed;
        }
        kr = vm_deallocate(mach_task_self(), (vm_address_t)pool.temporary, (vm_size_t)size);
        *error = kr;
        if (kr != KERN_SUCCESS) goto attempt_failed;
        pool.temporary = 0;
        /* Startup-only exact ownership metadata is no longer needed: published
         * pools are never reclaimed by this module. Keep its steady footprint
         * independent of how many VM objects debugger preparation produced. */
        free(pool.rx_snapshot); pool.rx_snapshot = NULL;
        free(pool.rw_snapshot); pool.rw_snapshot = NULL;
        pool.state = 3;
        pthread_mutex_lock(&jit_required_mutex);
        jit_required_pool = pool;
        pthread_mutex_unlock(&jit_required_mutex);
        *rx = pool.rx; *rw = pool.rw; *stage = 10; *error = KERN_SUCCESS;
        jit_log("[jit-placement-v1] ready bytes=0x%llx RX=0x%llx RW=0x%llx sharing=verified exec-pages=%llu temporary=released",
                (unsigned long long)size, (unsigned long long)*rx, (unsigned long long)*rw,
                (unsigned long long)(size / JIT_REQUIRED_PAGE));
        return true;

attempt_failed:
        jit_log("[jit-placement-v1] failed attempt=%u stage=%u error=%d cleanup=checking-owned",
                attempt + 1, *stage, *error);
        if (avoid_count < 6) avoid[avoid_count++] = (struct jit_required_avoid){pool.rx, size};
        if (avoid_count < 6) avoid[avoid_count++] = (struct jit_required_avoid){pool.rw, size};
        /* If protection failed during setup, the alias legitimately still has
         * RX current rights. Track that exact state for safe cleanup. */
        if (!jit_required_drop(&pool)) { *stage = 9; *error = KERN_FAILURE; goto failed; }
        memset(&pool, 0, sizeof(pool));
    }
failed:
    pthread_mutex_lock(&jit_required_mutex);
    if (pool.rx || pool.rw || pool.temporary || pool.fex) { pool.state = 4; jit_required_pool = pool; }
    else memset(&jit_required_pool, 0, sizeof(jit_required_pool));
    pthread_mutex_unlock(&jit_required_mutex);
    return false;
}

static void jit_required_early_hold(void)
{
    struct jit_required_pool pool;
    int32_t error = KERN_SUCCESS;
    int held = jit_required_hold(&pool, JIT_REQUIRED_BYTES, UINT64_C(0x140000000),
                                  UINT64_C(0x8000000), NULL, 0, &error);
    if (held > 0) jit_required_pool = pool;
    else if (held < 0) { pool.state = 4; jit_required_pool = pool; }
}
/* END REQUIRED POOL PLACEMENT */

/* ml1040: CLAIM THE LOW GAP AT IMAGE LOAD.
 *
 * On the iPhone 18 Pro everything that must live low -- the 0x140000000 window
 * for a non-relocatable main image, and the RX JIT pool, which the debugger
 * places first-fit with no address hint -- competes for one gap of roughly
 * 1.4GB between the app image and the malloc zones. By the time the user taps
 * launch, our own process has allocated into that gap, differently every time:
 *
 *   launch A:  505MB | window | 628MB | 261MB            -> 608MB pool
 *   launch B:  476MB | window | 604MB | 286MB            -> 592MB pool
 *   launch C:  463MB | window | 349MB | 181MB | 329MB    -> 448MB pool, and the
 *              image head alone filled it (397MB) before the game started:
 *              "[jit-pool] EXHAUSTED ... FAILING the load" x4, shell32 then ran
 *              from its un-pooled address (AV EXEC) and the process died.
 *
 * In launch C a 31MB runtime allocation had landed at 0x15dd00000, in the
 * middle of the hole the pool needs. We cannot stop the runtime allocating, but
 * we can get there first: a constructor runs before main, before SwiftUI, Metal
 * or the log store exist. Hold the window, then hold the largest contiguous run
 * directly above it. Both are PROT_NONE reservations and cost no memory.
 * StikJITHelper releases the pool placeholder immediately before asking the
 * debugger for RX, and plugs any lower hole that would win first-fit. */
#include <mach/mach.h>
unsigned long madeira_early_window_base, madeira_early_window_size;
unsigned long madeira_early_pool_base, madeira_early_pool_size;
unsigned long madeira_early_intruder_base, madeira_early_intruder_size;   /* ml1135 */
unsigned madeira_early_intruder_tag, madeira_early_intruder_prot;

/* BEGIN LEGACY POOL OWNERSHIP */
#define JIT_LEGACY_POOL_TAG 250
static uint64_t jit_legacy_pool_object;
static unsigned jit_legacy_pool_state;

bool jit_legacy_pool_release_owned(int32_t *error)
{
    int ok = 1;
    if (!error) return false;
    *error = KERN_SUCCESS;
    pthread_mutex_lock(&jit_required_mutex);
    if (jit_legacy_pool_state == 2 || !madeira_early_pool_base) {
        pthread_mutex_unlock(&jit_required_mutex);
        return true;
    }
    if (jit_legacy_pool_state != 1 || !jit_legacy_pool_object ||
        !jit_required_range((uint64_t)madeira_early_pool_base,
                             (uint64_t)madeira_early_pool_size,
                             JIT_LEGACY_POOL_TAG, VM_PROT_NONE, &jit_legacy_pool_object)) {
        *error = KERN_INVALID_ADDRESS;
        ok = 0;
    } else {
        *error = vm_deallocate(mach_task_self(), (vm_address_t)madeira_early_pool_base,
                                (vm_size_t)madeira_early_pool_size);
        if (*error == KERN_SUCCESS) jit_legacy_pool_state = 2;
        else ok = 0;
    }
    pthread_mutex_unlock(&jit_required_mutex);
    return ok != 0;
}
/* END LEGACY POOL OWNERSHIP */

/* Read-only views of the above, for callers that cannot take a mutable global.
 * The values are written once by the constructor below, before main runs, and
 * never change afterwards -- so this is an access-shape fix, not a lock. */
void madeira_early_pool_placeholder(unsigned long *base, unsigned long *size) {
    if (base) *base = madeira_early_pool_base;
    if (size) *size = madeira_early_pool_size;
}

void madeira_early_pool_intruder(unsigned long *base, unsigned long *size, unsigned *tag) {
    if (base) *base = madeira_early_intruder_base;
    if (size) *size = madeira_early_intruder_size;
    if (tag)  *tag  = madeira_early_intruder_tag;
}

__attribute__((constructor(101), used)) static void madeira_early_va_claim(void)
{
    const vm_address_t win = 0x140000000ul, winsz = 0x8000000ul;       /* 128MB, see ml1037 */
    vm_address_t a = win;
    vm_size_t sz;

    if (vm_allocate(mach_task_self(), &a, winsz, VM_FLAGS_FIXED) == KERN_SUCCESS && a == win) {
        vm_protect(mach_task_self(), a, winsz, 0, VM_PROT_NONE);
        madeira_early_window_base = win; madeira_early_window_size = winsz;
    }
    /* Largest no-overwrite run starting at the window's end, 16MB granularity. */
    for (sz = 1024ul << 20; sz >= (256ul << 20); sz -= (16ul << 20)) {
        a = win + winsz;
        if (vm_allocate(mach_task_self(), &a, sz,
                         VM_FLAGS_FIXED | VM_MAKE_TAG((unsigned)JIT_LEGACY_POOL_TAG)) == KERN_SUCCESS && a == win + winsz) {
            unsigned char zero = 0;
            kern_return_t kr = vm_write(mach_task_self(), a, (vm_offset_t)(uintptr_t)&zero, 1);
            if (kr == KERN_SUCCESS &&
                jit_required_capture((uint64_t)a, (uint64_t)sz, JIT_LEGACY_POOL_TAG,
                                      VM_PROT_READ | VM_PROT_WRITE, &jit_legacy_pool_object) &&
                jit_legacy_pool_object &&
                vm_protect(mach_task_self(), a, sz, 0, VM_PROT_NONE) == KERN_SUCCESS &&
                jit_required_range((uint64_t)a, (uint64_t)sz, JIT_LEGACY_POOL_TAG,
                                    VM_PROT_NONE, &jit_legacy_pool_object)) {
                madeira_early_pool_base = a; madeira_early_pool_size = sz;
                jit_legacy_pool_state = 1;
                break;
            }
            /* A newly allocated but unverified extent is never advertised as
             * an owned legacy placeholder or retried over somebody's mapping. */
            if (jit_legacy_pool_object &&
                jit_required_range((uint64_t)a, (uint64_t)sz, JIT_LEGACY_POOL_TAG,
                                    -1, &jit_legacy_pool_object) &&
                vm_deallocate(mach_task_self(), a, sz) == KERN_SUCCESS) continue;
            madeira_early_pool_base = a; madeira_early_pool_size = sz;
            jit_legacy_pool_state = 3;
            break;
        }
    }
    /* Preserve the legacy low placeholder for other games, but independently
     * own BOTH full-size CS2 destinations before SwiftUI/Metal initialization.
     * They remain mapped until the debugger-backed object atomically replaces
     * each owned placeholder; there is no unmap-and-first-fit handoff. */
    jit_required_early_hold();
    /* ml1135: NAME what blocked it. ph-rdr90 got no placeholder because a ~31MB
     * mapping already sat at ~0x157d00000 before this constructor ran, leaving
     * 253MB above the window; the pool fell back to a 432MB hole below it and FEX
     * rolled its code cache over 52 times (a ~1 s freeze each). Record the first
     * mapped region above the window so the log can say what it is.
     * madeira-bcd: also when a placeholder was obtained -- it ends where the first
     * mapping above it starts (normally the main thread's stack, VM tag 30; on
     * RDR2's build 470 run a 71MB mapping at 0x159d00000 cut it to 272MB and the
     * pool to 604MB). */
    {
        vm_address_t ra = win + winsz + (vm_address_t)madeira_early_pool_size;
        vm_size_t rs = 0;
        natural_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (vm_region_recurse_64(mach_task_self(), &ra, &rs, &depth, (vm_region_recurse_info_t)&info, &cnt) == KERN_SUCCESS
            && ra < 0x190000000ul) {
            madeira_early_intruder_base = ra; madeira_early_intruder_size = rs;
            madeira_early_intruder_tag = info.user_tag; madeira_early_intruder_prot = (unsigned)info.protection;
        }
    }
}

/* ml1249: METAL API VALIDATION ON DEMAND.
 *
 * `metal-validation = 1` in Documents/madeira.cfg turns on Metal's own debug
 * layer for this launch, reporting instead of aborting, and routes NSLog to
 * stderr so the reports land in the Madeira log. It has to be in the
 * environment before the first MTLDevice exists, and the app makes one for its
 * CAMetalLayer long before madeira.cfg is otherwise read -- hence a
 * constructor. Expensive: diagnostic runs only. */
__attribute__((constructor(102), used)) static void madeira_metal_validation_opt_in(void)
{
    /* Metal API validation for this launch (debug layer, reports instead of aborts). */
    if (!madeira_cfg_bool("metal-validation", 0)) return;
    setenv("MTL_DEBUG_LAYER", "1", 1);
    setenv("MTL_DEBUG_LAYER_ERROR_MODE", "nslog", 1);
    setenv("MTL_DEBUG_LAYER_WARNING_MODE", "nslog", 1);
    setenv("CFLOG_FORCE_STDERR", "1", 1);
}
