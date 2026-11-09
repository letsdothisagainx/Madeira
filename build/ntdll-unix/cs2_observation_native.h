/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Native adapters only. Guest metadata is copied through the supplied bounded
 * read operation; a failed observation never changes a loader result. */
#ifndef MADEIRA_CS2_OBSERVATION_NATIVE_H
#define MADEIRA_CS2_OBSERVATION_NATIVE_H
extern unsigned long long ios_thread_process_try_observation_lease(void *, unsigned);

static int ios_cs2_copy(const void *source, void *target, size_t size)
{
    if (!source || size > UINTPTR_MAX - (uintptr_t)source) return 0;
    return MADEIRA_CS2_READ(source, target, size);
}

static size_t ios_cs2_copy_string(const UNICODE_STRING *description, uint16_t *target, size_t capacity)
{
    if ((description->Length & 1) || description->Length > description->MaximumLength ||
        description->Length / 2 >= capacity || !description->Length ||
        !ios_cs2_copy(description->Buffer, target, description->Length)) return 0;
    return description->Length / 2;
}

struct ios_cs2_context {
    void *owner;
    uint32_t pid, tid;
    uint64_t lease;
    size_t image_length;
    uint16_t image[IOS_CS2_PATH];
    UNICODE_STRING command;
};

static int ios_cs2_current_context(struct ios_cs2_context *context, int require_registered)
{
    TEB *teb = NtCurrentTeb();
    RTL_USER_PROCESS_PARAMETERS *parameters;
    UNICODE_STRING image;
    uintptr_t address;
    if (!teb || !(context->owner = teb->Peb)) return 0;
    context->pid = (uint32_t)(uintptr_t)teb->ClientId.UniqueProcess;
    context->tid = (uint32_t)(uintptr_t)teb->ClientId.UniqueThread;
    if (!context->pid || !context->tid) return 0;
    if (require_registered)
    {
        unsigned i;
        struct ios_cs2_process *state;
        /* Foreign processes and exhausted observers do no guest memory reads
         * and take no owner-registry lock. This is only a prefilter; the exact
         * existing lease and current image role are still checked below. */
        for (i = 0; i < 4; i++)
            if (__atomic_load_n(&ios_cs2_processes[i].owner, __ATOMIC_ACQUIRE) == context->owner &&
                ios_cs2_processes[i].pid == context->pid &&
                (require_registered != 1 || __atomic_load_n(&ios_cs2_processes[i].maps, __ATOMIC_RELAXED) < IOS_CS2_MAPS) &&
                (require_registered != 2 || !__atomic_load_n(&ios_cs2_processes[i].debug_observed, __ATOMIC_RELAXED))) break;
        if (i == 4 || !(context->lease = ios_thread_process_try_observation_lease(context->owner, context->pid)) ||
            !(state = ios_cs2_find(context->owner, context->pid, context->lease)) ||
            (require_registered == 1 && __atomic_load_n(&state->maps, __ATOMIC_RELAXED) >= IOS_CS2_MAPS) ||
            (require_registered == 2 && __atomic_load_n(&state->debug_observed, __ATOMIC_RELAXED))) return 0;
    }
    address = (uintptr_t)context->owner;
    if (address > UINTPTR_MAX - offsetof(PEB, ProcessParameters) ||
        !ios_cs2_copy((const void *)(address + offsetof(PEB, ProcessParameters)), &parameters, sizeof(parameters)) ||
        !parameters) return 0;
    address = (uintptr_t)parameters;
    if (address > UINTPTR_MAX - sizeof(*parameters) ||
        !ios_cs2_copy((const void *)(address + offsetof(RTL_USER_PROCESS_PARAMETERS, ImagePathName)), &image, sizeof(image))) return 0;
    context->image_length = ios_cs2_copy_string(&image, context->image, IOS_CS2_PATH);
    if (!ios_cs2_role(context->image, context->image_length)) return 0;
    if (!require_registered &&
        !(context->lease = ios_thread_process_try_observation_lease(context->owner, context->pid))) return 0;
    /* A command-line read failure is reported as incomplete at startup. It
     * does not discard independently observed image-map metadata. */
    if (!require_registered)
    {
        memset(&context->command, 0, sizeof(context->command));
        if (!ios_cs2_copy((const void *)(address + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine)),
                         &context->command, sizeof(context->command)))
            memset(&context->command, 0, sizeof(context->command));
    }
    return 1;
}

#define IOS_CS2_COMMAND 2048
static void ios_cs2_observe_debug(const struct ios_cs2_context *context)
{
    struct ios_cs2_process *state = ios_cs2_find(context->owner, context->pid, context->lease);
    uintptr_t address = (uintptr_t)context->owner;
    unsigned char being_debugged;
    uint32_t global_flags;
    char flags[9] = "";
    const char *debugged = "unmeasured", *global = "unmeasured";
    /* Snapshot guest fields only, once after successful observer registration.
     * The Wine IsDebuggerPresent implementation reads this same BOOLEAN, but
     * no guest API is called, no bit is changed, and host debugger attachment
     * or later guest changes are not measured here. Failed/partial copies must
     * never become an observed false/zero result. */
    if (!state || __atomic_exchange_n(&state->debug_observed, 1, __ATOMIC_RELAXED)) return;
    if (address <= UINTPTR_MAX - offsetof(PEB, BeingDebugged) &&
        ios_cs2_copy((const void *)(address + offsetof(PEB, BeingDebugged)), &being_debugged, sizeof(being_debugged)))
        debugged = being_debugged ? "1" : "0";
    if (address <= UINTPTR_MAX - offsetof(PEB, NtGlobalFlag) &&
        ios_cs2_copy((const void *)(address + offsetof(PEB, NtGlobalFlag)), &global_flags, sizeof(global_flags)))
    {
        snprintf(flags, sizeof(flags), "%08x", (unsigned)global_flags);
        global = flags;
    }
    MADEIRA_CS2_EMIT("[cs2-guest-debug-v1] pid=%04x tid=%04x being-debugged=%s nt-global-flag=%s limit=1-per-process coverage=accepted-post-server-init-snapshot evidence=fault-safe-peb-read-only scope=guest-peb-fields-only\n",
        context->pid, context->tid, debugged, global);
}

/* Keep the bounded command copy out of every foreign process's startup frame.
 * Overlong commands remain unmeasured/incomplete rather than parsing a prefix
 * as a complete token. No allocation, guest write or startup retry loop. */
static __attribute__((noinline)) void ios_cs2_start_with_context(const struct ios_cs2_context *context, unsigned machine)
{
    uint16_t command[IOS_CS2_COMMAND];
    size_t length = ios_cs2_copy_string(&context->command, command, IOS_CS2_COMMAND);
    ios_cs2_record_start(context->owner, context->pid, context->tid, context->lease,
        context->image, context->image_length, command, length, getenv("WINEDLLPATH"));
    ios_cs2_record_map(context->owner, context->pid, context->tid, context->lease,
        context->image, context->image_length, context->image, context->image_length, machine, -1, -1, 1);
}

void ios_cs2_observe_current_start(unsigned machine)
{
    int saved_errno = errno;
    struct ios_cs2_context context;
    if (ios_cs2_current_context(&context, 0))
    {
        if (!ios_cs2_find(context.owner, context.pid, context.lease)) ios_cs2_start_with_context(&context, machine);
    }
    errno = saved_errno;
}

void ios_cs2_observe_current_debug(void)
{
    int saved_errno = errno;
    struct ios_cs2_context context;
    /* init_process_done can set BeingDebugged. Observe only after its server
     * reply, before guest entry, through the already registered owner lease. */
    if (ios_cs2_current_context(&context, 2)) ios_cs2_observe_debug(&context);
    errno = saved_errno;
}

void ios_cs2_observe_current_map(const void *name, unsigned machine, int hybrid, int wine_builtin)
{
    int saved_errno = errno;
    struct ios_cs2_context context;
    UNICODE_STRING description;
    uint16_t path[IOS_CS2_PATH];
    size_t length = 0;
    if (ios_cs2_current_context(&context, 1))
    {
        if (ios_cs2_copy(name, &description, sizeof(description)))
            length = ios_cs2_copy_string(&description, path, IOS_CS2_PATH);
        ios_cs2_record_map(context.owner, context.pid, context.tid, context.lease,
            context.image, context.image_length, path, length, machine, hybrid, wine_builtin, 0);
    }
    errno = saved_errno;
}
#endif
