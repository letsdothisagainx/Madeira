/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Bounded observation of the existing CS2 positional-read path. No file data,
 * private path, guest context, VM protection or completion is changed here.
 */
#ifndef MADEIRA_PREAD_OBSERVATION_H
#define MADEIRA_PREAD_OBSERVATION_H
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef IOS_PREAD_OWNER
#define IOS_PREAD_OWNER ios_pread_capture_owner
#endif
#ifndef IOS_PREAD_BACKING_FD
#define IOS_PREAD_BACKING_FD ios_swap_fd
#endif
#ifndef IOS_PREAD_NOW
static uint64_t ios_pread_now(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
}
#define IOS_PREAD_NOW ios_pread_now
#endif
#ifndef IOS_PREAD_PATH
static int ios_pread_path(int fd, char *out, size_t capacity)
{
#ifdef F_GETPATH
    /* Darwin F_GETPATH requires MAXPATHLEN bytes. Never publish this buffer. */
    if (capacity < 1024) return -1;
    return fcntl(fd, F_GETPATH, out);
#else
    (void)fd; (void)out; (void)capacity;
    return -1;
#endif
}
#define IOS_PREAD_PATH ios_pread_path
#endif

enum ios_pread_route { IOS_PREAD_DIRECT, IOS_PREAD_ALIAS, IOS_PREAD_WRITEWATCH };
struct ios_pread_scope
{
    struct ios_pread_scope *previous;
    uint64_t start, lock_start, lock_acquired, lock_wait, lock_hold, bytes;
    off_t offset, last_offset;
    size_t size;
    ssize_t first_result, last_result;
    unsigned pid, tid, calls;
    int active, first_errno, last_errno, route;
};
static _Thread_local struct ios_pread_scope *ios_pread_active;
static _Thread_local unsigned ios_pread_sequence;
static _Thread_local uint64_t ios_pread_last_line;
static unsigned ios_pread_lines, ios_pread_initial_routes;
#define IOS_PREAD_MAX_LINES 24

static void ios_pread_begin(struct ios_pread_scope *scope, size_t size, off_t offset)
{
    int saved_errno = errno;
    unsigned pid, tid;
    scope->active = 0;
    if (__atomic_load_n(&ios_pread_lines, __ATOMIC_RELAXED) >= IOS_PREAD_MAX_LINES ||
        !IOS_PREAD_OWNER(&pid, &tid)) goto done;
    /* MiB reads are timed until the output cap. Medium reads are sampled one
     * in eight, smaller reads one in 64, after four initial calls/thread.
     * Never add a syscall per byte/page. Ineligible processes do not read a
     * clock or an fd path. Spacing and the lifetime output cap apply below. */
    if (++ios_pread_sequence > 4 && size < 1048576 &&
        (ios_pread_sequence & (size >= 65536 ? 7 : 63))) goto done;
    memset(scope, 0, sizeof(*scope));
    scope->pid = pid; scope->tid = tid;
    scope->size = size; scope->offset = offset;
    if (!(scope->start = IOS_PREAD_NOW())) goto done;
    scope->active = 1;
    scope->previous = ios_pread_active;
    ios_pread_active = scope;
done:
    errno = saved_errno;
}

static ssize_t ios_pread_native(int fd, void *address, size_t size, off_t offset)
{
    ssize_t result = pread(fd, address, size, offset);
    int saved_errno = errno;
    struct ios_pread_scope *scope = ios_pread_active;
    if (scope)
    {
        if (!scope->calls) { scope->first_result = result; scope->first_errno = result < 0 ? saved_errno : 0; }
        scope->calls++;
        scope->last_offset = offset;
        scope->last_result = result;
        scope->last_errno = result < 0 ? saved_errno : 0;
        if (result > 0) scope->bytes += result;
    }
    errno = saved_errno;
    return result;
}

static void ios_pread_lock_start(struct ios_pread_scope *scope)
{
    if (scope->active) scope->lock_start = IOS_PREAD_NOW();
}
static void ios_pread_lock_acquired(struct ios_pread_scope *scope)
{
    if (scope->active) { scope->lock_acquired = IOS_PREAD_NOW(); scope->lock_wait = scope->lock_acquired - scope->lock_start; }
}
static void ios_pread_lock_done(struct ios_pread_scope *scope)
{
    if (scope->active) scope->lock_hold = IOS_PREAD_NOW() - scope->lock_acquired;
}

static const char *ios_pread_file_role(int fd, const struct stat *st)
{
    char path[1024];
    const char *dot;
    if (fd == IOS_PREAD_BACKING_FD) return "madeira-backing";
    if (!S_ISREG(st->st_mode)) return "nonregular";
    if (IOS_PREAD_PATH(fd, path, sizeof(path))) return "regular-unresolved";
    path[sizeof(path)-1] = 0;
    /* These are suffix/directory classifications, never authenticated asset
     * identities. Unknown names and account/device paths remain private. */
    if (strstr(path, "/shadercache/")) return "shader-cache-directory";
    if (strstr(path, "/htmlcache/") || strstr(path, "/cef_cache/")) return "browser-cache-directory";
    dot = strrchr(path, '.');
    if (dot && !strcmp(dot, ".vpk")) return "suffix-vpk";
    if (dot && (!strcmp(dot, ".dll") || !strcmp(dot, ".exe"))) return "suffix-pe";
    return "regular-private";
}

static void ios_pread_end(struct ios_pread_scope *scope, int fd, ssize_t result)
{
    static const char *const routes[] = { "direct", "rw-alias-bounce", "writewatch-retry" };
    uint64_t elapsed, now;
    struct stat st;
    unsigned ticket, bit, initial;
    int saved_errno = errno;
    if (!scope->active) return;
    ios_pread_active = scope->previous;
    now = IOS_PREAD_NOW();
    elapsed = now - scope->start;
    bit = 1u << scope->route;
    /* One initial record per observed route, thereafter only sampled slow
     * reads or real errors. A startup burst cannot spend the slow-read budget
     * in one batch: at most one slow line/thread/two seconds. All output and
     * fd queries also share a fixed lifetime cap. Original errors and the
     * initial route records are never hidden by that spacing rule. */
    initial = !(__atomic_fetch_or(&ios_pread_initial_routes, bit, __ATOMIC_RELAXED) & bit);
    if (result >= 0 && !initial && (elapsed < UINT64_C(5000000) ||
        (ios_pread_last_line && now - ios_pread_last_line < UINT64_C(2000000000)))) goto done;
    ticket = __atomic_fetch_add(&ios_pread_lines, 1, __ATOMIC_RELAXED);
    if (ticket >= IOS_PREAD_MAX_LINES) goto done;
    ios_pread_last_line = now;
    memset(&st, 0, sizeof(st));
    if (fstat(fd, &st)) memset(&st, 0, sizeof(st));
    dprintf(2, "[pread-path-v1] sample=%u pid=%04x tid=%04x fd=%d role=%s "
        "file-id=%llx:%llx offset=%lld requested=%zu result=%lld errno=%d route=%s "
        "native-calls=%u native-bytes=%llu first-result=%lld first-errno=%d "
        "last-offset=%lld last-result=%lld last-errno=%d elapsed-us=%llu vm-lock-wait-us=%llu vm-lock-held-us=%llu\n",
        ticket+1, scope->pid, scope->tid, fd, ios_pread_file_role(fd, &st),
        (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
        (long long)scope->offset, scope->size, (long long)result, result < 0 ? saved_errno : 0,
        routes[scope->route], scope->calls, (unsigned long long)scope->bytes,
        (long long)scope->first_result, scope->first_errno, (long long)scope->last_offset,
        (long long)scope->last_result, scope->last_errno,
        (unsigned long long)(elapsed/1000), (unsigned long long)(scope->lock_wait/1000),
        (unsigned long long)(scope->lock_hold/1000));
done:
    errno = saved_errno;
}
#endif
