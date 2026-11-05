/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Read-only metadata for the actual ThreadedValidateFiles worker's completed
 * regular-file reads. Included only in the staged ntdll file.c. Byte totals
 * include rereads; offset advances are observations, never unique coverage.
 * The first four reads of a tracked file epoch share a 64-line initial quota,
 * leaving room for five-second summaries within the 128-line process-wide
 * ceiling. A bounded FIFO retains the latest 32 identities; an evicted file's
 * next observation starts a labeled epoch with fresh per-file counters. */
#ifndef MADEIRA_STEAM_VALIDATION_TRACE_H
#define MADEIRA_STEAM_VALIDATION_TRACE_H
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

extern int ios_steam_validation_active(void);

struct ios_validation_file
{
    dev_t dev;
    ino_t ino;
    uint64_t epoch, bytes, reads, advances, repeats, rewinds, unknown, high_end;
    int64_t last_offset;
    unsigned int last_length;
    int used, last_known;
};
static __thread struct
{
    struct ios_validation_file files[32];
    uint64_t bytes, reads, advances, repeats, rewinds, unknown, files_seen, file_evictions;
    uint64_t last_report_ms;
    unsigned int next_slot;
    int clock_started;
} ios_validation_state;
static unsigned int ios_validation_lines, ios_validation_initial_lines;

static int ios_validation_reserve_line( unsigned int *counter, unsigned int limit )
{
    unsigned int value = __atomic_load_n( counter, __ATOMIC_RELAXED );
    while (value < limit)
        if (__atomic_compare_exchange_n( counter, &value, value + 1, 0,
                                         __ATOMIC_RELAXED, __ATOMIC_RELAXED )) return 1;
    return 0;
}

static void ios_validation_basename( int fd, char *name, size_t capacity )
{
    char path[PATH_MAX];
    const char *base;
    size_t i = 0;
#ifdef F_GETPATH
    if (fcntl( fd, F_GETPATH, path ) == -1) { snprintf( name, capacity, "unknown" ); return; }
#else
    char link[64];
    ssize_t n;
    snprintf( link, sizeof(link), "/proc/self/fd/%d", fd );
    if ((n = readlink( link, path, sizeof(path) - 1 )) < 0)
    { snprintf( name, capacity, "unknown" ); return; }
    path[n] = 0;
#endif
    base = strrchr( path, '/' ); base = base ? base + 1 : path;
    while (base[i] && i + 1 < capacity)
    {
        unsigned char c = (unsigned char)base[i];
        name[i++] = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' ? c : '_';
    }
    name[i] = 0;
}

static void ios_steam_validation_read_note( int fd, unsigned int got, const LARGE_INTEGER *offset )
{
    struct ios_validation_file *file = NULL;
    struct stat st;
    struct timespec ts;
    uint64_t now = 0, end = 0;
    int saved_errno = errno, known = offset && offset->QuadPart >= 0;
    int periodic = 0, sample = 0;
    unsigned int i;
    char name[96], position[64];
    TEB *teb;

    if (!ios_steam_validation_active() || !got ||
        __atomic_load_n( &ios_validation_lines, __ATOMIC_RELAXED ) >= 128) return;
    if (fstat( fd, &st ) == -1 || !S_ISREG( st.st_mode )) goto out;
    for (i = 0; i < 32; i++)
        if (ios_validation_state.files[i].used && ios_validation_state.files[i].dev == st.st_dev &&
            ios_validation_state.files[i].ino == st.st_ino) { file = &ios_validation_state.files[i]; break; }
    if (!file)
    {
        file = &ios_validation_state.files[ios_validation_state.next_slot];
        ios_validation_state.next_slot = (ios_validation_state.next_slot + 1) % 32;
        if (file->used) ios_validation_state.file_evictions++;
        memset( file, 0, sizeof(*file) );
        file->used = 1; file->dev = st.st_dev; file->ino = st.st_ino;
        file->epoch = ++ios_validation_state.files_seen;
    }
    ios_validation_state.bytes += got;
    ios_validation_state.reads++;
    if (!known) ios_validation_state.unknown++;
    if (file)
    {
        file->bytes += got;
        file->reads++;
        if (known)
        {
            end = (uint64_t)offset->QuadPart + got;
            if (end > file->high_end) file->high_end = end;
            if (file->last_known)
            {
                if (offset->QuadPart > file->last_offset) { file->advances++; ios_validation_state.advances++; }
                else if (offset->QuadPart < file->last_offset) { file->rewinds++; ios_validation_state.rewinds++; }
                else if (got == file->last_length) { file->repeats++; ios_validation_state.repeats++; }
            }
            file->last_offset = offset->QuadPart;
            file->last_length = got;
        }
        else file->unknown++;
        file->last_known = known;
        sample = file->reads <= 4;
    }
    if (!clock_gettime( CLOCK_MONOTONIC, &ts ) && ts.tv_sec >= 0)
    {
        now = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
        if (!ios_validation_state.clock_started)
        { ios_validation_state.clock_started = 1; ios_validation_state.last_report_ms = now; }
        else if (now >= ios_validation_state.last_report_ms && now - ios_validation_state.last_report_ms >= 5000)
            periodic = 1;
    }
    if (periodic) ios_validation_state.last_report_ms = now;
    else if (!sample || !ios_validation_reserve_line( &ios_validation_initial_lines, 64 )) goto out;
    if (!ios_validation_reserve_line( &ios_validation_lines, 128 )) goto out;
    ios_validation_basename( fd, name, sizeof(name) );
    if (known) snprintf( position, sizeof(position), "explicit:%llu", (unsigned long long)offset->QuadPart );
    else snprintf( position, sizeof(position), "current-position-unknown" );
    teb = NtCurrentTeb();
    dprintf( 2, "[steam-validation] kind=%s pid=%04x tid=%04x owner=%p file=%s dev=%llu ino=%llu size=%lld "
                "offset=%s got=%u file-reads=%llu file-bytes=%llu high-end=%llu tracked-advances=%llu "
                "tracked-repeats=%llu tracked-rewinds=%llu unknown-reads=%llu total-reads=%llu total-bytes=%llu "
                "file-epoch=%llu file-evictions=%llu coverage=not-inferred\n",
             periodic ? "periodic" : "sample", (unsigned)(ULONG_PTR)teb->ClientId.UniqueProcess,
             (unsigned)(ULONG_PTR)teb->ClientId.UniqueThread, teb->Peb, name,
             (unsigned long long)st.st_dev, (unsigned long long)st.st_ino, (long long)st.st_size,
             position, got, (unsigned long long)(file ? file->reads : 0),
             (unsigned long long)(file ? file->bytes : 0), (unsigned long long)(file ? file->high_end : 0),
             (unsigned long long)ios_validation_state.advances, (unsigned long long)ios_validation_state.repeats,
             (unsigned long long)ios_validation_state.rewinds, (unsigned long long)ios_validation_state.unknown,
             (unsigned long long)ios_validation_state.reads, (unsigned long long)ios_validation_state.bytes,
             (unsigned long long)file->epoch, (unsigned long long)ios_validation_state.file_evictions );
out:
    errno = saved_errno;
}
#endif
