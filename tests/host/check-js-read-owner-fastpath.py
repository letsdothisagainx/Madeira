#!/usr/bin/env python3
"""Actual read observer: reject unrelated owners before Steam JS locking."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / 'build/ntdll-unix/js_read_trace.h'
GUARD = '''    if (!got || !__atomic_load_n( &ios_js_track_any, __ATOMIC_ACQUIRE ) ||
        !ios_js_owner_possible( owner )) return;'''
OLD_GUARD = '    if (!got || !__atomic_load_n( &ios_js_track_any, __ATOMIC_RELAXED )) return;'

SOURCE = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
typedef void *HANDLE;
typedef unsigned long ULONG;
typedef unsigned int UINT;
typedef union { long long QuadPart; } LARGE_INTEGER;
typedef struct { void *Peb; } TEB;
static _Thread_local TEB teb;
#define NtCurrentTeb() (&teb)
static unsigned long locks, stats;
static int counted_lock(pthread_mutex_t *mutex)
{
    __atomic_add_fetch(&locks, 1, __ATOMIC_RELAXED);
    return pthread_mutex_lock(mutex);
}
static int counted_fstat(int fd, struct stat *st)
{
    __atomic_add_fetch(&stats, 1, __ATOMIC_RELAXED);
    return fstat(fd, st);
}
#define pthread_mutex_lock counted_lock
#define fstat counted_fstat
#include "HEADER"
#undef pthread_mutex_lock
#undef fstat

static const uintptr_t steam_owner = UINT64_C(0x7200310000);
static uintptr_t game_owner = UINT64_C(0x107c94000);
static int asset_fd;
static HANDLE handle = (HANDLE)0x88;
static unsigned char reference[64];
static int worker_started, worker_done;

static struct ios_js_entry *entry(uintptr_t owner, HANDLE h)
{
    for (unsigned int i = 0; i < IOS_JSTRACK_MAX; i++)
        if (ios_js_track[i].generation && ios_js_track[i].owner == owner && ios_js_track[i].handle == h)
            return &ios_js_track[i];
    return NULL;
}

static void real_read_note(int fd, HANDLE h)
{
    unsigned char bytes[64];
    LARGE_INTEGER offset = {.QuadPart = 0};
    assert(pread(fd, bytes, sizeof(bytes), 0) == sizeof(bytes));
    assert(!memcmp(bytes, reference, sizeof(bytes)));
    errno = EHOSTUNREACH;
    ios_js_read_note(h, fd, bytes, sizeof(bytes), sizeof(bytes), &offset);
    assert(errno == EHOSTUNREACH);
}

static void *asset_worker(void *unused)
{
    (void)unused;
    teb.Peb = (void *)game_owner;
    __atomic_store_n(&worker_started, 1, __ATOMIC_RELEASE);
    real_read_note(asset_fd, handle);
    __atomic_store_n(&worker_done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void *publish_worker(void *name)
{
    teb.Peb = (void *)game_owner;
    ios_js_track_add(handle, name);
    return NULL;
}

int main(int argc, char **argv)
{
    char path[1024], other[1024];
    pthread_t worker;
    struct timespec pause = {0, 1000000};
    assert(argc == 2);
    snprintf(path, sizeof(path), "%s/steamui-library.js", argv[1]);
    snprintf(other, sizeof(other), "%s/steamui-other.js", argv[1]);
    asset_fd = open(path, O_CREAT | O_RDWR, 0600);
    int other_fd = open(other, O_CREAT | O_RDWR, 0600);
    assert(asset_fd >= 0 && other_fd >= 0);
    for (unsigned int i = 0; i < sizeof(reference); i++) reference[i] = (unsigned char)(i * 7 + 3);
    assert(write(asset_fd, reference, sizeof(reference)) == sizeof(reference));
    assert(write(other_fd, reference, sizeof(reference)) == sizeof(reference));

    teb.Peb = (void *)steam_owner;
    ios_js_track_add(handle, path);
    assert(ios_js_owner_possible(steam_owner));
    /* The real recorded owners are distinct filter entries. Keep the fixture
     * independent of the hash choice if a future valid implementation collides. */
    while (ios_js_owner_possible(game_owner)) game_owner += 0x4000;
    teb.Peb = (void *)game_owner;
    locks = stats = 0;
    for (int i = 0; i < 10000; i++) real_read_note(asset_fd, handle);
#if EXPECT_FAST
    assert(locks == 0 && stats == 0);
#else
    assert(locks == 10000 && stats == 0);
#endif
    assert(sizeof(ios_js_owner_filter) == 32);

    /* Hold exactly the production observer's mutex. A real unrelated asset
     * read must complete without waiting for Steam's diagnostic work. The old
     * guard reproduces the block, then still completes honestly after unlock. */
    locks = stats = 0;
    assert(!pthread_mutex_lock(&ios_js_track_lock));
    assert(!pthread_create(&worker, NULL, asset_worker, NULL));
    while (!__atomic_load_n(&worker_started, __ATOMIC_ACQUIRE)) nanosleep(&pause, NULL);
    for (int i = 0; i < 2000; i++)
    {
#if EXPECT_FAST
        if (__atomic_load_n(&worker_done, __ATOMIC_ACQUIRE)) break;
#else
        if (__atomic_load_n(&locks, __ATOMIC_RELAXED)) break;
#endif
        nanosleep(&pause, NULL);
    }
#if EXPECT_FAST
    assert(__atomic_load_n(&worker_done, __ATOMIC_ACQUIRE) && locks == 0);
#else
    assert(__atomic_load_n(&locks, __ATOMIC_RELAXED) == 1 &&
           !__atomic_load_n(&worker_done, __ATOMIC_ACQUIRE));
#endif
    assert(!pthread_mutex_unlock(&ios_js_track_lock));
    assert(!pthread_join(worker, NULL));
    assert(__atomic_load_n(&worker_done, __ATOMIC_ACQUIRE));

    /* An owner rejected above can later open tracked JS on another thread.
     * There is no permanent negative TLS cache and no lost publication. */
    assert(!pthread_create(&worker, NULL, publish_worker, path));
    assert(!pthread_join(worker, NULL));
    assert(ios_js_owner_possible(game_owner));
    struct ios_js_entry *game = entry(game_owner, handle);
    assert(game && game->bytes == 0);
    real_read_note(asset_fd, handle);
    assert(game->bytes == sizeof(reference));
    uint64_t generation = game->generation;
    ios_js_track_add(handle, other);
    assert(game->generation != generation && game->bytes == 0);
    real_read_note(asset_fd, handle); /* same handle, wrong inode: not attributed */
    assert(game->bytes == 0);
    real_read_note(other_fd, handle);
    assert(game->bytes == sizeof(reference));

    /* Bloom collisions are permitted and must fall through to exact owner /
     * handle checks. They can cost a diagnostic lock, never misattribute data. */
    uintptr_t collision = 0;
    for (uintptr_t i = 1; i <= 1000000; i++)
    {
        uintptr_t owner = UINT64_C(0x6000000000) + i * 0x4000;
        if (ios_js_owner_possible(owner)) { collision = owner; break; }
    }
    assert(collision && !entry(collision, handle));
    teb.Peb = (void *)collision;
    locks = stats = 0;
    real_read_note(other_fd, handle);
    assert(locks == 1 && stats == 0 && game->bytes == sizeof(reference));

    /* Owner bits are never cleared when bounded entries are evicted. Earlier
     * owners remain conservatively possible; zero is also a legitimate tag. */
    for (uintptr_t i = 0; i < IOS_JSTRACK_MAX + 8; i++)
    {
        teb.Peb = (void *)(UINT64_C(0x7000000000) + i * 0x4000);
        ios_js_track_add((HANDLE)(0x1000 + i), path);
        assert(ios_js_owner_possible((uintptr_t)teb.Peb));
    }
    assert(ios_js_owner_possible(steam_owner) && ios_js_owner_possible(game_owner));
    teb.Peb = NULL;
    ios_js_track_add(handle, path);
    assert(ios_js_owner_possible(0));
    close(asset_fd); close(other_fd);
#if EXPECT_FAST
    puts("PASS actual JS read observer: 10000 unrelated real preads require zero diagnostic locks/stats; read completes while Steam observer mutex held; later owner publication, handle/inode reuse, collisions and eviction remain correct");
#else
    puts("PASS old-guard negative control: 10000 unrelated reads take 10000 locks and queue behind Steam observer mutex");
#endif
    return 0;
}
'''

cc = os.environ.get('CC') or shutil.which('gcc' if platform.system() == 'Linux' else 'clang') or 'cc'
text = HEADER.read_text()
assert text.count(GUARD) == 1, 'production owner prefilter boundary changed'
with tempfile.TemporaryDirectory() as directory:
    tmp = Path(directory)
    for fast in (0, 1):
        header = tmp / f'observer-{fast}.h'
        header.write_text(text if fast else text.replace(GUARD, OLD_GUARD))
        source = tmp / f'check-{fast}.c'
        source.write_text(SOURCE.replace('HEADER', str(header)))
        exe = tmp / f'check-{fast}'
        subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        f'-DEXPECT_FAST={fast}', str(source), '-o', str(exe)], check=True)
        result = subprocess.run([str(exe), str(tmp)], check=True, timeout=30,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout, end='')
