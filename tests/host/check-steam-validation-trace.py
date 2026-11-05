#!/usr/bin/env python3
"""Exercise the production validation read observer with real regular files.

The observer records completed read metadata, never unique coverage. Compile
its real header and real thread-name gate under ASan/UBSan, then run the actual
build staging transformation without changing the pinned Wine sources.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
header = root / 'build/ntdll-unix/steam_validation_trace.h'
thread = (root / 'build/ntdll-unix/thread_ios.c').read_text()


def function(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', source[brace:], re.S):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if not depth:
                return source[start:brace + token.end()]
    raise AssertionError(signature)


gate = 'static __thread int ios_steam_validation_worker;\n'
gate += function(thread, 'int ios_steam_validation_active(void)') + '\n'
gate += function(thread, 'static void ios_steam_validation_thread_named(') + '\n'
naming = function(thread, 'static void set_native_thread_name(')
assert 'ios_steam_validation_thread_named( ios_terminate_is_self( handle ), nm );' in naming

source = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
typedef uintptr_t ULONG_PTR;
typedef union { int64_t QuadPart; } LARGE_INTEGER;
typedef struct { struct { void *UniqueProcess, *UniqueThread; } ClientId; void *Peb; } TEB;
static __thread TEB fixture_teb;
#define NtCurrentTeb() (&fixture_teb)
GATE
static uint64_t fake_ms;
static int fake_clock_gettime(clockid_t clock, struct timespec *ts)
{
    assert(clock == CLOCK_MONOTONIC);
    ts->tv_sec = (time_t)(fake_ms / 1000);
    ts->tv_nsec = (long)((fake_ms % 1000) * 1000000);
    return 0;
}
static char captured[131072];
static size_t captured_used;
static unsigned captured_lines;
static int capture_dprintf(int fd, const char *format, ...)
{
    va_list args;
    assert(fd == 2);
    va_start(args, format);
    int n = vsnprintf(captured + captured_used, sizeof(captured) - captured_used, format, args);
    va_end(args);
    assert(n > 0 && (size_t)n < sizeof(captured) - captured_used);
    captured_used += (size_t)n;
    captured_lines++;
    errno = EIO; /* Even a logging failure's errno must not escape. */
    return n;
}
#define clock_gettime fake_clock_gettime
#define dprintf capture_dprintf
#include "HEADER"
#undef dprintf
#undef clock_gettime

static char directory[1024];
static void reset(void)
{
    memset(&ios_validation_state, 0, sizeof(ios_validation_state));
    ios_validation_lines = ios_validation_initial_lines = 0;
    captured_used = captured_lines = 0;
    captured[0] = 0;
    fake_ms = 0;
    fixture_teb.ClientId.UniqueProcess = (void *)0x68;
    fixture_teb.ClientId.UniqueThread = (void *)0x28c;
    fixture_teb.Peb = (void *)0x1043ec000;
    ios_steam_validation_thread_named(1, "ThreadedValidateFiles worker");
    assert(ios_steam_validation_active());
}
static int regular_file(unsigned number)
{
    char path[1200];
    unsigned char payload[4096];
    for (unsigned i = 0; i < sizeof(payload); i++) payload[i] = (unsigned char)(i ^ number);
    snprintf(path, sizeof(path), "%s/validate-private-%u.bin", directory, number);
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    assert(fd >= 0);
    assert(write(fd, payload, sizeof(payload)) == sizeof(payload));
    assert(lseek(fd, 37, SEEK_SET) == 37);
    return fd;
}
static void note(int fd, unsigned length, int64_t offset, int known)
{
    LARGE_INTEGER position = {.QuadPart = offset};
    unsigned char before[4096], after[4096];
    off_t cursor = lseek(fd, 0, SEEK_CUR);
    assert(cursor >= 0);
    assert(pread(fd, before, sizeof(before), 0) == sizeof(before));
    errno = EAGAIN;
    ios_steam_validation_read_note(fd, length, known ? &position : NULL);
    assert(errno == EAGAIN);
    assert(lseek(fd, 0, SEEK_CUR) == cursor);
    assert(pread(fd, after, sizeof(after), 0) == sizeof(after));
    assert(!memcmp(before, after, sizeof(before)));
}
static unsigned used_files(void)
{
    unsigned used = 0;
    for (unsigned i = 0; i < 32; i++) used += ios_validation_state.files[i].used != 0;
    return used;
}
static void check_name_gate(void)
{
    reset();
    ios_steam_validation_thread_named(1, NULL); assert(!ios_steam_validation_active());
    ios_steam_validation_thread_named(0, "ThreadedValidateFiles worker"); assert(!ios_steam_validation_active());
    ios_steam_validation_thread_named(1, "ThreadedValidateFiles worker "); assert(!ios_steam_validation_active());
    ios_steam_validation_thread_named(1, "threadedValidateFiles worker"); assert(!ios_steam_validation_active());
    ios_steam_validation_thread_named(1, "ThreadedValidateFiles"); assert(!ios_steam_validation_active());
    ios_steam_validation_thread_named(1, "ThreadedValidateFiles worker"); assert(ios_steam_validation_active());
    ios_steam_validation_thread_named(0, "another worker"); assert(ios_steam_validation_active());
    ios_steam_validation_thread_named(1, "another worker"); assert(!ios_steam_validation_active());
    int fd = regular_file(1);
    note(fd, 8, 0, 1);
    assert(!captured_lines && !ios_validation_state.reads);
    close(fd);
}
static void check_offsets_and_identity(void)
{
    reset();
    int fd = regular_file(2);
    note(fd, 4, 0, 0);
    assert(ios_validation_state.unknown == 1 && !ios_validation_state.files[0].last_known);
    assert(strstr(captured, "offset=current-position-unknown"));
    note(fd, 8, 0, 1);
    note(fd, 8, 0, 1);
    note(fd, 8, 8, 1);
    note(fd, 4, 2, 1);
    note(fd, 3, -2, 1);
    assert(!ios_validation_state.files[0].last_known);
    note(fd, 5, 25, 1); /* Unknown position broke the comparison chain. */
    note(fd, 5, 30, 1);
    struct ios_validation_file *first = &ios_validation_state.files[0];
    assert(ios_validation_state.reads == 8 && ios_validation_state.bytes == 45);
    assert(ios_validation_state.advances == 2 && ios_validation_state.repeats == 1);
    assert(ios_validation_state.rewinds == 1 && ios_validation_state.unknown == 2);
    assert(first->reads == 8 && first->bytes == 45 && first->high_end == 35);
    assert(first->advances == 2 && first->repeats == 1 && first->rewinds == 1 && first->unknown == 2);
    assert(first->last_offset == 30 && first->last_length == 5 && first->last_known);
    assert(captured_lines == 4 && ios_validation_initial_lines == 4);
    assert(strstr(captured, "pid=0068 tid=028c") && strstr(captured, "owner=0x1043ec000"));
    assert(strstr(captured, "file=validate-private-2.bin") && !strstr(captured, directory));
    assert(strstr(captured, "coverage=not-inferred") && !strstr(captured, "offset=explicit:-"));
    int alias = dup(fd); assert(alias >= 0);
    note(alias, 1, 35, 1); assert(used_files() == 1 && first->reads == 9);
    close(alias);
    ino_t old_inode = first->ino;
    int other = regular_file(3);
    struct stat old_stat, other_stat;
    assert(!fstat(fd, &old_stat) && !fstat(other, &other_stat));
    assert(old_stat.st_dev != other_stat.st_dev || old_stat.st_ino != other_stat.st_ino);
    assert(dup2(other, fd) == fd); close(other);
    note(fd, 6, 0, 1);
    assert(used_files() == 2 && first->ino == old_inode && first->reads == 9);
    assert(ios_validation_state.files[1].reads == 1 && ios_validation_state.files[1].bytes == 6);
    assert(ios_validation_state.files[1].ino == other_stat.st_ino);
    close(fd);
}
static void check_nonfiles_and_errno(void)
{
    reset();
    int pipefd[2]; assert(!pipe(pipefd));
    LARGE_INTEGER offset = {.QuadPart = 0};
    errno = EDOM; ios_steam_validation_read_note(pipefd[0], 1, &offset); assert(errno == EDOM);
    errno = ERANGE; ios_steam_validation_read_note(-1, 1, &offset); assert(errno == ERANGE);
    int fd = regular_file(4);
    errno = EINVAL; ios_steam_validation_read_note(fd, 0, &offset); assert(errno == EINVAL);
    assert(!ios_validation_state.reads && !captured_lines && !used_files());
    close(pipefd[0]); close(pipefd[1]); close(fd);
}
static void check_periodic_and_caps(void)
{
    reset();
    int fd = regular_file(5);
    for (unsigned i = 0; i < 10; i++) note(fd, 1, 0, 1);
    assert(captured_lines == 4);
    fake_ms = 4999; note(fd, 1, 0, 1); assert(captured_lines == 4);
    fake_ms = 5000; note(fd, 1, 0, 1); assert(captured_lines == 5);
    assert(strstr(captured, "kind=periodic") && strstr(captured, "tracked-repeats=11"));
    fake_ms = 9999; note(fd, 1, 0, 1); assert(captured_lines == 5);
    fake_ms = 10000; note(fd, 1, 0, 1); assert(captured_lines == 6);
    close(fd);

    reset();
    for (unsigned n = 0; n < 33; n++)
    {
        fd = regular_file(100 + n);
        for (unsigned i = 0; i < 4; i++) note(fd, 1, i, 1);
        close(fd);
    }
    assert(used_files() == 32 && ios_validation_state.reads == 132);
    assert(ios_validation_state.files_seen == 33 && ios_validation_state.file_evictions == 1);
    assert(ios_validation_state.next_slot == 1);
    struct ios_validation_file *latest = &ios_validation_state.files[0];
    assert(latest->epoch == 33 && latest->reads == 4 && latest->bytes == 4);
    assert(latest->last_offset == 3 && latest->advances == 3 && !latest->repeats);
    assert(captured_lines == 64 && ios_validation_initial_lines == 64 && ios_validation_lines == 64);
    fd = regular_file(132);
    note(fd, 1, 3, 1); /* The 33rd identity still gets repeat/advance tracking. */
    note(fd, 1, 4, 1);
    assert(latest->reads == 6 && latest->repeats == 1 && latest->advances == 4);
    assert(ios_validation_state.files_seen == 33 && ios_validation_state.file_evictions == 1);
    int returned = regular_file(100); /* Reintroduce the first evicted inode. */
    note(returned, 1, 100, 1);
    struct ios_validation_file *again = &ios_validation_state.files[1];
    assert(again->epoch == 34 && again->reads == 1 && again->bytes == 1);
    assert(again->last_offset == 100 && again->high_end == 101);
    assert(!again->advances && !again->repeats && !again->rewinds);
    assert(ios_validation_state.files_seen == 34 && ios_validation_state.file_evictions == 2);
    assert(ios_validation_state.next_slot == 2 && used_files() == 32);
    assert(ios_validation_state.reads == 135 && ios_validation_state.bytes == 135);
    assert(ios_validation_state.advances == 100 && ios_validation_state.repeats == 1);
    assert(captured_lines == 64); /* A new epoch cannot escape the shared sample quota. */
    fake_ms = 5000; note(fd, 1, 5, 1);
    assert(captured_lines == 65 && strstr(captured, "file-epoch=33 file-evictions=2"));
    fake_ms = 10000; note(returned, 1, 100, 1);
    assert(captured_lines == 66 && strstr(captured, "file-epoch=34 file-evictions=2"));
    assert(again->reads == 2 && again->repeats == 1 && ios_validation_state.repeats == 2);
    for (unsigned i = 2; i < 64; i++) { fake_ms += 5000; note(fd, 1, i + 4, 1); }
    assert(captured_lines == 128 && ios_validation_lines == 128 && ios_validation_initial_lines == 64);
    uint64_t reads = ios_validation_state.reads;
    for (unsigned i = 0; i < 20; i++) { fake_ms += 5000; note(fd, 1, i, 1); }
    assert(captured_lines == 128 && ios_validation_state.reads == reads);
    close(returned); close(fd);
}
static void *thread_fixture(void *opaque)
{
    unsigned number = (unsigned)(uintptr_t)opaque;
    assert(!ios_steam_validation_active() && !ios_validation_state.reads);
    ios_steam_validation_thread_named(1, "ThreadedValidateFiles worker");
    int fd = regular_file(number);
    for (unsigned i = 0; i < 4; i++) note(fd, 1, i, 1);
    assert(ios_validation_state.reads == 4 && used_files() == 1);
    ios_steam_validation_thread_named(1, "different job");
    assert(!ios_steam_validation_active());
    close(fd);
    return NULL;
}
static void check_thread_isolation(void)
{
    reset();
    pthread_t first, second;
    assert(!pthread_create(&first, NULL, thread_fixture, (void *)200));
    assert(!pthread_join(first, NULL));
    assert(!pthread_create(&second, NULL, thread_fixture, (void *)201));
    assert(!pthread_join(second, NULL));
    assert(!ios_validation_state.reads && ios_steam_validation_active());
    assert(captured_lines == 8 && ios_validation_initial_lines == 8 && ios_validation_lines == 8);
}
int main(int argc, char **argv)
{
    assert(argc == 2 && strlen(argv[1]) < sizeof(directory));
    strcpy(directory, argv[1]);
    check_name_gate();
    check_offsets_and_identity();
    check_nonfiles_and_errno();
    check_periodic_and_caps();
    check_thread_isolation();
    puts("PASS actual validation observer: exact self-name gating, errno/payload/cursor preservation, real inode identity and descriptor reuse, unknown/explicit offsets, FIFO epochs after 32 identities, 5s summaries, separate 64/128 quotas and thread isolation");
}
'''.replace('GATE', gate).replace('HEADER', str(header))

with tempfile.TemporaryDirectory(prefix='madeira-validation-') as temporary:
    folder = Path(temporary)
    fixture = folder / 'check.c'
    fixture.write_text(source)
    executable = folder / 'check'
    subprocess.run([os.environ.get('CC', shutil.which('clang') or 'cc'), '-std=gnu11', '-O1', '-g',
                    '-Wall', '-Wextra', '-Werror', '-pthread', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', str(fixture), '-o', str(executable)], check=True)
    subprocess.run([str(executable), str(folder)], check=True,
                   env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))

build = (root / 'build/ntdll-unix/build.sh').read_text()
start = build.index('source, output, header = map(Path, sys.argv[1:])')
end = build.index('\nPYCODE', start)
pinned = root / 'wine/dlls/ntdll/unix/file.c'
unchanged = pinned.read_bytes()
with tempfile.TemporaryDirectory(prefix='madeira-validation-stage-') as temporary:
    output = Path(temporary) / 'file.c'
    namespace = {'Path': Path, 'sys': type('Args', (), {'argv': [
        'stage', str(pinned), str(output), str(root / 'build/ntdll-unix/io_status_trace.h')]})}
    exec(build[start:end], namespace)
    staged = output.read_text()
    assert staged.count('#include "' + str(header) + '"') == 1
    assert staged.count('ios_steam_validation_read_note( unix_handle, total, offset );') == 1
    read = function(staged, 'NTSTATUS WINAPI NtReadFile(')
    hook = 'if (type == FD_TYPE_FILE && status == STATUS_SUCCESS && total)\n        ios_steam_validation_read_note( unix_handle, total, offset );'
    assert hook in read
    completion = read.index(hook)
    close_fd = read.index('if (needs_close) close( unix_handle );', read.index('\nerr:', completion))
    assert read.index('ios_video_read_note(') < completion < close_fd
    assert pinned.read_bytes() == unchanged
print('PASS actual build staging observes successful regular-file reads before closing their fd; pinned Wine source stays unchanged')
