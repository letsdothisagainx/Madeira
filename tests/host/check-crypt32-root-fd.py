#!/usr/bin/env python3
"""Exercise the actual root-PEM reader's descriptor ownership and DER bytes.

This is an owned fixture, not a trust or VAC verdict. The C block is copied
verbatim from production; only POSIX I/O gateways schedule a deterministic
concurrent fd reuse or inject genuine failure returns.
"""
import argparse
import base64
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = 'build/crypto-unix/crypt32_unixlib_ios.c'
parser = argparse.ArgumentParser()
parser.add_argument('--baseline', help='Compile this committed production reader instead')
parser.add_argument('--expect-baseline-reuse-failure', action='store_true')
args = parser.parse_args()
assert not args.expect_baseline_reuse_failure or args.baseline
if args.baseline:
    source = subprocess.check_output(['git', 'show', args.baseline + ':' + SOURCE], cwd=ROOT, text=True)
else:
    source = (ROOT / SOURCE).read_text()
start = source.index('struct root_cert\n{')
end = source.index('static const char * const CRYPT_knownLocations[]')
production = source[start:end]
assert production.count('static void import_certs_from_file(') == 1
assert production.count('import_certs_from_file(fd)') == 1
bundle = (ROOT / 'app/Madeira/cacert.pem').read_bytes()
blocks = re.findall(rb'-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----', bundle, re.S)
assert blocks, 'The actual bundled public CA fixture must be available'
der = base64.b64decode(re.sub(rb'\s', b'', blocks[0]), validate=True)
pem = b'-----BEGIN CERTIFICATE-----\n' + base64.encodebytes(der) + b'-----END CERTIFICATE-----\n'

prefix = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include "wine/list.h"
typedef int BOOL;
typedef uint32_t DWORD;
typedef unsigned char BYTE;
typedef size_t SIZE_T;
typedef const char *LPCSTR;
#define TRUE 1
#define FALSE 0
#define max(a,b) ((a) > (b) ? (a) : (b))
#define debugstr_a(value) (value)
/* Keep production trace operands referenced on Apple Clang without emitting
 * fixture paths/certificate bodies or weakening warning checks. */
#define TRACE(...) do { if (0) fprintf(stderr, __VA_ARGS__); } while (0)
#define WARN(...) do {} while (0)
#define ERR(...) do {} while (0)
static struct { unsigned opened, fdopened, closed, fclose_calls; } counts;
static int fail_fdopen, fail_fstat, fail_fclose;
static int inject_reuse, reuse_request, reuse_ready, retired_fd, unrelated_fd;
static char unrelated_path[4096];
static pthread_mutex_t reuse_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t reuse_cond = PTHREAD_COND_INITIALIZER;
static int probe_open(const char *path, int flags)
{
    int fd = open(path, flags);
    if (fd >= 0) counts.opened++;
    return fd;
}
static int probe_close(int fd)
{
    counts.closed++;
    return close(fd);
}
static int probe_fstat(int fd, struct stat *st)
{
    if (fail_fstat) { errno = EIO; return -1; }
    return fstat(fd, st);
}
static FILE *probe_fdopen(int fd, const char *mode)
{
    if (fail_fdopen) { errno = ENOMEM; return NULL; }
    FILE *file = fdopen(fd, mode);
    if (file) counts.fdopened++;
    return file;
}
static int probe_fclose(FILE *file)
{
    int fd = fileno(file);
    int result = fclose(file);
    counts.fclose_calls++;
    if (inject_reuse)
    {
        pthread_mutex_lock(&reuse_mutex);
        retired_fd = fd;
        reuse_request = 1;
        pthread_cond_broadcast(&reuse_cond);
        while (!reuse_ready) pthread_cond_wait(&reuse_cond, &reuse_mutex);
        pthread_mutex_unlock(&reuse_mutex);
    }
    if (fail_fclose) { errno = EIO; return EOF; }
    return result;
}
static void *reuse_worker(void *unused)
{
    (void)unused;
    pthread_mutex_lock(&reuse_mutex);
    while (!reuse_request) pthread_cond_wait(&reuse_cond, &reuse_mutex);
    unrelated_fd = open(unrelated_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    assert(unrelated_fd >= 0 && unrelated_fd == retired_fd);
    reuse_ready = 1;
    pthread_cond_broadcast(&reuse_cond);
    pthread_mutex_unlock(&reuse_mutex);
    return NULL;
}
#define open probe_open
#define close probe_close
#define fstat probe_fstat
#define fdopen probe_fdopen
#define fclose probe_fclose
'''

suffix = r'''
#undef open
#undef close
#undef fstat
#undef fdopen
#undef fclose
static char pem_path[4096], empty_path[4096], invalid_path[4096], missing_path[4096];
static char fixture_dir[4096], disallowed_dir[4096];
static BYTE expected[16384];
static size_t expected_size;
static void reset_counts(void)
{
    memset(&counts, 0, sizeof(counts));
    fail_fdopen = fail_fstat = fail_fclose = inject_reuse = 0;
}
static unsigned cert_count(void)
{
    struct list *ptr;
    unsigned n = 0;
    LIST_FOR_EACH(ptr, &root_cert_list) n++;
    return n;
}
static void verify_and_clear(unsigned n)
{
    struct list *ptr, *next;
    assert(cert_count() == n);
    LIST_FOR_EACH_SAFE(ptr, next, &root_cert_list)
    {
        struct root_cert *cert = LIST_ENTRY(ptr, struct root_cert, entry);
        assert(cert->size == expected_size && !memcmp(cert->data, expected, expected_size));
        list_remove(ptr);
        free(cert);
    }
}
static unsigned open_count(void)
{
    unsigned fd, n = 0;
    for (fd = 0; fd < 512; fd++)
        if (fcntl(fd, F_GETFD) >= 0) n++;
    return n;
}
static int reproduce_reuse(void)
{
    static const char canary[] = "unrelated-owner-write-is-still-valid";
    pthread_t thread;
    reset_counts();
    inject_reuse = 1;
    assert(!pthread_create(&thread, NULL, reuse_worker, NULL));
    import_certs_from_path(pem_path, FALSE);
    assert(!pthread_join(thread, NULL));
    inject_reuse = 0;
    if (fcntl(unrelated_fd, F_GETFD) < 0)
    {
        puts("PRODUCTION_DOUBLE_CLOSE_CLOSED_UNRELATED_FD");
        verify_and_clear(1);
        return 77;
    }
    assert(counts.opened == 1 && counts.fdopened == 1 && counts.fclose_calls == 1 && counts.closed == 0);
    assert(write(unrelated_fd, canary, sizeof(canary)) == sizeof(canary));
    assert(lseek(unrelated_fd, 0, SEEK_SET) == 0);
    char data[sizeof(canary)];
    assert(read(unrelated_fd, data, sizeof(data)) == sizeof(data) && !memcmp(data, canary, sizeof(data)));
    assert(!close(unrelated_fd));
    verify_and_clear(1);
    puts("PASS actual production reader: unrelated concurrent fd reuse survives");
    return 0;
}
static pthread_mutex_t import_mutex = PTHREAD_MUTEX_INITIALIZER;
static int churn_stop;
static void *churn_worker(void *unused)
{
    (void)unused;
    while (!__atomic_load_n(&churn_stop, __ATOMIC_ACQUIRE))
    {
        int fd = open(unrelated_path, O_RDONLY);
        if (fd >= 0) { assert(fcntl(fd, F_GETFD) >= 0); assert(!close(fd)); }
    }
    return NULL;
}
static void *import_worker(void *unused)
{
    (void)unused;
    for (unsigned i = 0; i < 40; i++)
    {
        /* Mirrors the production outer root-store mutex. The root certificate
         * list itself is intentionally not made concurrent by this test. */
        pthread_mutex_lock(&import_mutex);
        import_certs_from_path(pem_path, FALSE);
        verify_and_clear(1);
        pthread_mutex_unlock(&import_mutex);
    }
    return NULL;
}
int main(int argc, char **argv)
{
    assert(argc == 3);
    snprintf(pem_path, sizeof(pem_path), "%s/one.pem", argv[1]);
    snprintf(empty_path, sizeof(empty_path), "%s/empty", argv[1]);
    snprintf(invalid_path, sizeof(invalid_path), "%s/invalid.pem", argv[1]);
    snprintf(missing_path, sizeof(missing_path), "%s/absent", argv[1]);
    snprintf(fixture_dir, sizeof(fixture_dir), "%s/roots", argv[1]);
    snprintf(disallowed_dir, sizeof(disallowed_dir), "%s/empty-dir", argv[1]);
    snprintf(unrelated_path, sizeof(unrelated_path), "%s/unrelated", argv[1]);
    FILE *expected_file = fopen(argv[2], "rb");
    assert(expected_file);
    expected_size = fread(expected, 1, sizeof(expected), expected_file);
    assert(expected_size > 0 && expected_size < sizeof(expected) && !ferror(expected_file));
    assert(!fclose(expected_file));
    unsigned baseline = open_count();
    int reuse = reproduce_reuse();
    if (reuse) return reuse;
    assert(open_count() == baseline);

    reset_counts();
    import_certs_from_path(pem_path, FALSE);
    assert(counts.opened == 1 && counts.fdopened == 1 && counts.fclose_calls == 1 && counts.closed == 0);
    verify_and_clear(1);
    assert(open_count() == baseline);

    reset_counts(); fail_fdopen = 1;
    import_certs_from_path(pem_path, FALSE);
    assert(counts.opened == 1 && counts.fdopened == 0 && counts.fclose_calls == 0 && counts.closed == 1);
    assert(errno == ENOMEM && cert_count() == 0 && open_count() == baseline);

    reset_counts(); fail_fstat = 1;
    import_certs_from_path(pem_path, FALSE);
    assert(counts.opened == 1 && counts.closed == 1 && counts.fdopened == 0);
    assert(cert_count() == 0 && open_count() == baseline);

    reset_counts(); fail_fclose = 1;
    import_certs_from_path(pem_path, FALSE);
    assert(counts.fclose_calls == 1 && counts.closed == 0 && errno == EIO);
    verify_and_clear(1);
    assert(open_count() == baseline);

    for (unsigned i = 0; i < 2; i++)
    {
        reset_counts();
        import_certs_from_path(i ? invalid_path : empty_path, FALSE);
        assert(counts.opened == 1 && counts.fdopened == 1 && counts.fclose_calls == 1 && counts.closed == 0);
        verify_and_clear(0);
        assert(open_count() == baseline);
    }
    reset_counts();
    import_certs_from_path(missing_path, FALSE);
    assert(counts.opened == 0 && counts.closed == 0 && cert_count() == 0);
    reset_counts();
    import_certs_from_path(disallowed_dir, FALSE);
    assert(counts.opened == 1 && counts.closed == 1 && counts.fdopened == 0 && cert_count() == 0);
    reset_counts();
    import_certs_from_path(fixture_dir, TRUE);
    assert(counts.opened == 3 && counts.fdopened == 2 && counts.fclose_calls == 2 && counts.closed == 1);
    verify_and_clear(2);
    assert(open_count() == baseline);

    reset_counts();
    pthread_t churn, workers[8];
    assert(!pthread_create(&churn, NULL, churn_worker, NULL));
    for (unsigned i = 0; i < 8; i++) assert(!pthread_create(&workers[i], NULL, import_worker, NULL));
    for (unsigned i = 0; i < 8; i++) assert(!pthread_join(workers[i], NULL));
    __atomic_store_n(&churn_stop, 1, __ATOMIC_RELEASE);
    assert(!pthread_join(churn, NULL));
    assert(counts.opened == 320 && counts.fclose_calls == 320 && counts.closed == 0);
    assert(cert_count() == 0 && open_count() == baseline);
    puts("PASS actual production root parser: DER bytes, fdopen/fstat/fclose errors, directories, 8 import callers and fd churn");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-crypt32-fd-') as directory:
    temp = Path(directory)
    (temp / 'one.pem').write_bytes(pem)
    (temp / 'expected.der').write_bytes(der)
    (temp / 'empty').write_bytes(b'')
    (temp / 'invalid.pem').write_bytes(b'-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n')
    (temp / 'empty-dir').mkdir()
    (temp / 'roots').mkdir()
    (temp / 'roots/a.pem').write_bytes(pem)
    (temp / 'roots/b.pem').write_bytes(pem)
    harness = temp / 'crypt32-root-fd.c'
    harness.write_text(prefix + production + suffix)
    binary = temp / 'crypt32-root-fd'
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-sign-compare', '-O1', '-g', '-fsanitize=address,undefined', '-pthread',
                    '-I' + str(ROOT / 'wine/include'), str(harness), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary), str(temp), str(temp / 'expected.der')], text=True, capture_output=True)
    print(result.stdout, end='')
    if result.stderr:
        print(result.stderr, end='')
    assert 'ERROR: AddressSanitizer' not in result.stderr and 'runtime error:' not in result.stderr
    if args.expect_baseline_reuse_failure:
        assert result.returncode == 77 and 'PRODUCTION_DOUBLE_CLOSE_CLOSED_UNRELATED_FD' in result.stdout, result.returncode
        print('PASS baseline: actual committed root reader closes a concurrently reused unrelated descriptor')
    else:
        assert result.returncode == 0, result.returncode
        print('crypt32 root descriptor ownership: PASS')
