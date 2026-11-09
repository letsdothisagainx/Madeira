#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 125hz
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Run the real event producer and pinned Wine printf's string/integer path.

The old unbuffered printf callback boundary permits unrelated writes between
format pieces. The Win32 transport edge is owned here; this is not an iPhone
transport test or a service/readiness fixture. No Valve endpoint is accessed.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def function(source, marker):
    start = source.index(marker)
    cursor = source.index('{', start)
    depth = 1
    cursor += 1
    while depth:
        depth += (source[cursor] == '{') - (source[cursor] == '}')
        cursor += 1
    return source[start:cursor]


main = (ROOT / 'build/steam-service/main.c').read_text()
event = function(main, 'static void event(')
assert event.count('WriteFile(') == 1
assert 'fprintf(' not in event and 'GetStdHandle(STD_ERROR_HANDLE)' in event
assert 'SetLastError(incoming)' in event
printf = (ROOT / 'wine/dlls/msvcrt/printf.h').read_text()
wcs = (ROOT / 'wine/dlls/msvcrt/wcs.c').read_text()
flags_start = wcs.index('typedef struct')
flags = wcs[flags_start:wcs.index('} pf_flags;', flags_start) + len('} pf_flags;')]
parts = [function(printf, marker) for marker in (
    'static inline const APICHAR* FUNC_NAME(pf_parse_int)',
    'static inline int FUNC_NAME(pf_fill)',
    'static inline int FUNC_NAME(pf_output_str)',
    'static inline int FUNC_NAME(pf_output_format_str)',
    'static inline int FUNC_NAME(pf_handle_string)',
    'static inline void FUNC_NAME(pf_integer_conv)',
    'int FUNC_NAME(pf_printf)',
)]
code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
typedef uint32_t DWORD;
typedef intptr_t HANDLE;
typedef int BOOL;
typedef unsigned char BOOLEAN;
typedef int64_t LONGLONG;
typedef uint64_t ULONGLONG;
typedef uintptr_t ULONG_PTR;
typedef void *_locale_t;
#define TRUE 1
#define FALSE 0
#define APICHAR char
#define FUNC_NAME(x) x ## _a
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define _MSVCR_VER 140
#define MSVCRT_PRINTF_POSITIONAL_PARAMS 1
#define MSVCRT_PRINTF_INVOKE_INVALID_PARAM_HANDLER 2
#define _CRT_INTERNAL_PRINTF_LEGACY_WIDE_SPECIFIERS 4
#define _CRT_INTERNAL_PRINTF_LEGACY_MSVCRT_COMPATIBILITY 8
#define _CRT_INTERNAL_PRINTF_LEGACY_THREE_DIGIT_EXPONENTS 16
#define _CRT_INTERNAL_PRINTF_STANDARD_ROUNDING 32
#define MSVCRT_CHECK_PMT(x) (assert(x), 1)
#define MSVCRT_INVALID_PMT(x, e) abort()
#define HeapAlloc(h, f, n) malloc(n)
#define HeapFree(h, f, p) free(p)
#define GetProcessHeap() 0
static int n_format_enabled;
static int *_errno(void) { return &errno; }
static void _invalid_parameter(void *a, void *b, void *c, int d, int e) {
    (void)a; (void)b; (void)c; (void)d; (void)e; abort();
}
typedef int (*puts_clbk_a)(void *, int, const char *);
typedef union { void *get_ptr; int get_int; LONGLONG get_longlong; double get_double; } printf_arg;
typedef printf_arg (*args_clbk)(void *, int, int, va_list *);
enum { VT_PTR, VT_INT, VT_I8, VT_R8 };
FLAGS
/* These branches are outside the exact narrow %s/%lu production format.
 * They abort if unexpectedly reached; none supplies a formatting result. */
static int pf_output_format_wstr_a(puts_clbk_a p, void *c, const wchar_t *s,
        int n, pf_flags *f, _locale_t l) {
    (void)p; (void)c; (void)s; (void)n; (void)f; (void)l; abort();
}
static int pf_output_special_fp_a(puts_clbk_a p, void *c, double v, pf_flags *f,
        _locale_t l, BOOL a, BOOL b) {
    (void)p; (void)c; (void)v; (void)f; (void)l; (void)a; (void)b; abort();
}
static int pf_output_hex_fp_a(puts_clbk_a p, void *c, double v, pf_flags *f,
        _locale_t l, BOOL a) {
    (void)p; (void)c; (void)v; (void)f; (void)l; (void)a; abort();
}
static int pf_output_fp_a(puts_clbk_a p, void *c, double v, pf_flags *f,
        _locale_t l, BOOL a, BOOL b) {
    (void)p; (void)c; (void)v; (void)f; (void)l; (void)a; (void)b; abort();
}
/* The following functions are extracted unchanged from pinned Wine printf.h
 * (Copyright 2011 Piotr Caban for CodeWeavers, LGPL-2.1-or-later). */
PRINTF

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static char output[1 << 20];
static size_t used;
static unsigned writes, callbacks;
static int mode;
static HANDLE output_handle = 2;
static _Thread_local DWORD error_value;
#define STD_ERROR_HANDLE ((DWORD)-12)
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
static DWORD GetLastError(void) { return error_value; }
static void SetLastError(DWORD error) { error_value = error; }
static HANDLE GetStdHandle(DWORD kind) {
    assert(kind == STD_ERROR_HANDLE); error_value = 0x11111111; return output_handle;
}
static void append(const char *data, size_t size) {
    assert(size < sizeof(output) - used);
    memcpy(output + used, data, size); used += size; output[used] = 0;
}
static const char noise[] = "[vfree] unrelated-native-diagnostic\n";
static BOOL WriteFile(HANDLE handle, const void *data, DWORD size, DWORD *written, void *overlapped) {
    assert(handle == 2 && !overlapped && size > 0 && size < 128);
    pthread_mutex_lock(&lock); writes++;
    *written = mode == 1 ? 0 : mode == 2 ? size / 2 : size;
    if (*written) append(data, *written);
    append(noise, sizeof(noise) - 1);
    pthread_mutex_unlock(&lock);
    error_value = 0x22222222;
    return mode != 1;
}
static int formatting(char *out, size_t size, const char *format, ...) {
    va_list args; va_start(args, format);
    int count = vsnprintf(out, size, format, args); va_end(args);
    error_value = 0x33333333;
    return count;
}
#define snprintf formatting
EVENT
#undef snprintf

struct arguments { const char *name; DWORD value; unsigned next; };
static printf_arg argument(void *opaque, int position, int type, va_list *list) {
    struct arguments *args = opaque; printf_arg result = {0};
    (void)list; assert(position == -1);
    if (!args->next++) { assert(type == VT_PTR); result.get_ptr = (void *)args->name; }
    else { assert(args->next == 2 && type == VT_INT); result.get_int = (int)args->value; }
    return result;
}
static int unbuffered_transport(void *opaque, int length, const char *bytes) {
    (void)opaque; assert(length > 0);
    pthread_mutex_lock(&lock); callbacks++;
    append(bytes, (size_t)length); append(noise, sizeof(noise) - 1);
    pthread_mutex_unlock(&lock);
    return length;
}
static void reset(void) { used = writes = callbacks = 0; output[0] = 0; mode = 0; output_handle = 2; }
static unsigned exact_running_records(void) {
    unsigned count = 0;
    const char *start = output, *end;
    const char record[] = "[steam-service] service-state=4\r";
    while ((end = strchr(start, '\n'))) {
        if ((size_t)(end - start) == sizeof(record) - 1 && !memcmp(start, record, sizeof(record) - 1)) count++;
        start = end + 1;
    }
    return count;
}
static void *concurrent(void *opaque) {
    DWORD incoming = (DWORD)(uintptr_t)opaque;
    for (unsigned i = 0; i < 64; i++) {
        SetLastError(incoming); event("service-state", 4); assert(GetLastError() == incoming);
    }
    return NULL;
}
int main(void) {
    reset(); struct arguments args = {"service-state", 4, 0};
    int length = pf_printf_a(unbuffered_transport, NULL, "[steam-service] %s=%lu\n",
        NULL, 0, argument, &args, NULL);
    assert(length == (int)strlen("[steam-service] service-state=4\n"));
    assert(callbacks == 5 && exact_running_records() == 0);
    assert(strstr(output, "service-state[vfree]") && strstr(output, "4[vfree]"));
    puts("PASS actual pinned Wine printf narrow string/integer path emits five fragments; interleaved native rows destroy the old service-state record");

    reset(); SetLastError(1053); event("service-state", 4);
    assert(writes == 1 && callbacks == 0 && exact_running_records() == 1 && GetLastError() == 1053);
    reset(); SetLastError(5); event("result", UINT32_MAX);
    assert(writes == 1 && strstr(output, "[steam-service] result=4294967295\r\n") && GetLastError() == 5);
    for (int failure = 1; failure <= 2; failure++) {
        reset(); mode = failure; SetLastError(1722); event("service-state", 4);
        assert(writes == 1 && exact_running_records() == 0 && GetLastError() == 1722);
    }
    for (int invalid = 0; invalid < 2; invalid++) {
        reset(); output_handle = invalid ? INVALID_HANDLE_VALUE : 0;
        SetLastError(1060); event("service-state", 4); assert(!writes && GetLastError() == 1060);
    }
    reset(); char long_name[256]; memset(long_name, 'x', sizeof(long_name) - 1); long_name[255] = 0;
    SetLastError(87); event(long_name, 4); assert(!writes && GetLastError() == 87);
    reset(); SetLastError(2); event("result", 0);
    assert(writes == 1 && strstr(output, "[steam-service] result=0\r\n") && GetLastError() == 2);
    puts("PASS actual service event sends one bounded inherited-stderr record, preserves LastError through formatting/handle/write failures, and never retries short writes or fabricates a state");

    reset(); pthread_t threads[16];
    for (unsigned i = 0; i < ARRAY_SIZE(threads); i++) assert(!pthread_create(&threads[i], NULL, concurrent, (void *)(uintptr_t)(i + 1)));
    for (unsigned i = 0; i < ARRAY_SIZE(threads); i++) assert(!pthread_join(threads[i], NULL));
    assert(writes == 1024 && exact_running_records() == 1024);
    puts("PASS 16 concurrent producers preserve 1024 complete records and per-thread LastError at the single-write transport boundary; actual iPhone transport remains a device check");
}
'''.replace('\nFLAGS\n', '\n' + flags + '\n').replace('\nPRINTF\n', '\n' + '\n'.join(parts) + '\n').replace('\nEVENT\n', '\n' + event + '\n')
with tempfile.TemporaryDirectory(prefix='madeira-service-log-') as directory:
    path = Path(directory)
    source, executable = path / 'service-log.c', path / 'service-log'
    source.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-Wall', '-Wextra',
                    '-Werror', '-Wno-unused-parameter', '-Wno-sign-compare',
                    '-fsanitize=address,undefined', '-pthread', str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
