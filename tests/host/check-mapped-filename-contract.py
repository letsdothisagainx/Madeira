#!/usr/bin/env python3
"""Compile actual Wine mapped-filename APIs against a controlled query boundary.

The literal production Unicode and ANSI wrappers run here. The OS filename
query and ASCII conversion boundary are owned fixtures, not an independent
filename mapper. No test supplies a trust verdict or claims CS2/VAC acceptance.
"""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path('dlls/kernelbase/debug.c')
SPEC = importlib.util.spec_from_file_location('mapped_filename_stage', ROOT / 'tools/build/stage-mapped-filename-contract.py')
STAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGER)


def function(text, name):
    start = text.index('DWORD WINAPI DECLSPEC_HOTPATCH ' + name + '(')
    return text[start:text.index('\n}', start) + 2]


PREFIX = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint16_t WCHAR;
typedef uint32_t DWORD;
typedef uintptr_t ULONG_PTR;
typedef void *HANDLE;
typedef struct { uint16_t Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
typedef struct { UNICODE_STRING SectionFileName; } MEMORY_SECTION_NAME;
#define MAX_PATH 260
#define WINAPI
#define DECLSPEC_HOTPATCH
#define ERROR_INVALID_PARAMETER 87
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_ADDRESS 487
#define MemoryMappedFilenameInformation 2
#define min(a,b) ((a) < (b) ? (a) : (b))
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#c); return 23; } } while(0)
static DWORD last_error;
static unsigned query_calls, conversion_calls, query_status;
static WCHAR filename[MAX_PATH];
static unsigned filename_length;
static const HANDLE expected_process = (HANDLE)(uintptr_t)0x678;
static void *const expected_address = (void *)(uintptr_t)0x140001123ull;
static void SetLastError(DWORD error) { last_error = error; }
static int set_ntstatus(unsigned status) {
    if (!status) return 1;
    last_error = status == 1 ? ERROR_ACCESS_DENIED : status == 2 ? ERROR_INVALID_ADDRESS : ERROR_INSUFFICIENT_BUFFER;
    return 0;
}
static unsigned NtQueryVirtualMemory(HANDLE process, void *address, unsigned cls,
                                     MEMORY_SECTION_NAME *out, size_t size, void *returned) {
    assert(process == expected_process && address == expected_address);
    assert(cls == MemoryMappedFilenameInformation && size >= sizeof(*out) && !returned);
    query_calls++;
    if (query_status) return query_status;
    out->SectionFileName.Length = filename_length * sizeof(WCHAR);
    out->SectionFileName.MaximumLength = (filename_length + 1) * sizeof(WCHAR);
    out->SectionFileName.Buffer = filename;
    return 0;
}
static size_t fixture_wcslen(const WCHAR *text) { size_t length = 0; while (text[length]) length++; return length; }
#define wcslen fixture_wcslen
/* NLS is unchanged by this patch. Supply bounded ASCII conversion for the
 * actual ANSI wrapper's ASCII controls; Unicode cases run the real W wrapper. */
static DWORD file_name_WtoA(const WCHAR *input, int length, char *output, int size) {
    assert(length >= 0 && size > 0);
    conversion_calls++;
    DWORD count = min((DWORD)length, (DWORD)size);
    for (DWORD i = 0; i < count; i++) { assert(input[i] < 128); output[i] = input[i]; }
    return count;
}
static void ascii_name(const char *text) {
    filename_length = strlen(text); assert(filename_length < MAX_PATH);
    for (unsigned i = 0; i <= filename_length; i++) filename[i] = (unsigned char)text[i];
}
'''

SUFFIX = r'''
struct wide_buffer { WCHAR before, data[64], after; };
struct narrow_buffer { unsigned char before; char data[64]; unsigned char after; };
static void reset(struct wide_buffer *value) {
    value->before = value->after = 0xbeef;
    for (unsigned i = 0; i < 64; i++) value->data[i] = 0xa55a;
    last_error = 77; query_status = 0;
}
static int untouched_after(const struct wide_buffer *value, unsigned size) {
    if (value->before != 0xbeef || value->after != 0xbeef) return 0;
    for (unsigned i = size; i < 64; i++) if (value->data[i] != 0xa55a) return 0;
    return 1;
}
static int zero_control(void) {
    struct wide_buffer value; reset(&value); ascii_name("C:\\sample.dll");
    unsigned old_calls = query_calls;
    DWORD count = GetMappedFileNameW(expected_process, expected_address, value.data, 0);
    CHECK(count == 0 && last_error == ERROR_INSUFFICIENT_BUFFER);
    CHECK(untouched_after(&value, 0) && query_calls == old_calls + 1);
    return 0;
}
static int truncated_control(void) {
    struct wide_buffer value; reset(&value); ascii_name("C:\\sample.dll");
    DWORD count = GetMappedFileNameW(expected_process, expected_address, value.data, 2);
    CHECK(count == 2 && last_error == ERROR_INSUFFICIENT_BUFFER);
    CHECK(value.data[0] == 'C' && value.data[1] == 0 && untouched_after(&value, 2));
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "zero")) return zero_control();
    if (argc == 2 && !strcmp(argv[1], "truncated")) return truncated_control();
    CHECK(!zero_control() && !truncated_control());
    struct wide_buffer value;
    const WCHAR unicode_name[] = {'C',':','\\',0x03a9,0xd83d,0xde00,'.','d','l','l',0};
    for (unsigned which = 0; which < 2; which++) {
        if (!which) ascii_name("C:\\sample.dll");
        else { memcpy(filename, unicode_name, sizeof(unicode_name)); filename_length = 10; }
        for (unsigned size = 0; size <= filename_length + 3; size++) {
            reset(&value);
            DWORD count = GetMappedFileNameW(expected_process, expected_address, value.data, size);
            CHECK(count == min(filename_length, size));
            CHECK(untouched_after(&value, size));
            if (!size) CHECK(last_error == ERROR_INSUFFICIENT_BUFFER);
            else {
                unsigned copied = min(filename_length, size - 1);
                CHECK(!memcmp(value.data, filename, copied * sizeof(WCHAR)));
                CHECK(value.data[copied] == 0);
                CHECK(last_error == (filename_length >= size ? ERROR_INSUFFICIENT_BUFFER : 77));
            }
        }
    }
    /* Keep pre-existing NULL and failed-query precedence, output contents,
     * actual handle/address forwarding, and incoming success LastError. */
    reset(&value); unsigned calls = query_calls;
    CHECK(!GetMappedFileNameW(expected_process, expected_address, NULL, 5));
    CHECK(last_error == ERROR_INVALID_PARAMETER && query_calls == calls);
    CHECK(!GetMappedFileNameW(expected_process, expected_address, NULL, 0));
    CHECK(last_error == ERROR_INSUFFICIENT_BUFFER && query_calls == calls + 1);
    for (unsigned status = 1; status <= 3; status++) for (unsigned size = 0; size <= 2; size++) {
        reset(&value); query_status = status; calls = query_calls;
        CHECK(!GetMappedFileNameW(expected_process, expected_address, value.data, size));
        CHECK(query_calls == calls + 1 && untouched_after(&value, 0));
        CHECK(last_error == (status == 1 ? ERROR_ACCESS_DENIED : status == 2 ? ERROR_INVALID_ADDRESS : ERROR_INSUFFICIENT_BUFFER));
    }
    struct narrow_buffer narrow; ascii_name("C:\\sample.dll"); query_status = 0;
    for (unsigned size = 0; size < 18; size++) {
        memset(&narrow, 0x5a, sizeof(narrow)); last_error = 77; calls = query_calls;
        unsigned converted = conversion_calls;
        DWORD count = GetMappedFileNameA(expected_process, expected_address, narrow.data, size);
        CHECK(count == min(filename_length, size) && query_calls == calls + 1);
        CHECK(narrow.before == 0x5a && narrow.after == 0x5a);
        for (unsigned i = size; i < sizeof(narrow.data); i++) CHECK((unsigned char)narrow.data[i] == 0x5a);
        if (!size) CHECK(last_error == ERROR_INSUFFICIENT_BUFFER && conversion_calls == converted);
        else {
            unsigned copied = min(filename_length, size - 1);
            for (unsigned i = 0; i < copied; i++) CHECK(narrow.data[i] == (char)filename[i]);
            CHECK(narrow.data[copied] == 0 && conversion_calls == converted + 1);
        }
    }
    calls = query_calls;
    CHECK(!GetMappedFileNameA(expected_process, expected_address, NULL, 5));
    CHECK(last_error == ERROR_INVALID_PARAMETER && query_calls == calls);
    CHECK(!GetMappedFileNameA(expected_process, expected_address, NULL, 0));
    CHECK(last_error == ERROR_INSUFFICIENT_BUFFER && query_calls == calls + 1);
    query_status = 1; memset(&narrow, 0x5a, sizeof(narrow));
    CHECK(!GetMappedFileNameA(expected_process, expected_address, narrow.data, 32));
    CHECK(last_error == ERROR_ACCESS_DENIED);
    for (unsigned i = 0; i < sizeof(narrow); i++) CHECK(((unsigned char *)&narrow)[i] == 0x5a);
    puts("PASS actual GetMappedFileNameW capacity/truncated-count contract, exact fit, UTF16 identity, canaries, NULL/failed-query precedence and LastError; actual ANSI wrapper preserved at its query/NLS boundary");
    return 0;
}
'''


def compile_apis(directory, label, text):
    file = directory / (label + '.c')
    file.write_text(PREFIX + function(text, 'GetMappedFileNameW') + '\n' +
                    function(text, 'GetMappedFileNameA') + SUFFIX)
    binary = directory / label
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', str(file), '-o', str(binary)], check=True)
    return binary


def rejected(operation, label):
    try:
        operation()
    except (AssertionError, OSError, ValueError, subprocess.CalledProcessError):
        return
    raise AssertionError('stage accepted ' + label)


def main():
    original = (ROOT / 'wine' / SOURCE).read_bytes()
    # Use a real nested Git working-tree directory. Patch application must not
    # silently skip hunks because git discovered the enclosing repository.
    with tempfile.TemporaryDirectory(prefix='mapped-filename-contract-', dir=ROOT / 'build') as temp:
        directory = Path(temp)
        staged = directory / 'staged'
        STAGER.stage(staged, ROOT / 'wine')
        changed = (staged / SOURCE).read_text()
        text = original.decode()
        assert text != changed
        assert function(text, 'GetMappedFileNameA') == function(changed, 'GetMappedFileNameA')
        # No other filename, module, security, or identity implementation changes.
        assert text.replace(function(text, 'GetMappedFileNameW'), '') == changed.replace(function(changed, 'GetMappedFileNameW'), '')
        baseline = compile_apis(directory, 'baseline', text)
        corrected = compile_apis(directory, 'corrected', changed)
        for control in ('zero', 'truncated'):
            before = subprocess.run([str(baseline), control], text=True, capture_output=True, timeout=30)
            assert before.returncode == 23 and 'FAIL' in before.stderr, before
            subprocess.run([str(corrected), control], check=True, timeout=30)
            print('BEFORE actual production ' + control + '-capacity control fails; AFTER corrected production passes', flush=True)
        subprocess.run([str(corrected)], check=True, timeout=30)
        rejected(lambda: STAGER.stage(staged, ROOT / 'wine'), 'existing staged output')
        fixture = directory / 'wine'
        (fixture / SOURCE).parent.mkdir(parents=True)
        (fixture / SOURCE).write_bytes(original)
        state = directory / 'state'
        state.mkdir()
        STAGER.apply(state, fixture)
        assert (fixture / SOURCE).read_text() == changed
        rejected(lambda: STAGER.apply(state, fixture), 'existing transaction')
        restaged = directory / 'already-applied'
        rejected(lambda: STAGER.stage(restaged, fixture), 'already-applied source')
        (fixture / SOURCE).write_text(changed + '\n/* later build input */\n')
        rejected(lambda: STAGER.restore(state), 'modified build-time source')
        assert (fixture / SOURCE).read_text().endswith('/* later build input */\n')
        (fixture / SOURCE).write_text(changed)
        backup = state / 'original/debug.c'
        backup.write_bytes(original + b'\n')
        rejected(lambda: STAGER.restore(state), 'modified original backup')
        backup.write_bytes(original)
        STAGER.restore(state)
        assert (fixture / SOURCE).read_bytes() == original
        rejected(lambda: STAGER.restore(state), 'double restoration')
        (fixture / SOURCE).unlink()
        (fixture / SOURCE).symlink_to(ROOT / 'wine' / SOURCE)
        rejected(lambda: STAGER.stage(directory / 'symlink-source', fixture), 'symlinked source')
        assert (ROOT / 'wine' / SOURCE).read_bytes() == original
        print('PASS reversible owned staging inside a Git worktree: unchanged vendor input, exact restoration, stale/already-applied/modified/symlink input refusal')


if __name__ == '__main__':
    main()
