#!/usr/bin/env python3
"""Configure the production owner allocator hook without editing FEX inputs."""
from pathlib import Path
import hashlib
import os
import shlex
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
COMPAT = ROOT / 'build/fex-compat'
ALLOCATOR = ROOT / 'FEX/External/rpmalloc/rpmalloc'
CMAKE = shlex.split(os.environ.get('CMAKE', 'cmake'))
assert CMAKE and shutil.which(CMAKE[0]), 'CMake 3.19 or newer is required'

ORIGINAL = (ALLOCATOR / 'rpmalloc.c').read_text()
FIRST = 'block_t* block = global_memory_interface->memory_map(heap_size, 0, &offset, &mapped_size);\n#if ENABLE_DECOMMIT'
SECOND = 'heap_t* heap = heap_allocate(1);\n\trpmalloc_assume(heap != 0);'
assert ORIGINAL.count(FIRST) == ORIGINAL.count(SECOND) == 1
EXPECTED = ORIGINAL.replace(FIRST, FIRST.replace('\n#if', '\n\tif (!block)\n\t\treturn 0;\n#if')).replace(
    SECOND, SECOND.replace('\n\trpmalloc_assume', '\n\tif (!heap)\n\t\treturn 0;\n\trpmalloc_assume'))
EXPECTED = EXPECTED.replace('void fex_ios_rpm_lock(void) {\n\tuintptr_t self, expected = 0;',
    '#include "owner_allocator_backoff.h"\nvoid fex_ios_rpm_lock(void) {\n\tuintptr_t self;\n\tunsigned madeira_contended_polls = 0;').replace(
    '\twhile (!atomic_compare_exchange_weak_explicit(&fex_ios_rpm_owner, &expected, self, memory_order_acquire,\n\t                                              memory_order_relaxed)) {\n\t\texpected = 0;\n\t\twait_spin();\n\t}\n\tfex_ios_rpm_depth = 1;',
    '\twhile (!madeira_fex_rpm_try_owner(self)) {\n\t\tif (++madeira_contended_polls == 64) {\n\t\t\tmadeira_contended_polls = 0;\n\t\t\tmadeira_fex_rpm_backoff();\n\t\t} else {\n\t\t\twait_spin();\n\t\t}\n\t}\n\tmadeira_fex_rpm_publish_depth();')


def configure(source, build, *, windows=True, host=True, allocator=True, success=True):
    command = CMAKE + ['-S', str(source), '-B', str(build),
                       '-DTEST_WINDOWS=' + ('ON' if windows else 'OFF'),
                       '-DFEX_IOS_HOST_BUILD=' + ('ON' if host else 'OFF'),
                       '-DENABLE_FEX_ALLOCATOR=' + ('ON' if allocator else 'OFF'),
                       '-DCMAKE_PROJECT_FEX_INCLUDE=' + str(source / 'project-hook.cmake')]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert (result.returncode == 0) == success, result.stdout
    return result.stdout


def fixture(directory):
    source = directory / 'source'
    allocator = source / 'External/rpmalloc/rpmalloc'
    allocator.mkdir(parents=True)
    for name in ('rpmalloc.c', 'rpmalloc.h'):
        shutil.copyfile(ALLOCATOR / name, allocator / name)
    (source / 'allocator-hooks.cpp').write_text('void original_allocator_hooks() {}\n')
    (source / 'project-hook.cmake').write_text(
        'set(WIN32 "${TEST_WINDOWS}")\ninclude("' + str(COMPAT / 'owner_allocator.cmake') + '")\n')
    (source / 'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.19)
project(FEX C CXX)
option(FEX_IOS_HOST_BUILD "Windows PE host" ON)
option(ENABLE_FEX_ALLOCATOR "FEX allocator" ON)
add_library(rpmalloc STATIC External/rpmalloc/rpmalloc/rpmalloc.c)
target_compile_definitions(rpmalloc PRIVATE ENABLE_DECOMMIT=1 DYNAMIC_TLS_NO_FLS=1)
add_library(JemallocLibs STATIC allocator-hooks.cpp)
target_link_libraries(JemallocLibs PUBLIC rpmalloc)
function(report)
  get_target_property(rpm_sources rpmalloc SOURCES)
  get_target_property(owner_sources JemallocLibs SOURCES)
  get_target_property(rpm_definitions rpmalloc COMPILE_DEFINITIONS)
  get_target_property(owner_definitions JemallocLibs COMPILE_DEFINITIONS)
  file(WRITE "${CMAKE_BINARY_DIR}/report.txt"
    "rpm_sources=${rpm_sources}\\nowner_sources=${owner_sources}\\nrpm_definitions=${rpm_definitions}\\nowner_definitions=${owner_definitions}\\n")
endfunction()
cmake_language(DEFER CALL report)
''')
    return source


def report(build):
    return dict(line.split('=', 1) for line in (build / 'report.txt').read_text().splitlines())


with tempfile.TemporaryDirectory(prefix='madeira-owner-config-') as directory:
    base = Path(directory)
    source = fixture(base / 'enabled')
    build = base / 'enabled/build'
    configure(source, build)
    observed = report(build)
    checked = build / 'madeira-fex-compat/rpmalloc-checked.c'
    assert Path(observed['rpm_sources']) == checked
    assert Path(observed['owner_sources']) == COMPAT / 'owner_allocator.cpp'
    assert 'RPMALLOC_FIRST_CLASS_HEAPS=1' in observed['rpm_definitions'].split(';')
    assert 'ENABLE_DECOMMIT=1' in observed['rpm_definitions'].split(';')
    assert 'DYNAMIC_TLS_NO_FLS=1' in observed['rpm_definitions'].split(';')
    assert 'RPMALLOC_FIRST_CLASS_HEAPS=1' in observed['owner_definitions'].split(';')
    assert checked.read_text() == EXPECTED, 'Unexpected generated allocator changes'
    timestamp = checked.stat().st_mtime_ns
    configure(source, build)
    assert report(build) == observed
    assert checked.stat().st_mtime_ns == timestamp, 'Cached configure rewrote unchanged allocator input'
    assert (source / 'External/rpmalloc/rpmalloc/rpmalloc.c').read_text() == ORIGINAL

    for name, options in (('native-ios', {'windows': False}),
                          ('allocator-off', {'allocator': False}),
                          ('host-off', {'host': False})):
        source = fixture(base / name)
        build = base / name / 'build'
        configure(source, build, **options)
        observed = report(build)
        assert observed['rpm_sources'] == 'External/rpmalloc/rpmalloc/rpmalloc.c'
        assert observed['owner_sources'] == 'allocator-hooks.cpp'
        assert 'RPMALLOC_FIRST_CLASS_HEAPS' not in observed['rpm_definitions']
        assert 'RPMALLOC_FIRST_CLASS_HEAPS' not in observed['owner_definitions']
        assert not (build / 'madeira-fex-compat').exists()

    for name, file, message in (('source-pin', 'rpmalloc.c', 'Pinned rpmalloc input changed'),
                                ('header-pin', 'rpmalloc.h', 'Pinned rpmalloc API changed')):
        source = fixture(base / name)
        changed = source / 'External/rpmalloc/rpmalloc' / file
        changed.write_bytes(changed.read_bytes() + b'\n')
        output = configure(source, base / name / 'build', success=False)
        assert message in output

assert hashlib.sha256((ALLOCATOR / 'rpmalloc.c').read_bytes()).hexdigest() == 'd810c3695daab1c74e92ba971f1f068b44b3d6172e0a69c5a0c6f8a07234f96b'
print('PASS owner allocator CMake: deferred Windows targets, cached reconfigure, two NULL guards + bounded owner-lock backoff, source/API pins, native/OFF unchanged')
