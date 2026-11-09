#!/usr/bin/env python3
"""Compile and execute the owned production native observation bodies."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
thread = (ROOT / 'build/ntdll-unix/thread_ios.c').read_text()
def body(source, mark):
    start = source.index(mark)
    brace = source.index('{', start)
    depth = 0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]', source[brace:], re.S):
        if token[0] == '{':
            depth += 1
        elif token[0] == '}':
            depth -= 1
            if not depth:
                return source[start:brace + token.end()]
    raise AssertionError('missing complete production body: ' + mark)

with tempfile.TemporaryDirectory() as directory:
    temp = Path(directory)
    (temp / 'cs2_observation_lease_under_test.h').write_text('''
#include "native_thread_lifetime.h"
''' + body(thread, 'struct ios_thread_group\n{') + ''';
static struct ios_thread_group ios_thread_groups[4];
static unsigned long long ios_thread_next_lease;
static pthread_mutex_t ios_thread_group_mutex = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local struct madeira_native_thread ios_native_current;
static _Thread_local void *ios_retired_thread_owner;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
''' + '\n'.join(body(thread, mark) for mark in (
    'void set_thread_id(',
    'static struct ios_thread_group *ios_thread_group_locked(',
    'static void ios_native_link_current_locked(',
    'unsigned long long ios_thread_process_lease(',
    'unsigned long long ios_thread_process_try_observation_lease(')))
    sources = ('cs2_observation_test.c', 'cs2_observation_native_test.c')
    for source in sources:
        binary = temp / source.removesuffix('.c')
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
            '-O2', '-pthread', '-I' + str(ROOT / 'build/ntdll-unix'), '-I' + str(temp),
            str(ROOT / 'tests/host' / source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)

# Boundary regressions: no failed-map callback, no registry/VM lock held while
# observing, and startup uses accepted identity rather than a command token.
virtual = (ROOT / 'build/ntdll-unix/virtual_ios.c').read_text()
image_map = virtual[virtual.index('static NTSTATUS virtual_map_image('):virtual.index(' *             virtual_map_section')]
assert image_map.index('server_leave_uninterrupted_section(') < image_map.index('ios_cs2_observe_current_map(')
assert 'if (NT_SUCCESS(status)) ios_cs2_observe_current_map(nt_name, image_info->machine, image_info->is_hybrid, image_info->wine_builtin);' in image_map
loader = (ROOT / 'build/ntdll-unix/loader_ios.c').read_text()
assert 'ios_register_proc_ident(NtCurrentTeb()->Peb, &main_image_info);\n    ios_cs2_observe_current_start(main_image_info.Machine);' in loader
assert 'ios_cs2_observe_current_start(ios_cur_image_info()->Machine);' in loader
server = (ROOT / 'build/ntdll-unix/server_ios.c').read_text()
done = body(server, 'void server_init_process_done(void)')
assert done.index('SERVER_END_REQ;') < done.index('ios_cs2_observe_current_debug();') < done.index('signal_start_thread(')
assert done.count('ios_cs2_observe_current_debug();') == 1
for name in ('size_t server_init_process(void)', 'size_t server_init_process_child('):
    startup = body(server, name)
    assert startup.index('set_thread_id( NtCurrentTeb(), pid, tid );') < startup.index('ios_thread_process_lease(NtCurrentTeb()->Peb,1);')
initial = body(loader, 'static void start_main_thread(void)\n{')
assert initial.index('virtual_alloc_first_teb()') < initial.index('startup_info_size = server_init_process();') < initial.index('unix_init_startup_info();') < initial.index('ios_cs2_observe_current_start(')
assert initial.count('ios_cs2_observe_current_start(') == 2
child = body(loader, 'DECLSPEC_EXPORT void wine_ios_child_main(')
assert child.index('teb->Peb = child_peb;') < child.index('pthread_setspecific( teb_key, teb );') < child.index('startup_info_size = server_init_process_child(') < child.index('unix_init_startup_info();') < child.index('ios_cs2_observe_current_start(')
assert child.count('ios_cs2_observe_current_start(') == 2
env = body((ROOT / 'build/ntdll-unix/env_ios.c').read_text(), 'static void init_peb(')
assert env.index('PEB *peb = NtCurrentTeb()->Peb;') < env.index('peb->ProcessParameters          = params;')
print('CS2 passive accepted-boundary observations: PASS')
