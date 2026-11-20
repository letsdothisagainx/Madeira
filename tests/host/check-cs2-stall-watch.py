#!/usr/bin/env python3
"""Normal-input tests for the bounded Run13 observation (no fault injection)."""
import os
import argparse
from pathlib import Path
import re
import subprocess
import shutil
import tempfile

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-swift', action='store_true')
args = parser.parse_args()
source = (root / 'build/ntdll-unix/server_ios.c').read_text()
start = source.index('static int ios_ldst_ea( uint32_t')
end = source.index('\n}', start) + 2
with tempfile.TemporaryDirectory() as directory:
    temp = Path(directory)
    (temp / 'actual_store_decode.h').write_text(source[start:end])
    binary = temp / 'cs2-stall-watch'
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
        '-O2', '-pthread', '-I' + str(root / 'build/ntdll-unix'), '-I' + str(temp),
        str(root / 'tests/host/cs2_stall_watch_test.c'), '-o', str(binary)], check=True)
    rows = temp / 'normal-rows.txt'
    subprocess.run([str(binary)], check=True, env={**os.environ, 'MADEIRA_TEST_ROWS': str(rows)})
    swift = shutil.which('swiftc')
    if swift:
        # Only the unchanged production sanitizer is needed. Do not execute
        # exporter error-path or protected-page tests for this investigation.
        sanitizer = (root / 'app/Madeira/RunDiagnostics.swift').read_text()
        sanitizer = sanitizer[:sanitizer.index('    private static func json(')] + '}\n'
        (temp / 'Sanitizer.swift').write_text(sanitizer)
        (temp / 'Check.swift').write_text('''import Foundation
@main struct Check {
    static func main() throws {
        let rows = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8).split(separator: "\\n")
        assert(rows.count == 2)
        for row in rows {
            let text = String(row)
            assert(RunDiagnostics.sanitize(text) == text)
            assert(RunDiagnostics.sanitize(text + " Cookie: PRIVATE_VALUE") == nil)
        }
        print("actual sanitizer preserves both scoped rows and privacy filtering: PASS")
    }
}''')
        check = temp / 'sanitize'
        subprocess.run([swift, '-parse-as-library', str(temp / 'Sanitizer.swift'), str(temp / 'Check.swift'), '-o', str(check)], check=True)
        subprocess.run([str(check), str(rows)], check=True)
    elif args.require_swift:
        raise SystemExit('Swift compiler required')
    else:
        print('SKIP actual Swift sanitizer execution: compiler unavailable locally')

# The new main observer must be called even when xp's top-CPU threshold drops
# an idle main thread. Worker observations reuse existing recovery captures.
xp = source[source.index('static void ios_xprobe_main('):source.index('/* madeira-bcd lean-diag:')]
assert xp.index('ios_cs2_stall_main_sample(th[k], idi.thread_id);') < xp.index('if (pt + et > 0.05)')
native = (root / 'build/ntdll-unix/cs2_stall_watch_native.h').read_text()
held = native[native.index('suspend_result = thread_suspend(port);'):native.index('ios_stuck_clock_us(&held_end);')]
assert held.count('thread_resume(port)') == 1
assert not re.search(r'ios_ts_|wine_log|malloc|pthread_|process_try|ios_ldst', held)
recovery = native[native.index('static void ios_cs2_stall_recovery_note('):]
assert 'thread_suspend(' not in recovery and 'thread_set_state(' not in recovery
assert 'ios_cs2_stall_register_worker' in source[source.index('static void ios_ts_print_copy('):source.index('static void ios_thread_sampler_pass(')]
assert source.index('thread_resume(tlist[k]);', source.index('static void ios_thread_sampler_pass(')) < source.index('ios_ts_print_copy(&copy, rip, mp);')
print('CS2 exact-thread observation bounds and normal snapshot paths: PASS (no faults injected)')
