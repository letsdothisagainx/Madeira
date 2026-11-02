#!/usr/bin/env python3
"""Run the packaging entry point with synthetic build products/Xcode commands.
This validates resource gates and ZIP contents, not an iOS executable."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import zipfile
import struct
root = Path(__file__).resolve().parents[2]
entry = (root/'tools/build-ipa.sh').read_text()
assert entry.index('"$ROOT/tools/build/setup-llvm-mingw.sh"') < entry.index('"$ROOT/build/madeira-dock/build.sh"') < entry.index('"$ROOT/tools/build/package-ipa.sh"')
project = (root/'app/Madeira.xcodeproj/project.pbxproj').read_text()
assert 'A1000080 /* arm64ec-windows in Resources */' in project
assert 'lastKnownFileType = folder; path = "arm64ec-windows"' in project
script = (root/'tools/build/package-ipa.sh').read_text()
with tempfile.TemporaryDirectory() as temp:
    t = Path(temp); commands = t/'bin'; commands.mkdir()
    package = t/'package.sh'; package.write_text(script)
    # Populate all production prerequisites, avoiding a separate list that can drift.
    for relative in re.findall(r'"\$ROOT/([^"\n]+)"', script.split('for path in "${required[@]}"')[0]):
        p = t/relative
        if relative.endswith(('.a','.exe','.dll','.txt')):
            p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b'fixture')
    # A minimal architecture/marker fixture tests the gate, not executable Wine.
    wow = bytearray(256)
    wow[:2] = b'MZ'; struct.pack_into('<I', wow, 0x3c, 0x80)
    wow[0x80:0x84] = b'PE\0\0'; struct.pack_into('<H', wow, 0x84, 0xaa64)
    wow[0xa0:0xa0+len(b'madeira-io-abi-v2')] = b'madeira-io-abi-v2'
    wow.extend(b'[wow-thread-init-v1][wow-break-deliver-v1]MadeiraBTCpuWriteMemory[wow-query-zero-v1][wow-group-attribute-v1]')
    (t/'app/Madeira/aarch64-windows/wow64.dll').write_bytes(wow)
    cpu = bytearray(0x700)
    cpu[:0x98] = wow[:0x98]
    struct.pack_into('<H', cpu, 0x86, 2)  # writable DATA and native RX code
    struct.pack_into('<H', cpu, 0x94, 240)
    struct.pack_into('<H', cpu, 0x98, 0x20b)
    struct.pack_into('<II', cpu, 0x98 + 112, 0x1000, 0x100)
    cpu[0x188:0x190] = b'.data\0\0\0'
    struct.pack_into('<IIII', cpu, 0x190, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into('<I', cpu, 0x188 + 36, 0xc0000040)
    cpu[0x1b0:0x1b8] = b'.text\0\0\0'
    struct.pack_into('<IIII', cpu, 0x1b8, 0x100, 0x1400, 0x100, 0x600)
    struct.pack_into('<I', cpu, 0x1b0 + 36, 0x60000020)
    struct.pack_into('<IIHHIIIIIII', cpu, 0x200, 0, 0, 0, 0, 0, 1, 4, 4, 0x1040, 0x1050, 0x1060)
    struct.pack_into('<IIII', cpu, 0x240, 0x1200, 0x1208, 0x1400, 0x1404)
    struct.pack_into('<IIII', cpu, 0x250, 0x1080, 0x10a0, 0x10c0, 0x10e8)
    struct.pack_into('<HHHH', cpu, 0x260, 0, 1, 2, 3)
    for offset, name in [(0x280, b'ios_fex_band_base\0'), (0x2a0, b'ios_fex_band_end\0'),
                         (0x2c0, b'MadeiraBTCpuIosReleaseThreadHolds\0'), (0x2e8, b'MadeiraBTCpuIosRetireThread\0')]:
        cpu[offset:offset + len(name)] = name
    cpu.extend(b'MadeiraBTCpuThreadInit[fex-thread-init-v1]MadeiraBTCpuWriteMemory[fex-guest-write-v1][fex-first-use-v1][fex-blocklist-v1][fex-hold-release-v1][fex-thread-retire-v1]')
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(cpu)
    guest = bytearray(wow)
    struct.pack_into('<H',guest,0x84,0x14c)
    guest.extend(b'[wpm-call-v1][steam-arch-v1]')
    (t/'app/Madeira/i386-windows/kernelbase.dll').write_bytes(guest)
    (t/'tools').mkdir()
    (t/'tools/check-io-abi-package.py').write_text((root/'tools/check-io-abi-package.py').read_text())
    bodies = {
      'xcodebuild': '''mkdir -p "$TEST_APP/arm64ec-windows" "$TEST_APP/i386-windows" "$TEST_APP/x86_64-vcruntime" "$TEST_APP/aarch64-windows"
cp "$ROOT/app/Madeira/aarch64-windows/wow64.dll" "$ROOT/app/Madeira/aarch64-windows/xtajit.dll" "$TEST_APP/aarch64-windows/"
printf '[child-native-ntdll-v1][guest-trap-context-v1][surface-expose-v1][steam-client-update-v1][alias-prot-compat][image-alias-retire-v1][swp-context-v1][alias-prot-v2][fex-exit-v1][native-thread-cancel-v1][io-abi] v2 native-owned IOSB scopes active[wow-write][guest32-symbols][guest32-cxx-first-v1][cef-atexit-v1][steam-handoff-v1]_madeira_child_server_exited[fex-owner-v1] pre-crt[fex-owner-v1] retired[fex-owner-census-v2][hold-release-v2][deliver-hold-v2][native-window-retire-v1]_winios_native_window_create_winios_native_window_retire[guest32-fault-v1][steam-progress-v1]_winios_ui_progress_snapshot[srv-poll-drop-v1]poll-slots-highwater=' > "$TEST_APP/Madeira.debug.dylib"
cp "$ROOT/app/Madeira/i386-windows/kernelbase.dll" "$TEST_APP/i386-windows/"
printf fixture > "$TEST_APP/Madeira"
printf fixture > "$TEST_APP/prefix-template.tar.gz"
printf fixture > "$TEST_APP/arm64ec-windows/xtajit64.dll"
printf fixture > "$TEST_APP/x86_64-vcruntime/vcruntime140.dll"
for resource in dockhost.exe dock-notices.txt madeira-steam-service.exe madeira-scm-probe.exe; do
  if [ "${OMIT_RESOURCE:-}" != "$resource" ]; then cp "$ROOT/app/Madeira/arm64ec-windows/$resource" "$TEST_APP/arm64ec-windows/"; fi
done
for resource in madeira-wow64-probe.exe madeira-wow64-module-probe.dll; do
  if [ "${OMIT_RESOURCE:-}" != "$resource" ]; then cp "$ROOT/app/Madeira/i386-windows/$resource" "$TEST_APP/i386-windows/"; fi
done
''',
      'codesign': 'if [ "$1" = -d ]; then echo com.apple.security.cs.allow-jit; fi\n',
      'ditto': 'cp -R "$1" "$2"\n',
    }
    for name, body in bodies.items():
        p=commands/name; p.write_text('#!/bin/sh\nset -eu\n'+body); p.chmod(0o755)
    env=dict(os.environ, ROOT=str(t), TEST_APP=str(t/'app/DerivedData/Build/Products/Debug-iphoneos/Madeira.app'), PATH=str(commands)+os.pathsep+os.environ['PATH'])
    def run(extra=None):
        return subprocess.run(['bash',str(package)],env=dict(env,**(extra or {})),capture_output=True,text=True)
    result=run(); assert result.returncode == 0, result.stdout+result.stderr
    with zipfile.ZipFile(t/'dist/Madeira.ipa') as archive:
        for resource in ['dockhost.exe','dock-notices.txt','madeira-steam-service.exe','madeira-scm-probe.exe']:
            assert archive.read('Payload/Madeira.app/arm64ec-windows/'+resource) == b'fixture'
    with zipfile.ZipFile(t/'dist/Madeira.ipa') as archive:
        for resource in ['madeira-wow64-probe.exe','madeira-wow64-module-probe.dll']:
            assert archive.read('Payload/Madeira.app/i386-windows/'+resource)==b'fixture'
    print('PASS final ZIP includes Dock, helpers, i386 loader fixture and license notices')
    for resource in ['dockhost.exe','dock-notices.txt','madeira-steam-service.exe','madeira-scm-probe.exe']:
        result=run({'OMIT_RESOURCE':resource})
        assert result.returncode != 0 and 'required bundle resource missing' in result.stderr, result.stderr
        p=t/'app/Madeira/arm64ec-windows'/resource; p.write_bytes(b'')
        result=run()
        assert result.returncode != 0 and 'required build artifact missing' in result.stderr, result.stderr
        p.write_bytes(b'fixture')
    for resource in ['madeira-wow64-probe.exe','madeira-wow64-module-probe.dll']:
        result=run({'OMIT_RESOURCE':resource}); assert result.returncode and 'required bundle resource missing' in result.stderr
        p=t/'app/Madeira/i386-windows'/resource; p.write_bytes(b'')
        result=run();assert result.returncode and 'required build artifact missing' in result.stderr
        p.write_bytes(b'fixture')
    print('PASS missing bundle resources and empty staging outputs fail packaging')
    invalid_cpu = bytearray(cpu)
    invalid_cpu[0x280] = ord('x')
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(invalid_cpu)
    result=run()
    assert result.returncode and 'FEX compatibility exports missing' in result.stderr, result.stderr
    invalid_cpu = bytearray(cpu)
    struct.pack_into('<I', invalid_cpu, 0x188 + 36, 0xe0000040)
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(invalid_cpu)
    result=run()
    assert result.returncode and 'writable non-executable DATA' in result.stderr, result.stderr
    struct.pack_into('<I', invalid_cpu, 0x188 + 36, 0xd0000040)
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(invalid_cpu)
    result=run()
    assert result.returncode and 'private writable non-executable DATA' in result.stderr, result.stderr
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(cpu)
    print('PASS missing or executable FEX arena DATA exports fail final IPA validation')
    for export, message in [(0x1200, 'native RX function'), (0x10c0, 'export is forwarded')]:
        invalid_cpu = bytearray(cpu)
        struct.pack_into('<I', invalid_cpu, 0x248, export)
        (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(invalid_cpu)
        result=run()
        assert result.returncode and message in result.stderr, result.stderr
    invalid_cpu = bytearray(cpu)
    struct.pack_into('<I', invalid_cpu, 0x1b0 + 36, 0xe0000020)
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(invalid_cpu)
    result=run()
    assert result.returncode and 'native RX function' in result.stderr, result.stderr
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(cpu)
    print('PASS writable, non-executable and forwarded FEX hold-release callbacks fail final IPA validation')
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(wow)
    result=run()
    assert result.returncode and 'stale FEX CPU producer' in result.stderr, result.stderr
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(cpu)
    print('PASS stale FEX checked-init producer fails final IPA validation')
    (t/'app/Madeira/aarch64-windows/wow64.dll').write_bytes(b'old image')
    result=run()
    assert result.returncode and 'not a PE image' in result.stderr, result.stderr
    print('PASS stale WoW64 IOSB producer fails final IPA validation')
