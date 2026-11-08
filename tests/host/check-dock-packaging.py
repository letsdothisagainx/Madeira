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
import plistlib
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
    import importlib.util
    fixture_spec=importlib.util.spec_from_file_location('htmlipc_fixture', root/'tests/host/check-htmlipc-image.py')
    htmlipc=importlib.util.module_from_spec(fixture_spec);fixture_spec.loader.exec_module(htmlipc)
    bridge=htmlipc.fixture();bridge_manifest=htmlipc.manifest(bridge)
    bridge_dir=t/'app/Madeira/arm64ec-windows'
    bridge_dir.mkdir(parents=True,exist_ok=True)
    (bridge_dir/'madeira-htmlipc-bridge.dll').write_bytes(bridge)
    import json
    (bridge_dir/'madeira-htmlipc-bridge.manifest.json').write_text(json.dumps(bridge_manifest))
    (t/'tools').mkdir(exist_ok=True)
    (t/'tools/check-htmlipc-image.py').write_text((root/'tools/check-htmlipc-image.py').read_text())
    abi=t/'build/scm-rpc/htmlipc_ready_abi.h';abi.parent.mkdir(parents=True,exist_ok=True);abi.write_bytes(htmlipc.ABI.read_bytes())
    report=t/'build/htmlipc/obj/madeira-htmlipc-bridge.build.json';report.parent.mkdir(parents=True,exist_ok=True)
    source_hashes={}
    for index in range(7):
        path=t/f'source/{index}.cpp';path.parent.mkdir(parents=True,exist_ok=True);path.write_text(str(index))
        source_hashes[path.relative_to(t).as_posix()]=htmlipc.image.sha256(path.read_bytes())
    report.write_text(json.dumps(htmlipc.report(bridge,source_hashes)))
    service_fixture = b'fixture update-handoff-v1' 
    service_path = t/'app/Madeira/arm64ec-windows/madeira-steam-service.exe'
    service_path.write_bytes(service_fixture)
    # A minimal architecture/marker fixture tests the gate, not executable Wine.
    wow = bytearray(256)
    wow[:2] = b'MZ'; struct.pack_into('<I', wow, 0x3c, 0x80)
    wow[0x80:0x84] = b'PE\0\0'; struct.pack_into('<H', wow, 0x84, 0xaa64)
    wow[0xa0:0xa0+len(b'madeira-io-abi-v2')] = b'madeira-io-abi-v2'
    wow.extend(b'[wow-thread-init-v1][wow-break-deliver-v1]MadeiraBTCpuWriteMemory[wow-query-zero-v1][wow-group-attribute-v1]')
    (t/'app/Madeira/aarch64-windows/wow64.dll').write_bytes(wow)
    scm = bytearray(wow)
    scm.extend(b'[scm-pipe-wait-v1]')
    scm_path = t/'app/Madeira/aarch64-windows/services.exe'
    scm_path.write_bytes(scm)
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
    shared = b'[fex-core-init-v1][fex-ir-pool-v1][fex-owner-allocator-v1]'
    cpu.extend(shared)
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(cpu)
    # ARM64EC keeps its own exports and hybrid metadata, without acquiring
    # WoW64-only TLS/hold exports. This is a packaging fixture, not executable FEX.
    ec_cpu = bytearray(cpu[:0x700])
    struct.pack_into('<H', ec_cpu, 0x84, 0x8664)
    struct.pack_into('<Q', ec_cpu, 0x98 + 24, 0x180000000)
    struct.pack_into('<II', ec_cpu, 0x98 + 112 + 80, 0x1180, 208)
    ec_cpu[0x240:0x600] = bytes(0x3c0)
    struct.pack_into('<IIHHIIIIIII', ec_cpu, 0x200, 0, 0, 0, 0, 0, 1, 5, 5, 0x1040, 0x1060, 0x1080)
    struct.pack_into('<IIIII', ec_cpu, 0x240, 0x13a0, 0x13a8, 0x1400, 0x1404, 0x1408)
    struct.pack_into('<IIIII', ec_cpu, 0x260, 0x10a0, 0x10c0, 0x10e0, 0x1100, 0x1120)
    struct.pack_into('<HHHHH', ec_cpu, 0x280, 0, 1, 2, 3, 4)
    for offset, name in [(0x2a0, b'ios_fex_band_base'), (0x2c0, b'ios_fex_band_end'),
                         (0x2e0, b'BTCpu64FlushInstructionCache'), (0x300, b'BTCpu64NotifyMemoryDirty'),
                         (0x320, b'BTCpu64IosAddAliasMapping')]:
        ec_cpu[offset:offset + len(name) + 1] = name + b'\0'
    struct.pack_into('<I', ec_cpu, 0x380, 208)
    struct.pack_into('<Q', ec_cpu, 0x380 + 200, 0x180001260)
    struct.pack_into('<III', ec_cpu, 0x460, 1, 0x1270, 1)
    struct.pack_into('<II', ec_cpu, 0x470, 0x1401, 0x100)
    ec_cpu.extend(shared)
    ec_cpu_path = t/'app/Madeira/arm64ec-windows/xtajit64.dll'
    ec_cpu_path.write_bytes(ec_cpu)
    guest = bytearray(wow)
    struct.pack_into('<H',guest,0x84,0x14c)
    guest.extend(b'[wpm-call-v1][steam-arch-v1]')
    (t/'app/Madeira/i386-windows/kernelbase.dll').write_bytes(guest)
    (t/'tools').mkdir(exist_ok=True)
    (t/'tools/check-io-abi-package.py').write_text((root/'tools/check-io-abi-package.py').read_text())
    bodies = {
      'xcodebuild': '''mkdir -p "$TEST_APP/arm64ec-windows" "$TEST_APP/i386-windows" "$TEST_APP/x86_64-vcruntime" "$TEST_APP/aarch64-windows"
python3 - "$TEST_APP/Info.plist" <<'PY_FIXTURE_INFO'
import plistlib, sys
from pathlib import Path
Path(sys.argv[1]).write_bytes(plistlib.dumps({'CFBundleIdentifier':'test.madeira.fixture', 'CFBundleShortVersionString':'0.1.3', 'CFBundleVersion':'4'}))
PY_FIXTURE_INFO
cp "$ROOT/app/Madeira/aarch64-windows/wow64.dll" "$ROOT/app/Madeira/aarch64-windows/xtajit.dll" "$TEST_APP/aarch64-windows/"
cp "$ROOT/app/Madeira/aarch64-windows/services.exe" "$TEST_APP/aarch64-windows/"
if [ "${STALE_SCM:-}" = 1 ]; then printf 'old SCM' > "$TEST_APP/aarch64-windows/services.exe"; fi
printf '[native-group-retire-v1][wow-placement-v1][wow-native-export-v1][fex-callback-v2][child-native-dll-v1][process-wow64-v1][child-native-ntdll-v1][guest-trap-context-v1][surface-expose-v1][steam-client-update-v1][alias-prot-compat][image-alias-retire-v1][swp-context-v1][alias-prot-v2][fex-exit-v1][native-thread-cancel-v1][io-abi] v2 native-owned IOSB scopes active[wow-write][guest32-symbols][guest32-cxx-first-v1][cef-atexit-v1][steam-handoff-v1]_madeira_child_server_exited[fex-owner-v1] pre-crt[fex-owner-v1] retired[fex-owner-census-v2][hold-release-v2][deliver-hold-v2][native-window-retire-v1]_winios_native_window_create_winios_native_window_retire[guest32-fault-v1][steam-progress-v1]_winios_ui_progress_snapshot[srv-poll-drop-v1]poll-slots-highwater=' > "$TEST_APP/Madeira.debug.dylib"
printf '[cef-image-owner-v1][guest-breakpoint64-v1]' >> "$TEST_APP/Madeira.debug.dylib"
if [ "${STALE_CEF_IMAGE:-}" = 1 ]; then
  sed 's/\\[cef-image-owner-v1\\]//g' "$TEST_APP/Madeira.debug.dylib" > "$TEST_APP/native.stale"
  mv "$TEST_APP/native.stale" "$TEST_APP/Madeira.debug.dylib"
fi
if [ "${STALE_GUEST64_BREAK:-}" = 1 ]; then
  sed 's/\\[guest-breakpoint64-v1\\]//g' "$TEST_APP/Madeira.debug.dylib" > "$TEST_APP/native.stale"
  mv "$TEST_APP/native.stale" "$TEST_APP/Madeira.debug.dylib"
fi
if [ "${STALE_NATIVE_GROUP:-}" = 1 ]; then
  sed 's/\\[native-group-retire-v1\\]//g' "$TEST_APP/Madeira.debug.dylib" > "$TEST_APP/native.stale"
  mv "$TEST_APP/native.stale" "$TEST_APP/Madeira.debug.dylib"
fi
if [ "${STALE_WOW_PLACEMENT:-}" = 1 ]; then
  sed 's/\\[wow-placement-v1\\]//g' "$TEST_APP/Madeira.debug.dylib" > "$TEST_APP/native.stale"
  mv "$TEST_APP/native.stale" "$TEST_APP/Madeira.debug.dylib"
fi
cp "$ROOT/app/Madeira/i386-windows/kernelbase.dll" "$TEST_APP/i386-windows/"
printf fixture > "$TEST_APP/Madeira"
printf fixture > "$TEST_APP/prefix-template.tar.gz"
cp "$ROOT/app/Madeira/arm64ec-windows/xtajit64.dll" "$TEST_APP/arm64ec-windows/"
if [ "${STALE_EC_CPU:-}" = 1 ]; then printf 'old CPU' > "$TEST_APP/arm64ec-windows/xtajit64.dll"; fi
printf fixture > "$TEST_APP/x86_64-vcruntime/vcruntime140.dll"
for resource in dockhost.exe dock-notices.txt madeira-steam-service.exe madeira-scm-probe.exe madeira-htmlipc-bridge.dll madeira-htmlipc-bridge.manifest.json; do
  if [ "${OMIT_RESOURCE:-}" != "$resource" ]; then cp "$ROOT/app/Madeira/arm64ec-windows/$resource" "$TEST_APP/arm64ec-windows/"; fi
done
if [ "${STALE_HTMLIPC:-}" = 1 ]; then printf old-source > "$TEST_APP/arm64ec-windows/madeira-htmlipc-bridge.dll"; fi
if [ "${STALE_SERVICE:-}" = 1 ]; then printf 'old update-handoff-v1' > "$TEST_APP/arm64ec-windows/madeira-steam-service.exe"; fi
for resource in madeira-wow64-probe.exe madeira-wow64-module-probe.dll; do
  if [ "${OMIT_RESOURCE:-}" != "$resource" ]; then cp "$ROOT/app/Madeira/i386-windows/$resource" "$TEST_APP/i386-windows/"; fi
done
''',
      'codesign': 'if [ "$1" = -d ]; then echo com.apple.security.cs.allow-jit; fi\n',
      'ditto': 'cp -R "$1" "$2"\n',
    }
    for name, body in bodies.items():
        p=commands/name; p.write_text('#!/bin/sh\nset -eu\n'+body); p.chmod(0o755)
    revision = '0123456789abcdef0123456789abcdef01234567'
    env=dict(os.environ, ROOT=str(t), GITHUB_SHA=revision, TEST_APP=str(t/'app/DerivedData/Build/Products/Debug-iphoneos/Madeira.app'), PATH=str(commands)+os.pathsep+os.environ['PATH'])
    def run(extra=None):
        return subprocess.run(['bash',str(package)],env=dict(env,**(extra or {})),capture_output=True,text=True)
    result=run(); assert result.returncode == 0, result.stdout+result.stderr
    result=run({'STALE_EC_CPU':'1'})
    assert result.returncode and 'Xcode packaged stale ARM64EC FEX' in result.stderr, result.stderr
    for marker in (b'[fex-ir-pool-v1]', b'[fex-owner-allocator-v1]'):
        ec_cpu_path.write_bytes(ec_cpu.replace(marker, b'old'))
        result=run()
        assert result.returncode and 'stale arm64ec FEX shared protection' in result.stderr, result.stderr
    ec_cpu_path.write_bytes(ec_cpu)
    invalid_ec = bytearray(ec_cpu); struct.pack_into('<Q', invalid_ec, 0x380 + 200, 0)
    ec_cpu_path.write_bytes(invalid_ec)
    result=run()
    assert result.returncode and 'CHPE metadata missing' in result.stderr, result.stderr
    ec_cpu_path.write_bytes(ec_cpu)
    result=run(); assert result.returncode == 0, result.stdout+result.stderr
    print('PASS both PE CPUs require shared allocator/IR protections; stale ARM64EC copies and missing hybrid metadata fail')
    with zipfile.ZipFile(t/'dist/Madeira.ipa') as archive:
        info = plistlib.loads(archive.read('Payload/Madeira.app/Info.plist'))
        assert info['MadeiraBuild'] == 'v0.1.3 (4) source=' + revision
        assert info['CFBundleIdentifier'] == 'test.madeira.fixture'
        for resource in ['dockhost.exe','dock-notices.txt','madeira-steam-service.exe','madeira-scm-probe.exe']:
            assert archive.read('Payload/Madeira.app/arm64ec-windows/'+resource) == (service_fixture if resource == 'madeira-steam-service.exe' else b'fixture')
    with zipfile.ZipFile(t/'dist/Madeira.ipa') as archive:
        for resource in ['madeira-wow64-probe.exe','madeira-wow64-module-probe.dll']:
            assert archive.read('Payload/Madeira.app/i386-windows/'+resource)==b'fixture'
    result=run({'GITHUB_SHA':'invalid-revision'})
    assert result.returncode and 'invalid source revision' in result.stderr, result.stderr
    print('PASS exact source revision is packaged in the existing build label; invalid revisions fail closed and bundle ID is preserved')
    for resource,expected in [('madeira-htmlipc-bridge.dll',bridge),('madeira-htmlipc-bridge.manifest.json',json.dumps(bridge_manifest).encode())]:
        with zipfile.ZipFile(t/'dist/Madeira.ipa') as archive:
            assert archive.read('Payload/Madeira.app/arm64ec-windows/'+resource)==expected
        result=run({'OMIT_RESOURCE':resource})
        assert result.returncode and 'required bundle resource missing' in result.stderr,result.stderr
        path=bridge_dir/resource;path.write_bytes(b'')
        result=run();assert result.returncode and 'required build artifact missing' in result.stderr,result.stderr
        path.write_bytes(expected)
    result=run({'STALE_HTMLIPC':'1'})
    assert result.returncode and 'app resource differs from staged' in result.stderr,result.stderr
    print('PASS AMD64 source DLL/manifest present exactly; missing, empty and stale Xcode source resources fail packaging')
    print('PASS final ZIP includes Dock, helpers, i386 loader fixture and license notices')
    result=run({'STALE_WOW_PLACEMENT':'1'})
    assert result.returncode and 'stale native WoW64-segment placement' in result.stderr, result.stderr
    print('PASS stale native WoW64-segment placement fails final IPA validation')
    result=run({'STALE_NATIVE_GROUP':'1'})
    assert result.returncode and 'stale native process-group retirement' in result.stderr, result.stderr
    print('PASS stale native process-group retirement fails final IPA validation')
    result=run({'STALE_CEF_IMAGE':'1'})
    assert result.returncode and 'stale private CEF image retirement' in result.stderr, result.stderr
    result=run({'STALE_GUEST64_BREAK':'1'})
    assert result.returncode and 'stale AMD64 guest breakpoint diagnostics' in result.stderr, result.stderr
    print('PASS stale CEF backing retirement and AMD64 trap diagnostics fail final IPA validation')
    for resource in ['dockhost.exe','dock-notices.txt','madeira-steam-service.exe','madeira-scm-probe.exe']:
        result=run({'OMIT_RESOURCE':resource})
        assert result.returncode != 0 and 'required bundle resource missing' in result.stderr, result.stderr
        p=t/'app/Madeira/arm64ec-windows'/resource; p.write_bytes(b'')
        result=run()
        assert result.returncode != 0 and 'required build artifact missing' in result.stderr, result.stderr
        p.write_bytes(service_fixture if resource == 'madeira-steam-service.exe' else b'fixture')
    for resource in ['madeira-wow64-probe.exe','madeira-wow64-module-probe.dll']:
        result=run({'OMIT_RESOURCE':resource}); assert result.returncode and 'required bundle resource missing' in result.stderr
        p=t/'app/Madeira/i386-windows'/resource; p.write_bytes(b'')
        result=run();assert result.returncode and 'required build artifact missing' in result.stderr
        p.write_bytes(b'fixture')
    print('PASS missing bundle resources and empty staging outputs fail packaging')
    service_path.write_bytes(b'old helper')
    result=run()
    assert result.returncode and 'stale Steam service update handoff helper' in result.stderr, result.stderr
    service_path.write_bytes(service_fixture)
    result=run({'STALE_SERVICE':'1'})
    assert result.returncode and 'Xcode packaged stale Steam service helper' in result.stderr, result.stderr
    print('PASS stale service handoff helper and stale Xcode resource copy fail final IPA validation')
    scm_path.write_bytes(wow)
    result=run()
    assert result.returncode and 'stale SCM startup timeout producer' in result.stderr, result.stderr
    scm_path.write_bytes(scm)
    result=run({'STALE_SCM':'1'})
    assert result.returncode and 'Xcode packaged stale SCM startup producer' in result.stderr, result.stderr
    invalid_scm = bytearray(scm); struct.pack_into('<H',invalid_scm,0x84,0x8664)
    scm_path.write_bytes(invalid_scm)
    result=run()
    assert result.returncode and 'SCM must retain native ARM64 architecture' in result.stderr, result.stderr
    scm_path.write_bytes(scm)
    print('PASS stale, wrong-architecture and stale-bundle SCM producers fail final IPA validation')
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
    assert result.returncode and 'stale WoW64 FEX' in result.stderr, result.stderr
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(cpu)
    print('PASS stale FEX checked-init producer fails final IPA validation')
    (t/'app/Madeira/aarch64-windows/wow64.dll').write_bytes(b'old image')
    result=run()
    assert result.returncode and 'not a PE image' in result.stderr, result.stderr
    print('PASS stale WoW64 IOSB producer fails final IPA validation')
