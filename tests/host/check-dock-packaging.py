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
import shutil
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
    # Exercise the actual script bytes, not a protocol-shaped marker. These
    # packaging fixtures do not execute a debugger or claim an iPhone result.
    jit_script=t/'app/Madeira/madeira-jit.js'
    jit_script.parent.mkdir(parents=True,exist_ok=True)
    jit_script.write_bytes((root/'app/Madeira/madeira-jit.js').read_bytes())
    import importlib.util
    package_fixture_spec=importlib.util.spec_from_file_location('fex_package_fixture',root/'tests/host/check-fex-subfloor-package.py')
    package_fixture=importlib.util.module_from_spec(package_fixture_spec);package_fixture_spec.loader.exec_module(package_fixture)
    for directory,machine in (('aarch64-windows',0xaa64),('arm64ec-windows',0x8664)):
        native_path=t/'app/Madeira'/directory/'ntdll.dll';native_path.parent.mkdir(parents=True,exist_ok=True)
        native_path.write_bytes(package_fixture.ntdll_fixture(machine)[0])
    stage_verifier=t/'tools/build/stage-native-counter-writes.py';stage_verifier.parent.mkdir(parents=True,exist_ok=True)
    stage_verifier.write_bytes((root/'tools/build/stage-native-counter-writes.py').read_bytes())
    (stage_verifier.parent/'stage-native-srw-wake.py').write_bytes((root/'tools/build/stage-native-srw-wake.py').read_bytes())
    (stage_verifier.parent/'stage-native-lfh-size.py').write_bytes((root/'tools/build/stage-native-lfh-size.py').read_bytes())
    # Keep the real provenance gate active. Xcode below supplies a structural
    # Mach-O with real fixture source digests; it is deliberately not executable.
    # The separate native-provenance check compiles the actual accessors/decoder.
    (t/'tools/build/native-provenance.py').write_bytes((root/'tools/build/native-provenance.py').read_bytes())
    for relative in ('build/ntdll-unix/virtual_ios.c','build/ntdll-unix/pe_x64_write_span.h',
                     'app/Madeira/JITAllocator.c'):
        target=t/relative;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes((root/relative).read_bytes())
    native_abi=t/'build/ntdll-unix/native_counter_alias_abi.h';native_abi.parent.mkdir(parents=True,exist_ok=True)
    native_abi.write_bytes((root/'build/ntdll-unix/native_counter_alias_abi.h').read_bytes())
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
    (t/'tools/check-dxmt-pixel-probe.py').write_text((root/'tools/check-dxmt-pixel-probe.py').read_text())
    # Structural, deliberately non-executable PE fixture for the packaging
    # gate only. The actual D3D11 probe is compiled by build-pixel-readback.sh;
    # this synthetic import table never supplies a pixel/GPU result.
    pixel_fixture = bytearray(0xa00)
    pixel_fixture[:2] = b'MZ'
    struct.pack_into('<I', pixel_fixture, 0x3c, 0x80)
    pixel_fixture[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', pixel_fixture, 0x84, 0x8664, 1)
    struct.pack_into('<H', pixel_fixture, 0x94, 0xf0)
    struct.pack_into('<H', pixel_fixture, 0x98, 0x20b)
    struct.pack_into('<H', pixel_fixture, 0x98 + 68, 3)
    struct.pack_into('<II', pixel_fixture, 0x98 + 120, 0x1000, 40)
    struct.pack_into('<IIII', pixel_fixture, 0x188 + 8, 0x800, 0x1000, 0x800, 0x200)
    struct.pack_into('<IIIII', pixel_fixture, 0x200, 0x1040, 0, 0, 0x1050, 0x1040)
    struct.pack_into('<Q', pixel_fixture, 0x240, 0x1060)
    pixel_fixture[0x250:0x25a] = b'd3d11.dll\0'
    pixel_fixture[0x262:0x273] = b'D3D11CreateDevice\0'
    markers = b'[d3d11-pixels]\0DXMT device identity\0GPU completion exceeded 30 seconds\0BC3-update-copy-region-tail\0readbacks=%u failures=%u\0contract=extended-v2 expected-readbacks=184 baseline=113\0'
    pixel_fixture[0x2a0:0x2a0 + len(markers)] = markers
    pixel_fixture = bytes(pixel_fixture)
    pixel_path = bridge_dir/'pixel-readback-x64.exe'
    pixel_path.write_bytes(pixel_fixture)
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
    # Reuse the full package fixture: actual private diagnostic descriptors,
    # valid zero-fill payload bounds, real arena exports and hybrid metadata.
    # These bytes prove packaging gates, not executable Wine/FEX behavior.
    cpu, cpu_meta = package_fixture.fex_fixture('wow64')
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(cpu)
    ec_cpu, ec_meta = package_fixture.fex_fixture('arm64ec')
    ec_cpu_path = t/'app/Madeira/arm64ec-windows/xtajit64.dll'
    ec_cpu_path.write_bytes(ec_cpu)
    guest = bytearray(wow)
    struct.pack_into('<H',guest,0x84,0x14c)
    guest.extend(b'[wpm-call-v1][steam-arch-v1]')
    (t/'app/Madeira/i386-windows/kernelbase.dll').write_bytes(guest)
    # Compose real provenance fixtures without replacing the independently
    # validated ntdll/FEX/HTMLIPC images above. Every final gate remains active.
    registration_spec=importlib.util.spec_from_file_location('dock_registration_fixture',root/'tests/host/check-native-registration-tools.py')
    registration=importlib.util.module_from_spec(registration_spec);registration_spec.loader.exec_module(registration)
    registration_stage,registration_source,_,_=registration.fixture_tree(t/'registration-fixture')
    shutil.copytree(registration_source,t/'wine',dirs_exist_ok=True)
    for farm in registration.CHECKER.FARMS:
        for resource in ('regsvr32.exe','rundll32.exe','user32.dll','ole32.dll','kernelbase.dll'):
            shutil.copyfile(registration_stage/farm/resource,t/'app/Madeira'/farm/resource)
    guest=(t/'app/Madeira/i386-windows/kernelbase.dll').read_bytes()+b'[wpm-call-v1][steam-arch-v1]'
    (t/'app/Madeira/i386-windows/kernelbase.dll').write_bytes(guest)
    shutil.copyfile(registration_stage/registration.CHECKER.MANIFEST,t/'app/Madeira'/registration.CHECKER.MANIFEST)
    trust_spec=importlib.util.spec_from_file_location('dock_trust_fixture',root/'tests/host/check-trust-diagnostics-package.py')
    trust=importlib.util.module_from_spec(trust_spec);trust_spec.loader.exec_module(trust)
    trust_stage,trust_source,trust_recipes,_,_=trust.fixture_tree(t/'trust-fixture')
    shutil.copytree(trust_source,t/'wine',dirs_exist_ok=True)
    shutil.copytree(trust_recipes,t,dirs_exist_ok=True)
    for farm in trust.CHECKER.FARMS:
        shutil.copyfile(trust_stage/farm/'wintrust.dll',t/'app/Madeira'/farm/'wintrust.dll')
    shutil.copyfile(trust_stage/trust.CHECKER.MANIFEST,t/'app/Madeira'/trust.CHECKER.MANIFEST)
    # Keep the new security package gate active alongside registration/trust.
    # These owned COFF/PE byte fixtures prove packaging only, never executable
    # signature verification, Windows API behavior or VAC compatibility.
    security_spec=importlib.util.spec_from_file_location('dock_security_fixture',root/'tests/host/check-security-compat-package.py')
    security=importlib.util.module_from_spec(security_spec);security_spec.loader.exec_module(security)
    security_stage,security_source,security_recipes,_,_=security.setup(t/'security-fixture')
    shutil.copytree(security_source,t/'wine',dirs_exist_ok=True)
    shutil.copytree(security_recipes,t,dirs_exist_ok=True)
    for farm in security.CHECKER.FARMS:
        shutil.copyfile(security_stage/farm/'crypt32.dll',t/'app/Madeira'/farm/'crypt32.dll')
        kernelbase=security_stage/farm/'kernelbase.dll'
        data=kernelbase.read_bytes()+registration.CHECKER.MARKER
        if farm=='i386-windows':
            data+=b'[wpm-call-v1][steam-arch-v1]'
        kernelbase.write_bytes(data)
        shutil.copyfile(kernelbase,t/'app/Madeira'/farm/'kernelbase.dll')
    security.check(security_stage,security_source,security_recipes,writing=True,objects=security_source)
    shutil.copyfile(security_stage/security.CHECKER.MANIFEST,t/'app/Madeira'/security.CHECKER.MANIFEST)
    # Compose the registry security compiler/linked-code provenance fixture
    # through its real checker. Do not stub the new final packaging gate.
    registry_spec=importlib.util.spec_from_file_location('dock_registry_fixture',root/'tests/host/check-registry-security-package.py')
    registry=importlib.util.module_from_spec(registry_spec);registry_spec.loader.exec_module(registry)
    registry_stage,registry_source,registry_recipes,_,_=registry.setup(t/'registry-fixture')
    shutil.copytree(registry_source,t/'wine',dirs_exist_ok=True)
    shutil.copytree(registry_recipes,t,dirs_exist_ok=True)
    for farm in registry.CHECK.code.FARMS:
        shutil.copyfile(registry_stage/farm/'advapi32.dll',t/'app/Madeira'/farm/'advapi32.dll')
    shutil.copyfile(registry_stage/registry.CHECK.MANIFEST,t/'app/Madeira'/registry.CHECK.MANIFEST)
    # Keep the actual memory-recipe provenance gate active. These owned PE
    # fixtures carry checked ABI/export structures, not working DXMT code.
    # Real stagers operate transactionally on copied pinned source bytes; no
    # production bypass or hand-written successful manifest is supplied.
    memory_spec=importlib.util.spec_from_file_location('dock_dxmt_memory_fixture',root/'tools/check-dxmt-memory-package.py')
    memory=importlib.util.module_from_spec(memory_spec);memory_spec.loader.exec_module(memory)
    for relative in memory.RECIPES:
        target=t/relative;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes((root/relative).read_bytes())
    compat_spec=importlib.util.spec_from_file_location('dock_dxmt_memory_stage',root/'tools/build/stage-dxmt-memory-compat.py')
    compat=importlib.util.module_from_spec(compat_spec);compat_spec.loader.exec_module(compat)
    source_names=['src/dxmt/'+name for name in compat.UPLOAD]+list(compat.DYNAMIC)
    source_names+=list(compat.CENSUS)+list(compat.PERF)
    source_names+=['src/winemetal/unix/winemetal_unix.c']
    for relative in source_names:
        target=t/'dxmt'/relative;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes((root/'dxmt'/relative).read_bytes())
    # Pin the pristine shader so the real checker can independently derive the
    # existing, exact Xcode atomic compatibility transform from HEAD + recipe.
    shader=t/'dxmt'/memory.SHADER;shader.parent.mkdir(parents=True,exist_ok=True)
    shader.write_bytes(subprocess.check_output(['git','-C',str(root/'dxmt'),'show','HEAD:'+memory.SHADER]))
    for name in ('wine','dxmt'):
        subprocess.run(['git','init','-q',str(t/name)],check=True)
        if name=='dxmt':
            subprocess.run(['git','-C',str(t/name),'add','--',memory.SHADER],check=True)
        subprocess.run(['git','-C',str(t/name),'-c','user.name=Madeira package fixture',
                        '-c','user.email=fixture@invalid','-c','core.hooksPath=/dev/null',
                        'commit','-q','--allow-empty','-m','Structural packaging fixture pin'],check=True)
    shader.write_bytes(memory.shader_bytes(t)[1])
    for farm in memory.FARMS:
        for module,export in memory.MODULES.items():
            data=bytearray(registration.fixture(farm))
            if export:
                dirs=0x98+(96 if farm=='i386-windows' else 112)
                struct.pack_into('<II',data,dirs,0x2000,0xa0)
                struct.pack_into('<IIHHIIIIIII',data,0x600,0,0,0,0,0,1,1,1,0x2040,0x2050,0x2060)
                struct.pack_into('<I',data,0x640,0x1000)
                struct.pack_into('<I',data,0x650,0x2070)
                struct.pack_into('<H',data,0x660,0)
                name=export.encode()+b'\0';data[0x670:0x670+len(name)]=name
            if module=='d3d11.dll':
                data.extend(b'\0'.join(memory.PE_MARKERS))
            (t/'app/Madeira'/farm/module).write_bytes(data)
    (t/'app/Madeira/libdxmt_combined.a').write_bytes(b'!<arch>\nstructural fixture\0'+b'\0'.join(memory.NATIVE_MARKERS))
    memory_state=t/'memory-transaction'
    subprocess.run(['python3',str(t/'tools/build/stage-dxmt-memory-compat.py'),
                    'apply',str(memory_state),'--root',str(t)],check=True,stdout=subprocess.PIPE)
    subprocess.run(['python3',str(t/'tools/build/stage-dxmt-memory-compat.py'),
                    'restore',str(memory_state)],check=True,stdout=subprocess.PIPE)
    memory.check(t/'app/Madeira',t,write=True,transaction=memory_state)
    (t/'tools').mkdir(exist_ok=True)
    (t/'tools/check-io-abi-package.py').write_text((root/'tools/check-io-abi-package.py').read_text())
    bodies = {
      'xcodebuild': '''mkdir -p "$TEST_APP/arm64ec-windows" "$TEST_APP/i386-windows" "$TEST_APP/x86_64-vcruntime" "$TEST_APP/aarch64-windows"
if [ "${OMIT_RESOURCE:-}" != madeira-jit.js ]; then cp "$ROOT/app/Madeira/madeira-jit.js" "$TEST_APP/madeira-jit.js"; fi
if [ "${STALE_JIT_SCRIPT:-}" = 1 ]; then printf '\\n// stale debugger protocol' >> "$TEST_APP/madeira-jit.js"; fi
python3 - "$TEST_APP/Info.plist" <<'PY_FIXTURE_INFO'
import plistlib, sys
from pathlib import Path
Path(sys.argv[1]).write_bytes(plistlib.dumps({'CFBundleIdentifier':'test.madeira.fixture', 'CFBundleShortVersionString':'0.1.3', 'CFBundleVersion':'4'}))
PY_FIXTURE_INFO
cp "$ROOT/app/Madeira/aarch64-windows/wow64.dll" "$ROOT/app/Madeira/aarch64-windows/xtajit.dll" "$TEST_APP/aarch64-windows/"
cp "$ROOT/app/Madeira/aarch64-windows/services.exe" "$TEST_APP/aarch64-windows/"
cp "$ROOT/app/Madeira/aarch64-windows/ntdll.dll" "$TEST_APP/aarch64-windows/"
cp "$ROOT/app/Madeira/arm64ec-windows/ntdll.dll" "$TEST_APP/arm64ec-windows/"
for farm in aarch64-windows arm64ec-windows i386-windows; do
  for resource in regsvr32.exe rundll32.exe user32.dll ole32.dll kernelbase.dll wintrust.dll crypt32.dll advapi32.dll; do
    cp "$ROOT/app/Madeira/$farm/$resource" "$TEST_APP/$farm/"
  done
done
cp "$ROOT/app/Madeira/arm64ec-windows/madeira-system-programs.json" "$TEST_APP/arm64ec-windows/"
cp "$ROOT/app/Madeira/arm64ec-windows/madeira-trust-diagnostics.json" "$TEST_APP/arm64ec-windows/"
cp "$ROOT/app/Madeira/arm64ec-windows/madeira-security-compat.json" "$TEST_APP/arm64ec-windows/"
cp "$ROOT/app/Madeira/arm64ec-windows/madeira-registry-security.json" "$TEST_APP/arm64ec-windows/"
for farm in aarch64-windows arm64ec-windows i386-windows; do
  for resource in d3d11.dll dxgi.dll d3d10core.dll winemetal.dll; do
    cp "$ROOT/app/Madeira/$farm/$resource" "$TEST_APP/$farm/"
  done
done
cp "$ROOT/app/Madeira/arm64ec-windows/madeira-dxmt-memory.json" "$TEST_APP/arm64ec-windows/"
if [ "${STALE_DXMT_MEMORY:-}" = 1 ]; then printf 'stale DXMT' > "$TEST_APP/arm64ec-windows/d3d11.dll"; fi
if [ "${STALE_REGISTRATION_TOOL:-}" = 1 ]; then printf 'stale registration program' > "$TEST_APP/arm64ec-windows/regsvr32.exe"; fi
if [ "${STALE_TRUST_OBSERVER:-}" = 1 ]; then printf 'stale trust observer' > "$TEST_APP/arm64ec-windows/wintrust.dll"; fi
if [ "${STALE_SECURITY_CRYPTO:-}" = 1 ]; then printf 'stale crypto provider' > "$TEST_APP/arm64ec-windows/crypt32.dll"; fi
if [ "${STALE_REGISTRY_SECURITY:-}" = 1 ]; then printf 'stale registry security' > "$TEST_APP/i386-windows/advapi32.dll"; fi
if [ "${STALE_NATIVE_NTDLL:-}" = 1 ]; then printf 'old ntdll' > "$TEST_APP/arm64ec-windows/ntdll.dll"; fi
if [ "${STALE_SCM:-}" = 1 ]; then printf 'old SCM' > "$TEST_APP/aarch64-windows/services.exe"; fi
printf '[native-group-retire-v1][wow-placement-v1][wow-native-export-v1][fex-callback-v2][child-native-dll-v1][process-wow64-v1][child-native-ntdll-v1][guest-trap-context-v1][surface-expose-v1][steam-client-update-v1][alias-prot-compat][image-alias-retire-v1][swp-context-v1][alias-prot-v2][fex-exit-v1][native-thread-cancel-v1][io-abi] v2 native-owned IOSB scopes active[wow-write][guest32-symbols][guest32-cxx-first-v1][cef-atexit-v1][steam-handoff-v1]_madeira_child_server_exited[fex-owner-v1] pre-crt[fex-owner-v1] retired[fex-owner-census-v2][hold-release-v2][deliver-hold-v2][native-window-retire-v1]_winios_native_window_create_winios_native_window_retire[guest32-fault-v1][steam-progress-v1]_winios_ui_progress_snapshot[srv-poll-drop-v1]poll-slots-highwater=' > "$TEST_APP/Madeira.debug.dylib"
printf '[cef-image-owner-v1][guest-breakpoint64-v1]' >> "$TEST_APP/Madeira.debug.dylib"
printf '[dynamic-memory-pressure-v1] policy=bounded-hot-v2 storage=owner-heap-v1 counter-storage=census-perf-heap-v1 [upload-memory-v1][madeira-memory-pressure-v1]' >> "$TEST_APP/Madeira.debug.dylib"
if [ "${STALE_DXMT_NATIVE:-}" = 1 ]; then
  sed 's/\\[madeira-memory-pressure-v1\\]//g' "$TEST_APP/Madeira.debug.dylib" > "$TEST_APP/native.stale"
  mv "$TEST_APP/native.stale" "$TEST_APP/Madeira.debug.dylib"
fi
if [ "${STALE_SUBFLOOR_CONTRACT:-}" != 1 ]; then printf '[subfloor-contract-v1]' >> "$TEST_APP/Madeira.debug.dylib"; fi
if [ "${STALE_NATIVE_SRW_ALIAS:-}" != 1 ]; then printf '[native-srw-alias-v1]' >> "$TEST_APP/Madeira.debug.dylib"; fi
if [ "${STALE_FEX_NATIVE_DIAGNOSTICS:-}" != 1 ]; then
  printf '%s' '[fex-native-diagnostics-v1] module=%s spans=%u action=%s' >> "$TEST_APP/Madeira.debug.dylib"
else
  printf '%s' '[fex-native-diagnostics-v1] module=%s spans=3 action=%s' >> "$TEST_APP/Madeira.debug.dylib"
fi
if [ "${STALE_POOL_GROWTH:-}" != 1 ]; then printf '[pool-code-growth]' >> "$TEST_APP/Madeira.debug.dylib"; fi
if [ "${STALE_POOL_ACCOUNTING:-}" != 1 ]; then printf '[pool-accounting]' >> "$TEST_APP/Madeira.debug.dylib"; fi
if [ "${STALE_WINDOW_GEOMETRY:-}" != 1 ]; then printf '[cs2-window-geometry-v1]' >> "$TEST_APP/Madeira.debug.dylib"; fi
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
python3 - "$ROOT" "$TEST_APP/Madeira.debug.dylib" <<'PY_FIXTURE_NATIVE'
import hashlib, importlib.util, os, struct, sys
from pathlib import Path
root,image=Path(sys.argv[1]),Path(sys.argv[2])
spec=importlib.util.spec_from_file_location('native_provenance',root/'tools/build/native-provenance.py')
provenance=importlib.util.module_from_spec(spec);spec.loader.exec_module(provenance)
native=provenance.source_hash(root,'virtual')
jit=hashlib.sha256((root/'app/Madeira/JITAllocator.c').read_bytes()).hexdigest()
generated=(root/'app/Madeira/.build-provenance/JITAllocator.generated.h').read_text()
assert jit in generated and os.environ['GITHUB_SHA'] in generated, 'Xcode fixture needs the actual pre-build JIT provenance header'
if os.environ.get('STALE_NATIVE_SOURCE')=='1':native='0'*64
if os.environ.get('STALE_JIT_SOURCE')=='1':jit='0'*64
records=('MadeiraNativeVirtual:v1:'+native+':'+('a'*40)).encode()+bytes([0])
records+=('MadeiraJITAllocator:v1:'+jit+':'+os.environ['GITHUB_SHA']).encode()+bytes([0])
header=struct.pack('<8I',0xfeedfacf,0x100000c,0,6,1,24,0,0)
header+=struct.pack('<II',0x1b,24)+bytes.fromhex('123456781234567890ab123456789abc')
image.write_bytes(header+image.read_bytes()+records)
PY_FIXTURE_NATIVE
cp "$ROOT/app/Madeira/i386-windows/kernelbase.dll" "$TEST_APP/i386-windows/"
printf fixture > "$TEST_APP/Madeira"
printf fixture > "$TEST_APP/prefix-template.tar.gz"
cp "$ROOT/app/Madeira/arm64ec-windows/xtajit64.dll" "$TEST_APP/arm64ec-windows/"
if [ "${STALE_EC_CPU:-}" = 1 ]; then printf 'old CPU' > "$TEST_APP/arm64ec-windows/xtajit64.dll"; fi
printf fixture > "$TEST_APP/x86_64-vcruntime/vcruntime140.dll"
for resource in dockhost.exe dock-notices.txt madeira-steam-service.exe madeira-scm-probe.exe madeira-htmlipc-bridge.dll madeira-htmlipc-bridge.manifest.json pixel-readback-x64.exe; do
  if [ "${OMIT_RESOURCE:-}" != "$resource" ]; then cp "$ROOT/app/Madeira/arm64ec-windows/$resource" "$TEST_APP/arm64ec-windows/"; fi
done
if [ "${STALE_PIXEL_PROBE:-}" = 1 ]; then printf stale >> "$TEST_APP/arm64ec-windows/pixel-readback-x64.exe"; fi
if [ "${STALE_HTMLIPC:-}" = 1 ]; then printf old-source > "$TEST_APP/arm64ec-windows/madeira-htmlipc-bridge.dll"; fi
if [ "${STALE_SERVICE:-}" = 1 ]; then printf 'old update-handoff-v1' > "$TEST_APP/arm64ec-windows/madeira-steam-service.exe"; fi
for resource in madeira-wow64-probe.exe madeira-wow64-module-probe.dll; do
  if [ "${OMIT_RESOURCE:-}" != "$resource" ]; then cp "$ROOT/app/Madeira/i386-windows/$resource" "$TEST_APP/i386-windows/"; fi
done
''',
      'codesign': 'if [ "$1" = -d ]; then echo com.apple.security.cs.allow-jit; fi\n',
      'ditto': 'cp -R "$1" "$2"\nif [ "${STALE_IPA_JIT_SCRIPT:-}" = 1 ]; then printf "\\n// stale archived debugger protocol" >> "$2/madeira-jit.js"; fi\n',
    }
    for name, body in bodies.items():
        p=commands/name; p.write_text('#!/bin/sh\nset -eu\n'+body); p.chmod(0o755)
    revision = '0123456789abcdef0123456789abcdef01234567'
    env=dict(os.environ, ROOT=str(t), GITHUB_SHA=revision, TEST_APP=str(t/'app/DerivedData/Build/Products/Debug-iphoneos/Madeira.app'), PATH=str(commands)+os.pathsep+os.environ['PATH'])
    def run(extra=None):
        return subprocess.run(['bash',str(package)],env=dict(env,**(extra or {})),capture_output=True,text=True)
    result=run(); assert result.returncode == 0, result.stdout+result.stderr
    with zipfile.ZipFile(t/'dist/Madeira.ipa') as archive:
        assert archive.read('Payload/Madeira.app/madeira-jit.js')==jit_script.read_bytes()
        provenance=plistlib.loads(archive.read('Payload/Madeira.app/Info.plist'))['MadeiraNativeBuildProvenance']
        assert provenance['packageSourceRevision']==revision
        assert provenance['virtualBuildRevision']=='a'*40
        assert provenance['virtualBuildRevision']!=provenance['packageSourceRevision']
        assert provenance['nativeImageUUID']=='12345678-1234-5678-90AB-123456789ABC'
    result=run({'OMIT_RESOURCE':'madeira-jit.js'})
    assert result.returncode and 'required bundle resource missing' in result.stderr,result.stderr
    result=run({'STALE_JIT_SCRIPT':'1'})
    assert result.returncode and 'Xcode packaged stale JIT debugger script' in result.stderr,result.stderr
    result=run({'STALE_IPA_JIT_SCRIPT':'1'})
    assert result.returncode and 'IPA JIT debugger script differs from current source' in result.stderr,result.stderr
    current_jit=jit_script.read_bytes()
    jit_script.unlink()
    result=run()
    assert result.returncode and 'required build artifact missing' in result.stderr,result.stderr
    jit_script.write_bytes(b'')
    result=run()
    assert result.returncode and 'required build artifact missing' in result.stderr,result.stderr
    jit_script.write_bytes(current_jit)
    print('PASS exact current JIT debugger script survives app/IPA packaging; missing/empty source, missing/stale Xcode copy and changed archive bytes fail actual gates; no debugger execution claim')
    for stale,component in [('STALE_NATIVE_SOURCE','virtual'),('STALE_JIT_SOURCE','jitallocator')]:
        result=run({stale:'1'})
        assert result.returncode and component+': linked source digest differs from package source' in result.stderr,result.stderr
    print('PASS real native-provenance tool creates the pre-Xcode header, stamps linked source/UUID expectations and verifies final app/IPA; stale native/JIT source records fail, legitimate older component revisions remain visible')
    result=run({'STALE_PIXEL_PROBE':'1'})
    assert result.returncode and 'Xcode packaged stale DXMT pixel probe' in result.stderr,result.stderr
    result=run({'OMIT_RESOURCE':'pixel-readback-x64.exe'})
    assert result.returncode and 'required bundle resource missing' in result.stderr,result.stderr
    pixel_path.write_bytes(b'')
    result=run()
    assert result.returncode and 'required build artifact missing' in result.stderr,result.stderr
    pixel_path.write_bytes(pixel_fixture)
    print('PASS exact DXMT pixel probe in final app; missing/empty/stale copies fail actual packaging gates; fixture supplies no GPU result')
    result=run({'STALE_REGISTRATION_TOOL':'1'})
    assert result.returncode and 'stale app system program' in result.stderr,result.stderr
    result=run({'STALE_TRUST_OBSERVER':'1'})
    assert result.returncode and 'stale app trust observer' in result.stderr,result.stderr
    result=run({'STALE_SECURITY_CRYPTO':'1'})
    assert result.returncode and 'stale app security DLL' in result.stderr,result.stderr
    result=run({'STALE_REGISTRY_SECURITY':'1'})
    assert result.returncode and ('stale app registry security' in result.stderr or 'missing or truncated PE' in result.stderr),result.stderr
    result=run({'STALE_DXMT_MEMORY':'1'})
    assert result.returncode and 'stale app DXMT memory binary' in result.stderr,result.stderr
    result=run({'STALE_DXMT_NATIVE':'1'})
    assert result.returncode and 'stale compiled DXMT memory contract' in result.stderr,result.stderr
    print('PASS real DXMT memory recipe, source transaction and all-farm ABI/export provenance survive actual app/IPA packaging; stale PE/native copies fail actual gates; no GPU or memory reduction claim')
    print('PASS stale native registration utility and trust observer fail their actual final provenance/package gates')
    print('PASS all-farm security corrections and provenance survive actual app/IPA packaging; stale crypto provider fails its real gate')
    print('PASS all-farm registry security corrections and compiler provenance survive actual app/IPA packaging; stale I386 advapi32 fails its real gate')
    result=run({'STALE_SUBFLOOR_CONTRACT':'1'})
    assert result.returncode and 'stale native fixed-image subfloor protocol consumer' in result.stderr, result.stderr
    result=run({'STALE_NATIVE_SRW_ALIAS':'1'})
    assert result.returncode and 'stale native private SRW writer binder' in result.stderr, result.stderr
    result=run({'STALE_NATIVE_NTDLL':'1'})
    assert result.returncode and 'Xcode packaged stale native ntdll writer contracts' in result.stderr, result.stderr
    native_ntdll_path=t/'app/Madeira/arm64ec-windows/ntdll.dll'
    complete_ntdll=native_ntdll_path.read_bytes()
    invalid_ntdll=bytearray(complete_ntdll);invalid_ntdll[package_fixture.ntdll_fixture(0x8664)[1](0xc280)]=0
    native_ntdll_path.write_bytes(invalid_ntdll)
    result=run()
    assert result.returncode and 'native SRW history contents differ from source ABI' in result.stderr, result.stderr
    native_ntdll_path.write_bytes(complete_ntdll)
    print('PASS missing native subfloor consumer, stale ntdll copies and invalid private history contracts fail actual final packaging')
    invalid_ec=bytearray(ec_cpu);struct.pack_into('<Q',invalid_ec,ec_meta['raw'](0x2010),0)
    ec_cpu_path.write_bytes(invalid_ec)
    result=run()
    assert result.returncode and 'FEX DATA capability value differs from source ABI' in result.stderr, result.stderr
    ec_cpu_path.write_bytes(ec_cpu)
    print('PASS stale ARM64EC subfloor DATA capability fails actual final packaging; both CPUs require tracker heap storage')
    result=run({'STALE_EC_CPU':'1'})
    assert result.returncode and 'Xcode packaged stale ARM64EC FEX' in result.stderr, result.stderr
    for marker in (b'[fex-ir-pool-v1]', b'[fex-owner-allocator-v1]'):
        ec_cpu_path.write_bytes(ec_cpu.replace(marker, b'old'))
        result=run()
        assert result.returncode and 'stale arm64ec FEX shared protection' in result.stderr, result.stderr
    ec_cpu_path.write_bytes(ec_cpu)
    invalid_ec = bytearray(ec_cpu); struct.pack_into('<Q', invalid_ec, ec_meta['raw'](0x1300) + 200, 0)
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
    assert result.returncode and 'source revision' in result.stderr, result.stderr
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
    result=run({'STALE_POOL_GROWTH':'1'})
    assert result.returncode and 'stale native executable-pool growth budget' in result.stderr, result.stderr
    result=run({'STALE_POOL_ACCOUNTING':'1'})
    assert result.returncode and 'stale native executable-pool owner accounting' in result.stderr, result.stderr
    result=run({'STALE_WINDOW_GEOMETRY':'1'})
    assert result.returncode and 'stale native original-window geometry observer' in result.stderr, result.stderr
    print('PASS missing original-window geometry observer fails actual final IPA validation')
    print('PASS stale executable-pool growth code fails final IPA validation')
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
    invalid_cpu[cpu_meta['strings'][b'ios_fex_band_base']] = ord('x')
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(invalid_cpu)
    result=run()
    assert result.returncode and 'FEX compatibility exports missing' in result.stderr, result.stderr
    invalid_cpu = bytearray(cpu)
    struct.pack_into('<I', invalid_cpu, cpu_meta['sections']['.data'] + 36, 0xe0000040)
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(invalid_cpu)
    result=run()
    assert result.returncode and 'writable non-executable DATA' in result.stderr, result.stderr
    struct.pack_into('<I', invalid_cpu, cpu_meta['sections']['.data'] + 36, 0xd0000040)
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(invalid_cpu)
    result=run()
    assert result.returncode and 'private writable non-executable DATA' in result.stderr, result.stderr
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(cpu)
    print('PASS missing or executable FEX arena DATA exports fail final IPA validation')
    invalid_cpu=bytearray(cpu)
    contract=cpu_meta['diagnostics'][b'MadeiraFEXTelemetryWriteContract'][0]
    struct.pack_into('<Q',invalid_cpu,cpu_meta['raw'](contract),0)
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(invalid_cpu)
    result=run()
    assert result.returncode and 'differs from source ABI' in result.stderr,result.stderr
    (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(cpu)
    result=run({'STALE_FEX_NATIVE_DIAGNOSTICS':'1'})
    assert result.returncode and 'stale native private FEX diagnostic writer binder' in result.stderr,result.stderr
    print('PASS stale FEX private source ABI and native writer consumer fail final IPA validation')
    for export, message in [(0x2000, 'native RX function'), (0x1100, 'export is forwarded')]:
        invalid_cpu = bytearray(cpu)
        struct.pack_into('<I', invalid_cpu, cpu_meta['slots'][b'MadeiraBTCpuIosReleaseThreadHolds'], export)
        (t/'app/Madeira/aarch64-windows/xtajit.dll').write_bytes(invalid_cpu)
        result=run()
        assert result.returncode and message in result.stderr, result.stderr
    invalid_cpu = bytearray(cpu)
    struct.pack_into('<I', invalid_cpu, cpu_meta['sections']['.text'] + 36, 0xe0000020)
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
