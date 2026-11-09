#!/usr/bin/env python3
"""Require matching IOSB images and rebuilt ARM64/WoW64 and ARM64EC FEX CPUs."""
import argparse
import importlib.util
from pathlib import Path
import struct
import zipfile

PRODUCER = b'madeira-io-abi-v2'
CONSUMER = b'[io-abi] v2 native-owned IOSB scopes active'


def fex_arena_exports(data, require_hold_release=False, code_exports=(), require_hybrid=False, data_exports=None):
    """Require real DATA/code exports, not matching strings in a stale PE."""
    data_exports = data_exports or {}
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[:2] == b'MZ' and data[pe:pe + 4] == b'PE\0\0', 'invalid FEX PE headers'
    count = struct.unpack_from('<H', data, pe + 6)[0]
    optional = pe + 24
    assert struct.unpack_from('<H', data, optional)[0] == 0x20b, 'FEX must be PE32+'
    optional_size = struct.unpack_from('<H', data, pe + 20)[0]
    assert optional_size >= 240, 'truncated FEX optional header'
    image_size = struct.unpack_from('<I', data, optional + 56)[0]
    assert image_size and struct.unpack_from('<I', data, optional + 108)[0] >= 11, 'invalid FEX image/directory bounds'
    table = optional + optional_size
    assert 0 < count <= 96, 'invalid FEX section count'
    assert table + count * 40 <= len(data), 'truncated FEX section table'
    sections = []
    for i in range(count):
        entry = table + i * 40
        size, rva, raw_size, raw = struct.unpack_from('<IIII', data, entry + 8)
        extent = max(size, raw_size)
        assert extent and rva <= image_size and extent <= image_size - rva, 'FEX section outside image bounds'
        assert raw <= len(data) and raw_size <= len(data) - raw, 'FEX section outside file bounds'
        assert not any(rva < base + span and base < rva + extent for base, span, _, _, _ in sections), 'overlapping FEX sections'
        sections.append((rva, extent, raw, raw_size, struct.unpack_from('<I', data, entry + 36)[0]))

    def offset(rva, size):
        for start, _, raw, raw_size, _ in sections:
            if start <= rva and rva - start + size <= raw_size and raw + rva - start + size <= len(data):
                return raw + rva - start
        raise AssertionError('FEX export metadata outside file-backed sections')

    if require_hybrid:
        config_rva, config_size = struct.unpack_from('<II', data, optional + 112 + 10 * 8)
        assert config_rva and config_size >= 208, 'ARM64EC FEX load configuration missing'
        config = offset(config_rva, 208)
        assert struct.unpack_from('<I', data, config)[0] >= 208, 'ARM64EC FEX load configuration too small'
        image_base = struct.unpack_from('<Q', data, optional + 24)[0]
        metadata_va = struct.unpack_from('<Q', data, config + 200)[0]
        assert metadata_va >= image_base, 'ARM64EC FEX CHPE metadata missing'
        metadata = offset(metadata_va - image_base, 12)
        version, code_map, code_count = struct.unpack_from('<III', data, metadata)
        assert version in (1, 2) and 0 < code_count <= 65536, 'invalid ARM64EC FEX CHPE code map'
        native = False
        for i in range(code_count):
            encoded, size = struct.unpack_from('<II', data, offset(code_map + i * 8, 8))
            start = encoded & ~3
            if encoded & 3 == 1 and size:
                assert any(base <= start and start + size <= base + extent and flags & 0x20000000
                           and flags & 0x40000000 and not flags & 0x80000000
                           for base, extent, _, _, flags in sections), 'ARM64EC code range must be native RX'
                native = True
        assert native, 'ARM64EC FEX has no native ARM64EC code range'

    directory, directory_size = struct.unpack_from('<II', data, optional + 112)
    assert directory and directory_size >= 40, 'FEX arena DATA exports missing'
    fields = struct.unpack_from('<IIHHIIIIIII', data, offset(directory, 40))
    functions, names, addresses, strings, ordinals = fields[6:]
    assert names <= functions <= 65536, 'invalid FEX export counts'
    required = {b'ios_fex_band_base', b'ios_fex_band_end'}
    required.update(code_exports)
    assert not set(data_exports) & set(code_exports), 'FEX code/DATA export contracts overlap'
    required.update(data_exports)
    hold_release = b'MadeiraBTCpuIosReleaseThreadHolds'
    if require_hold_release:
        required.update({hold_release,b'MadeiraBTCpuIosRetireThread'})
    found = set()
    for i in range(names):
        name_rva = struct.unpack_from('<I', data, offset(strings + i * 4, 4))[0]
        start = offset(name_rva, 1)
        end = data.find(b'\0', start, start + 256)
        assert end >= start, 'unterminated FEX export name'
        offset(name_rva, end - start + 1)
        name = data[start:end]
        if name not in required:
            continue
        assert name not in found, 'duplicate FEX compatibility export'
        ordinal = struct.unpack_from('<H', data, offset(ordinals + i * 2, 2))[0]
        assert ordinal < functions, 'invalid FEX arena export ordinal'
        target = struct.unpack_from('<I', data, offset(addresses + ordinal * 4, 4))[0]
        assert target and not directory <= target < directory + directory_size, 'FEX arena export is forwarded'
        if name in {hold_release,b'MadeiraBTCpuIosRetireThread', *code_exports}:
            assert any(base <= target and target + 4 <= base + raw_size and flags & 0x20000000 and
                       flags & 0x40000000 and not flags & 0x80000000
                       for base, _, _, raw_size, flags in sections), 'FEX hold release must be a file-backed native RX function'
            offset(target, 4)
        else:
            assert not target & 7 and any(base <= target and target + 8 <= base + size and
                       flags & 0xc0000000 == 0xc0000000 and not flags & 0x32000000
                       for base, size, _, _, flags in sections), 'FEX arena export must be aligned private writable non-executable DATA'
            if name in data_exports:
                # Allocator band bounds are initialized at runtime and may be
                # legitimate zero-fill DATA. An initialized protocol magic is
                # different: its exact source ABI must exist in file bytes.
                try:
                    data_offset = offset(target, 8)
                except AssertionError as error:
                    raise AssertionError(f'FEX DATA capability {name.decode("ascii")} requires eight file-backed bytes') from error
                assert struct.unpack_from('<Q', data, data_offset)[0] == data_exports[name], f'FEX DATA capability value differs from source ABI: {name.decode("ascii")}'
        found.add(name)
    assert found == required, 'FEX compatibility exports missing'


def producer(data):
    assert data[:2] == b'MZ', 'WoW64 producer is not a PE image'
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[pe:pe + 4] == b'PE\0\0', 'invalid WoW64 PE signature'
    assert struct.unpack_from('<H', data, pe + 4)[0] == 0xaa64, 'WoW64 producer must be native ARM64'
    assert PRODUCER in data, 'stale WoW64 IOSB producer'


def fex_cpu(data, backend):
    """The shared allocator/IR protections apply to both Windows PE backends.

    ARM64EC retains its own thread/TLS/hold ABI. Its existing CPU image is an
    AMD64-header hybrid; an ordinary AMD64 image must not pass this gate.
    """
    assert data[:2] == b'MZ', f'{backend} FEX is not a PE image'
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[pe:pe + 4] == b'PE\0\0', f'invalid {backend} FEX signature'
    machine = struct.unpack_from('<H', data, pe + 4)[0]
    code_exports = ()
    if backend == 'wow64':
        assert machine == 0xaa64, 'WoW64 FEX must be native ARM64'
        for marker in (b'MadeiraBTCpuThreadInit', b'[fex-thread-init-v1]',
                       b'MadeiraBTCpuWriteMemory', b'[fex-guest-write-v1]',
                       b'[fex-first-use-v1]', b'[fex-blocklist-v1]',
                       b'[fex-hold-release-v1]', b'[fex-thread-retire-v1]'):
            assert marker in data, f'stale WoW64 FEX: {marker!r}'
    else:
        assert backend == 'arm64ec' and machine in (0xa641, 0x8664), 'ARM64EC FEX machine mismatch'
        # These are actual ARM64EC module exports, not the WoW64 BTCpu ABI.
        code_exports = (b'BTCpu64FlushInstructionCache', b'BTCpu64NotifyMemoryDirty', b'BTCpu64IosAddAliasMapping')
    for marker in (b'[fex-core-init-v1]', b'[fex-ir-pool-v1]', b'[fex-owner-allocator-v1]'):
        assert marker in data, f'stale {backend} FEX shared protection: {marker!r}'
    fex_arena_exports(data, require_hold_release=backend == 'wow64', code_exports=code_exports,
                      require_hybrid=backend == 'arm64ec',
                      data_exports={b'IosSubfloorProtocolV1': 0x4d53460100000001} if backend == 'arm64ec' else None)


def native_ntdll_contract(path, machine):
    """Run the same source-stage verifier on the actual app/IPA native bytes."""
    source = Path(__file__).resolve().parent / 'build/stage-native-counter-writes.py'
    spec = importlib.util.spec_from_file_location('madeira_native_counter_package', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify_pe(path, machine)


def check(staged, app, ipa):
    expected = staged.read_bytes()
    producer(expected)
    assert (app / 'aarch64-windows/wow64.dll').read_bytes() == expected, 'Xcode packaged a stale WoW64 producer'
    native = (app / 'Madeira.debug.dylib').read_bytes()
    assert CONSUMER in native, 'native IOSB consumer missing from linked image'
    assert b'[steam-handoff-v1]' in native and b'_madeira_child_server_exited' in native, 'native Steam restart consumer missing'
    assert b'[fex-owner-v1] pre-crt' in native and b'[fex-owner-v1] retired' in native, 'native FEX ownership lifecycle missing'
    assert b'[fex-owner-census-v2]' in native, 'native FEX live-owner census missing'
    assert b'[pool-code-growth]' in native, 'stale native executable-pool growth budget'
    assert b'[subfloor-contract-v1]' in native, 'stale native fixed-image subfloor protocol consumer'
    assert b'[native-srw-alias-v1]' in native, 'stale native private SRW writer binder'
    assert b'[hold-release-v2]' in native and b'[deliver-hold-v2]' in native, 'native FEX hold-release boundary missing'
    assert b'[native-window-retire-v1]' in native, 'native dead-window layer cleanup missing'
    assert b'_winios_native_window_create' in native and b'_winios_native_window_retire' in native, 'native window lifecycle bridge missing'
    assert b'[guest32-fault-v1]' in native, 'native WoW32 first-fault diagnostics missing'
    assert b'[steam-progress-v1]' in native and b'_winios_ui_progress_snapshot' in native, 'native Steam UI progress diagnostics missing'
    assert b'[srv-poll-drop-v1]' in native and b'poll-slots-highwater=' in native, 'native wineserver readiness validation missing'
    assert b'[wow-thread-init-v1]' in expected, 'stale Wine CPU initialization consumer'
    assert b'[wow-break-deliver-v1]' in expected, 'stale Wine breakpoint diagnostics'
    assert b'MadeiraBTCpuWriteMemory' in expected, 'stale Wine native-write consumer'
    assert b'[wow-query-zero-v1]' in expected, 'stale Wine guest memory-enumeration consumer'
    assert b'[wow-group-attribute-v1]' in expected, 'stale Wine thread-affinity attribute consumer'
    assert b'[guest32-cxx-first-v1]' in native, 'native first C++ exception diagnostics missing'
    assert b'[cef-atexit-v1]' in native, 'native CEF registration diagnostics missing'
    assert b'[wow-write]' in native and b'[guest32-symbols]' in native, 'native guest memory diagnostics missing'
    cpu = staged.parent / 'xtajit.dll'
    cpu_data = cpu.read_bytes()
    fex_cpu(cpu_data, 'wow64')
    ec_cpu_data = (staged.parent.parent / 'arm64ec-windows/xtajit64.dll').read_bytes()
    fex_cpu(ec_cpu_data, 'arm64ec')
    assert (app / 'arm64ec-windows/xtajit64.dll').read_bytes() == ec_cpu_data, 'Xcode packaged stale ARM64EC FEX'
    native_ntdlls = {}
    for directory, machine in (('aarch64-windows', 'aarch64'), ('arm64ec-windows', 'arm64ec')):
        staged_ntdll = staged.parent.parent / directory / 'ntdll.dll'
        packaged_ntdll = app / directory / 'ntdll.dll'
        expected_ntdll = staged_ntdll.read_bytes()
        assert packaged_ntdll.read_bytes() == expected_ntdll, 'Xcode packaged stale native ntdll writer contracts'
        native_ntdll_contract(packaged_ntdll, machine)
        native_ntdlls[directory] = expected_ntdll
    assert b'[alias-prot-v2]' in native and b'[fex-exit-v1]' in native and b'[native-thread-cancel-v1]' in native, 'native protection/retirement/cancellation consumer missing'
    assert b'[alias-prot-compat]' in native and b'[image-alias-retire-v1]' in native and b'[swp-context-v1]' in native, 'stale native alias lifetime/protection producer'
    assert b'[surface-expose-v1]' in native and b'[steam-client-update-v1]' in native, 'stale popup expose or official Steam updater integration'
    assert b'[child-native-ntdll-v1]' in native and b'[guest-trap-context-v1]' in native, 'stale mixed-architecture child loader or trap diagnostics'
    assert b'[child-native-dll-v1]' in native and b'[process-wow64-v1]' in native, 'stale native child imports or owner-aware WoW64 PEB query'
    assert b'[fex-callback-v2]' in native, 'stale direct Unix-to-PE FEX cleanup callback'
    assert b'[wow-native-export-v1]' in native, 'stale pool-only WoW64 native startup data'
    assert b'[wow-placement-v1]' in native, 'stale native WoW64-segment placement'
    assert b'[native-group-retire-v1]' in native, 'stale native process-group retirement'
    assert b'[cef-image-owner-v1]' in native, 'stale private CEF image retirement'
    assert b'[guest-breakpoint64-v1]' in native, 'stale AMD64 guest breakpoint diagnostics'
    assert (app / 'aarch64-windows/xtajit.dll').read_bytes() == cpu_data, 'Xcode packaged stale FEX'
    guest = (staged.parent.parent / 'i386-windows/kernelbase.dll').read_bytes()
    assert struct.unpack_from('<H', guest, struct.unpack_from('<I', guest, 0x3c)[0] + 4)[0] == 0x14c
    assert b'[wpm-call-v1]' in guest, 'stale guest32 memory API producer'
    assert b'[steam-arch-v1]' in guest, 'stale Steam architecture observation producer'
    assert (app / 'i386-windows/kernelbase.dll').read_bytes() == guest, 'Xcode packaged stale guest32 caller'
    service = (staged.parent.parent / 'arm64ec-windows/madeira-steam-service.exe').read_bytes()
    assert b'update-handoff-v1' in service, 'stale Steam service update handoff helper'
    assert (app / 'arm64ec-windows/madeira-steam-service.exe').read_bytes() == service, 'Xcode packaged stale Steam service helper'
    scm = (staged.parent / 'services.exe').read_bytes()
    assert scm[:2] == b'MZ', 'SCM is not a PE image'
    scm_pe = struct.unpack_from('<I', scm, 0x3c)[0]
    assert scm[scm_pe:scm_pe + 4] == b'PE\0\0' and struct.unpack_from('<H', scm, scm_pe + 4)[0] == 0xaa64, 'SCM must retain native ARM64 architecture'
    assert b'[scm-pipe-wait-v1]' in scm, 'stale SCM startup timeout producer'
    assert (app / 'aarch64-windows/services.exe').read_bytes() == scm, 'Xcode packaged stale SCM startup producer'
    with zipfile.ZipFile(ipa) as archive:
        assert archive.read('Payload/Madeira.app/aarch64-windows/wow64.dll') == expected, 'ZIP producer differs'
        assert archive.read('Payload/Madeira.app/Madeira.debug.dylib') == native, 'ZIP native consumer differs'
        assert archive.read('Payload/Madeira.app/aarch64-windows/xtajit.dll') == cpu_data, 'ZIP FEX producer differs'
        assert archive.read('Payload/Madeira.app/arm64ec-windows/xtajit64.dll') == ec_cpu_data, 'ZIP ARM64EC FEX producer differs'
        for directory, expected_ntdll in native_ntdlls.items():
            assert archive.read('Payload/Madeira.app/' + directory + '/ntdll.dll') == expected_ntdll, 'ZIP native ntdll writer contract differs'
        assert archive.read('Payload/Madeira.app/i386-windows/kernelbase.dll') == guest, 'ZIP guest32 caller differs'
        assert archive.read('Payload/Madeira.app/arm64ec-windows/madeira-steam-service.exe') == service, 'ZIP Steam service helper differs'
        assert archive.read('Payload/Madeira.app/aarch64-windows/services.exe') == scm, 'ZIP SCM startup producer differs'
    print('PASS final IPA contains matching IOSB images and byte-identical rebuilt WoW64/ARM64EC FEX CPUs')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staged', type=Path, required=True)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--ipa', type=Path, required=True)
    args = parser.parse_args()
    check(args.staged, args.app, args.ipa)
