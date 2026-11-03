#!/usr/bin/env python3
"""Require the matching native IOSB consumer and rebuilt ARM64 WoW64 producer."""
import argparse
from pathlib import Path
import struct
import zipfile

PRODUCER = b'madeira-io-abi-v2'
CONSUMER = b'[io-abi] v2 native-owned IOSB scopes active'


def fex_arena_exports(data, require_hold_release=False):
    """Require real DATA/code exports, not matching strings in a stale PE."""
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[:2] == b'MZ' and data[pe:pe + 4] == b'PE\0\0', 'invalid FEX PE headers'
    count = struct.unpack_from('<H', data, pe + 6)[0]
    optional = pe + 24
    assert struct.unpack_from('<H', data, optional)[0] == 0x20b, 'FEX must be PE32+'
    table = optional + struct.unpack_from('<H', data, pe + 20)[0]
    assert 0 < count <= 96, 'invalid FEX section count'
    sections = []
    for i in range(count):
        entry = table + i * 40
        size, rva, raw_size, raw = struct.unpack_from('<IIII', data, entry + 8)
        sections.append((rva, max(size, raw_size), raw, raw_size, struct.unpack_from('<I', data, entry + 36)[0]))

    def offset(rva, size):
        for start, _, raw, raw_size, _ in sections:
            if start <= rva and rva - start + size <= raw_size and raw + rva - start + size <= len(data):
                return raw + rva - start
        raise AssertionError('FEX export metadata outside file-backed sections')

    directory, directory_size = struct.unpack_from('<II', data, optional + 112)
    assert directory and directory_size >= 40, 'FEX arena DATA exports missing'
    fields = struct.unpack_from('<IIHHIIIIIII', data, offset(directory, 40))
    functions, names, addresses, strings, ordinals = fields[6:]
    assert names <= functions <= 65536, 'invalid FEX export counts'
    required = {b'ios_fex_band_base', b'ios_fex_band_end'}
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
        ordinal = struct.unpack_from('<H', data, offset(ordinals + i * 2, 2))[0]
        assert ordinal < functions, 'invalid FEX arena export ordinal'
        target = struct.unpack_from('<I', data, offset(addresses + ordinal * 4, 4))[0]
        assert target and not directory <= target < directory + directory_size, 'FEX arena export is forwarded'
        if name in {hold_release,b'MadeiraBTCpuIosRetireThread'}:
            assert any(base <= target and target + 4 <= base + raw_size and flags & 0x20000000 and
                       flags & 0x40000000 and not flags & 0x80000000
                       for base, _, _, raw_size, flags in sections), 'FEX hold release must be a file-backed native RX function'
        else:
            assert any(base <= target and target + 8 <= base + size and flags & 0x80000000 and not flags & 0x30000000
                       for base, size, _, _, flags in sections), 'FEX arena export must be private writable non-executable DATA'
        found.add(name)
    assert found == required, 'FEX compatibility exports missing'


def producer(data):
    assert data[:2] == b'MZ', 'WoW64 producer is not a PE image'
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[pe:pe + 4] == b'PE\0\0', 'invalid WoW64 PE signature'
    assert struct.unpack_from('<H', data, pe + 4)[0] == 0xaa64, 'WoW64 producer must be native ARM64'
    assert PRODUCER in data, 'stale WoW64 IOSB producer'


def check(staged, app, ipa):
    expected = staged.read_bytes()
    producer(expected)
    assert (app / 'aarch64-windows/wow64.dll').read_bytes() == expected, 'Xcode packaged a stale WoW64 producer'
    native = (app / 'Madeira.debug.dylib').read_bytes()
    assert CONSUMER in native, 'native IOSB consumer missing from linked image'
    assert b'[steam-handoff-v1]' in native and b'_madeira_child_server_exited' in native, 'native Steam restart consumer missing'
    assert b'[fex-owner-v1] pre-crt' in native and b'[fex-owner-v1] retired' in native, 'native FEX ownership lifecycle missing'
    assert b'[fex-owner-census-v2]' in native, 'native FEX live-owner census missing'
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
    assert struct.unpack_from('<H', cpu_data, struct.unpack_from('<I', cpu_data, 0x3c)[0] + 4)[0] == 0xaa64
    assert b'MadeiraBTCpuThreadInit' in cpu_data and b'[fex-thread-init-v1]' in cpu_data, 'stale FEX CPU producer'
    assert b'MadeiraBTCpuWriteMemory' in cpu_data and b'[fex-guest-write-v1]' in cpu_data, 'stale FEX native-write producer'
    assert b'[fex-first-use-v1]' in cpu_data, 'stale FEX first-execution allocation checks'
    assert b'[fex-blocklist-v1]' in cpu_data, 'stale FEX contiguous block map'
    assert b'[fex-hold-release-v1]' in cpu_data, 'stale FEX terminal hold cleanup'
    assert b'[fex-thread-retire-v1]' in cpu_data, 'stale FEX private thread destruction'
    assert b'[alias-prot-v2]' in native and b'[fex-exit-v1]' in native and b'[native-thread-cancel-v1]' in native, 'native protection/retirement/cancellation consumer missing'
    assert b'[alias-prot-compat]' in native and b'[image-alias-retire-v1]' in native and b'[swp-context-v1]' in native, 'stale native alias lifetime/protection producer'
    assert b'[surface-expose-v1]' in native and b'[steam-client-update-v1]' in native, 'stale popup expose or official Steam updater integration'
    assert b'[child-native-ntdll-v1]' in native and b'[guest-trap-context-v1]' in native, 'stale mixed-architecture child loader or trap diagnostics'
    assert b'[child-native-dll-v1]' in native and b'[process-wow64-v1]' in native, 'stale native child imports or owner-aware WoW64 PEB query'
    assert b'[fex-callback-v1]' in native, 'stale direct Unix-to-PE FEX cleanup callback'
    assert b'[wow-native-export-v1]' in native, 'stale pool-only WoW64 native startup data'
    fex_arena_exports(cpu_data, require_hold_release=True)
    assert (app / 'aarch64-windows/xtajit.dll').read_bytes() == cpu_data, 'Xcode packaged stale FEX'
    guest = (staged.parent.parent / 'i386-windows/kernelbase.dll').read_bytes()
    assert struct.unpack_from('<H', guest, struct.unpack_from('<I', guest, 0x3c)[0] + 4)[0] == 0x14c
    assert b'[wpm-call-v1]' in guest, 'stale guest32 memory API producer'
    assert b'[steam-arch-v1]' in guest, 'stale Steam architecture observation producer'
    assert (app / 'i386-windows/kernelbase.dll').read_bytes() == guest, 'Xcode packaged stale guest32 caller'
    service = (staged.parent.parent / 'arm64ec-windows/madeira-steam-service.exe').read_bytes()
    assert b'update-handoff-v1' in service, 'stale Steam service update handoff helper'
    assert (app / 'arm64ec-windows/madeira-steam-service.exe').read_bytes() == service, 'Xcode packaged stale Steam service helper'
    with zipfile.ZipFile(ipa) as archive:
        assert archive.read('Payload/Madeira.app/aarch64-windows/wow64.dll') == expected, 'ZIP producer differs'
        assert archive.read('Payload/Madeira.app/Madeira.debug.dylib') == native, 'ZIP native consumer differs'
        assert archive.read('Payload/Madeira.app/aarch64-windows/xtajit.dll') == cpu_data, 'ZIP FEX producer differs'
        assert archive.read('Payload/Madeira.app/i386-windows/kernelbase.dll') == guest, 'ZIP guest32 caller differs'
        assert archive.read('Payload/Madeira.app/arm64ec-windows/madeira-steam-service.exe') == service, 'ZIP Steam service helper differs'
    print('PASS final IPA contains matching native IOSB consumer and byte-identical rebuilt ARM64 WoW64 producer')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staged', type=Path, required=True)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--ipa', type=Path, required=True)
    args = parser.parse_args()
    check(args.staged, args.app, args.ipa)
