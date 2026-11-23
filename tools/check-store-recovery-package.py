#!/usr/bin/env python3
"""Read-only verification of the recovery call paths in an actual IPA.

No game/native code is executed. Require the real ARM64 function/stub symbols
and direct branch targets; a missing symbol is an unsupported inspection, not
an inferred pass from a revision string.
"""
import argparse
import bisect
import json
from pathlib import Path
import plistlib
import struct
import zipfile


def inspect(data, require_pressure_boundary=False, require_recovery_scope=False):
    if struct.unpack_from('<II', data) != (0xfeedfacf, 0x100000c):
        raise ValueError('expected thin ARM64 Mach-O native image')
    sections, symtab, indirect = [], None, None
    at = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, at)
        if size < 8 or at + size > len(data):
            raise ValueError('invalid load command bounds')
        if command == 0x19:
            count = struct.unpack_from('<I', data, at + 64)[0]
            if 72 + count * 80 > size:
                raise ValueError('invalid section table')
            for i in range(count):
                row = struct.unpack_from('<16s16sQQIIIIIIII', data, at + 72 + i * 80)
                sections.append(dict(name=row[0].split(b'\0')[0], addr=row[2], size=row[3],
                                     offset=row[4], flags=row[8], reserved1=row[9], reserved2=row[10]))
        elif command == 2:
            symtab = struct.unpack_from('<IIII', data, at + 8)
        elif command == 0xb:
            indirect = struct.unpack_from('<II', data, at + 56)
        at += size
    if not symtab:
        raise ValueError('native symbol table unavailable')
    offset, count, strings, string_size = symtab
    if offset + count * 16 > len(data) or strings + string_size > len(data):
        raise ValueError('invalid native symbols')
    symbols = []
    for i in range(count):
        index, kind, section, _, address = struct.unpack_from('<IBBHQ', data, offset + i * 16)
        if index >= string_size:
            raise ValueError('invalid symbol name')
        end = data.index(b'\0', strings + index, strings + string_size)
        name = data[strings + index:end].decode('utf-8', errors='replace')
        symbols.append((name, kind, section, address))
    if require_pressure_boundary:
        for marker in (b'[pressure-boundary-v1]', b'[pressure-owner-v1]'):
            if marker not in data:
                raise ValueError('missing compiled Run14 producer: ' + marker.decode())
        if not any(name == '_madeira_pressure_boundary_request' and
                   kind & 0xe == 0xe and not kind & 0xe0 and section and address
                   for name, kind, section, address in symbols):
            raise ValueError('Run14 native pressure request is not defined in the linked image')
    if require_recovery_scope:
        for marker in (b'[store-recovery-scope-v1]', b'advisory=unheld commit=fresh-held',
                       b'held-qos=user-interactive', b'write0-us=', b'write1-us=',
                       b'prepare-read-us=', b'suspend-us=', b'recovery-worker='):
            if marker not in data:
                raise ValueError('missing compiled recovery scope: ' + marker.decode())
        if not any(name == '_ios_store_split_crossing_timed' and
                   kind & 0xe == 0xe and not kind & 0xe0 and section and address
                   for name, kind, section, address in symbols):
            raise ValueError('timed checked-write producer is not defined in linked image')
    names = {address: name for name, kind, _, address in symbols if address and kind & 0xe == 0xe}
    if indirect:
        offset, count = indirect
        if offset + count * 4 > len(data):
            raise ValueError('invalid indirect symbols')
        for section in sections:
            stride = section['reserved2']
            if section['flags'] & 0xff != 8 or not stride:
                continue
            for i in range(section['size'] // stride):
                index = section['reserved1'] + i
                if index >= count:
                    raise ValueError('invalid stub index')
                symbol, = struct.unpack_from('<I', data, offset + index * 4)
                if symbol < len(symbols):
                    names[section['addr'] + i * stride] = symbols[symbol][0]
    boundaries = {}
    for name, kind, index, address in symbols:
        if name.startswith('_') and kind & 0xe == 0xe and not kind & 0xe0 and index:
            boundaries.setdefault(index, set()).add(address)
    boundaries = {index: sorted(addresses) for index, addresses in boundaries.items()}
    functions = {}
    for name, kind, index, address in symbols:
        if not name.startswith('_ios_stuck_store_') or kind & 0xe != 0xe or kind & 0xe0 or not index:
            continue
        section = sections[index - 1]
        if section['name'] != b'__text':
            continue
        following = bisect.bisect_right(boundaries[index], address)
        end = boundaries[index][following] if following < len(boundaries[index]) else section['addr'] + section['size']
        if not section['addr'] <= address < end <= section['addr'] + section['size']:
            raise ValueError('invalid function bounds')
        begin = section['offset'] + address - section['addr']
        calls = []
        for i in range(0, end - address - 3, 4):
            word, = struct.unpack_from('<I', data, begin + i)
            if word & 0xfc000000 != 0x94000000:
                continue
            delta = word & 0x3ffffff
            if delta & 0x2000000:
                delta -= 0x4000000
            destination = address + i + delta * 4
            calls.append((address + i, names.get(destination, hex(destination))))
        functions[name] = calls
    check = functions.get('_ios_stuck_store_check')
    hot = '_ios_stuck_store_hot_check'
    checkpoint = '_ios_stuck_store_discovery_checkpoint'
    if check is None:
        # Clang can inline the single-use discovery body into its recovery
        # owner. Require its actual scan -> hot service -> list release ->
        # fresh clock call path in that same owner, not just a build string.
        for name, calls in functions.items():
            if not name.startswith('_ios_stuck_store_recovery_'):
                continue
            for begin, target in calls:
                if target != '_task_threads':
                    continue
                serviced = [(pc, callee) for pc, callee in calls if pc > begin and
                    (callee == hot or callee == checkpoint and any(
                        nested == hot for _, nested in functions.get(checkpoint, [])))]
                released = [pc for pc, callee in calls if callee in ('_vm_deallocate', '_mach_vm_deallocate') and
                            any(begin < service < pc for service, _ in serviced)]
                if released and any(pc > released[-1] and callee in ('_clock_gettime', '_ios_stuck_clock_us')
                                    for pc, callee in calls):
                    return dict(interleavedDiscovery=True, discoveryFunction=name, discoveryInlined=True,
                        pressureBoundaryRequired=require_pressure_boundary, recoveryScopeRequired=require_recovery_scope,
                        postDiscoveryClockFunctions=[name],
                        discoveryCalls=[dict(pc=hex(pc), target=callee) for pc, callee in serviced])
        raise ValueError('inlined discovery call path not established: ' + json.dumps(functions))
    interleaved = any(target == hot or target == checkpoint and
                      any(callee == hot for _, callee in functions.get(checkpoint, [])) for _, target in check)
    if not interleaved:
        raise ValueError('compiled discovery does not service hot targets')
    deadline = []
    for name, calls in functions.items():
        if not name.startswith('_ios_stuck_store_recovery_'):
            continue
        for pc, target in calls:
            if target == '_ios_stuck_store_check' and any(
                following > pc and callee in ('_clock_gettime', '_ios_stuck_clock_us') for following, callee in calls):
                deadline.append(name)
    if not deadline:
        raise ValueError('post-discovery clock call not established in compiled recovery')
    return dict(interleavedDiscovery=True, discoveryFunction='_ios_stuck_store_check', discoveryInlined=False,
                pressureBoundaryRequired=require_pressure_boundary, recoveryScopeRequired=require_recovery_scope,
                postDiscoveryClockFunctions=sorted(deadline),
                discoveryCalls=[dict(pc=hex(pc), target=name) for pc, name in check
                                if name in (hot, checkpoint)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ipa', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--require-pressure-boundary', action='store_true',
                        help='Require the linked Run14 producer markers and defined native callback')
    parser.add_argument('--require-recovery-scope', action='store_true',
                        help='Require linked advisory/held-scope producer and phase record')
    args = parser.parse_args()
    with zipfile.ZipFile(args.ipa) as ipa:
        info = plistlib.loads(ipa.read('Payload/Madeira.app/Info.plist'))
        if info.get('MadeiraNativeBuildProvenance', {}).get('packageSourceRevision') != args.revision:
            raise ValueError('package source revision mismatch')
        result = inspect(ipa.read('Payload/Madeira.app/Madeira.debug.dylib'), args.require_pressure_boundary, args.require_recovery_scope)
        result.update(source=args.revision, bundleIdentifier=info['CFBundleIdentifier'],
                      nativeUUID=info['MadeiraNativeBuildProvenance']['nativeImageUUID'])
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
