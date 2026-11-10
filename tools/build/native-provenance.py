#!/usr/bin/env python3
"""Tie packaged source expectations to records in the linked native image.

Native archives may legitimately come from an earlier commit when their source
inputs are unchanged. Their build revision is recorded, never equated with the
package revision. The source digests, unlike those revisions, must match.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import uuid
import zipfile

COMPONENTS = {
    'virtual': ('build/ntdll-unix/virtual_ios.c', 'MadeiraNativeVirtual:v1:',
                'MADEIRA_NATIVE_VIRTUAL_SOURCE_SHA256', 'MADEIRA_NATIVE_BUILD_REVISION'),
    'jitallocator': ('app/Madeira/JITAllocator.c', 'MadeiraJITAllocator:v1:',
                     'MADEIRA_JIT_ALLOCATOR_SOURCE_SHA256', 'MADEIRA_JIT_BUILD_REVISION'),
}
KEY = 'MadeiraNativeBuildProvenance'


def revision(value):
    if not re.fullmatch(r'[0-9a-f]{40}', value):
        raise ValueError('source revision must be a full lowercase Git SHA')
    return value


def source_hash(root, component):
    return hashlib.sha256((root / COMPONENTS[component][0]).read_bytes()).hexdigest()


def write_header(root, component, output, build_revision):
    _, _, digest_macro, revision_macro = COMPONENTS[component]
    content = ('/* Generated from the exact compile input; do not edit. */\n'
               f'#define {digest_macro} "{source_hash(root, component)}"\n'
               f'#define {revision_macro} "{revision(build_revision)}"\n')
    output.parent.mkdir(parents=True, exist_ok=True)
    if not output.is_file() or output.read_text() != content:
        output.write_text(content)


def linked_record(image, component):
    prefix = COMPONENTS[component][1].encode()
    # A missing, stale or malformed marker cannot be blessed by Info.plist.
    records = set(re.findall(re.escape(prefix) + rb'([0-9a-f]{64}):([0-9a-f]{40})\x00', image))
    if len(records) != 1:
        raise ValueError(f'{component}: linked native provenance missing or ambiguous')
    digest, build_revision = next(iter(records))
    return dict(sourceSHA256=digest.decode(), buildRevision=build_revision.decode())


def image_uuid(image):
    if len(image) < 32 or struct.unpack_from('<I', image)[0] != 0xfeedfacf:
        raise ValueError('expected a thin 64-bit native Mach-O image')
    count, commands_size = struct.unpack_from('<II', image, 16)
    if commands_size > len(image) - 32:
        raise ValueError('invalid native Mach-O command bounds')
    at, found = 32, []
    for _ in range(count):
        if at + 8 > 32 + commands_size:
            raise ValueError('truncated native Mach-O command')
        command, size = struct.unpack_from('<II', image, at)
        if size < 8 or at + size > 32 + commands_size:
            raise ValueError('invalid native Mach-O command size')
        if command == 0x1b:
            if size != 24:
                raise ValueError('invalid LC_UUID size')
            found.append(str(uuid.UUID(bytes=image[at + 8:at + 24])).upper())
        at += size
    if len(found) != 1:
        raise ValueError('native image must have exactly one UUID')
    return found[0]


def expectations(root, package_revision):
    allocator = (root / COMPONENTS['jitallocator'][0]).read_text()
    match = re.search(r'uint64_t\s+jit_cs2_code_tail_limit_mb\(void\)\s*\{\s*return\s+([0-9]+)\s*;\s*\}', allocator)
    if not match:
        raise ValueError('cannot identify the compiled JIT startup policy')
    return dict(format=1, packageSourceRevision=revision(package_revision),
                expectedVirtualSourceSHA256=source_hash(root, 'virtual'),
                expectedJITAllocatorSourceSHA256=source_hash(root, 'jitallocator'),
                expectedJITCodeTailLimitMB=int(match[1]))


def verified_manifest(root, package_revision, image):
    value = expectations(root, package_revision)
    for component, field in [('virtual', 'expectedVirtualSourceSHA256'),
                             ('jitallocator', 'expectedJITAllocatorSourceSHA256')]:
        record = linked_record(image, component)
        if record['sourceSHA256'] != value[field]:
            raise ValueError(f'{component}: linked source digest differs from package source')
        value[component + 'BuildRevision'] = record['buildRevision']
    value['nativeImageUUID'] = image_uuid(image)
    return value


def check(root, package_revision, info_data, image):
    info = plistlib.loads(info_data)
    expected = verified_manifest(root, package_revision, image)
    if info.get(KEY) != expected:
        raise ValueError('packaged native provenance differs from linked image or expected source')
    if not info.get('MadeiraBuild', '').endswith(' source=' + package_revision):
        raise ValueError('packaged source revision differs from workflow revision')
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['header', 'stamp', 'check'])
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--revision')
    parser.add_argument('--component', choices=COMPONENTS)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--app', type=Path)
    parser.add_argument('--ipa', type=Path)
    args = parser.parse_args()
    build_revision = revision(args.revision or subprocess.check_output(
        ['git', '-C', str(args.root), 'rev-parse', 'HEAD'], text=True).strip())
    if args.mode == 'header':
        if not args.component or not args.output:
            parser.error('header needs --component and --output')
        write_header(args.root, args.component, args.output, build_revision)
        return
    value = None
    if args.app:
        info_file = args.app / 'Info.plist'
        image = (args.app / 'Madeira.debug.dylib').read_bytes()
        if args.mode == 'stamp':
            info = plistlib.loads(info_file.read_bytes())
            info[KEY] = verified_manifest(args.root, build_revision, image)
            info_file.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        value = check(args.root, build_revision, info_file.read_bytes(), image)
    if args.ipa:
        with zipfile.ZipFile(args.ipa) as archive:
            packaged = check(args.root, build_revision,
                             archive.read('Payload/Madeira.app/Info.plist'),
                             archive.read('Payload/Madeira.app/Madeira.debug.dylib'))
        if value is not None and value != packaged:
            raise ValueError('app and IPA provenance differ')
        value = packaged
    if value is None:
        parser.error('stamp/check needs --app or --ipa')
    print('PASS linked native source provenance ' + json.dumps(value, sort_keys=True))


if __name__ == '__main__':
    main()
