#!/usr/bin/env python3
"""Read public Valve packages; never install, load, execute or alter their PEs.

This disposable CI inspection deliberately makes no HTMLIPC ABI or runtime
readiness claim. In particular an iOS mapped-image size may include Madeira's
alignment padding: compare actual PE headers, not only a runtime log extent.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import urllib.request
import zipfile

ORIGIN = 'https://client-update.akamai.steamstatic.com/'
OLD = ('bins_win64.zip.1f91da2609327de9658146b01307e89a13cc1ef8', 64309479,
       'f34b0d5924d0cca4c81775ed2fef0aee1ca060e2daa5c24270711267786c0236')
OLD_CORE_SHA = '37f5ddbe874362d729b7cd33504943a9d649d845525afae4bcc2af36ab971f4b'
OLD_METHODS = [0x58bf0, 0x59100, 0x590e0, 0x593f0, 0x58fa0, 0x58e60, 0x58dc0]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def fetch(name, destination, maximum, expected_size=None, expected_sha=None):
    require(re.fullmatch(r'[A-Za-z0-9_.-]+', name) is not None, 'unsafe package name')
    url = ORIGIN + name
    digest, total = hashlib.sha256(), 0
    with urllib.request.urlopen(urllib.request.Request(url, headers={'Accept-Encoding': 'identity'}), timeout=90) as response:
        require(response.status == 200 and response.url == url, 'unexpected Valve CDN response')
        with destination.open('wb') as output:
            while chunk := response.read(1 << 20):
                total += len(chunk)
                require(total <= maximum, 'download exceeds bound')
                digest.update(chunk)
                output.write(chunk)
    actual = digest.hexdigest()
    require(expected_size is None or total == expected_size, 'package size mismatch')
    require(expected_sha is None or actual == expected_sha, 'package SHA-256 mismatch')
    return {'file': name, 'bytes': total, 'sha256': actual, 'source': ORIGIN}


class PE:
    def __init__(self, data):
        self.data = data
        require(64 <= len(data) <= 64 << 20 and data[:2] == b'MZ', 'invalid PE size/header')
        nt = self.unpack('<I', 60)[0]
        require(self.read(nt, 4) == b'PE\0\0', 'missing PE signature')
        self.machine, count = self.unpack('<HH', nt + 4)
        self.timestamp = self.unpack('<I', nt + 8)[0]
        optional_size = self.unpack('<H', nt + 20)[0]
        self.characteristics = self.unpack('<H', nt + 22)[0]
        optional = nt + 24
        magic = self.unpack('<H', optional)[0]
        require(magic in (0x10b, 0x20b) and 96 <= optional_size <= 4096 and 0 < count <= 96, 'unsupported PE headers')
        self.bits = 64 if magic == 0x20b else 32
        self.base = self.unpack('<Q' if self.bits == 64 else '<I', optional + (24 if self.bits == 64 else 28))[0]
        self.image_size, self.headers = self.unpack('<II', optional + 56)
        require(4096 <= self.image_size <= 256 << 20 and self.headers <= len(data), 'invalid PE image bounds')
        self.checksum_offset = optional + 64
        self.sections = []
        for index in range(count):
            row = optional + optional_size + index * 40
            name = self.read(row, 8).split(b'\0', 1)[0].decode('ascii', errors='replace')
            virtual, rva, size, raw = self.unpack('<IIII', row + 8)
            flags = self.unpack('<I', row + 36)[0]
            require(raw <= len(data) and size <= len(data) - raw and rva <= self.image_size and max(virtual, size) <= self.image_size - rva, 'invalid PE section')
            self.sections.append({'name': name, 'rva': rva, 'virtual': virtual, 'raw': raw, 'bytes': size, 'flags': flags,
                                  'raw_sha256': hashlib.sha256(self.read(raw, size)).hexdigest()})
        directory = optional + (112 if self.bits == 64 else 96)
        directory_count = self.unpack('<I', directory - 4)[0]
        require(directory_count <= 16 and directory + directory_count * 8 <= optional + optional_size, 'invalid PE directories')
        self.directories = [self.unpack('<II', directory + i * 8) for i in range(directory_count)]
        self.security_directory_offset = directory + 4 * 8 if directory_count > 4 else None

    def read(self, offset, size):
        require(0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset, 'truncated PE bytes')
        return self.data[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack(fmt, self.read(offset, struct.calcsize(fmt)))

    def offset(self, rva, size):
        if rva < self.headers and size <= self.headers - rva:
            return rva
        for section in self.sections:
            delta = rva - section['rva']
            if 0 <= delta <= section['bytes'] and size <= section['bytes'] - delta:
                return section['raw'] + delta
        raise ValueError('RVA is not file backed')

    def at(self, rva, size):
        return self.read(self.offset(rva, size), size)

    def rva_of(self, offset):
        for section in self.sections:
            if section['raw'] <= offset < section['raw'] + section['bytes']:
                return section['rva'] + offset - section['raw']
        return offset if offset < self.headers else None

    def string(self, rva):
        offset = self.offset(rva, 1)
        end = self.data.find(b'\0', offset, min(offset + 256, len(self.data)))
        require(end >= 0, 'unterminated PE name')
        name = self.data[offset:end].decode('ascii')
        require(all(32 <= ord(c) < 127 for c in name), 'nonprintable PE name')
        return name

    def imports(self):
        if len(self.directories) < 2 or not self.directories[1][0]:
            return []
        rva, size = self.directories[1]
        names = []
        for index in range(min(size // 20, 512)):
            row = self.at(rva + index * 20, 20)
            if not any(row):
                return names
            names.append(self.string(struct.unpack_from('<I', row, 12)[0]))
        raise ValueError('unterminated/excessive PE imports')

    def exports(self):
        if not self.directories or not self.directories[0][0]:
            return {}
        row = self.at(self.directories[0][0], 40)
        functions, names, functions_rva, names_rva, ordinals_rva = struct.unpack_from('<IIIII', row, 20)
        require(functions <= 4096 and names <= 4096, 'export count bound')
        result = {}
        for index in range(names):
            name = self.string(struct.unpack('<I', self.at(names_rva + index * 4, 4))[0])
            ordinal = struct.unpack('<H', self.at(ordinals_rva + index * 2, 2))[0]
            require(ordinal < functions, 'invalid export ordinal')
            result[name] = struct.unpack('<I', self.at(functions_rva + ordinal * 4, 4))[0]
        return result

    def function_ranges(self):
        if len(self.directories) < 4 or not self.directories[3][0] or self.bits != 64:
            return []
        rva, size = self.directories[3]
        require(size <= 8 << 20 and size % 12 == 0, 'invalid exception directory')
        result = []
        for offset in range(0, size, 12):
            start, end, unwind = struct.unpack('<III', self.at(rva + offset, 12))
            require(0 < start < end <= self.image_size, 'invalid unwind function range')
            result.append((start, end, unwind))
        return result

    def section_for(self, rva):
        return next((s for s in self.sections if s['rva'] <= rva < s['rva'] + max(s['bytes'], s['virtual'])), None)

    def describe(self):
        certificate_offset, certificate_bytes = self.directories[4] if len(self.directories) > 4 else (0, 0)
        certificate_at_eof = bool(certificate_offset and certificate_bytes and certificate_offset % 8 == 0 and
                                  certificate_offset <= len(self.data) and certificate_bytes == len(self.data) - certificate_offset and
                                  all(s['raw'] + s['bytes'] <= certificate_offset for s in self.sections))
        canonical = bytearray(self.data[:certificate_offset] if certificate_at_eof else self.data)
        canonical[self.checksum_offset:self.checksum_offset + 4] = bytes(4)
        if self.security_directory_offset is not None:
            canonical[self.security_directory_offset:self.security_directory_offset + 8] = bytes(8)
        return {'bytes': len(self.data), 'sha256': hashlib.sha256(self.data).hexdigest(),
                'machine': f'{self.machine:04x}', 'pointer_bits': self.bits,
                'timestamp': f'0x{self.timestamp:x}', 'preferred_base': hex(self.base),
                'size_of_image': hex(self.image_size), 'sections': self.sections,
                'imports': self.imports(), 'certificate_file_offset': hex(certificate_offset),
                'certificate_bytes': certificate_bytes, 'certificate_is_bounded_eof_overlay': certificate_at_eof,
                'canonical_comparison_sha256': hashlib.sha256(canonical).hexdigest(),
                'canonical_comparison_scope': 'Checksum and security-directory bytes zeroed; certificate removed only when bounded at EOF outside every section. This is a byte-comparison aid, not Authenticode or trust verification.'}


def select(archive, wanted):
    with zipfile.ZipFile(archive) as z:
        require(len(z.infolist()) < 10000, 'archive entry bound exceeded')
        found = {}
        for item in z.infolist():
            name = item.filename.replace('\\', '/')
            require(item.orig_filename == item.filename, 'ambiguous archive member')
            if name.casefold() not in wanted:
                continue
            require(name.casefold() not in found and not item.flag_bits & 1 and item.file_size <= 64 << 20, 'invalid selected archive member')
            require(all(part not in ('', '.', '..') for part in name.split('/')), 'unsafe selected member')
            data = z.read(item)
            require(len(data) == item.file_size, 'truncated archive member')
            found[name.casefold()] = data
        return found


def occurrences(image, needle, limit=16):
    found, start = [], 0
    while (offset := image.data.find(needle, start)) >= 0:
        require(len(found) < limit, 'ambiguous/excessive ABI pattern matches')
        found.append({'file_offset': hex(offset), 'rva': hex(image.rva_of(offset)) if image.rva_of(offset) is not None else None})
        start = offset + 1
    return found


def rtti_tables(image, type_name, slots):
    """Derive MSVC x64 COL/vftable identities from real relocated-image RVAs."""
    require(image.bits == 64, 'RTTI inspector requires x64 image')
    names = occurrences(image, type_name.encode('ascii') + b'\0')
    result = []
    for name in names:
        name_rva = int(name['rva'], 16)
        descriptor = name_rva - 16
        needle = struct.pack('<I', descriptor)
        for section in image.sections:
            if section['name'] != '.rdata':
                continue
            data = image.read(section['raw'], section['bytes'])
            at = 0
            while (at := data.find(needle, at)) >= 0:
                col = section['rva'] + at - 12
                at += 1
                try:
                    signature, offset, cd, td, hierarchy, self_rva = struct.unpack('<IIIIII', image.at(col, 24))
                    if signature != 1 or offset != 0 or cd != 0 or td != descriptor or self_rva != col:
                        continue
                    image.at(hierarchy, 16)
                    for reference in occurrences(image, struct.pack('<Q', image.base + col), limit=32):
                        table = int(reference['rva'], 16) + 8
                        if table % 8:
                            continue
                        entries = list(struct.unpack('<' + 'Q' * slots, image.at(table, slots * 8)))
                        targets = [entry - image.base for entry in entries]
                        if not all(image.section_for(target) and image.section_for(target)['flags'] & 0x20000000 for target in targets):
                            continue
                        result.append({'type_descriptor_rva': hex(descriptor), 'complete_object_locator_rva': hex(col),
                                       'class_hierarchy_rva': hex(hierarchy), 'vtable_rva': hex(table),
                                       'methods': [hex(target) for target in targets]})
                except ValueError:
                    continue
    return result


def disassemble_function(image, address, known):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
    ranges = image.function_ranges()
    candidates = [item for item in ranges if item[0] == address]
    if len(candidates) != 1:
        return {'rva': hex(address), 'error': 'no unique complete unwind range; no equivalence claimed'}
    start, end, unwind = candidates[0]
    require(end - start <= 16384, 'inspected method exceeds bound')
    engine = Cs(CS_ARCH_X86, CS_MODE_64)
    engine.detail = True
    instructions, shape = [], []

    def target_name(target):
        if start <= target < end:
            return {'kind': 'local', 'offset': hex(target - start)}
        if target in known:
            return {'kind': 'named-target', 'name': known[target], 'rva': hex(target)}
        section = image.section_for(target)
        result = {'kind': 'external', 'rva': hex(target), 'section': section['name'] if section else None}
        if section:
            result['section_offset'] = hex(target - section['rva'])
            if not section['flags'] & 0x20000000:
                try:
                    value = image.at(target, 32)
                    result['bytes_32'] = value.hex()
                except ValueError:
                    result['bytes_32'] = None
        return result

    consumed = 0
    for instruction in engine.disasm(image.at(start, end - start), start):
        references = []
        normalized = bytearray(instruction.bytes)
        for operand in instruction.operands:
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                references.append(target_name(instruction.address + instruction.size + operand.mem.disp))
                normalized[instruction.disp_offset:instruction.disp_offset + instruction.disp_size] = bytes(instruction.disp_size)
            if operand.type == X86_OP_IMM and (instruction.group(CS_GRP_JUMP) or instruction.group(CS_GRP_CALL)):
                references.append(target_name(operand.imm))
                normalized[instruction.imm_offset:instruction.imm_offset + instruction.imm_size] = bytes(instruction.imm_size)
        instructions.append({'offset': hex(instruction.address - start), 'bytes': instruction.bytes.hex(),
                             'instruction': instruction.mnemonic + ' ' + instruction.op_str,
                             'references': references})
        shape.append(normalized.hex())
        consumed += instruction.size
    require(consumed == end - start, 'instruction decode did not cover complete unwind body')
    return {'rva': hex(start), 'end_rva': hex(end), 'unwind_rva': hex(unwind),
            'code_sha256': hashlib.sha256(image.at(start, end - start)).hexdigest(),
            'relative_encoding_shape_sha256': hashlib.sha256(''.join(shape).encode()).hexdigest(),
            'shape_scope': 'PC-relative encodings zeroed only; compare every resolved target separately. Shape equality is not semantic equivalence.',
            'instructions': instructions}


def native_profile(image):
    stream = rtti_tables(image, '.?AVCSharedMemStream@@', 7)
    controller = rtti_tables(image, '.?AVCHTMLController@@', 42)
    known = {}
    for name, tables in [('stream', stream), ('controller', controller)]:
        for table in tables:
            known[int(table['vtable_rva'], 16)] = name + '-vtable'
            known[int(table['complete_object_locator_rva'], 16)] = name + '-COL'
            for index, method in enumerate(table['methods']):
                known.setdefault(int(method, 16), name + '-slot-' + str(index))
    exports = image.exports()
    for name, rva in exports.items():
        known[rva] = 'export-' + name
    methods = []
    if len(stream) == 1:
        methods = [disassemble_function(image, int(method, 16), known) for method in stream[0]['methods']]
    type_names = [match.group().decode('ascii') for match in re.finditer(rb'\.\?AV[A-Za-z0-9_?$@]*HTML[A-Za-z0-9_?$@]*@@', image.data)]
    return {'stream_tables': stream, 'controller_tables': controller, 'stream_complete_methods': methods,
            'related_type_names': sorted(set(type_names))[:32], 'exports': {key: hex(value) for key, value in exports.items() if key == 'CreateInterface'},
            'factory': disassemble_function(image, exports['CreateInterface'], known) if 'CreateInterface' in exports else None}


def varint(data, at):
    value = 0
    for shift in range(0, 70, 7):
        require(at < len(data), 'truncated protobuf varint')
        byte = data[at]
        at += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, at
    raise ValueError('oversized protobuf varint')


def descriptors(image):
    from google.protobuf.descriptor_pb2 import FileDescriptorProto
    from google.protobuf.message import DecodeError
    result = {}
    # Generated C++ stores serialized FileDescriptorProto beginning with field
    # one (filename). No string-table hit alone is accepted as a descriptor.
    for match in re.finditer(rb'[A-Za-z0-9_./-]{1,200}\.proto', image.data):
        for back in range(2, 6):
            start = match.start() - back
            if start < 0 or image.data[start] != 10:
                continue
            try:
                length, body = varint(image.data, start + 1)
                if body != match.start() or length != len(match.group()):
                    continue
                at = body + length
                while at - start < 2 << 20 and at < len(image.data):
                    tag, cursor = varint(image.data, at)
                    field, wire = tag >> 3, tag & 7
                    if not 1 <= field <= 14 or wire not in (0, 1, 2, 5):
                        break
                    if wire == 0:
                        _, cursor = varint(image.data, cursor)
                    elif wire == 2:
                        count, cursor = varint(image.data, cursor)
                        cursor += count
                    else:
                        cursor += 8 if wire == 1 else 4
                    require(cursor <= len(image.data), 'descriptor exceeds image')
                    at = cursor
                raw = image.data[start:at]
                descriptor = FileDescriptorProto.FromString(raw)
                require(descriptor.name.encode() == match.group() and len(descriptor.message_type) > 0, 'not a message descriptor')
                require(descriptor.name not in result, 'duplicate serialized descriptor')
                result[descriptor.name] = {'rva': hex(image.rva_of(start)), 'bytes': len(raw),
                                           'sha256': hashlib.sha256(raw).hexdigest(), 'descriptor': descriptor}
            except (ValueError, UnicodeError, DecodeError):
                continue
    return result


def descriptor_comparison(old, current):
    before, after = descriptors(old), descriptors(current)
    output = {'old_files': {}, 'current_files': {}, 'files_identical': {}, 'message_comparison': []}
    for key, files in [('old_files', before), ('current_files', after)]:
        for name, item in files.items():
            output[key][name] = {k: v for k, v in item.items() if k != 'descriptor'}
            output[key][name]['messages'] = [message.name for message in item['descriptor'].message_type]
            output[key][name]['enums'] = {enum.name: {value.name: value.number for value in enum.value} for enum in item['descriptor'].enum_type}
    for name in sorted(set(before) | set(after)):
        output['files_identical'][name] = bool(name in before and name in after and before[name]['sha256'] == after[name]['sha256'])
    def messages(files):
        found = {}
        for file in files.values():
            def walk(prefix, entries):
                for item in entries:
                    name = prefix + item.name
                    require(name not in found, 'ambiguous protobuf message identity')
                    found[name] = item
                    walk(name + '.', item.nested_type)
            descriptor = file['descriptor']
            walk(descriptor.package + '.' if descriptor.package else '', descriptor.message_type)
        return found
    a, b = messages(before), messages(after)
    for name in sorted(set(a) | set(b)):
        output['message_comparison'].append({'name': name, 'old_present': name in a, 'current_present': name in b,
            'serialized_definition_identical': bool(name in a and name in b and a[name].SerializeToString(deterministic=True) == b[name].SerializeToString(deterministic=True))})
    output['scope'] = 'Exact embedded protobuf descriptors and definitions only; producer/consumer numeric command assignment still requires its actual instruction/table proof.'
    return output


def compare(old, current):
    methods = []
    for rva in OLD_METHODS:
        prefix = old.at(rva, 48)
        methods.append({'old_rva': hex(rva), 'old_prefix_48': prefix.hex(),
                        'current_exact_prefix_locations': occurrences(current, prefix)})
    needles = [b'.?AVCSharedMemStream@@\0', b'.?AVIMemStream@@\0',
               b'ChromeHTML_Controller_003\0', b'bin/cef/cef.win64/steamwebhelper.exe\0',
               b'SteamChrome_MasterStream_spid%u\0']
    fields = {}
    for rva, size in [(0x132338, 64), (0x15c550, 24), (0x121cd8, 48), (0x123688, 42 * 8), (0x1806b0, 8)]:
        try:
            new_bytes = current.at(rva, size).hex()
        except ValueError:
            new_bytes = None
        try:
            old_bytes = old.at(rva, size).hex()
        except ValueError:
            old_bytes = None  # Mutable BSS/controller state has no disk bytes.
        fields[hex(rva)] = {'old': old_bytes, 'current_at_old_rva': new_bytes}
    return {'identical_file_bytes': old.data == current.data, 'old_profile_fields': fields,
            'method_prefixes': methods,
            'named_ABI_patterns': {needle.decode('ascii').rstrip('\0'): {'old': occurrences(old, needle), 'current': occurrences(current, needle)} for needle in needles},
            'warning': 'Prefix/string matches alone do not establish stream ABI or wire-command compatibility.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {'format': 1, 'mode': 'read-only-public-file-inspection',
              'runtime_readiness': 'unmeasured', 'trust_scope': 'HTTPS Valve manifest plus package SHA-256; no VAC verdict'}
    with tempfile.TemporaryDirectory(prefix='madeira-steam-browser-inspection-') as name:
        temporary = Path(name)
        manifest_file = temporary / 'manifest'
        report['manifest'] = fetch('steam_client_win64', manifest_file, 1 << 20)
        manifest = manifest_file.read_text()
        version = re.search(r'"version"\s+"([0-9]+)"', manifest)
        require(version is not None, 'manifest has no version')
        report['manifest']['version'] = version[1]
        packages = {}
        for package in ('bins_win64', 'bins_webhelpers_win64', 'bins_cef_win64'):
            block = re.search(r'"' + package + r'"\s*\{([^{}]+)\}', manifest)
            require(block is not None, 'missing manifest package ' + package)
            values = dict(re.findall(r'"([A-Za-z0-9_]+)"\s+"([^"\r\n]+)"', block[1]))
            require(re.fullmatch(package + r'\.zip\.[0-9a-f]{40}', values.get('file', '')) is not None, 'unsupported package container')
            require(re.fullmatch(r'[0-9a-f]{64}', values.get('sha2', '')) is not None, 'missing authenticated package digest')
            packages[package] = (values['file'], int(values['size']), values['sha2'])
        report['manifest']['packages'] = packages
        old_path = temporary / 'old-core.zip'
        report['old_package'] = fetch(OLD[0], old_path, 128 << 20, OLD[1], OLD[2])
        old_bytes = select(old_path, {'bin/chromehtml.dll'})['bin/chromehtml.dll']
        require(hashlib.sha256(old_bytes).hexdigest() == OLD_CORE_SHA, 'old core provenance mismatch')
        old = PE(old_bytes)
        report['old_core'] = old.describe()
        report['current_packages'] = []
        selected = {}
        for package in ('bins_win64', 'bins_webhelpers_win64'):
            file, size, sha = packages[package]
            path = temporary / (package + '.zip')
            report['current_packages'].append(fetch(file, path, 128 << 20, size, sha))
            wanted = {'bin/chromehtml.dll', 'bin/steamservice.dll', 'bin/steamservice.exe',
                      'bin/cef/cef.win64/steamwebhelper.exe', 'steamclient64.dll', 'steamclient.dll'}
            for member, data in select(path, wanted).items():
                require(member not in selected, 'duplicate selected component')
                selected[member] = data
        require('bin/chromehtml.dll' in selected and 'bin/cef/cef.win64/steamwebhelper.exe' in selected, 'required current components absent')
        report['current_components'] = {member: PE(data).describe() for member, data in selected.items()}
        current = PE(selected['bin/chromehtml.dll'])
        report['core_comparison'] = compare(old, current)
        report['native_profiles'] = {'old': native_profile(old), 'current': native_profile(current)}
        report['embedded_protobuf_comparison'] = descriptor_comparison(old, current)
    text = json.dumps(report, indent=2, sort_keys=True) + '\n'
    require(len(text) < 1 << 20, 'inspection report exceeds bound')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
