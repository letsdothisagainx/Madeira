#!/usr/bin/env python3
"""Read public Valve packages; never install, load, execute or alter their PEs.

This disposable CI inspection deliberately makes no HTMLIPC ABI or runtime
readiness claim. In particular an iOS mapped-image size may include Madeira's
alignment padding: compare actual PE headers, not only a runtime log extent.
"""
import argparse
import bisect
import capstone as cs
import pefile
import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import urllib.request
import zipfile
from collections import deque

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

    def import_slots(self):
        if len(self.directories) < 2 or not self.directories[1][0]:
            return {}
        rva, size = self.directories[1]
        slots = {}
        width = self.bits // 8
        for index in range(min(size // 20, 512)):
            row = self.at(rva + index * 20, 20)
            if not any(row):
                return slots
            original, _, _, name, first = struct.unpack('<IIIII', row)
            dll = self.string(name).lower()
            for item in range(8192):
                value = int.from_bytes(self.at((original or first) + item * width, width), 'little')
                if not value:
                    break
                function = '#' + str(value & 0xffff) if value & (1 << (self.bits - 1)) else self.string(value + 2)
                slots[first + item * width] = dll + '!' + function
            else:
                raise ValueError('unterminated import thunk list')
        raise ValueError('unterminated import directory')

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
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
    ranges = image.function_ranges()
    candidates = [item for item in ranges if item[0] == address]
    require(len(candidates) <= 1, 'ambiguous unwind entry')
    start = address
    unwind = candidates[0][2] if candidates else None
    engine = Cs(CS_ARCH_X86, CS_MODE_64)
    engine.detail = True
    imports = image.import_slots()
    known = {**known, **imports}
    pending, decoded, indirect_exits, tail_exits, trap_exits = [start], {}, [], [], []
    while pending:
        pc = pending.pop()
        if pc in decoded:
            continue
        if pc != start and known.get(pc, '').startswith('stream-slot-'):
            tail_exits.append({'rva': hex(pc), 'target': known[pc]})
            continue
        require(len(decoded) < 4096 and abs(pc - start) < 256 << 10, 'method CFG exceeds bound')
        section = image.section_for(pc)
        require(section and section['flags'] & 0x20000000, 'method CFG leaves executable image bytes')
        maximum = min(15, section['rva'] + section['bytes'] - pc)
        require(maximum > 0, 'method instruction is not file backed')
        instruction = next(engine.disasm(image.at(pc, maximum), pc, count=1), None)
        require(instruction is not None, 'method CFG undecoded instruction')
        decoded[pc] = instruction
        if instruction.mnemonic in ('int3', 'ud2'):
            trap_exits.append(hex(pc))
            continue
        if instruction.group(CS_GRP_RET):
            continue
        if instruction.group(CS_GRP_JUMP):
            if len(instruction.operands) == 1 and instruction.operands[0].type == X86_OP_IMM:
                pending.append(instruction.operands[0].imm)
            else:
                indirect_exits.append(hex(pc))
            if instruction.mnemonic != 'jmp':
                pending.append(pc + instruction.size)
        else:
            pending.append(pc + instruction.size)
    end = max(pc + item.size for pc, item in decoded.items())
    node_index = {pc: index for index, pc in enumerate(sorted(decoded))}
    instructions, shape = [], []

    def target_name(target):
        if target in decoded:
            return {'kind': 'local', 'offset': hex(target - start), 'instruction_index': node_index[target]}
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

    code_bytes = bytearray()
    for pc in sorted(decoded):
        instruction = decoded[pc]
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
        code_bytes.extend(instruction.bytes)
    return {'rva': hex(start), 'end_rva': hex(end), 'unwind_rva': hex(unwind) if unwind is not None else None,
            'initial_unwind_end_rva': hex(candidates[0][1]) if candidates else None,
            'scope': 'All statically reachable instructions from entry; conditional/direct jumps followed across unwind fragments, calls resolved but not inlined.',
            'indirect_exits': indirect_exits, 'other_stream_method_tail_exits': tail_exits, 'trap_exits': trap_exits,
            'control_flow_statically_closed': not indirect_exits,
            'code_sha256': hashlib.sha256(code_bytes).hexdigest(),
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
    registry = interface_registry(image, 'ChromeHTML_Controller_003')
    for entry in registry:
        if entry.get('returned_object_rva'):
            known[int(entry['returned_object_rva'], 16)] = 'controller-global-object'
    methods = []
    if len(stream) == 1:
        methods = [disassemble_function(image, int(method, 16), known) for method in stream[0]['methods']]
    callees = sorted({int(reference['rva'], 16) for method in methods for instruction in method['instructions']
                      for reference in instruction['references'] if reference['kind'] == 'external' and reference.get('section') == '.text'})
    require(len(callees) <= 32, 'direct stream callee count exceeds bound')
    callee_bodies = [disassemble_function(image, address, known) for address in callees]
    controller_init = None
    controller_init_callees = []
    if len(controller) == 1:
        # The established interface's slot four is Init; slot zero is its
        # deleting destructor. Retain the full instruction graph so all member
        # offsets and the actual subobject constructor arguments can be checked.
        controller_init = disassemble_function(image, int(controller[0]['methods'][4], 16), known)
        init_callees = sorted({int(reference['rva'], 16) for instruction in controller_init['instructions']
                               for reference in instruction['references'] if reference['kind'] == 'external' and reference.get('section') == '.text'})
        require(len(init_callees) <= 16, 'controller Init direct callee count exceeds bound')
        controller_init_callees = [disassemble_function(image, address, known) for address in init_callees]
    type_names = [match.group().decode('ascii') for match in re.finditer(rb'\.\?AV[A-Za-z0-9_?$@]*HTML[A-Za-z0-9_?$@]*@@', image.data)]
    return {'stream_tables': stream, 'controller_tables': controller, 'stream_complete_methods': methods,
            'direct_stream_callees': callee_bodies,
            'controller_init': controller_init, 'controller_init_direct_callees': controller_init_callees,
            'related_type_names': sorted(set(type_names))[:32], 'interface_registry_candidates': registry,
            'exports': {key: hex(value) for key, value in exports.items() if key == 'CreateInterface'},
            'factory': disassemble_function(image, exports['CreateInterface'], known) if 'CreateInterface' in exports else None}


def interface_registry(image, interface_name):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import X86_OP_REG, X86_OP_MEM, X86_REG_RAX, X86_REG_RIP, X86_REG_R8, X86_REG_RDX, X86_REG_RCX
    engine = Cs(CS_ARCH_X86, CS_MODE_64)
    engine.detail = True
    found = []
    for name in occurrences(image, interface_name.encode('ascii') + b'\0'):
        string_rva = int(name['rva'], 16)
        for reference in occurrences(image, struct.pack('<Q', image.base + string_rva), limit=32):
            at = int(reference['rva'], 16)
            if at % 8:
                continue
            try:
                function, pointer, next_pointer = struct.unpack('<QQQ', image.at(at - 8, 24))
                address = function - image.base
                section = image.section_for(address)
                if not section or not section['flags'] & 0x20000000:
                    continue
                if next_pointer and not image.section_for(next_pointer - image.base):
                    continue
                code = []
                for instruction in engine.disasm(image.at(address, 64), address):
                    code.append(instruction)
                    if instruction.mnemonic in ('ret', 'jmp'):
                        break
                entry = {'node_rva': hex(at - 8), 'name_rva': hex(string_rva),
                         'callback_rva': hex(address), 'initial_next_pointer': hex(next_pointer),
                         'callback_instructions': [{'rva': hex(i.address), 'bytes': i.bytes.hex(), 'instruction': i.mnemonic + ' ' + i.op_str} for i in code]}
                # Accept the object identity only from the complete ordinary
                # two-instruction factory leaf, never by proximity or a guess.
                if len(code) == 2 and code[0].mnemonic == 'lea' and code[1].mnemonic == 'ret':
                    operands = code[0].operands
                    if len(operands) == 2 and operands[0].type == X86_OP_REG and operands[0].reg == X86_REG_RAX and operands[1].type == X86_OP_MEM and operands[1].mem.base == X86_REG_RIP:
                        object_rva = code[0].address + code[0].size + operands[1].mem.disp
                        target = image.section_for(object_rva)
                        if target and target['flags'] & 0x80000000 and not target['flags'] & 0x20000000:
                            entry['returned_object_rva'] = hex(object_rva)
                found.append(entry)
            except ValueError:
                continue
    # Valve also initializes InterfaceReg in an ordinary static constructor:
    # lea r8,[name]; lea rdx,[factory]; lea rcx,[node]; jmp Register. The node
    # may live in BSS, so looking only for initialized disk pointers misses it.
    wanted = {int(item['rva'], 16) for item in occurrences(image, interface_name.encode('ascii') + b'\0')}
    for section in image.sections:
        if not section['flags'] & 0x20000000:
            continue
        history = deque(maxlen=4)
        for instruction in engine.disasm(image.at(section['rva'], section['bytes']), section['rva']):
            history.append(instruction)
            if len(history) != 4 or instruction.mnemonic not in ('jmp', 'call'):
                continue
            values = {}
            for item in list(history)[:3]:
                operands = item.operands
                if item.mnemonic != 'lea' or len(operands) != 2 or operands[0].type != X86_OP_REG or operands[1].type != X86_OP_MEM or operands[1].mem.base != X86_REG_RIP:
                    break
                values[operands[0].reg] = item.address + item.size + operands[1].mem.disp
            if set(values) != {X86_REG_R8, X86_REG_RDX, X86_REG_RCX} or values[X86_REG_R8] not in wanted:
                continue
            address, node = values[X86_REG_RDX], values[X86_REG_RCX]
            target, node_section = image.section_for(address), image.section_for(node)
            if not target or not target['flags'] & 0x20000000 or not node_section or not node_section['flags'] & 0x80000000:
                continue
            callback = []
            for item in engine.disasm(image.at(address, 64), address):
                callback.append(item)
                if item.mnemonic in ('ret', 'jmp'):
                    break
            entry = {'node_rva': hex(node), 'name_rva': hex(values[X86_REG_R8]), 'callback_rva': hex(address),
                     'source': 'validated-register-arguments-in-static-initializer',
                     'initializer': [{'rva': hex(i.address), 'bytes': i.bytes.hex(), 'instruction': i.mnemonic + ' ' + i.op_str} for i in history],
                     'callback_instructions': [{'rva': hex(i.address), 'bytes': i.bytes.hex(), 'instruction': i.mnemonic + ' ' + i.op_str} for i in callback]}
            if len(callback) == 2 and callback[0].mnemonic == 'lea' and callback[1].mnemonic == 'ret':
                operands = callback[0].operands
                if len(operands) == 2 and operands[0].type == X86_OP_REG and operands[0].reg == X86_REG_RAX and operands[1].type == X86_OP_MEM and operands[1].mem.base == X86_REG_RIP:
                    object_rva = callback[0].address + callback[0].size + operands[1].mem.disp
                    object_section = image.section_for(object_rva)
                    if object_section and object_section['flags'] & 0x80000000 and not object_section['flags'] & 0x20000000:
                        entry['returned_object_rva'] = hex(object_rva)
            found.append(entry)
    return found


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


def wire_require(value, reason):
    if not value:
        raise ValueError(reason)


class WireInspector:
    MAX_FILE = 64 << 20
    MAX_COMMAND = 511
    MAX_CASE_BYTES = 192

    def __init__(self, raw):
        wire_require(64 <= len(raw) <= self.MAX_FILE, 'input size exceeds bound')
        self.raw = raw
        self.pe = pefile.PE(data=raw, fast_load=True)
        wire_require(self.pe.FILE_HEADER.Machine in (0x8664, 0x14c), 'expected AMD64 or I386')
        self.bits = 64 if self.pe.FILE_HEADER.Machine == 0x8664 else 32
        self.width = self.bits // 8
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64 if self.bits == 64 else cs.CS_MODE_32)
        self.md.detail = True
        self.sections = [(s.VirtualAddress, s.get_data(), s.Characteristics) for s in self.pe.sections]
        wire_require(len(self.sections) <= 96, 'excessive sections')
        self.code = [(r, d) for r, d, f in self.sections if f & 0x20000000]
        self.vtables = self.wrapper_vtables()
        self.functions = []
        if self.bits == 64:
            self.pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
            self.functions = sorted((e.struct.BeginAddress, e.struct.EndAddress)
                                    for e in getattr(self.pe, 'DIRECTORY_ENTRY_EXCEPTION', []))
        self.starts = [a for a, z in self.functions]

    def data(self, rva, length):
        wire_require(0 <= rva and 0 <= length <= 1 << 20, 'invalid requested RVA/length')
        for start, data, flags in self.sections:
            offset = rva - start
            if 0 <= offset <= len(data) and length <= len(data) - offset:
                return data[offset:offset+length]
        raise ValueError('RVA is not file backed')

    def executable(self, rva):
        return any(start <= rva < start + len(data) for start, data in self.code)

    def reg(self, ident):
        name = self.md.reg_name(ident)
        if name in ('eax', 'ax', 'al'): return 'rax'
        if name in ('ebx', 'bx', 'bl'): return 'rbx'
        if name in ('ecx', 'cx', 'cl'): return 'rcx'
        if name in ('edx', 'dx', 'dl'): return 'rdx'
        if name in ('esi', 'si', 'sil'): return 'rsi'
        if name in ('edi', 'di', 'dil'): return 'rdi'
        if name in ('ebp', 'bp', 'bpl'): return 'rbp'
        if name in ('esp', 'sp', 'spl'): return 'rsp'
        return re.sub(r'(r[0-9]+)[dwb]$', r'\1', name)

    def row(self, ins):
        return {'rva': hex(ins.address), 'bytes': ins.bytes.hex(),
                'asm': ins.mnemonic + ' ' + ins.op_str}

    def wrapper_vtables(self):
        pattern = rb'\.\?AV\?\$CHTMLProtoBufMsg@V(CMsg[A-Za-z0-9_]+)@@@@\x00'
        types = {}
        for match in re.finditer(pattern, self.raw):
            wire_require(len(types) < 512, 'wrapper RTTI count exceeds bound')
            types[self.pe.get_rva_from_offset(match.start()) - 2*self.width] = match[1].decode('ascii')
        cols = {}
        for start, data, flags in self.sections:
            if flags & 0x20000000: continue
            length = 24 if self.bits == 64 else 20
            for offset in range(0, len(data)-length+1, 4):
                fields = struct.unpack_from('<' + 'I'*(length//4), data, offset)
                signature, object_offset, constructor_offset, type_, hierarchy = fields[:5]
                if self.bits == 64:
                    valid = signature == 1 and fields[5] == start + offset
                else:
                    type_ -= self.base
                    valid = signature == 0
                if valid and object_offset == 0 and type_ in types:
                    cols[start+offset] = types[type_]
        tables = {}
        fmt = '<Q' if self.bits == 64 else '<I'
        for col, name in cols.items():
            needle = struct.pack(fmt, self.base + col)
            for start, data, flags in self.sections:
                if flags & 0x20000000: continue
                for match in re.finditer(re.escape(needle), data):
                    rva = start + match.start() + self.width
                    first = struct.unpack(fmt, self.data(rva, self.width))[0] - self.base
                    if self.executable(first):
                        wire_require(rva not in tables or tables[rva] == name, 'ambiguous RTTI vtable')
                        tables[rva] = name
        return tables

    def stable_register(self, at, family, wanted=None):
        """Find an actual earlier RIP LEA, with no intervening register write."""
        if self.bits != 64: return None
        lo = max(0, at-512)
        try: raw = self.data(lo, at-lo)
        except ValueError: return None
        pattern = rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....'
        for match in reversed(list(re.finditer(pattern, raw, re.S))):
            address = lo + match.start()
            ins = next(self.md.disasm(match[0], address, count=1), None)
            if not ins or ins.size != 7 or self.reg(ins.operands[0].reg) != family: continue
            value = address + 7 + ins.operands[1].mem.disp
            if wanted is not None and value != wanted: continue
            if wanted is None and value not in self.vtables: continue
            subsequent = list(self.md.disasm(self.data(address+7, at-address-7), address+7))
            if subsequent and subsequent[-1].address + subsequent[-1].size != at: continue
            if any(any(self.reg(reg) == family for reg in other.regs_access()[1]) for other in subsequent): continue
            return value
        return None

    def normalized_header(self, compare):
        """Require MOV command,[object+0], then one known integer normalization."""
        for back in range(3, 17):
            start = compare.address - back
            try: ins = list(self.md.disasm(self.data(start, back), start))
            except ValueError: continue
            if not ins or ins[-1].address + ins[-1].size != compare.address: continue
            first = ins[0]
            if first.mnemonic != 'mov' or len(first.operands) != 2: continue
            dst, src = first.operands
            if dst.type != cs.x86.X86_OP_REG or dst.size != 4 or src.type != cs.x86.X86_OP_MEM: continue
            if src.size != 4 or src.mem.disp != 0 or src.mem.index: continue
            family = self.reg(dst.reg)
            if self.reg(compare.operands[0].reg) != family: continue
            bias = 0
            valid = True
            for item in ins[1:]:
                operands = item.operands
                if not operands or operands[0].type != cs.x86.X86_OP_REG or self.reg(operands[0].reg) != family:
                    valid = False; break
                if item.mnemonic == 'dec': bias += 1
                elif item.mnemonic in ('add', 'sub') and len(operands) == 2 and operands[1].type == cs.x86.X86_OP_IMM:
                    bias += operands[1].imm * (-1 if item.mnemonic == 'add' else 1)
                else: valid = False; break
            if valid and 0 <= bias <= self.MAX_COMMAND:
                return family, bias, ins
        raise ValueError('unrecognized command header normalization')

    def switch_targets(self, compare, following, index, maximum):
        """Evaluate only integer table lookup instructions for every bounded index."""
        wire_require(following and following[0].mnemonic == 'ja', 'expected unsigned bound branch')
        pipeline = []
        for item in following[1:13]:
            pipeline.append(item)
            if item.mnemonic == 'jmp': break
        wire_require(pipeline and pipeline[-1].mnemonic == 'jmp', 'missing bounded indirect jump')
        wire_require(pipeline[-1].operands[0].type != cs.x86.X86_OP_IMM, 'expected indirect jump')
        tables = set()
        external = {}
        result = []
        for position in range(maximum+1):
            state = {index: position}
            loads = 0
            def reg_value(reg):
                key = self.reg(reg)
                if key not in state:
                    if key not in external:
                        external[key] = self.stable_register(compare.address, key, 0)
                    wire_require(external[key] == 0, 'table base lacks a stable image-base producer')
                    state[key] = 0
                return state[key]
            def memory(mem, size):
                nonlocal loads
                wire_require(mem.segment == 0, 'segmented jump-table address')
                address = mem.disp
                if mem.base: address += reg_value(mem.base)
                if mem.index: address += reg_value(mem.index) * mem.scale
                if self.bits == 32: address -= self.base
                wire_require(size in (1, 4), 'invalid jump-table element width')
                data = self.data(address, size)
                tables.add((address, size)); loads += 1
                return int.from_bytes(data, 'little')
            for item in pipeline:
                ops = item.operands
                if item.mnemonic == 'lea':
                    wire_require(ops[1].type == cs.x86.X86_OP_MEM and ops[1].mem.base == cs.x86.X86_REG_RIP and not ops[1].mem.index,
                            'unexpected switch LEA')
                    value = item.address + item.size + ops[1].mem.disp
                    wire_require(value == 0, 'switch LEA does not produce module-relative base')
                    state[self.reg(ops[0].reg)] = value
                elif item.mnemonic == 'cdqe': state['rax'] = reg_value(cs.x86.X86_REG_EAX)
                elif item.mnemonic == 'movsxd':
                    wire_require(ops[1].type == cs.x86.X86_OP_REG, 'unexpected switch sign extension')
                    state[self.reg(ops[0].reg)] = reg_value(ops[1].reg)
                elif item.mnemonic in ('mov', 'movzx'):
                    wire_require(ops[0].type == cs.x86.X86_OP_REG and ops[1].type == cs.x86.X86_OP_MEM,
                            'unexpected switch move')
                    state[self.reg(ops[0].reg)] = memory(ops[1].mem, ops[1].size)
                elif item.mnemonic == 'add':
                    wire_require(ops[0].type == cs.x86.X86_OP_REG and ops[1].type == cs.x86.X86_OP_REG,
                            'unexpected switch add')
                    state[self.reg(ops[0].reg)] = reg_value(ops[0].reg) + reg_value(ops[1].reg)
                elif item.mnemonic == 'jmp':
                    target = reg_value(ops[0].reg) if ops[0].type == cs.x86.X86_OP_REG else memory(ops[0].mem, ops[0].size)
                    if self.bits == 32: target -= self.base
                    wire_require(loads and self.executable(target), 'jump-table target is not executable')
                    result.append(target)
                else: raise ValueError('unrecognized switch instruction')
        return result, pipeline, tables

    def case_wrapper(self, target, stop, preloaded=None):
        # Follow both ordinary paths through bounded trace/log instrumentation;
        # do not linearly cross a different dispatch case to find a type name.
        limit = min(stop, target + self.MAX_CASE_BYTES)
        pending = [(target, dict(preloaded or {}))]
        visited = set()
        found = []
        unresolved = False
        steps = 0
        while pending:
            address, state = pending.pop()
            key = (address, tuple(sorted(state.items())))
            if key in visited: continue
            visited.add(key)
            steps += 1
            if steps > 256: return None
            if not target <= address < limit:
                unresolved = True; continue
            item = next(self.md.disasm(self.data(address, min(15, limit-address)), address, count=1), None)
            if not item:
                unresolved = True; continue
            ops = item.operands
            next_state = dict(state)
            if item.mnemonic == 'lea' and len(ops) == 2 and ops[1].type == cs.x86.X86_OP_MEM and ops[1].mem.base == cs.x86.X86_REG_RIP:
                value = item.address + item.size + ops[1].mem.disp
                if value in self.vtables: next_state[self.reg(ops[0].reg)] = value
                else: next_state.pop(self.reg(ops[0].reg), None)
            elif item.mnemonic == 'mov' and len(ops) == 2 and ops[0].type == cs.x86.X86_OP_MEM and ops[0].size == self.width:
                value = None
                if ops[1].type == cs.x86.X86_OP_IMM:
                    candidate = ops[1].imm - self.base
                    if candidate in self.vtables: value = candidate
                elif ops[1].type == cs.x86.X86_OP_REG:
                    family = self.reg(ops[1].reg)
                    value = state.get(family)
                if value in self.vtables and self.reg(ops[0].mem.base) in ('rbp', 'rsp'):
                    found.append({'name': self.vtables[value], 'case_rva': hex(target), 'wrapper_vtable_rva': hex(value),
                                  'wrapper_store': self.row(item)})
                    continue
            if item.mnemonic != 'lea':
                for reg in item.regs_access()[1]: next_state.pop(self.reg(reg), None)
            if item.mnemonic == 'call':
                for family in ('rax','rcx','rdx','r8','r9','r10','r11'):
                    next_state.pop(family, None)
            if item.mnemonic == 'ret':
                unresolved = True; continue
            if item.group(cs.CS_GRP_JUMP):
                if not ops or ops[0].type != cs.x86.X86_OP_IMM:
                    unresolved = True; continue
                pending.append((ops[0].imm, dict(next_state)))
                if item.mnemonic == 'jmp': continue
            pending.append((item.address + item.size, next_state))
        if found and not unresolved and len({value['name'] for value in found}) == 1:
            return found[0]
        return None

    def receivers(self):
        candidates = []
        pattern = rb'\x3d....|\x81[\xf8-\xff]....|\x83[\xf8-\xff].'
        for section, raw in self.code:
            for match in re.finditer(pattern, raw, re.S):
                at = section + match.start()
                try:
                    ins = list(self.md.disasm(self.data(at, 96), at))
                    compare = ins[0]
                    if compare.mnemonic != 'cmp' or len(compare.operands) != 2: continue
                    dst, value = compare.operands
                    if dst.type != cs.x86.X86_OP_REG or dst.size != 4 or value.type != cs.x86.X86_OP_IMM: continue
                    maximum = value.imm
                    if not 50 <= maximum <= self.MAX_COMMAND: continue
                    index, bias, header = self.normalized_header(compare)
                    if maximum + bias > self.MAX_COMMAND: continue
                    targets, pipeline, tables = self.switch_targets(compare, ins[1:], index, maximum)
                    unique = sorted(set(targets) | {ins[1].operands[0].imm})
                    preloaded = {}
                    for reg in ('rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15'):
                        value = self.stable_register(compare.address, reg)
                        if value is not None: preloaded[reg] = value
                    bindings = {}
                    for number, target in enumerate(targets):
                        after = next((v for v in unique if v > target), target+self.MAX_CASE_BYTES)
                        wrapper = self.case_wrapper(target, after, preloaded)
                        if wrapper: bindings[number+bias] = wrapper
                    if len(bindings) < 10: continue
                    candidates.append({'compare_rva': hex(at), 'first_command': bias,
                        'last_command': bias+maximum, 'bound_and_lookup': [self.row(i) for i in header+ins[:2]+pipeline],
                        'table_bytes_sha256': hashlib.sha256(b''.join(struct.pack('<II', a, n)+self.data(a,n) for a,n in sorted(tables))).hexdigest(),
                        'bindings': bindings,
                        'unresolved': [i+bias for i in range(maximum+1) if i+bias not in bindings]})
                except (ValueError, IndexError, struct.error, pefile.PEFormatError): continue
        return candidates

    def inspect(self):
        receivers = self.receivers()
        merged = {}
        for receiver in receivers:
            for number, binding in receiver['bindings'].items():
                key = str(number)
                if key in merged and merged[key]['name'] != binding['name']:
                    raise ValueError('conflicting receiver switch command binding')
                merged[key] = binding
        return {'scope': 'static receiver jump-table bindings only; absent commands remain unresolved',
            'machine': hex(self.pe.FILE_HEADER.Machine), 'sha256': hashlib.sha256(self.raw).hexdigest(),
            'wrapper_vtable_count': len(self.vtables), 'receiver_switches': receivers,
            'proven_receiver_bindings': merged, 'proven_receiver_count': len(merged),
            'producer_status': 'not inferred from constants or string presence'}


def wire_extract_command_evidence(data):
    return WireInspector(data).inspect()



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
        old_wire = wire_extract_command_evidence(old.data)
        new_wire = wire_extract_command_evidence(current.data)
        report['wire_receiver_evidence'] = {'old': old_wire, 'current': new_wire}
        a = {key: value['name'] for key, value in old_wire['proven_receiver_bindings'].items()}
        b = {key: value['name'] for key, value in new_wire['proven_receiver_bindings'].items()}
        report['wire_receiver_evidence']['exact_binding_set_unchanged'] = a == b
        report['wire_receiver_evidence']['scope'] = 'Only independently decoded receiver-switch bindings; absent producer IDs remain unresolved.'
    text = json.dumps(report, indent=2, sort_keys=True) + '\n'
    require(len(text) < 1 << 20, 'inspection report exceeds bound')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
