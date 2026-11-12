#!/usr/bin/env python3
"""Read-only public Valve PE inspection. Never execute, install or modify a PE.

Package hashes come from Valve's current HTTPS manifest. This establishes download
provenance, not Authenticode trust, service functionality or a VAC verdict.
"""
import argparse
import bisect
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import tempfile
import zipfile

import capstone as cs


spec = importlib.util.spec_from_file_location(
    'steam_public_pe', Path(__file__).with_name('inspect-steam-browser-update.py'))
public = importlib.util.module_from_spec(spec)
spec.loader.exec_module(public)
require = public.require
NEEDLES = (b'Failed to load Steam Service', b'SteamServiceConnect',
           b'SteamService.dll', b'steamservice.dll', b'SteamService64',
           b'CreateServicePipe', b'ConnectServicePipe')


def manifest_blocks(text):
    """Parse Valve KeyValues nesting; bootstrapper packages contain child variants."""
    tokens = [a if a else b for a, b in re.findall(r'"([^"\r\n]*)"|([{}])', text)]
    require(len(tokens) < 10000, 'manifest token bound exceeded')
    cursor = 0
    def block(depth):
        nonlocal cursor
        require(depth <= 8, 'manifest nesting bound exceeded')
        result = {}
        while cursor < len(tokens) and tokens[cursor] != '}':
            key = tokens[cursor]
            cursor += 1
            require(cursor < len(tokens) and key not in ('{', '}') and key not in result, 'invalid/duplicate manifest key')
            value = tokens[cursor]
            cursor += 1
            if value == '{':
                value = block(depth+1)
                require(cursor < len(tokens) and tokens[cursor] == '}', 'unterminated manifest block')
                cursor += 1
            require(value != '}', 'invalid manifest value')
            result[key] = value
        return result
    result = block(0)
    require(cursor == len(tokens) and 'win64' in result, 'unexpected manifest root')
    root = result['win64']
    require(isinstance(root, dict), 'invalid manifest root block')
    return root


class Inspector:
    def __init__(self, raw):
        self.pe = public.PE(raw)
        require(self.pe.machine in (0x14c, 0x8664), 'unsupported selected PE machine')
        self.md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64 if self.pe.bits == 64 else cs.CS_MODE_32)
        self.md.detail = True
        self.md.skipdata = True
        self.imports = self.pe.import_slots()
        delayed = public.pefile.PE(data=raw, fast_load=True)
        delayed.parse_data_directories(directories=[public.pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT']])
        self.delayed_imports = {}
        for entry in getattr(delayed, 'DIRECTORY_ENTRY_DELAY_IMPORT', []):
            dll = entry.dll.decode('ascii').lower()
            for imported in entry.imports:
                name = imported.name.decode('ascii') if imported.name else '#'+str(imported.ordinal)
                slot = imported.address-self.pe.base
                require(0 <= slot < self.pe.image_size and slot not in self.imports, 'invalid/overlapping delay import slot')
                self.delayed_imports[slot] = dll+'!'+name
        self.imports.update(self.delayed_imports)
        self.ranges = self.pe.function_ranges()
        self.starts = [x[0] for x in self.ranges]
        self.code = [s for s in self.pe.sections if s['flags'] & 0x20000000]

    def at(self, rva, count):
        section = self.pe.section_for(rva)
        if not section:
            return b''
        return self.pe.at(rva, min(count, section['rva'] + section['bytes'] - rva))

    def literal(self, rva):
        section = self.pe.section_for(rva)
        if not section or section['flags'] & 0x20000000:
            return None
        try:
            raw = self.at(rva, 384)
            if len(raw) >= 4 and raw[1] == 0 and raw[3] == 0:
                end = next((i for i in range(0, len(raw)-1, 2) if raw[i:i+2] == b'\0\0'), -1)
                value = raw[:end].decode('utf-16le') if end >= 0 else ''
            else:
                end = raw.find(b'\0')
                value = raw[:end].decode('ascii') if end >= 0 else ''
            return value if len(value) >= 3 and all(c.isprintable() or c in '\t\r\n' for c in value) else None
        except (ValueError, UnicodeError):
            return None

    def row(self, ins):
        result = {'rva': hex(ins.address), 'bytes': ins.bytes.hex(),
                  'asm': ins.mnemonic + ' ' + ins.op_str}
        if not ins.id:
            return result
        refs = []
        for op in ins.operands:
            target = None
            if op.type == cs.x86.X86_OP_MEM:
                if op.mem.base == cs.x86.X86_REG_RIP:
                    target = ins.address + ins.size + op.mem.disp
                elif not op.mem.base and not op.mem.index:
                    target = op.mem.disp - self.pe.base
            elif op.type == cs.x86.X86_OP_IMM:
                target = op.imm if ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP) else op.imm - self.pe.base
            if target is not None:
                ref = {'rva': hex(target)}
                if target in self.imports:
                    ref['import'] = self.imports[target]
                literal = self.literal(target)
                if literal:
                    ref['literal'] = literal
                if len(ref) > 1 or ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP):
                    refs.append(ref)
        if refs:
            result['references'] = refs
        return result

    def string_refs(self, rva):
        result = []
        for section in self.code:
            raw = self.pe.at(section['rva'], section['bytes'])
            if self.pe.bits == 64:
                # RIP-relative LEA/MOV. Verify each candidate instruction and exact target.
                pattern = rb'[\x40-\x4f][\x8d\x8b][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....'
                candidates = (m.start() for m in re.finditer(pattern, raw, re.S))
                for offset in candidates:
                    at = section['rva'] + offset
                    ins = next(self.md.disasm(raw[offset:offset+15], at, count=1), None)
                    if ins and ins.id and any(op.type == cs.x86.X86_OP_MEM and op.mem.base == cs.x86.X86_REG_RIP
                                              and ins.address + ins.size + op.mem.disp == rva for op in ins.operands):
                        result.append(at)
            else:
                needle = struct.pack('<I', self.pe.base + rva)
                for match in re.finditer(re.escape(needle), raw):
                    for back in (1, 2):
                        offset = match.start() - back
                        if offset < 0:
                            continue
                        ins = next(self.md.disasm(raw[offset:offset+15], section['rva']+offset, count=1), None)
                        if ins and ins.id and ins.size == back+4 and any(
                                op.type == cs.x86.X86_OP_IMM and op.imm == self.pe.base+rva for op in ins.operands):
                            result.append(ins.address)
        require(len(result) <= 128, 'excessive string cross references')
        return sorted(set(result))

    def containing(self, rva):
        index = bisect.bisect_right(self.starts, rva) - 1
        if index >= 0 and self.ranges[index][0] <= rva < self.ranges[index][1]:
            start, end, _ = self.ranges[index]
            return start, min(end, start+16384), 'PE exception-directory function boundary'
        # x86 has no mandatory pdata. Never call this window a proven function.
        section = self.pe.section_for(rva)
        low = max(section['rva'], rva-1536)
        raw = self.pe.at(low, rva-low)
        prologue = raw.rfind(b'\x55\x8b\xec')
        start = low+prologue if prologue >= 0 else max(section['rva'], rva-256)
        return start, min(section['rva']+section['bytes'], rva+768), 'bounded x86 window; function start unproven'

    def body(self, rva):
        start, end, scope = self.containing(rva)
        if self.pe.bits == 64:
            # One RUNTIME_FUNCTION entry can contain only a prologue fragment.
            # Follow actual branch/fallthrough edges through all fragments;
            # do not mistake the unwind entry's end for the function's end.
            try:
                graph = public.disassemble_function(self.pe, start, {})
            except ValueError as error:
                # An unsupported or exceptionally large helper must not stop
                # inspection of the actual service-load call. Keep the bounded
                # window and explicitly report that CFG proof is incomplete.
                instructions = list(self.md.disasm(self.pe.at(start, end-start), start))
                return {'start_rva': hex(start), 'end_rva': hex(end),
                        'scope': 'bounded unwind fragment; CFG incomplete', 'cfg_error': str(error),
                        'sha256': hashlib.sha256(self.pe.at(start, end-start)).hexdigest(),
                        'instructions': [self.row(i) for i in instructions]}
            instructions = []
            for item in graph['instructions']:
                at = start+int(item['offset'], 16)
                raw = bytes.fromhex(item['bytes'])
                instruction = next(self.md.disasm(raw, at, count=1), None)
                require(instruction is not None and instruction.size == len(raw), 'CFG instruction identity mismatch')
                instructions.append(self.row(instruction))
            return {'start_rva': hex(start), 'end_rva': graph['end_rva'],
                    'scope': graph['scope'], 'initial_unwind_end_rva': graph['initial_unwind_end_rva'],
                    'indirect_exits': graph['indirect_exits'], 'sha256': graph['code_sha256'],
                    'instructions': instructions}
        instructions = list(self.md.disasm(self.pe.at(start, end-start), start))
        require(len(instructions) <= 8192, 'function instruction bound exceeded')
        return {'start_rva': hex(start), 'end_rva': hex(end), 'scope': scope,
                'sha256': hashlib.sha256(self.pe.at(start, end-start)).hexdigest(),
                'instructions': [self.row(i) for i in instructions]}

    def inspect(self):
        strings = []
        bodies = {}
        roots = []
        loader_exports = {name: hex(rva) for name, rva in self.pe.exports().items()
                          if 'Sys_LoadModule' in name or 'Sys_GetLastError' in name}
        roots.extend(int(rva, 16) for rva in loader_exports.values())
        for needle in NEEDLES:
            for encoding, value in [('ascii', needle), ('utf16le', needle.decode().encode('utf-16le'))]:
                cursor = 0
                while (offset := self.pe.data.find(value, cursor)) >= 0:
                    cursor = offset+1
                    require(len(strings) < 192, 'string occurrence bound exceeded')
                    rva = self.pe.rva_of(offset)
                    if rva is None:
                        continue
                    refs = self.string_refs(rva)
                    strings.append({'search': needle.decode(), 'encoding': encoding,
                                    'rva': hex(rva), 'literal': self.literal(rva),
                                    'code_references': [hex(x) for x in refs]})
                    if needle == NEEDLES[0]:
                        roots.extend(refs)
        queue = [(rva, 0) for rva in roots]
        while queue and len(bodies) < 24:
            rva, depth = queue.pop(0)
            section = self.pe.section_for(rva)
            if not section or not section['flags'] & 0x20000000:
                continue
            start = self.containing(rva)[0]
            if start in bodies:
                continue
            body = self.body(rva)
            body['depth_from_error_producer'] = depth
            bodies[start] = body
            if depth < 2:
                for row in body['instructions']:
                    if row['asm'].startswith('call '):
                        for ref in row.get('references', []):
                            if 'import' not in ref:
                                queue.append((int(ref['rva'], 16), depth+1))
        return {'pe': self.pe.describe(), 'loader_exports': loader_exports, 'relevant_import_slots': {
                    hex(rva): name for rva, name in self.imports.items()
                    if re.search(r'LoadLibrary|GetProcAddress|GetLastError|CreateService|OpenService|ConnectNamedPipe|CreateFile|IsWow64|GetNativeSystemInfo', name, re.I)},
                'strings': strings, 'error_producer_functions_and_direct_callees': list(bodies.values()),
                'interpretation': 'Static code evidence only. Unknown indirect callees, runtime paths and last-error provenance require separate evidence.'}

    def imported_calls(self, wanted):
        """Decode direct calls and cached IAT loads; never infer register calls."""
        matches = {}
        for section in self.code:
            raw = self.pe.at(section['rva'], section['bytes'])
            for match in re.finditer(rb'\xff\x15....', raw, re.S):
                at = section['rva']+match.start()
                slot = at+6+struct.unpack_from('<i', match[0], 2)[0] if self.pe.bits == 64 else \
                       struct.unpack_from('<I', match[0], 2)[0]-self.pe.base
                if self.imports.get(slot) not in wanted:
                    continue
                instruction = next(self.md.disasm(match[0], at, count=1), None)
                require(instruction and instruction.id and instruction.size == 6 and instruction.mnemonic == 'call',
                        'invalid IAT call candidate')
                matches[at] = {**self.row(instruction), 'reference_kind': 'direct IAT call'}
            if self.pe.bits == 32:
                for slot, name in self.imports.items():
                    if name not in wanted:
                        continue
                    address = struct.pack('<I', self.pe.base+slot)
                    for match in re.finditer(re.escape(address), raw):
                        for back in range(1, 7):
                            offset = match.start()-back
                            if offset < 0:
                                continue
                            at = section['rva']+offset
                            instruction = next(self.md.disasm(raw[offset:offset+15], at, count=1), None)
                            if not instruction or not instruction.id or instruction.size != back+4 or \
                                    instruction.mnemonic not in ('mov', 'call', 'jmp', 'push'):
                                continue
                            if any(op.type == cs.x86.X86_OP_MEM and not op.mem.base and not op.mem.index
                                   and op.mem.disp == self.pe.base+slot for op in instruction.operands):
                                matches.setdefault(at, {**self.row(instruction), 'reference_kind': 'cached IAT reference; inspect later use'})
        require(len(matches) <= 256, 'registry IAT call bound exceeded')
        return [matches[at] for at in sorted(matches)]

    def x86_frame_cfg(self, target):
        """Trace a decoded frame prologue, without pretending to have symbols."""
        require(self.pe.bits == 32, 'registry frame proof requires captured I386 image')
        section = self.pe.section_for(target)
        low = max(section['rva'], target-8192)
        raw = self.pe.at(low, target-low)
        starts = [(low+m.start(), 'decoded x86 frame prologue') for m in re.finditer(rb'\x55\x8b\xec', raw)]
        # MSVC also emits frame-pointer-omitted wrappers. INT3 alignment is a
        # useful candidate boundary, but remains explicitly weaker than symbols.
        starts.extend((low+m.end(), 'preceding x86 INT3 padding boundary') for m in re.finditer(rb'\xcc+', raw))
        start = None
        boundary_scope = ''
        for candidate, candidate_scope in sorted(starts, reverse=True):
            if candidate >= target:
                continue
            prefix = list(self.md.disasm(self.pe.at(candidate, target-candidate), candidate))
            if prefix and prefix[-1].address+prefix[-1].size == target and all(i.id for i in prefix):
                start = candidate
                boundary_scope = candidate_scope
                break
        if start is None:
            return {'target_rva': hex(target), 'scope': 'unresolved: no decoded preceding x86 frame prologue',
                    'instructions': []}
        pending, decoded, exits = [start], {}, []
        while pending:
            at = pending.pop()
            if at in decoded:
                continue
            current = self.pe.section_for(at)
            if not current or not current['flags'] & 0x20000000 or abs(at-start) >= 16384 or len(decoded) >= 4096:
                exits.append(hex(at))
                continue
            instruction = next(self.md.disasm(self.at(at, 15), at, count=1), None)
            if not instruction or not instruction.id:
                exits.append(hex(at))
                continue
            decoded[at] = instruction
            if instruction.group(cs.CS_GRP_RET) or instruction.mnemonic in ('int3', 'ud2'):
                continue
            if instruction.group(cs.CS_GRP_JUMP):
                if len(instruction.operands) == 1 and instruction.operands[0].type == cs.x86.X86_OP_IMM:
                    pending.append(instruction.operands[0].imm)
                else:
                    exits.append(hex(at))
                if instruction.mnemonic == 'jmp':
                    continue
            pending.append(at+instruction.size)
        return {'start_rva': hex(start), 'target_rva': hex(target),
                'scope': 'CFG from nearest '+boundary_scope+'; no PDB identity',
                'target_reachable': target in decoded, 'unresolved_exits': exits,
                'instructions': [self.row(decoded[at]) for at in sorted(decoded)]}

    def direct_calls_to(self, targets):
        calls = []
        for section in self.code:
            raw = self.pe.at(section['rva'], section['bytes'])
            for match in re.finditer(rb'\xe8....', raw, re.S):
                at = section['rva']+match.start()
                target = at+5+struct.unpack_from('<i', match[0], 1)[0]
                if target in targets:
                    calls.append({'rva': hex(at), 'target_rva': hex(target)})
        require(len(calls) <= 128, 'registry direct caller bound exceeded')
        return calls

    def inspect_registry_security(self):
        wanted = {name for name in self.imports.values() if re.search(
            r'!Reg(?:QueryInfoKey[AW]|OpenKeyEx[AW]|CreateKeyEx[AW]|GetKeySecurity|CloseKey)$', name)}
        calls = self.imported_calls(wanted)
        query_calls = [row for row in calls if any('!RegQueryInfoKey' in ref.get('import', '')
                                                  for ref in row.get('references', []))]
        functions = {}
        for row in query_calls:
            at = int(row['rva'], 16)
            body = self.x86_frame_cfg(at)
            key = body.get('start_rva', row['rva'])
            functions[key] = {**body, 'relationship': 'contains genuine RegQueryInfoKey IAT call or cached reference'}
        parents = self.direct_calls_to({int(key, 16) for key in functions})
        for row in parents:
            at = int(row['rva'], 16)
            body = self.x86_frame_cfg(at)
            key = body.get('start_rva', row['rva'])
            if key not in functions:
                functions[key] = {**body, 'relationship': 'direct caller of query wrapper',
                                  'wrapper_target_rva': row['target_rva']}
        dynamic_names = []
        for name in ('RegQueryInfoKeyA', 'RegQueryInfoKeyW'):
            for encoding, needle in [('ascii', name.encode()), ('utf16le', name.encode('utf-16le'))]:
                for match in re.finditer(re.escape(needle), self.pe.data):
                    rva = self.pe.rva_of(match.start())
                    dynamic_names.append({'name': name, 'encoding': encoding, 'rva': hex(rva) if rva is not None else None})
        return {'pe': self.pe.describe(), 'query_api_name_occurrences': dynamic_names,
                'delayed_registry_imports': {hex(slot): name for slot, name in self.delayed_imports.items() if '!Reg' in name},
                'registry_import_slots': {
                    hex(slot): name for slot, name in self.imports.items() if name in wanted},
                'iat_calls': calls, 'query_wrapper_callers': parents, 'functions': list(functions.values()),
                'scope': 'Public unmodified I386 PE. Static code only; handle rights and output use require actual dataflow proof.'}


def emit_summary(report):
    """Make bounded evidence readable when artifact downloads are unavailable."""
    remaining = 60000
    omitted = 0
    def emit(value):
        nonlocal remaining, omitted
        encoded = json.dumps(value, separators=(',', ':'))
        if len(encoded)+1 > remaining:
            omitted += 1
            return
        print(encoded)
        remaining -= len(encoded)+1
    emit({'kind': 'manifest', 'manifest': report.get('manifest'), 'packages': report['packages']})
    emit({'kind': 'service-archive-inventory', 'entries': report.get('archive_service_inventory', [])})
    candidates = []
    for name, component in report['components'].items():
        pe = component['pe']
        emit({'kind': 'component', 'name': name, 'machine': pe['machine'], 'sha256': pe['sha256'],
              'bytes': pe['bytes'], 'imports': pe['imports'], 'strings': component['strings'],
              'loader_exports': component.get('loader_exports', {}),
              'relevant_import_slots': component['relevant_import_slots']})
        for body in component['error_producer_functions_and_direct_callees']:
            relevant = any(re.search(r'LoadLibrary|GetLastError|GetProcAddress|IsWow64|GetNativeSystemInfo',
                                    ref.get('import', ''), re.I)
                           for row in body['instructions'] for ref in row.get('references', []))
            candidates.append((pe['machine'] != '8664', body['depth_from_error_producer'] != 0, not relevant, name, body))
    for _, _, _, name, body in sorted(candidates, key=lambda row: (row[0], row[1], row[2], row[3], row[4]['start_rva'])):
        emit({'kind': 'function', 'component': name, **{k: v for k, v in body.items() if k != 'instructions'}})
        # Full small functions; for large helper bodies retain import-call
        # argument/return contexts rather than unrelated profiler/logging code.
        instructions = body['instructions']
        indices = set(range(len(instructions))) if len(instructions) <= 200 else set(range(24))
        for index, row in enumerate(instructions):
            if any('import' in ref or 'literal' in ref for ref in row.get('references', [])):
                indices.update(range(max(0, index-10), min(len(instructions), index+5)))
        for index in sorted(indices):
            emit({'component': name, **instructions[index]})
    print(json.dumps({'kind': 'summary-bound', 'omitted_records': omitted,
                      'complete_evidence': 'steam-service-loader.json artifact', 'vac_verdict': 'unmeasured'}))


def emit_registry_summary(report):
    remaining, omitted = 60000, 0
    def emit(row):
        nonlocal remaining, omitted
        encoded = json.dumps(row, separators=(',', ':'))
        if len(encoded)+1 <= remaining:
            print(encoded)
            remaining -= len(encoded)+1
        else:
            omitted += 1
    emit({'kind': 'registry-manifest', 'manifest': report.get('manifest'), 'packages': report['packages']})
    for name, component in report['components'].items():
        pe = component['pe']
        emit({'kind': 'registry-component', 'name': name, 'machine': pe['machine'], 'sha256': pe['sha256'],
              'bytes': pe['bytes'], 'timestamp': pe['timestamp'], 'size_of_image': pe['size_of_image'],
              'query_api_name_occurrences': component['query_api_name_occurrences'],
              'delayed_registry_imports': component['delayed_registry_imports'],
              'registry_import_slots': component['registry_import_slots'],
              'iat_calls': component['iat_calls'], 'query_wrapper_callers': component['query_wrapper_callers']})
        for body in component['functions']:
            emit({'kind': 'registry-function', 'component': name,
                  **{key: value for key, value in body.items() if key != 'instructions'}})
            for row in body['instructions']:
                emit({'component': name, **row})
    print(json.dumps({'kind': 'registry-summary-bound', 'omitted_records': omitted,
                      'complete_evidence': 'steam-service-loader.json artifact', 'vac_verdict': 'unmeasured'}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inspect-file', type=Path, action='append', default=[])
    parser.add_argument('--registry-security', action='store_true', help='Inspect genuine I386 registry query handle rights and output use')
    args = parser.parse_args()
    report = {'format': 1, 'mode': 'read-only-public-file-inspection', 'vac_verdict': 'unmeasured',
              'service_functionality': 'unmeasured', 'components': {}, 'packages': []}
    if args.inspect_file:
        for path in args.inspect_file:
            inspector = Inspector(path.read_bytes())
            report['components'][path.name] = inspector.inspect_registry_security() if args.registry_security else inspector.inspect()
    else:
        with tempfile.TemporaryDirectory(prefix='madeira-steam-service-inspection-') as name:
            temporary = Path(name)
            manifest_path = temporary / 'manifest'
            report['manifest'] = public.fetch('steam_client_win64', manifest_path, 1 << 20)
            manifest = manifest_path.read_text()
            version = re.search(r'"version"\s+"([0-9]+)"', manifest)
            require(version is not None, 'missing current manifest version')
            report['manifest']['version'] = version[1]
            blocks = manifest_blocks(manifest)
            require('bins_win64' in blocks, 'current manifest missing native binaries')
            report['archive_service_inventory'] = []
            for package in ('bins_win64', 'steam_win64', 'steam_win32', 'steam'):
                if package not in blocks:
                    continue
                values = blocks[package]
                file, size, sha = values.get('file', ''), int(values.get('size', '0')), values.get('sha2', '')
                require(re.fullmatch(r'[A-Za-z0-9_]+\.zip\.[0-9a-f]{40}', file) is not None
                        and re.fullmatch(r'[0-9a-f]{64}', sha) is not None and 0 < size <= 128 << 20,
                        'invalid authenticated public package metadata')
                archive = temporary / (package+'.zip')
                report['packages'].append(public.fetch(file, archive, 128 << 20, size, sha))
                with zipfile.ZipFile(archive) as z:
                    require(len(z.infolist()) < 10000, 'archive member bound exceeded')
                    for item in z.infolist():
                        member = item.filename.replace('\\', '/').lower()
                        if 'service' in member:
                            report['archive_service_inventory'].append({'package': package, 'member': member, 'bytes': item.file_size})
                        leaf = member.rsplit('/', 1)[-1]
                        if args.registry_security and leaf not in ('steamservice.dll', 'steamservice.exe'):
                            continue
                        if leaf not in ('steam.exe', 'steamclient.dll', 'steamclient64.dll',
                                        'vstdlib_s64.dll', 'tier0_s64.dll') and not (
                                'service' in leaf and member.endswith(('.dll', '.exe'))):
                            continue
                        require(item.orig_filename == item.filename and not item.flag_bits & 1 and
                                all(part not in ('', '.', '..') for part in member.split('/')) and
                                0 < item.file_size <= 64 << 20, 'unsafe selected PE member')
                        key = package+'/'+member
                        require(key not in report['components'] and len(report['components']) < 16, 'duplicate or excessive selected PE')
                        data = z.read(item)
                        require(len(data) == item.file_size, 'selected PE length mismatch')
                        inspector = Inspector(data)
                        report['components'][key] = inspector.inspect_registry_security() if args.registry_security else inspector.inspect()
            require(report['components'], 'no selected public components')
    encoded = json.dumps(report, indent=2).encode()+b'\n'
    require(len(encoded) <= 16 << 20, 'static inspection output bound exceeded')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    print(f'Inspected {len(report["components"])} public PE files; report {len(encoded)} bytes; no PE executed')
    if args.registry_security:
        emit_registry_summary(report)
    else:
        emit_summary(report)


if __name__ == '__main__':
    main()
