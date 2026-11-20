#!/usr/bin/env python3
"""Bounded anonymous official-depot retrieval; never execute or alter a Valve PE."""
import argparse
import bisect
import hashlib
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import urllib.request
import zipfile

import capstone as cs
import pefile
import xxhash

APP, DEPOT, MANIFEST = 730, 2347771, 4200138934793327916
FILE = 'game/csgo/bin/win64/client.dll'
TIER0 = 'game/bin/win64/tier0.dll'
TIER0_ID = '8f2d32d37c93635a'
EXPECTED_BYTES = 39120536
EXPECTED_ID = 'eb5edd5d42fad2d2'
TOOL_URL = ('https://github.com/SteamRE/DepotDownloader/releases/download/'
            'DepotDownloader_3.4.0/DepotDownloader-linux-x64.zip')
TOOL_SHA256 = 'a999dec66b4850fc961bd50366696d23c2d0fad7b18790e6a5647b2f19097a53'


def report_log(path):
    lines = path.read_text(errors='replace').splitlines()
    useful = [line for line in lines if re.search(
        r'(?i)anonymous|connect|fail|error|denied|depot|manifest|download|license', line)]
    for line in useful[-35:]:
        print('STEAM ' + re.sub(r'https?://\S+', '[url]', line)[:500])


def inspect_tier0(path):
    image = path.read_bytes()
    assert len(image) <= 16 << 20, 'tier0 exceeds analysis bound'
    pe = pefile.PE(data=image)
    base = pe.OPTIONAL_HEADER.ImageBase
    identity = xxhash.xxh3_64_intdigest(b'tier0.dll') ^ ((pe.OPTIONAL_HEADER.SizeOfImage << 32) | pe.FILE_HEADER.TimeDateStamp)
    print(f'TIER0_OBSERVED bytes={len(image)} sha256={hashlib.sha256(image).hexdigest()} identity={identity:016x} timestamp={pe.FILE_HEADER.TimeDateStamp:#x} image-size={pe.OPTIONAL_HEADER.SizeOfImage:#x}')
    assert f'{identity:016x}' == TIER0_ID and pe.FILE_HEADER.Machine == 0x8664, 'runtime tier0 identity mismatch'
    exports = {sym.address: (sym.name or b'').decode(errors='replace')
               for sym in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])}
    imports = {}
    for descriptor in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        for imported in descriptor.imports:
            imports[imported.address - base] = descriptor.dll.decode() + '!' + (imported.name.decode() if imported.name else '#' + str(imported.ordinal))
    functions = [(r.struct.BeginAddress, r.struct.EndAddress, r.struct.UnwindData)
                 for r in getattr(pe, 'DIRECTORY_ENTRY_EXCEPTION', [])]
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    shown = set()
    def chain_root(record, depth=0):
        assert depth < 16, 'unwind chain exceeds bound'
        begin, end, unwind = record
        header = pe.get_data(unwind, 4)
        if header[0] >> 3 & 4:
            offset = 4 + ((header[2] + 1) & ~1) * 2
            parent = struct.unpack('<3I', pe.get_data(unwind + offset, 12))
            return chain_root(parent, depth + 1)
        return begin
    def show_function(target, label):
        matches = [r for r in functions if r[0] <= target < r[1]]
        if not matches:
            print(f'TIER0_FUNCTION_UNPROVEN label={label} rva={target:#x}')
            return
        root = chain_root(matches[0])
        if root in shown:
            print(f'TIER0_FUNCTION_ALREADY_SHOWN label={label} root={root:#x}')
            return
        shown.add(root)
        segments = [r for r in functions if chain_root(r) == root]
        total = 0
        for begin, end, unwind in segments:
            total += end - begin
            assert total <= 32768, 'logical Tier0 function exceeds instruction bound'
            print(f'TIER0_FUNCTION label={label} target={target:#x} root={root:#x} begin={begin:#x} end={end:#x} unwind={unwind:#x} raw-unwind={pe.get_data(unwind, 48).hex()}')
            for ins in md.disasm(pe.get_data(begin, end - begin), begin):
                print(f'TIER0_CODE {ins.address:#x}: {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}')
                if ins.group(cs.CS_GRP_CALL):
                    for operand in ins.operands:
                        if operand.type == cs.x86.X86_OP_IMM and operand.imm in exports:
                            print(f'TIER0_CALLEE instruction={ins.address:#x} target={operand.imm:#x} export={exports[operand.imm]!r}')
                for operand in ins.operands:
                    if operand.type == cs.x86.X86_OP_MEM and operand.mem.base == cs.x86.X86_REG_RIP:
                        slot = ins.address + ins.size + operand.mem.disp
                        if slot in imports:
                            print(f'TIER0_IMPORT instruction={ins.address:#x} slot={slot:#x} name={imports[slot]}')
                        if ins.mnemonic == 'lea':
                            text = pe.get_data(slot, 128).split(b'\0', 1)[0]
                            if 4 <= len(text) <= 127 and all(32 <= b < 127 for b in text):
                                print(f'TIER0_STRING instruction={ins.address:#x} rva={slot:#x} value={text.decode()!r}')
    selected = [(rva, name) for rva, name in exports.items()
                if any(t in name for t in ('ThreadPool', 'g_pThreadPool', 'AddJob', 'CreateJob', 'CPUInformation'))]
    for rva, name in selected[:100]:
        print(f'TIER0_EXPORT rva={rva:#x} name={name!r}')
        if 'g_pThreadPool' in name:
            raw = pe.get_data(rva, 64)
            print(f'TIER0_GLOBAL rva={rva:#x} raw={raw.hex()}')
            pointer = struct.unpack_from('<Q', raw)[0]
            if base <= pointer < base + pe.OPTIONAL_HEADER.SizeOfImage:
                print(f'TIER0_GLOBAL_OBJECT rva={pointer-base:#x} raw={pe.get_data(pointer-base, 128).hex()}')
        elif any(t in name for t in ('CreateThreadPool', 'ThreadPool@@', 'AddJob', 'CPUInformation')):
            show_function(rva, name)
    # Match x64 MSVC type descriptor -> complete object locator -> vftable.
    # Report only a true signature/self-RVA locator, not arbitrary text bytes.
    sections = [(section.VirtualAddress, section.get_data()) for section in pe.sections
                if not section.Characteristics & 0x20000000]
    type_count, table_count = 0, 0
    for section_rva, raw in sections:
        for match in re.finditer(rb'\.\?AV[^\0]{0,180}ThreadPool[^\0]{0,180}\0', raw):
            type_count += 1
            assert type_count <= 32, 'too many thread-pool RTTI descriptors'
            descriptor = section_rva + match.start() - 16
            print(f'TIER0_RTTI type-rva={descriptor:#x} name={match.group()!r}')
            needle = struct.pack('<I', descriptor)
            for candidate_section_rva, candidate_raw in sections:
                position = -1
                while True:
                    position = candidate_raw.find(needle, position + 1)
                    if position < 0:
                        break
                    locator = candidate_section_rva + position - 12
                    if position < 12:
                        continue
                    fields = struct.unpack('<6I', pe.get_data(locator, 24))
                    if fields[0] != 1 or fields[3] != descriptor or fields[5] != locator:
                        continue
                    print(f'TIER0_COL rva={locator:#x} fields={fields}')
                    pointer_bytes = struct.pack('<Q', base + locator)
                    for vtable_section_rva, vtable_raw in sections:
                        p = -1
                        while True:
                            p = vtable_raw.find(pointer_bytes, p + 1)
                            if p < 0:
                                break
                            table_count += 1
                            assert table_count <= 16, 'too many thread-pool vtables'
                            table = vtable_section_rva + p + 8
                            entries = struct.unpack('<24Q', pe.get_data(table, 24 * 8))
                            print(f'TIER0_VTABLE rva={table:#x} entries={[hex(v-base) for v in entries]}')
                            target = entries[16] - base
                            if 0 <= target < pe.OPTIONAL_HEADER.SizeOfImage:
                                show_function(target, f'vtable{table:#x}+0x80')
    for target in (0xa4190, 0xa7490, 0xa5b40, 0xa5cf0, 0xa5f80, 0xa5780, 0xa7520, 0xa7680):
        show_function(target, 'exact-pool-start-queue-stop-suspend-path')
    field_writers = set()
    for record in functions:
        low, high, _ = record
        if not 0xa3900 <= low < 0xa7900:
            continue
        for instruction in md.disasm(pe.get_data(low, high - low), low):
            for operand in instruction.operands:
                if operand.type != cs.x86.X86_OP_MEM or operand.mem.base in (cs.x86.X86_REG_RIP, cs.x86.X86_REG_RSP, cs.x86.X86_REG_RBP, 0):
                    continue
                if any(operand.mem.disp <= field < operand.mem.disp + operand.size for field in (0x130, 0x159)):
                    print(f'TIER0_POOL_FIELD instruction={instruction.address:#x} root={chain_root(record):#x} access={operand.access} bytes={operand.size} code={instruction.mnemonic} {instruction.op_str}')
                    if operand.access & cs.CS_AC_WRITE:
                        field_writers.add(chain_root(record))
    assert len(field_writers) <= 16, 'pool field writer bound exceeded'
    for target in sorted(field_writers):
        show_function(target, 'observed-pool-field-writer')
    cpu_constructors = (0x65430, 0x65f40, 0x62d20, 0x63420, 0x63610)
    for target in cpu_constructors:
        show_function(target, 'exact-cpu-topology-constructor-or-derived-info')
    cpu_tables = set()
    for target in cpu_constructors:
        records = [record for record in functions if record[0] <= target < record[1]]
        if not records:
            continue
        root = chain_root(records[0])
        for low, high, _ in functions:
            if chain_root((low, high, _)) != root:
                continue
            for ins in md.disasm(pe.get_data(low, high - low), low):
                if ins.mnemonic != 'lea':
                    continue
                for operand in ins.operands:
                    if operand.type != cs.x86.X86_OP_MEM or operand.mem.base != cs.x86.X86_REG_RIP:
                        continue
                    slot = ins.address + ins.size + operand.mem.disp
                    table = pe.get_data(slot, 64)
                    if len(table) != 64:
                        continue
                    entries = struct.unpack('<8Q', table)
                    if not all(any(lo <= value - base < hi for lo, hi, _ in functions) for value in entries):
                        continue
                    if slot in cpu_tables:
                        continue
                    cpu_tables.add(slot)
                    assert len(cpu_tables) <= 16, 'CPU vtable inspection exceeds bound'
                    print(f'TIER0_CPU_VTABLE constructor={target:#x} instruction={ins.address:#x} table={slot:#x} entries={[hex(value-base) for value in entries]}')
                    for index in (1, 3, 5, 7):
                        show_function(entries[index] - base, f'actual-cpu-vtable{slot:#x}+{index*8:#x}')
    cpu_slots = {slot: name for slot, name in imports.items() if any(term in name for term in (
        'LogicalProcessor', 'ActiveProcessor', 'SystemInfo', 'Affinity', 'ProcessorNumber'))}
    print(f'TIER0_CPU_IMPORTS {cpu_slots!r}')
    for low, high, _ in functions:
        raw = pe.get_data(low, high - low)
        if not any(op in raw for op in (b'\xff\x15', b'\xff\x25')):
            continue
        for ins in md.disasm(raw, low):
            if not (ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP)):
                continue
            for operand in ins.operands:
                if operand.type == cs.x86.X86_OP_MEM and operand.mem.base == cs.x86.X86_REG_RIP:
                    slot = ins.address + ins.size + operand.mem.disp
                    if slot in cpu_slots:
                        print(f'TIER0_CPU_IMPORT_XREF instruction={ins.address:#x} root={chain_root((low, high, _)):#x} name={cpu_slots[slot]}')
                        show_function(low, 'actual-cpu-topology-api-consumer')
    print(f'TIER0_SUMMARY threadpool-types={type_count} vtables={table_count}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True)
    args = parser.parse_args()
    scratch = args.scratch.resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    archive = scratch / 'depotdownloader.zip'
    digest, count = hashlib.sha256(), 0
    with urllib.request.urlopen(TOOL_URL, timeout=45) as source, archive.open('wb') as dest:
        while chunk := source.read(1 << 20):
            count += len(chunk)
            assert count <= 40 << 20, 'tool download exceeds bound'
            digest.update(chunk)
            dest.write(chunk)
    assert digest.hexdigest() == TOOL_SHA256, 'official tool release hash mismatch'
    with zipfile.ZipFile(archive) as package:
        assert package.getinfo('DepotDownloader').file_size <= 128 << 20
        tool = scratch / 'DepotDownloader'
        tool.write_bytes(package.read('DepotDownloader'))
    tool.chmod(0o700)
    filelist = scratch / 'filelist.txt'
    filelist.write_text(FILE + '\n' + TIER0 + '\n')
    content = scratch / 'content'
    command = [str(tool), '-app', str(APP), '-depot', str(DEPOT), '-manifest', str(MANIFEST),
               '-os', 'windows', '-osarch', '64', '-filelist', str(filelist),
               '-dir', str(content), '-validate', '-max-downloads', '4']
    environment = {k: v for k, v in os.environ.items()
                   if k not in ('GH_TOKEN', 'GITHUB_TOKEN', 'STEAM_USERNAME', 'STEAM_PASSWORD')}
    log = scratch / 'anonymous.log'
    print(f'REQUEST anonymous-only app={APP} depot={DEPOT} manifest={MANIFEST} file={FILE}', flush=True)
    with log.open('w') as output:
        process = subprocess.Popen(command, cwd=scratch, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            status = process.wait(timeout=240)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            report_log(log)
            raise SystemExit('UNAVAILABLE: anonymous connection/content deadline; no login or protection bypass attempted')
    report_log(log)
    candidates = [p for p in content.rglob('client.dll') if p.as_posix().endswith(FILE)] if content.exists() else []
    if status or len(candidates) != 1:
        raise SystemExit(f'UNAVAILABLE: official anonymous retrieval exit={status}, exact-file-count={len(candidates)}')
    assert f'Manifest {MANIFEST} ' in log.read_text(errors='replace'), 'requested manifest not confirmed by downloader'
    assert candidates[0].stat().st_size <= 64 << 20, 'client PE exceeds read bound'
    image = candidates[0].read_bytes()
    pe = pefile.PE(data=image)
    assert pe.FILE_HEADER.Machine == 0x8664, 'expected official Windows x64 client'
    identity = xxhash.xxh3_64_intdigest(b'client.dll') ^ (
        (pe.OPTIONAL_HEADER.SizeOfImage << 32) | pe.FILE_HEADER.TimeDateStamp)
    print(f'OBSERVED client.dll bytes={len(image)} expected-audit-bytes={EXPECTED_BYTES} sha256={hashlib.sha256(image).hexdigest()} '
          f'identity={identity:016x} timestamp={pe.FILE_HEADER.TimeDateStamp:#x} '
          f'image-size={pe.OPTIONAL_HEADER.SizeOfImage:#x}')
    assert f'{identity:016x}' == EXPECTED_ID, ('recorded FEX module identity mismatch', f'{identity:016x}')
    if len(image) != EXPECTED_BYTES:
        print('STALE_AUDIT_SIZE: startup cached-audit size differs from official post-update file; '
              'exact requested manifest and runtime loaded-module header identity both match')
    imports = {}
    for descriptor in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        for imported in descriptor.imports:
            imports[imported.address - pe.OPTIONAL_HEADER.ImageBase] = (
                descriptor.dll.decode() + '!' + (imported.name.decode() if imported.name else '#' + str(imported.ordinal)))
    target = 0x457b
    functions = [(r.struct.BeginAddress, r.struct.EndAddress, r.struct.UnwindData)
                 for r in getattr(pe, 'DIRECTORY_ENTRY_EXCEPTION', [])]
    matches = [r for r in functions if r[0] <= target < r[1]]
    assert len(matches) == 1, ('unproven client function boundary', matches)
    begin, end, unwind = matches[0]
    print(f'FUNCTION target={target:#x} begin={begin:#x} end={end:#x} unwind={unwind:#x}')
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    stop = min(end, begin + 8192)
    if target >= stop:
        print('NOTE function exceeds bounded full-function window; selected target window only')
        begin = max(begin, target - 128)
        stop = min(end, target + 384)
    for ins in md.disasm(pe.get_data(begin, stop - begin), begin):
        print(f'CODE {ins.address:#x}: {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}')
        if ins.group(cs.CS_GRP_CALL) and ins.address + ins.size == target:
            print('CALLER_RETURN validated instruction ends at recorded client return RVA')
        for operand in ins.operands:
            if operand.type != cs.x86.X86_OP_MEM or operand.mem.base != cs.x86.X86_REG_RIP:
                continue
            rva = ins.address + ins.size + operand.mem.disp
            if rva in imports:
                print(f'IMPORT instruction={ins.address:#x} slot={rva:#x} name={imports[rva]}')
            if ins.mnemonic == 'lea':
                raw = pe.get_data(rva, 256)
                for encoding in ('ascii', 'utf-16le'):
                    try:
                        text = raw.decode(encoding).split('\0', 1)[0]
                    except UnicodeError:
                        continue
                    if len(text) >= 5 and all(c.isprintable() for c in text):
                        print(f'STRING instruction={ins.address:#x} rva={rva:#x} encoding={encoding} value={text[:160]!r}')
    # Validate direct-call candidates against real instruction boundaries from
    # the containing x64 unwind range. Never label a raw E8 byte as a call.
    functions.sort()
    starts = [r[0] for r in functions]
    callers = {}
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        raw = section.get_data()
        position = -1
        while True:
            position = raw.find(b'\xe8', position + 1)
            if position < 0 or position + 5 > len(raw):
                break
            address = section.VirtualAddress + position
            displacement = struct.unpack_from('<i', raw, position + 1)[0]
            if address + 5 + displacement != matches[0][0]:
                continue
            index = bisect.bisect_right(starts, address) - 1
            if index < 0:
                continue
            low, high, _ = functions[index]
            if not low <= address < high or address - low > 16384:
                continue
            instructions = list(md.disasm(pe.get_data(low, min(high, low + 16384) - low), low))
            if not any(i.address == address and i.group(cs.CS_GRP_CALL) and i.size == 5 for i in instructions):
                continue
            print(f'CALLER_XREF instruction={address:#x} function={low:#x}..{high:#x} target={matches[0][0]:#x}')
            callers[low] = (high, instructions)
            assert len(callers) <= 16, 'caller inspection exceeds bound'
    for low, (high, instructions) in callers.items():
        print(f'CALLER_FUNCTION begin={low:#x} end={high:#x}')
        for ins in instructions[:1500]:
            print(f'CALLER_CODE {ins.address:#x}: {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}')
            for operand in ins.operands:
                if operand.type == cs.x86.X86_OP_MEM and operand.mem.base == cs.x86.X86_REG_RIP:
                    slot = ins.address + ins.size + operand.mem.disp
                    if slot in imports:
                        print(f'CALLER_IMPORT instruction={ins.address:#x} slot={slot:#x} name={imports[slot]}')
    # One additional upstream level: identify a direct call, a RIP-relative
    # function-address load, or a data-table pointer to the known caller.
    # Every code reference is validated from the containing unwind range.
    upstream_targets = set(callers) | {0x14a7c0}
    print(f'UPSTREAM_SCAN targets={sorted(upstream_targets)} source=ffd80496-plus-unwind-validation')
    for destination in upstream_targets:
        ix = bisect.bisect_left(starts, destination)
        for low, high, unwind_rva in functions[max(0, ix - 2):ix + 3]:
            raw_unwind = pe.get_data(unwind_rva, 48)
            print(f'UPSTREAM_UNWIND begin={low:#x} end={high:#x} unwind={unwind_rva:#x} raw={raw_unwind.hex()} flags={raw_unwind[0] >> 3}')
        for symbol in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', []):
            if symbol.address == destination:
                print(f'UPSTREAM_EXPORT target={destination:#x} name={symbol.name!r} ordinal={symbol.ordinal}')
    load_config = getattr(getattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG', None), 'struct', None)
    if load_config is not None:
        cf_table = getattr(load_config, 'GuardCFFunctionTable', 0)
        cf_count = getattr(load_config, 'GuardCFFunctionCount', 0)
        cf_flags = getattr(load_config, 'GuardFlags', 0)
        print(f'UPSTREAM_CFG table={cf_table:#x} count={cf_count} flags={cf_flags:#x}')
        stride = 4 + ((cf_flags >> 28) & 15)
        if cf_table and cf_count <= 1000000:
            table_data = pe.get_data(cf_table - pe.OPTIONAL_HEADER.ImageBase, cf_count * stride)
            fid = [struct.unpack_from('<I', table_data, i * stride)[0] for i in range(cf_count)]
            for destination in upstream_targets:
                ix = bisect.bisect_left(fid, destination)
                print(f'UPSTREAM_CFG_NEAR target={destination:#x} entries={[hex(x) for x in fid[max(0, ix - 2):ix + 3]]}')
    pointer_slots = {}
    raw_refs = 0
    for section in pe.sections:
        if section.Characteristics & 0x20000000:
            continue
        raw = section.get_data()
        for destination in upstream_targets:
            rva_bytes = struct.pack('<I', destination)
            position = -1
            while True:
                position = raw.find(rva_bytes, position + 1)
                if position < 0:
                    break
                raw_refs += 1
                if raw_refs <= 24:
                    slot = section.VirtualAddress + position
                    print(f'UPSTREAM_RAW_RVA slot={slot:#x} target={destination:#x} neighbors={raw[max(0, position - 16):position + 32].hex()}')
            value = struct.pack('<Q', pe.OPTIONAL_HEADER.ImageBase + destination)
            position = -1
            while True:
                position = raw.find(value, position + 1)
                if position < 0:
                    break
                slot = section.VirtualAddress + position
                pointer_slots[slot] = destination
                print(f'UPSTREAM_DATA_POINTER slot={slot:#x} target={destination:#x} neighbors={raw[max(0, position - 128):position + 128].hex()}')
                assert len(pointer_slots) <= 32, 'upstream data-reference inspection exceeds bound'
    upstream_ranges = {}
    def validated_reference(address, destination, kind):
        index = bisect.bisect_right(starts, address) - 1
        if index < 0:
            return
        low, high, _ = functions[index]
        print(f'UPSTREAM_CANDIDATE instruction={address:#x} kind={kind} destination={destination:#x} unwind={low:#x}..{high:#x}')
        if not low <= address < high:
            following = functions[index + 1] if index + 1 < len(functions) else None
            gap_end = min(following[0] if following else address + 256, address + 256)
            gap_begin = max(high, address - 256)
            print(f'UPSTREAM_GAP candidate={address:#x} preceding={low:#x}..{high:#x} following={following!r} window={gap_begin:#x}..{gap_end:#x}')
            if 0 < gap_end - gap_begin <= 1024:
                for instruction in md.disasm(pe.get_data(gap_begin, gap_end - gap_begin), gap_begin):
                    print(f'GAP_CODE {instruction.address:#x}: {instruction.bytes.hex()} {instruction.mnemonic} {instruction.op_str}')
                    for operand in instruction.operands:
                        if operand.type == cs.x86.X86_OP_MEM and operand.mem.base == cs.x86.X86_REG_RIP:
                            slot = instruction.address + instruction.size + operand.mem.disp
                            if slot in imports:
                                print(f'GAP_IMPORT instruction={instruction.address:#x} slot={slot:#x} name={imports[slot]}')
            return
        if address - low > 524288:
            return
        instructions = list(md.disasm(pe.get_data(low, min(high, max(address + 512, low + 32768)) - low), low))
        instruction = next((i for i in instructions if i.address == address), None)
        if instruction is None:
            return
        if kind == 'branch':
            valid = instruction.group(cs.CS_GRP_CALL) or instruction.group(cs.CS_GRP_JUMP)
            valid = valid and any(o.type == cs.x86.X86_OP_IMM and o.imm == destination for o in instruction.operands)
        else:
            valid = any(o.type == cs.x86.X86_OP_MEM and o.mem.base == cs.x86.X86_REG_RIP
                        and instruction.address + instruction.size + o.mem.disp == destination for o in instruction.operands)
        if not valid:
            return
        print(f'UPSTREAM_XREF instruction={address:#x} kind={kind} destination={destination:#x} function={low:#x}..{high:#x}')
        upstream_ranges[low] = (high, instructions if high - low <= 32768 else [i for i in instructions if abs(i.address - address) <= 512])
        assert len(upstream_ranges) <= 24, 'upstream function inspection exceeds bound'
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        raw = section.get_data()
        for opcode in (0xe8, 0xe9):
            position = -1
            while True:
                position = raw.find(bytes([opcode]), position + 1)
                if position < 0 or position + 5 > len(raw):
                    break
                address = section.VirtualAddress + position
                destination = address + 5 + struct.unpack_from('<i', raw, position + 1)[0]
                if destination in upstream_targets:
                    validated_reference(address, destination, 'branch')
        # LEA reg,[RIP+disp32] takes an address without calling it. Native
        # callback and vtable assignment sites often use this exact encoding.
        position = -1
        while True:
            position = raw.find(b'\x8d', position + 1)
            if position < 0 or position + 6 > len(raw):
                break
            if raw[position + 1] & 0xc7 != 0x05:
                continue
            destination = section.VirtualAddress + position + 6 + struct.unpack_from('<i', raw, position + 2)[0]
            near_table = any(slot - 256 <= destination <= slot and (slot - destination) % 8 == 0 for slot in pointer_slots)
            if destination not in upstream_targets and not near_table:
                continue
            start = position - 1 if position and 0x40 <= raw[position - 1] <= 0x4f else position
            validated_reference(section.VirtualAddress + start, destination, 'rip-address')
    print(f'UPSTREAM_SUMMARY validated-functions={len(upstream_ranges)} absolute-pointer-slots={len(pointer_slots)} raw-rva-words={raw_refs}')
    for low, (high, instructions) in upstream_ranges.items():
        urva = next(r[2] for r in functions if r[0] == low)
        print(f'UPSTREAM_FUNCTION begin={low:#x} end={high:#x} unwind={urva:#x} raw-unwind={pe.get_data(urva, 48).hex()}')
        for ins in instructions[:2200]:
            print(f'UPSTREAM_CODE {ins.address:#x}: {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}')
            for operand in ins.operands:
                if operand.type == cs.x86.X86_OP_MEM and operand.mem.base == cs.x86.X86_REG_RIP:
                    slot = ins.address + ins.size + operand.mem.disp
                    if slot in imports:
                        print(f'UPSTREAM_IMPORT instruction={ins.address:#x} slot={slot:#x} name={imports[slot]}')
                    if ins.mnemonic == 'lea':
                        raw_text = pe.get_data(slot, 128).split(b'\0', 1)[0]
                        if 4 <= len(raw_text) <= 127 and all(32 <= b < 127 for b in raw_text):
                            print(f'UPSTREAM_STRING instruction={ins.address:#x} slot={slot:#x} value={raw_text.decode()!r}')
    print(f'CLIENT_JOB_NAME rva=0x1abc088 raw={pe.get_data(0x1abc088, 128).hex()}')
    locator_ptr = struct.unpack('<Q', pe.get_data(0x1abc488 - 8, 8))[0]
    locator_rva = locator_ptr - pe.OPTIONAL_HEADER.ImageBase
    if 0 <= locator_rva < pe.OPTIONAL_HEADER.SizeOfImage:
        fields = struct.unpack('<6I', pe.get_data(locator_rva, 24))
        print(f'CLIENT_JOB_RTTI vtable=0x1abc488 locator={locator_rva:#x} fields={fields}')
        if fields[0] == 1 and fields[5] == locator_rva:
            print(f'CLIENT_JOB_TYPE descriptor={fields[3]:#x} name={pe.get_data(fields[3] + 16, 256).split(bytes([0]),1)[0]!r}')
    tier0_candidates = [p for p in content.rglob('tier0.dll') if p.as_posix().endswith(TIER0)]
    assert len(tier0_candidates) == 1, 'exact official tier0 file missing'
    inspect_tier0(tier0_candidates[0])
    print('PASS exact official-manifest client content inspected without execution; purpose requires disassembly interpretation')


if __name__ == '__main__':
    main()
