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

APP, DEPOT, MANIFEST = 730, 2347771, 6054210037651104742
FILE = 'game/csgo/bin/win64/client.dll'
EXPECTED_BYTES = 39120536
EXPECTED_ID = 'eb5eed5d42f84131'
TOOL_URL = ('https://github.com/SteamRE/DepotDownloader/releases/download/'
            'DepotDownloader_3.4.0/DepotDownloader-linux-x64.zip')
TOOL_SHA256 = 'a999dec66b4850fc961bd50366696d23c2d0fad7b18790e6a5647b2f19097a53'


def report_log(path):
    lines = path.read_text(errors='replace').splitlines()
    useful = [line for line in lines if re.search(
        r'(?i)anonymous|connect|fail|error|denied|depot|manifest|download|license', line)]
    for line in useful[-35:]:
        print('STEAM ' + re.sub(r'https?://\S+', '[url]', line)[:500])


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
    filelist.write_text(FILE + '\n')
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
    print('PASS exact official-manifest client content inspected without execution; purpose requires disassembly interpretation')


if __name__ == '__main__':
    main()
