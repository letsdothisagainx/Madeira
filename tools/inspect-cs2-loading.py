#!/usr/bin/env python3
"""Read-only, bounded official-image inspection for the 2026-11-20 loading run.

Never execute/modify Valve code or claim a saved guest RIP is current execution.
"""
import argparse
import bisect
import hashlib
from pathlib import Path
import re
import struct
import subprocess
import urllib.request
import zipfile

import capstone
import pefile
import xxhash

TOOL_URL = ('https://github.com/SteamRE/DepotDownloader/releases/download/'
            'DepotDownloader_3.4.0/DepotDownloader-linux-x64.zip')
TOOL_SHA = 'a999dec66b4850fc961bd50366696d23c2d0fad7b18790e6a5647b2f19097a53'
QUERIES = {
    'tier0.dll': ('8f2d32d37c93635a', [0x28fa33, 0xc4973, 0x215faa]),
    'embree3.dll': ('bfdf794d989662f5', [0x2aa1e, 0x2aa54]),
    'networksystem.dll': ('942d2ad34c245d8a', [0x1c5429, 0x1c5430]),
    'soundsystem.dll': ('d33a17eb78d1efeb', [0x33c9fe, 0x33dd44, 0x33dd16]),
}


def inspect(path, expected, queries):
    image = path.read_bytes()
    assert len(image) <= 96 << 20, 'image exceeds inspection bound'
    pe = pefile.PE(data=image)
    base = pe.OPTIONAL_HEADER.ImageBase
    identity = xxhash.xxh3_64_intdigest(path.name.encode()) ^ (
        (pe.OPTIONAL_HEADER.SizeOfImage << 32) | pe.FILE_HEADER.TimeDateStamp)
    print(f'IMAGE name={path.name} bytes={len(image)} sha256={hashlib.sha256(image).hexdigest()} '
          f'identity={identity:016x} timestamp={pe.FILE_HEADER.TimeDateStamp:#x} '
          f'image-size={pe.OPTIONAL_HEADER.SizeOfImage:#x}', flush=True)
    assert pe.FILE_HEADER.Machine == 0x8664 and f'{identity:016x}' == expected, 'runtime image identity mismatch'
    exports = {s.address: (s.name or b'').decode(errors='replace')
               for s in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])}
    imports = {i.address - base: d.dll.decode() + '!' + (i.name.decode() if i.name else str(i.ordinal))
               for d in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []) for i in d.imports}
    ranges = [(r.struct.BeginAddress, r.struct.EndAddress, r.struct.UnwindData)
              for r in getattr(pe, 'DIRECTORY_ENTRY_EXCEPTION', [])]
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    for target in queries:
        records = [r for r in ranges if r[0] <= target < r[1]]
        if not records:
            print(f'UNRESOLVED {path.name}+{target:#x}: no containing unwind range; no guessed boundary')
            continue
        begin, end, unwind = records[0]
        print(f'QUERY {path.name}+{target:#x} range={begin:#x}..{end:#x} '
              f'unwind={unwind:#x} export={exports.get(begin, "unexported")}', flush=True)
        # Decode from the real entry, not an arbitrary middle byte. Large
        # functions decline rather than emit an unbounded dump.
        assert end - begin <= 256 << 10, 'function exceeds bounded decode'
        instructions = list(decoder.disasm(pe.get_data(begin, end - begin), begin))
        positions = [i.address for i in instructions]
        at = bisect.bisect_left(positions, target)
        assert at < len(instructions) and instructions[at].address == target, 'target is not an instruction boundary'
        for i in instructions[max(0, at - 32):at + 49]:
            detail = ''
            for operand in i.operands:
                if operand.type == capstone.x86.X86_OP_MEM and operand.mem.base == capstone.x86.X86_REG_RIP:
                    dest = i.address + i.size + operand.mem.disp
                    if dest in imports:
                        detail += ' import=' + imports[dest]
                    elif i.mnemonic == 'lea':
                        raw = pe.get_data(dest, 160).split(b'\0', 1)[0]
                        if raw and all(32 <= b < 127 for b in raw):
                            detail += ' string=' + repr(raw.decode())
            print(f'  {i.address:#010x} {i.bytes.hex():24s} {i.mnemonic:9s} {i.op_str}{detail}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--existing', action='store_true')
    args = parser.parse_args()
    args.scratch.mkdir(parents=True, exist_ok=True)
    if not args.existing:
        archive = args.scratch / 'tool.zip'
        with urllib.request.urlopen(TOOL_URL, timeout=30) as response:
            data = response.read((40 << 20) + 1)
        assert len(data) <= 40 << 20 and hashlib.sha256(data).hexdigest() == TOOL_SHA
        archive.write_bytes(data)
        with zipfile.ZipFile(archive) as z:
            z.extract('DepotDownloader', args.scratch)
        tool = args.scratch / 'DepotDownloader'
        tool.chmod(0o700)
        listing = args.scratch / 'files.txt'
        listing.write_text(''.join('game/bin/win64/' + name + '\n' for name in QUERIES))
        log = args.scratch / 'download.log'
        with log.open('w') as out:
            # The earlier manifest is no longer available anonymously. Fetch
            # the current public manifest, but accept each image only if its
            # independently recorded runtime identity matches this capture.
            result = subprocess.run([str(tool), '-app', '730', '-depot', '2347771',
                                     '-filelist', str(listing), '-dir', str(args.scratch / 'images'),
                                     '-max-downloads', '2'], stdout=out, stderr=subprocess.STDOUT, timeout=150)
        for line in log.read_text(errors='replace').splitlines()[-30:]:
            print('STEAM ' + re.sub(r'https?://\S+', '[url]', line)[:400])
        assert result.returncode == 0, 'anonymous retrieval failed; no game-image execution attempted'
    for name, (identity, queries) in QUERIES.items():
        inspect(args.scratch / 'images/game/bin/win64' / name, identity, queries)


if __name__ == '__main__':
    main()
