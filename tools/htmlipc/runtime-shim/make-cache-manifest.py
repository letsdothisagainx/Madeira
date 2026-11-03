#!/usr/bin/env python3
"""Trusted host staging gate: verify official cache PE machines/full hashes.

Creates the provider's completion marker only after all four streaming checks
pass. It does not edit the PEs or any official AMD64 files.
"""
from pathlib import Path
import argparse,hashlib,os,struct
here=Path(__file__).resolve().parent
parser=argparse.ArgumentParser()
parser.add_argument('cache',type=Path,help='staged SteamRoot/bin/cef/cef.win7')
args=parser.parse_args()
expected=(here/'cache-contract.txt').read_bytes().replace(b'\r\n',b'\n')
lines=expected.decode('ascii').splitlines()
assert lines[0]=='MadeiraHtmlIPC-I386-Cache-v2'
marker=args.cache/'.madeira-cache-verified-v1'
# A previous completed preparation must not attest a failed restage.
marker.unlink(missing_ok=True)
for line in lines[1:]:
    name,machine_text,digest=line.split()
    with (args.cache/name).open('rb') as file:
        dos=file.read(64)
        if len(dos)!=64 or dos[:2]!=b'MZ':raise SystemExit(f'Invalid DOS header: {name}')
        offset=struct.unpack_from('<I',dos,60)[0]
        if offset>1024*1024:raise SystemExit(f'Invalid PE offset: {name}')
        file.seek(offset);nt=file.read(6)
        if len(nt)!=6 or nt[:4]!=b'PE\0\0' or struct.unpack_from('<H',nt,4)[0]!=int(machine_text,16):
            raise SystemExit(f'Wrong PE machine: {name}')
        file.seek(0);actual=hashlib.sha256()
        while block:=file.read(1024*1024):actual.update(block)
        if actual.hexdigest()!=digest:raise SystemExit(f'Wrong full SHA-256: {name}')
    print(f'PASS {name}: I386 and full SHA-256')
temporary=marker.with_name(marker.name+'.tmp')
with temporary.open('wb') as file:
    file.write(expected);file.flush();os.fsync(file.fileno())
os.replace(temporary,marker)
print('PASS trusted cache preparation marker written atomically')
