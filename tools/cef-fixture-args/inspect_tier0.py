#!/usr/bin/env python3
"""Verify the pinned original and record its actual CreateSimpleProcess route."""
from pathlib import Path
import argparse,hashlib,json
import capstone,pefile
here=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__);p.add_argument('tier0',type=Path)
a=p.parse_args();raw=a.tier0.read_bytes()
expected='8559e6bd32eb3fddd95079633272866deb292211ec4f7e69aeb0ec48fdafef72'
assert hashlib.sha256(raw).hexdigest()==expected
pe=pefile.PE(data=raw);assert pe.FILE_HEADER.Machine==0x8664
exports={e.name.decode():e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
imports={e.address-pe.OPTIONAL_HEADER.ImageBase:(d.dll.decode(),e.name.decode() if e.name else None)
         for d in pe.DIRECTORY_ENTRY_IMPORT for e in d.imports}
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
def function(name):
    start=exports[name];end=next(e.struct.EndAddress for e in pe.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress==start)
    return list(cs.disasm(pe.get_data(start,end-start),start))
simple=function('CreateSimpleProcess');utf8=function('CreateProcessUTF8')
calls=[i for i in simple if i.mnemonic=='call' and len(i.operands)==1 and i.operands[0].type==capstone.x86.X86_OP_IMM
       and i.operands[0].imm==exports['CreateProcessUTF8']]
assert len(calls)==1
wide=[];ansi=[]
for i in utf8:
    if i.mnemonic!='call' or len(i.operands)!=1:continue
    op=i.operands[0]
    if op.type!=capstone.x86.X86_OP_MEM or op.mem.base!=capstone.x86.X86_REG_RIP:continue
    target=i.address+i.size+op.mem.disp
    if imports.get(target)==('KERNEL32.dll','CreateProcessW'):wide.append((i,target))
    if imports.get(target)==('KERNEL32.dll','CreateProcessA'):ansi.append((i,target))
assert len(wide)==1 and not ansi
call,slot=wide[0]
report={'scope':'Static disassembly of exact original; no PE execution or runtime success asserted',
    'tier0_sha256':expected,'file_size':len(raw),'machine':hex(pe.FILE_HEADER.Machine),
    'route':[{'name':'CreateSimpleProcess','rva':hex(exports['CreateSimpleProcess']),
              'call_rva':hex(calls[0].address),'call_bytes':bytes(calls[0].bytes).hex()},
             {'name':'CreateProcessUTF8','rva':hex(exports['CreateProcessUTF8']),
              'call_rva':hex(call.address),'call_bytes':bytes(call.bytes).hex()},
             {'name':'KERNEL32.dll!CreateProcessW','iat_rva':hex(slot)}],
    'create_process_a_calls_in_utf8':0}
(here/'tier0-route.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
