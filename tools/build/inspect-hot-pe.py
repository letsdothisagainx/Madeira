#!/usr/bin/env python3
"""Read-only exact packaged PE exports/COFF symbols and native bytes."""
from pathlib import Path
import argparse,hashlib,struct,subprocess,shutil
import capstone
p=argparse.ArgumentParser();p.add_argument('image',type=Path);p.add_argument('--rva',action='append',type=lambda x:int(x,0),default=[]);p.add_argument('--data-rva',action='append',type=lambda x:int(x,0),default=[]);p.add_argument('--arm64',action='store_true');p.add_argument('--context',type=int,default=128);a=p.parse_args();d=a.image.read_bytes()
def read(fmt,o):
 assert 0<=o<=len(d)-struct.calcsize(fmt)
 return struct.unpack_from(fmt,d,o)
assert d[:2]==b'MZ';nt,=read('<I',0x3c);assert d[nt:nt+4]==b'PE\0\0';machine,n,stamp,sym,nsym,opt,_=read('<HHIIIHH',nt+4);magic,=read('<H',nt+24);size,=read('<I',nt+24+56);sections=[]
for i in range(n):
 o=nt+24+opt+i*40;name=d[o:o+8].rstrip(b'\0').decode(errors='replace');vs,rva,z,raw=read('<IIII',o+8);flags,=read('<I',o+36);sections.append((name,rva,max(vs,z),raw,z,flags))
def offset(rva,length=1):
 for name,b,vs,raw,z,flags in sections:
  if b<=rva and rva-b+length<=z:return raw+rva-b
 raise ValueError('not-file-backed RVA '+hex(rva))
def raw(rva,length):return d[offset(rva,length):offset(rva,length)+length]
def string(rva):
 o=offset(rva);end=d.find(b'\0',o,min(len(d),o+8192));assert end>=0;return d[o:end].decode(errors='replace')
rows=[];functions=[];exports=[]
if sym and nsym:
 strings=sym+nsym*18;string_size,=read('<I',strings);assert strings+string_size<=len(d);i=0
 while i<nsym:
  o=sym+i*18;name=d[o:o+8]
  if name[:4]==bytes(4):
   j=struct.unpack_from('<I',name,4)[0];end=d.find(b'\0',strings+j,strings+string_size);assert end>=0;name=d[strings+j:end].decode(errors='replace')
  else:name=name.rstrip(b'\0').decode(errors='replace')
  value,sec,kind,storage,aux=read('<IhHBB',o+8)
  if 0<sec<=n:
   item=(sections[sec-1][1]+value,name,sec,kind);rows.append(item)
   if kind&0x20 and sections[sec-1][5]&0x20000000:functions.append(item)
  i+=aux+1
directory=nt+24+(112 if magic==0x20b else 96);er,esz=read('<II',directory)
if er:
 exp=read('<IIHHIIIIIII',offset(er,40));base,count,names,ft,ntab,otab=exp[5:]
 assert count<100000 and names<100000
 for i in range(names):
  nr,=read('<I',offset(ntab+i*4,4));ordinal,=read('<H',offset(otab+i*2,2));assert ordinal<count;fr,=read('<I',offset(ft+ordinal*4,4))
  if fr and not er<=fr<er+esz:exports.append((fr,string(nr),0,0x20))
redirected=[]
if a.arm64 and machine in (0x8664,0xa641):
 lc,lcs=read('<II',directory+10*8)
 if lc and lcs>=0xd0:
  pointer,=read('<Q',offset(lc+0xc8,8));preferred,=read('<Q',nt+24+24)
  if pointer>=preferred and pointer-preferred<size:
   meta=pointer-preferred;red,count=read('<I',offset(meta+16,4))[0],read('<I',offset(meta+52,4))[0];assert count<100000
   table=dict(read('<II',offset(red+i*8,8)) for i in range(count))
   redirected=[(table.get(fr,fr),name,sec,kind) for fr,name,sec,kind in exports]
rows.sort();functions.sort();exports.sort();redirected.sort()
print(f'IMAGE {a.image.name} sha256={hashlib.sha256(d).hexdigest()} bytes={len(d):#x} machine={machine:04x} image-size={size:#x} timestamp={stamp:08x} coff-symbols={nsym} named-exports={len(exports)}')
cs=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN) if a.arm64 else capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32 if machine==0x14c else capstone.CS_MODE_64);cs.skipdata=True
for target in a.rva:
 print(f'CODE RVA {target:#x}')
 for label,choices in [('COFF-function',functions),('nearest-export',exports),('native-redirected-export',redirected)]:
  before=[x for x in choices if x[0]<=target]
  if before:
   start,name,_,_=before[-1];following=next((x[0] for x in choices if x[0]>start),None);print(f'  {label}={name} start={start:#x} offset={target-start:#x} next={hex(following) if following else "unknown"}')
 begin=max(0,target-a.context);begin=begin&~3 if a.arm64 else begin
 for x in cs.disasm(raw(begin,a.context*2),begin):print(f'  {"=>" if x.address==target else "  "} {x.address:#x} {x.bytes.hex()} {x.mnemonic} {x.op_str}')
for target in a.data_rva:
 print(f'DATA RVA {target:#x}')
 choices=[x for x in rows if x[0]<=target and not x[1].startswith('.') and not sections[x[2]-1][5]&0x20000000 and sections[x[2]-1][1]<=target<sections[x[2]-1][1]+sections[x[2]-1][2]]
 for start,name,sec,kind in reversed(choices[-8:]):print(f'  COFF-data={name} start={start:#x} offset={target-start:#x} section={sections[sec-1][0]}')
 try:print('  bytes='+raw(target,32).hex(' '))
 except ValueError:print('  no-raw-bytes (zero-filled virtual data)')
