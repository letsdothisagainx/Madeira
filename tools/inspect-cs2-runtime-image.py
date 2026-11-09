import sys,struct,hashlib,zipfile,json
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
u16=lambda b,a:struct.unpack_from('<H',b,a)[0]
u32=lambda b,a:struct.unpack_from('<I',b,a)[0]
u64=lambda b,a:struct.unpack_from('<Q',b,a)[0]
ipa=Path(sys.argv[1]); z=zipfile.ZipFile(ipa)
wanted=[n for n in z.namelist() if '/arm64ec-windows/' in n and n.rsplit('/',1)[-1].lower() in ('ntdll.dll','xtajit64.dll','libarm64ecfex.dll')]
assert wanted, 'exact ARM64EC packaged images missing'
for name in wanted:
 b=z.read(name); pe=u32(b,60); opt=pe+24; n=u16(b,pe+6); st=opt+u16(b,pe+20)
 size=u32(b,opt+56); image=bytearray(size); image[:min(size,u32(b,opt+60))]=b[:min(size,u32(b,opt+60))]
 sections=[]
 for i in range(n):
  a=st+i*40; label=b[a:a+8].split(b'\0')[0].decode(errors='replace'); vs,va,raw,off=struct.unpack_from('<4I',b,a+8)
  assert va<=size and vs<=size-va
  copy=min(raw,size-va,len(b)-off); image[va:va+copy]=b[off:off+copy]
  sections.append({'name':label,'rva':hex(va),'virtual_bytes':hex(vs),'raw_bytes':hex(raw),'flags':hex(u32(b,a+36))})
 exports=[]; er=u32(b,opt+112); en=u32(b,opt+116)
 if er and en>=40:
  functions,names,ordinals=[u32(image,er+a) for a in (28,32,36)]
  for i in range(u32(image,er+24)):
   r=u32(image,names+4*i); end=image.index(0,r); text=image[r:end].decode(errors='replace'); ordinal=u16(image,ordinals+2*i)
   exports.append((u32(image,functions+4*ordinal),text))
 exports.sort()
 debug=[]; dr=u32(b,opt+112+6*8); dn=u32(b,opt+116+6*8)
 for a in range(dr,dr+dn,28):
  if a+28>size:break
  if u32(image,a+12)==2:
   r=u32(image,a+20); length=u32(image,a+16); data=bytes(image[r:r+length])
   if data[:4]==b'RSDS': debug.append({'guid_raw':data[4:20].hex(),'age':u32(data,20),'pdb':data[24:].split(b'\0')[0].decode(errors='replace').replace('\\','/').rsplit('/',1)[-1]})
 print('IMAGE',json.dumps({'member':name,'sha256':hashlib.sha256(b).hexdigest(),'file_bytes':len(b),'machine':hex(u16(b,pe+4)),'image_bytes':hex(size),'preferred':hex(u64(b,opt+24)),'debug':debug,'sections':sections}))
 ranges=[(0x69c40,0x69e20),(0x6a380,0x6a600)] if name.lower().endswith('/ntdll.dll') else [(0x14560,0x14690),(0x147d0,0x14880)]
 targets=[0xe0a58,0xe1e40] if name.lower().endswith('/ntdll.dll') else [0x3bd288]
 for lo,hi in ranges:
  if hi>size: print('OUTSIDE',hex(lo),hex(hi)); continue
  nearby=[(hex(r),t) for r,t in exports if abs(r-lo)<0x600 or abs(r-hi)<0x600]
  print('EXPORTS_NEAR',hex(lo),json.dumps(nearby[:32]))
  print('RAW',hex(lo),bytes(image[lo:hi]).hex())
  md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
  for ins in md.disasm(bytes(image[lo:hi]),lo):print(f'{ins.address:08x}: {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}')
 for target in targets:
  nearby=sorted(exports,key=lambda p:abs(p[0]-target))[:5]
  print('DATA_TARGET',hex(target),'exports',json.dumps([(hex(r),t) for r,t in nearby]),'bytes',bytes(image[max(0,target-32):target+96]).hex())
 print('EXPORT_HOT_NAMES',json.dumps([(hex(r),t) for r,t in exports if any(q in t.lower() for q in ('queryperformance','entercritical','leavecritical','debug','dbg','trace'))][:60]))
