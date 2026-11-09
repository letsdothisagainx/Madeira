import io,json,plistlib,struct,sys,tarfile,zipfile
from pathlib import Path
archive=zipfile.ZipFile(Path(sys.argv[1]))
info=plistlib.loads(archive.read('Payload/Madeira.app/Info.plist'))
assert info['MadeiraBuild'].endswith(' source=4b41f1dd7603612e1596ac885d0b883fa601cf26')
print('BUILD',info['MadeiraBuild'])
for farm in ('aarch64-windows','arm64ec-windows','i386-windows'):
 prefix='Payload/Madeira.app/'+farm+'/'
 entries=[n for n in archive.namelist() if n.startswith(prefix) and n.lower().endswith('.exe')]
 print('EXECUTABLES',farm,'count',len(entries))
 for name in sorted(entries):
  data=archive.read(name);pe=struct.unpack_from('<I',data,0x3c)[0]
  assert data[:2]==b'MZ' and data[pe:pe+4]==b'PE\0\0'
  machine=struct.unpack_from('<H',data,pe+4)[0]
  print('EXE',name[len(prefix):],len(data),hex(machine))
 for basename in ('regsvr32.exe','rundll32.exe'):
  exact=prefix+basename
  print('REGISTRATION-TOOL',farm,basename,'PRESENT' if exact in archive.namelist() else 'ABSENT')
with tarfile.open(fileobj=io.BytesIO(archive.read('Payload/Madeira.app/prefix-template.tar.gz')),mode='r:gz') as template:
 for member in template.getmembers():
  if member.name.lower().endswith(('/regsvr32.exe','/rundll32.exe')):
   print('TEMPLATE',json.dumps({'member':member.name,'size':member.size,'symlink':member.issym(),'target':member.linkname}))
import hashlib,uuid
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
native=archive.read('Payload/Madeira.app/Madeira.debug.dylib')
assert native[:4]==b'\xcf\xfa\xed\xfe'
ncmds=struct.unpack_from('<I',native,16)[0];cursor=32;native_uuid=None
for unused in range(ncmds):
 command,size=struct.unpack_from('<II',native,cursor)
 assert size>=8 and cursor+size<=len(native)
 if command==0x1b:native_uuid=str(uuid.UUID(bytes=native[cursor+8:cursor+24])).upper()
 cursor+=size
assert native_uuid=='47243C28-06E4-34D7-9EC4-DDAC8FD44FC8'
print('NATIVE-UUID',native_uuid)

def parse_pe(data):
 pe=struct.unpack_from('<I',data,0x3c)[0];assert data[:2]==b'MZ' and data[pe:pe+4]==b'PE\0\0'
 machine,count=struct.unpack_from('<HH',data,pe+4);opt=pe+24
 magic=struct.unpack_from('<H',data,opt)[0];assert magic in(0x10b,0x20b)
 dirs=opt+(112 if magic==0x20b else 96);entry=struct.unpack_from('<I',data,opt+16)[0]
 base=struct.unpack_from('<Q' if magic==0x20b else '<I',data,opt+(24 if magic==0x20b else 28))[0]
 st=opt+struct.unpack_from('<H',data,pe+20)[0];sections=[]
 for i in range(count):
  q=st+40*i;name=data[q:q+8].rstrip(b'\0').decode(errors='replace');vs,rva,rs,rp=struct.unpack_from('<IIII',data,q+8)
  sections.append((name,rva,vs,rp,rs))
 def at(rva,size):
  for name,va,vs,rp,rs in sections:
   if va<=rva and rva-va+size<=rs and rp+rva-va+size<=len(data):return data[rp+rva-va:rp+rva-va+size]
  raise ValueError('RVA not file-backed '+hex(rva))
 exports=[];dr,dsize=struct.unpack_from('<II',data,dirs)
 if dr and dsize>=40:
  f=struct.unpack('<IIHHIIIIIII',at(dr,40));nf,nn,fa,na,oa=f[6:]
  assert nn<=nf<=65536
  for i in range(nn):
   nr=struct.unpack('<I',at(na+4*i,4))[0];name=bytearray()
   for q in range(256):
    ch=at(nr+q,1)
    if ch==b'\0':break
    name+=ch
   ordinal=struct.unpack('<H',at(oa+2*i,2))[0];assert ordinal<nf
   exports.append((struct.unpack('<I',at(fa+4*ordinal,4))[0],name.decode(errors='replace')))
 return machine,dirs,entry,base,sections,at,sorted(exports)

for name in archive.namelist():
 basename=name.rsplit('/',1)[-1].lower()
 if '/x86_64-vcruntime/' in name and name.lower().endswith('.dll'):
  data=archive.read(name);machine,dirs,*unused=parse_pe(data);offset,size=struct.unpack_from('<II',data,dirs+4*8)
  print('CERTIFICATE',json.dumps({'basename':basename,'machine':hex(machine),'file_bytes':len(data),'certificate_file_offset':offset,'certificate_bytes':size,'present':bool(offset and size),'within_file':bool(offset and size and offset<=len(data) and size<=len(data)-offset),'sha256':hashlib.sha256(data).hexdigest(),'trust_verdict':'not-evaluated'}))
 if basename in('wintrust.dll','crypt32.dll'):
  data=archive.read(name);machine,*unused=parse_pe(data)
  print('TRUST-MODULE',name,len(data),hex(machine),hashlib.sha256(data).hexdigest())
 if basename in('xtajit.dll','xtajit64.dll') or (basename=='ntdll.dll' and ('/arm64ec-windows/' in name or '/aarch64-windows/' in name)):
  data=archive.read(name);machine,dirs,entry,base,sections,at,exports=parse_pe(data)
  print('CPU-MODULE',json.dumps({'member':name,'machine':hex(machine),'file_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'entry':hex(entry),'base':hex(base),'sections':[(n,hex(r),hex(v),hex(rs)) for n,r,v,rp,rs in sections]}))
  interesting=[(hex(r),s) for r,s in exports if any(term in s.lower() for term in('subfloor','critical','debug','trace','queryperformance','query_system_time','mutex','mangle','allocate'))]
  print('CPU-EXPORTS',json.dumps(interesting))
  ec=basename=='xtajit64.dll'
  wow=basename=='xtajit.dll'
  ranges=([(0x13f80,0x14900)] if ec else [(0xf32b0,0xf33c0),(0x102af0,0x102bd0),(0x13a90,0x13b90)] if wow else [])
  data_range=(0x3bd270,0x3bd480) if ec else (0x37f000,0x38b000)
  md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
  for lo,hi in ranges:
   print('DISASSEMBLY',basename,hex(lo),hex(hi))
   for instruction in md.disasm(at(lo,hi-lo),lo):print(f'{instruction.address:08x}: {instruction.bytes.hex()} {instruction.mnemonic} {instruction.op_str}')
  if ec or wow:
   print('DATA-EXPORTS',json.dumps([(hex(r),s) for r,s in exports if data_range[0]<=r<data_range[1]]))
   pe=struct.unpack_from('<I',data,0x3c)[0];symbols,count=struct.unpack_from('<II',data,pe+12)
   print('COFF-SYMBOL-TABLE',basename,'offset',symbols,'count',count)
   selected=[]
   if symbols and count and symbols+18*count+4<=len(data):
    strings=symbols+18*count;length=struct.unpack_from('<I',data,strings)[0];assert 4<=length<=len(data)-strings
    i=0
    while i<count:
     p=symbols+18*i;label=data[p:p+8];value,section=struct.unpack_from('<Ih',data,p+8);aux=data[p+17]
     if label[:4]==b'\0'*4:
      offset=struct.unpack_from('<I',label,4)[0]
      if 4<=offset<length:
       end=data.index(0,strings+offset,strings+length);label=data[strings+offset:end]
      else:label=b''
     else:label=label.split(b'\0')[0]
     if 1<=section<=len(sections):
      rva=sections[section-1][1]+value;decoded=label.decode(errors='replace')
      if data_range[0]<=rva<data_range[1] or 'TelemetryValues' in decoded:selected.append((hex(rva),decoded))
     i+=1+aux
   print('COFF-DATA-SYMBOLS',len(selected),json.dumps(selected[:1024]));assert len(selected)<=1024
   config_rva,config_size=struct.unpack_from('<II',data,dirs+80)
   if config_rva and config_size>=208:
    metadata_va=struct.unpack('<Q',at(config_rva+200,8))[0]
    if metadata_va>=base:
     version,code_map,code_count=struct.unpack('<III',at(metadata_va-base,12));code=[]
     for i in range(code_count):
      encoded,size=struct.unpack('<II',at(code_map+8*i,8));start=encoded&~3
      if any(start<hi and lo<start+size for lo,hi in ranges):code.append((hex(start),hex(size),encoded&3))
     print('CODEMAP',json.dumps({'version':version,'entries':code_count,'matching':code}))
