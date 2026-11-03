"""Read only the exact missing HTML controller functions; never execute PE."""
import base64,bisect,hashlib,io,json,struct,urllib.request,zipfile,zlib
from pathlib import Path
import capstone,pefile

PINS=[
 ('current','bins_win64.zip.1f91da2609327de9658146b01307e89a13cc1ef8','f34b0d5924d0cca4c81775ed2fef0aee1ca060e2daa5c24270711267786c0236','37f5ddbe874362d729b7cd33504943a9d649d845525afae4bcc2af36ab971f4b',
  [(0x10230,0x1637a),(0x34a0,None),(0x6e20,None),(0x7240,None),(0x7260,None),(0x7990,None),(0x80d0,None),(0x57510,0x57663),(0xf4660,None),(0xd530,None),(0xe490,None)]),
 ('legacy','bins_win64.zip.60eb5927dc89e3352bfabaf26ffa7b94d5f67604','117d666a5a06474260bf0407e21ac52ebecbdbca55bb85ad7807bcf09757f293','7d1fc0ab5f07e1b6522abf4797efaa19576bc3525843790c85b73f34fd3cc372',
  [(0x11550,0x17cd4),(0x3920,None),(0xa210,None),(0x7ed0,None),(0x7ee0,None),(0x82a0,None),(0x8850,None),(0x8db0,None),(0x5df60,0x5e095),(0xe730,None),(0xa0f0,None),(0xbc90,None)])]
report={}
for label,package,archive_sha,image_sha,ranges in PINS:
 url='https://client-update.akamai.steamstatic.com/'+package
 with urllib.request.urlopen(url,timeout=90) as response:
  assert response.status==200 and response.url==url
  archive=response.read((120<<20)+1)
 assert len(archive)<=120<<20 and hashlib.sha256(archive).hexdigest()==archive_sha
 with zipfile.ZipFile(io.BytesIO(archive)) as z:
  name=next(n for n in z.namelist() if n.lower()=='bin/chromehtml.dll')
  data=z.read(name)
 assert hashlib.sha256(data).hexdigest()==image_sha
 p=pefile.PE(data=data)
 assert p.FILE_HEADER.Machine==0x8664
 functions=sorted((r.struct.BeginAddress,r.struct.EndAddress) for r in p.DIRECTORY_ENTRY_EXCEPTION)
 starts=[a for a,b in functions]
 imports={v.address-p.OPTIONAL_HEADER.ImageBase:d.dll.decode()+'!'+(v.name.decode() if v.name else '#'+str(v.ordinal)) for d in p.DIRECTORY_ENTRY_IMPORT for v in d.imports}
 md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
 row={'archive':package,'archive_sha256':archive_sha,'image_sha256':image_sha,'functions':{},'references':{},'imports':imports}
 report[label]=row
 for entry,end in ranges:
  start=entry
  if end is None:
   i=bisect.bisect_right(starts,entry)-1
   if i>=0 and entry<functions[i][1]: start,end=functions[i]
   else:end=min(entry+2048,p.OPTIONAL_HEADER.SizeOfImage)
  assert end-start<=65536
  instructions=[]
  for ins in md.disasm(p.get_data(start,end-start),start):
   refs=[]
   for op in ins.operands:
    if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
     target=ins.address+ins.size+op.mem.disp
     refs.append(target)
     if target not in imports and 0<=target<p.OPTIONAL_HEADER.SizeOfImage and str(target) not in row['references']:
      n=min(2048,p.OPTIONAL_HEADER.SizeOfImage-target)
      row['references'][str(target)]=p.get_data(target,n).hex()
   instructions.append({'rva':ins.address,'bytes':ins.bytes.hex(),'asm':ins.mnemonic+' '+ins.op_str,'refs':refs})
  row['functions'][hex(entry)]={'start':start,'end':end,'raw':p.get_data(start,end-start).hex(),'instructions':instructions}
 print('IMAGE_COMPLETE',label,image_sha,'functions',len(row['functions']),flush=True)
Path('controller-fast-report.json').write_text(json.dumps(report))
blob=json.dumps(report,separators=(',',':')).encode();packed=zlib.compress(blob,9)
assert len(packed)<1<<20
print('FAST_REPORT_SHA256',hashlib.sha256(blob).hexdigest(),flush=True)
encoded=base64.b64encode(packed).decode()
for n in range(0,len(encoded),48000):print('FAST_REPORT_CHUNK',n//48000,encoded[n:n+48000],flush=True)
