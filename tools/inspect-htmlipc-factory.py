"""Bounded static inspection of the exact official current core; never execute PE."""
import urllib.request, hashlib, io, zipfile, struct, re, bisect, json
import pefile, capstone
origin='https://client-update.akamai.steamstatic.com/'
package='bins_win64.zip.1f91da2609327de9658146b01307e89a13cc1ef8'
size=64309479
sha='f34b0d5924d0cca4c81775ed2fef0aee1ca060e2daa5c24270711267786c0236'
with urllib.request.urlopen(origin+package,timeout=120) as r:
 assert r.status==200 and r.url==origin+package
 data=r.read(size+1)
assert len(data)==size and hashlib.sha256(data).hexdigest()==sha
print('PINNED_CORE_PACKAGE',json.dumps({'name':package,'bytes':len(data),'sha256':sha}))
terms=('ChromeHTML_Controller_001','IHTMLChromeController','HTMLCommandBuffer','SerializeCrossProc','DeserializeCrossProc','CChromeIPC','SteamChrome_MasterStream','chrome_ipc_shared.cpp','chrome_ipc_client.cpp','chrome_ipc_server.cpp')
with zipfile.ZipFile(io.BytesIO(data)) as z:
 assert sum(x.file_size for x in z.infolist())<700<<20
 names=[n for n in z.namelist() if n.lower().endswith(('.dll','.exe'))]
 print('PE_MEMBERS',json.dumps(names))
 selected=[n for n in names if n.rsplit('/',1)[-1].lower() in ('steamclient64.dll','steamui.dll','chromehtml.dll')]
 assert selected,'required core member not found'
 for name in selected:
  b=z.read(name);p=pefile.PE(data=b)
  imagebase=p.OPTIONAL_HEADER.ImageBase
  assert p.FILE_HEADER.Machine==0x8664
  print('IMAGE',json.dumps({'member':name,'machine':hex(p.FILE_HEADER.Machine),'sha256':hashlib.sha256(b).hexdigest(),'imagebase':hex(imagebase),'size':hex(p.OPTIONAL_HEADER.SizeOfImage)}))
  exports={e.name.decode('ascii','replace'):e.address for e in getattr(p,'DIRECTORY_ENTRY_EXPORT',type('x',(),{'symbols':[]})()).symbols if e.name}
  print('RELEVANT_EXPORTS',json.dumps({k:hex(v) for k,v in exports.items() if any(t in k.lower() for t in ('createinterface','html','chrome'))}))
  exec_ranges=[(s.VirtualAddress,s.VirtualAddress+s.Misc_VirtualSize) for s in p.sections if s.Characteristics&0x20000000]
  def is_exec(rva):return any(a<=rva<c for a,c in exec_ranges)
  functions=sorted((e.struct.BeginAddress,e.struct.EndAddress) for e in getattr(p,'DIRECTORY_ENTRY_EXCEPTION',[]));begins=[a for a,c in functions]
  def function(at):
   i=bisect.bisect_right(begins,at)-1
   if i>=0 and at<functions[i][1]:return functions[i]
   return (at,min(at+128,p.OPTIONAL_HEADER.SizeOfImage))
  strings={}
  for m in re.finditer(rb'[\x20-\x7e]{6,}',b):
   s=m[0].decode()
   if any(t.lower() in s.lower() for t in terms):
    try:rva=p.get_rva_from_offset(m.start())
    except pefile.PEFormatError:continue
    strings[rva]=s
  print('FACTORY_TRANSPORT_LITERALS',json.dumps({hex(k):v[:300] for k,v in strings.items()}))
  candidate_funcs={}
  for rva,s in strings.items():
   if s!='ChromeHTML_Controller_001':continue
   target=struct.pack('<Q',imagebase+rva)
   for m in re.finditer(re.escape(target),b):
    if m.start()<8 or m.start()+16>len(b):continue
    create,nxt=struct.unpack_from('<Q',b,m.start()-8)[0],struct.unpack_from('<Q',b,m.start()+8)[0]
    create-=imagebase
    if is_exec(create):
     print('FACTORY_REGISTRY_CANDIDATE',json.dumps({'name':s,'pointer_file_offset':hex(m.start()),'create_rva':hex(create),'next':hex(nxt)}))
     candidate_funcs[function(create)]=('factory-create',s)
  imports={}
  for e in getattr(p,'DIRECTORY_ENTRY_IMPORT',[]):
   for imp in e.imports:
    if imp.name:imports[imp.address-imagebase]=imp.name.decode()
  wanted_imports={k:v for k,v in imports.items() if v in ('CreateFileMappingA','CreateFileMappingW','OpenFileMappingA','OpenFileMappingW','MapViewOfFile','MapViewOfFileEx','UnmapViewOfFile','CreateEventA','CreateEventW','OpenEventA','OpenEventW','ReadFile','WriteFile')}
  print('TRANSPORT_IMPORTS',json.dumps({hex(k):v for k,v in wanted_imports.items()}))
  md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True;md.skipdata=True
  xrefs=[]
  # Streaming disassembly: no unbounded instruction arrays or code execution.
  for sec in p.sections:
   if not(sec.Characteristics&0x20000000):continue
   for ins in md.disasm(sec.get_data()[:sec.Misc_VirtualSize],sec.VirtualAddress):
    if not ins.id:continue
    for op in ins.operands:
     if op.type!=capstone.x86.X86_OP_MEM or op.mem.base!=capstone.x86.X86_REG_RIP:continue
     target=ins.address+ins.size+op.mem.disp
     if target in strings and len(xrefs)<100:
      f=function(ins.address);xrefs.append({'at':hex(ins.address),'target':hex(target),'string':strings[target][:180],'function':[hex(q) for q in f],'insn':ins.mnemonic+' '+ins.op_str})
      if strings[target]=='ChromeHTML_Controller_001' or 'SteamChrome_MasterStream' in strings[target]:candidate_funcs[f]=('literal-xref',strings[target])
  print('LITERAL_XREFS',json.dumps(xrefs))
  if 'CreateInterface' in exports and is_exec(exports['CreateInterface']):candidate_funcs[function(exports['CreateInterface'])]=('export','CreateInterface')
  for f,(why,label) in list(candidate_funcs.items())[:12]:
   print('BOUNDED_FUNCTION',json.dumps({'range':[hex(q) for q in f],'why':why,'label':label}))
   for i,ins in enumerate(md.disasm(p.get_data(f[0],min(f[1]-f[0],1536)),f[0])):
    if i>=160:break
    print('%08x %s %s'%(ins.address,ins.mnemonic,ins.op_str))
  if 'ChromeHTML_Controller_001' not in strings.values():print('STOP_NO_MODERN_FACTORY_STRING',name)
  print('STOP_CONDITION','Do not interpose legacy vtables or raw I/O until this exact binary proves a supported object ABI and full channel framing.')
