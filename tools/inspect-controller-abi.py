"""Bounded, read-only inspection of pinned public Steam transport images.
Never load or execute PE code; no user installation/archive is changed.
"""
import base64,bisect,hashlib,io,json,re,struct,urllib.request,zipfile,zlib
from pathlib import Path
import capstone,pefile
CORE_CURRENT=('current','bins_win64.zip.1f91da2609327de9658146b01307e89a13cc1ef8','f34b0d5924d0cca4c81775ed2fef0aee1ca060e2daa5c24270711267786c0236')
# Fill from the independent manifest-provenance audit before dispatch.
CORE_LEGACY=('legacy','bins_win64.zip.60eb5927dc89e3352bfabaf26ffa7b94d5f67604','117d666a5a06474260bf0407e21ac52ebecbdbca55bb85ad7807bcf09757f293')
MAX_ARCHIVE=120<<20
FUNCTION_BYTE_BUDGET=512<<10
FUNCTION_COUNT_BUDGET=240
report={'scope':'static images only, no PE execution; no compatibility assertion from matching names alone','images':{},'limits':{'max_archive_bytes':MAX_ARCHIVE,'per_image_function_bytes':FUNCTION_BYTE_BUDGET,'per_image_functions':FUNCTION_COUNT_BUDGET}}

def sha(b):return hashlib.sha256(b).hexdigest()
def fetch(file,expected):
 u='https://client-update.akamai.steamstatic.com/'+file
 with urllib.request.urlopen(u,timeout=120) as r:
  assert r.status==200 and r.url==u
  b=r.read(MAX_ARCHIVE+1)
 assert len(b)<=MAX_ARCHIVE and sha(b)==expected,(file,len(b),sha(b))
 return b

class Image:
 def __init__(self,label,name,b):
  self.label,self.name,self.b=label,name,b;self.p=pefile.PE(data=b)
  assert self.p.FILE_HEADER.Machine==0x8664,(name,'not AMD64')
  self.base=self.p.OPTIONAL_HEADER.ImageBase;self.size=self.p.OPTIONAL_HEADER.SizeOfImage
  self.md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);self.md.detail=True;self.md.skipdata=True
  self.funcs=sorted((e.struct.BeginAddress,e.struct.EndAddress) for e in getattr(self.p,'DIRECTORY_ENTRY_EXCEPTION',[]));self.begins=[a for a,z in self.funcs]
  self.execs=[(s.VirtualAddress,s.VirtualAddress+s.Misc_VirtualSize) for s in self.p.sections if s.Characteristics&0x20000000]
  self.imports={i.address-self.base:e.dll.decode(errors='replace')+'!'+(i.name.decode(errors='replace') if i.name else '#'+str(i.ordinal)) for e in getattr(self.p,'DIRECTORY_ENTRY_IMPORT',[]) for i in e.imports}
  self.exports={e.name.decode(errors='replace'):hex(e.address) for e in getattr(self.p,'DIRECTORY_ENTRY_EXPORT',type('x',(),{'symbols':[]})()).symbols if e.name}
  self.strings={};self.types={};self.data_calls={};self.functions={};self.used_bytes=0
  for m in re.finditer(rb'[\x20-\x7e]{6,350}',b):
   try:rva=self.p.get_rva_from_offset(m.start())
   except pefile.PEFormatError:continue
   st=m[0].decode();self.strings[rva]=st
   if st.startswith('.?A'):self.types[rva-16]=st
  self.o={'member':name,'sha256':sha(b),'machine':'0x8664','base':hex(self.base),'size':hex(self.size),'exports':self.exports,'imports':self.imports,'rtti_types':{hex(k):v for k,v in self.types.items() if any(t in v for t in ('HTML','ChromeIPC','UtlBuffer','CMsgBrowserCreate','CMsgSetBlockInput','CMsgInputBlocked','CMsgSetBrowserViewDomainRequestMapping','MemAlloc'))},'functions':self.functions}
  report['images'][label+'/'+name]=self.o
 def data(self,r,n):
  if not(0<=r<self.size) or n<0 or r+n>self.size:return b''
  return self.p.get_data(r,n)
 def q(self,r):
  b=self.data(r,8);return struct.unpack('<Q',b)[0] if len(b)==8 else 0
 def u(self,r):
  b=self.data(r,4);return struct.unpack('<I',b)[0] if len(b)==4 else 0
 def executable(self,r):return any(a<=r<z for a,z in self.execs)
 def function(self,r):
  i=bisect.bisect_right(self.begins,r)-1
  return self.funcs[i] if i>=0 and r<self.funcs[i][1] else (r,min(r+128,self.size))
 def decode(self,a,z):return [i for i in self.md.disasm(self.data(a,z-a),a) if i.id]
 def rip_targets(self,i):
  return [i.address+i.size+o.mem.disp for o in i.operands if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP]
 def ins_json(self,i):
  d={'rva':hex(i.address),'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str}
  refs=[]
  for r in self.rip_targets(i):
   if r in self.imports:refs.append({'iat':self.imports[r],'rva':hex(r)})
   if r in self.strings:refs.append({'literal':self.strings[r],'rva':hex(r)})
  if refs:d['refs']=refs
  return d
 def add_function(self,r,reason,limit=8192,follow=False):
  if not self.executable(r):return
  a,z=self.function(r);key=hex(a)
  if key in self.functions:
   if reason not in self.functions[key]['reasons']:self.functions[key]['reasons'].append(reason)
   return
  if len(self.functions)>=FUNCTION_COUNT_BUDGET or self.used_bytes>=FUNCTION_BYTE_BUDGET:return
  end=min(z,a+limit,a+FUNCTION_BYTE_BUDGET-self.used_bytes);self.used_bytes+=end-a
  ins=self.decode(a,end)
  self.functions[key]={'range':[hex(a),hex(z)],'captured_end':hex(end),'complete':end==z,'reasons':[reason],'raw_bytes':self.data(a,end-a).hex(),'instructions':[self.ins_json(i) for i in ins]}
  if follow:
   targets=[]
   for i in ins:
    if i.mnemonic in ('call','jmp') and i.operands and i.operands[0].type==capstone.x86.X86_OP_IMM and self.executable(i.operands[0].imm):targets.append(i.operands[0].imm)
   for t in dict.fromkeys(targets):
    # One direct-call level, no recursively following protobuf/logging runtime.
    self.add_function(t,'direct target from '+key,limit=2048)
 def scan_xrefs(self,targets):
  if not targets:return []
  out=[]
  for a,z in self.execs:
   for i in self.md.disasm(self.data(a,z-a),a):
    if not i.id:continue
    ts=set(self.rip_targets(i))&targets
    if ts:
     for t in ts:out.append({'target':hex(t),'function':[hex(v) for v in self.function(i.address)],**self.ins_json(i)})
  return out
 def vtables(self):
  # MSVC64 RTTI CompleteObjectLocator signature1, self-RVA validates candidates.
  cols={}
  for s in self.p.sections:
   if s.Characteristics&0x20000000:continue
   d=s.get_data();start=s.VirtualAddress
   for off in range(0,len(d)-24,4):
    sig,adjust,cd,td,ch,selfr=struct.unpack_from('<IIIIII',d,off)
    r=start+off
    if sig!=1 or selfr!=r or td not in self.types or adjust>4096:continue
    cols[r]={'rva':hex(r),'offset_to_complete_object':adjust,'constructor_displacement':cd,'type_descriptor':hex(td),'type':self.types[td],'class_hierarchy':hex(ch)}
  tables=[]
  for s in self.p.sections:
   if s.Characteristics&0x20000000:continue
   d=s.get_data();start=s.VirtualAddress
   for off in range(0,len(d)-16,8):
    c=struct.unpack_from('<Q',d,off)[0]-self.base
    if c not in cols:continue
    vt=start+off+8;entries=[]
    for slot in range(192):
     target=self.q(vt+slot*8)-self.base
     if not self.executable(target):break
     entries.append({'slot':slot,'offset':hex(slot*8),'rva':hex(target),'function':[hex(q) for q in self.function(target)]})
    if not entries:continue
    row={'rva':hex(vt),'col':cols[c],'entries':entries}
    # Parse concrete base-class adjustment records; no name=>ABI inference.
    ch=self.u(c+16);n=self.u(ch+8);arr=self.u(ch+12);bases=[]
    if 0<n<=100:
     for k in range(n):
      bd=self.u(arr+4*k);td=self.u(bd);raw=self.data(bd+8,12)
      if len(raw)==12:bases.append({'type':self.types.get(td,hex(td)),'pmd':list(struct.unpack('<iii',raw)),'attributes':self.u(bd+20)})
    row['bases']=bases
    if any(any(term in typ for term in ('HTML','ChromeIPC','UtlBuffer','CMsgBrowserCreate','CMsgSetBlockInput','CMsgInputBlocked','CMsgSetBrowserViewDomainRequestMapping','MemAlloc')) for typ in [row['col']['type']]+[x['type'] for x in bases]):tables.append(row)
  self.o['vtables']=tables
  return tables
 def inspect(self):
  chosen={r:s for r,s in self.strings.items() if any(t in s for t in ('ChromeHTML_Controller','CChromeIPCClient::','CUIProtoBufMsg::','CChromeIPCServer::','CMsgSetBlockInput','CMsgInputBlocked','CMsgSetBrowserViewDomainRequestMapping','CMsgBrowserCreate','htmlmessages.proto'))}
  self.o['relevant_literals']={hex(k):v for k,v in chosen.items()}
  refs=self.scan_xrefs(set(chosen));self.o['literal_xrefs']=refs
  for x in refs:
   s=chosen[int(x['target'],16)]
   if any(t in s for t in ('ChromeHTML_Controller','CChromeIPCClient::PushCommand','CChromeIPCClient::RunFrame','CUIProtoBufMsg::SerializeCrossProc','CMsgSetBlockInput','CMsgInputBlocked','CMsgSetBrowserViewDomainRequestMapping','CMsgBrowserCreate','htmlmessages.proto')):self.add_function(int(x['rva'],16),'literal '+s,limit=8192,follow=True)
  # EXPOSE_INTERFACE registration initializes a record with creator/code and name.
  # Recover its LEA code target, rather than assuming legacy uses the current RVA.
  for f in list(self.functions.values()):
   if any('ChromeHTML_Controller' in why for why in f['reasons']):
    for ins in self.decode(int(f['range'][0],16),int(f['captured_end'],16)):
     if ins.mnemonic=='lea' and ins.operands[0].type==capstone.x86.X86_OP_REG and ins.reg_name(ins.operands[0].reg) in ('rdx','r8'):
      for t in self.rip_targets(ins):
       if self.executable(t):self.add_function(t,'factory creator candidate from registration',limit=8192,follow=True)
  # Inspect exact registry constructor/creator and transport funcs already proven in prior run.
  if self.label=='current' and self.name.lower().endswith('chromehtml.dll'):
   for r in (0x1900,0x19100,0xf9640,0xf9660,0x799a,0x8171,0x57510):self.add_function(r,'prior exact pinned evidence',limit=8192,follow=True)
  tables=self.vtables()
  controller_tables=[t for t in tables if any(any(k in typ for k in ('HTMLController','HTMLChromeController','ChromeIPCClient','HTMLResponses','CMsgBrowserCreate','CMsgSetBlockInput','CMsgInputBlocked','CMsgSetBrowserViewDomainRequestMapping','MemAlloc')) for typ in [t['col']['type']]+[x['type'] for x in t['bases']])]
  controller_tables.sort(key=lambda t:0 if 'HTMLController' in t['col']['type'] or 'HTMLChromeController' in t['col']['type'] else 1 if any('HTMLResponses' in x['type'] for x in t['bases']) else 2 if 'ChromeIPCClient' in t['col']['type'] else 3)
  self.o['controller_vtables']=controller_tables
  table_refs=self.scan_xrefs({int(t['rva'],16) for t in controller_tables})
  self.o['controller_or_message_vtable_xrefs']=table_refs
  for x in table_refs:self.add_function(int(x['rva'],16),'controller/callback/message vtable initialization reference',limit=8192)
  for t in controller_tables:
   for e in t['entries']:self.add_function(int(e['rva'],16),'vtable '+t['col']['type']+' slot'+str(e['slot']),limit=32768 if any(k in t['col']['type'] for k in ('HTMLController','HTMLChromeController')) else 4096)
  # Public factory creation stubs often return a static object via lea rax,[rip].
  globals_=set()
  for f in list(self.functions.values()):
   if any('ChromeHTML_Controller' in x or 'prior exact' in x for x in f['reasons']):
    for ins in self.decode(int(f['range'][0],16),int(f['captured_end'],16)):
     if ins.mnemonic=='lea' and ins.operands[0].type==capstone.x86.X86_OP_REG and ins.reg_name(ins.operands[0].reg)=='rax':globals_.update(self.rip_targets(ins))
  self.o['factory_object_candidates']=[hex(r) for r in sorted(globals_) if not self.executable(r)]
  if globals_:
   grefs=self.scan_xrefs(globals_);self.o['factory_object_xrefs']=grefs
   for x in grefs:self.add_function(int(x['rva'],16),'factory static object reference',limit=8192)
  # Include constant IDs and callback slots, scoped to selected functions only.
  calls=[];imm=[]
  for f in self.functions.values():
   for ins in self.decode(int(f['range'][0],16),int(f['captured_end'],16)):
    if ins.mnemonic in ('call','jmp') and ins.operands and ins.operands[0].type==capstone.x86.X86_OP_MEM:
     o=ins.operands[0]
     if o.mem.base!=capstone.x86.X86_REG_RIP:calls.append({'function':f['range'][0],**self.ins_json(ins)})
    if ins.mnemonic in ('cmp','mov'):
     for o in ins.operands:
      if o.type==capstone.x86.X86_OP_IMM and 0<=o.imm<=512:imm.append({'value':o.imm,'function':f['range'][0],**self.ins_json(ins)})
  self.o['indirect_object_calls']=calls;self.o['small_command_candidate_immediates']=imm
  self.o['budget_used']={'function_bytes':self.used_bytes,'functions':len(self.functions)}
  print('IMAGE_SUMMARY',json.dumps({'label':self.label,'member':self.name,'sha256':self.o['sha256'],'vtables':len(tables),'controller_vtables':[(t['col']['type'],t['rva'],t['col']['offset_to_complete_object'],len(t['entries'])) for t in controller_tables],'functions':len(self.functions),'bytes':self.used_bytes}),flush=True)

for label,file,expected in (CORE_CURRENT,CORE_LEGACY):
 b=fetch(file,expected);report[label+'_archive']={'file':file,'sha256':sha(b),'bytes':len(b)}
 with zipfile.ZipFile(io.BytesIO(b)) as z:
  assert sum(i.file_size for i in z.infolist())<800<<20
  names=[n for n in z.namelist() if n.rsplit('/',1)[-1].lower() in ('chromehtml.dll','steamui.dll','steamclient64.dll','tier0_s64.dll','tier0.dll')]
  # Legacy SteamUI is useful to compare callback interface producers; no core is installed.
  assert any(n.lower().endswith('chromehtml.dll') for n in names)
  for name in names:
   member=z.read(name)
   if pefile.PE(data=member,fast_load=True).FILE_HEADER.Machine!=0x8664:
    print('SKIP_NON_AMD64',label,name,flush=True);continue
   im=Image(label,name,member);im.inspect()
 del b
Path('controller-abi-report.json').write_text(json.dumps(report,indent=2)+'\n')
blob=json.dumps(report,separators=(',',':')).encode();packed=zlib.compress(blob,9)
assert len(packed)<2<<20
print('REPORT_DIGEST',json.dumps({'sha256':sha(blob),'json_bytes':len(blob),'compressed_bytes':len(packed)}),flush=True)
# The report contains public static bytes only, never Steam account data.
encoded=base64.b64encode(packed).decode()
for offset in range(0,len(encoded),48000):print('REPORT_ZLIB_CHUNK',offset//48000,encoded[offset:offset+48000],flush=True)
