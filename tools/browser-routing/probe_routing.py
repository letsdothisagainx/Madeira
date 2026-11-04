from pathlib import Path
import os,urllib.request,hashlib,io,zipfile,re,json,bisect
import pefile,capstone
cache=Path(os.environ['MADEIRA_VALVE_ARCHIVE_CACHE']);cache.mkdir(parents=True,exist_ok=True)
packages=[('bins_win64.zip.1f91da2609327de9658146b01307e89a13cc1ef8',64309479,'f34b0d5924d0cca4c81775ed2fef0aee1ca060e2daa5c24270711267786c0236'),('steamui_websrc_all.zip.24dd80531ce5c8cf19b5bfdd2e580ab55ebf8365',35647879,'275f353463226631c3a43e90994f65a64262c30a961dccd257ccfc4b08f2f1a1')]
blobs=[]
for name,size,sha in packages:
 p=cache/name
 if p.exists():data=p.read_bytes()
 else:
  url='https://client-update.akamai.steamstatic.com/'+name
  with urllib.request.urlopen(url,timeout=60) as r:
   assert r.status==200 and r.url==url;data=r.read(size+1)
 assert len(data)==size and hashlib.sha256(data).hexdigest()==sha;p.write_bytes(data);blobs.append(data)
with zipfile.ZipFile(io.BytesIO(blobs[0])) as z:
 names=[n for n in z.namelist() if n.lower().endswith('steamui.dll')];assert len(names)==1
 blob=z.read(names[0])
assert hashlib.sha256(blob).hexdigest()=='cd9226db4e6c28942df70c22c0475d91fdd62cba5f100baae2d65af57cabb610'
p=pefile.PE(data=blob);base=p.OPTIONAL_HEADER.ImageBase
pattern=re.compile(r'screensaver|browser.?view|loopback|local.?file.?request|domain.?map|file.?mapping|steamui.*(?:legacy|browser)|cef.*(?:legacy|browser|webview)|disable.*(?:browser|loopback)',re.I)
strings={}
for m in re.finditer(rb'[\x20-\x7e]{4,}',blob):
 s=m.group().decode()
 if pattern.search(s):strings[p.get_rva_from_offset(m.start())]=s[:320]
assert len(strings)<400
print('FEATURE_STRINGS '+json.dumps({hex(k):v for k,v in strings.items()}),flush=True)
funcs=sorted((x.struct.BeginAddress,x.struct.EndAddress) for x in p.DIRECTORY_ENTRY_EXCEPTION);starts=[x[0] for x in funcs]
def containing(r):
 i=bisect.bisect_right(starts,r)-1
 return funcs[i] if i>=0 and funcs[i][0]<=r<funcs[i][1] else None
c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);c.skipdata=True
xref={};slot38=[]
for s in p.sections:
 if not s.Characteristics&0x20000000:continue
 for addr,size,mn,op in c.disasm_lite(s.get_data(),base+s.VirtualAddress):
  r=addr-base
  match=re.search(r'\[rip ([+-]) (0x[0-9a-f]+)\]',op)
  if match:
   target=r+size+(int(match[2],16) if match[1]=='+' else -int(match[2],16))
   if target in strings or target==0x11935b8:
    f=containing(r)
    if f:xref.setdefault(f,[]).append({'rva':hex(r),'asm':mn+' '+op,'target':hex(target),'literal':strings.get(target,'controller-global')})
  if mn=='call' and re.search(r'\[[^]]+ \+ 0x130\]',op):slot38.append((r,containing(r),mn+' '+op))
print('SLOT38 '+json.dumps([(hex(r),tuple(hex(v) for v in f) if f else None,asm) for r,f,asm in slot38]),flush=True)
f=containing(0x66aa30)
assert f
xref.setdefault(f,[]).append({'rva':hex(f[0]),'asm':'explicit exact screensaver-mapping callee','target':'0x66aa30','literal':'registration setup'})
for f,refs in xref.items():
 print('FUNCTION_REFS '+json.dumps({'range':tuple(hex(v) for v in f),'refs':refs}),flush=True)
 # Preserve complete small functions or bounded context around matching references.
 spans=[(f[0],f[1])] if f[1]-f[0]<=2200 else [(max(f[0],int(ref['rva'],16)-120),min(f[1],int(ref['rva'],16)+220)) for ref in refs]
 for a,b in spans:
  print('FUNCTION_CONTEXT '+json.dumps({'function':hex(f[0]),'range':[hex(a),hex(b)],'instructions':[(hex(ad-base),mn+' '+op) for ad,_,mn,op in c.disasm_lite(p.get_data(a,b-a),base+a)]}),flush=True)
for a,b in [(0x66aa30,0x66ace3),(0x5b9660,0x5b9a30)]:
 print('EXACT_MAPPING_BODY '+json.dumps({'range':[hex(a),hex(b)],'instructions':[(hex(ad-base),mn+' '+op) for ad,_,mn,op in c.disasm_lite(p.get_data(a,b-a),base+a)]}),flush=True)
with zipfile.ZipFile(io.BytesIO(blobs[1])) as z:
 count=0
 for name in z.namelist():
  if not name.endswith(('.js','.json')):continue
  text=z.read(name).decode(errors='replace')
  for m in re.finditer(r'bBrowserViewDomainMapping|SetBrowserViewDomainRequestMapping|BrowserViewDomainMapping|BrowserViewDomainRequestMapping|[A-Za-z_][A-Za-z_0-9]*(?:LegacyBrowser|BrowserViewEnabled|EnableBrowserView)[A-Za-z_0-9]*',text):
   print('JS_ROUTING '+json.dumps({'file':name,'offset':m.start(),'context':text[max(0,m.start()-2200):m.end()+1600]}),flush=True);count+=1
   assert count<100
print('PASS readonly exact-build browser routing feature inspection',flush=True)
