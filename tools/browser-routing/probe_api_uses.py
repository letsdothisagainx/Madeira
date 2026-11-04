from pathlib import Path
import os,urllib.request,hashlib,io,zipfile,re,json
name='steamui_websrc_all.zip.24dd80531ce5c8cf19b5bfdd2e580ab55ebf8365';size=35647879;sha='275f353463226631c3a43e90994f65a64262c30a961dccd257ccfc4b08f2f1a1'
cache=Path(os.environ['MADEIRA_VALVE_ARCHIVE_CACHE']);cache.mkdir(parents=True,exist_ok=True);p=cache/name
if p.exists():blob=p.read_bytes()
else:
 url='https://client-update.akamai.steamstatic.com/'+name
 with urllib.request.urlopen(url,timeout=60) as r:assert r.status==200 and r.url==url;blob=r.read(size+1)
assert len(blob)==size and hashlib.sha256(blob).hexdigest()==sha
p.write_bytes(blob)
targets=['RemoveAllBackstackEntries','IsDebuggingEnabled','GetBrowserProcessDetails','RegisterForStyleChanges','RegisterForOpenNewTab','RegisterForGestureEvents','SetShouldExitSteamOnBrowserClosed','FlashWindow','StopFlashWindow','SetWindowFlashing']
with zipfile.ZipFile(io.BytesIO(blob)) as z:
 for entry in z.infolist():
  if not entry.filename.endswith('.js'):continue
  text=z.read(entry).decode(errors='replace')
  for target in targets:
   hits=list(re.finditer(re.escape(target),text))
   if not hits:continue
   assert len(hits)<=80
   for m in hits:
    print('API_USE '+json.dumps(dict(file=entry.filename,sha256=hashlib.sha256(text.encode()).hexdigest(),target=target,offset=m.start(),context=text[max(0,m.start()-550):m.end()+1100])),flush=True)
  if entry.filename.endswith('/login.js'):
   print('LOGIN_ENTRY '+json.dumps(dict(file=entry.filename,length=len(text),head=text[:600],tail=text[-1800:])),flush=True)
print('PASS exact pinned current web resources inspected read-only',flush=True)
