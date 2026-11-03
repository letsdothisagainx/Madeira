"""Bounded exact official-image inspection, never execute a PE."""
import hashlib,io,subprocess,sys,urllib.request,zipfile
from pathlib import Path
ORIGIN='https://client-update.akamai.steamstatic.com/'
PINS=[
 ('bins_win64.zip.1f91da2609327de9658146b01307e89a13cc1ef8','f34b0d5924d0cca4c81775ed2fef0aee1ca060e2daa5c24270711267786c0236','SteamUI.dll','current-steamui','cd9226db4e6c28942df70c22c0475d91fdd62cba5f100baae2d65af57cabb610'),
 ('bins_win64.zip.60eb5927dc89e3352bfabaf26ffa7b94d5f67604','117d666a5a06474260bf0407e21ac52ebecbdbca55bb85ad7807bcf09757f293','SteamUI.dll','legacy-steamui',''),
 ('bins_webhelpers_win64.zip.24cccba0a57045dd639e797a63facc0f56d9cd4c','697b728a706405a73bbcfcb530f609d414968c2ba189ae87aba83715ff9394c6','steamwebhelper.exe','current-helper','abbd293bd42564944700b46b9245209a4fef15247e21b968dd622d874961f4ce')]
args=[]
for package,sha,member,label,image_sha in PINS:
 url=ORIGIN+package
 with urllib.request.urlopen(url,timeout=90) as r:
  assert r.status==200 and r.url==url
  blob=r.read((120<<20)+1)
 assert len(blob)<=120<<20 and hashlib.sha256(blob).hexdigest()==sha
 with zipfile.ZipFile(io.BytesIO(blob)) as z:
  names=[n for n in z.namelist() if n.lower()==member.lower() or n.lower().endswith('/'+member.lower())]
  assert len(names)==1,names
  data=z.read(names[0])
 digest=hashlib.sha256(data).hexdigest()
 if image_sha:assert digest==image_sha
 path=Path(label+'.dll');path.write_bytes(data)
 args+=['--image',label,str(path),digest]
subprocess.run([sys.executable,'tools/inspect-domain.py',*args,'--output','domain-report.json'],check=True)
