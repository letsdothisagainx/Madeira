import hashlib,importlib.util,json,os,zipfile
from pathlib import Path
import pefile
here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('stage',here/'stage.py');s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
raw=(here/'steam_client_win64.tracking').read_bytes();assert s.digest(raw)=='0b12d3072042b2f2aa7b5bc0677c686210465438de981340bb46ac717b1caab8'
current=s.vdf(raw.decode())['win64'];expected={v['file']:(int(v['size']),v['sha2']) for v in current.values() if isinstance(v,dict)}
for name,pin in [(s.I386_CEF[0],(130079979,s.I386_CEF[1])),(s.I386_HELPER[0],(2735010,s.I386_HELPER[1]))]:expected[name]=pin
root=Path(os.environ['MADEIRA_VALVE_ARCHIVE_CACHE'])
for name,(size,sha) in expected.items():
 path=root/name
 if not path.is_file():continue
 with zipfile.ZipFile(path) as z:
  members=[n for n in z.namelist() if n.replace('\\','/').split('/')[-1].lower() in ('sdl3.dll','sdl2.dll')]
  if not members:continue
  assert path.stat().st_size==size and hashlib.sha256(path.read_bytes()).hexdigest()==sha
  for n in members:
   data=z.read(n);p=pefile.PE(data=data)
   print('SDL_PIN '+json.dumps({'archive':name,'member':n,'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'machine':hex(p.FILE_HEADER.Machine)}))
