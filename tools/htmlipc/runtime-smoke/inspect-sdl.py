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
raw32=s.fetch('steam_client_win32');assert s.digest(raw32)=='4b8aa78d95dd7a1475c7849c3e783b136452d34be67342b53728799d697c4823'
manifest=s.vdf(raw32.decode());assert manifest['win32']['version']=='1769731672'
for key,value in manifest['win32'].items():
 if not isinstance(value,dict) or key not in ('bins_win32','bins_client_win32','bins_sdl_win32'):continue
 name,size,sha=s.package(manifest,'win32',key);blob=s.fetch(name,size);assert s.digest(blob)==sha
 with zipfile.ZipFile(__import__('io').BytesIO(blob)) as z:
  names=[n for n in z.namelist() if n.replace('\\','/').split('/')[-1].lower()=='sdl3.dll']
  for n in names:
   data=z.read(n);p=pefile.PE(data=data)
   print('LEGACY_SDL_PIN '+json.dumps({'archive':name,'archive_size':size,'archive_sha256':sha,'member':n,'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'machine':hex(p.FILE_HEADER.Machine),'exports':[e.name.decode() for e in p.DIRECTORY_ENTRY_EXPORT.symbols if e.name in (b'SDL_Init',b'SDL_SetAppMetadata',b'SDL_GetError')]}))
