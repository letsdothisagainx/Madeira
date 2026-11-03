"""Read the official hash-verified process launcher import; never execute it."""
import hashlib,importlib.util,io,json,os,zipfile
from pathlib import Path
import pefile
here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('read_pin',here/'fetch-pin.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
blob=(Path(os.environ['MADEIRA_VALVE_ARCHIVE_CACHE'])/m.name).read_bytes()
assert hashlib.sha256(blob).hexdigest()==m.sha
with zipfile.ZipFile(io.BytesIO(blob)) as z:
 names=[n for n in z.namelist() if n.replace('\\','/').split('/')[-1].lower()=='tier0_s64.dll']
 assert len(names)==1, {'tier0_count':len(names),'dll_names':[n for n in z.namelist() if n.lower().endswith('.dll')][:80]}
 data=z.read(names[0])
p=pefile.PE(data=data);imports=[]
for library in p.DIRECTORY_ENTRY_IMPORT:
 for function in library.imports:
  if function.name and b'CreateProcess' in function.name:
   imports.append({'dll':library.dll.decode(),'name':function.name.decode(),'iat_rva':hex(function.address-p.OPTIONAL_HEADER.ImageBase)})
print('TIER0_PIN '+json.dumps({'member':names[0],'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'machine':hex(p.FILE_HEADER.Machine),'image_size':hex(p.OPTIONAL_HEADER.SizeOfImage),'process_imports':imports}))
