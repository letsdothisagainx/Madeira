"""Read exact public transport fixture; never execute its PE during preparation."""
from pathlib import Path
import hashlib,io,os,urllib.request,zipfile
name='bins_win64.zip.1f91da2609327de9658146b01307e89a13cc1ef8'
sha='f34b0d5924d0cca4c81775ed2fef0aee1ca060e2daa5c24270711267786c0236'
cache=Path(os.environ['MADEIRA_VALVE_ARCHIVE_CACHE']);cache.mkdir(parents=True,exist_ok=True)
archive_path=cache/name
if archive_path.is_file():
 blob=archive_path.read_bytes()
else:
 url='https://client-update.akamai.steamstatic.com/'+name
 with urllib.request.urlopen(url,timeout=90) as response:
  assert response.status==200 and response.url==url
  blob=response.read(64309480)
assert len(blob)==64309479 and hashlib.sha256(blob).hexdigest()==sha
archive_path.write_bytes(blob)
with zipfile.ZipFile(io.BytesIO(blob)) as z:
 data=z.read('bin/chromehtml.dll')
assert hashlib.sha256(data).hexdigest()=='37f5ddbe874362d729b7cd33504943a9d649d845525afae4bcc2af36ab971f4b'
Path(__file__).resolve().parent.parent.joinpath('current-chromehtml.dll').write_bytes(data)
print('PASS exact genuine transport fixture: AMD64, 1668248bytes, SHA25637f5ddbe…')
