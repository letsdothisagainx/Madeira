"""Read official pinned chromehtml bytes, never load or execute image."""
import base64,hashlib,io,urllib.request,zipfile,zlib
url='https://client-update.akamai.steamstatic.com/bins_win64.zip.1f91da2609327de9658146b01307e89a13cc1ef8'
with urllib.request.urlopen(url,timeout=90) as r:
 assert r.url==url and r.status==200
 archive=r.read((120<<20)+1)
assert len(archive)==64309479 and hashlib.sha256(archive).hexdigest()=='f34b0d5924d0cca4c81775ed2fef0aee1ca060e2daa5c24270711267786c0236'
with zipfile.ZipFile(io.BytesIO(archive)) as z:
 data=z.read('bin/chromehtml.dll')
assert hashlib.sha256(data).hexdigest()=='37f5ddbe874362d729b7cd33504943a9d649d845525afae4bcc2af36ab971f4b'
assert len(data)<4<<20
encoded=base64.b64encode(zlib.compress(data,9)).decode()
print('PUBLIC_PINNED_IMAGE','current-chromehtml',len(data),hashlib.sha256(data).hexdigest(),len(encoded),flush=True)
for n in range(0,len(encoded),48000):print('RAW_IMAGE_CHUNK',n//48000,encoded[n:n+48000],flush=True)
