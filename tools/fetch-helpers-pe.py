"""Read pinned official helper images for static protocol analysis only."""
import base64,hashlib,io,urllib.request,zipfile,zlib
rows=[('current-helper','bins_webhelpers_win64.zip.24cccba0a57045dd639e797a63facc0f56d9cd4c','697b728a706405a73bbcfcb530f609d414968c2ba189ae87aba83715ff9394c6','abbd293bd42564944700b46b9245209a4fef15247e21b968dd622d874961f4ce','cef.win64'),('legacy-i386-helper','bins_webhelpers_win32.zip.8a153ec2ee2090c19b25204806ffca2a7ba15bf2','1ab3b3834172a644759860f65d853970ba1d8b65f30190aae774395d69136307','8dba99d204779a30a88a794d1a88d7e76355d004d876ed4bb29da7c3d5a4fc70','cef.win7')]
for label,pkg,sha,image_sha,kind in rows:
 url='https://client-update.akamai.steamstatic.com/'+pkg
 with urllib.request.urlopen(url,timeout=90) as r:
  assert r.url==url and r.status==200;archive=r.read((32<<20)+1)
 assert len(archive)<=32<<20 and hashlib.sha256(archive).hexdigest()==sha
 with zipfile.ZipFile(io.BytesIO(archive)) as z:
  names=[n for n in z.namelist() if n.lower().endswith('/steamwebhelper.exe') and '/'+kind+'/' in n.lower()]
  assert len(names)==1,names;data=z.read(names[0])
 assert hashlib.sha256(data).hexdigest()==image_sha
 assert len(data)<16<<20
 encoded=base64.b64encode(zlib.compress(data,9)).decode()
 print('PUBLIC_PINNED_HELPER',label,len(data),image_sha,len(encoded),flush=True)
 for n in range(0,len(encoded),48000):print('HELPER_IMAGE_CHUNK',label,n//48000,encoded[n:n+48000],flush=True)
