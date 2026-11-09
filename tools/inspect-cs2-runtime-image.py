import io,json,plistlib,struct,sys,tarfile,zipfile
from pathlib import Path
archive=zipfile.ZipFile(Path(sys.argv[1]))
info=plistlib.loads(archive.read('Payload/Madeira.app/Info.plist'))
assert info['MadeiraBuild'].endswith(' source=4b41f1dd7603612e1596ac885d0b883fa601cf26')
print('BUILD',info['MadeiraBuild'])
for farm in ('aarch64-windows','arm64ec-windows','i386-windows'):
 prefix='Payload/Madeira.app/'+farm+'/'
 entries=[n for n in archive.namelist() if n.startswith(prefix) and n.lower().endswith('.exe')]
 print('EXECUTABLES',farm,'count',len(entries))
 for name in sorted(entries):
  data=archive.read(name);pe=struct.unpack_from('<I',data,0x3c)[0]
  assert data[:2]==b'MZ' and data[pe:pe+4]==b'PE\0\0'
  machine=struct.unpack_from('<H',data,pe+4)[0]
  print('EXE',name[len(prefix):],len(data),hex(machine))
 for basename in ('regsvr32.exe','rundll32.exe'):
  exact=prefix+basename
  print('REGISTRATION-TOOL',farm,basename,'PRESENT' if exact in archive.namelist() else 'ABSENT')
with tarfile.open(fileobj=io.BytesIO(archive.read('Payload/Madeira.app/prefix-template.tar.gz')),mode='r:gz') as template:
 for member in template.getmembers():
  if member.name.lower().endswith(('/regsvr32.exe','/rundll32.exe')):
   print('TEMPLATE',json.dumps({'member':member.name,'size':member.size,'symlink':member.issym(),'target':member.linkname}))
