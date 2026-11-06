# SPDX-License-Identifier: MIT
"""Derive fixture bootstrap sizes from the production-pinned official helper.

Only immutable public package bytes are read; no Windows process, Steam install,
account, or official executable is modified by this static contract check.
"""
from pathlib import Path
import hashlib
import re
import struct
import urllib.request
import zipfile


def header(root, directory, *, download=False, helper=None):
    source=(root/'app/Madeira/SteamBrowserRuntime.swift').read_text()
    package=re.search(r'Package\(file: "(bins_webhelpers_win32\.zip\.[0-9a-f]+)", bytes: ([0-9_]+),\s*sha256: "([0-9a-f]{64})"\)',source)
    expected=re.search(r'Key\(name: "steamwebhelper\.exe", sha256: "([0-9a-f]{64})"\)',source)
    assert package and expected,'production helper/cache pin changed'
    if helper is not None:
        image=Path(helper).read_bytes()
    else:
        assert download,'official-helper contract requires explicit download permission'
        name,size,digest=package.groups();size=int(size.replace('_',''))
        file=directory/name
        if not file.exists():
            url='https://client-update.akamai.steamstatic.com/'+name
            with urllib.request.urlopen(urllib.request.Request(url,headers={'Accept-Encoding':'identity'}),timeout=60) as response:
                assert response.status==200 and response.url==url
                data=response.read(size+1)
            assert len(data)==size and hashlib.sha256(data).hexdigest()==digest
            file.write_bytes(data)
        data=file.read_bytes();assert len(data)==size and hashlib.sha256(data).hexdigest()==digest
        with zipfile.ZipFile(file) as archive:
            member='bin/cef/cef.win7/steamwebhelper.exe'
            assert archive.namelist().count(member)==1
            image=archive.read(member)
    assert hashlib.sha256(image).hexdigest()==expected[1],'official helper changed'
    nt=struct.unpack_from('<I',image,0x3c)[0]
    assert image[:2]==b'MZ' and image[nt:nt+4]==b'PE\0\0' and struct.unpack_from('<H',image,nt+4)[0]==0x14c
    count,optional=struct.unpack_from('<H',image,nt+6)[0],struct.unpack_from('<H',image,nt+20)[0]
    assert count<96
    table=nt+24+optional
    def read(rva,size):
        for index in range(count):
            row=table+40*index;va,raw,offset=struct.unpack_from('<III',image,row+12)
            if va<=rva and rva-va+size<=raw:return image[offset+rva-va:offset+rva-va+size]
        raise AssertionError('official bootstrap instruction is not file-backed')
    assert read(0xd950c,1)==b'\x68' and read(0xd9514,5)==bytes.fromhex('e807af0a00')
    capacity=struct.unpack('<I',read(0xd950d,4))[0]
    assert read(0xd9a3c,2)==bytes.fromhex('6a04')
    assert read(0xd9b02,2)==bytes.fromhex('6a48')
    assert read(0xd9c66,2)==bytes.fromhex('6a48')
    opcode=read(0xd9a3d,1)[0];body=read(0xd9b03,1)[0];response=read(0xd9c67,1)[0]
    assert read(0xd9b1e,7)==bytes.fromhex('83bd7cffffff01')
    assert read(0xd9b5e,10)==bytes.fromhex('c78530ffffff02000000')
    assert read(0x184610,3)==bytes.fromhex('8d5f10')
    map_header=read(0x184612,1)[0]
    assert capacity==8192 and opcode+body==76 and response==72 and map_header==16
    assert b'SteamChrome_MasterStream_spid%u\0' in image and b'SteamChrome_ClientStream_%u_%u\0' in image
    path=directory/'bootstrap-contract.h'
    path.write_text(f'#define CAPACITY {capacity}u\n#define MAP_HEADER {map_header}u\n#define REQUEST_BYTES {opcode+body}u\n#define RESPONSE_BYTES {response}u\n')
    return path
