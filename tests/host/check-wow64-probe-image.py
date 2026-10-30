#!/usr/bin/env python3
"""Verify the real i386 loader fixture from an IPA; requires pefile."""
from pathlib import Path
import argparse,struct
import pefile
ap=argparse.ArgumentParser();ap.add_argument('farm',type=Path);args=ap.parse_args()
for name in ['madeira-wow64-probe.exe','madeira-wow64-module-probe.dll']:
    p=pefile.PE(str(args.farm/name))
    assert p.FILE_HEADER.Machine==0x14c and p.OPTIONAL_HEADER.Magic==0x10b
    assert hasattr(p,'DIRECTORY_ENTRY_TLS') and p.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
    callback_rva=p.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks-p.OPTIONAL_HEADER.ImageBase
    assert struct.unpack('<I',p.get_data(callback_rva,4))[0], 'empty TLS callback list'
    imports={d.dll.lower():{i.name for i in d.imports if i.name} for d in p.DIRECTORY_ENTRY_IMPORT}
    if name.endswith('.dll'):
        assert b'wglGetCurrentContext' in imports.get(b'opengl32.dll',set())
        assert b'probe_state' in {e.name for e in p.DIRECTORY_ENTRY_EXPORT.symbols}
    else:
        assert {b'LoadLibraryW',b'CreateThread',b'WaitForSingleObject'} <= imports.get(b'kernel32.dll',set())
print('PASS packaged i386 probe: real LoadLibrary/thread APIs, OpenGL dependency, TLS callbacks and state export')
