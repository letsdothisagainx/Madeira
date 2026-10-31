#!/usr/bin/env python3
"""Verify the read-only inventory against genuine filesystem/PE layouts."""
from pathlib import Path
import hashlib
import os
import struct
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='madeira-steam-deps-') as temp:
    folder=Path(temp); steam=folder/'Steam'; (steam/'bin').mkdir(parents=True)
    def image(path,machine):
        data=bytearray(160);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,0x80)
        data[0x80:0x84]=b'PE\0\0';struct.pack_into('<H',data,0x84,machine);path.write_bytes(data)
    image(steam/'bin/sDl2.DlL',0x14c)
    image(steam/'bin/gldriverquery.exe',0x14c)
    image(steam/'bin/gldriverquery64.exe',0x8664)
    image(steam/'bin/vulkandriverquery.exe',0x14c)
    image(steam/'bin/vulkandriverquery64.exe',0x8664)
    cef=steam/'bin/cef/cef.win7'; cef.mkdir(parents=True)
    image(cef/'vulkan-1.dll',0x14c)
    (steam/'SDL3.dll').write_text('invalid PE fixture')
    before={p:(hashlib.sha256(p.read_bytes()).digest(),p.stat().st_mtime_ns) for p in steam.rglob('*') if p.is_file()}
    source,binary=folder/'test.c',folder/'test'
    source.write_text('''#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include "steam_dependency_probe.h"
int main(int argc,char **argv) { assert(argc==2);errno=EAGAIN;madeira_steam_probe_dependencies(argv[1]);assert(errno==EAGAIN);return 0; }
''')
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-I'+str(root/'app/Madeira'),str(source),'-o',str(binary)],check=True)
    result=subprocess.run([str(binary),str(steam)],capture_output=True,text=True,check=True)
    assert 'dir=bin file=SDL2.dll present=1 machine=014c read-error=0' in result.stderr
    assert 'dir=bin file=gldriverquery64.exe present=1 machine=8664 read-error=0' in result.stderr
    assert 'dir=bin file=vulkandriverquery.exe present=1 machine=014c read-error=0' in result.stderr
    assert 'dir=bin file=vulkandriverquery64.exe present=1 machine=8664 read-error=0' in result.stderr
    assert 'dir=bin/cef/cef.win7 file=vulkan-1.dll present=1 machine=014c read-error=0' in result.stderr
    assert 'dir=bin file=vulkan-1.dll present=0 scan-complete=1' in result.stderr
    assert 'dir=. file=SDL2.dll present=0 scan-complete=1' in result.stderr
    assert 'dir=. file=SDL3.dll present=1 machine=0000 read-error=' in result.stderr
    assert str(steam) not in result.stderr, 'private installation path leaked'
    assert before=={p:(hashlib.sha256(p.read_bytes()).digest(),p.stat().st_mtime_ns) for p in steam.rglob('*') if p.is_file()}
    print('PASS bounded Steam DLL inventory: case-insensitive names, x86/x64 architecture, invalid PE, missing files, unchanged file contents/times and errno')
