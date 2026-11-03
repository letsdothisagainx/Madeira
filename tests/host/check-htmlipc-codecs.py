#!/usr/bin/env python3
"""Exercise actual command/stream codecs; no Steam image or network needed."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='madeira-htmlipc-codecs-') as folder:
    tmp=Path(folder);flags=['-fno-pie','-no-pie'] if sys.platform.startswith('linux') else []
    for kind in ('wire','stream'):
        binary=tmp/kind;codec=ROOT/f'build/htmlipc/{kind}-codec'
        sources=[codec/f'{kind}_codec.cpp',ROOT/f'tests/host/htmlipc/test_{kind}_codec.cpp']
        if kind=='stream':sources.append(ROOT/'build/htmlipc/wire-codec/wire_codec.cpp')
        subprocess.run([os.environ.get('CXX','c++'),'-std=c++20','-O1','-g','-Wall','-Wextra','-Werror',
                        '-pthread','-fsanitize=address,undefined','-fno-omit-frame-pointer',*flags,
                        '-I'+str(codec),*map(str,sources),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True,timeout=60)
print('PASS HTMLIPC real codecs: command pairing/framing and preserved original stream behavior')
