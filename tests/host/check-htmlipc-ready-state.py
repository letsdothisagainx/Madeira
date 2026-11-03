#!/usr/bin/env python3
"""Run exact native Ready DATA publisher under host ASan/UBSan."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='madeira-htmlipc-ready-') as folder:
    binary=Path(folder)/'ready'
    flags=['-fno-pie','-no-pie'] if sys.platform.startswith('linux') else []
    command=[os.environ.get('CXX','c++'),'-std=c++20','-O1','-g','-Wall','-Wextra','-Werror',
             '-pthread','-fno-omit-frame-pointer','-fsanitize=address,undefined',
             '-fno-sanitize-recover=all',*flags,'-I'+str(ROOT/'build/scm-rpc'),
             '-I'+str(ROOT/'build/htmlipc/runtime'),str(ROOT/'build/htmlipc/runtime/ready_state.cpp'),
             str(ROOT/'tests/host/htmlipc/test_ready_state.cpp'),'-o',str(binary)]
    subprocess.run(command,check=True)
    environment=dict(os.environ,ASAN_OPTIONS=('detect_leaks=0:halt_on_error=1' if sys.platform == 'darwin' else 'detect_leaks=1:halt_on_error=1'),UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    modes=['valid',*[f'owner{i}' for i in range(7)],'partial','stock','revoke','detach','busy','wrap','writers',*['race']*12]
    for mode in modes:subprocess.run([str(binary),mode],check=True,env=environment,timeout=30)
print('PASS HTMLIPC Ready DATA: ABI80, all owner/mode guards, sticky failures/detach, bounded publication and concurrent revoke races')
