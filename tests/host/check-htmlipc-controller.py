#!/usr/bin/env python3
"""Installed-state controller validation logic, without a Steam image or Wine."""
from pathlib import Path
import os, platform, subprocess, sys, tempfile
root=Path(__file__).resolve().parents[2]
if platform.machine().lower() not in ('amd64','x86_64'):
    print('SKIP controller logic fixture requires AMD64; the controller-image Actions job runs it on Linux AMD64')
    raise SystemExit(0)
with tempfile.TemporaryDirectory(prefix='madeira-controller-image-') as folder:
    binary=Path(folder)/'controller'
    flags=['-fno-pie','-no-pie'] if sys.platform.startswith('linux') else []
    subprocess.run([os.environ.get('CXX','c++'),'-std=c++20','-O1','-g','-D_WIN64=1',
        '-fsanitize=address,undefined','-fno-omit-frame-pointer',*flags,
        '-I'+str(root/'build/htmlipc/stream-install'),
        str(root/'build/htmlipc/stream-install/installer.cpp'),
        str(root/'tests/host/htmlipc/test_controller_protection.cpp'),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=30)
