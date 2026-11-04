#!/usr/bin/env python3
"""Source registry semantics only: does not substitute for helper integration."""
from pathlib import Path
import os,subprocess,sys,tempfile
root=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='madeira-domain-') as directory:
    binary=Path(directory)/'domain'
    flags=['-fno-pie','-no-pie'] if sys.platform.startswith('linux') else []
    subprocess.run([os.environ.get('CXX','c++'),'-std=c++20','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',*flags,
        '-I'+str(root/'build/htmlipc/domain-routing'),str(root/'build/htmlipc/domain-routing/domain_registry.cpp'),str(root/'tests/host/htmlipc/test_domain_registry.cpp'),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=30)
