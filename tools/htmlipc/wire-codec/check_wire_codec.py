#!/usr/bin/env python3
"""Compile and run the host codec fixture with AddressSanitizer and UBSan."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

here=Path(__file__).resolve().parent
binary=here/'wire-codec-tests'
command=['/usr/bin/g++','-std=c++20','-O1','-g','-Wall','-Wextra','-Werror',
         '-fno-omit-frame-pointer','-fsanitize=address,undefined',
         '-fno-sanitize-recover=all','wire_codec.cpp','test_wire_codec.cpp',
         '-o',str(binary)]
subprocess.run(command,cwd=here,check=True)
environment=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                 UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
result=subprocess.run([str(binary)],cwd=here,env=environment,check=False,
                      text=True,capture_output=True)
print(result.stdout,end='')
if result.stderr: print(result.stderr,end='')
result.check_returncode()
(here/'results.json').write_text(json.dumps({
    'scope':'host full-frame wire codec fixture; fixture command IDs do not establish Steam command IDs',
    'compiler':'g++ host C++20','sanitizers':['address','undefined'],
    'command':command,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
    'output':result.stdout.strip(),'passed':True,
},indent=2)+'\n')
