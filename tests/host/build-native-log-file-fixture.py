#!/usr/bin/env python3
"""Compile the actual staged NtCreateFile body with a temporary POSIX backend.

The path resolver/open backend are explicit test adapters, not a replacement
Wine server. Production routing/ownership and NtCreateFile control flow are
executed unchanged. This does not claim an on-device or stock-Wine interposer.
"""
from pathlib import Path
import argparse
import os
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]

def function(source,signature):
    begin=source.index(signature);cursor=source.index('{',begin)+1;depth=1
    while depth:
        depth+=(source[cursor]=='{')-(source[cursor]=='}');cursor+=1
    return source[begin:cursor]

def build(output):
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    original=(ROOT/'wine/dlls/ntdll/unix/file.c').read_text()
    with tempfile.TemporaryDirectory(prefix='native-log-handler-') as folder:
        temporary=Path(folder);staged=temporary/'file.c';staged.write_text(original)
        subprocess.run(['python3',str(ROOT/'tools/build/stage-htmlipc-log-file.py'),str(staged)],check=True)
        body=function(staged.read_text(),'NTSTATUS WINAPI NtCreateFile(')
        baseline=function(original,'NTSTATUS WINAPI NtCreateFile(').replace('NtCreateFile(','BaselineNtCreateFile(',1)
        harness=(ROOT/'tests/host/htmlipc/test_native_log_file.c').read_text()
        assert harness.count('/*production-native-file-bodies*/')==1
        harness=harness.replace('/*production-native-file-bodies*/',baseline+'\n'+body)
        source=temporary/'native-log-file.c';source.write_text(harness)
        subprocess.run([os.environ.get('CC','cc'),'-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
            '-Wno-misleading-indentation','-Wno-unused-parameter','-Wno-unused-function','-Wno-sign-compare',
            '-fsanitize=address,undefined','-fno-sanitize-recover=all',
            '-I'+str(ROOT/'build/ntdll-unix'),str(source),'-o',str(output)],check=True)
    return output

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();build(args.output)
