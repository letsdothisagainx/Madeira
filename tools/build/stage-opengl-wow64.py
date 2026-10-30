#!/usr/bin/env python3
"""Stage the reviewed iOS OpenGL Unix overlay without changing the Wine pin."""
import argparse
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FILES = ('unix_private.h', 'unix_wgl.c', 'unix_thunks.c')

def stage(source, destination):
    target = destination / 'dlls/opengl32'
    target.mkdir(parents=True)
    for name in FILES:
        shutil.copyfile(source / 'dlls/opengl32' / name, target / name)
    includes = ['--include=dlls/opengl32/' + name for name in FILES]
    # The generated thunks are already in this patch: no registry downloads or
    # generator/version drift, and no edits to the shared Wine checkout.
    for patch in [ROOT/'patches/wine-opengl-winios.patch', ROOT/'build/opengl-wow64/thread-attach.patch']:
        command = ['git', '-C', str(destination), 'apply', *includes]
        forward = subprocess.run([*command, '--check', str(patch)], capture_output=True)
        if forward.returncode:
            # Explicit developer PE builds may already have the documented
            # overlay applied. Accept only a complete reversible application.
            subprocess.run([*command, '--reverse', '--check', str(patch)], check=True)
        else:
            subprocess.run([*command, str(patch)], check=True)
    text = (target/'unix_private.h').read_text()
    assert 'TEB32 *teb32_ptr = ios_wow_host_ptr( teb32 );' in text
    assert 'TEB32 *teb32_ptr = ULongToPtr( teb32 );' not in text
    print('OpenGL Unix side: staged window-aware TEB and generated pointer thunks')
    return target

if __name__ == '__main__':
    ap=argparse.ArgumentParser();ap.add_argument('destination',type=Path);ap.add_argument('--wine',type=Path,default=ROOT/'wine')
    args=ap.parse_args();stage(args.wine.resolve(),args.destination.resolve())
