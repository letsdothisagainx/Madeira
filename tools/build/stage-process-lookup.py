#!/usr/bin/env python3
"""Stage bounded kernelbase failed-image attribution and restore exact inputs.

This overlay may be nested inside the maintained IOSB stage. It backs up the
current owned build copy, never checks out or edits a pinned Wine source.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT=Path(__file__).resolve().parents[2]
SOURCE=Path('dlls/kernelbase/process.c')
HEADER=Path('dlls/kernelbase/madeira_process_lookup_trace.h')


def digest(file):return hashlib.sha256(file.read_bytes()).hexdigest()


def stage(destination,source):
    assert (source/SOURCE).is_file() and not (source/SOURCE).is_symlink(),'lookup source must be a regular file'
    for path in(SOURCE,HEADER):
        assert not (destination/path).exists() and not (destination/path).is_symlink(),'refusing an existing lookup staging output'
    text=(source/SOURCE).read_text()
    include='WINE_DEFAULT_DEBUG_CHANNEL(process);'
    needle='        if (!(tidy_cmdline = get_file_name( cmd_line, name, ARRAY_SIZE(name) ))) return FALSE;'
    assert text.count(include)==1 and text.count(needle)==1,'kernelbase image lookup boundary changed'
    assert 'madeira_process_lookup_trace.h' not in text,'process lookup overlay already applied'
    text=text.replace(include,include+'\n\n#include "madeira_process_lookup_trace.h"',1)
    text=text.replace(needle,'''        if (!(tidy_cmdline = get_file_name( cmd_line, name, ARRAY_SIZE(name) )))
        {
            madeira_process_image_lookup_failed( cmd_line, GetLastError() );
            return FALSE;
        }''',1)
    (destination/SOURCE).parent.mkdir(parents=True,exist_ok=True)
    (destination/SOURCE).write_text(text)
    shutil.copyfile(ROOT/'build/wine-pe/process_lookup_trace.h',destination/HEADER)


def apply(state,source):
    assert not (source/HEADER).exists() and not (source/HEADER).is_symlink(),'refusing to overwrite an existing lookup trace header'
    assert not (state/'manifest.json').exists() and not (state/'manifest.json').is_symlink(),'refusing an existing lookup transaction'
    stage(state/'staged',source)
    original=state/'original';original.mkdir()
    shutil.copyfile(source/SOURCE,original/'process.c')
    manifest={'source':str(source.resolve()),'before':digest(source/SOURCE),'after':{str(p):digest(state/'staged'/p) for p in(SOURCE,HEADER)}}
    (state/'manifest.json').write_text(json.dumps(manifest))
    try:
        for p in(SOURCE,HEADER):shutil.copyfile(state/'staged'/p,source/p)
    except BaseException:
        shutil.copyfile(original/'process.c',source/SOURCE)
        (source/HEADER).unlink(missing_ok=True)
        raise


def restore(state):
    assert (state/'manifest.json').is_file() and not (state/'manifest.json').is_symlink(),'invalid lookup transaction manifest'
    manifest=json.loads((state/'manifest.json').read_text());source=Path(manifest['source'])
    for name,expected in manifest['after'].items():
        assert (source/name).is_file() and not (source/name).is_symlink() and digest(source/name)==expected,'refusing to discard build-time source changes: '+name
    original=state/'original/process.c'
    assert original.is_file() and not original.is_symlink() and digest(original)==manifest['before'],'invalid lookup source backup'
    shutil.copyfile(original,source/SOURCE)
    (source/HEADER).unlink()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('stage','apply','restore'))
    parser.add_argument('directory',type=Path)
    parser.add_argument('--source',type=Path,default=ROOT/'wine')
    args=parser.parse_args();args.directory.mkdir(parents=True,exist_ok=True)
    if args.operation=='stage':stage(args.directory,args.source)
    elif args.operation=='apply':apply(args.directory,args.source)
    else:restore(args.directory)
