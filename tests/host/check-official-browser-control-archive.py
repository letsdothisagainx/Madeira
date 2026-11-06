#!/usr/bin/env python3
"""Exercise the exact control parser with Windows ZIP names and hostile inputs."""
from pathlib import Path
import importlib.util
import io
import stat
import zipfile
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('official_archive',ROOT/'tests/integration/htmlipc/official_archive.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

def run(entries):
    raw=io.BytesIO()
    with zipfile.ZipFile(raw,'w',compression=zipfile.ZIP_STORED) as archive:
        for name,value in entries:archive.writestr(name,value)
    seen=[]
    with zipfile.ZipFile(io.BytesIO(raw.getvalue())) as archive:
        rows=list(module.validated_members(archive,lambda old,new:seen.append((old,new))))
        # Read through the original ZipInfo; normalization must never bypass the
        # original raw local-header identity or the actual member CRC check.
        return [(p.as_posix(),archive.read(entry)) for entry,p in rows],seen

def reject(entries):
    try:run(entries)
    except (AssertionError,ValueError,zipfile.BadZipFile):return
    raise AssertionError('accepted hostile archive identity')

rows,seen=run([(r'bin\cef\cef.win7\libcef.dll',b'library'),('bin/cef/cef.win7/locales/',b''),(r'bin\cef\cef.win7\locales\en-US.pak',b'locale')])
assert rows==[('bin/cef/cef.win7/libcef.dll',b'library'),('bin/cef/cef.win7/locales/en-US.pak',b'locale')]
assert seen[0]==(r'bin\cef\cef.win7\libcef.dll','bin/cef/cef.win7/libcef.dll')
assert module.normalized_member('bin\\cef\\cef.win7\\')==(Path('bin/cef/cef.win7'),True)
for name in ['', '/', '\\', '../escape',r'bin\..\escape',r'..\escape',r'\absolute',r'\\server\share',r'C:\escape','C:relative','bin//child','bin/./child','bin/.','bin/child.','bin/child ','bin/child\x01','bin/child\x00suffix','x'*240]:
    try:module.normalized_member(name)
    except AssertionError:pass
    else:raise AssertionError('accepted hostile path')
reject([(r'bin\cef\cef.win7\libcef.dll',b'a'),('bin/cef/cef.win7/libcef.dll',b'b')])
reject([('bin/cef/A.dll',b'a'),(r'bin\cef\a.dll',b'b')])
reject([('bin/cef/',b''),(r'bin\cef',b'file')])
reject([('bin/cef/',b'nonempty-directory')])
link=zipfile.ZipInfo('bin/cef/link');link.create_system=3;link.external_attr=(stat.S_IFLNK|0o777)<<16
reject([(link,b'target')])
pipe=zipfile.ZipInfo('bin/cef/pipe');pipe.create_system=3;pipe.external_attr=(stat.S_IFIFO|0o600)<<16
reject([(pipe,b'')])
# Exercise metadata that ZipFile writers sanitize rather than serialize verbatim.
class Archive:
    def __init__(self,entry):self.entry=entry
    def infolist(self):return [self.entry]
for field,value in [('flag_bits',1),('compress_type',99),('orig_filename','bin/cef/libcef.dll\0private')]:
    entry=zipfile.ZipInfo('bin/cef/libcef.dll');setattr(entry,field,value)
    try:list(module.validated_members(Archive(entry)))
    except AssertionError:pass
    else:raise AssertionError('accepted hostile metadata')
# Source guard: production normalization ordering remains the reference, and
# this fixture fix does not change Swift's integrity or extraction implementation.
source=(ROOT/'app/Madeira/SteamRuntime.swift').read_text()
assert source.index('let normalizedName = rawName.replacingOccurrences')<source.index('try need(validPath(name) && seen.insert')
control=(ROOT/'tests/integration/check-official-steam-browser-bootstrap.py').read_text()
assert 'official_archive.py' in control and 'validated_members' in control
print('PASS official-browser control Windows ZIP normalization before traversal/duplicate checks; original raw entry reads, CRC path, directories, cross-separator/case collisions, traversal/UNC/drive/control/NUL/symlink/unsupported metadata rejected')
