# SPDX-License-Identifier: MIT
"""Strict path/metadata selection for the disposable official-browser control.

Matches SteamRuntimeFiles.unpack/validPath Windows-separator policy. This is a
fixture helper; production cache verification and package pins are unchanged.
"""
from pathlib import PurePosixPath
import stat


def normalized_member(raw):
    # Match production: normalize Windows separators before every traversal,
    # ambiguity and duplicate test. Do not let PurePath erase dot/empty parts.
    normalized=raw.replace('\\','/')
    directory=normalized.endswith('/')
    name=normalized[:-1] if directory else normalized
    assert name and len(name.encode('utf-8'))<240
    assert '\\' not in name and ':' not in name and not any(ord(c)<32 for c in name)
    assert all(part not in ('','.','..') and not part.endswith(('.',' ')) for part in name.split('/'))
    path=PurePosixPath(name)
    assert not path.is_absolute()
    return path,directory


def validated_members(archive,on_legacy_rejection=None):
    entries=archive.infolist()
    assert len(entries)<5000 and sum(x.file_size for x in entries)<768*1024**2
    seen=set()
    for entry in entries:
        # Python truncates embedded NULs in filename, preserving orig_filename.
        # Never adopt a different canonical identity from the archive's raw one.
        assert entry.orig_filename==entry.filename
        path,directory=normalized_member(entry.filename)
        canonical=path.as_posix()
        assert not entry.flag_bits&1 and entry.compress_type in (0,8)
        assert stat.S_IFMT(entry.external_attr>>16) in (0,stat.S_IFREG,stat.S_IFDIR)
        assert canonical.lower() not in seen;seen.add(canonical.lower())
        assert entry.file_size<=256*1024**2
        if directory:assert entry.file_size==0 and entry.compress_size==0
        if on_legacy_rejection:
            old=PurePosixPath(entry.filename)
            if not (old.parts and not old.is_absolute() and '..' not in old.parts and '\\' not in entry.filename and ':' not in entry.filename):
                on_legacy_rejection(entry.filename,canonical)
        if not directory:yield entry,path
