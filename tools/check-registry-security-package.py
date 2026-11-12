#!/usr/bin/env python3
"""Require compiled registry-view handling in every packaged Wine architecture.

Compiler-to-linked-code provenance is not a Steam service or VAC verdict.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('registry_security_code', ROOT / 'tools/check-security-compat-package.py')
code = importlib.util.module_from_spec(spec)
spec.loader.exec_module(code)
MANIFEST = 'arm64ec-windows/madeira-registry-security.json'
FUNCTIONS = ('SetNamedSecurityInfoW', 'GetNamedSecurityInfoW')
SOURCES = ('build/wine-pe/registry-security-views.patch', 'build/wine-pe/registry-security-views.json',
           'build/wine-pe/build-registry-security.sh', 'tools/build/stage-registry-security-views.py',
           'tools/check-registry-security-package.py')


def inputs(source, repo):
    result = {name: code.digest(code.read(repo / name, 2 << 20)) for name in SOURCES}
    for name in ('dlls/advapi32/security.c', 'dlls/advapi32/advapi32.spec', 'dlls/advapi32/Makefile.in',
                 'include/accctrl.h', 'include/winnt.h'):
        result['wine/' + name] = code.digest(code.read(source / name, 2 << 20))
    reviewed = json.loads(code.read(repo / SOURCES[1]), object_pairs_hook=code.unique_object)
    assert reviewed['patchSHA256'] == result[SOURCES[0]], 'unreviewed registry security patch'
    assert reviewed['files']['dlls/advapi32/security.c']['beforeSHA256'] == result['wine/dlls/advapi32/security.c'], 'registry security source not restored or pin changed'
    return result


def build_proof(build_root, farm, image):
    data = code.read(Path(build_root) / code.TREES[farm] / 'dlls/advapi32' / farm / 'security.o')
    obj = code.Code(data)
    allowed = {0xa641, 0xaa64} if farm == 'arm64ec-windows' else {code.FARMS[farm]}
    assert obj.machine in allowed and not obj.pe, 'wrong registry security object architecture'
    records = [obj.proof(obj.function(name)) for name in FUNCTIONS]
    for proof in records:
        code.verify_proof(image, proof)
    return {'objectSHA256': code.digest(data), 'code': records}


def check(root, source, repo=ROOT, build_root=None, write=False, app=None, ipa=None):
    root, source, repo = Path(root), Path(source), Path(repo)
    provenance, images, payload, records = inputs(source, repo), {}, {}, {}
    for farm in code.FARMS:
        assert not (root / farm).is_symlink(), 'symlinked registry security farm'
        relative = farm + '/advapi32.dll'
        data = code.read(root / relative)
        records[relative] = code.PE.inspect(data, farm, required_export=FUNCTIONS[0])
        images[farm] = code.Code(data)
        for name in FUNCTIONS:
            images[farm].function(name)
        payload[relative] = data
    path = root / MANIFEST
    if write:
        assert build_root is not None, 'real compiler object tree required'
        value = {'recipe': 1, 'sources': provenance, 'dlls': records,
                 'compiled': {farm: build_proof(build_root, farm, images[farm]) for farm in code.FARMS}}
        pending = path.with_suffix('.json.pending')
        assert not path.is_symlink() and not pending.exists() and not pending.is_symlink(), 'unowned registry security manifest'
        pending.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
        pending.replace(path)
    raw = code.read(path, 2 << 20)
    value = json.loads(raw, object_pairs_hook=code.unique_object)
    assert set(value) == {'recipe', 'sources', 'dlls', 'compiled'} and value['recipe'] == 1, 'invalid registry security provenance'
    assert value['sources'] == provenance and value['dlls'] == records, 'stale registry security source or packaged DLL'
    assert set(value['compiled']) == set(code.FARMS), 'missing registry security architecture'
    for farm, proof in value['compiled'].items():
        assert set(proof) == {'objectSHA256', 'code'} and re.fullmatch('[0-9a-f]{64}', proof['objectSHA256']), 'invalid registry security object proof'
        assert [code.canonical(x['symbol']) for x in proof['code']] == list(FUNCTIONS), 'missing registry security function proof'
        for record in proof['code']:
            code.verify_proof(images[farm], record)
        if build_root is not None:
            assert proof == build_proof(build_root, farm, images[farm]), 'stale registry security compiler object'
    payload[MANIFEST] = raw
    if app:
        for relative, data in payload.items():
            assert code.read(Path(app) / relative) == data, 'stale app registry security component: ' + relative
    if ipa:
        with zipfile.ZipFile(ipa) as archive:
            for relative, data in payload.items():
                entries = [e for e in archive.infolist() if e.filename == 'Payload/Madeira.app/' + relative]
                assert len(entries) == 1 and entries[0].file_size == len(data), 'missing, duplicated or stale IPA registry security component'
                with archive.open(entries[0]) as stream:
                    assert stream.read(len(data) + 1) == data, 'substituted IPA registry security component'
    print('PASS registry security package: all 3 ABIs, actual compiler-to-linked function proofs, source hashes and exact requested app/IPA bytes; no VAC verdict')
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT / 'wine')
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    parser.add_argument('--build-root', type=Path)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--app', type=Path)
    parser.add_argument('--ipa', type=Path)
    args = parser.parse_args()
    check(args.root, args.source_root, args.repo_root, args.build_root, args.write, args.app, args.ipa)
