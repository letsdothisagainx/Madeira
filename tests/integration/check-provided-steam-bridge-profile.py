#!/usr/bin/env python3
"""Exercise a reviewed, locally supplied core with the real production installer.

No network access or implicit downloads. The proprietary input is not copied
into the repository or executed. The host fixture maps original PE bytes, applies
DIR64 relocations and changes only its owned private mappings. This establishes
installer behavior, not Steam/CEF/iPhone runtime readiness or certificate trust.
"""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BASELINE = 'b44797931491de55e98218fbe6181025952d5c7f'
CORE_SHA256 = '872c1373defbe853260b5eed5e8b25ab85a680a05b1801cb12e01df7aabb1736'
CORE_BYTES = 1_667_224


def digest(path):
    state = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1 << 20), b''):
            state.update(chunk)
    return state.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core-file', type=Path, required=True,
                        help='read-only reviewed original chromehtml.dll')
    parser.add_argument('--baseline-revision', default=BASELINE,
                        help='already present Git revision; no history is fetched')
    args = parser.parse_args()
    if sys.platform != 'linux' or platform.machine().lower() not in ('x86_64', 'amd64'):
        parser.error('actual mapped-file fixture requires Linux AMD64 with 4 KiB pages')
    core = args.core_file.resolve(strict=True)
    if not core.is_file() or core.stat().st_size != CORE_BYTES or digest(core) != CORE_SHA256:
        parser.error('supplied bytes do not match the complete reviewed core identity')
    install = ROOT / 'build/htmlipc/stream-install'
    with tempfile.TemporaryDirectory(prefix='madeira-provided-bridge-profile-') as folder:
        folder = Path(folder)
        baseline = folder / 'baseline'
        baseline.mkdir()
        for name in ('installer.cpp', 'installer.h'):
            result = subprocess.run(
                ['git', '-C', str(ROOT), 'show', args.baseline_revision + ':build/htmlipc/stream-install/' + name],
                capture_output=True, check=False)
            if result.returncode:
                parser.error('baseline source is unavailable locally; no history/network fetch attempted')
            (baseline / name).write_bytes(result.stdout)
        for label, source, defines in (
                ('baseline', baseline, ['-DMADEIRA_REJECT_PROVIDED_PROFILE=1']),
                ('corrected', install, [])):
            binary = folder / (label + '-fixture')
            command = [os.environ.get('CXX', 'c++'), '-std=c++20', '-O1', '-g', '-D_WIN64=1', *defines,
                       '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
                       '-I' + str(source), '-I' + str(install), str(source / 'installer.cpp'),
                       str(ROOT / 'tests/integration/htmlipc/bridge_profile_fixture.cpp'), '-o', str(binary)]
            subprocess.run(command, check=True, timeout=120)
            subprocess.run([str(binary), str(core)], check=True, timeout=90)
    if core.stat().st_size != CORE_BYTES or digest(core) != CORE_SHA256:
        raise AssertionError('read-only supplied core changed during validation')
    print('PASS reviewed supplied core: original production rejection and corrected mapped-file installer, '
          'native W^X, rollback, tamper and unload checks; source file unchanged; no Valve code executed')


if __name__ == '__main__':
    main()
