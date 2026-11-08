#!/usr/bin/env bash
# One source-overlay transaction owns both PE builds; they must not race.
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
backend="${1:-both}"
case "$backend" in wow64|arm64ec|both) ;; *) echo "Invalid FEX PE backend: $backend" >&2; exit 1;; esac
lock="$ROOT/FEX/.madeira-pe-overlay.lock"
if ! mkdir "$lock"; then
  echo "Another FEX PE overlay build owns $lock" >&2
  exit 1
fi
state="$(mktemp -d)"
cleanup() {
  local status=$?
  if [[ -f "$state/manifest.json" ]]; then
    if ! python3 "$ROOT/tools/build/stage-fex-compat.py" restore "$state"; then
      echo "FEX overlay restoration failed; originals retained at $state" >&2
      rmdir "$lock"
      exit 1
    fi
  fi
  rm -rf "$state"
  rmdir "$lock"
  exit "$status"
}
trap cleanup EXIT
python3 "$ROOT/tools/build/stage-fex-compat.py" apply "$state" --backend "$backend"
if [[ "$backend" != arm64ec ]]; then
  bash "$ROOT/build/fex-wow64/build.sh"
fi
if [[ "$backend" != wow64 ]]; then
  bash "$ROOT/build/fex-arm64ec/build.sh"
fi
python3 - "$ROOT" "$backend" <<'PY'
from pathlib import Path
import runpy, struct, sys
root = Path(sys.argv[1])
check = runpy.run_path(str(root / 'tools/check-io-abi-package.py'))
for backend, relative in (('wow64', 'aarch64-windows/xtajit.dll'), ('arm64ec', 'arm64ec-windows/xtajit64.dll')):
    if sys.argv[2] not in (backend, 'both'):
        continue
    path = root / 'app/Madeira' / relative
    data = path.read_bytes()
    check['fex_cpu'](data, backend)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    size = struct.unpack_from('<I', data, pe + 24 + 56)[0]
    if len(data) < size:
        path.write_bytes(data + bytes(size - len(data)))
    print(f'PASS rebuilt {backend} FEX CPU allocator/startup/arena contract')
PY
