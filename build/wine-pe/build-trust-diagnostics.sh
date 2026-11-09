#!/usr/bin/env bash
# Rebuild Wine's actual verifier with bounded result observation in every farm.
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
TC="$ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
export PATH="$TC:$PATH"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 8)}"
WINE="$ROOT/wine"
for tree in build-macos build-arm64ec build-i386; do
    [[ -f "$WINE/$tree/Makefile" ]] || { echo "Missing configured Wine tree: $tree" >&2; exit 1; }
done
STATE="$(mktemp -d)"
python3 "$ROOT/tools/build/stage-trust-diagnostics.py" apply "$STATE/source" --source "$WINE"
cleanup() {
    status=$?
    if ! python3 "$ROOT/tools/build/stage-trust-diagnostics.py" restore "$STATE/source"; then
        echo "Trust observer restoration failed; backup retained at $STATE" >&2; exit 1
    fi
    if [[ "$status" == 0 ]]; then
        if ! python3 "$ROOT/tools/check-trust-diagnostics-package.py" --root "$ROOT/app/Madeira" \
             --source-root "$WINE" --repo-root "$ROOT" --write; then
            status=1
        fi
    fi
    rm -rf "$STATE"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for config in 'build-macos:aarch64:aarch64-windows' 'build-arm64ec:arm64ec:arm64ec-windows' 'build-i386:i686:i386-windows'; do
    IFS=: read -r tree triple farm <<< "$config"
    target="dlls/wintrust/$farm/wintrust.dll"
    rm -f "$WINE/$tree/dlls/wintrust/$farm/wintrust_main.o" "$WINE/$tree/$target"
    make -C "$WINE/$tree" -j"$JOBS" "$target"
    if [[ "$farm" != i386-windows ]]; then
        python3 "$ROOT/tools/check-trust-diagnostics-object.py" "$WINE/$tree/dlls/wintrust/$farm/wintrust_main.o"
    fi
    mkdir -p "$ROOT/app/Madeira/$farm"
    "$TC/$triple-w64-mingw32-strip" --strip-debug -o "$STATE/wintrust.dll" "$WINE/$tree/$target"
    python3 - "$STATE/wintrust.dll" <<'PY'
import sys
from pathlib import Path
if b'[trust-result-v1]' not in Path(sys.argv[1]).read_bytes():
    raise SystemExit('built wintrust.dll has no owned observer marker')
PY
    cp "$STATE/wintrust.dll" "$ROOT/app/Madeira/$farm/wintrust.dll.pending"
    mv "$ROOT/app/Madeira/$farm/wintrust.dll.pending" "$ROOT/app/Madeira/$farm/wintrust.dll"
done
