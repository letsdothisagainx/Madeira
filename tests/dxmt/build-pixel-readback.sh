#!/usr/bin/env bash
# Build an ordinary x64 PE for the existing FEX/ARM64EC launch path. Never mark
# it Wine builtin: that would test a different path from the x64 game.
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
MINGW="$ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
PIXEL_CC="${PIXEL_CC:-$MINGW/x86_64-w64-mingw32-clang}"
PIXEL_OUT="${PIXEL_OUT:-$ROOT/app/Madeira/arm64ec-windows/pixel-readback-x64.exe}"
[[ -x "$PIXEL_CC" ]] || { echo "ERROR: missing x64 compiler: $PIXEL_CC" >&2; exit 1; }
mkdir -p "$(dirname "$PIXEL_OUT")"
temporary="$(mktemp "${PIXEL_OUT}.XXXXXX")"
trap 'rm -f "$temporary"' EXIT
"$PIXEL_CC" -std=c11 -O2 -Wall -Wextra -Werror -static \
    "$ROOT/tests/dxmt/pixel-readback.c" -ld3d11 -lm -o "$temporary"
python3 "$ROOT/tests/host/check-dxmt-pixel-probe.py" --image "$temporary"
mv "$temporary" "$PIXEL_OUT"
echo "Built DXMT pixel probe: $PIXEL_OUT (GPU readbacks are checked when launched)"
