#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WINE="$ROOT/wine"
TC="$ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
export PATH="$TC:$PATH"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 8)}"
# Keep the published Wine pin: apply reviewed, versioned SCM overlays only
# during the PE build, then restore the exact original source even on failure.
for file in dlls/ntdll/loader.c dlls/ntdll/unixlib.h dlls/sechost/Makefile.in programs/services/services.c; do
  git -C "$WINE" diff --quiet HEAD -- "$file" || {
    echo "Refusing to overwrite local Wine changes: $file" >&2; exit 1;
  }
done
HEADER="$WINE/dlls/ntdll/madeira_scm_aux_slot.h"
[[ ! -e "$HEADER" ]] || { echo "Refusing to overwrite $HEADER" >&2; exit 1; }
HTMLIPC_HEADERS=(madeira_htmlipc_pe_loader.h htmlipc_policy.h htmlipc_ready_abi.h)
for name in "${HTMLIPC_HEADERS[@]}"; do
  [[ ! -e "$WINE/dlls/ntdll/$name" ]] || { echo "Refusing to overwrite $name" >&2; exit 1; }
done
TMP="$(mktemp -d)"
cp "$WINE/dlls/ntdll/loader.c" "$TMP/loader.c"
cp "$WINE/dlls/ntdll/unixlib.h" "$TMP/unixlib.h"
cp "$WINE/programs/services/services.c" "$TMP/services.c"
cleanup() {
  cp "$TMP/loader.c" "$WINE/dlls/ntdll/loader.c"
  cp "$TMP/unixlib.h" "$WINE/dlls/ntdll/unixlib.h"
  cp "$TMP/services.c" "$WINE/programs/services/services.c"
  rm -f "$HEADER"
  for name in "${HTMLIPC_HEADERS[@]}"; do rm -f "$WINE/dlls/ntdll/$name"; done
  rm -rf "$TMP"
}
trap cleanup EXIT
# Expose compiler diagnostics in public Actions annotations as well as logs.
run_build() {
  local status=0
  "$@" > "$TMP/build.log" 2>&1 || status=$?
  cat "$TMP/build.log"
  if [[ "$status" != 0 ]]; then
    python3 - "$TMP/build.log" <<'PY'
import sys
from pathlib import Path
lines=Path(sys.argv[1]).read_text(errors='replace').splitlines()
errors=[s for s in lines if 'error:' in s.lower() or 'undefined symbol' in s.lower() or 'no rule to make' in s.lower()]
for s in (errors or lines[-6:])[:8]:
    print('::error::'+s.replace('%','%25').replace('\r','%0D').replace('\n','%0A'))
PY
    return "$status"
  fi
}
git -C "$WINE" apply --check "$ROOT/build/scm-rpc/loader.patch"
git -C "$WINE" apply --check "$ROOT/build/scm-rpc/services.patch"
git -C "$WINE" apply "$ROOT/build/scm-rpc/loader.patch"
git -C "$WINE" apply "$ROOT/build/scm-rpc/services.patch"
git -C "$WINE" apply --check "$ROOT/build/scm-rpc/htmlipc-loader.patch"
git -C "$WINE" apply "$ROOT/build/scm-rpc/htmlipc-loader.patch"
cp "$ROOT/build/scm-rpc/htmlipc_pe_loader.h" "$WINE/dlls/ntdll/madeira_htmlipc_pe_loader.h"
cp "$ROOT/build/scm-rpc/htmlipc_policy.h" "$WINE/dlls/ntdll/htmlipc_policy.h"
cp "$ROOT/build/scm-rpc/htmlipc_ready_abi.h" "$WINE/dlls/ntdll/htmlipc_ready_abi.h"
cp "$ROOT/build/scm-rpc/aux-slot.h" "$HEADER"
run_build "$ROOT/build/wine-pe/build-ntdll.sh"
# Eagerly resolve the SCM import; the loader now also fills its native aux slot.
# build-modules restores its temporary Makefile edit on success or failure.
UNDELAY=1 run_build "$ROOT/build/wine-pe/build-modules.sh" sechost
python3 "$ROOT/tools/check-scm-rpc-image.py" "$ROOT/app/Madeira/arm64ec-windows/sechost.dll" "$ROOT/app/Madeira/arm64ec-windows/ntdll.dll"

# The shipped SCM is native AA64, including its existing crosslink in an
# ARM64EC session. Rebuild that producer without changing the selected CPU.
B="$WINE/build-macos"
[[ -f "$B/config.status" ]] || { echo "Missing Wine build tree: run tools/build/build-wine.sh first" >&2; exit 1; }
target="programs/services/aarch64-windows/services.exe"
# A restored host cache must not satisfy this target with the unpatched SCM.
rm -f "$B/programs/services/aarch64-windows/services.o" "$B/$target"
run_build make -C "$B" -j"$JOBS" "$target"
out="$ROOT/app/Madeira/aarch64-windows/services.exe"
mkdir -p "$(dirname "$out")"
cp "$B/$target" "$TMP/services.exe"
"$TC/aarch64-w64-mingw32-strip" --strip-debug "$TMP/services.exe"
python3 - "$TMP/services.exe" <<'PY'
import struct, sys
from pathlib import Path
d = Path(sys.argv[1]).read_bytes()
pe = struct.unpack_from('<I', d, 0x3c)[0]
assert d[:2] == b'MZ' and d[pe:pe+4] == b'PE\0\0', 'invalid rebuilt SCM PE'
assert struct.unpack_from('<H', d, pe+4)[0] == 0xaa64, 'incorrect SCM architecture'
assert b'[scm-pipe-wait-v1]' in d, 'stale SCM: timeout overlay missing'
PY
mv "$TMP/services.exe" "$out"
ls -l "$out"
