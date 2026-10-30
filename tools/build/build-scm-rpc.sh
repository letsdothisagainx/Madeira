#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WINE="$ROOT/wine"
# Keep the published Wine pin: apply a reviewed, versioned loader overlay only
# during the PE build, then restore the exact original source even on failure.
for file in dlls/ntdll/loader.c dlls/ntdll/unixlib.h dlls/sechost/Makefile.in; do
  git -C "$WINE" diff --quiet HEAD -- "$file" || {
    echo "Refusing to overwrite local Wine changes: $file" >&2; exit 1;
  }
done
HEADER="$WINE/dlls/ntdll/madeira_scm_aux_slot.h"
[[ ! -e "$HEADER" ]] || { echo "Refusing to overwrite $HEADER" >&2; exit 1; }
TMP="$(mktemp -d)"
cp "$WINE/dlls/ntdll/loader.c" "$TMP/loader.c"
cp "$WINE/dlls/ntdll/unixlib.h" "$TMP/unixlib.h"
cleanup() {
  cp "$TMP/loader.c" "$WINE/dlls/ntdll/loader.c"
  cp "$TMP/unixlib.h" "$WINE/dlls/ntdll/unixlib.h"
  rm -f "$HEADER"
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
git -C "$WINE" apply "$ROOT/build/scm-rpc/loader.patch"
cp "$ROOT/build/scm-rpc/aux-slot.h" "$HEADER"
run_build "$ROOT/build/wine-pe/build-ntdll.sh"
# Eagerly resolve the SCM import; the loader now also fills its native aux slot.
# build-modules restores its temporary Makefile edit on success or failure.
UNDELAY=1 run_build "$ROOT/build/wine-pe/build-modules.sh" sechost
python3 "$ROOT/tools/check-scm-rpc-image.py" "$ROOT/app/Madeira/arm64ec-windows/sechost.dll" "$ROOT/app/Madeira/arm64ec-windows/ntdll.dll"
