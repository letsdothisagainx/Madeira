#!/usr/bin/env bash
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
export PATH="$ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin:$PATH"
test -f "$ROOT/wine/include/wine/ios_io_abi.h"
# The i386 backend imports the native aarch64 wow64 DLL; it is not an i386
# image or an ARM64EC DLL. Rebuild the actual producer, not a replacement API.
make -C "$ROOT/wine/build-macos" -j"${JOBS:-8}" dlls/wow64/aarch64-windows/wow64.dll
output="$ROOT/app/Madeira/aarch64-windows/wow64.dll"
cp "$ROOT/wine/build-macos/dlls/wow64/aarch64-windows/wow64.dll" "$output"
"$ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin/aarch64-w64-mingw32-strip" --strip-debug "$output"
python3 - "$output" <<'PY'
from pathlib import Path
import struct, sys
path = Path(sys.argv[1]); data = path.read_bytes()
pe = struct.unpack_from('<I', data, 0x3c)[0]
assert struct.unpack_from('<H', data, pe + 4)[0] == 0xaa64, 'wow64.dll must be native ARM64'
assert b'madeira-io-abi-v2' in data, 'stale WoW64 IOSB producer'
size = struct.unpack_from('<I', data, pe + 24 + 56)[0]
if len(data) < size: path.write_bytes(data + bytes(size - len(data)))
print('PASS native ARM64 WoW64 IOSB producer rebuilt')
PY

# Rebuild the actual guest32 caller so query/protect failures are visible even
# when WriteProcessMemory never reaches the native NtWriteVirtualMemory path.
if [[ ! -f "$ROOT/wine/build-i386/Makefile" ]]; then
  mkdir -p "$ROOT/wine/build-i386"
  (cd "$ROOT/wine/build-i386" && ../configure --enable-archs=i386 --without-x --without-vulkan \
      --without-freetype --without-gnutls --disable-tests --enable-winegstreamer)
fi
# The native A64/EC source-built ntdll images receive this same small lifetime
# correction through stage-native-counter-writes. Rebuild the real guest32
# producer too, independently of the cached complete i386 farm. The sole
# source overlay is restored even if compilation/validation fails.
WAIT_TMP="$(mktemp -d)"
WAIT_STAGE="$ROOT/tools/build/stage-wait-address-lifetime.py"
cleanup_wait_lifetime() {
  local status=$?
  if ! python3 "$WAIT_STAGE" restore --wine "$ROOT/wine" --backup "$WAIT_TMP/source"; then
    echo "WaitOnAddress source restoration failed; preserving $WAIT_TMP" >&2
    return 1
  fi
  rm -rf "$WAIT_TMP"
  return "$status"
}
trap cleanup_wait_lifetime EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 "$WAIT_STAGE" apply --wine "$ROOT/wine" --backup "$WAIT_TMP/source"
rm -f "$ROOT/wine/build-i386/dlls/ntdll/i386-windows/sync.o" \
      "$ROOT/wine/build-i386/dlls/ntdll/i386-windows/ntdll.dll"
make -C "$ROOT/wine/build-i386" -j"${JOBS:-8}" dlls/ntdll/i386-windows/ntdll.dll
cp "$ROOT/wine/build-i386/dlls/ntdll/i386-windows/ntdll.dll" "$WAIT_TMP/ntdll.dll"
"$ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin/i686-w64-mingw32-strip" --strip-debug "$WAIT_TMP/ntdll.dll"
python3 - "$WAIT_TMP/ntdll.dll" <<'PY'
from pathlib import Path
import struct, sys
data = Path(sys.argv[1]).read_bytes()
pe = struct.unpack_from('<I', data, 0x3c)[0]
assert data[:2] == b'MZ' and data[pe:pe+4] == b'PE\0\0'
assert struct.unpack_from('<H', data, pe+4)[0] == 0x14c
assert b'[wait-address-lifetime-v1]' in data, 'stale guest32 WaitOnAddress lifetime'
print('PASS rebuilt guest32 WaitOnAddress retains stack nodes through waker unlink')
PY
mv "$WAIT_TMP/ntdll.dll" "$ROOT/app/Madeira/i386-windows/ntdll.dll"
cleanup_wait_lifetime
trap - EXIT INT TERM
make -C "$ROOT/wine/build-i386" -j"${JOBS:-8}" dlls/kernelbase/i386-windows/kernelbase.dll
cp "$ROOT/wine/build-i386/dlls/kernelbase/i386-windows/kernelbase.dll" "$ROOT/app/Madeira/i386-windows/kernelbase.dll"
"$ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin/i686-w64-mingw32-strip" --strip-debug "$ROOT/app/Madeira/i386-windows/kernelbase.dll"
python3 - "$ROOT/app/Madeira/i386-windows/kernelbase.dll" <<'PY'
from pathlib import Path
import struct, sys
data = Path(sys.argv[1]).read_bytes()
pe = struct.unpack_from('<I', data, 0x3c)[0]
assert struct.unpack_from('<H', data, pe + 4)[0] == 0x14c
assert b'[wpm-call-v1]' in data, 'stale guest32 WriteProcessMemory diagnostics'
assert b'[steam-arch-v1]' in data, 'stale Steam architecture observation producer'
print('PASS rebuilt i386 WriteProcessMemory caller includes bounded query/result diagnostics')
PY
