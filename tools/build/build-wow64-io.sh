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
assert b'madeira-io-abi-v1' in data, 'stale WoW64 IOSB producer'
size = struct.unpack_from('<I', data, pe + 24 + 56)[0]
if len(data) < size: path.write_bytes(data + bytes(size - len(data)))
print('PASS native ARM64 WoW64 IOSB producer rebuilt')
PY
