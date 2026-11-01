#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TC="${LLVM_MINGW:-$ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin}"
CC="$TC/i686-w64-mingw32-clang"
OUT="$ROOT/app/Madeira/i386-windows"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
"$CC" -std=c11 -O2 -Wall -Wextra -Werror -shared -static \
  -Wl,--strip-all -Wl,--no-insert-timestamp -Wl,--kill-at \
  "$ROOT/build/wow64-probe/module.c" -lopengl32 -o "$TMP/madeira-wow64-module-probe.dll"
"$CC" -std=c11 -O2 -Wall -Wextra -Werror -static \
  -Wl,--strip-all -Wl,--no-insert-timestamp \
  "$ROOT/build/wow64-probe/main.c" -o "$TMP/madeira-wow64-probe.exe"
mkdir -p "$OUT"
cp "$TMP/madeira-wow64-probe.exe" "$TMP/madeira-wow64-module-probe.dll" "$OUT/"
echo 'Built i386 loader/TLS/OpenGL probe (not executed on this build host)'
