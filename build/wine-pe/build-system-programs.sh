#!/usr/bin/env bash
# Build stock Wine registration utilities and the bounded pre-process lookup
# observer. These are real Windows programs; no installer result is invented.
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
TC="$ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
export PATH="$TC:$PATH"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 8)}"
WINE="$ROOT/wine"
for tree in build-macos build-arm64ec; do
  [[ -f "$WINE/$tree/Makefile" ]] || { echo "Missing configured Wine tree: $tree" >&2; exit 1; }
done
if [[ ! -f "$WINE/build-i386/Makefile" ]]; then
  # A warm app cache restores the I386 farm, not its compiler build tree.
  # Configure only this tree; never rebuild or replace cached I386 utilities.
  mkdir -p "$WINE/build-i386"
  (cd "$WINE/build-i386" && ../configure --enable-archs=i386 --without-x --without-vulkan \
      --without-freetype --without-gnutls --disable-tests --enable-winegstreamer)
fi
for name in regsvr32 rundll32; do
  [[ -s "$ROOT/app/Madeira/i386-windows/$name.exe" ]] || {
    echo "Missing stock I386 $name.exe; build the i386 farm before native registration utilities" >&2; exit 1;
  }
  git -C "$WINE" diff --quiet HEAD -- "programs/$name" || {
    echo "Refusing modified stock registration program: $name" >&2; exit 1;
  }
done
STATE="$(mktemp -d)"
python3 "$ROOT/tools/build/stage-process-lookup.py" apply "$STATE/source" --source "$WINE"
cleanup() {
  status=$?
  if ! python3 "$ROOT/tools/build/stage-process-lookup.py" restore "$STATE/source"; then
    echo "Failed to restore owned process lookup overlay; backup retained at $STATE" >&2;exit 1;
  fi
  rm -rf "$STATE"
  exit "$status"
}
trap cleanup EXIT
for config in 'build-macos:aarch64:aarch64-windows' 'build-arm64ec:arm64ec:arm64ec-windows' 'build-i386:i686:i386-windows'; do
  IFS=: read -r tree triple farm <<< "$config"
  B="$WINE/$tree"
  targets=("dlls/kernelbase/$farm/kernelbase.dll")
  if [[ "$farm" != i386-windows ]]; then
    targets+=("programs/regsvr32/$farm/regsvr32.exe" "programs/rundll32/$farm/rundll32.exe")
  fi
  # A restored build tree may have outputs newer than the owned source stage.
  # Invalidate only this known generated object and DLL before the patched build.
  rm -f "$B/dlls/kernelbase/$farm/process.o" "$B/dlls/kernelbase/$farm/kernelbase.dll"
  make -C "$B" -j"$JOBS" "${targets[@]}"
  mkdir -p "$ROOT/app/Madeira/$farm"
  for target in "${targets[@]}"; do
    name="$(basename "$target")"
    "$TC/$triple-w64-mingw32-strip" --strip-debug -o "$STATE/$name" "$B/$target"
    [[ ! -L "$ROOT/app/Madeira/$farm/$name" && ! -e "$ROOT/app/Madeira/$farm/$name.pending" && ! -L "$ROOT/app/Madeira/$farm/$name.pending" ]] || {
      echo "Refusing an unowned system program output or pending path: $farm/$name" >&2;exit 1;
    }
    cp "$STATE/$name" "$ROOT/app/Madeira/$farm/$name.pending"
    mv "$ROOT/app/Madeira/$farm/$name.pending" "$ROOT/app/Madeira/$farm/$name"
  done
done
python3 "$ROOT/tools/check-system-programs.py" --root "$ROOT/app/Madeira" --source-root "$WINE" --write-manifest
