#!/usr/bin/env bash
# Build the actual D3D11 resource implementation, not just its native bridge.
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 8)}"
DXMT="$ROOT/dxmt"
TC="$ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
STATE="$(mktemp -d)"
PENDING_OUTPUTS=()
cleanup() {
  local status=$?
  trap - EXIT
  for pending in "${PENDING_OUTPUTS[@]:-}"; do
    if [[ -n "$pending" ]]; then rm -f "$pending"; fi
  done
  if [[ -f "$STATE/state.json" ]]; then
    if ! python3 "$ROOT/tools/build/stage-dxmt-memory-compat.py" restore "$STATE"; then
      echo "ERROR: DXMT source restoration failed; preserved transaction: $STATE" >&2
      exit 1
    fi
  fi
  rm -rf "$STATE"
  exit "$status"
}
trap cleanup EXIT
[[ "$(uname -s)" == Darwin ]] || { echo 'ERROR: DXMT PE/native build requires Xcode on macOS' >&2; exit 1; }
[[ -x "$TC/arm64ec-w64-mingw32-clang++" ]] || { echo 'ERROR: llvm-mingw is missing' >&2; exit 1; }
# build-shader-headers.sh applies an existing Xcode Metal atomic compatibility
# fix. Accept only its exact attributed transform; all other tracked edits fail.
python3 "$ROOT/tools/check-dxmt-memory-package.py" --root "$ROOT/app/Madeira" \
  --repo-root "$ROOT" --check-source-tree
python3 "$ROOT/tools/build/stage-dxmt-memory-compat.py" apply "$STATE"

# Avoid PATH-dependent native compiler selection: generic clang in an LLVM
# cross-toolchain is not necessarily Apple's compiler used by Metal headers.
mkdir -p "$DXMT/build-memory-common"
native_file="$DXMT/build-memory-common/native.txt"
cat > "$native_file" <<EOF
[binaries]
c = '$(xcrun --sdk macosx --find clang)'
cpp = '$(xcrun --sdk macosx --find clang++)'
EOF
for farm in aarch64-windows arm64ec-windows i386-windows; do
  case "$farm" in
    aarch64-windows) triple=aarch64; tree=build-macos; family=aarch64; cpu=aarch64 ;;
    arm64ec-windows) triple=arm64ec; tree=build-arm64ec; family=aarch64; cpu=aarch64 ;;
    i386-windows) triple=i686; tree=build-i386; family=x86; cpu=i686 ;;
  esac
  wine_build="$ROOT/wine/$tree"
  [[ -f "$wine_build/Makefile" ]] || { echo "ERROR: unconfigured $tree" >&2; exit 1; }
  # Imported headers/tools are produced by the existing Wine build. DXMT also
  # requires three real architecture-matched import libraries, even on a cache
  # that previously built only the native Wine bridge.
  PATH="$TC:$PATH" make -C "$wine_build" -j"$JOBS" \
    "libs/winecrt0/$farm/libwinecrt0.a" \
    "dlls/ntdll/$farm/libntdll.a" "dlls/dbghelp/$farm/libdbghelp.a"
  build="$DXMT/build-memory-$triple"
  mkdir -p "$build"
  cross="$build/madeira-cross.txt"
  cat > "$cross" <<EOF
[binaries]
c = '$TC/$triple-w64-mingw32-clang'
cpp = '$TC/$triple-w64-mingw32-clang++'
ar = '$TC/$triple-w64-mingw32-ar'
strip = '$TC/$triple-w64-mingw32-strip'
windres = '$TC/$triple-w64-mingw32-windres'
dlltool = '$TC/$triple-w64-mingw32-dlltool'
[properties]
needs_exe_wrapper = true
[host_machine]
system = 'windows'
cpu_family = '$family'
cpu = '$cpu'
endian = 'little'
EOF
  opts=(--cross-file "$cross" --native-file "$native_file" --buildtype release
    -Dwine_build_path="$wine_build" -Dwine_builtin_dll=true
    -Denable_tests=false -Denable_nvapi=false -Denable_nvngx=false -Dmetal_std=metal3.1)
  if [[ -f "$build/build.ninja" ]]; then
    SDKROOT="$(xcrun --sdk macosx --show-sdk-path)" meson setup --reconfigure "${opts[@]}" "$build" "$DXMT"
  else
    SDKROOT="$(xcrun --sdk macosx --show-sdk-path)" meson setup "${opts[@]}" "$build" "$DXMT"
  fi
  # Build just the D3D11 family and the real winemetal ABI substrate. Explicit
  # postprocess targets preserve Wine builtin and ARM64EC hybrid metadata;
  # compiling d3d11.dll alone does not run winebuild --builtin.
  SDKROOT="$(xcrun --sdk macosx --show-sdk-path)" ninja -C "$build" -j"$JOBS" \
    src/d3d11/d3d11.dll.postproc src/dxgi/dxgi.dll.postproc \
    src/d3d10/d3d10core.dll.postproc src/winemetal/winemetal.dll.postproc
  for module in d3d11/d3d11.dll dxgi/dxgi.dll d3d10/d3d10core.dll winemetal/winemetal.dll; do
    output="$ROOT/app/Madeira/$farm/$(basename "$module")"
    [[ ! -L "$output" && ! -e "$output.memory-pending" && ! -L "$output.memory-pending" ]] || {
      echo "ERROR: unowned DXMT output $output" >&2; exit 1;
    }
    PENDING_OUTPUTS+=("$output.memory-pending")
    "$TC/$triple-w64-mingw32-strip" --strip-debug -o "$output.memory-pending" "$build/src/$module"
    mv "$output.memory-pending" "$output"
  done
  echo "Built real memory-corrected DXMT D3D11 binaries: $farm"
done

# The same staged C++ substrate is compiled natively for the D3D9 path and
# the measured native process-pressure producer is compiled into winemetal.
"$ROOT/tools/build/build-dxmt-ios.sh"
python3 "$ROOT/tools/build/stage-dxmt-memory-compat.py" restore "$STATE"
python3 "$ROOT/tools/check-dxmt-memory-package.py" --root "$ROOT/app/Madeira" \
  --repo-root "$ROOT" --transaction "$STATE" --write-manifest
