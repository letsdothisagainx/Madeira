#!/usr/bin/env bash
# Build the real Wine Authenticode and mapped-filename corrections in every
# architecture farm. No verifier result or module identity is substituted.
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
WINE="$ROOT/wine"
TC="$ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
export PATH="$TC:$PATH"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 8)}"
STATE="$(mktemp -d)"
crypto_staged=0
filename_staged=0
cleanup() {
    status=$?
    restored=1
    if [[ "$filename_staged" == 1 ]]; then
        python3 "$ROOT/tools/build/stage-mapped-filename-contract.py" restore "$STATE/filename" || restored=0
    fi
    if [[ "$crypto_staged" == 1 ]]; then
        python3 "$ROOT/tools/build/stage-crypt32-authattrs.py" restore "$STATE/crypto" || restored=0
    fi
    if [[ "$restored" != 1 ]]; then
        echo "Security compatibility source restoration failed; backup retained at $STATE" >&2
        exit 1
    fi
    if [[ "$status" == 0 ]]; then
        python3 "$ROOT/tools/check-security-compat-package.py" --write \
            --root "$ROOT/app/Madeira" --source-root "$WINE" --repo-root "$ROOT" \
            --build-root "$WINE" || status=$?
    fi
    rm -rf "$STATE"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

python3 "$ROOT/tools/build/stage-crypt32-authattrs.py" apply "$STATE/crypto" --source "$WINE"
crypto_staged=1
python3 "$ROOT/tools/build/stage-mapped-filename-contract.py" apply "$STATE/filename" --source "$WINE"
filename_staged=1

# Build kernelbase while its filename correction and the existing process-
# lookup overlay are both present. The nested transaction restores only its
# own process.c inputs and retains the genuine registration utilities.
for config in 'build-macos:aarch64-windows' 'build-arm64ec:arm64ec-windows' 'build-i386:i386-windows'; do
    IFS=: read -r tree farm <<< "$config"
    rm -f "$WINE/$tree/dlls/kernelbase/$farm/debug.o"
done
"$ROOT/build/wine-pe/build-system-programs.sh"

for config in 'build-macos:aarch64:aarch64-windows' 'build-arm64ec:arm64ec:arm64ec-windows' 'build-i386:i686:i386-windows'; do
    IFS=: read -r tree triple farm <<< "$config"
    [[ -f "$WINE/$tree/Makefile" ]] || { echo "Missing configured Wine tree: $tree" >&2; exit 1; }
    target="dlls/crypt32/$farm/crypt32.dll"
    # Cached compiler outputs must never satisfy a changed source overlay.
    rm -f "$WINE/$tree/dlls/crypt32/$farm/encode.o" \
          "$WINE/$tree/dlls/crypt32/$farm/msg.o" "$WINE/$tree/$target"
    make -C "$WINE/$tree" -j"$JOBS" "$target"
    mkdir -p "$ROOT/app/Madeira/$farm"
    destination="$ROOT/app/Madeira/$farm/crypt32.dll"
    [[ ! -L "$destination" && ! -e "$destination.pending" && ! -L "$destination.pending" ]] || {
        echo "Refusing an unowned crypt32 output or pending path: $farm" >&2; exit 1;
    }
    "$TC/$triple-w64-mingw32-strip" --strip-debug -o "$STATE/crypt32.dll" "$WINE/$tree/$target"
    cp "$STATE/crypt32.dll" "$destination.pending"
    mv "$destination.pending" "$destination"
done
