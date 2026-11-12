#!/usr/bin/env bash
# Compile real registry-view security handling, without changing access policy.
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
WINE="$ROOT/wine"
TC="$ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
export PATH="$TC:$PATH"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 8)}"
STATE="$(mktemp -d)"
python3 "$ROOT/tools/build/stage-registry-security-views.py" apply "$STATE/source" --source "$WINE"
cleanup() {
    status=$?
    if ! python3 "$ROOT/tools/build/stage-registry-security-views.py" restore "$STATE/source"; then
        echo "Registry security source restoration failed; backup retained at $STATE" >&2
        exit 1
    fi
    if [[ "$status" == 0 ]]; then
        python3 "$ROOT/tools/check-registry-security-package.py" --write --root "$ROOT/app/Madeira" \
            --source-root "$WINE" --build-root "$WINE" || status=$?
    fi
    rm -rf "$STATE"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for config in 'build-macos:aarch64:aarch64-windows' 'build-arm64ec:arm64ec:arm64ec-windows' 'build-i386:i686:i386-windows'; do
    IFS=: read -r tree triple farm <<< "$config"
    [[ -f "$WINE/$tree/Makefile" ]] || { echo "Missing configured Wine tree: $tree" >&2; exit 1; }
    target="dlls/advapi32/$farm/advapi32.dll"
    rm -f "$WINE/$tree/dlls/advapi32/$farm/security.o" "$WINE/$tree/$target"
    make -C "$WINE/$tree" -j"$JOBS" "$target"
    mkdir -p "$ROOT/app/Madeira/$farm"
    destination="$ROOT/app/Madeira/$farm/advapi32.dll"
    [[ ! -L "$destination" && ! -e "$destination.pending" && ! -L "$destination.pending" ]] || {
        echo "Refusing unowned registry security output: $farm" >&2; exit 1;
    }
    "$TC/$triple-w64-mingw32-strip" --strip-debug -o "$STATE/advapi32.dll" "$WINE/$tree/$target"
    cp "$STATE/advapi32.dll" "$destination.pending"
    mv "$destination.pending" "$destination"
done
