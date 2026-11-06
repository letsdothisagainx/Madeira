#!/bin/bash
# Build both source-built native PE ntdll images. Their private diagnostic
# counters use a loader-bound RW alias without changing their exported layout.
# ARM64EC alone retains its existing SizeOfImage + 0x50000 padding policy.
# Other PE modules: build/wine-pe/build-modules.sh (the same build tree; it
# strips them with --strip-debug and does not pad). Requires the llvm-mingw
# toolchain (docs/BUILDING.md).
# --enable-winegstreamer keeps winegstreamer's PE rules although GStreamer is
# absent (its unix side is build/ntdll-unix/winegstreamer_unixlib_ios.c); build
# it as `make dlls/winegstreamer/arm64ec-windows/winegstreamer.dll`, never as
# `make -C dlls/winegstreamer`, which would also try the GStreamer-based .so.
set -euo pipefail
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TC="$R/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
export PATH="$TC:$PATH"
B="$R/wine/build-arm64ec"
if [ ! -f "$B/config.status" ]; then
    mkdir -p "$B" && cd "$B" && ../configure --enable-archs=arm64ec --without-x --disable-tests --enable-winegstreamer
fi
A64_BUILD="$R/wine/build-macos"
[[ -f "$A64_BUILD/config.status" ]] || {
    echo "Missing native Wine build tree: run tools/build/build-wine.sh first" >&2; exit 1;
}
NATIVE_COUNTER_TMP="$(mktemp -d)"
NATIVE_COUNTER_STAGE="$R/tools/build/stage-native-counter-writes.py"
cleanup_native_counter() {
    local status=$?
    if ! python3 "$NATIVE_COUNTER_STAGE" restore --wine "$R/wine" --backup "$NATIVE_COUNTER_TMP/source"; then
        echo "Counter source restoration failed; preserving $NATIVE_COUNTER_TMP" >&2
        return 1
    fi
    rm -rf "$NATIVE_COUNTER_TMP"
    return "$status"
}
trap cleanup_native_counter EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 "$NATIVE_COUNTER_STAGE" apply --wine "$R/wine" --backup "$NATIVE_COUNTER_TMP/source"
# Rebuild both consumers of the source overlay, even when Actions restored old
# build outputs. The other source-built SCM/HTMLIPC overlays remain staged by
# the caller and use disjoint files.
for entry in "arm64ec:$B" "aarch64:$A64_BUILD"; do
    arch="${entry%%:*}"; tree="${entry#*:}"
    rm -f "$tree/dlls/ntdll/$arch-windows/sync.o" \
          "$tree/dlls/ntdll/$arch-windows/time.o" \
          "$tree/dlls/ntdll/$arch-windows/ntdll.dll"
    make -C "$tree" -j"${JOBS:-8}" "dlls/ntdll/$arch-windows/ntdll.dll"
    cp "$tree/dlls/ntdll/$arch-windows/ntdll.dll" "$NATIVE_COUNTER_TMP/$arch-ntdll.dll"
    "$TC/$arch-w64-mingw32-strip" "$NATIVE_COUNTER_TMP/$arch-ntdll.dll"
done
OUT="$R/app/Madeira/arm64ec-windows/ntdll.dll"
A64_OUT="$R/app/Madeira/aarch64-windows/ntdll.dll"
# Preserve the established EC-only image padding. The A64 image is stripped
# without inventing additional file-backed/BSS slack.
python3 - "$NATIVE_COUNTER_TMP/arm64ec-ntdll.dll" <<'PY'
import struct, sys
p = sys.argv[1]; d = open(p, 'rb').read()
pe = struct.unpack_from('<I', d, 0x3c)[0]
soi = struct.unpack_from('<I', d, pe + 24 + 56)[0]     # OptionalHeader.SizeOfImage
# ml1004: PAD UP TO the target, do not blindly append.
#
# The old code asserted `len(d) == soi` and then appended 0x50000. Stripping
# removes sections and debug data, so the stripped file is SMALLER than
# SizeOfImage (measured: 0x120000 stripped vs 0x140000 SizeOfImage) and the
# assert failed on every single run -- this script has never completed, and the
# file was being padded by hand instead. Appending a fixed 0x50000 would also
# have produced the wrong total even if the assert had passed.
#
# The header comment states the intent: pad to SizeOfImage + 0x50000. Compute
# that target and fill up to it, which reproduces the known-good hand-built
# size exactly (0x140000 + 0x50000 = 0x190000 = 1,638,400 bytes).
target = soi + 0x50000
if len(d) > target:
    raise SystemExit("stripped ntdll is %d bytes, already larger than the "
                     "target SizeOfImage(%d) + 0x50000 = %d -- the padding "
                     "assumption no longer holds, do not guess"
                     % (len(d), soi, target))
pad = target - len(d)
with open(p, 'ab') as f:
    f.write(b'\0' * pad)
final = len(open(p, 'rb').read())
if final != target:
    raise SystemExit("padding produced %d bytes, expected %d" % (final, target))
print("ntdll.dll: stripped %d + pad %d = %d bytes (SizeOfImage %d + 0x50000)"
      % (len(d), pad, final, soi))
PY
# Inspect the actual stripped/padded packaged bytes, not an intermediate object.
# Both must expose the same native counter size and a NULL, unrelocated writer.
python3 "$NATIVE_COUNTER_STAGE" verify-pe --machine arm64ec "$NATIVE_COUNTER_TMP/arm64ec-ntdll.dll"
python3 "$NATIVE_COUNTER_STAGE" verify-pe --machine aarch64 "$NATIVE_COUNTER_TMP/aarch64-ntdll.dll"
mkdir -p "$(dirname "$OUT")" "$(dirname "$A64_OUT")"
mv "$NATIVE_COUNTER_TMP/arm64ec-ntdll.dll" "$OUT"
mv "$NATIVE_COUNTER_TMP/aarch64-ntdll.dll" "$A64_OUT"
ls -l "$OUT" "$A64_OUT"
