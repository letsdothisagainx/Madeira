#!/usr/bin/env bash
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
DERIVED="$ROOT/app/DerivedData"
DIST="$ROOT/dist"
# Debug is the configuration that runs games (docs/BUILDING.md); Release builds
# have crashed the guest.
CONFIGURATION="${CONFIGURATION:-Debug}"
APP="$DERIVED/Build/Products/$CONFIGURATION-iphoneos/Madeira.app"

required=(
  "$ROOT/app/Madeira/madeira-jit.js"
  "$ROOT/app/Madeira/aarch64-windows/wow64.dll"
  "$ROOT/app/Madeira/aarch64-windows/services.exe"
  "$ROOT/app/Madeira/i386-windows/madeira-wow64-probe.exe"
  "$ROOT/app/Madeira/i386-windows/madeira-wow64-module-probe.dll"
  "$ROOT/FEX/build-ios/FEXCore/Source/libFEXCore.a"
  "$ROOT/FEX/build-ios/FEXCore/Source/libFEXCore_Base.a"
  "$ROOT/FEX/build-ios/External/fmt/libfmt.a"
  "$ROOT/FEX/build-ios/External/cephes/libcephes_128bit.a"
  "$ROOT/app/Madeira/arm64ec-windows/madeira-scm-probe.exe"
  "$ROOT/app/Madeira/arm64ec-windows/madeira-steam-service.exe"
  "$ROOT/app/Madeira/arm64ec-windows/pixel-readback-x64.exe"
  "$ROOT/app/Madeira/arm64ec-windows/dockhost.exe"
  "$ROOT/app/Madeira/arm64ec-windows/dock-notices.txt"
  "$ROOT/app/Madeira/arm64ec-windows/madeira-htmlipc-bridge.dll"
  "$ROOT/app/Madeira/arm64ec-windows/madeira-htmlipc-bridge.manifest.json"
  "$ROOT/app/Madeira/libwineserver.a"
  "$ROOT/app/Madeira/libntdll_unix.a"
  "$ROOT/app/Madeira/libwin32u_unix.a"
  "$ROOT/app/Madeira/libdxmt_combined.a"
  "$ROOT/app/Madeira/libmadeira_rppairing.a"
)
for path in "${required[@]}"; do
  [[ -s "$path" ]] || { echo "ERROR: required build artifact missing: $path" >&2; exit 1; }
done

python3 "$ROOT/tools/check-dxmt-pixel-probe.py" "$ROOT/app/Madeira/arm64ec-windows/pixel-readback-x64.exe"
python3 "$ROOT/tools/check-dxmt-memory-package.py" --root "$ROOT/app/Madeira" --repo-root "$ROOT"

python3 "$ROOT/tools/check-htmlipc-image.py" \
  --staged "$ROOT/app/Madeira/arm64ec-windows/madeira-htmlipc-bridge.dll" \
  --manifest "$ROOT/app/Madeira/arm64ec-windows/madeira-htmlipc-bridge.manifest.json" \
  --abi-header "$ROOT/build/scm-rpc/htmlipc_ready_abi.h" \
  --build-report "$ROOT/build/htmlipc/obj/madeira-htmlipc-bridge.build.json" \
  --source-root "$ROOT"

rm -rf "$DERIVED" "$DIST/Payload"
mkdir -p "$DIST"

# The JIT allocator is compiled by Xcode, independently of cached native Wine.
source_revision="${GITHUB_SHA:-$(git -C "$ROOT" rev-parse HEAD)}"
python3 "$ROOT/tools/build/native-provenance.py" header --root "$ROOT" \
  --component jitallocator --revision "$source_revision" \
  --output "$ROOT/app/Madeira/.build-provenance/JITAllocator.generated.h"

xcodebuild \
  -project "$ROOT/app/Madeira.xcodeproj" \
  -scheme Madeira \
  -configuration "$CONFIGURATION" \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  -derivedDataPath "$DERIVED" \
  IPHONEOS_DEPLOYMENT_TARGET=18.0 \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY='' \
  build

[[ -d "$APP" ]] || { echo "ERROR: xcodebuild succeeded but Madeira.app is missing" >&2; exit 1; }

# Include the exact Actions source revision in the existing startup build label,
# including failures during browser preparation before the native UUID is logged.
source_revision="${GITHUB_SHA:-$(git -C "$ROOT" rev-parse HEAD)}"
python3 - "$APP/Info.plist" "$source_revision" <<'PY_BUILD_STAMP'
import plistlib, re, sys
from pathlib import Path
file, revision = Path(sys.argv[1]), sys.argv[2]
assert re.fullmatch(r'[0-9a-f]{40}', revision), 'invalid source revision'
value = plistlib.loads(file.read_bytes())
value['MadeiraBuild'] = f"v{value['CFBundleShortVersionString']} ({value['CFBundleVersion']}) source={revision}"
file.write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_BINARY))
PY_BUILD_STAMP

python3 "$ROOT/tools/build/native-provenance.py" stamp --root "$ROOT" \
  --revision "$source_revision" --app "$APP"

# Preserve Madeira's requested JIT/debug entitlements in the IPA. SideStore will
# replace this ad-hoc signature with the user's development signature while
# retaining the supported entitlements.
codesign --force --sign - \
  --entitlements "$ROOT/app/Madeira/Madeira.entitlements" \
  "$APP"

bundle_required=(
  "$APP/madeira-jit.js"
  "$APP/aarch64-windows/wow64.dll"
  "$APP/aarch64-windows/services.exe"
  "$APP/Madeira.debug.dylib"
  "$APP/i386-windows/madeira-wow64-probe.exe"
  "$APP/i386-windows/madeira-wow64-module-probe.dll"
  "$APP/arm64ec-windows/madeira-scm-probe.exe"
  "$APP/arm64ec-windows/madeira-steam-service.exe"
  "$APP/arm64ec-windows/pixel-readback-x64.exe"
  "$APP/arm64ec-windows/dockhost.exe"
  "$APP/arm64ec-windows/dock-notices.txt"
  "$APP/arm64ec-windows/madeira-htmlipc-bridge.dll"
  "$APP/arm64ec-windows/madeira-htmlipc-bridge.manifest.json"
  "$APP/Madeira"
  "$APP/prefix-template.tar.gz"
  "$APP/arm64ec-windows/xtajit64.dll"
  "$APP/x86_64-vcruntime/vcruntime140.dll"
)
for path in "${bundle_required[@]}"; do
  [[ -s "$path" ]] || { echo "ERROR: required bundle resource missing: $path" >&2; exit 1; }
done
# The debugger script and native allocator negotiate the same JIT wire
# protocol. Never ship a cached Xcode resource beside a newly linked allocator.
cmp -s "$ROOT/app/Madeira/madeira-jit.js" "$APP/madeira-jit.js" || {
  echo "ERROR: Xcode packaged stale JIT debugger script" >&2
  exit 1
}
python3 "$ROOT/tools/check-dxmt-pixel-probe.py" "$APP/arm64ec-windows/pixel-readback-x64.exe"
cmp -s "$ROOT/app/Madeira/arm64ec-windows/pixel-readback-x64.exe" "$APP/arm64ec-windows/pixel-readback-x64.exe" || {
  echo "ERROR: Xcode packaged stale DXMT pixel probe" >&2
  exit 1
}
codesign -d --entitlements :- "$APP" 2>/dev/null | grep -q 'com.apple.security.cs.allow-jit' || {
  echo "ERROR: packaged app is missing the allow-jit entitlement" >&2
  exit 1
}

mkdir -p "$DIST/Payload"
ditto "$APP" "$DIST/Payload/Madeira.app"
rm -f "$DIST/Madeira.ipa"
(
  cd "$DIST"
  /usr/bin/zip -qry Madeira.ipa Payload
)
rm -rf "$DIST/Payload"
[[ -s "$DIST/Madeira.ipa" ]] || { echo "ERROR: failed to create IPA" >&2; exit 1; }
unzip -tq "$DIST/Madeira.ipa" >/dev/null
unzip -p "$DIST/Madeira.ipa" 'Payload/Madeira.app/madeira-jit.js' | cmp -s - "$ROOT/app/Madeira/madeira-jit.js" || {
  echo "ERROR: IPA JIT debugger script differs from current source" >&2
  exit 1
}

for resource in dockhost.exe dock-notices.txt madeira-steam-service.exe madeira-scm-probe.exe; do
  unzip -p "$DIST/Madeira.ipa" "Payload/Madeira.app/arm64ec-windows/$resource" | cmp - "$APP/arm64ec-windows/$resource"
done

for resource in madeira-wow64-probe.exe madeira-wow64-module-probe.dll; do
  unzip -p "$DIST/Madeira.ipa" "Payload/Madeira.app/i386-windows/$resource" | cmp - "$APP/i386-windows/$resource"
done

python3 "$ROOT/tools/check-io-abi-package.py" \
  --staged "$ROOT/app/Madeira/aarch64-windows/wow64.dll" --app "$APP" --ipa "$DIST/Madeira.ipa"

python3 "$ROOT/tools/check-ios-network-package.py" \
  --native "$APP/Madeira.debug.dylib" --ipa "$DIST/Madeira.ipa"

python3 "$ROOT/tools/check-system-programs.py" \
  --root "$ROOT/app/Madeira" --source-root "$ROOT/wine" --app "$APP" --ipa "$DIST/Madeira.ipa"
python3 "$ROOT/tools/check-dxmt-memory-package.py" \
  --root "$ROOT/app/Madeira" --repo-root "$ROOT" --app "$APP" --ipa "$DIST/Madeira.ipa"
python3 "$ROOT/tools/check-trust-diagnostics-package.py" \
  --root "$ROOT/app/Madeira" --source-root "$ROOT/wine" --repo-root "$ROOT" \
  --app "$APP" --ipa "$DIST/Madeira.ipa"
python3 "$ROOT/tools/check-security-compat-package.py" \
  --root "$ROOT/app/Madeira" --source-root "$ROOT/wine" --repo-root "$ROOT" \
  --app "$APP" --ipa "$DIST/Madeira.ipa"
python3 "$ROOT/tools/check-registry-security-package.py" \
  --root "$ROOT/app/Madeira" --source-root "$ROOT/wine" --repo-root "$ROOT" \
  --app "$APP" --ipa "$DIST/Madeira.ipa"

python3 "$ROOT/tools/check-htmlipc-image.py" \
  --staged "$ROOT/app/Madeira/arm64ec-windows/madeira-htmlipc-bridge.dll" \
  --manifest "$ROOT/app/Madeira/arm64ec-windows/madeira-htmlipc-bridge.manifest.json" \
  --abi-header "$ROOT/build/scm-rpc/htmlipc_ready_abi.h" \
  --build-report "$ROOT/build/htmlipc/obj/madeira-htmlipc-bridge.build.json" \
  --source-root "$ROOT" \
  --app "$APP" --ipa "$DIST/Madeira.ipa"

python3 "$ROOT/tools/build/native-provenance.py" check --root "$ROOT" \
  --revision "$source_revision" --app "$APP" --ipa "$DIST/Madeira.ipa"
