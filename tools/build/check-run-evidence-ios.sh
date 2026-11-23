#!/usr/bin/env bash
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
# Only type-check the iOS-specific subscriber, Mach task and native ABI calls.
# No test executable or captured instruction is run.
xcrun --sdk iphoneos swiftc -typecheck -swift-version 5 \
  -target arm64-apple-ios18.0 -sdk "$SDK" \
  "$ROOT/app/Madeira/RunEvidence.swift" "$ROOT/tests/host/run_evidence_ios_stub.swift"
