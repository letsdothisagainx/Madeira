#!/usr/bin/env bash
# Retain the narrow developer entry point; the IPA builds both in one transaction.
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
exec bash "$ROOT/tools/build/build-fex-pe-compat.sh" wow64
