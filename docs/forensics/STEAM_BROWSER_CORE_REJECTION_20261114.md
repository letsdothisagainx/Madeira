# Pre-Wine browser core rejection and interrupted-cache recovery

Follow-up: the supplied installed DLL is now independently authenticated and
has a reviewed native profile. See
[the compatibility correction](STEAM_BROWSER_CORE_20261113_COMPAT.md).
The investigation and access limitations below describe the earlier evidence
boundary, before that DLL was supplied.

Tested source: `df52539b6b43eb676907484c7d1f0f862a39a485`.
Evidence: the supplied `madeira-log(1).txt`, reporting that exact source.

## What failed

StikDebug reports success at 15:56:57.700 in the supplied local-clock log. The
bundled bridge then passes its expected 55,808-byte size, SHA-256 and AMD64
machine checks. Browser preparation fails at 15:56:57.750, phase `core`, before
owner-root access, cache enumeration, cache reuse or full JIT-pool initialization.
Thus `records-observed=-1` means **not enumerated**, not 80 missing files.

`compatibleCoreSHA256()` had two `changedCore` predicates: an invalid component
location, or a full-file digest outside the two reviewed native bridge profiles.
The production caller constructs `bin/chromehtml.dll` directly beneath the
validated Steam launcher root, making the unsupported-digest branch the strongest
explanation. The log does not record that digest, file size, PE header or version.
It cannot establish which particular Steam update or damaged/mixed file is on
the phone. Neither is invented here.

Browser Swift code, recipe and native bridge profiles did not change between
`e481cc04`, `fd6b7c03` and `df52539b`. The latter's native loading changes have not
executed at this failure boundary. There is no evidence supporting their revert.

## Corrections implemented

Core-admission failures now use `CoreIssue`, separately from cache-record
failures. It identifies the fixed relative component `bin/chromehtml.dll`, the
actual full digest, measured size, bounded PE architecture and exact failed
predicate. UI text explains that the component does not match a supported
verified profile; it does not falsely claim that Steam legitimately updated or
that the cache is corrupt. Only a 4 KiB PE-header read is added after rejection.
No private filesystem path, credentials, arbitrary error text or version strings
are exported. The actual native installer and its exact profile pins remain
mandatory; this is not permission to accept an unknown core.

Existing supported-cache reuse and rebuild already verify every recorded file,
architecture, key pin, generated marker and complete manifest, retaining the
previous tree until replacement validation. A separate crash-recovery gap is
corrected: after a crash between the two publication renames, a completed
`.stage-*` or `.retained-*` tree can exist with no final cache. Preparation now
validates and atomically promotes such a tree before downloading again.

Recovery requires the existing dedicated owner root and owner marker, unchanged
recipe identity, the ordinary full validator, current-core recheck and idle
state. Completed stages precede retained trees, with deterministic lexical
ordering. Symlinks are refused, existing final caches are never replaced by this
helper, and partial/foreign candidates remain unchanged. Scanning is bounded to
128 entries and 32 candidates; exceeding either bound preserves everything and
continues normal verified fresh preparation instead of requiring manual cleanup.

## Validation and support boundary

The actual Swift file helpers run in the focused regression suite. New cases
cover completed stages, retained caches, deterministic selection, incomplete and
foreign candidates, core changes, active sessions, owner/path/link refusal and
bounded scans. Core diagnostics are checked against actual fixture-file size and
PE headers, malformed hash-provider redaction and location rejection before any
digest attempt. Existing corruption, missing-file, manifest, architecture and
atomic replacement tests remain active. Fixture hashes are not Valve trust
authentication, and none of these tests establishes on-device Steam startup.

The canonical I386 cache still contains the same 79 official files and one
generated marker. The native bridge supports the same two fully reviewed core
identities. A new Swift allowlist entry alone would not make an unknown native
HTMLIPC layout compatible, so no such entry is added without the real binary and
its compatibility evidence.

Current official-core inspection requires access to
`client-update.akamai.steamstatic.com`. The selected Cloud environment's enforced
destination policy currently denies it, and no settings-change tool is exposed.
An owner grant was requested. No alternate host, proxy, IP, or remote execution
environment is used to bypass that restriction. Existing completed GitHub
inspection reports cover only the already-supported November 11–12 cores.

**The supplied startup failure is not yet resolved by these independent recovery
changes.** Restoring an unrecognized installed core requires identifying its
actual bytes and a correctly reviewed native profile, or genuine Steam repair if
damage is established. A previous cache cannot authenticate an unsupported core.
No IPA is presented as a confirmed startup fix on the strength of these tests.

JIT placement/partition, FEX, DXMT, UDP transport, input, exports, Wine prefix,
Steam account, installed games and the recent loading corrections are unchanged.
Actual acceptance still requires full JIT initialization, genuine Steam/helper
startup, App ID 730 launch and a usable CS2 menu, followed by map-load testing.
