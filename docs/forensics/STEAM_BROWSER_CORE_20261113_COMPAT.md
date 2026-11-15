# Support the supplied signed Steam browser core

The user supplied the installed `bin/chromehtml.dll` after the pre-Wine
`changed-core` failure. This provides the exact bytes missing from that log.

## Confirmed failure mechanism

The file is AMD64, 1,667,224 bytes, with SHA-256
`872c1373defbe853260b5eed5e8b25ab85a680a05b1801cb12e01df7aabb1736`,
PE timestamp `0x6af66f64`, image size `0x19d000`, six sections and preferred
base `0x180000000`. The prior Swift admission list and native installer knew
only the `37f5ddbe...` and `7afabbd8...` cores.

The old native production installer reproduces `PinMismatch` on this exact
file before image queries or protection changes. Its size passes the existing
read bound, but its full digest and timestamp do not select either profile.
The Swift full-hash check rejects it even earlier, explaining `phase=core`
with `records-observed=-1`. The cache was not enumerated; this is not evidence
that its 80 records disappeared. The loading/VM fixes had not executed at this
boundary and do not need reverting.

## Authentication and compatibility review

[Offline signature evidence](STEAM_CORE_20261113_AUTHENTICODE.json) records:

- The recomputed Authenticode image digest matches the signed digest.
- The publisher is Valve Corp., with code-signing EKU and a verified PKCS#7
  signature/chain against the pre-existing system CA store.
- The independent root is DigiCert Trusted Root G4; an embedded root was not
  imported as trusted evidence.
- The timestamp countersignature and its parent-signature imprint verify,
  including its timestamp-purpose chain at the signed time.

This authenticates the supplied file offline. Online revocation, Windows
WinVerifyTrust policy, the current official package identity and VAC acceptance
are not inferred from it. No fresh Valve request or network-policy workaround
was used.

[Static ABI evidence](STEAM_CORE_20261113_ABI.json) compares the supplied file
with the already-completed official-package inspection of `7afabbd8...`:

- The entire `.text` section is byte-identical. `.data`, `.pdata`, `.fptable`
  and `.reloc` are also identical.
- All seven examined stream method CFGs, instruction references and reviewed
  callees match; the stream vtable remains at `0x1323a0`.
- The 42-entry controller table remains at `0x123710`, controller object at
  `0x1806c0`, and factory at `0xf9420`; initialization and registry callbacks
  match the examined updated-core behavior.
- All 56 independently extracted receiver bindings and both serialized
  protobuf descriptors match.

The timestamp and `.rdata` differ, so this is **not** treated as a signature-only
change. No changed read-only bytes are ignored by runtime comparison. The seven
previously unresolved command IDs remain unresolved; no new mappings are guessed.

## Production correction

`installer.cpp`/`.h` add one separate immutable `reviewed_profile`, selected only
by this full-file SHA-256 and exact PE metadata. Its proven coordinates match the
preceding updated profile. The existing mapped-image comparison, owner checks,
write protections, rollback and unload rules remain unchanged. The supplied
Valve file is neither patched nor installed by Madeira.

`SteamBrowserRuntime.swift` admits the same third exact identity. The build
checker, source-provenance list and generated bridge manifest declare all three
profiles; packaging requires every pin in the actual compiled bridge DLL.
Updating only Swift would not have fixed the native rejection.

The canonical I386 browser recipe, original package pins, 79 official files,
generated marker and completion-manifest identity are unchanged. An existing
valid 80-record cache is verified and reused. No Steam downgrade, browser-cache
deletion, prefix reset, game reinstall or authentication change is introduced.
The separately implemented completed-stage recovery and precise core errors
remain available for interrupted cache preparation and genuinely unknown cores.

## Tests and remaining acceptance

The offline actual-file regression runs:

```sh
python3 tests/integration/check-provided-steam-bridge-profile.py --core-file chromehtml.dll
```

It pins the supplied input's size/hash, compiles the old production installer to
reproduce rejection, then exercises the corrected installer on a test-owned
mapping of the original complete file under ASan/UBSan. Tests check installation,
controller validation, real native RX/RW protections, protection failures and
rollback, file/section tamper refusal, unload and unchanged executable/helper
bytes. Valve DllMain and Valve instructions are not executed. The original
attachment's digest remains unchanged. The binary is not committed to source.

The Swift suite checks all three exact profiles, rejection of unknown/spoofed
recipes and unchanged 80-record cache identity, alongside the completed-cache
recovery, corruption, architecture, ownership and interrupted-publication cases.
CI separately checks compiled bridge pins, manifests and exact IPA contents;
those checks are not represented as execution of the supplied Valve file.

Actual iPhone acceptance remains full JIT-pool initialization, genuine Steam and
browser-helper startup, actual App ID 730 process creation and a usable CS2 menu.
Only then can the retained map-loading corrections be benchmarked. No new FPS,
loading-time, memory or matchmaking result is claimed from these static tests.

Install over the existing app with the same signing identity/bundle ID. All
Wine, Steam, CS2, account, input and game data are retained. Rollback uses the
prior IPA with that same identity; no data migration is required.
