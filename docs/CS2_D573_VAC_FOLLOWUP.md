# CS2 signature-warning follow-up to d573d421

The November 9 `050951` capture identifies source d573d421. CS2 reaches its
menu, but the user reports the same VAC missing/invalid-signature warning.
Steam startup, Steam API initialization and a running service do not establish
VAC acceptance. No successful secure matchmaking is claimed.

## Confirmed parser defect and trust limits

The old auditor interprets signature-section magic `0x55AA1234` as a key length
and rejects supported modern Source 2 VPK v2 descriptors. Their declared size
is 20 bytes; separately sized public-key and signature buffers follow outside
those bytes. This is a proven false rejection, not evidence of corrupt content.

The correction checks the real structure and bounds, recomputes current
SHA-1/MD5 preimages, and uses Apple Security for RSA mathematical verification.
[Exact references and limitations](STEAM_VPK_SIGNATURE_DIAGNOSTICS.md) distinguish
classic inline signatures, modern descriptors and unsupported forms.

The device's old `cache-hash-match` results already came from fresh SHA-1 reads
of 107,558,579 current bytes. The expected digests were cached installed-depot
references, not independently reauthenticated manifests. Current and reference
digests are now separately labeled. The attachment contained no actual VPK
descriptor bytes or independently authenticated Valve signing-key reference.
Those phone files therefore still need the corrected on-device audit.

An embedded key cannot establish its own authority. All results retain
`key-provenance=embedded-untrusted`, `trust=unmeasured` and `vac=unclaimed`, even
when checksum and RSA consistency checks pass. The audit does not decide
launch readiness, repair/sign archives or provide a verdict to Steam/VAC.
It fixes Madeira's reporting, not CS2's private verifier.

## Steam service and available logs

The genuine I386 service loads SteamService.dll and its observed dependencies
successfully and reports SCM state 4. A separate AMD64 SteamServiceConnect
thread receives c000007b for that DLL path, then c0000135 for bare-name fallback,
and exits normally. The previously inspected official archive contains an
I386 bin/SteamService.dll. This is consistent with the cross-architecture
rejection, but does not establish the client's purpose or a VAC cause. No
verified loader defect justifies force-loading it or replacing Valve binaries.

The new export reads known service PE headers, including official and lower
case spellings, and labels them as disk snapshots, not loaded-image/trust proof.
All CAB trust warnings in this capture come from DXSETUP, outside the scoped
trust observer. CS2 loads Wintrust but records no verifier return; that proves
neither success nor that VAC uses that API.

The named logs/cs2.exe timestamp file was not attached separately. Both session
log implementations create hardlinks to the main runtime log. It is not
independent CS2-console evidence. Source 2's distinct console.log remains
unavailable in the attachment.

## User-requested package and runtime boundaries

Settings → Diagnostics → Export Steam/CS2 Diagnostics creates a ZIP only on
explicit request. Nofollow descriptor reads and closed typed schemas exclude
raw log bodies, credentials, tokens, account IDs, network addresses and private
host paths. Unknown trust subject names are redacted while actual result
codes are retained. File identity distinguishes aliases from independent logs.

Available records include current VPK results/offsets, ordered known launch
flags, accepted image mappings, service errors and exact known public console
messages. Unknown argument values and unrecognized console bodies are omitted;
missing sources and bounded head/tail coverage are explicit. Mapping events
do not prove DLL initialization/execution or a complete module inventory.
Header machine 8664 and native hybrid status are separate observations.

Passive native capture uses four existing owner/PID/lease generations and at
most 256 mapping events each. The current main thread alone has 125 module
load records, motivating that bounded allowance. Argument/drop bounds remain
128. Trylock-only ownership reads do not adopt/register threads. Hooks preserve
errno, loader results and protections and perform no file I/O or allocation.
No protected game/VAC check is hooked or modified.

## Evidence and next device test

Apple [validation 42568011319](https://github.com/letsdothisagainx/Madeira/actions/runs/42568011319)
compiled the real d573 auditor and reproduced rejection of modern signed,
unsigned and pinned public CS2 fixtures. Corrected production Swift/Security
with ASan passed 22 owned cases and the public fixture, including genuine RSA
mismatch, current checksum preimages, same-size mutations and budget limits.
Public fixture provenance proves format/math evidence, not Valve key authority.

Export tests execute the production parser/reader and real ZIP writer with
secret canaries, case variants, symlink rejection, hardlink provenance, flood
limits and CRC/readback. Native tests execute actual lifecycle/snapshot bodies,
quoting, protected/partial metadata, owner reuse, concurrency and unchanged state.

The game request occurs at app-monotonic 152.528 seconds, or 147.912 seconds
after the accepted JIT-ready launch attempt. New device timings are unmeasured.
The pool, FEX allocator, renderer, controls and Steam launch settings remain
unchanged. The idle audit never blocks launch; export work is on demand.

The remaining blocker is the unidentified rejected file/verifier or secure
environment requirement. This capture establishes neither content corruption
nor a definitive unsupported-platform reason. Secure play on iOS/Wine/FEX is
still unverified; no requirement or validation result is spoofed.

Update the existing Madeira app through SideStore with the same signing account
and bundle identity; do not uninstall it. Reproduce the warning and use the
Diagnostics export action. No reset, game reinstall, manual phone file edit or
computer is required.
