# November 10 probe-to-Steam regression

The two supplied logs are separate sessions. The first runs the owned x64 D3D11
probe and passes 113 pixel readbacks. The second fails before Wine starts. Neither
retests VAC, CS2 rendering or complete-game performance.

## Confirmed cause and repair

The probe's ordinary runtime setup runs the generic ARM64EC DLL farm. That farm
removed the managed `system32/madeira-htmlipc-bridge.dll` regular file and replaced
it with a bundle symlink. The strict Swift installer rejected that leaf in
`SteamRuntimeFiles.destination`, before reaching the ownership-stamp phase.
The bundled bridge source and all 80 official browser-cache records were valid.
The browser Swift code itself did not change between working 4a70400 and b6edc4d;
the new user-accessible probe exposed the conflicting filesystem producers.

All four generic farms now exclude the exact bridge DLL, source manifest and
installation-stamp names, case insensitively, before any removal or link creation.
The runtime loader still uses the same fixed system32 bridge path.

The installer repairs only the named app-owned entry. A link to the currently
verified source may be repaired even before the first stamp exists. A preceding
app-container UUID link requires a valid ownership stamp and the exact same
bundle/application/architecture/filename route. No link referent is read or
adopted. The link entry is retained before a verified regular copy is published.
Unknown links, unowned regular files, foreign/malformed stamps, case aliases,
linked parents, directories and wrong-owner entries are refused.

Current-source bytes can reconcile a stale valid stamp. A damaged current-owned
copy is retained with its metadata before replacement. Unknown damaged older
versions are refused. A pending transaction is persisted before removing the
owned entry, so an interruption leaves a retryable missing-target state. All
launches still require hash, size, PE architecture and installed readback checks.
Fixed-label filesystem diagnostics identify stage, operation, relative path,
error domain/code and underlying errno without printing container paths.

The regression compiles the exact old installer and old Objective-C farm as a
negative control, and executes the current production Swift and farm policy.
It covers repeated launches, missing/stale stamps, target damage, interrupted
transactions, preceding live/dangling bundle links, parent links and aliases.
The Apple workflow also verifies the authentic pinned browser archives.

## Probe isolation and graphics coverage

The legacy non-Steam environment path supplied Thumper identity even for the
standalone test. Only the owned probe now requests a host-only launch marker.
The bridge captures it before config import and removes all case variants of
Steam title identity after import. Config cannot forge the marker. Genuine
Steam Direct, direct-game, Dock and ordinary launch behavior remains covered
by production-body regressions.

The 113 original GPU readbacks remain intact. Seventy-one additional reference
readbacks cover relative array/mip views, BC6H cube/cube-array faces, sampler
filter/address/LOD behavior, indexed/instanced geometry, dynamic buffers,
multipass render-target-to-SRV transitions, nonzero bindings, state clearing,
bound-resource lifetime and repeated shader/pipeline use. The original BC1,
BC3, BC4, BC5, BC7, typeless, sRGB, blend and depth coverage remains present.
The PE contract now requires 184 readbacks, preventing packaging of the old probe.
Host input-vector checks are not GPU rendering results. New pixel results and
CS2's complex pipeline must be checked on the actual iPhone.

The raw CAMetalLayer starts framebuffer-only; DXMT later requests a different
setting. Actual drawable readability and capture lifetime are not established.
The existing CAP request belongs to the D3D12 diagnostic path, not DXMT. A UIKit
snapshot's success Boolean cannot prove it contains Metal pixels. No unproven
capture hook or blank-image fallback is added; an iOS screenshot of Madeira's
actual displayed image remains the safe visual comparison artifact.

## VAC remains unresolved

The earlier x86 Steam service DLL candidate cannot legitimately be forced into
an AMD64 client. A running separate service and a rejected in-process candidate
are distinct observations; no causal link to the signature popup is established.
Genuine Steam verification completion against authenticated depot references
and the precise rejected integrity component remain unobserved.

The exporter now retains the exact fixed `path=nonfile` trust-observer record
previously rejected by its codec. The actual producer-to-codec test reproduces
that loss and checks URL/extra-field rejection. This is a diagnostic schema fix,
not a certificate, trust-policy or VAC decision change. The separate partial-chain
trust-policy review patch remains unshipped.

After Steam is restored, use the existing Steam verification action, mark the
matchmaking error, and export the existing compact VAC package. The next evidence
must include a genuine CS2 session, the marker, real console output, service and
trust/module records. Only an actual VAC-secured server accepting the client can
establish secure-play success. No platform-wide impossibility or successful VAC
repair is claimed from these logs.

No prefix, Steam account, game files, settings, JIT-pool policy, FEX allocator,
atomic recovery, controls or 800x450 display configuration is reset or changed.
Install over the existing Madeira using the same signing identity. Do not
uninstall. Rollback is an in-place install of the previous IPA with that identity.
