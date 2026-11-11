# Steam browser update compatibility — November 11

The `51963bfc` iPhone capture confirms the full shared 1152 MiB JIT pool and
`wide-breakpoint-batched` preparation in 11,508 ms. Neither JIT placement nor
the 768/384 MiB partition changes in this correction.

Steam legitimately updates manifest 1792618285 to 1794424036 and retains its
`-applaunch 730 -condebug` request. The helper request reaches
`NtCreateUserProcess`, CEF policy and environment preparation. There is no
corresponding helper child creation. The next boundary is Madeira's
`ios_htmlipc_redirect`, before image inspection, server process creation or
`spawn_process`. A missing master section therefore does not establish a
named-object namespace defect.

## Confirmed incompatibility

The original bridge accepts only one exact `chromehtml.dll` layout. Its first
file gate requires 1,668,248 bytes. The updated official file has 1,667,224
bytes, so it cannot prepare or publish Installed readiness. The native helper
redirect requires that readiness and returns `STATUS_NOT_SUPPORTED` instead of
creating a child. That build did not record the individual guard's return;
the exact production gate and official-file regression establish the defect.

The current official HTTPS manifest and SHA-256 checked archives were inspected
in Actions [43119095325](https://github.com/letsdothisagainx/Madeira/actions/runs/43119095325)
and [43119766650](https://github.com/letsdothisagainx/Madeira/actions/runs/43119766650).
The original and updated core SHA-256 values are respectively:

```
37f5ddbe874362d729b7cd33504943a9d649d845525afae4bcc2af36ab971f4b
7afabbd8fae70a1b9831546d4c126ebd74c18796457e3a12fa259f529f7f2266
```

The new PE has image size `0x19d000`, timestamp `0x6af24bcb`, changed executable
and read-only sections, and moved stream/controller coordinates. This is not
merely re-signing. A hash-only refresh, an unconditional Ready flag or a section
fabricated on Steam's behalf would be incorrect.

FEX's existing `ComputeCodeMapId` uses the lowercased module name, PE timestamp
and image size. Those independently read current PE fields produce
`da1f62aa54b87135`, exactly the captured `chromehtml.dll` module ID; the old fields
produce `da1f72aa5493109d`. This identifies the captured header version without
pretending to have measured a complete on-device file hash.

## Production correction

The installer selects a complete immutable compatibility profile by bounded
file size, full SHA-256 and exact PE metadata. All stream methods, RTTI,
controller, factory and helper-path checks use that selected profile. The
installer rechecks the file at installation, compares mapped immutable sections
with relocation/IAT normalization and retains its existing protection and
rollback checks. The runtime provider and controller resolver use the same
profile instead of legacy global offsets.

Cold-launch preparation recognizes the same two official cores. The separately
verified I386 browser cache, all 80 records, archive pins and cache identity stay
unchanged; a core update does not trigger unrelated browser downloads. The
packaged bridge manifest records both supported hashes and the build checks
their presence in the actual linked DLL. The legacy `coreSHA256` manifest field
continues to identify the original cache contract, rather than pretending it is
the hash of every subsequently installed Steam core.

Unknown cores remain refused. A future package update that leaves the supported
core contract unchanged needs no Madeira change. A genuinely changed private
HTMLIPC ABI requires evidence and a compatible profile; arbitrary future Valve
protocols are not claimed supported. No Steam update is disabled or rolled back.

Precise, bounded native rejection records identify the stage, real status and
requested architecture. Readiness error fields are included only from coherent
current-owner/lease DATA snapshots. This does not relax any admission check.

## Separate findings and acceptance limits

`MoveFileTransactedW` delegates to real file replacement and propagates rename
failures, although Wine lacks complete transaction isolation/rollback. The
capture does not demonstrate a failed CEF file replacement. Reimplementing TxF
is not justified as a remedy for this pre-spawn bridge incompatibility.

The official-file installer fixture uses full original PE bytes and the actual
production installer, with owned native mappings/protections. It executes only
test-owned hooks, not Valve instructions; initialized controller BSS is a fixture
boundary. It does not prove Steam, CEF rendering, or iPhone operation.

On-device acceptance still requires the genuine helper's process creation,
master-section creation/open, responsive Steam, actual `cs2.exe` creation and a
usable menu. This capture provides no new VAC result. Secure matchmaking remains
unverified until a genuine VAC-secured server accepts the client. No signatures,
security decisions, game files, account data or module visibility are changed.
