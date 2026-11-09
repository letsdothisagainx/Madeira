# CS2 secure-matchmaking investigation after 4711d123

The November 9 `083624` Madeira capture and the distinct 1,050-line Source 2
`console.log` are separate evidence. CS2 reaches its menu and the user reports
the same missing/invalid-signature dialog. No successful VAC-secured connection
is recorded. The objective remains genuine secure matchmaking; this document
does not designate a test fixture, Steam login or a local server as success.

## Confirmed observations

* The effective accepted process arguments are `-steam -condebug -joy`.
  The native observer reports a complete parse, no unknown arguments, and no
  `-insecure` or third-party-software option. No launch option is changed.
* Both directory VPKs now use the supported type-1 20-byte descriptor. Their
  current tree/table/whole MD5 values match, and RSA verification is consistent
  with each embedded key. Current SHA-1 values match cached depot references.
  Independently authenticated Valve keys/manifests and numbered archive
  payloads remain unmeasured. The parser is unchanged in this pass.
* The real console records the main-menu state at 03:32:36, networking
  certificate authentication becoming OK at 03:32:41, and usable relay
  configuration with 25 valid relays at 03:32:47. The temporary HTTP 504
  precedes successful configuration and is not a demonstrated integrity cause.
* The 03:33:39 connection is loopback/local. It does not establish secure
  matchmaking. There are no case-insensitive VAC/signature/trusted messages in
  this console capture. The generic-confirm localization warning at 03:35:16
  cannot be assigned to the popup without a user timestamp.
* No post-CS2-start file-read/write failure or verifier return is exposed by
  the enabled logging. This is a tracing limitation, not proof that every file
  operation or private integrity check succeeded.

## Service and PIX investigations

The genuine I386 SteamService.exe (PID 0050) reaches SCM state 4 and loads its
service DLL and observed dependencies. The failing SteamServiceConnect thread
00b0 belongs to separate AMD64 Steam PID 0068. Wine's native architecture check
can reject an I386 DLL before import binding; the inspected official package
contains such a service DLL. The exact failed phone file header/hash and
LoadLibrary flags remain unavailable. Its purpose and relationship to VAC are
not established, and the loader's architecture rejection is not weakened.

The tracked DXMT ARM64EC `d3d11.dll` annotation GetStatus implementation returns
FALSE (RVA 0x747e0, `MOV W0,WZR; RET`), and DXMT rejects known debug/PIX/RenderDoc
interfaces. The observed ID3D11InfoQueue probe is also rejected; RenderDoc loads
fail. Metadata matches the recorded image identity, but FEX's name/timestamp/
size identifier is not a content hash. The complete Source 2 PIX/Nsight
detection predicate is unobserved. No debugger is hidden and no graphics
capability or interface response is changed. Actual d3d9.dll/nvapi64.dll map
events are added to the literal public inventory catalog instead of redacting
those known names; this does not hide any module from the game or security.

## Support boundary and strongest hypothesis

[Valve's Trusted Mode FAQ](https://help.steampowered.com/en/faqs/view/09A0-4879-4353-EF95)
distinguishes secure operation from foreign/unsigned injected software. It
does not identify Madeira's compatibility modules as injections or establish
that the PIX message controls the warning. We do not add the FAQ's alternative
launch option or fabricate trust.

The official [CS2 system requirements](https://store.steampowered.com/app/730/CounterStrike_2/)
document Windows and Linux, not iOS/Wine/FEX. In Valve's trackers,
[report 4125](https://github.com/ValveSoftware/csgo-osx-linux/issues/4125) and
[report 4258](https://github.com/ValveSoftware/csgo-osx-linux/issues/4258)
describe the same signature warning under Windows CS2/Proton, including an
immediate Play rejection and ineffective file verification. A Valve maintainer
routes these to [Proton 2704](https://github.com/ValveSoftware/Proton/issues/2704)
as unofficial compatibility and recommends native Linux. These are primary
compatibility reports, not a proof that Windows Steam under Madeira can never
work; typical Proton and Madeira use different host/client arrangements.

An environment/trust compatibility failure is consequently a strong hypothesis.
The exact rejected component, current full game-content authenticity, local
versus server decision path and any immutable Valve-controlled requirement
remain unresolved. None is replaced by a fabricated compatibility verdict.

## Focus of this implementation

The existing export dropped the actual timestamped console's useful auth/menu/
relay records because its decoder recognized only a few complete messages.
Its shared record cap also allowed a large runtime log to crowd out game
evidence. The export is being corrected to retain bounded, newly encoded,
timestamped console evidence with per-source limits and explicit provenance.
It never copies arbitrary raw bodies, account identifiers, endpoint addresses,
authentication certificates/tickets, cookies or credentials.

Explicit Begin VAC Test and Mark VAC Error actions bracket the next interaction.
Markers carry UTC, local offset and monotonic time. Coarse input dispatch
markers are temporary and rate-limited, contain no keys/text/coordinates, and
do not intercept protected checks. Menu readiness comes only from the real
reported console transition. A user error marker is a report, not an observed
internal VAC verdict. A ring snapshot prevents the large runtime log from
discarding the most useful markers.

The iOS certificate importer also contains a proven descriptor-ownership bug:
fdopen/fclose consumes the descriptor and the caller closes it again. A
concurrent open can reuse that number before the second close. A focused
production-path regression and ownership correction are included separately.
There is no captured causal link between this defect and the VAC warning.
Certificate contents, signature algorithms, trust decisions and error results
are not overridden.

## Next iPhone evidence

Update Madeira in place with SideStore using the same account and app identity.
Keep the prefix, Steam login and installed game. Use the genuine Steam Library
file-verification UI when possible, wait for its actual result, and record that
result without calling a cached hash match authenticated verification.

At the real menu, choose Begin VAC Test, press Play once, and immediately choose
Mark VAC Error if the popup appears. Export CS2 VAC Diagnostics after the mark.
The ZIP should contain console provenance/times, the explicit marker bracket,
accepted launch/module observations, actual service errors and bounded
read-only content observations, with unknowns stated. A secure server
connection is the only acceptance result; otherwise the warning remains open.
