# Secure-play findings

VAC-secured acceptance has not been demonstrated on Madeira. Steam login,
network certificates, relay readiness, local play, cached hashes and embedded
VPK signature consistency do not establish it. The current short capture ends
before Wine and does not retest the preceding Wine signature corrections.

## Established compatibility facts

The installed Wine pin had a genuine authenticated-attribute ordering bug;
the existing backport preserves signed attribute order during verification.
Native Windows reference checks accept that valid message and reject tampering
and a wrong public key. No captured Valve file or call trace establishes that
this was CS2's rejecting operation. The correction is retained.

The observed `SteamService.dll` is I386, while its failing executable-style load
belongs to native64 Steam. In pinned Wine, resource-only `LoadLibraryEx` modes
bypass `LdrLoadDll`; the observed failure comes from `load_dll` on the executable
path. Refusing an incompatible executable DLL is correct. The log does not
distinguish ordinary code loading from `DONT_RESOLVE_DLL_REFERENCES`, explain
Steam's intent, or demonstrate a broken service-authentication RPC. Separate
genuine service operations report running state 4. No forced architecture or
RPC success is introduced.

The pinned DXMT annotation status already returns false and its device rejects
D3D11 debug, PIX, RenderDoc and GPA interfaces. The game-side `PIX/NSIGHT WAS
detected` message alone does not prove an active graphics debugger or its
involvement in the signature rejection. No detection state is hidden or changed.

## Support boundary

[Valve's store requirements](https://store.steampowered.com/app/730/CounterStrike_2/)
list Windows and Ubuntu, not iOS/Wine/FEX.
[Valve's Trusted Mode FAQ](https://help.steampowered.com/en/faqs/view/09A0-4879-4353-EF95)
restricts foreign injections, including unsigned injected DLLs. It does not
identify a rejected Madeira component or prove that ordinary compatibility
dependencies are treated as injections.

[Proton issue 9973](https://github.com/ValveSoftware/Proton/issues/9973) reports
the same Windows-CS2 signature warning after Steam verification and is closed
as an unofficially supported configuration. That is evidence of compatibility
trouble, not an ARM64/iOS-specific technical prohibition. A current
[macOS Wine competitive-play report](https://github.com/Sikarugir-App/Sikarugir/issues/301)
is contrary evidence to declaring all Wine incapable of server entry, but is
uncorroborated and describes a different VAC Live error. Neither is a secure-play
approval or guarantee for Madeira.

The exact rejected file/module or trust requirement remains unidentified.
Consequently there is no evidence-supported security decision to override, nor
a demonstrated universal prohibition to report as fact. Only an unmodified
client's genuine VAC-secured connection establishes success. Required next
device evidence is actual post-preparation game behaviour; the provided new
capture cannot establish any VAC improvement or regression.
