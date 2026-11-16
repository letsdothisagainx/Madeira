# Required textures rejected during the Inferno map change

The supplied run reports source `5b92d91e90097397a84208f893c3d9691bb37d9b`.
CS2 starts in this session and establishes remote Mirage and Inferno connections.
The 23:25:05–06 disconnect is an explicit server changelevel, not an established
network timeout. The export completes at 2026-11-16 04:32:49 UTC.

## Confirmed failure

At 23:27:05 the native admission guard rejects 43,688/87,376-byte texture
creations with `E_OUTOFMEMORY`, `reason=physical-budget`. Its first reported
available value, 402,671,440 bytes, is only 18,256 bytes above the configured
384 MiB ordinary floor. Metal has not reported a nil texture at this point:
the guard prevents the actual allocation attempt.

The current CS2 console captures 1,196 texture-creation OOM messages. At
23:29:05 a required texture creation fails, SRV creation returns `E_INVALIDARG`,
and Source 2 asserts. A subsequent null-read AV resolves to
`rendersystemdx11.dll+0x7A2FE`; Steam reports `0xC0000005`. Madeira remains alive
through export. This run does not establish an iOS jetsam termination.

The screenshot's missing/checkerboard materials are consistent with these
explicit resource failures. Severe frame stalls already occur before the
first denial, so this does not identify the cause of all CPU-side stalls.

## Corrections

An ordinary growth refusal now triggers a completion-proven spare drain before
the final retry. This includes the last warm initializer block, main-queue
transient rings and eligible dynamic spares. No pending command, executing GPU
resource, live texture or CPU command heap is freed. A private upload-event
wait remains bounded to 50 ms; failure to complete never becomes fake success.

The retry can use a finite small-resource completion band. On a measured 6 GiB
process budget, ordinary creations retain their 384 MiB floor. Only requests
at most 1 MiB, after explicit reclamation, can use up to 128 MiB in total per
pressure episode, while retaining a 256 MiB absolute floor. Outstanding
creators remain charged. CPU release and process retirement do not refill the
episode allowance; only a fresh measured recovery above the high watermark
does. A real native allocation failure still returns an error with no resource.

The old automatic physical-mip omission also violates the shader resource
contract: texture dimensions and explicit/integer sampling can observe the
smaller physical resource while GetDesc advertises the original. The default
CS2 memory profile therefore uses the game's own Low texture-detail setting
instead. It preserves unrelated video settings and exposes restoration through
the existing Full quality choice. Explicit custom DXMT settings remain owned
by the user.

The game setting is `setting.videocfg_texture_detail`, with 0/1/2 corresponding
to Low/Medium/High in the depot-derived current settings UI:

- [Low defaults](https://github.com/SteamTracking/GameTracking-CS2/blob/82e2b9d62cc97f1358c68a220a4a392c9e41c509/game/csgo/pak01_dir/cfg/video_defaults_0.txt)
- [Video settings UI](https://github.com/SteamTracking/GameTracking-CS2/blob/82e2b9d62cc97f1358c68a220a4a392c9e41c509/game/csgo/pak01_dir/panorama/layout/settings/settings_video.xml)

## Limits of verification

Host tests replay the exact denied byte requests and execute production budget,
factory, initializer, ownership and configuration code with controlled adapters.
They do not measure iPhone physical savings or prove that every resource in the
map fits. The final package checks bind the new producer to the IPA.

No texture/upload leak is established by this run: map teardown releases
private textures, and completed initializer storage eventually reaches zero.
The latest texture capacity is 612 MiB, buffers 701 MiB, and Metal reports
1,426 MiB. These metrics overlap and must not be added. After game exit, seven
native threads still lack quiescence proof; their pages cannot safely be
recycled merely because Steam records a process exit.

Actual-device acceptance remains correct textures, completed map loading,
responsive input, sustained remote connectivity and measured memory headroom.
The JIT pool/partition, Steam/browser launch, UDP and game files are unchanged.
