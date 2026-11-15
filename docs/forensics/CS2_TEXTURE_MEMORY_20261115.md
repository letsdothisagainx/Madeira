# CS2 texture-loading memory pressure, November 15

## Evidence and limits

The tested source is `74f426bb2e04e9cba0fe8a9924d31f68f468032e`.
Its native log ends at 6,135 MiB physical footprint, against a reported limit
near 6,144 MiB. No fatal Windows exception or official iOS termination report
establishes jetsam independently. Memory-pressure termination is the leading
explanation, rather than a confirmed termination reason. This standalone log
does not identify the final multiplayer state.

Near the end, adjacent native wall-clock checkpoints show approximately
5,875 MiB at 17:36:03.206, 6,046 MiB at 17:36:04.690, and 6,135 MiB near
17:36:04.991. These are adjacent native observations, not subtraction between
Wine and app monotonic clocks. Growth of roughly 260 MiB within two seconds
leaves little opportunity for a late memory warning.

The final compared resource snapshots show:

| Metric | Earlier | Later | Meaning |
| --- | ---: | ---: | --- |
| Texture accounting | 2,093 MiB | 2,684 MiB | Requested-capacity estimate; old BC calculation is wrong |
| Buffer accounting | 597 MiB | 660 MiB | Requested capacity, not separately additive physical bytes |
| Initial uploads | 32 MiB | 32 MiB | One retained/reusable heap; 46 allocations, 45 frees |
| Staging ring | 36 MiB | 32 MiB | Completed reuse/release works; 500 allocations, 499 frees |
| Metal allocated size | 1,321 MiB | 1,589 MiB | Metal accounting, distinct from process footprint |
| Texture allocations/frees | 6,255/2,875 | 6,911/3,269 | Net increase of 262 allocation wrappers |

Earlier texture accounting drops from over 2 GiB to about 1 GiB while resources
are freed. Neither an unconditional texture leak nor a retained upload-heap leak
is established. Metal and DXMT figures must not be added together.

The BC census is cumulative creation history: its 6,272 resources and roughly
2 GiB logical bytes do not describe current live residency. Hardware reports
native BC support; the monitored software decode/refill counters are zero.
The native-BC capacity estimator incorrectly used decoded texel sizes, further
preventing interpretation of its old values as physical texture memory.

Existing process retirement and decommit are functioning: recorded dead owners
have no remaining reclaimable/unsafe views; 2,513 decommit remaps use no
synchronous fallback, with no deferred punches left queued. Those paths and the
1,152 MiB JIT pool are preserved. The prior rendering baselines are different
workloads; the new scheduler did not change worker limits or resource ownership.

## Confirmed implementation defects

1. Destination texture allocation was unconditional. Upload backpressure only
   considered growth of the temporary upload heap. Reusing a warm 32 MiB heap
   therefore allowed many new private textures without checking process headroom.
2. A non-null `TextureAllocation` wrapper could contain a nil Metal texture.
   The device-texture factory then initialized/published it with `S_OK`.
3. Native BC capacity accounting used decoded sizes, and cube faces were not
   included. That estimate is unsuitable for admission of native BC resources.
4. The vertex-descriptor pipeline factory retained its `alloc/init` creator
   reference after assigning the descriptor to Metal's copying property.
   This leak is real; its physical contribution to this run is unmeasured.

## Production changes

### Admit whole texture creations before allocating backing

`ResourceGrowthPermit` uses the existing pointer-free native control ABI with
new admission/release operations. The native producer samples real process
footprint and `os_proc_available_memory()` on every creation, serialized with a
bounded table of outstanding creation credits. It does not rely on the older
per-thread 100 ms snapshot for permission to grow. Charges use the physical mip
selection and the actual device's native-BC capability.

The soft pressure watermark remains one eighth of measured process capacity,
clamped to 128--1,024 MiB. Its recovery watermark is one quarter higher. The
hard growth safety floor is half that reserve, clamped to 128--512 MiB:
approximately 768 MiB soft pressure and 384 MiB protected headroom on this
6,144 MiB launch. Applying the soft trim watermark as an unconditional hard
limit would unnecessarily reject previous valid loading states.

A permit remains held through backing creation and all initial-data/zero-fill
encoding. Concurrent callers cannot all spend the same observed headroom.
Its owner and process generation are verified on grant/release. Interrupted
creators' credits are retired only after Wine's existing complete native-thread
quiescence proof, before that generation/window is recycled. No receipt expires
by age, and a foreign/successor owner cannot release another generation's credit.
This retirement frees metadata credit, not guest or GPU memory.

Pressure requests reclaim only GPU-complete transient/cache entries. The normal
hot-buffer cache policy remains intact. Equivalent sweeps are deduplicated by
queue domain, completion frontier and requested growth to avoid scanning the
buffer registry for every texture. A denied request can submit genuine pending
uploads and wait at most 50 ms on their GPU-signalled event, outside the
initializer mutex, then remeasure/retry. Continued denial returns a real
`E_OUTOFMEMORY`; it never drops uploads and reports success.

For a granted pressured creation, initial uploads are submitted after the whole
texture has been encoded and before its CPU creation credit is released. This
helps avoid retaining only CPU-side initialization work while the GPU is idle.
Submission does not pretend GPU completion. Existing retained references and
completion frontiers still govern upload/resource retirement.

Backing is checked before rename, upload, or publication on ordinary, shared
and renamable-depth creation paths. A nil native texture now produces an actual
failed creation with a null output resource. The global allocator's return
contract is unchanged for unrelated callers.

Creation credits bound CPU-concurrent loading bursts. They do not reserve a
texture's entire lifetime, control unrelated guest allocations, or guarantee
when Metal charges lazy residency. No application-side policy can promise that
all live assets fit or that iOS will never terminate the process.

### Visible lower-memory CS2 profile

CS2's Compatibility settings now offer Automatic, Balanced and Full quality.
Automatic selects Balanced on a measured process budget at or below 8 GiB, or
an unknown budget. Balanced enables the existing `d3d11.mipClampAuto` policy.
It removes one top mip only from eligible large BC textures created under
pressure, using the existing 1,536 MiB headroom threshold. It leaves smaller
textures and render targets, CPU-access, shared and exotic resources alone.
Existing initial uploads, arrays/cubes, SRVs and streamed subresource remapping
remain in charge of valid data and bindings.

This is an explicit lower-resolution quality choice, not transparent full-quality
residency. Shader explicit LOD and GetDimensions observe physical storage.
Full quality disables the automatic reduction and can require more memory.
Explicit custom mip options remain authoritative. Other games/probes are not
changed, the DXMT configuration-length limit is preserved, and Valve files are
not edited. The optional library preference preserves existing library data,
UUIDs, controls, Steam identity and configuration.

### Correct ownership and capacity

The native pipeline factory releases only the creator reference of
`MTLVertexDescriptor`, after assigning its layout to the pipeline descriptor.
No live texture, buffer or GPU command reference is removed.

The tight requested-capacity helper uses 4x4 blocks of 8 or 16 bytes on native
BC devices, decoded sizes on fallback devices, all mips/depth/slices/cube faces,
and saturating arithmetic. It is still not a residency or driver-padding
measurement. Correcting it does not itself free physical memory.

## Verification and remaining device acceptance

Focused checks exercise actual production budget/header/factory code with
controlled native measurements, concurrent creators, cancellation/generation
proofs, real failed-backing HRESULTs, bounded GPU-event retry and completion-safe
reclamation. Accounting uses independent reference cases. Mip-policy tests use
the existing production formulas. macOS additionally executes real Metal
vertex-descriptor ownership and Swift library/launch-profile tests. Final IPA
checks must prove the compiled capabilities, all three PE ABIs, native source
provenance and exact packaged bytes.

These are not measurements of CS2 on iPhone. The device must still establish
peak physical footprint, practical headroom, completed loading, correct images,
responsive team selection, sustained multiplayer and frame timing. No new FPS,
loading-time or confirmed jetsam result is claimed from host tests.

Install over the existing Madeira application with the same signing identity
and bundle ID. No Wine-prefix, Steam, game-file or controller migration occurs.
The prior `74f426bb` IPA provides rollback using the same update method.
