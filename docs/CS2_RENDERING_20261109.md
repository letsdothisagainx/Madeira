# CS2 rendering investigation, November 9

No texture or shader translation root cause has been demonstrated for the
reported missing graphics. This change adds a real pixel readback probe and
bounded geometry observations; it does not claim to fix CS2's rendered image.

The supplied `DC4B7153-5EEE-472C-B91A-FE22FDC0FA4D/1-madeira-log.txt`
was inspected against the clean DXMT pin `05876bb6738b879f1da92a1f7f7e118ef2158d96`.
Source was read from an existing checkout with that exact gitlink. Vendor
source and Valve files are unchanged.

## Evidence and remaining uncertainty

| Observation | What it establishes |
| --- | --- |
| Log line 46472: `supportsBCTextureCompression = YES`, device `AGXG18PDevice` | This run uses native BC textures. The no-BC CPU decoder, remap and synthetic BC6H fallback do not explain this run. |
| Line 54894: parent format 130, requested 131, physical 131 | A native BC1 linear allocation successfully produced an sRGB Metal view. It does not establish correct sampling by every game shader. |
| Lines 50840, 60764: physical formats 152 and 151, correct block pitches and mip/slice indices | Native BC7 and BC6H uploads were encoded. In Metal's enum 152 means BC7, 134 means BC3. Upload fingerprints sample only a prefix and do not validate an entire resource. |
| Last periodic census, lines 61661–61678: 3,712 BC resources and 1,279,323 KiB cumulative logical bytes | Cumulative creation volume, not simultaneous live texture bytes, physical residency, a leak or corruption. Most resources are immutable typeless textures with initial data and paired linear/sRGB views. |
| Sampled libraries, pipelines, views, uploads and command buffers report no native API error | No sampled API failure was identified. A successful object or completed command buffer does not establish correct pixels. |
| Hundreds of draw calls per frame; GPU busy roughly 2–5% late in the run | Work is being encoded and submitted. These counters do not identify a shader correctness defect or prove all game geometry is visible. |
| `ParseInstruction` / `read_control_flow` samples | Normal shader parsing is active; samples alone do not demonstrate malformed control flow, repeated cache misses or nontermination. |

The traced resource path is `CreateDeviceTextureInternal` → normalized logical
descriptor and physical `Texture` → per-array-slice, per-mip initializer uploads.
`MTLQueryDXGIFormat` retains BC format identity, view normalization selects the
requested linear/sRGB format and mip/slice range, and `Texture::createView`
keys all those properties. Native `to_metal_pixel_format` leaves BC unchanged
when the device supports it. The shader cache keys both shader SHA-1 and variant
SHA-1, separates Metal versions and uses format/depth/sample/blending inputs
for pipeline variants. No demonstrated mismatch in these paths justified a
rendering-semantic patch.

The old `drawable-presented` probe counted a zero `presentedTime` as an error.
Zero supplies no valid presentation timestamp; it is not a Metal `NSError`.
The owned staging copy now reports `timestamp=unavailable` and
`callback-without-valid-presentation-timestamp` separately. Positive timestamps
still do not validate menu pixels.

The old log establishes a 640×480 virtual monitor, not the actual game's
swapchain backbuffer size. `ResizeBuffers` uses explicit application dimensions,
or the window size for zero dimensions. `ApplyLayerProps` passes those dimensions
times the spatial scale to the presenter and Metal layer. New
`[metal-geometry-v1]` observations record layer requested/final sizes, acquired
drawable texture size, render attachment zero size and viewport zero size.
Their independent limit is eight dimension changes per kind, 32 lines total;
unchanged sizes are omitted. These are native Metal observations, not a query
of the application's original DXGI arguments or proof of valid frame contents.

## Run the bundled pixel probe on iPhone

1. Open **Settings → Interface → Use developer interface** and restart Madeira.
2. In portrait, enable JIT using the existing button. Scroll the horizontal action
   buttons to **DX11 pixel readback**, beside **x64 DX11 cube**, and tap it.
3. Read or export the existing log. The probe reports `[d3d11-pixels] PASS
   readbacks=113 failures=0` only after checking every pixel of every readback.
   API failure, a wrong backend, a pixel mismatch or a 30-second GPU completion
   timeout reports `FAIL` and exits unsuccessfully.
4. Restart before a game session. **Use New Interface** returns to the library
   on the next restart.

No files need to be copied or edited. The normal IPA build compiles and bundles
the owned x64 executable using the existing LLVM MinGW toolchain, and packaging
checks its real PE imports, x64 loader path and reporting contract. The probe
requests a hardware D3D11 device and requires DXMT's actual `IMTLDXGIDevice`
identity. It does not substitute WARP or another graphics backend.

The 113 offscreen readbacks cover native BC1/3/4/5/6H/7 typeless allocations,
linear/sRGB views where supported, two array slices, four mip levels including
2×2 and 1×1 tails, padded upload rows, immutable initialization, default-resource
update/copies, relative view mip ranges, dynamic shader branches and loop
continue/break, floating-point/UNORM targets, alpha blending, and passing/failing
depth tests. Blocks and expected texels are owned, deterministic inputs; BC6H
coverage is a zero block and BC7 coverage is mode 6, not all format modes.

This offscreen test does not cover presentation, every CS2 shader, streaming
scenario or asset. A passing device result narrows the fault; it does not certify
CS2 rendering.

## Validation status

Passed locally: strict x64 PE compilation with Zig 0.15.1, actual PE contract
validation and corrupt-image rejection, the 47 existing production BC decoder
host checks, and the existing diagnostic staging/sanitizer tests extended with
concurrent geometry budgets and unchanged Metal operation contracts.

The actual D3D11 GPU readbacks have **not been executed in this Linux
workspace**. The iPhone result and staged Objective-C compilation against the
iPhoneOS SDK remain required device/Apple-CI evidence. Host checks print that
distinction explicitly.

## Follow-up capture DB9C3F84, candidate 4a70400

The later log has no `[d3d11-pixels]` execution record. It does demonstrate
failed GPU work: frame 301 reports `MTLCommandBufferErrorDomain` code 7,
`BackgroundExecutionNotPermitted`; frames 848–850 repeat the same native error.
This identifies submission while iOS denies background GPU execution. It does
not establish that every missing game graphic came from those failures, and
no shader/BC format root cause was demonstrated. Native BC remains supported.

The owned native submission correction holds encoded command buffers while
the UIKit application is inactive and submits them after activation. Normal
Wine/encoding producers sleep on a condition, preserving their work and queue
backpressure. A UIKit-main submission uses a retained deferred entry instead
of waiting for an activation callback on its own run loop. A FIFO preserves
submission order across these entries. The UIKit state setter never waits on
that condition or on GPU completion; its mutex covers native commit calls, so
an already-entered commit can briefly hold it. All Metal statuses, errors,
events and completion callbacks remain native results. Already submitted work
is not retried or reported as successful after a native error.

The main-thread deferred path is not used by the production DXMT D3D11 encoder,
which submits from Wine/encoding workers. It is not a facility for a UIKit
caller to synchronously wait for GPU work while inactive. Asynchronous work
can resume only after UIKit delivers activation. Commit-request wall timing
includes any lifecycle pause; `[metal-progress-v1] event=command-submit-request`
therefore identifies a request rather than completed native submission.

The production FIFO policy passed ASan/UBSan tests for paused work, mixed
worker/deferred ordering, cancellation cleanup, 8,000 exact-once submissions
and 10,000 lifecycle transitions. This tests admission, not emulated GPU
completion. Actual iPhone background/foreground validation remains required.

The monitor is 800×450 in this capture, while SDL's window is already 640 wide
before Metal setup (`{80,0,720,450}`), and the requested layer and acquired
drawable are 640×450. No Metal downsize was found. Original DXGI arguments and
the initial client rectangle are absent, so explicit application sizing versus
earlier window geometry remains unproven; no forced resize/upscale is applied.

## Normal-library pixel test access

Settings → Diagnostics → **Run D3D11 pixel test** now enables JIT through the
normal flow and starts the bundled probe as a transient Library session. Close
Wine first and restart after any previous session when the one-session rule
applies. The action copies only the owned bundled executable into a newly
created `drive_c/madeira-graphics-probe-<UUID>/` directory. It never adopts an
existing directory or replaces a prefix file, and does not save a Library entry,
change the game profile or override the renderer. The small owned stage is
retained; no unowned directory is deleted during cleanup.

The probe checks DXMT identity itself. Its actual `[d3d11-pixels]` log is the
result; staging/compilation success is not a GPU pass. Share the Madeira log
after the test and restart before returning to a game. This removes the need
to switch to the developer interface to run the same 113 readbacks.
