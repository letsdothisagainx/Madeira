# CS2 team-picker capture: 5621b019

The November 12 run reached remote de_vertigo activation, a full state update,
and team selection. It did not establish responsive gameplay or independently
establish VAC-secured acceptance. No Valve code or protocol is changed here.

## Exact-image attribution

The previous IPA was inspected without rebuilding it in Actions run
[43335934636](https://github.com/letsdothisagainx/Madeira/actions/runs/43335934636).
Its recorded source is `5621b019d26fb1a080307c5f272208c2928c3e47`.

| Captured address | Attribution |
| --- | --- |
| Saved guest bucket `0x71d514f5c0` | `tier0.dll`, base `0x71d4e80000`, saved caller RVA `0x2cf5d8` |
| Actual host `0x7c3f90efb8` | FEX block metadata maps to `tier0.dll+0x28fa33`; bounded vector-copy loop |
| WOW native RVA `0x102ef0`, data RVA `0x386e38` | `IosWowSyscallC::Declined` diagnostic atomic increment |
| ARM64EC native RVAs `0x118960`, `0x11896c`, `0x118978` | `IosXpFex` transition counter and sampled-target ring writes |
| D3D11 native RVA `0x118774`, data RVA `0x301b50` | `DynamicBuffer::TrimCompletedForQueue`, `g_dynamic_warm_cache_credit` |
| Post-FULL native ntdll RVA `0x65290` | `memset+0xd0`, called by FEX `GenerateIR+0x540` |

The tier0 samples precede FULL. The saved frame RIP is not the executing guest
instruction, and the old fixed-base profiler heuristic mislabeled relocated
game DLLs as native callees. The proprietary tier0 PE/symbols are not included
in the archive, so its internal copy function's name is unverified. The IR
clear zeros `0x7e0` bytes of cached named IR-node references per block; removing
it would retain invalid references. No spin-loop, timeout-scale, or lost-input
defect was established.

## Production corrections

FEX diagnostic writers now use explicit, source-built private DATA contracts:
the WOW declined-syscall counter and ARM64EC transition counters/ring. The
loader binds only an unpublished owned image, validates module/architecture,
exact exported payload identity, sizes/alignment, section protections,
non-overlap and relocations, and preserves the descriptor during source-data
refresh. The selected RW address aliases the same backing bytes. All original
atomic operations, counts, branch decisions and security/protection behavior
remain in place. Unknown/unbound contracts retain ordinary fault recovery.
The final IPA gate also checks the compiled ARM64EC writer-load sequences.

DXMT's buffer-registry mutex, links, pressure controller, decision, warm credit
and bounded-report counter use one private heap-owned state instead of mutable
executable-image DATA. The lifetime follows the original namespace-scope
initialization/destruction order. This removes recurrent protected-image writes
from real cache bookkeeping without changing cache credits, pressure
watermarks, trim eligibility, GPU completion or resource ownership. It does
not allocate another texture/buffer cache or increase its budget. The compiled
ARM64EC state is 80 bytes per loaded runtime image, plus allocator overhead.

The existing profiler uses actual host image/JIT mapping classification for
native callees and labels the saved guest histogram accurately. Its sampling
rate is unchanged.

## Scope and verification limits

Tests exercise actual staged writer bodies/assembly, shared protected aliases,
counter values, atomic concurrency, malformed descriptors, refresh and process
isolation, compiled-consumer package checks, and DXMT registry ownership and
unchanged cache behavior. They do not simulate a successful CS2 match.

The protected-image regression faults on the old credit store and completes
128 registry/lease/trim cycles with the new immutable owner still read-only.
Old writable storage and new protected-owner storage produce identical credit,
backing and trim totals. The existing hot-buffer tests retain 1280/1280 and
32/32 reuse hits and enforce the same 32 MiB fixture cache budget.

All observed touch down/up pairs drain into Wine. After joining, legacy mouse
coordinates are center-clipped, while Wine emits raw input before that clamp.
This may be intentional mouselook; no coordinate override or automatic team
selection is introduced. CS2's actual UI dispatch remains unverified.

The 1152 MiB pool, 768/384 MiB partition, online transport, Steam state, buffer
cache limits, installed game and input policy are unchanged. Real iPhone
testing must establish lower exception cost, responsive team selection,
gameplay/FPS and continued memory headroom. Revert this change to roll back
the source fixes; no prefix or game-data migration is needed.
