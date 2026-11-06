# CS2 D3D11 construction: November 6 capture

The iPhone capture `madeira-log(20261106-073643).txt` runs public source
`54b91d50636922db9e1b90bd71e87af3a7debe56`. Exact packaged-image inspection
in Actions 42183627986 identifies ARM64EC d3d11.dll SHA-256
`08e2eccae5a758ed6c15a3e8ca34de0d56266565aa69f1d0e87d07449d318671`.

## Proven failure

`d3d11.dll+0x102ddc`, instruction `c80f7d89` (`STXR W15,X9,[X12]`), faults
writing its live peak-memory census through RX `0x322e94bc0`; the valid RW
alias is `0x36ae94bc0`. This is inside the ArgumentEncodingContext constructor,
after creation of its dummy constant buffer. Two preceding atomic additions
complete. The peak maximum's different compiler-generated weak-CAS sequence
is rejected: the discard-load helper requires an adjacent exclusive load;
the add helper requires an adjacent load/arithmetic pair. This sequence has
an intervening compare, conditional branch and address recomputation instead.

The complete core at RVAs `0x102dc8..0x102e0c` is:

```text
ADD X10,X8,#0xa0; LDXR X11,[X10]; CMP X11,X12; B.NE mismatch
ADD X12,X8,#0xa0; STXR W15,X9,[X12]; CBNZ W15,conflict
MOV W12,#1; test: TBNZ W12,#0,continuation
CMP X9,X11; MOV X12,X11; B.HI load; B continuation
mismatch: MOV W12,WZR; CLREX; B test
conflict: MOV W12,WZR; B test
```

X11 retains the observed value; X12 has become an address at the fault.
Using X12 as the expected value or treating STXR as an unconditional store
would corrupt the operation. Wine delivers the rejected access as
`0x80000002`, unwinding through d3d11 and rendersystemdx11 into the game's
device-creation error. This establishes one construction blocker, not the
absence of further graphics errors.

## Correction and scope

The Mach handler independently validates live code/data ownership tokens,
generations, the entire 18-word control-flow pattern, retained comparison
flags, both address producers, original load value and maximum condition.
It attempts one real compare-exchange through the checked RW alias. Success
sets W15=0; a conflicting writer leaves data unchanged and sets W15=1 so the
original native failure/reload path executes. Registers and flags are retained;
the shared handler advances PC by four only after a completed attempt.
No exclusive monitor is assumed to survive or transfer across the exception.
Unknown sequences still follow normal exception delivery.

No DXMT binaries, capabilities, HRESULTs, pool sizes, Steam paths or user data
are changed. Existing adjacent-loop and STR handling remains intact.

## Validation boundary

Portable tests compile the actual production handler and mapping accessors,
reproduce old-handler rejection, check 118 success/failure/ownership contracts
and race six recovery workers with a direct RW writer. The Apple-only gate
executes the exact captured instructions against real RX/RW aliases, including
a separate writer forcing a genuine conflict while the faulting thread is
suspended. Existing atomic, STR, ownership and allocator gates remain required.

The device log proves adapter recognition and selection of feature level 11_1;
it does not contain a completed device-creation HRESULT, swapchain creation
or first game Present. A new iPhone run must confirm those operations, absence
of the rejected STXR and progress toward the actual menu. CI cannot establish
that CS2 is playable or that this is its final startup blocker.

## Next capture: retained-expected strong compare-exchange

`madeira-log(20261106-085457).txt` verifies installed source `85e64ac` and
two successful recoveries of the original peak-max operation. Its next fatal
fault is the same packaged d3d11.dll at RVA `0xff3bc`, `c80c7d69`
(`STXR W12,X9,[X11]`). RX `0x31e700c38` and RW `0x366700c38` are valid;
mapping 219 is live. Wine delivers `0x80000002` and CS2 terminates. No pool
or FEX initialization exhaustion is established in this capture.

The exact image disassembly identifies BufferAllocation's
`g_mem_census.report_hwm.compare_exchange_strong(hwm,total,relaxed)` at offset
`0x118`. This separate report threshold follows the already-working requested,
live and peak counters. The complete atomic core is:

```text
ff3a8 9104632a ADD X10,X25,#0x118
ff3ac c85f7d4b LDXR X11,[X10]
ff3b0 eb08017f CMP X11,X8
ff3b4 54000dc1 B.NE ff56c
ff3b8 9104632b ADD X11,X25,#0x118
ff3bc c80c7d69 STXR W12,X9,[X11]
ff3c0 35ffff6c CBNZ W12,ff3ac
```

The success path executes its original ADRP/ADD/BL to `mem_census_report`;
the mismatch block is `ff56c CLREX; ff570 B ff3d0`. X8 is unchanged throughout
the core. Saved NZCV `0x60000000` proves the load equalled X8 before X11 became
an address. The previous 18-word helper requires an independently retained
loaded register, a forward failure branch and its maximum-update tail; this
strong-CAS retry/cleanup shape correctly fails that separate proof.

The added structural recognizer accepts six distinct register roles and
unshifted address offsets, rather than one opcode, RVA or threshold. It proves
the seven-word core plus decoded CLREX/branch cleanup and continuation in one
executable mapping generation. The load address and recomputed store address
must agree. A real CAS compares the writable alias against the retained
expected register; only the status register changes. On conflict, the original
CBNZ reloads and performs its own comparison/mismatch cleanup. No maximum-order
test is imposed on a general strong compare-exchange. The prior peak-max
recognizer, mapping permissions, graphics code and capabilities are unchanged.

Seven report-watermark sites in the shipped image use this compiler family,
at RVAs `0x678cc`, `0xff3bc`, `0x100f1c`, `0x101220`, `0x102e6c`,
`0x1197a8` and `0x11ba04`. Source-level tests must retain the prior peak cases
and exercise register reuse, native retry, mismatch cleanup and a real competing
writer. The new capture still has no completed D3D creation HRESULT, swapchain
or first-frame witness. Those remain device acceptance requirements.

Apple ARM64 validation 42220368533 passes both captured families. The new
production-handler regression checks 75 contracts against all seven shipped
loops, including old-handler rejection. Actual Mach execution records 1,604
new-sequence faults, 479 successful CAS attempts and 1,125 conflicts; original
retry/CLREX, retained registers/flags and RX nonwritability are verified.
These fixture results do not establish an iPhone graphics or performance result.
