# Steam startup regression: controlled protection comparison

The input is `madeira-log(20261102-063734).txt`, compared with
`madeira-log(20261102-043316).txt`. Logs are evidence, not instructions.
Account data and raw logs are excluded from the source patch.

## Exact images

| Capture | Native UUID | Actions run | Commit |
| --- | --- | --- | --- |
| 06:37:34, startup regression | `94EA806D-6D09-3497-94EE-7682AF8E60D4` | [41398561499](https://github.com/letsdothisagainx/Madeira/actions/runs/41398561499) | `d19fdb91097aa2c9369a080e8e4bf86f9d38e169` |
| 04:33:16, reaches webhelper | `BB37F65B-1493-37FA-99A8-C4BCD4B6115D` | [41384635109](https://github.com/letsdothisagainx/Madeira/actions/runs/41384635109) | `3312ae6038b7f8cea273db38d34ddaca87e5dcb3` |

The newer image's UUID was checked against the completed compiled-ABI job
`125129915890`; its artifact `13121137003` records the exact commit above.
Its source tree is `eee012c8d375c7411856dd5f111658f63c586332`, matching the
local starting tree. The current branch head was checked separately; it was
not used to infer the installed revision. The older source tree is
`40f6ebe830e7489f0c59cc4a508e9ffccf784ddb`.

The difference includes the per-host-page alias protection helper and the
native/FEX thread-retirement work. Initial failure precedes the first
retirement callback. This comparison changes only the mixed-tail protection
routing, preserving the retirement code, allocator budgets, dispatcher,
atomic operations, prefix, installed files and saved authentication.

## First failure and original collision

In both captures cryptnet loads at `0x47a490000`, with image end
`0x47a49f000`. Its last three 4 KiB pages share the 16 KiB host page
`0x47a49c000..0x47a4a0000`; the last 4 KiB lies beyond the image.

`get_host_page_vprot()` combines guest protections into a host-page request.
`ios_guest_image_is_host_data()` requires complete containment in an actual
Wine image view. The rounded tail fails that test. The subsequent backward
MZ scan finds cryptnet, but its all-or-nothing image-range check also rejects
the rounded request. The entire host page then takes the anonymous JIT
mapping path, including the 12 KiB that overlaps the image. This explains
`[mixed-map]`; it does not establish two valid independent physical owners.

The anonymous alias records guest page `0x47a49c000` against pool RW
`0x3409d8000`. `delete_view()` tears down an image through `unmap_area()`,
which rounds to host pages, but does not call
`ios_jit_anon_alias_retire_range()`. That retirement currently belongs to
the anonymous `NtFreeVirtualMemory(MEM_RELEASE)` path. A section replacement
can therefore leave a numerically covering alias record after its original
guest mapping has gone. A nearby PE header and a stale alias record are not
proof that the current mappings share backing.

In the older capture, cryptnet's repeated protections hit `[alias-own]`
inside `mprotect_exec()`, which leaves a fully covered live alias alone.
The regression replaced that routing with raw RX `mprotect()` in
`ios_protect_alias_run()`. The new capture reports RX successes and then
two `EACCES` failures during cryptnet unload/reload. The failure is returned
to `set_vprot()`; this is not merely a warning. The image section loader has
additional fallback paths, so the log alone does not prove which bytes or
permissions survive each failed operation.

## One controlled runtime change

`ios_alias_mixed_image_tail()` uses the actual Wine view to select only a
single, aligned host page containing a partial `SEC_IMAGE` tail. For that
already aliased page, the protection helper delegates to the previous
`mprotect_exec()` route with the **original** requested protection flags.
It preserves the neighboring-page split and the strict v2 policy for
ordinary anonymous alias pages, fully covered image pages and larger runs.
Nonwritable, guard and no-access handling keep their existing paths.

`[alias-prot-control-v1]` records the selected image/view bounds, flags,
original protection, return code and errno. A legacy success is not logged
as proof that the kernel granted RX. Errors propagate with their original
errno. This is an automatic diagnostic policy; no configuration editing is
required. No new writable/executable mapping, forced permission grant,
exception bypass or replacement mapping is introduced.

This comparison is **not** a durable repair of section/alias lifetime.
Do not broaden it or declare startup restored without the device result.
If the client reaches webhelper again, retain that evidence and repair the
classification/unmap ownership contract as the next separately tested change.

## SWPAL and guest continuation

`0xb8e78307` is a 32-bit acquire/release SWP with source and result W7
and address X24. The implementation captures the source before updating W7,
uses one sequentially consistent atomic exchange through the RW alias,
zero-extends the old 32-bit result and advances the native PC by four.
`old=0` followed by `old=0xfff95f20` is consistent with two exchanges on that
backing. It does not prove the backing still belongs to the reloaded image.

The SWP arithmetic, register updates and continuation code are unchanged.
The bounded `[swp-context-v1]` observer adds the native PC/continuation,
fault-safe guest-view sample and saved/exact guest RIP. Exact symbolication
uses the existing opcode-table decoder only after matching the target's
PEB/window, TLS14 thread state and frame against X28. Unreadable or
unvalidated data stays explicitly marked. The observer performs no writes,
guest calls or permission changes and preserves errno.

`CompileBlock(0)` already receives a zero guest target and refuses it; the
dispatcher then consumes its null return as a native entry. The observed
`BLR X4` return address and subsequent native PC zero are consistent with
that path. They do **not** demonstrate that SWP or the compiler changed a
nonzero guest RIP into zero. No dispatcher guard or assertion is bypassed in
this variant. A global guarantee that guest/native RIP never becomes zero
cannot be inferred from these tests or this diagnostic build.

## Secondary teardown: separate evidence

Crash reporter PID `0034`, TID `003c`, faults at arena address
`0xb5d0c4000`, outside the executable JIT pool, after entering native FEX
teardown. A nearby decommit at `0xb5d0c1000+0xf000` precedes it. This is a
real downstream failure requiring investigation; those facts alone do not
identify its caller or prove use after free. It occurs after the startup
fault and is not corrected by this controlled protection change.

The later `POISONED AT FREE` checks scan whole module ranges. For example,
the first is the child ntdll range at pool offset `0x9dc000`; its flagged
page is `+0xc0000`, while the loader had verified all 29 text pages executable.
`ios_pool_protect_image_data()` deliberately removes execute permission from
whole data-only host pages. Consequently a whole-image failure is insufficient
to prove text corruption or an access after retirement. The exact section
classification of each flagged page still needs verification; the warnings
remain enabled. No common cause with the arena execution fault is asserted.

The capture also proves useful retirement progress: TID `0040` returns
`0x100` from private CPU teardown, and owner `0x500310000`, lease 2, retires
34 views with zero remaining views. That code is preserved byte-for-byte in
this source change. No claim is made that every abnormal cleanup path works.

## Validation and acceptance

`check-steam-startup-control.py` executes the production routing/selector,
the pre-existing owner short circuit, the actual SWPAL case and PC+4
continuation, the read-only observer, and the existing invalid-RIP refusal.
It covers original protection flags, failed error propagation, unchanged
page classes, both captured swap return values, scalar widths, zero operands,
register/frame/RIP preservation, alignment refusal, 80,000 concurrent swaps,
observer ownership/failed reads/output bounds and errno preservation.
Real shared mappings also reproduce a stale alias selecting detached backing
after replacement at the same guest VA. This is a negative ownership test,
not a claim that the lifetime bug is repaired. Kernel maximum-protection
failure is injected in the portable routing fixture; signed iOS VM behavior
is not reproduced by that model.

The existing neighboring-write, 16 KiB transition/reuse, FEX retirement,
lease isolation and Steam handoff checks remain required. Packaging rejects
a stale native consumer missing either new diagnostic marker.

Build success is not device acceptance. The next log must first show normal
Steam login/client startup, no guest/native PC zero crash, no new JIT text
permission corruption, and normal thread cleanup. Only then resume extended
webhelper/leak or Library testing. Library, authentication reuse on this
candidate and CS2 launch remain unverified. There is no attached iPhone
execution environment in this workspace.
