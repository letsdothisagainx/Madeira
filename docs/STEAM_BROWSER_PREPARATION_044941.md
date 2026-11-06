# Browser preparation: November 6 short capture

The 45-line capture identifies installed source `97d4abcc` and ends during the
first official-package download, before Wine starts. It establishes neither a
crash nor a stalled download. It does not evaluate that commit's native allocator,
IPC, service or fault-rate changes.

The old cache contains `bin/cef/cef.win7/debug.log`. Strict reuse therefore rejects
it. One rebuild is expected on this upgrade: preparation verifies all three pinned
Valve archives and all 80 completed records, then retains the entire old tree and
commits the newly verified tree. An interrupted attempt preserves the old tree and
can be retried through Play. No verifier exception, binary pin or cache migration
rule was changed.

Previously no transfer event appeared between package start and completion. The
preparation flow now reports bounded numeric response/byte/elapsed-time states,
including a 15-second heartbeat, followed by SHA verification, extraction and
commit stages. Errors report cancellation or retry eligibility without URLs,
credentials or private paths. There is no new automatic retry loop or launch gate.

The existing mutable-log setup still runs after successful cache/bridge preparation
and before Wine. Its exact-file native redirect is unchanged. Tests exercise the
actual staged NtCreateFile body and strict Swift preparation/reuse separately from
the unmodified official helper running under stock Wine. Stock Wine has no Madeira
iOS file hook; that control cannot prove same-process on-device redirection.

The official-archive upgrade regression covers failed transfer, actual task
cancellation, altered-package rejection, retained-tree preservation, full rebuild,
a native-handler write outside the cache, and strict next-launch reuse with zero
download calls. On-device acceptance remains: allow preparation to finish, confirm
the owned-mutable log route after Wine starts, and confirm the next launch reuses
80 records without downloading. Service status, native64/I386 master-section IPC,
fault reduction, UI responsiveness and CS2 launch also remain device checks.
