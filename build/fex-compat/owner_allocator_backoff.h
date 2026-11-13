/* SPDX-License-Identifier: MIT */
#ifndef MADEIRA_FEX_OWNER_ALLOCATOR_BACKOFF_H
#define MADEIRA_FEX_OWNER_ALLOCATOR_BACKOFF_H

/* Included only in the pinned, generated Windows/iOS rpmalloc translation
 * unit. A successful explicit-heap acquisition arms this path: its mapper has
 * already entered Wine's NT VM interface. Before that boundary, including
 * constructor-time allocations, retain the original no-CRT polling behavior.
 * No FEX allocation, TLS, environment lookup or FEX wait-address state is
 * needed (Wine's NT layer owns its existing thread wait state). The recursive
 * owner/depth and acquire/release operations stay in
 * rpmalloc; sleeping never grants ownership or reports allocation success. */
#include <winternl.h>

NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN alertable, const LARGE_INTEGER* timeout);

static _Atomic(unsigned) madeira_fex_rpm_backoff_ready;

void fex_ios_rpm_enable_backoff(void) {
	atomic_store_explicit(&madeira_fex_rpm_backoff_ready, 1, memory_order_release);
}

/* Keep the mutable addresses local to leaf functions. Inlining these into
 * the nonleaf polling loop lets the compiler carry an address across a call
 * or merge its final store into an earlier block. Such a producer correctly
 * fails Wine's conservative native RW-alias proof. No pointer is passed out. */
static NOINLINE int madeira_fex_rpm_try_owner(uintptr_t self) {
	uintptr_t expected = 0;
	return atomic_compare_exchange_weak_explicit(&fex_ios_rpm_owner, &expected, self,
		memory_order_acquire, memory_order_relaxed);
}

static NOINLINE void madeira_fex_rpm_publish_depth(void) {
	fex_ios_rpm_depth = 1;
}

static NOINLINE void madeira_fex_rpm_backoff(void) {
	if (atomic_load_explicit(&madeira_fex_rpm_backoff_ready, memory_order_acquire)) {
		LARGE_INTEGER timeout;
		/* Relative 100us, nonalertable. A failed or interrupted delay still
		 * returns to the real CAS; no dependency on a matching wakeup. */
		timeout.QuadPart = -1000;
		NtDelayExecution(FALSE, &timeout);
	} else {
		wait_spin();
	}
}
#endif
