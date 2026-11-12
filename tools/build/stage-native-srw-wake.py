#!/usr/bin/env python3
"""Omit an SRW exclusive wake when the last reader has no writer to wake.

An exclusive contender increments exclusive_waiters before it checks owners.
If it publishes before the reader's ownership CAS, that CAS observes the count
and the wake remains. If it publishes later, it can acquire the unlocked state
or wait behind a subsequent reader whose release observes its count. Shared
waiters use the whole lock word, rather than the owners address; their wake
still belongs to the exclusive-release path.
"""
from __future__ import annotations

SIGNATURE = "void WINAPI RtlReleaseSRWLockShared( RTL_SRWLOCK *lock )"
ORIGINAL = "    if (!new.s.owners)\n        RtlWakeAddressSingle( &u.s->owners );"
GUARDED = "    if (!new.s.owners && new.s.exclusive_waiters)\n        RtlWakeAddressSingle( &u.s->owners );"


def stage(source: str) -> str:
    if source.count(SIGNATURE) != 1:
        raise ValueError("SRW wake overlay: expected one shared-release function")
    start = source.index(SIGNATURE)
    end = source.index("\n}\n", start) + len("\n}\n")
    body = source[start:end]
    if body.count(ORIGINAL) != 1 or GUARDED in body:
        raise ValueError("SRW wake overlay: expected one original last-reader wake")
    return source[:start] + body.replace(ORIGINAL, GUARDED, 1) + source[end:]
