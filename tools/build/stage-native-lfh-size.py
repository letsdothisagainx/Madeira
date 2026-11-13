#!/usr/bin/env python3
"""Keep ordinary LFH size reads off the unrelated shared heap lock.

The caller must own a live block. LFH allocation, free, resize and user-flag
updates already access its header without this lock. Reading that block's size
needs only its header; it does not touch the shared bin/group/free-list state.
All existing handle/pointer validation and every other heap path stay intact.
"""
from __future__ import annotations

SIGNATURE = "SIZE_T WINAPI RtlSizeHeap( HANDLE handle, ULONG flags, const void *ptr )"
ANCHOR = """    else
    {
        heap_lock( heap, heap_flags );
        status = heap_size( heap, block, &size );
        heap_unlock( heap, heap_flags );
    }
"""
FAST = """    /* Madeira: a live LFH block's size is private to its caller. Other
     * blocks cannot change this header, and LFH free/resize already bypass
     * the heap lock. Keep all checking and non-LFH paths serialized. */
    else if (block_get_type( block ) == BLOCK_TYPE_USED &&
             (block_get_flags( block ) & (BLOCK_FLAG_LFH | BLOCK_FLAG_LARGE | BLOCK_FLAG_FREE)) == BLOCK_FLAG_LFH &&
             !(heap_flags & (HEAP_VALIDATE | HEAP_VALIDATE_ALL | HEAP_VALIDATE_PARAMS |
                             HEAP_CHECKING_ENABLED | HEAP_TAIL_CHECKING_ENABLED |
                             HEAP_FREE_CHECKING_ENABLED | HEAP_PAGE_ALLOCS)))
        status = heap_size( heap, block, &size );
"""


def stage(source: str) -> str:
    if source.count(SIGNATURE) != 1:
        raise ValueError("LFH size overlay: expected one RtlSizeHeap function")
    start = source.index(SIGNATURE)
    end = source.index("\n}\n", start) + len("\n}\n")
    body = source[start:end]
    if body.count(ANCHOR) != 1 or "Madeira: a live LFH block" in body:
        raise ValueError("LFH size overlay: expected one original serialized size read")
    return source[:start] + body.replace(ANCHOR, FAST + ANCHOR, 1) + source[end:]
