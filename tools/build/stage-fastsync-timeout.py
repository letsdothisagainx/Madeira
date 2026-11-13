#!/usr/bin/env python3
"""Charge native fastsync lookup, spinning and parking to relative waits.

Only the generated iOS unix sync translation unit is changed. Expired waits
still reach server_wait with a zero timeout, retaining its object, APC and
error checks. Absolute deadlines and explicit zero polls keep their routes.
"""
from pathlib import Path
import sys

SIGNATURE = "static NTSTATUS madeira_fast_wait( HANDLE handle, const LARGE_INTEGER *timeout,"
MARKER = "/* Madeira: relative waits include lookup and both spin phases. */"


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("fastsync timeout overlay: expected one source anchor")
    return source.replace(old, new, 1)


def stage(source):
    if source.count(SIGNATURE) != 1 or MARKER in source:
        raise ValueError("fastsync timeout overlay: missing, duplicate or staged function")
    start = source.index(SIGNATURE)
    end = source.index("\n}\n", start) + 3
    body = source[start:end]
    body = replace_once(body,
        "    unsigned long long t0, spent = 0, budget_ns;",
        "    unsigned long long t0, spent = 0, budget_ns, wait_t0 = 0, timeout_ticks = 0;")
    body = replace_once(body, "    *fallback = timeout;", """    *fallback = timeout;
    /* Madeira: relative waits include lookup and both spin phases. */
    if (timeout && timeout->QuadPart < 0)
    {
        timeout_ticks = 0ull - (unsigned long long)timeout->QuadPart;
        wait_t0 = madeira_now_ns();
    }""")
    # Misses still use the original server route; charge the time spent learning
    # a handle too. Do not alter the explicit zero-poll peek's return value.
    if body.count("        return STATUS_NOT_IMPLEMENTED;") != 2:
        raise ValueError("fastsync timeout overlay: unexpected early fallback paths")
    body = body.replace("        return STATUS_NOT_IMPLEMENTED;", "        goto fallback;")
    body = replace_once(body,
        "            unsigned long long s0 = madeira_now_ns();\n            for (;;)",
        """            unsigned long long s0 = madeira_now_ns();

            if (timeout_ticks)
            {
                unsigned long long elapsed = (s0 - wait_t0) / 100, left;

                if (elapsed >= timeout_ticks) goto fallback;
                left = timeout_ticks - elapsed;
                if (left <= spin_ns / 100) spin_ns = left * 100;
            }
            for (;;)""")
    old = """    /* never park past the caller's own relative timeout */
    budget_ns = madeira_fast_cap_ns;
    if (timeout && timeout->QuadPart < 0 &&
        (unsigned long long)(-timeout->QuadPart) * 100 < budget_ns)
        budget_ns = (unsigned long long)(-timeout->QuadPart) * 100;

    /* `rounds' bounds the loop independently of the clock, so a clock that
     * stops or jumps cannot turn it into an unbounded spin. */
    t0 = madeira_now_ns();"""
    new = """    /* Keep the existing park cap, within the original relative deadline. */
    budget_ns = madeira_fast_cap_ns;
    t0 = madeira_now_ns();
    if (timeout_ticks)
    {
        unsigned long long elapsed = (t0 - wait_t0) / 100, left;

        if (elapsed >= timeout_ticks) goto fallback;
        left = timeout_ticks - elapsed;
        if (left <= budget_ns / 100) budget_ns = left * 100;
    }

    /* `rounds' bounds the loop independently of the clock, so a clock that
     * stops or jumps cannot turn it into an unbounded spin. */"""
    body = replace_once(body, old, new)
    old = """    if (timeout && timeout->QuadPart < 0)
    {
        /* This function can only have consumed budget_ns of the caller's
         * wait, so charge at most that: clock overshoot must never drive the
         * remainder to 0, which server_wait treats as a poll. */
        long long left;

        spent = madeira_now_ns() - t0;
        if (spent > budget_ns) spent = budget_ns;
        left = -timeout->QuadPart - (long long)(spent / 100);
        store->QuadPart = (left > 0) ? -left : 0;
        *fallback = store;
    }"""
    new = """fallback:
    if (timeout_ticks)
    {
        unsigned long long elapsed = (madeira_now_ns() - wait_t0) / 100;

        /* A genuinely expired relative wait becomes a server poll, so the
         * server still checks the object and pending system APCs first. */
        store->QuadPart = elapsed >= timeout_ticks ? 0 :
                         (long long)(0ull - (timeout_ticks - elapsed));
        *fallback = store;
    }"""
    body = replace_once(body, old, new)
    source = source[:start] + body + source[end:]
    # The existing adaptive helper also negated LLONG_MIN and multiplied long
    # durations before clamping. Compare in 100 ns units before conversion.
    old = """    if (timeout && timeout->QuadPart < 0 &&
        (unsigned long long)(-timeout->QuadPart) * 100 < ns)
        ns = (unsigned long long)(-timeout->QuadPart) * 100;"""
    new = """    if (timeout && timeout->QuadPart < 0 &&
        0ull - (unsigned long long)timeout->QuadPart <= ns / 100)
        ns = (0ull - (unsigned long long)timeout->QuadPart) * 100;"""
    return replace_once(source, old, new)


if __name__ == "__main__":
    path = Path(sys.argv[1])
    path.write_text(stage(path.read_text()))
