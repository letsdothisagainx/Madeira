#!/usr/bin/env python3
"""Correct partial positional scatter reads in the immutable Wine build copy."""
import argparse
from pathlib import Path

OLD = "min( length - pos, page_size - pos )"
NEW = "min( length, page_size - pos )"


def stage(text):
    start = text.index("NTSTATUS WINAPI NtReadFileScatter(")
    end = text.index("\n}\n", start) + 3
    body = text[start:end]
    if body.count(OLD) != 2:
        raise ValueError("NtReadFileScatter partial-read boundary changed; refusing stale correction")
    body = body.replace(OLD, NEW)
    eof = "    if (total == 0) status = STATUS_END_OF_FILE;"
    if body.count(eof) != 1:
        raise ValueError("NtReadFileScatter error boundary changed; refusing stale correction")
    # Zero transferred bytes on a native error are not an EOF observation.
    body = body.replace(eof, "    if (status == STATUS_SUCCESS && !total) status = STATUS_END_OF_FILE;")
    body = body.replace("    while (length)\n", "    /* length is already the remaining byte count; pos only limits this page. */\n    while (length)\n", 1)
    return text[:start] + body + text[end:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    original = args.source.read_text()
    updated = stage(original)
    args.output.write_text(updated)


if __name__ == "__main__":
    main()
