#!/usr/bin/env python3
"""Preserve native socket failures across the existing iOS observers.

The pinned Wine source stays unchanged. A changed producer boundary fails the
build rather than silently compiling an incomplete overlay or reusing an object.
"""
from pathlib import Path
import argparse
import re

ROOT = Path(__file__).resolve().parents[2]
INCLUDE = '#include "unix_private.h"'
BEGIN = '    while ((ret = sendmsg( fd, &hdr, async->unix_flags )) == -1)\n    {'
END = '\n    async->sent_len += ret;'
DESTINATION = '        if (sock_type == SOCK_DGRAM && ((unix_addr.addr.sa_family == AF_INET && !unix_addr.in.sin_port)'


def stage_source(text, header):
    if 'ios_socket_send_failure( fd, &hdr' in text:
        raise ValueError('socket error overlay already applied')
    if text.count(INCLUDE) != 1 or text.count(BEGIN) != 1 or text.count(DESTINATION) != 1:
        raise ValueError('native socket producer boundary changed')
    start = text.index(BEGIN)
    end = text.index(END, start)
    original = text[start:end]
    required = ['if (errno == EISCONN)', 'else if (errno != EINTR)',
                'if (errno != EWOULDBLOCK)', 'if (!attempt && errno == ECONNREFUSED)',
                'ios_sock_big_note( fd, 1, 0, errno );',
                'ios_sock_wire( fd, 1, NULL, 0, errno );',
                'ios_sock_tl( fd, 1, NULL, 0, errno );',
                'return sock_errno_to_status( errno );']
    if any(original.count(fragment) != 1 for fragment in required):
        raise ValueError('native send error handling changed')
    changed = re.sub(r'\berrno\b', 'send_error', original)
    # Keep the one source read immediately after the failed syscall; no
    # debug/cleanup routine runs before it. Function names remain unchanged.
    changed = changed.replace(BEGIN, BEGIN + '\n        const int send_error = errno;')
    changed = changed.replace('return sock_errno_to_status( send_error );',
        'NTSTATUS send_status = sock_errno_to_status( send_error );\n'
        '            ios_socket_send_failure( fd, &hdr, async->unix_flags, send_error, send_status );\n'
        '            errno = send_error;\n'
        '            return send_status;')
    text = text[:start] + changed + text[end:]
    text = text.replace(DESTINATION,
        '        if (sock_type == SOCK_DGRAM &&\n'
        '            ios_socket_invalid_datagram_destination( &unix_addr.addr, hdr.msg_namelen ))\n'
        '        {\n'
        '            ios_socket_send_invalid_destination( fd, &hdr, async->unix_flags );\n'
        '            return STATUS_INVALID_ADDRESS;\n'
        '        }\n' + DESTINATION)
    return text.replace(INCLUDE, INCLUDE + '\n#include "' + str(header) + '"')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    args.source.write_text(stage_source(args.source.read_text(),
        ROOT / 'build/ntdll-unix/socket_error_context.h'))


if __name__ == '__main__':
    main()
