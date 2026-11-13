#!/usr/bin/env python3
"""Correct native traffic-class aliases and WoW64 ancillary-data lengths.

Packet bytes and asynchronous receive behavior are unchanged. No game packet,
endpoint, route or authenticated protocol is inspected or rewritten.
"""
import argparse
import hashlib
import json
from pathlib import Path


BEGIN = 'static int wow64_translate_control('
END = '\nstruct ip_hdr\n'
ORIGINAL_SHA256 = '9b06446268818a7178b3a5bc1b58c7c85e66c83fd1e4918980d3e74caa5da7e4'
NATIVE_BEGIN = 'static int convert_control_headers('
NATIVE_SHA256 = '333ac49d121418a514cb117be044215ae7b6b2ce9ef7e10292eeaec1dfb2d46b'
MARKER = 'madeira-control32-bounded-payload-v1'
CAPABILITY = 'MadeiraSocketControl:traffic-class-bounds-v1'
CONTRACT = '''/* Immutable build capability; no runtime work or diagnostic output. */
static const char madeira_socket_control_contract[] __attribute__((used)) =
    "MadeiraSocketControl:traffic-class-bounds-v1";

'''

REPLACEMENT = '''static int wow64_translate_control( const WSABUF *control64, struct afd_wsabuf_32 *control32 )
{
    /* madeira-control32-bounded-payload-v1: source/destination headers have
     * different widths. Only their payload is common; never copy a native
     * header's length from the payload pointer. This is a format conversion,
     * not permission to truncate or synthesize ancillary data. */
    char *const buf32 = afd_guest_ptr(control32->buf);
    const size_t max_len = control32->len;
    const char *ptr64 = control64->buf;
    char *ptr32 = buf32;
    size_t remaining64 = control64->len, used32 = 0;

    if (remaining64 && (!ptr64 || !buf32)) goto error;
    while (remaining64)
    {
        WSACMSGHDR cmsg64;
        struct cmsghdr_32 cmsg32;
        size_t payload, size32, step32, step64;

        if (remaining64 < sizeof(cmsg64)) goto error;
        memcpy(&cmsg64, ptr64, sizeof(cmsg64));
        if (cmsg64.cmsg_len < sizeof(cmsg64) || cmsg64.cmsg_len > remaining64) goto error;
        payload = cmsg64.cmsg_len - sizeof(cmsg64);
        size32 = sizeof(cmsg32) + payload;
        step32 = cmsg_align_32(size32);
        step64 = WSA_CMSG_ALIGN(cmsg64.cmsg_len);
        if (step32 > max_len - used32) goto error;
        /* Internal conversion normally supplies complete native padding. Also
         * accept an exactly unpadded final record, without reading past it. */
        if (step64 > remaining64)
        {
            if (cmsg64.cmsg_len != remaining64) goto error;
            step64 = remaining64;
        }

        cmsg32.cmsg_len = size32;
        cmsg32.cmsg_level = cmsg64.cmsg_level;
        cmsg32.cmsg_type = cmsg64.cmsg_type;
        memcpy(ptr32, &cmsg32, sizeof(cmsg32));
        memcpy(ptr32 + sizeof(cmsg32), ptr64 + sizeof(cmsg64), payload);
        if (step32 > size32) memset(ptr32 + size32, 0, step32 - size32);
        ptr64 += step64;
        remaining64 -= step64;
        ptr32 += step32;
        used32 += step32;
    }
    control32->len = used32;
    return 1;

error:
    control32->len = 0;
    return 0;
}'''


def stage_source(source):
    if MARKER in source or source.count(BEGIN) != 1 or source.count(END) != 1:
        raise ValueError('WoW64 socket control input changed or was already staged')
    native_at = source.index(NATIVE_BEGIN)
    native_end = source.index('\n}', native_at) + 2
    native = source[native_at:native_end]
    if hashlib.sha256(native.encode()).hexdigest() != NATIVE_SHA256:
        raise ValueError('Pinned native ancillary conversion changed; review its contract')
    native = native.replace('                    case IP_TOS:', '''                    /* Darwin reports the receiving option as the cmsg type.
                     * Linux normally reports IP_TOS. Both carry one TOS byte. */
#if defined(IP_RECVTOS) && IP_RECVTOS != IP_TOS
                    case IP_RECVTOS:
#endif
                    case IP_TOS:''', 1)
    native = native.replace('                    case IPV6_TCLASS:', '''                    /* Older Darwin SDKs/kernels use a receiving-option alias. */
#if defined(IPV6_RECVTCLASS) && IPV6_RECVTCLASS != IPV6_TCLASS
                    case IPV6_RECVTCLASS:
#endif
#if defined(IP_RECVTCLASS) && IP_RECVTCLASS != IPV6_TCLASS && \\
    (!defined(IPV6_RECVTCLASS) || IP_RECVTCLASS != IPV6_RECVTCLASS)
                    case IP_RECVTCLASS:
#endif
                    case IPV6_TCLASS:''', 1)
    source = source[:native_at] + CONTRACT + native + source[native_end:]
    start = source.index(BEGIN)
    end = source.index(END, start)
    old = source[start:end].rstrip()
    if hashlib.sha256(old.encode()).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('Pinned WoW64 ancillary conversion changed; review its contract')
    return source[:start] + REPLACEMENT + source[start + len(old):]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error('source must remain immutable')
    original = args.source.read_bytes()
    generated = stage_source(original.decode()).encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(generated)
    print(json.dumps({'stage': MARKER, 'source_sha256': hashlib.sha256(original).hexdigest(),
                      'output_sha256': hashlib.sha256(generated).hexdigest(),
                      'scope': 'native traffic-class aliases and bounded WoW64 ancillary payloads'}))


if __name__ == '__main__':
    main()
