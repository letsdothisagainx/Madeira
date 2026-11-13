#!/usr/bin/env python3
"""Correct the pinned BSD IPv4 NSI route parser in an immutable owned copy."""
import argparse
import hashlib
from pathlib import Path

PIN = '6f8dccc887ee635116fab936be4089dcd806609517c032593f537966813844c9'
START = '#elif defined(HAVE_SYS_SYSCTL_H) && defined(NET_RT_DUMP)\n'
END = '\n#else\n    FIXME( "not implemented\\n" );\n    return STATUS_NOT_IMPLEMENTED;\n#endif'
BSD = r'''#elif defined(HAVE_SYS_SYSCTL_H) && defined(NET_RT_DUMP)
    {
        int mib[6] = { CTL_NET, PF_ROUTE, 0, PF_INET, NET_RT_DUMP, 0 };
        size_t needed;
        char *buf = NULL, *lim, *next, *addr_ptr;
        struct rt_msghdr *rtm;

        if (sysctl( mib, ARRAY_SIZE(mib), NULL, &needed, NULL, 0 ) < 0) return STATUS_NOT_SUPPORTED;
        if (!needed) { *count = 0; return STATUS_SUCCESS; }
        if (!(buf = malloc( needed ))) return STATUS_NO_MEMORY;
        if (sysctl( mib, ARRAY_SIZE(mib), buf, &needed, NULL, 0 ) < 0)
        {
            free( buf );
            return STATUS_NOT_SUPPORTED;
        }

        lim = buf + needed;
        for (next = buf; next < lim; next += rtm->rtm_msglen)
        {
            unsigned int i;
            BOOL have_destination = FALSE, have_mask = FALSE, have_gateway = FALSE, valid = TRUE;

            if ((size_t)(lim - next) < sizeof(*rtm)) goto ios_route_malformed;
            rtm = (struct rt_msghdr *)next;
            if (rtm->rtm_msglen < sizeof(*rtm) || (rtm->rtm_msglen & (sizeof(int)-1)) ||
                rtm->rtm_msglen > lim - next)
                goto ios_route_malformed;
            if (rtm->rtm_type != RTM_GET) continue;
            if ((rtm->rtm_flags & RTF_GATEWAY) && (rtm->rtm_flags & RTF_MULTICAST)) continue;

            /* nsi-ipv4-route-v1: every message owns a complete fresh row.
             * A host route normally omits RTA_NETMASK. Neither its prefix nor
             * a missing gateway/loopback bit may come from another message. */
            memset( &entry, 0, sizeof(entry) );
            entry.if_index = rtm->rtm_index;
            if (!convert_index_to_luid( entry.if_index, &entry.luid )) continue;
            entry.protocol = (rtm->rtm_flags & RTF_GATEWAY) ? MIB_IPPROTO_NETMGMT : MIB_IPPROTO_LOCAL;
            entry.metric = rtm->rtm_rmx.rmx_hopcount;
            entry.loopback = entry.luid.Info.IfType == MIB_IF_TYPE_LOOPBACK;
            addr_ptr = (char *)(rtm + 1);

            for (i = 1; i; i <<= 1)
            {
                const struct sockaddr *sa;
                struct sockaddr_in sin = {0};
                size_t available, stride;

                if (!(i & rtm->rtm_addrs)) continue;
                available = next + rtm->rtm_msglen - addr_ptr;
                if (available < 2) goto ios_route_malformed;
                sa = (const struct sockaddr *)addr_ptr;
                stride = sa->sa_len ? (sa->sa_len + sizeof(int)-1) & ~(sizeof(int)-1) : sizeof(int);
                if ((sa->sa_len && sa->sa_len < 2) || sa->sa_len > available || stride > available)
                    goto ios_route_malformed;
                addr_ptr += stride;
                if (i != RTA_DST && i != RTA_GATEWAY && i != RTA_NETMASK) continue;

                /* A compact BSD netmask has only its nonzero bytes, and its
                 * family need not be AF_INET. Zero length represents /0. */
                if (i == RTA_NETMASK)
                {
                    if (sa->sa_len > sizeof(sin)) goto ios_route_malformed;
                    memcpy( &sin, sa, sa->sa_len );
                    entry.prefix_len = mask_v4_to_prefix( &sin.sin_addr );
                    have_mask = TRUE;
                    continue;
                }
                if (sa->sa_family == AF_INET)
                {
                    if (sa->sa_len < offsetof(struct sockaddr_in, sin_addr) + sizeof(sin.sin_addr) ||
                        sa->sa_len > sizeof(sin)) goto ios_route_malformed;
                    memcpy( &sin, sa, sa->sa_len );
                    if (i == RTA_DST) { entry.prefix = sin.sin_addr; have_destination = TRUE; }
                    else { entry.next_hop = sin.sin_addr; have_gateway = TRUE; }
                }
#ifdef AF_LINK
                else if (i == RTA_GATEWAY && sa->sa_family == AF_LINK)
                {
                    /* An interface/link gateway is on-link, not an IPv4
                     * next-hop address. Windows represents that with zero. */
                    entry.next_hop.s_addr = 0;
                    have_gateway = TRUE;
                }
#endif
                else valid = FALSE;
            }
            if (!valid || !have_destination || ((rtm->rtm_flags & RTF_GATEWAY) && !have_gateway)) continue;
            if (rtm->rtm_flags & RTF_HOST) entry.prefix_len = 32;
            else if (!have_mask && entry.prefix.s_addr) continue; /* not a representable network prefix */

            if (num < *count)
            {
                ipv4_forward_fill_entry( &entry, key_data, rw_data, dynamic_data, static_data );
                key_data = (BYTE *)key_data + key_size;
                rw_data = (BYTE *)rw_data + rw_size;
                dynamic_data = (BYTE *)dynamic_data + dynamic_size;
                static_data = (BYTE *)static_data + static_size;
            }
            num++;
        }
        free( buf );
        goto ios_route_complete;
ios_route_malformed:
        ERR( "[nsi-ipv4-route-v1] malformed BSD routing snapshot\n" );
        free( buf );
        return STATUS_DATA_ERROR;
ios_route_complete:;
    }'''


def stage(source):
    if hashlib.sha256(source.encode()).hexdigest() != PIN:
        raise ValueError('pinned NSI IP provider changed; review the BSD route parser')
    if source.count(START) != 1:
        raise ValueError('BSD IPv4 route boundary changed')
    start = source.index(START)
    end = source.index(END, start)
    return source[:start] + BSD + source[end:]


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--source', type=Path, required=True)
    args.add_argument('--output', type=Path, required=True)
    args = args.parse_args()
    if args.source.resolve() == args.output.resolve():
        raise ValueError('the pinned Wine source must remain immutable')
    changed = stage(args.source.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(changed)
    print('Staged nsi-ipv4-route-v1: fresh rows, host prefixes, bounded BSD messages')


if __name__ == '__main__':
    main()
