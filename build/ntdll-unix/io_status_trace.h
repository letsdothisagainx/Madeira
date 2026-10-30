/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Included after unix_private.h in the staged file/socket translation units.
 * Record the real producer's decision; leave layout, pointer and result alone. */
#ifndef MADEIRA_IO_STATUS_TRACE_H
#define MADEIRA_IO_STATUS_TRACE_H
extern void ios_trace_iosb_registration( IO_STATUS_BLOCK *io, client_ptr_t target, const char *api );
static inline client_ptr_t ios_observed_iosb_client_ptr( IO_STATUS_BLOCK *io, const char *api )
{
    client_ptr_t target = iosb_client_ptr( io );
    ios_trace_iosb_registration( io, target, api );
    return target;
}
#define iosb_client_ptr(io) ios_observed_iosb_client_ptr( (io), __func__ )
#endif
