/* SPDX-License-Identifier: LGPL-2.1-or-later
 * IOSB layout belongs to the request, not to the owning process's machine.
 * Native bootstrap/FEX I/O in a WoW64 process uses a native IOSB. Only the
 * actual wow64 file thunk binds a converted 32-bit IOSB to its native proxy.
 */
#include "config.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"
#include "unix_private.h"
#include "io_status_abi.h"

C_ASSERT( sizeof(struct madeira_io_scope) == 24 );
C_ASSERT( sizeof(struct madeira_io_control) == 32 );

static _Thread_local struct madeira_io_scope *io_scope;

NTSTATUS ios_io_status_control( HANDLE thread, const void *data, ULONG size )
{
    const struct madeira_io_control *control = data;
    struct madeira_io_scope *scope;

    if (thread != NtCurrentThread()) return STATUS_INVALID_HANDLE;
    if (size != sizeof(*control)) return STATUS_INFO_LENGTH_MISMATCH;
    if (!data || !virtual_check_buffer_for_read( data, size )) return STATUS_ACCESS_VIOLATION;
    if (control->version != MADEIRA_IO_ABI_VERSION) return STATUS_REVISION_MISMATCH;
    switch (control->operation)
    {
    case MADEIRA_IO_ENTER:
        scope = control->scope;
        if (!scope) return STATUS_INVALID_PARAMETER;
        {
            struct madeira_io_scope *ancestor;
            for (ancestor = io_scope; ancestor; ancestor = ancestor->previous)
                if (ancestor == scope) return STATUS_INVALID_PARAMETER;
        }
        if (!virtual_check_buffer_for_write( scope, sizeof(*scope) )) return STATUS_ACCESS_VIOLATION;
        scope->previous = io_scope;
        scope->native_iosb = scope->guest_iosb = NULL;
        io_scope = scope;
        {
            static unsigned int announced;
            if (!__atomic_exchange_n( &announced, 1, __ATOMIC_RELAXED ))
            {
                int saved_errno = errno;
                dprintf( 2, "[io-abi] v1 per-request IOSB layout active\n" );
                errno = saved_errno;
            }
        }
        return STATUS_SUCCESS;
    case MADEIRA_IO_LEAVE:
        if (!io_scope || control->scope != io_scope) return STATUS_INVALID_PARAMETER;
        scope = io_scope;
        io_scope = scope->previous;
        memset( scope, 0, sizeof(*scope) );
        return STATUS_SUCCESS;
    case MADEIRA_IO_BIND:
        if (!io_scope || !control->native_iosb || !control->guest_iosb) return STATUS_INVALID_PARAMETER;
        if (io_scope->native_iosb && io_scope->native_iosb != control->native_iosb)
            return STATUS_INVALID_PARAMETER;
        io_scope->native_iosb = control->native_iosb;
        io_scope->guest_iosb = control->guest_iosb;
        return STATUS_SUCCESS;
    case MADEIRA_IO_UNBIND:
        if (!io_scope || !control->native_iosb) return STATUS_INVALID_PARAMETER;
        /* Some PE validation failures call put_iosb without issuing native
         * I/O or binding a proxy. Preserve their real status and leave an
         * outer scope's binding alone. */
        if (!io_scope->native_iosb) return STATUS_SUCCESS;
        if (io_scope->native_iosb != control->native_iosb) return STATUS_INVALID_PARAMETER;
        io_scope->native_iosb = io_scope->guest_iosb = NULL;
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

void *ios_io_status_proxy( const IO_STATUS_BLOCK *native )
{
    struct madeira_io_scope *scope;
    if (!native) return NULL;
    for (scope = io_scope; scope; scope = scope->previous)
        if (scope->native_iosb == native) return scope->guest_iosb;
    return NULL;
}

BOOL ios_io_status_target32( client_ptr_t target )
{
    struct madeira_io_scope *scope;
    if (!target) return FALSE;
    for (scope = io_scope; scope; scope = scope->previous)
        if ((client_ptr_t)(ULONG_PTR)scope->guest_iosb == target) return TRUE;
    return FALSE;
}

void ios_complete_io_status( client_ptr_t address, NTSTATUS status, ULONG_PTR information, BOOL guest32 )
{
    if (!address) return;
    if (guest32)
    {
        IO_STATUS_BLOCK32 *io = wine_server_get_ptr( address );
        io->Information = information;
        WriteRelease( &io->Status, status );
    }
    else
    {
        IO_STATUS_BLOCK *io = wine_server_get_ptr( address );
        io->Information = information;
        WriteRelease( &io->Status, status );
    }
}
