/* Exact production function from de910d342b8da83db2800a130e2cf2a9c817f9a1
 * build/ntdll-unix/virtual_ios.c; SHA256 of function bytes below:
 * 5dbdc89fe9df874f2d098a71e9c1249fb6ec5ca69901a01d18c38d48d1608b42
 */
NTSTATUS WINAPI NtWriteVirtualMemory( HANDLE process, void *addr, const void *buffer,
                                      SIZE_T size, SIZE_T *bytes_written )
{
    unsigned int status;
#ifdef WINE_IOS
    ios_trace_wow_write_begin( process, addr, buffer, size );
    if (ios_wow_self_write_target( process, addr, size ))
    {
        status = ios_wow_write_self( addr, buffer, size );
        if (bytes_written) *bytes_written = status ? 0 : size;
        ios_trace_wow_write( status, status ? 0 : size, "self" );
        return status;
    }
#endif

    if (virtual_check_buffer_for_read( buffer, size ))
    {
        SERVER_START_REQ( write_process_memory )
        {
            req->handle     = wine_server_obj_handle( process );
            req->addr       = wine_server_client_ptr( addr );
            wine_server_add_data( req, buffer, size );
            status = wine_server_call( req );
            size = reply->written;
        }
        SERVER_END_REQ;
    }
    else
    {
        status = STATUS_PARTIAL_COPY;
        size = 0;
    }
    if (bytes_written) *bytes_written = size;
#ifdef WINE_IOS
    ios_trace_wow_write( status, size, "server" );
#endif
    return status;
}
