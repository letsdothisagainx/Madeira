/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Private Wine PE/Unix ABI. All pointers are host addresses; none are tokens
 * stored in an application IOSB. No structure crosses the server protocol. */
#ifndef MADEIRA_IO_STATUS_ABI_H
#define MADEIRA_IO_STATUS_ABI_H
#define MADEIRA_IO_ABI_VERSION 1
#define MADEIRA_THREAD_IO_ABI 1011
enum madeira_io_operation { MADEIRA_IO_ENTER, MADEIRA_IO_LEAVE, MADEIRA_IO_BIND, MADEIRA_IO_UNBIND };
struct madeira_io_scope
{
    struct madeira_io_scope *previous;
    void *native_iosb;
    void *guest_iosb;
};
struct madeira_io_control
{
    unsigned int version;
    unsigned int operation;
    struct madeira_io_scope *scope;
    void *native_iosb;
    void *guest_iosb;
};
#endif
