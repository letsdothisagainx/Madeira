/* Bounded, read-only context for a genuinely failed native datagram operation.
 * Do not read SO_ERROR here: that query consumes a pending transport error.
 * Never print addresses or packet contents, and never change route/socket
 * options. The caller supplies the errno captured immediately after sendmsg. */
#ifndef MADEIRA_SOCKET_ERROR_CONTEXT_H
#define MADEIRA_SOCKET_ERROR_CONTEXT_H
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define IOS_SOCKET_ERROR_OWNERS 64
#define IOS_SOCKET_ERROR_PROCESS_LIMIT 32
#define IOS_SOCKET_ERROR_FDS 16
#define IOS_SOCKET_ERROR_FD_LIMIT 2

#ifdef WINE_IOS
static const char *ios_socket_ipv4_class( uint32_t address )
{
    uint32_t a = ntohl(address);
    if (!a) return "unspecified";
    if ((a >> 24) == 127) return "loopback";
    if ((a & 0xffff0000u) == 0xa9fe0000u) return "linklocal";
    if ((a >> 24) == 10 || (a & 0xfff00000u) == 0xac100000u ||
        (a & 0xffff0000u) == 0xc0a80000u) return "private";
    if ((a & 0xffc00000u) == 0x64400000u) return "shared";
    if (a == 0xffffffffu) return "broadcast";
    if ((a & 0xf0000000u) == 0xe0000000u) return "multicast";
    if ((a & 0xffffff00u) == 0xc0000200u || (a & 0xffffff00u) == 0xc6336400u ||
        (a & 0xffffff00u) == 0xcb007100u) return "documentation";
    if (!(a >> 24) || (a & 0xf0000000u) == 0xf0000000u) return "reserved";
    return "public";
}

static const char *ios_socket_address_class( const struct sockaddr *address, socklen_t size )
{
    static const unsigned char zero[16];
    const unsigned char *a;
    uint32_t mapped;
    if (!address || size < offsetof(struct sockaddr,sa_data)) return "absent";
    if (address->sa_family == AF_INET && size >= sizeof(struct sockaddr_in))
        return ios_socket_ipv4_class(((const struct sockaddr_in *)address)->sin_addr.s_addr);
    if (address->sa_family != AF_INET6 || size < sizeof(struct sockaddr_in6)) return "unknown";
    a = (const unsigned char *)&((const struct sockaddr_in6 *)address)->sin6_addr;
    if (!memcmp(a,zero,16)) return "unspecified";
    if (!memcmp(a,zero,15) && a[15] == 1) return "loopback";
    if (!memcmp(a,zero,10) && a[10] == 0xff && a[11] == 0xff)
    {
        memcpy(&mapped,a+12,sizeof(mapped));
        if (!strcmp(ios_socket_ipv4_class(mapped),"unspecified")) return "mapped-unspecified";
        if (!strcmp(ios_socket_ipv4_class(mapped),"loopback")) return "mapped-loopback";
        if (!strcmp(ios_socket_ipv4_class(mapped),"linklocal")) return "mapped-linklocal";
        if (!strcmp(ios_socket_ipv4_class(mapped),"private")) return "mapped-private";
        if (!strcmp(ios_socket_ipv4_class(mapped),"public")) return "mapped-public";
        return "mapped-other";
    }
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return "linklocal";
    if ((a[0] & 0xfe) == 0xfc) return "private";
    if (a[0] == 0xff) return "multicast";
    if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0d && a[3] == 0xb8) return "documentation";
    return "public";
}

static int ios_socket_error_option( int fd, int level, int option )
{
    int value = -1;
    socklen_t size = sizeof(value);
    return getsockopt(fd,level,option,&value,&size) || size != sizeof(value) ? -1 : value;
}

/* Windows rejects unspecified UDP peers with WSAEADDRNOTAVAIL. Linux can
 * instead deliver them to loopback and Darwin reports EHOSTUNREACH. Validate
 * explicit destinations only; an unspecified local bind remains legitimate. */
static int ios_socket_invalid_datagram_destination( const struct sockaddr *address, socklen_t size )
{
    static const unsigned char zero[16];
    const unsigned char *a;
    if (!address || size < offsetof(struct sockaddr,sa_data)) return 0;
    if (address->sa_family == AF_INET && size >= sizeof(struct sockaddr_in))
        return !((const struct sockaddr_in *)address)->sin_addr.s_addr;
    if (address->sa_family != AF_INET6 || size < sizeof(struct sockaddr_in6)) return 0;
    a = (const unsigned char *)&((const struct sockaddr_in6 *)address)->sin6_addr;
    return !memcmp(a,zero,16) || (!memcmp(a,zero,10) && a[10] == 0xff && a[11] == 0xff && !memcmp(a+12,zero,4));
}

/* First public, non-DNS native datagram boundary per owner and direction.
 * This samples a kernel result, not a packet count, a paired request/reply or
 * a Valve/authentication verdict. Explicit sockaddr metadata only: no route
 * changes, peer queries, packet reads, endpoints or payload in the report. */
static void ios_socket_datagram_progress( int fd, const struct msghdr *message, int flags,
                                           long long bytes, unsigned int status, int send )
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static struct { const void *owner; unsigned int pid, done; } owners[64];
    static _Thread_local struct { const void *owner; unsigned int pid, done; } cached;
    const unsigned int bit = send ? 1 : 2;
    const struct sockaddr *address;
    const void *owner;
    unsigned int pid, tid, i, slot = 64;
    const char *address_class;
    unsigned short port;
    int saved_errno, protocol = -1, emit = 0;
#ifdef SO_PROTOCOL
    socklen_t protocol_size = sizeof(protocol);
#endif
    struct timespec observed;
    unsigned long long ns = 0;
    unsigned int valid_time = 0;
    char protocol_text[24];
    TEB *teb = NtCurrentTeb();

    if (!teb || !(owner = teb->Peb) || !(pid = (unsigned int)(ULONG_PTR)teb->ClientId.UniqueProcess)) return;
    if (cached.owner != owner || cached.pid != pid)
    {
        cached.owner = owner;
        cached.pid = pid;
        cached.done = 0;
    }
    if (cached.done & bit) return; /* No classification, lock or syscall on the hot path. */
    if (bytes <= 0 || !(address = message->msg_name)) return;
    address_class = ios_socket_address_class(address,message->msg_namelen);
    if (strcmp(address_class,"public") && strcmp(address_class,"mapped-public")) return;
    if (address->sa_family == AF_INET) port = ((const struct sockaddr_in *)address)->sin_port;
    else if (address->sa_family == AF_INET6) port = ((const struct sockaddr_in6 *)address)->sin6_port;
    else return;
    if (port == htons(53)) return;

    saved_errno = errno;
    pthread_mutex_lock(&lock);
    for (i = 0; i < 64; i++)
    {
        if (owners[i].owner == owner && owners[i].pid == pid) { slot = i; break; }
        if (!owners[i].owner && slot == 64) slot = i;
    }
    if (slot == 64) { cached.done = 3; goto out; } /* Fixed lifetime budget. */
    if (owners[slot].owner && (owners[slot].done & bit))
    {
        cached.done |= bit;
        goto out;
    }
    if (ios_socket_error_option(fd,SOL_SOCKET,SO_TYPE) != SOCK_DGRAM) goto out;
#ifdef SO_PROTOCOL
    if (getsockopt(fd,SOL_SOCKET,SO_PROTOCOL,&protocol,&protocol_size) || protocol_size != sizeof(protocol))
        protocol = -1;
    if (protocol != -1 && protocol != IPPROTO_UDP) goto out;
#endif
    owners[slot].owner = owner;
    owners[slot].pid = pid;
    owners[slot].done |= bit;
    cached.done |= bit;
    emit = 1;
out:
    pthread_mutex_unlock(&lock);
    if (!emit) { errno = saved_errno; return; }
    /* Reserve the once-only record under the lock; timestamp/format/output
     * outside it so a slow diagnostic sink cannot serialize other owners. */
    if (!clock_gettime(CLOCK_MONOTONIC,&observed) && observed.tv_sec >= 0 && observed.tv_nsec >= 0 &&
        observed.tv_nsec < 1000000000 && (unsigned long long)observed.tv_sec <= UINT64_MAX / 1000000000ull - 1)
    {
        ns = (unsigned long long)observed.tv_sec * 1000000000ull + observed.tv_nsec;
        valid_time = 1;
    }
    if (protocol == -1) strcpy(protocol_text,"unmeasured");
    else snprintf(protocol_text,sizeof(protocol_text),"%d",protocol);
    tid = (unsigned int)(ULONG_PTR)teb->ClientId.UniqueThread;
    dprintf(2,"[udp-native-progress-v1] pid=%04x tid=%04x direction=%s first-owner-direction=1 paired=0 "
              "fd=%d family-native=%u socktype=dgram protocol=%s native-bytes=%lld afd-status=%08x flags=%#x "
              "clock=monotonic time-valid=%u observed-ns=%llu endpoints=omitted payload=omitted\n",
            pid,tid,send ? "send" : "recv",fd,(unsigned int)address->sa_family,protocol_text,bytes,status,flags,
            valid_time,ns);
    errno = saved_errno;
}

static void ios_socket_io_context( int fd, const struct msghdr *message, int flags,
                                   int native_error, unsigned int status, int validation, int receive )
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static struct {
        const void *owner;
        unsigned pid, count;
        struct { int fd; unsigned count; } descriptors[IOS_SOCKET_ERROR_FDS];
    } owners[IOS_SOCKET_ERROR_OWNERS];
    struct sockaddr_storage local, peer;
    const struct sockaddr *destination = message->msg_name;
    socklen_t local_size = sizeof(local), peer_size = sizeof(peer);
    socklen_t destination_size = message->msg_namelen;
    unsigned pid = 0, tid = 0, i, j, owner_slot = IOS_SOCKET_ERROR_OWNERS, fd_slot = IOS_SOCKET_ERROR_FDS, scope = 0;
    int saved_errno = errno, type, ipv4_bound = -1, ipv6_bound = -1, dont_route = -1;
    char error_text[24];
    const void *owner = NULL;
    TEB *teb = NtCurrentTeb();

    /* Expected nonblocking backpressure is not a route-failure observation. */
    if (!validation && (native_error == EWOULDBLOCK || native_error == EAGAIN || native_error == EINTR)) return;
    if (teb)
    {
        owner = teb->Peb;
        pid = (unsigned)(ULONG_PTR)teb->ClientId.UniqueProcess;
        tid = (unsigned)(ULONG_PTR)teb->ClientId.UniqueThread;
    }
    if (!pid || !owner) goto out;
    type = ios_socket_error_option(fd,SOL_SOCKET,SO_TYPE);
    if (type != SOCK_DGRAM) goto out;
    pthread_mutex_lock(&lock);
    for (i = 0; i < IOS_SOCKET_ERROR_OWNERS; i++)
    {
        if (owners[i].pid == pid && owners[i].owner == owner) { owner_slot = i; break; }
        if (!owners[i].pid && owner_slot == IOS_SOCKET_ERROR_OWNERS) owner_slot = i;
    }
    if (owner_slot == IOS_SOCKET_ERROR_OWNERS || owners[owner_slot].count >= IOS_SOCKET_ERROR_PROCESS_LIMIT) goto unlock;
    if (!owners[owner_slot].pid) { owners[owner_slot].pid = pid; owners[owner_slot].owner = owner; }
    for (j = 0; j < IOS_SOCKET_ERROR_FDS; j++)
    {
        if (owners[owner_slot].descriptors[j].count && owners[owner_slot].descriptors[j].fd == fd)
        { fd_slot = j; break; }
        if (!owners[owner_slot].descriptors[j].count && fd_slot == IOS_SOCKET_ERROR_FDS) fd_slot = j;
    }
    if (fd_slot == IOS_SOCKET_ERROR_FDS || owners[owner_slot].descriptors[fd_slot].count >= IOS_SOCKET_ERROR_FD_LIMIT) goto unlock;
    owners[owner_slot].descriptors[fd_slot].fd = fd;
    owners[owner_slot].descriptors[fd_slot].count++;
    owners[owner_slot].count++;
    pthread_mutex_unlock(&lock);

    memset(&local,0,sizeof(local));
    if (getsockname(fd,(struct sockaddr *)&local,&local_size)) local_size = 0;
    if (!destination)
    {
        memset(&peer,0,sizeof(peer));
        if (!getpeername(fd,(struct sockaddr *)&peer,&peer_size))
        { destination = (struct sockaddr *)&peer; destination_size = peer_size; }
    }
    if (destination && destination->sa_family == AF_INET6 && destination_size >= sizeof(struct sockaddr_in6))
        scope = ((const struct sockaddr_in6 *)destination)->sin6_scope_id;
#ifdef IP_BOUND_IF
    ipv4_bound = ios_socket_error_option(fd,IPPROTO_IP,IP_BOUND_IF);
#endif
#ifdef IPV6_BOUND_IF
    ipv6_bound = ios_socket_error_option(fd,IPPROTO_IPV6,IPV6_BOUND_IF);
#endif
#ifdef SO_DONTROUTE
    dont_route = ios_socket_error_option(fd,SOL_SOCKET,SO_DONTROUTE);
#endif
    if (validation) strcpy(error_text,"not-called");
    else snprintf(error_text,sizeof(error_text),"%d",native_error);
    dprintf(2,"%s pid=%04x tid=%04x op=%s api=%s fd=%d "
              "family=%u socket-type=%d flags=%#x destination-class=%s bind-class=%s "
              "address-length=%u scope=%u ip-bound-if=%d ipv6-bound-if=%d dont-route=%d "
              "errno=%s ntstatus=%08x anticipated-wsa=%s so-error=unread-destructive\n",
            receive ? "[udp-recv-failure-v1]" : "[udp-send-failure-v1]",
            pid,tid,validation ? "validation" : receive ? "recvmsg" : "sendmsg",
            receive ? "AFD_RECVMSG" : "AFD_SENDMSG",fd,
            destination ? (unsigned)destination->sa_family : 0,type,flags,
            ios_socket_address_class(destination,destination_size),
            ios_socket_address_class((struct sockaddr *)&local,local_size),
            (unsigned)destination_size,scope,ipv4_bound,ipv6_bound,dont_route,error_text,status,
            validation ? "10049" : native_error == EHOSTUNREACH ? "10065" : "not-derived");
    goto out;
unlock:
    pthread_mutex_unlock(&lock);
out:
    errno = saved_errno;
}
static void ios_socket_send_failure( int fd, const struct msghdr *message, int flags,
                                     int native_error, unsigned int status )
{
    ios_socket_io_context(fd,message,flags,native_error,status,0,0);
}

static void ios_socket_send_invalid_destination( int fd, const struct msghdr *message, int flags )
{
    ios_socket_io_context(fd,message,flags,0,STATUS_INVALID_ADDRESS,1,0);
}

static void ios_socket_recv_failure( int fd, int flags, int native_error, unsigned int status )
{
    /* A failed recvmsg has not initialized msg_name. Inspect only the actual
     * connected peer, when there is one, and the local bind. Never consume a
     * packet or read/clear SO_ERROR merely to describe the failure. */
    const struct msghdr message = {0};
    ios_socket_io_context(fd,&message,flags,native_error,status,0,1);
}
#else
#define ios_socket_send_failure(fd,message,flags,error,status) do { } while (0)
#define ios_socket_recv_failure(fd,flags,error,status) do { } while (0)
#define ios_socket_datagram_progress(fd,message,flags,bytes,status,send) do { } while (0)
#endif
#endif
