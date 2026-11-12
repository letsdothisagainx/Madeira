/* Native UDP destination reference. Uses only owned ephemeral loopback
 * listeners and fixed loopback/unspecified destinations, never Valve hosts.
 * The zero-initialized sockaddr conversion intentionally matches Wine's Unix
 * sockaddr_to_unix: on Darwin the user-supplied sin_len/sin6_len stays zero. */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
typedef int native_len_t;
#define CLOSE_SOCKET(s) closesocket(s)
static int socket_error(void) { return WSAGetLastError(); }
static void clear_socket_error(void) { WSASetLastError(0); }
static unsigned process_id(void) { return GetCurrentProcessId(); }
static int nonblocking(SOCKET s) { u_long yes = 1; return ioctlsocket(s, FIONBIO, &yes); }
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
typedef int SOCKET;
typedef socklen_t native_len_t;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define CLOSE_SOCKET(s) close(s)
static int socket_error(void) { return errno; }
static void clear_socket_error(void) { errno = 0; }
static unsigned process_id(void) { return (unsigned)getpid(); }
static int nonblocking(SOCKET s) { int flags = fcntl(s, F_GETFL, 0); return flags < 0 ? -1 : fcntl(s, F_SETFL, flags | O_NONBLOCK); }
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct destination_case {
    const char *name;
    int receiver_family, sender_family, mapped, unspecified, required;
};
static const struct destination_case cases[] = {
    {"ipv4-loopback", AF_INET, AF_INET, 0, 0, 1},
    {"ipv6-loopback", AF_INET6, AF_INET6, 0, 0, 1},
    {"ipv4-mapped-dualstack", AF_INET, AF_INET6, 1, 0, 1},
    {"ipv4-unspecified", AF_INET, AF_INET, 0, 1, 0},
    {"ipv6-unspecified", AF_INET6, AF_INET6, 0, 1, 0},
    {"ipv4-mapped-unspecified", AF_INET, AF_INET6, 1, 1, 0},
};

static native_len_t address(struct sockaddr_storage *storage, int family, unsigned short port,
                            int mapped, int unspecified, int local_bind)
{
    memset(storage, 0, sizeof(*storage));
    if (family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)storage;
        v4->sin_family = AF_INET; v4->sin_port = port;
        v4->sin_addr.s_addr = htonl(unspecified || local_bind ? INADDR_ANY : INADDR_LOOPBACK);
        return sizeof(*v4);
    } else {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)storage;
        v6->sin6_family = AF_INET6; v6->sin6_port = port;
        if (mapped) {
            unsigned char *bytes = (unsigned char *)&v6->sin6_addr;
            bytes[10] = bytes[11] = 0xff;
            if (!unspecified) { bytes[12] = 127; bytes[15] = 1; }
        } else if (!unspecified && !local_bind) {
            ((unsigned char *)&v6->sin6_addr)[15] = 1;
        }
        return sizeof(*v6);
    }
}

static unsigned short port_of(const struct sockaddr_storage *storage)
{
    return storage->ss_family == AF_INET ? ((const struct sockaddr_in *)storage)->sin_port :
                                          ((const struct sockaddr_in6 *)storage)->sin6_port;
}

static int readable(SOCKET s)
{
    fd_set readers;
    struct timeval timeout;
    FD_ZERO(&readers); FD_SET(s, &readers);
    timeout.tv_sec = 0; timeout.tv_usec = 250000;
#ifdef _WIN32
    return select(0, &readers, NULL, NULL, &timeout) > 0;
#else
    return select(s + 1, &readers, NULL, NULL, &timeout) > 0;
#endif
}

static int run_case(const struct destination_case *test, unsigned id, int method)
{
    SOCKET receiver = INVALID_SOCKET, sender = INVALID_SOCKET;
    struct sockaddr_storage receive_address, sender_address, destination, peer;
    native_len_t receive_len, sender_len, destination_len, peer_len;
    uint32_t payload[4] = {0x4d414445u, 0, 0, 0}, received[8];
    int yes, send_result = SOCKET_ERROR, original_error = 0, format_error = 0;
    unsigned long sent_bytes = 0, formatted = 0;
    int got_payload = 0, got_reply = 0, setup_error = 0;
    const char *stage = "socket";
#ifdef _WIN32
    const char *method_name = method ? "WSASendTo" : "WSASendMsg";
#else
    const char *method_name = "sendmsg";
    (void)method;
#endif
    payload[1] = process_id(); payload[2] = id; payload[3] = (unsigned)method;
    receiver = socket(test->receiver_family, SOCK_DGRAM, IPPROTO_UDP);
    sender = socket(test->sender_family, SOCK_DGRAM, IPPROTO_UDP);
    if (receiver == INVALID_SOCKET || sender == INVALID_SOCKET) goto setup_failed;
    stage = "v6only";
    if (test->receiver_family == AF_INET6) {
        yes = 1;
        if (setsockopt(receiver, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&yes, sizeof(yes))) goto setup_failed;
    }
    if (test->sender_family == AF_INET6) {
        yes = !test->mapped;
        if (setsockopt(sender, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&yes, sizeof(yes))) goto setup_failed;
    }
    stage = "bind-receiver";
    receive_len = address(&receive_address, test->receiver_family, 0, 0, 0, 0);
    if (bind(receiver, (struct sockaddr *)&receive_address, receive_len)) goto setup_failed;
    receive_len = sizeof(receive_address);
    if (getsockname(receiver, (struct sockaddr *)&receive_address, &receive_len)) goto setup_failed;
    stage = "bind-sender";
    sender_len = address(&sender_address, test->sender_family, 0, 0, 1, 1);
    if (bind(sender, (struct sockaddr *)&sender_address, sender_len)) goto setup_failed;
    sender_len = sizeof(sender_address);
    if (getsockname(sender, (struct sockaddr *)&sender_address, &sender_len)) goto setup_failed;
    stage = "nonblocking";
    if (nonblocking(receiver) || nonblocking(sender)) goto setup_failed;
    destination_len = address(&destination, test->sender_family, port_of(&receive_address), test->mapped, test->unspecified, 0);
    clear_socket_error();
#ifdef _WIN32
    {
        WSABUF chunks[2]; DWORD count = 0;
        chunks[0].buf = (char *)payload; chunks[0].len = 8;
        chunks[1].buf = (char *)payload + 8; chunks[1].len = 8;
        if (method) {
            send_result = WSASendTo(sender, chunks, 2, &count, 0, (struct sockaddr *)&destination, destination_len, NULL, NULL);
        } else {
            GUID guid = WSAID_WSASENDMSG; LPFN_WSASENDMSG send_message = NULL; DWORD bytes = 0;
            WSAMSG message;
            stage = "WSASendMsg-extension";
            if (WSAIoctl(sender, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid),
                         &send_message, sizeof(send_message), &bytes, NULL, NULL) || !send_message) goto setup_failed;
            memset(&message, 0, sizeof(message));
            message.name = (struct sockaddr *)&destination; message.namelen = destination_len;
            message.lpBuffers = chunks; message.dwBufferCount = 2;
            clear_socket_error();
            send_result = send_message(sender, &message, 0, &count, NULL, NULL);
        }
        original_error = send_result == SOCKET_ERROR ? socket_error() : 0;
        sent_bytes = send_result == 0 ? count : 0;
        if (original_error) {
            char text[256];
            formatted = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                       NULL, (DWORD)original_error, 0, text, sizeof(text), NULL);
            format_error = socket_error();
        }
    }
#else
    {
        struct iovec chunks[2]; struct msghdr message; ssize_t result;
        chunks[0].iov_base = payload; chunks[0].iov_len = 8;
        chunks[1].iov_base = (char *)payload + 8; chunks[1].iov_len = 8;
        memset(&message, 0, sizeof(message));
        message.msg_name = &destination; message.msg_namelen = destination_len;
        message.msg_iov = chunks; message.msg_iovlen = 2;
        result = sendmsg(sender, &message, 0);
        original_error = result < 0 ? socket_error() : 0;
        send_result = result < 0 ? SOCKET_ERROR : 0; sent_bytes = result < 0 ? 0 : (unsigned long)result;
    }
#endif
    if (!send_result && sent_bytes == sizeof(payload) && readable(receiver)) {
        int count;
        peer_len = sizeof(peer);
        count = (int)recvfrom(receiver, (char *)received, sizeof(received), 0, (struct sockaddr *)&peer, &peer_len);
        got_payload = count == sizeof(payload) && !memcmp(payload, received, sizeof(payload)) && port_of(&peer) == port_of(&sender_address);
        if (got_payload && sendto(receiver, (const char *)payload, sizeof(payload), 0, (struct sockaddr *)&peer, peer_len) == sizeof(payload) && readable(sender)) {
            count = (int)recvfrom(sender, (char *)received, sizeof(received), 0, NULL, NULL);
            got_reply = count == sizeof(payload) && !memcmp(payload, received, sizeof(payload));
        }
    }
    printf("{\"event\":\"destination\",\"case\":\"%s\",\"method\":\"%s\",\"required\":%s,\"sendResult\":%d,\"sentBytes\":%lu,\"originalSocketError\":%d,\"errorAfterFormatMessage\":%d,\"formatCharacters\":%lu,\"receivedPayload\":%s,\"receivedReply\":%s}\n",
           test->name, method_name, test->required ? "true" : "false", send_result, sent_bytes, original_error, format_error, formatted, got_payload ? "true" : "false", got_reply ? "true" : "false");
    CLOSE_SOCKET(sender); CLOSE_SOCKET(receiver);
    return !test->required || (got_payload && got_reply);
setup_failed:
    setup_error = socket_error();
    printf("{\"event\":\"setup-failure\",\"case\":\"%s\",\"method\":\"%s\",\"stage\":\"%s\",\"originalSocketError\":%d}\n",test->name,method_name,stage,setup_error);
    if (sender != INVALID_SOCKET) CLOSE_SOCKET(sender);
    if (receiver != INVALID_SOCKET) CLOSE_SOCKET(receiver);
    return !test->required;
}

int main(void)
{
    unsigned i, methods = 1, failures = 0;
    int method;
    setvbuf(stdout, NULL, _IONBF, 0);
#ifdef _WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2,2), &data)) return 2;
    methods = 2;
#endif
    printf("{\"event\":\"environment\",\"pointerBits\":%u,\"receiveTimeoutMs\":250,\"ownedLoopbackOnly\":true,\"zeroCasesAreObservations\":true}\n", (unsigned)(sizeof(void *) * 8));
    for (method = 0; method < (int)methods; ++method)
        for (i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i)
            if (!run_case(&cases[i], i + 1, method)) ++failures;
#ifdef _WIN32
    WSACleanup();
#endif
    printf("{\"event\":\"complete\",\"failures\":%u,\"cases\":%u,\"requiredRoundtrips\":%u}\n", failures, methods * (unsigned)(sizeof(cases)/sizeof(cases[0])), methods * 3);
    return failures ? 1 : 0;
}
