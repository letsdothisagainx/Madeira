#!/usr/bin/env python3
"""Execute actual try_recv/async_recv_proc with real owned UDP packets.

The native receive syscall and poll are real. The Windows FD lookup and VM
write guard are host shims; injected errors specifically test errno corruption
by existing observers. This does not contact Valve or establish SDR acceptance.
"""
from pathlib import Path
import ast
import hashlib
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = ROOT / 'wine/dlls/ntdll/unix/socket.c'
ORIGINAL = SOURCE_PATH.read_bytes()
SOURCE = ORIGINAL.decode()
HEADER = ROOT / 'build/ntdll-unix/socket_error_context.h'
spec = importlib.util.spec_from_file_location('recv_socket_stage', ROOT / 'tools/build/stage-ios-socket-errors.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
AFTER = stage.stage_source(SOURCE, HEADER)

# Reuse the reviewed primitive/native/Windows-width host declarations without
# importing or executing the send regression's standalone test runner.
constants = {}
for node in ast.parse((ROOT / 'tests/host/check-native-udp-send.py').read_text()).body:
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'PRELUDE' for t in node.targets):
        constants['PRELUDE'] = ast.literal_eval(node.value)
PREFIX = constants['PRELUDE'].replace('static int injected,send_calls,observer_calls,last_native_error;',
    'static int observer_error=ENOTCONN;\nstatic int injected,send_calls,observer_calls,last_native_error;')
PREFIX = PREFIX.replace('errno=ENOTCONN;', 'errno=observer_error;')


def function(text, marker):
    at = text.index(marker)
    return text[at:text.index('\n}', at) + 2]


RECV_PRELUDE = r'''
#undef sendmsg
#define TRUE 1
#define FALSE 0
typedef void *HANDLE;
typedef struct {unsigned len; char *buf;} WSABUF;
struct fake_fileio {HANDLE handle;};
struct async_recv_ioctl {
 struct fake_fileio io; unsigned count; int unix_flags; WSABUF *control;
 struct WS_sockaddr *addr; int *addr_len; unsigned *ret_flags; BOOL icmp_over_dgram;
 struct iovec iov[2];
};
#define WS_MSG_CTRUNC 0x0200
static unsigned recv_calls,releases;
static int recv_injected;
static ssize_t actual_or_injected_recv(int fd,struct msghdr *hdr,int flags) {
 ++recv_calls;
 if(recv_injected){errno=recv_injected;recv_injected=0;return -1;}
 return recvmsg(fd,hdr,flags);
}
#define virtual_locked_recvmsg actual_or_injected_recv
static int afd_is_wow64_caller(void){return 0;}
static int convert_control_headers(struct msghdr *hdr,WSABUF *control){(void)hdr;(void)control;assert(!"unexpected ancillary fixture");return 0;}
static int wow64_translate_control(const WSABUF *a,void *b){(void)a;(void)b;assert(0);return 0;}
static ssize_t fixup_icmp_over_dgram(struct msghdr *hdr,union unix_sockaddr *addr,HANDLE handle,ssize_t length,NTSTATUS *status){(void)hdr;(void)addr;(void)handle;(void)length;(void)status;assert(0);return -1;}
static unsigned server_get_unix_fd(HANDLE handle,unsigned access,int *fd,int *close_needed,void *type,void *options){(void)access;(void)type;(void)options;*fd=(int)(intptr_t)handle;*close_needed=0;return 0;}
static void release_fileio(void *io){(void)io;++releases;}
#define TRACE(...) do {}while(0)
'''

MAIN = r'''
static struct async_recv_ioctl receive_op(int fd,unsigned char *buffer,size_t length,void *address,int *address_length,unsigned *flags) {
 struct async_recv_ioctl op;memset(&op,0,sizeof op);op.io.handle=(void*)(intptr_t)fd;
 op.count=2;op.iov[0]=(struct iovec){buffer,length/3};op.iov[1]=(struct iovec){buffer+length/3,length-length/3};
 op.addr=address;op.addr_len=address_length;op.ret_flags=flags;return op;
}
static void real_ready(int fd,int expected) {
 struct pollfd ready={fd,POLLIN,0};int ret=poll(&ready,1,expected?2000:0);
 assert(expected?(ret==1&&(ready.revents&POLLIN)):ret==0);
}
static int bound_udp(int family,union unix_sockaddr *address,socklen_t *size) {
 int fd=socket(family,SOCK_DGRAM,0);if(fd<0)return -1;
 memset(address,0,sizeof *address);
 if(family==AF_INET){address->in.sin_family=AF_INET;address->in.sin_addr.s_addr=htonl(INADDR_LOOPBACK);*size=sizeof address->in;}
 else{address->in6.sin6_family=AF_INET6;address->in6.sin6_addr=in6addr_loopback;*size=sizeof address->in6;}
 assert(!bind(fd,&address->addr,*size));assert(!getsockname(fd,&address->addr,size));
 int flags=fcntl(fd,F_GETFL,0);assert(flags>=0&&!fcntl(fd,F_SETFL,flags|O_NONBLOCK));return fd;
}
static void exercise(int family) {
 union unix_sockaddr receiver_address,peer_address; socklen_t receiver_size,peer_size;
 int receiver=bound_udp(family,&receiver_address,&receiver_size);
 if(receiver<0&&family==AF_INET6&&errno==EAFNOSUPPORT){puts("SKIP native IPv6 unavailable");return;}
 assert(receiver>=0);int peer=bound_udp(family,&peer_address,&peer_size);assert(peer>=0);
 /* This existing opt-in observer really does call getpeername on an
  * unconnected UDP socket. The default export does not establish it was on;
  * exercise it explicitly rather than claiming it caused the device failure. */
 assert(!setenv("MADEIRA_SOCK_WIRE","1",1));errno=EWOULDBLOCK;
 captured_ios_sock_wire(receiver,0,NULL,0,EWOULDBLOCK);assert(errno==ENOTCONN);
 unsigned char bytes[64],payload[96];for(unsigned i=0;i<sizeof payload;++i)payload[i]=(unsigned char)(0xd7^i);
 unsigned char from[sizeof(struct WS_sockaddr_in6)];memset(from,0xa5,sizeof from);int from_length=sizeof from;unsigned flags=0;
 struct async_recv_ioctl op=receive_op(receiver,bytes,sizeof bytes,from,&from_length,&flags);
 ULONG_PTR size=0x7788;observer_error=ENOTCONN;releases=0;real_ready(receiver,0);
 unsigned status=STATUS_ALERTED;
 BOOL done=async_recv_proc(&op,&size,&status);
#ifdef BASELINE
 assert(done&&status==(unsigned)STATUS_INVALID_CONNECTION&&releases==1&&size==0x7788&&errno==ENOTCONN);
 puts("BEFORE reproduced: actual async_recv_proc completes empty UDP receive with observer ENOTCONN instead of keeping it pending");
#else
 assert(!done&&status==(unsigned)STATUS_DEVICE_NOT_READY&&!releases&&size==0x7788&&(errno==EWOULDBLOCK||errno==EAGAIN));
#endif
 /* Real readiness -> real packet -> actual async completion. No packet or
  * callback is invented to satisfy a successful return value. */
 assert(sendto(peer,payload,31,0,&receiver_address.addr,receiver_size)==31);real_ready(receiver,1);
 status=STATUS_ALERTED;releases=0;assert(async_recv_proc(&op,&size,&status));
 assert(!status&&size==31&&releases==1&&!memcmp(payload,bytes,31));real_ready(receiver,0);
 assert(from_length==(family==AF_INET?sizeof(struct WS_sockaddr_in):sizeof(struct WS_sockaddr_in6)));
 union unix_sockaddr reply_address;socklen_t reply_size=sockaddr_to_unix((void*)from,from_length,&reply_address);assert(reply_size);
 if(family==AF_INET)assert(reply_address.in.sin_port==peer_address.in.sin_port);
 else assert(reply_address.in6.sin6_port==peer_address.in6.sin6_port);
 assert(sendto(receiver,payload,31,0,&reply_address.addr,reply_size)==31);real_ready(peer,1);
 struct async_recv_ioctl reply=receive_op(peer,bytes,sizeof bytes,NULL,NULL,NULL);
 assert(try_recv(peer,&reply,&size)==STATUS_SUCCESS&&size==31&&!memcmp(payload,bytes,31));real_ready(peer,0);
#ifndef BASELINE
 unsigned before=recv_calls;recv_injected=EINTR;observer_error=ENETUNREACH;
 assert(try_recv(receiver,&op,&size)==STATUS_DEVICE_NOT_READY&&recv_calls==before+2&&(errno==EAGAIN||errno==EWOULDBLOCK));
 /* EINTR followed by genuine data still produces the exact payload. */
 assert(sendto(peer,payload,31,0,&receiver_address.addr,receiver_size)==31);real_ready(receiver,1);before=recv_calls;recv_injected=EINTR;
 assert(try_recv(receiver,&op,&size)==STATUS_SUCCESS&&size==31&&recv_calls==before+2&&!memcmp(payload,bytes,31));
 op.unix_flags=MSG_OOB;recv_injected=EINVAL;
 assert(try_recv(receiver,&op,&size)==STATUS_DEVICE_NOT_READY&&errno==EWOULDBLOCK);op.unix_flags=0;
 const int errors[]={EHOSTUNREACH,ENETUNREACH,ECONNRESET,ECONNREFUSED,EMSGSIZE,EFAULT};
 const NTSTATUS results[]={STATUS_HOST_UNREACHABLE,STATUS_NETWORK_UNREACHABLE,STATUS_CONNECTION_RESET,STATUS_CONNECTION_REFUSED,STATUS_BUFFER_OVERFLOW,STATUS_ACCESS_VIOLATION};
 for(unsigned i=0;i<sizeof errors/sizeof *errors;++i){recv_injected=errors[i];observer_error=ENOTCONN;size=0x7788;
  assert(try_recv(receiver,&op,&size)==results[i]&&errno==errors[i]&&size==0x7788);real_ready(receiver,0);}
#endif
 /* Honest truncation and empty datagrams retain native UDP semantics. */
 assert(sendto(peer,payload,sizeof payload,0,&receiver_address.addr,receiver_size)==sizeof payload);real_ready(receiver,1);
 assert(try_recv(receiver,&op,&size)==STATUS_BUFFER_OVERFLOW&&size==sizeof bytes&&!memcmp(payload,bytes,sizeof bytes));
 assert(sendto(peer,payload,0,0,&receiver_address.addr,receiver_size)==0);real_ready(receiver,1);
 assert(try_recv(receiver,&op,&size)==STATUS_SUCCESS&&size==0);real_ready(receiver,0);
 assert(!connect(receiver,&peer_address.addr,peer_size));op.addr=NULL;op.addr_len=NULL;
 assert(sendto(peer,payload,31,0,&receiver_address.addr,receiver_size)==31);real_ready(receiver,1);
 assert(try_recv(receiver,&op,&size)==STATUS_SUCCESS&&size==31&&!memcmp(payload,bytes,31));
 printf("PASS production IPv%d receive: real scatter/gather bytes, source address, bidirectional nonce, pending/completion, EINTR, errors, zero/truncated and connected datagrams\n",family==AF_INET?4:6);
 close(receiver);close(peer);
}
int main(void){exercise(AF_INET);exercise(AF_INET6);return 0;}
'''

with tempfile.TemporaryDirectory(prefix='madeira-native-udp-recv-') as directory:
    for name, source in [('before', SOURCE), ('after', AFTER)]:
        path = Path(directory) / (name + '.c')
        binary = path.with_suffix('')
        path.write_text(PREFIX + RECV_PRELUDE + '\n' +
                        function(source, 'static void ios_sock_wire(').replace('static void ios_sock_wire(', 'static void captured_ios_sock_wire(') + '\n' +
                        function(source, 'static NTSTATUS sock_errno_to_status(') + '\n' +
                        function(source, 'static int sockaddr_from_unix(') + '\n' +
                        function(source, 'static socklen_t sockaddr_to_unix(') + '\n' +
                        function(source, 'static NTSTATUS try_recv(') + '\n' +
                        function(source, 'static BOOL async_recv_proc(') + '\n' + MAIN)
        command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-function', '-Wno-unused-variable', '-Wno-sign-compare', '-Wno-address',
                   '-pthread', '-fsanitize=undefined', '-fno-sanitize-recover=all',
                   '-I' + str(ROOT / 'wine/include'), '-I' + str(HEADER.parent), str(path), '-o', str(binary)]
        if name == 'before': command.insert(1, '-DBASELINE')
        subprocess.run(command, check=True)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        assert len(result.stdout) + len(result.stderr) < 65536, 'receive diagnostic output exceeded bound'
        print(result.stdout, end='')
        if result.returncode:
            print(result.stderr, end='')
            raise subprocess.CalledProcessError(result.returncode, [str(binary)])
        for line in result.stderr.splitlines()[:4]: print(line)

assert SOURCE_PATH.read_bytes() == ORIGINAL
assert AFTER.index('int recv_error = errno;') < AFTER.index('recv_status = sock_errno_to_status( recv_error );') < AFTER.index('WARN( "recvmsg: %s\\n", strerror( recv_error ) );')
assert AFTER.index('ios_socket_recv_failure( fd, async->unix_flags') < AFTER.index('errno = recv_error;')
for bad in (AFTER, SOURCE.replace('ios_sock_tl( fd, 0, NULL, 0, errno );', '/* missing observer */'),
            SOURCE + '\n/* ios_socket_datagram_progress( fd, partial stage */\n'):
    try: stage.stage_source(bad, HEADER)
    except ValueError: pass
    else: raise AssertionError('changed or already staged receive source must fail closed')
print('PASS receive staging: immutable pinned vendor source; errno/status captured before observers; changed producer rejected')
