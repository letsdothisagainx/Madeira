#!/usr/bin/env python3
"""Exercise staged production UDP send/error code and real owned loopback I/O.

The deterministic error injection tests observer-induced errno corruption;
successful traffic always uses actual native UDP packets and receives them.
Neither part supplies a CS2/server/VAC acceptance result.
"""
from pathlib import Path
import importlib.util
import os
import re
import subprocess
import tempfile
from collections import Counter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / 'wine/dlls/ntdll/unix/socket.c').read_text()
HEADER = ROOT / 'build/ntdll-unix/socket_error_context.h'
spec = importlib.util.spec_from_file_location('socket_stage', ROOT / 'tools/build/stage-ios-socket-errors.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
AFTER = stage.stage_source(SOURCE, HEADER)


def function(text, marker):
    at = text.index(marker)
    return text[at:text.index('\n}', at) + 2]


PRELUDE = r'''
#define _GNU_SOURCE
#define WINE_IOS 1
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <unistd.h>
typedef int32_t NTSTATUS;typedef int BOOL;typedef unsigned char BYTE;typedef uintptr_t ULONG_PTR;
#include "ntstatus.h"
typedef struct { void *Peb; struct { void *UniqueProcess, *UniqueThread; } ClientId; } TEB;
static TEB teb={(void*)0x12340000,{(void*)100,(void*)104}};
static TEB *NtCurrentTeb(void){return &teb;}
static int checked_getsockopt(int fd,int level,int option,void *value,socklen_t *size){assert(option!=SO_ERROR);return getsockopt(fd,level,option,value,size);}
#define getsockopt checked_getsockopt
#include "socket_error_context.h"
#define WS_AF_INET 2
#define WS_AF_INET6 23
#define WS_AF_UNSPEC 0
#define HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID 1
struct WS_sockaddr {uint16_t sa_family;char sa_data[14];};
struct WS_sockaddr_in {uint16_t sin_family,sin_port;struct in_addr sin_addr;char sin_zero[8];};
struct WS_sockaddr_in6 {uint16_t sin6_family,sin6_port;uint32_t sin6_flowinfo;struct in6_addr sin6_addr;uint32_t sin6_scope_id;};
union unix_sockaddr {struct sockaddr addr;struct sockaddr_in in;struct sockaddr_in6 in6;};
struct async_send_ioctl {const struct WS_sockaddr *addr;int addr_len,unix_flags;unsigned sent_len,count,iov_cursor;int fd;struct iovec iov[2];};
static int injected,send_calls,observer_calls,last_native_error;
static ssize_t actual_or_injected_send(int fd,const struct msghdr *message,int flags){
 send_calls++;if(injected){errno=injected;last_native_error=injected;injected=0;return -1;}
 ssize_t result=sendmsg(fd,message,flags);last_native_error=result<0?errno:0;return result;
}
#define sendmsg actual_or_injected_send
#define WARN(...) do {errno=ENOTCONN;}while(0)
#define ERR(...) do {errno=ENOTCONN;}while(0)
#define FIXME(...) do {errno=ENOTCONN;}while(0)
static void ios_sock_big_note(int fd,int send,long result,int error){(void)fd;(void)send;(void)result;(void)error;observer_calls++;errno=ENOTCONN;}
static void ios_sock_wire(int fd,int send,const void *buffer,long result,int error){(void)fd;(void)send;(void)buffer;(void)result;(void)error;observer_calls++;errno=ENOTCONN;}
static void ios_sock_tl(int fd,int send,const void *buffer,long result,int error){(void)fd;(void)send;(void)buffer;(void)result;(void)error;observer_calls++;errno=ENOTCONN;}
'''

MAIN = r'''
static struct async_send_ioctl operation(const void *address,int length,unsigned char *bytes){
 struct async_send_ioctl op;memset(&op,0,sizeof(op));op.addr=address;op.addr_len=length;op.count=2;op.fd=-1;
 op.iov[0]=(struct iovec){bytes,9};op.iov[1]=(struct iovec){bytes+9,23};return op;
}
static void receive_nonce(int fd,const unsigned char *expected){
 struct pollfd ready={fd,POLLIN,0};assert(poll(&ready,1,2000)==1&&(ready.revents&POLLIN));
 unsigned char actual[64];assert(recvfrom(fd,actual,sizeof(actual),0,NULL,NULL)==32);assert(!memcmp(actual,expected,32));
}
static int exercise(int family){
 observer_calls=0;send_calls=0;
 int listener=socket(family,SOCK_DGRAM,0);if(listener<0&&family==AF_INET6&&errno==EAFNOSUPPORT){puts("SKIP native IPv6 unavailable");return 0;}assert(listener>=0);
 int transmitter=socket(family,SOCK_DGRAM,0);assert(transmitter>=0);
 assert(!fcntl(listener,F_SETFL,O_NONBLOCK));assert(!fcntl(transmitter,F_SETFL,O_NONBLOCK));
 union unix_sockaddr destination;memset(&destination,0,sizeof(destination));socklen_t length;
 struct WS_sockaddr_in target4={0};struct WS_sockaddr_in6 target6={0};
 if(family==AF_INET){destination.in.sin_family=AF_INET;destination.in.sin_addr.s_addr=htonl(INADDR_LOOPBACK);length=sizeof(destination.in);}
 else{destination.in6.sin6_family=AF_INET6;destination.in6.sin6_addr=in6addr_loopback;length=sizeof(destination.in6);}
 assert(!bind(listener,&destination.addr,length));assert(!getsockname(listener,&destination.addr,&length));
 unsigned char bytes[32];for(unsigned i=0;i<32;i++)bytes[i]=(unsigned char)(0xa0^i);
 struct async_send_ioctl op;
 if(family==AF_INET){target4.sin_family=WS_AF_INET;target4.sin_port=destination.in.sin_port;target4.sin_addr=destination.in.sin_addr;op=operation(&target4,sizeof(target4),bytes);}
 else{target6.sin6_family=WS_AF_INET6;target6.sin6_port=destination.in6.sin6_port;target6.sin6_addr=destination.in6.sin6_addr;op=operation(&target6,sizeof(target6),bytes);}
#ifdef BASELINE
 injected=EHOSTUNREACH;errno=0;assert(try_send(transmitter,&op)==STATUS_INVALID_CONNECTION);assert(errno==ENOTCONN&&observer_calls==3);
 puts("PASS before: actual production try_send loses native EHOSTUNREACH to observer ENOTCONN");
#else
 injected=EHOSTUNREACH;errno=0;assert(try_send(transmitter,&op)==STATUS_HOST_UNREACHABLE);assert(errno==EHOSTUNREACH&&op.sent_len==0&&op.iov_cursor==0);
 assert(ios_socket_address_class(&destination.addr,length)&&!strcmp(ios_socket_address_class(&destination.addr,length),"loopback"));
 assert(!try_send(transmitter,&op)&&op.sent_len==32&&op.iov_cursor==2);receive_nonce(listener,bytes);
 op=operation(family==AF_INET?(void*)&target4:(void*)&target6,family==AF_INET?sizeof(target4):sizeof(target6),bytes);
 injected=EWOULDBLOCK;assert(try_send(transmitter,&op)==STATUS_DEVICE_NOT_READY&&errno==EWOULDBLOCK&&op.sent_len==0);
 op=operation(family==AF_INET?(void*)&target4:(void*)&target6,family==AF_INET?sizeof(target4):sizeof(target6),bytes);
 injected=ECONNREFUSED;int before=send_calls;assert(!try_send(transmitter,&op)&&send_calls==before+2&&op.sent_len==32);receive_nonce(listener,bytes);
 /* Actual connected UDP bidirectional exchange; destination NULL must retain
  * the existing connected-socket semantics. No invented send completion. */
 assert(!connect(transmitter,&destination.addr,length));op=operation(NULL,0,bytes);assert(!try_send(transmitter,&op)&&op.sent_len==32);receive_nonce(listener,bytes);
 union unix_sockaddr source;socklen_t source_length=sizeof(source);assert(!getsockname(transmitter,&source.addr,&source_length));
 assert(sendto(listener,bytes,32,0,&source.addr,source_length)==32);receive_nonce(transmitter,bytes);
 unsigned char empty;assert(recv(transmitter,&empty,1,0)==-1&&(errno==EAGAIN||errno==EWOULDBLOCK));
 printf("PASS after: production IPv%d UDP scatter/gather sends real nonce packets and receives replies; native errors/retry policy survive clobbering observers\n",family==AF_INET?4:6);
#endif
 close(listener);close(transmitter);return 1;
}
static void unspecified_case(unsigned kind){
 int listener_family=kind==1?AF_INET6:AF_INET,transmitter_family=kind?AF_INET6:AF_INET;
 int listener=socket(listener_family,SOCK_DGRAM,0),transmitter=socket(transmitter_family,SOCK_DGRAM,0);
 assert(listener>=0&&transmitter>=0);int disabled=0;
 if(kind==2)assert(!setsockopt(transmitter,IPPROTO_IPV6,IPV6_V6ONLY,&disabled,sizeof(disabled)));
 union unix_sockaddr local;memset(&local,0,sizeof(local));socklen_t local_length;
 if(listener_family==AF_INET){local.in.sin_family=AF_INET;local.in.sin_addr.s_addr=htonl(INADDR_LOOPBACK);local_length=sizeof(local.in);}
 else{local.in6.sin6_family=AF_INET6;local.in6.sin6_addr=in6addr_loopback;local_length=sizeof(local.in6);}
 assert(!bind(listener,&local.addr,local_length));assert(!getsockname(listener,&local.addr,&local_length));
 assert(!fcntl(listener,F_SETFL,O_NONBLOCK));assert(!fcntl(transmitter,F_SETFL,O_NONBLOCK));
 struct WS_sockaddr_in target4={0};struct WS_sockaddr_in6 target6={0};unsigned char target_before[sizeof(target6)];
 const void *target;int length;unsigned char bytes[32];for(unsigned i=0;i<32;i++)bytes[i]=(unsigned char)(0x70^i^kind);
 if(!kind){target4.sin_family=WS_AF_INET;target4.sin_port=local.in.sin_port;target=&target4;length=sizeof(target4);}
 else{target6.sin6_family=WS_AF_INET6;target6.sin6_port=listener_family==AF_INET?local.in.sin_port:local.in6.sin6_port;
  if(kind==2){unsigned char *p=(unsigned char*)&target6.sin6_addr;p[10]=0xff;p[11]=0xff;}target=&target6;length=sizeof(target6);}
 uint16_t port_before=!kind?target4.sin_port:target6.sin6_port;
 memcpy(target_before,target,length);struct async_send_ioctl op=operation(target,length,bytes);injected=0;int calls_before=send_calls;
 NTSTATUS status=try_send(transmitter,&op);
#ifdef BASELINE
#ifdef __APPLE__
 assert(status==STATUS_INVALID_CONNECTION&&last_native_error==EHOSTUNREACH&&op.sent_len==0&&send_calls==calls_before+1);
 struct pollfd ready={listener,POLLIN,0};assert(!poll(&ready,1,20));
 printf("PASS before: Darwin unspecified datagram form=%u reaches native sendmsg and reports real EHOSTUNREACH\n",kind);
#else
 assert(status==STATUS_SUCCESS&&op.sent_len==32&&send_calls==calls_before+1);receive_nonce(listener,bytes);
 printf("PASS before: Linux unspecified datagram form=%u wrongly delivers a real nonce to owned loopback\n",kind);
#endif
#else
 assert(status==STATUS_INVALID_ADDRESS&&op.sent_len==0&&op.iov_cursor==0&&send_calls==calls_before);
 struct pollfd ready={listener,POLLIN,0};assert(!poll(&ready,1,20));
 /* Invalid address is checked before the existing port-zero substitution.
  * This rejected attempt must never emit a packet to the discard service. */
 if(!kind)target4.sin_port=0;else target6.sin6_port=0;
 op=operation(target,length,bytes);assert(try_send(transmitter,&op)==STATUS_INVALID_ADDRESS&&send_calls==calls_before&&op.sent_len==0);
 if(!kind)target4.sin_port=port_before;
 else target6.sin6_port=port_before;
 printf("PASS after: unspecified datagram form=%u rejects with STATUS_INVALID_ADDRESS/WSAEADDRNOTAVAIL, no native call, no received packet and no port rewrite\n",kind);
#endif
 assert(!memcmp(target_before,target,length));close(listener);close(transmitter);
}
static void context_budget(void){
#ifndef BASELINE
 int listener=socket(AF_INET,SOCK_DGRAM,0),descriptors[17];assert(listener>=0);
 struct sockaddr_in local;memset(&local,0,sizeof(local));local.sin_family=AF_INET;local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 assert(!bind(listener,(struct sockaddr*)&local,sizeof(local)));socklen_t local_length=sizeof(local);assert(!getsockname(listener,(struct sockaddr*)&local,&local_length));
 struct WS_sockaddr_in target={0};target.sin_family=WS_AF_INET;target.sin_port=local.sin_port;target.sin_addr=local.sin_addr;
 unsigned char bytes[32]={0};teb.ClientId.UniqueProcess=(void*)300;teb.Peb=(void*)0x9abc0000;
 for(unsigned i=0;i<17;i++){descriptors[i]=socket(AF_INET,SOCK_DGRAM,0);assert(descriptors[i]>=0);
  for(unsigned j=0;j<3;j++){struct async_send_ioctl op=operation(&target,sizeof(target),bytes);injected=EHOSTUNREACH;
   assert(try_send(descriptors[i],&op)==STATUS_HOST_UNREACHABLE&&errno==EHOSTUNREACH&&!op.sent_len);}}
 struct pollfd ready={listener,POLLIN,0};assert(!poll(&ready,1,20));
 for(unsigned i=0;i<17;i++){close(descriptors[i]);}
 close(listener);
#endif
}
int main(void){
 struct sockaddr_in6 mapped;memset(&mapped,0,sizeof(mapped));mapped.sin6_family=AF_INET6;
 unsigned char *address=(unsigned char*)&mapped.sin6_addr;address[10]=0xff;address[11]=0xff;
 assert(!strcmp(ios_socket_address_class((struct sockaddr*)&mapped,sizeof(mapped)),"mapped-unspecified"));
 address[12]=127;address[15]=1;assert(!strcmp(ios_socket_address_class((struct sockaddr*)&mapped,sizeof(mapped)),"mapped-loopback"));
 address[12]=169;address[13]=254;assert(!strcmp(ios_socket_address_class((struct sockaddr*)&mapped,sizeof(mapped)),"mapped-linklocal"));
 address[12]=10;address[13]=0;assert(!strcmp(ios_socket_address_class((struct sockaddr*)&mapped,sizeof(mapped)),"mapped-private"));
 address[12]=8;address[13]=8;assert(!strcmp(ios_socket_address_class((struct sockaddr*)&mapped,sizeof(mapped)),"mapped-public"));
 assert(!strcmp(ios_socket_address_class((struct sockaddr*)&mapped,1),"absent"));
 exercise(AF_INET);exercise(AF_INET6);
 teb.ClientId.UniqueProcess=(void*)200;teb.Peb=(void*)0x56780000;
 unspecified_case(0);unspecified_case(1);unspecified_case(2);context_budget();return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-native-udp-send-') as directory:
    for name, source in [('before', SOURCE), ('after', AFTER)]:
        path = Path(directory) / (name + '.c')
        binary = path.with_suffix('')
        path.write_text(PRELUDE + '\n' + function(source, 'static NTSTATUS sock_errno_to_status(') + '\n' +
                        function(source, 'static socklen_t sockaddr_to_unix(') + '\n' +
                        function(source, 'static NTSTATUS try_send(') + '\n' + MAIN)
        command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-function', '-Wno-unused-variable', '-Wno-sign-compare', '-Wno-address',
                   '-pthread', '-fsanitize=undefined', '-fno-sanitize-recover=all',
                   '-I' + str(ROOT / 'wine/include'), '-I' + str(HEADER.parent), str(path), '-o', str(binary)]
        if name == 'before':
            command.insert(1, '-DBASELINE')
        subprocess.run(command, check=True)
        result = subprocess.run([str(binary)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert len(result.stdout) + len(result.stderr) < 65536, 'host diagnostic output exceeded bound'
        print(result.stdout, end='')
        if result.returncode:
            print(result.stderr, end='')
            raise subprocess.CalledProcessError(result.returncode, [str(binary)])
        print('\n'.join(result.stderr.splitlines()[:4]))
        if name == 'after':
            records = re.findall(r'\[udp-send-failure-v1\] pid=012c .*? fd=(\d+) ', result.stderr)
            counts = Counter(records)
            assert len(records) == 32 and len(counts) == 16 and set(counts.values()) == {2}
            print('PASS production context budget: 32/process, 16 distinct FDs, two/FD; no packets emitted by injected failures')

assert '#include "' + str(HEADER) + '"' in AFTER
assert AFTER.index('const int send_error = errno;') < AFTER.index('if (send_error == EISCONN)')
assert AFTER.index('ios_socket_invalid_datagram_destination( &unix_addr.addr') < AFTER.index(stage.DESTINATION)
assert '{STATUS_INVALID_ADDRESS,            WSAEADDRNOTAVAIL}' in (ROOT / 'wine/dlls/ws2_32/socket.c').read_text()
assert 'so-error=unread-destructive' in HEADER.read_text()
try:
    stage.stage_source(AFTER, HEADER)
except ValueError:
    pass
else:
    raise AssertionError('duplicate overlay must not be silently accepted')
try:
    stage.stage_source(SOURCE.replace('if (errno == EISCONN)', 'if (errno == EINVAL)'), HEADER)
except ValueError:
    pass
else:
    raise AssertionError('changed producer must fail closed')
print('PASS native socket staging boundaries: pinned source unchanged; duplicate/changed producer rejected')
