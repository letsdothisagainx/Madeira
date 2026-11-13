#!/usr/bin/env python3
"""Exercise the bounded passive native-result checkpoint, not Internet access.

Packets use real owned loopback sockets. Public sockaddr classification inputs
are deliberately synthetic metadata; no packet is sent to those addresses.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / 'build/ntdll-unix/socket_error_context.h'
PRELUDE = r'''
#define _GNU_SOURCE
#define WINE_IOS 1
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#define STATUS_INVALID_ADDRESS 0xc0000141u
#define STATUS_SUCCESS 0
#define STATUS_BUFFER_OVERFLOW 0x80000005u
typedef uintptr_t ULONG_PTR;
typedef struct {void *Peb;struct {void *UniqueProcess,*UniqueThread;} ClientId;} TEB;
static _Thread_local TEB teb;
static TEB* NtCurrentTeb(void){return &teb;}
static _Atomic unsigned option_calls,clock_calls,lock_calls,logs;
static _Thread_local unsigned held;
static char records[128][512];
static int controlled_clock_failure;
static int measured_option(int fd,int level,int option,void *value,socklen_t *size){
 assert(option!=SO_ERROR);atomic_fetch_add(&option_calls,1);int ret=getsockopt(fd,level,option,value,size);errno=ECHILD;return ret;
}
static int measured_clock(clockid_t clock,struct timespec *time){
 assert(!held&&clock==CLOCK_MONOTONIC);atomic_fetch_add(&clock_calls,1);if(controlled_clock_failure){errno=EINVAL;return -1;}
 int ret=clock_gettime(clock,time);errno=EIO;return ret;
}
static int measured_lock(pthread_mutex_t *mutex){atomic_fetch_add(&lock_calls,1);int ret=pthread_mutex_lock(mutex);assert(!ret);++held;errno=EDOM;return ret;}
static int measured_unlock(pthread_mutex_t *mutex){assert(held);--held;int ret=pthread_mutex_unlock(mutex);errno=EPERM;return ret;}
static int measured_print(int fd,const char *format,...){
 assert(!held&&fd==2);unsigned slot=atomic_fetch_add(&logs,1);assert(slot<128);va_list ap;va_start(ap,format);int ret=vsnprintf(records[slot],sizeof records[slot],format,ap);va_end(ap);assert(ret>0&&ret<sizeof records[slot]);errno=ENOTCONN;return ret;
}
#define getsockopt measured_option
#define clock_gettime measured_clock
#define pthread_mutex_lock measured_lock
#define pthread_mutex_unlock measured_unlock
#define dprintf measured_print
#include "socket_error_context.h"
#undef getsockopt
#undef clock_gettime
#undef pthread_mutex_lock
#undef pthread_mutex_unlock
#undef dprintf
'''
MAIN = r'''
static int actual_fd;
static struct sockaddr_in metadata;
static struct msghdr message;
static unsigned worker_pid=100;
static void owner(unsigned pid){teb.Peb=(void*)(uintptr_t)(0x100000+pid*64);teb.ClientId.UniqueProcess=(void*)(uintptr_t)pid;teb.ClientId.UniqueThread=(void*)(uintptr_t)(pid+4);}
static void checkpoint(int send,int status){errno=E2BIG;ios_socket_datagram_progress(actual_fd,&message,0,32,status,send);assert(errno==E2BIG);}
static void* worker(void *index){owner(worker_pid);teb.ClientId.UniqueThread=(void*)((uintptr_t)index+1000);for(unsigned i=0;i<10000;++i){checkpoint(1,STATUS_SUCCESS);checkpoint(0,STATUS_SUCCESS);}return NULL;}
int main(void){
 int listener=socket(AF_INET,SOCK_DGRAM,0),peer=socket(AF_INET,SOCK_DGRAM,0);assert(listener>=0&&peer>=0);actual_fd=listener;
 struct sockaddr_in local={0};local.sin_family=AF_INET;local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 assert(!bind(listener,(struct sockaddr*)&local,sizeof local));socklen_t size=sizeof local;assert(!getsockname(listener,(struct sockaddr*)&local,&size));
 unsigned char sent[32],received[32];for(unsigned i=0;i<sizeof sent;++i)sent[i]=(unsigned char)(0x71^i);
 assert(sendto(peer,sent,sizeof sent,0,(struct sockaddr*)&local,sizeof local)==sizeof sent);
 struct pollfd ready={listener,POLLIN,0};assert(poll(&ready,1,2000)==1&&(ready.revents&POLLIN));
 assert(recvfrom(listener,received,sizeof received,0,NULL,NULL)==sizeof received&&!memcmp(sent,received,sizeof sent));
 puts("PASS actual native loopback nonce; public endpoint classification below is SYNTHETIC metadata only, not a public UDP probe");
 metadata.sin_family=AF_INET;metadata.sin_addr.s_addr=htonl(0x7f000001);metadata.sin_port=htons(27000);message.msg_name=&metadata;message.msg_namelen=sizeof metadata;
 owner(100);checkpoint(1,0);checkpoint(0,0);assert(!logs&&!option_calls&&!clock_calls&&!lock_calls);
 metadata.sin_addr.s_addr=htonl(0x08080808);metadata.sin_port=htons(53);checkpoint(1,0);assert(!logs&&!option_calls&&!lock_calls);
 metadata.sin_port=htons(27000);checkpoint(1,STATUS_SUCCESS);checkpoint(0,STATUS_BUFFER_OVERFLOW);
 assert(logs==2&&clock_calls==2&&lock_calls==2);assert(strstr(records[0],"direction=send")&&strstr(records[1],"direction=recv"));
 assert(strstr(records[1],"afd-status=80000005")&&strstr(records[0],"clock=monotonic time-valid=1"));
 assert(strstr(records[0],"first-owner-direction=1 paired=0")&&strstr(records[0],"native-bytes=32"));
 assert(!strstr(records[0],"8.8.8.8")&&!strstr(records[0],"27000")&&strstr(records[0],"endpoints=omitted payload=omitted"));
 unsigned opts=option_calls,clocks=clock_calls,locks=lock_calls;
 for(unsigned i=0;i<100000;++i){checkpoint(1,0);checkpoint(0,0);}
 ios_socket_datagram_progress(actual_fd,NULL,0,32,0,1);ios_socket_datagram_progress(actual_fd,NULL,0,32,0,0);
 assert(option_calls==opts&&clock_calls==clocks&&lock_calls==locks&&logs==2);
 pthread_t threads[12];for(unsigned i=0;i<12;++i)assert(!pthread_create(&threads[i],0,worker,(void*)(uintptr_t)i));
 for(unsigned i=0;i<12;++i)assert(!pthread_join(threads[i],0));assert(logs==2&&option_calls==opts&&clock_calls==clocks);
 /* Each thread consults the shared sampled-owner bit at most once/direction;
  * its subsequent 20,000 invocations use only its owner-keyed TLS mask. */
 assert(lock_calls==locks+24);
 worker_pid=200;
 for(unsigned i=0;i<12;++i)assert(!pthread_create(&threads[i],0,worker,(void*)(uintptr_t)i));
 for(unsigned i=0;i<12;++i)assert(!pthread_join(threads[i],0));
 assert(logs==4&&clock_calls==clocks+2);
#ifdef SO_PROTOCOL
 assert(option_calls==opts+4);
#else
 assert(option_calls==opts+2);
#endif
 assert((!!strstr(records[2],"direction=send")+!!strstr(records[3],"direction=send"))==1);
 assert((!!strstr(records[2],"direction=recv")+!!strstr(records[3],"direction=recv"))==1);
 owner(101);controlled_clock_failure=1;checkpoint(1,0);assert(logs==5&&strstr(records[4],"time-valid=0 observed-ns=0"));checkpoint(0,0);controlled_clock_failure=0;
 /* A new logical PID with the same PEB pointer must not inherit cached bits. */
 teb.ClientId.UniqueProcess=(void*)102;checkpoint(1,0);checkpoint(0,0);assert(logs==8);
 /* Fixed table cap is 64 owners, two directions each. It is not a packet count. */
 for(unsigned pid=103;pid<180;++pid){owner(pid);checkpoint(1,0);checkpoint(0,0);}assert(logs==128);
 owner(999);checkpoint(1,0);opts=option_calls;clocks=clock_calls;locks=lock_calls;
 for(unsigned i=0;i<100000;++i){checkpoint(1,0);checkpoint(0,0);}
 assert(logs==128&&option_calls==opts&&clock_calls==clocks&&lock_calls==locks);
 close(peer);close(listener);
 puts("PASS passive boundary checkpoint: errno retained; public/non-DNS datagram filter; honest status/time; two directional events/owner; concurrent single sampling; 200k hot calls without extra syscalls/locks; fixed64-owner cap");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-udp-passive-') as directory:
    path = Path(directory) / 'progress.c'
    binary = path.with_suffix('')
    path.write_text(PRELUDE + MAIN)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-function', '-Wno-unused-variable', '-Wno-sign-compare', '-Wno-misleading-indentation',
                    '-pthread', '-fsanitize=undefined', '-fno-sanitize-recover=all',
                    '-I' + str(HEADER.parent), str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
