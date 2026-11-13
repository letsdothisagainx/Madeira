#!/usr/bin/env python3
"""Exercise actual native/WoW64 control converters with real UDP and bounds.

This does not contact a Valve endpoint or prove official matchmaking succeeds.
"""
from pathlib import Path
import hashlib
import importlib.util
import os
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = ROOT / 'wine/dlls/ntdll/unix/socket.c'
SOURCE = SOURCE_PATH.read_text()
spec = importlib.util.spec_from_file_location('socket_control_stage', ROOT / 'tools/build/stage-ios-socket-control.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
AFTER = stage.stage_source(SOURCE)


def function(source, name):
    at = source.index(name)
    return source[at:source.index('\n}', at) + 2]


PRELUDE = r'''
#define _GNU_SOURCE
#define __APPLE_USE_RFC_3542 1
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
typedef uint32_t ULONG; typedef int32_t INT; typedef uint32_t UINT;
typedef struct {ULONG len;char *buf;} WSABUF;
typedef struct {size_t cmsg_len;INT cmsg_level,cmsg_type;} WSACMSGHDR;
struct afd_wsabuf_32 {UINT len,buf;};
struct WS_in_pktinfo {struct in_addr ipi_addr;UINT ipi_ifindex;};
struct WS_in6_pktinfo {struct in6_addr ipi6_addr;UINT ipi6_ifindex;};
static unsigned char *mapped;
static void *afd_guest_ptr(uint64_t value){assert(!value||value==0x1234);return value?mapped:NULL;}
#define WSA_CMSG_ALIGN(n) (((n)+sizeof(size_t)-1)&~(sizeof(size_t)-1))
#define HAVE_STRUCT_IN6_PKTINFO_IPI6_ADDR 1
#define FIXME(...) do{}while(0)
'''

MAIN = r'''
static size_t align32(size_t n){return(n+3)&~(size_t)3;}
static size_t align64(size_t n){return(n+7)&~(size_t)7;}
static size_t record(unsigned char *p,unsigned n,unsigned ordinal){
 WSACMSGHDR h={16+n,0x12340000+(INT)ordinal,0x56780000+(INT)ordinal};memcpy(p,&h,16);
 for(unsigned i=0;i<n;++i)p[16+i]=(unsigned char)(ordinal*17+i);
 return align64(16+n);
}
static void guards(const unsigned char*p,size_t n){for(size_t i=0;i<n;++i)assert(p[i]==0xcc);}
static void source_guards(const unsigned char*p,size_t n){for(size_t i=0;i<n;++i)assert(p[i]==0x7a);}
static void vectors(void){
 const unsigned sizes[]={0,1,2,3,4,5,7,8,12,16,20,31,255};unsigned cases=0;
 for(unsigned misalign=0;misalign<2;++misalign)for(unsigned unpadded=0;unpadded<2;++unpadded)
 for(unsigned a=0;a<sizeof sizes/sizeof*sizes;++a)for(unsigned count=1;count<=3;++count){
  size_t in_len=0,out_len=0;
  for(unsigned i=0;i<count;++i){unsigned n=sizes[(a+i)%13];in_len+=align64(16+n);out_len+=align32(12+n);}
  if(unpadded)in_len-=align64(16+sizes[(a+count-1)%13])-(16+sizes[(a+count-1)%13]);
  unsigned char *in_raw=malloc(in_len+64+misalign),*out_raw=malloc(out_len+64+misalign);assert(in_raw&&out_raw);
  memset(in_raw,0x7a,in_len+64+misalign);memset(out_raw,0xcc,out_len+64+misalign);
  unsigned char *in=in_raw+32+misalign,*out=out_raw+32+misalign;size_t pos=0;
  for(unsigned i=0;i<count;++i){unsigned n=sizes[(a+i)%13];pos+=record(in+pos,n,i);}
  WSABUF from={(ULONG)in_len,(char*)in};struct afd_wsabuf_32 to={(UINT)out_len,0x1234};mapped=out;
  assert(wow64_translate_control(&from,&to)&&to.len==out_len);size_t ip=0,op=0;
  for(unsigned i=0;i<count;++i){unsigned n=sizes[(a+i)%13];struct cmsghdr_32 h;memcpy(&h,out+op,12);
   assert(h.cmsg_len==12+n&&h.cmsg_level==0x12340000+(INT)i&&h.cmsg_type==0x56780000+(INT)i);
   assert(!memcmp(out+op+12,in+ip+16,n));for(size_t j=12+n;j<align32(12+n);++j)assert(out[op+j]==0);
   ip+=align64(16+n);op+=align32(12+n);
  }
  source_guards(in_raw,32+misalign);source_guards(in+in_len,32);guards(out_raw,32+misalign);guards(out+out_len,32);
  memset(out_raw,0xcc,out_len+64+misalign);to.len=(UINT)out_len-1;
  assert(!wow64_translate_control(&from,&to)&&to.len==0);guards(out+out_len-1,33);
  free(in_raw);free(out_raw);++cases;
 }
 printf("PASS actual bounded WoW64 converter: %u multi-record/exact-sized/odd-payload/padding/unaligned/short-buffer cases, payloads and canaries exact\n",cases);
}
static void exact_allocations(void){
 const unsigned payloads[]={8,255};
 for(unsigned i=0;i<2;++i){unsigned n=payloads[i];size_t source_len=16+n,target_len=align32(12+n);
  unsigned char *src=malloc(source_len),*dst=malloc(target_len);assert(src&&dst);record(src,n,0);mapped=dst;
  WSABUF from={(ULONG)source_len,(char*)src};struct afd_wsabuf_32 to={(UINT)target_len,0x1234};
  assert(wow64_translate_control(&from,&to)&&to.len==target_len&&!memcmp(dst+12,src+16,n));free(src);free(dst);
 }
 puts("PASS ASan exact physical24/20-byte and271/268-byte allocations: no native-header overread or target overwrite");
}
static void malformed(void){
 unsigned char input[80]={0},output[80];mapped=output;WSABUF from={24,(char*)input};
 const size_t lengths[]={0,1,15,25,SIZE_MAX};
 for(unsigned i=0;i<sizeof lengths/sizeof*lengths;++i){WSACMSGHDR h={lengths[i],0,0};memcpy(input,&h,16);
  struct afd_wsabuf_32 to={64,0x1234};memset(output,0xcc,80);assert(!wow64_translate_control(&from,&to)&&!to.len);guards(output+64,16);}
 for(unsigned n=1;n<16;++n){from.len=n;struct afd_wsabuf_32 to={64,0x1234};assert(!wow64_translate_control(&from,&to)&&!to.len);}
 from.len=0;from.buf=NULL;struct afd_wsabuf_32 empty={0,0};assert(wow64_translate_control(&from,&empty)&&!empty.len);
 from.len=24;empty.len=64;assert(!wow64_translate_control(&from,&empty)&&!empty.len);
 puts("PASS malformed native headers/lengths and null/empty buffers fail honestly without source overreads");
}
static void before(void){
 unsigned char input[64],output[64];memset(input,0xa7,64);memset(output,0xcc,64);record(input,8,0);
 WSABUF from={24,(char*)input};struct afd_wsabuf_32 to={20,0x1234};mapped=output;
 assert(!old_wow64_translate_control(&from,&to)&&!to.len);
 to.len=64;assert(old_wow64_translate_control(&from,&to)&&to.len==20);
 assert(output[20]==0xa7&&output[35]==0xa7);
 puts("BEFORE reproduced: exact-size8-byte PKTINFO rejected; larger target receives16 bytes past declared payload");
}
static void class_case(int level,int type,int value,int byte_value,int expected_type,int is_alias){
 unsigned char ctl[CMSG_SPACE(sizeof(int))];memset(ctl,0,sizeof ctl);
 struct msghdr msg={0};msg.msg_control=ctl;msg.msg_controllen=CMSG_SPACE(byte_value?1:sizeof(int));
 struct cmsghdr *c=CMSG_FIRSTHDR(&msg);assert(c);c->cmsg_level=level;c->cmsg_type=type;
 c->cmsg_len=CMSG_LEN(byte_value?1:sizeof(int));
 if(byte_value)*(unsigned char*)CMSG_DATA(c)=(unsigned char)value;else memcpy(CMSG_DATA(c),&value,sizeof value);
 unsigned char out[24],old[24];WSABUF dst={24,(char*)out},baseline={24,(char*)old};
 assert(old_convert_control_headers(&msg,&baseline));if(is_alias)assert(!baseline.len);
 assert(convert_control_headers(&msg,&dst)&&dst.len==24);WSACMSGHDR h;memcpy(&h,out,16);int got;memcpy(&got,out+16,4);
 assert(h.cmsg_len==20&&h.cmsg_level==level&&h.cmsg_type==expected_type&&got==value);
}
static void classes(void){
 class_case(IPPROTO_IP,IP_TOS,0x29,1,WS_IP_TOS,0);
#if defined(IP_RECVTOS) && IP_RECVTOS != IP_TOS
 class_case(IPPROTO_IP,IP_RECVTOS,0xa7,1,WS_IP_TOS,1);
#endif
#ifdef IPV6_TCLASS
 class_case(IPPROTO_IPV6,IPV6_TCLASS,0x2b,0,WS_IPV6_TCLASS,0);
#if defined(IPV6_RECVTCLASS) && IPV6_RECVTCLASS != IPV6_TCLASS
 class_case(IPPROTO_IPV6,IPV6_RECVTCLASS,0x31,0,WS_IPV6_TCLASS,1);
#endif
#if defined(IP_RECVTCLASS) && IP_RECVTCLASS != IPV6_TCLASS && (!defined(IPV6_RECVTCLASS)||IP_RECVTCLASS != IPV6_RECVTCLASS)
 class_case(IPPROTO_IPV6,IP_RECVTCLASS,0x33,0,WS_IPV6_TCLASS,1);
#endif
#endif
 puts("PASS native IP_RECVTOS/IPv6 traffic-class aliases preserve actual TOS value in Windows INT control fields; original aliases were silently dropped");
}
static void native_udp(void){
 int rx=socket(AF_INET,SOCK_DGRAM,0),tx=socket(AF_INET,SOCK_DGRAM,0);assert(rx>=0&&tx>=0);
 struct sockaddr_in addr={0};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 assert(!bind(rx,(struct sockaddr*)&addr,sizeof addr));socklen_t alen=sizeof addr;assert(!getsockname(rx,(struct sockaddr*)&addr,&alen));
 int yes=1,packet=0,tos=0,configured_tos=0x28;
#ifdef IP_PKTINFO
 packet=!setsockopt(rx,IPPROTO_IP,IP_PKTINFO,&yes,sizeof yes);
#elif defined(IP_RECVDSTADDR)
 packet=!setsockopt(rx,IPPROTO_IP,IP_RECVDSTADDR,&yes,sizeof yes);
#endif
 if(!packet){puts("SKIP native IPv4 packet-info unsupported; loopback payload test remains active");}
#if defined(IP_RECVTOS) && defined(IP_TOS)
 tos=!setsockopt(rx,IPPROTO_IP,IP_RECVTOS,&yes,sizeof yes);
 assert(!setsockopt(tx,IPPROTO_IP,IP_TOS,&configured_tos,sizeof configured_tos));
#endif
 unsigned char payload[32],received[32],ctl[512];for(unsigned i=0;i<32;++i)payload[i]=(unsigned char)(0x8c^i);
 assert(sendto(tx,payload,32,0,(struct sockaddr*)&addr,sizeof addr)==32);
 struct pollfd ready={rx,POLLIN,0};assert(poll(&ready,1,2000)==1&&(ready.revents&POLLIN));
 struct iovec iov={received,sizeof received};struct msghdr msg={0};msg.msg_iov=&iov;msg.msg_iovlen=1;msg.msg_control=ctl;msg.msg_controllen=sizeof ctl;
 assert(recvmsg(rx,&msg,0)==32&&!memcmp(payload,received,32)&&!(msg.msg_flags&MSG_CTRUNC));
 unsigned char native64[512],windows32[512];WSABUF converted={512,(char*)native64};assert(convert_control_headers(&msg,&converted));
 size_t needed=0;unsigned packet_count=0,tos_count=0;
 for(size_t p=0;p<converted.len;){WSACMSGHDR h;memcpy(&h,native64+p,16);needed+=align32(12+h.cmsg_len-16);
  if(h.cmsg_type==WS_IP_PKTINFO){struct WS_in_pktinfo info;memcpy(&info,native64+p+16,sizeof info);assert(info.ipi_addr.s_addr==htonl(INADDR_LOOPBACK));++packet_count;}
  if(h.cmsg_type==WS_IP_TOS){int got;memcpy(&got,native64+p+16,4);assert(got==configured_tos);++tos_count;}
  p+=align64(h.cmsg_len);}
 assert(!packet||packet_count);assert(!tos||tos_count);
 mapped=windows32;struct afd_wsabuf_32 result={(UINT)needed,0x1234};assert(wow64_translate_control(&converted,&result)&&result.len==needed);
 size_t input_pos=0;for(size_t p=0;p<needed;){struct cmsghdr_32 h;WSACMSGHDR nh;memcpy(&h,windows32+p,12);memcpy(&nh,native64+input_pos,16);
  assert(h.cmsg_len==nh.cmsg_len-4&&h.cmsg_type==nh.cmsg_type&&h.cmsg_level==nh.cmsg_level);
  assert(!memcmp(windows32+p+12,native64+input_pos+16,h.cmsg_len-12));p+=align32(h.cmsg_len);input_pos+=align64(nh.cmsg_len);}
 close(tx);close(rx);puts("PASS actual native UDP recvmsg -> production native-control converter -> corrected exact-size WoW64 converter; real payload and destination address preserved");
}
static void native_udp6(void){
 int rx=socket(AF_INET6,SOCK_DGRAM,0);if(rx<0&&(errno==EAFNOSUPPORT||errno==EPROTONOSUPPORT)){puts("SKIP native IPv6 unsupported");return;}assert(rx>=0);
 int tx=socket(AF_INET6,SOCK_DGRAM,0);assert(tx>=0);struct sockaddr_in6 addr={0};addr.sin6_family=AF_INET6;addr.sin6_addr=in6addr_loopback;
 if(bind(rx,(struct sockaddr*)&addr,sizeof addr)){assert(errno==EADDRNOTAVAIL);close(rx);close(tx);puts("SKIP native IPv6 loopback address unavailable");return;}
 socklen_t alen=sizeof addr;assert(!getsockname(rx,(struct sockaddr*)&addr,&alen));int yes=1,packet=0,tos=0,value=0x28;
#ifdef IPV6_RECVPKTINFO
 packet=!setsockopt(rx,IPPROTO_IPV6,IPV6_RECVPKTINFO,&yes,sizeof yes);
#elif defined(IPV6_PKTINFO)
 packet=!setsockopt(rx,IPPROTO_IPV6,IPV6_PKTINFO,&yes,sizeof yes);
#endif
#if defined(IPV6_RECVTCLASS) && defined(IPV6_TCLASS)
 tos=!setsockopt(rx,IPPROTO_IPV6,IPV6_RECVTCLASS,&yes,sizeof yes);
 if(tos)assert(!setsockopt(tx,IPPROTO_IPV6,IPV6_TCLASS,&value,sizeof value));
#endif
 unsigned char bytes[31],actual[31],ctl[512];for(unsigned i=0;i<sizeof bytes;++i)bytes[i]=(unsigned char)(0x19+i);
 assert(sendto(tx,bytes,sizeof bytes,0,(struct sockaddr*)&addr,sizeof addr)==sizeof bytes);
 struct pollfd ready={rx,POLLIN,0};assert(poll(&ready,1,2000)==1&&(ready.revents&POLLIN));
 struct iovec iov={actual,sizeof actual};struct msghdr msg={0};msg.msg_iov=&iov;msg.msg_iovlen=1;msg.msg_control=ctl;msg.msg_controllen=sizeof ctl;
 assert(recvmsg(rx,&msg,0)==sizeof bytes&&!memcmp(bytes,actual,sizeof bytes)&&!(msg.msg_flags&MSG_CTRUNC));
 unsigned char native64[512],windows32[512];WSABUF converted={512,(char*)native64};assert(convert_control_headers(&msg,&converted));
 size_t needed=0;unsigned packet_count=0,tos_count=0;
 for(size_t p=0;p<converted.len;){WSACMSGHDR h;memcpy(&h,native64+p,16);needed+=align32(12+h.cmsg_len-16);
  if(h.cmsg_type==WS_IPV6_PKTINFO){struct WS_in6_pktinfo info;memcpy(&info,native64+p+16,sizeof info);assert(!memcmp(&info.ipi6_addr,&in6addr_loopback,16));++packet_count;}
  if(h.cmsg_type==WS_IPV6_TCLASS){int got;memcpy(&got,native64+p+16,4);assert(got==value);++tos_count;}
  p+=align64(h.cmsg_len);}
 assert(!packet||packet_count);assert(!tos||tos_count);mapped=windows32;struct afd_wsabuf_32 result={(UINT)needed,0x1234};
 assert(wow64_translate_control(&converted,&result)&&result.len==needed);
 size_t ip=0;for(size_t p=0;p<needed;){struct cmsghdr_32 h;WSACMSGHDR nh;memcpy(&h,windows32+p,12);memcpy(&nh,native64+ip,16);
  assert(h.cmsg_len==nh.cmsg_len-4&&h.cmsg_type==nh.cmsg_type&&h.cmsg_level==nh.cmsg_level);
  assert(!memcmp(windows32+p+12,native64+ip+16,h.cmsg_len-12));p+=align32(h.cmsg_len);ip+=align64(nh.cmsg_len);}
 close(rx);close(tx);printf("PASS native IPv6 UDP payload, packet-info=%d traffic-class=%d, exact-size WoW64 destination=%zu bytes\n",packet,tos,needed);
}
int main(void){before();vectors();exact_allocations();malformed();classes();native_udp();native_udp6();return 0;}
'''


constants = ''
headers = (ROOT / 'wine/include/ws2ipdef.h').read_text() + (ROOT / 'wine/include/ws2def.h').read_text()
for name in ('WS_IPPROTO_IP', 'WS_IP_TOS', 'WS_IP_TTL', 'WS_IP_PKTINFO',
             'WS_IPV6_PKTINFO', 'WS_IPV6_HOPLIMIT', 'WS_IPV6_TCLASS'):
    match = re.search(r'^#define\s+' + name + r'\s+(\d+)', headers, re.M)
    assert match, name
    constants += '#define ' + name + ' ' + match.group(1) + '\n'
constants += '#define WS_IPPROTO_IPV6 41\n'
types = SOURCE[SOURCE.index('struct cmsghdr_32\n'):SOURCE.index('/* we assume that cmsg_data')]
code = PRELUDE + constants + types
code += function(SOURCE, 'static WSACMSGHDR *fill_control_message(')
code += '\n' + function(SOURCE, 'static int convert_control_headers(').replace('convert_control_headers', 'old_convert_control_headers')
code += '\n' + function(AFTER, 'static int convert_control_headers(')
code += '\n' + function(SOURCE, stage.BEGIN).replace('wow64_translate_control', 'old_wow64_translate_control')
code += '\n' + function(AFTER, stage.BEGIN) + MAIN
with tempfile.TemporaryDirectory(prefix='madeira-control32-') as directory:
    d = Path(directory)
    c = d / 'controls.c'
    c.write_text(code)
    cc = shlex.split(os.environ.get('CC', 'cc'))
    binary = d / 'controls'
    subprocess.run(cc + ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                        '-fno-omit-frame-pointer', str(c), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=20)
    marker_c = d / 'capability.c'
    marker_c.write_text(stage.CONTRACT)
    marker_asm = d / 'capability.s'
    subprocess.run(cc + ['-std=c11', '-O2', '-S', str(marker_c), '-o', str(marker_asm)], check=True)
    assembly = marker_asm.read_text()
    assert stage.CAPABILITY in assembly
    if os.uname().sysname == 'Darwin':
        assert '.no_dead_strip' in assembly and '_madeira_socket_control_contract' in assembly
    old = d / 'old.c'
    old.write_text(SOURCE)
    out = d / 'staged.c'
    subprocess.run(['python3', str(ROOT / 'tools/build/stage-ios-socket-control.py'),
                    '--source', str(old), '--output', str(out)], check=True)
    assert old.read_text() == SOURCE and out.read_text() == AFTER
assert SOURCE_PATH.read_text() == SOURCE
error_spec = importlib.util.spec_from_file_location('socket_errno_overlay', ROOT / 'tools/build/stage-ios-socket-errors.py')
error_stage = importlib.util.module_from_spec(error_spec)
error_spec.loader.exec_module(error_stage)
error_source = error_stage.stage_source(SOURCE, ROOT / 'build/ntdll-unix/socket_error_context.h')
composed = stage.stage_source(error_source)
assert composed.count(stage.CAPABILITY) == 1
rest, original_rest = composed.replace(stage.CONTRACT, ''), error_source
for name in (stage.BEGIN, stage.NATIVE_BEGIN):
    rest = rest.replace(function(composed, name), 'OWNED_FUNCTION')
    original_rest = original_rest.replace(function(error_source, name), 'OWNED_FUNCTION')
assert rest == original_rest
print('PASS native errno -> ancillary staging composition; exact compiled capability retained, no errno overlay/async changes')
for bad in (AFTER, SOURCE.replace('cmsg32->cmsg_type = cmsg64->cmsg_type;', 'cmsg32->cmsg_type = 0;')):
    try:
        stage.stage_source(bad)
    except ValueError:
        pass
    else:
        raise AssertionError('changed/double-staged control conversion accepted')
assert AFTER.count(stage.CAPABILITY) == 1 and stage.CONTRACT in AFTER
old_rest, new_rest = SOURCE, AFTER.replace(stage.CONTRACT, '')
for name in (stage.BEGIN, stage.NATIVE_BEGIN):
    old_rest = old_rest.replace(function(SOURCE, name), 'OWNED_FUNCTION')
    new_rest = new_rest.replace(function(AFTER, name), 'OWNED_FUNCTION')
assert old_rest == new_rest
print('PASS immutable pinned vendor input, exact prior-function hashes, fail-closed staging, unchanged receive/async/packet paths outside the two ancillary converters')
