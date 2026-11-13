#!/usr/bin/env python3
"""Execute the original/staged BSD IPv4 parser; no relay reachability claim.

Only sysctl, LUID lookup and public scalar declarations are host fixtures.
The actual route-row structures, producer and fill routine execute verbatim.
Darwin additionally enumerates its real kernel routing table without traffic.
"""
from pathlib import Path
import hashlib
import importlib.util
import os
import platform
import re
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ios_route_stage', ROOT / 'tools/build/stage-ios-route-table.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
path = ROOT / 'wine/dlls/nsiproxy.sys/ip.c'
original = path.read_text()
changed = stage.stage(original)
assert hashlib.sha256(original.encode()).hexdigest() == stage.PIN
assert changed[:changed.index(stage.START)] == original[:original.index(stage.START)]
assert changed[changed.index(stage.END, changed.index(stage.START)):] == original[original.index(stage.END, original.index(stage.START)):]
for bad in (original + '\n', changed):
    try: stage.stage(bad)
    except ValueError: pass
    else: raise AssertionError('modified/stale source must fail closed')


def actual_parser(source):
    start = source.index('struct ipv4_route_data\n')
    end = source.index('\n#ifdef __linux__\nstruct ipv6_route_data', start)
    return source[start:end]


nsi = (ROOT / 'wine/include/wine/nsi.h').read_text()
rows = '\n'.join(re.search(r'struct ' + name + r'\n\{.*?\n\};', nsi, re.S)[0]
                 for name in ('nsi_ipv4_forward_key', 'nsi_ip_forward_rw', 'nsi_ipv4_forward_dynamic', 'nsi_ip_forward_static'))
PRE = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef REAL_BSD
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#else
typedef unsigned char sa_family_t;
struct in_addr { uint32_t s_addr; };
struct sockaddr { unsigned char sa_len,sa_family; char data[14]; };
struct sockaddr_in { unsigned char sin_len,sin_family; uint16_t sin_port; struct in_addr sin_addr; char zero[8]; };
#define AF_UNSPEC 0
#define AF_INET 2
#define AF_LINK 18
#define PF_INET AF_INET
#define PF_ROUTE 17
#define CTL_NET 4
#define NET_RT_DUMP 1
#include "route.h"
#ifndef RTF_HOST
#define RTF_HOST 0x4
#endif
static uint32_t htonl(uint32_t x) { return __BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__?__builtin_bswap32(x):x; }
static uint32_t ntohl(uint32_t x) { return htonl(x); }
static int sysctl(const int*,unsigned,void*,size_t*,const void*,size_t);
#endif
#undef __linux__
#define HAVE_SYS_SYSCTL_H 1
#define TRUE 1
#define FALSE 0
#define TRACE(...) ((void)0)
#define WARN(...) ((void)0)
#define ERR(...) ((void)0)
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(*(x)))
#define C_ASSERT(x) _Static_assert(x,#x)
#define STATUS_SUCCESS ((int32_t)0)
#define STATUS_NOT_SUPPORTED ((int32_t)0xc00000bb)
#define STATUS_NO_MEMORY ((int32_t)0xc0000017)
#define STATUS_BUFFER_OVERFLOW ((int32_t)0x80000005)
#define STATUS_DATA_ERROR ((int32_t)0xc000003e)
typedef int BOOL;
typedef int32_t NTSTATUS;
typedef unsigned char BYTE;
typedef uint32_t UINT;
typedef uintptr_t UINT_PTR;
typedef struct { uint32_t WS_s_addr; } IN_ADDR;
typedef union { uint64_t Value;struct { uint64_t Reserved:24,NetLuidIndex:24,IfType:16; } Info; } NET_LUID;
#define MIB_IF_TYPE_LOOPBACK 24
#define MIB_IPPROTO_NETMGMT 3
#define MIB_IPPROTO_LOCAL 2
#define NlroManual 0
static BOOL convert_index_to_luid(UINT index,NET_LUID *luid) {
 memset(luid,0,sizeof *luid);luid->Info.NetLuidIndex=index;
#ifdef REAL_BSD
 char name[IF_NAMESIZE];if(!if_indextoname(index,name))return FALSE;
 luid->Info.IfType=!strncmp(name,"lo",2)?MIB_IF_TYPE_LOOPBACK:6;
#else
 if(index==999)return FALSE;luid->Info.IfType=index==1?MIB_IF_TYPE_LOOPBACK:6;
#endif
 return TRUE;
}
static UINT mask_v4_to_prefix(struct in_addr *addr) { return __builtin_popcount(addr->s_addr); }
'''
FIXTURE = r'''
_Alignas(struct rt_msghdr) static unsigned char snapshot[8192];static size_t used;static int query_failure;
static int sysctl(const int *mib,unsigned n,void *out,size_t *len,const void *input,size_t inlen) {
 assert(n==6&&mib[0]==CTL_NET&&mib[1]==PF_ROUTE&&mib[3]==PF_INET&&mib[4]==NET_RT_DUMP);
 assert(!input&&!inlen);if(query_failure)return -1;
 if(!out){*len=used;return 0;}assert(*len>=used);memcpy(out,snapshot,used);*len=used;return 0;
}
static void append_addr(unsigned char *p,size_t *n,uint32_t ip,unsigned family,unsigned bytes) {
 struct sockaddr_in sa={0};sa.sin_len=bytes;sa.sin_family=family;sa.sin_addr.s_addr=htonl(ip);
 size_t step=bytes?(bytes+3)&~3u:4;memset(p+*n,0,step);memcpy(p+*n,&sa,bytes?bytes:2);*n+=step;
}
static size_t route(unsigned index,unsigned flags,uint32_t dest,int mask_bits,int gw_family,uint32_t gateway) {
 size_t at=used,n=sizeof(struct rt_msghdr);struct rt_msghdr *m=(void*)(snapshot+at);
 memset(m,0,sizeof *m);m->rtm_type=RTM_GET;m->rtm_index=index;m->rtm_flags=flags;
 m->rtm_addrs=RTA_DST;append_addr(snapshot+at,&n,dest,AF_INET,16);
 if(gw_family>=0){m->rtm_addrs|=RTA_GATEWAY;append_addr(snapshot+at,&n,gateway,gw_family,16);}
 if(mask_bits>=0){m->rtm_addrs|=RTA_NETMASK;uint32_t mask=mask_bits?~0u<<(32-mask_bits):0;
   unsigned bytes=mask_bits?4+(mask_bits+7)/8:0;append_addr(snapshot+at,&n,mask,255,bytes);}
 m->rtm_msglen=n;used+=n;return at;
}
static struct nsi_ipv4_forward_key keys[16];
static struct nsi_ip_forward_rw rw[16];
static struct nsi_ipv4_forward_dynamic dyn[16];
static struct nsi_ip_forward_static stat[16];
static NTSTATUS call(UINT_PTR *count,int data) {
 memset(keys,0xcc,sizeof keys);memset(rw,0xcc,sizeof rw);memset(dyn,0xcc,sizeof dyn);memset(stat,0xcc,sizeof stat);
 return ipv4_forward_enumerate_all(data?keys:0,data?sizeof *keys:0,data?rw:0,data?sizeof *rw:0,
   data?dyn:0,data?sizeof *dyn:0,data?stat:0,data?sizeof *stat:0,count);
}
int main(void) {
 UINT_PTR count;used=0;
 route(2,RTF_GATEWAY,0,0,AF_INET,0xc0000201);
 route(2,RTF_GATEWAY,0x64400000,10,AF_INET,0xc0000202);
 route(2,RTF_HOST,0xcb007104,-1,-1,0);
 route(1,RTF_HOST,0x7f000001,-1,AF_LINK,0);
 route(2,0,0xc0000200,24,AF_LINK,0);
 route(35,RTF_GATEWAY,0,0,AF_INET,0x0a070001); /* retain legitimate tunnel routes */
 count=16;assert(call(&count,1)==STATUS_SUCCESS&&count==6);
#if OLD_PARSER
 assert(keys[2].prefix_len==10&&keys[2].next_hop.WS_s_addr==htonl(0xc0000202));
 assert(rw[2].loopback!=0&&rw[3].loopback!=1);
 puts("BEFORE reproduced actual BSD parser: host inherited /10 and prior gateway; uninitialized loopback under compiler poison");
 return 0;
#else
 assert(keys[0].prefix_len==0&&keys[0].next_hop.WS_s_addr==htonl(0xc0000201));
 assert(keys[1].prefix_len==10&&keys[2].prefix_len==32&&keys[3].prefix_len==32&&keys[4].prefix_len==24);
 assert(!keys[2].next_hop.WS_s_addr&&!keys[3].next_hop.WS_s_addr&&!keys[4].next_hop.WS_s_addr);
 for(unsigned i=0;i<count;++i)assert(rw[i].loopback==(i==3));
 assert(stat[5].if_index==35&&keys[5].next_hop.WS_s_addr==htonl(0x0a070001));
 for(unsigned i=0;i<count;++i)assert(!memcmp(&dyn[i],&(struct nsi_ipv4_forward_dynamic){0},sizeof dyn[i]));
 count=0;assert(call(&count,0)==STATUS_SUCCESS&&count==6);
 count=2;assert(call(&count,1)==STATUS_BUFFER_OVERFLOW&&count==2&&keys[1].prefix_len==10);
 used=0;count=16;assert(call(&count,1)==STATUS_SUCCESS&&!count);
 query_failure=1;count=16;assert(call(&count,1)==STATUS_NOT_SUPPORTED&&count==16);query_failure=0;
 // A host bit is authoritative even with an explicit zero mask.
 used=0;route(2,RTF_HOST,0xcb007105,0,-1,0);count=16;assert(call(&count,1)==STATUS_SUCCESS&&count==1&&keys[0].prefix_len==32);
 // A missing network mask must not invent /0 for a non-default destination.
 used=0;route(2,0,0xc0000200,-1,-1,0);count=16;assert(call(&count,1)==STATUS_SUCCESS&&!count);
 used=0;route(2,RTF_GATEWAY,0,0,-1,0);count=16;assert(call(&count,1)==STATUS_SUCCESS&&!count);
 used=0;route(999,0,0,0,-1,0);count=16;assert(call(&count,1)==STATUS_SUCCESS&&!count);
 // Malformed kernel snapshots fail honestly without overflow or loops.
 for(unsigned mode=0;mode<8;++mode) {
  used=0;route(2,RTF_GATEWAY,0,0,AF_INET,0xc0000201);struct rt_msghdr *m=(void*)snapshot;
  if(mode==0)m->rtm_msglen=0;
  if(mode==1)m->rtm_msglen=sizeof *m-1;
  if(mode==2)m->rtm_msglen=used+4;
  if(mode==3)used=sizeof *m-1;
  if(mode==4)((struct sockaddr*)(snapshot+sizeof *m))->sa_len=255;
  if(mode==5){m->rtm_msglen=sizeof *m+1;used=m->rtm_msglen;}
  if(mode==6)((struct sockaddr*)(snapshot+sizeof *m))->sa_len=1;
  if(mode==7){route(2,RTF_HOST,0xcb007105,-1,-1,0);m->rtm_msglen++;}
  count=16;assert(call(&count,1)==STATUS_DATA_ERROR&&count==16);
 }
 puts("PASS actual staged BSD IPv4 parser: per-row ownership, host /32, compact/default masks, loopback, on-link gateway, tunnel preservation, short/count buffers, malformed snapshots and real failure propagation");
#endif
}
'''
NATIVE = r'''
int main(void) {
 UINT_PTR count=0;NTSTATUS status=ipv4_forward_enumerate_all(0,0,0,0,0,0,0,0,&count);
 if(status==STATUS_NOT_SUPPORTED){puts("SKIP real BSD route snapshot: host kernel query unavailable");return 0;}
 assert(status==STATUS_SUCCESS);UINT_PTR capacity=count;
 struct nsi_ipv4_forward_key *keys=calloc(count?count:1,sizeof *keys);
 struct nsi_ip_forward_rw *rw=calloc(count?count:1,sizeof *rw);
 struct nsi_ip_forward_static *stat=calloc(count?count:1,sizeof *stat);
 assert(keys&&rw&&stat);status=ipv4_forward_enumerate_all(keys,sizeof *keys,rw,sizeof *rw,0,0,stat,sizeof *stat,&count);
 if(status==STATUS_BUFFER_OVERFLOW){puts("SKIP real BSD route consistency: table grew between snapshots");return 0;}
 assert(status==STATUS_SUCCESS&&count<=capacity);
 for(unsigned i=0;i<count;++i){assert(keys[i].prefix_len<=32&&rw[i].loopback<=1&&stat[i].if_index);}
 printf("PASS actual staged parser queried real Darwin kernel: %llu IPv4 routes, bounded valid rows; no packets sent or endpoints exported\n",(unsigned long long)count);
 free(keys);free(rw);free(stat);return 0;
}
'''

cc = shlex.split(os.environ.get('CC', 'cc'))
if not shutil.which(cc[0]):
    cc = [str(Path('/tmp/llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64/bin/clang'))]
version = subprocess.check_output(cc + ['--version'], text=True)
flags = ['-std=gnu11', '-O2', '-ftrivial-auto-var-init=pattern']
if 'clang' not in version.lower():
    flags += ['-Wno-stringop-overflow']
with tempfile.TemporaryDirectory(prefix='madeira-bsd-routes-') as directory:
    d = Path(directory)
    shutil.copyfile(ROOT / 'build/ntdll-unix/shims/net/route.h', d / 'route.h')
    for label, source in (('before', original), ('after', changed)):
        file = d / (label + '.c')
        file.write_text(PRE + rows + actual_parser(source) + FIXTURE)
        binary = d / label
        subprocess.run(cc + flags + ['-I' + str(d), '-DOLD_PARSER=' + str(int(label == 'before')), str(file), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=10)
    # Exercise the exact new parser with memory/undefined-behavior sanitizers.
    if 'clang' not in version.lower() or platform.system() == 'Darwin':
        binary = d / 'sanitized'
        subprocess.run(cc + flags + ['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I' + str(d),
                                    '-DOLD_PARSER=0', str(d / 'after.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=10)
    if platform.system() == 'Darwin':
        file = d / 'native.c';file.write_text(PRE + rows + actual_parser(changed) + NATIVE)
        binary = d / 'native'
        subprocess.run(cc + ['-std=gnu11','-O2','-DREAL_BSD=1',str(file),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True,timeout=10)
    else: print('SKIP real Darwin route query: non-Darwin host; actual fixture parser tests do not establish iPhone routing')
assert path.read_text() == original
print('PASS pinned provider stays byte-identical; modified/restaged source fails closed; no family/interface policy forcing')
