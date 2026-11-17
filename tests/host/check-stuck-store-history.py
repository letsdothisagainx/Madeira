#!/usr/bin/env python3
"""Actual crossing-store check coverage; native Mach API adapters, no stores completed.

This tests identity bookkeeping and unchanged selection/control flow, not a
Darwin kernel pathology, iPhone frames, or an instruction-splitting workaround.
"""
from pathlib import Path
import argparse, hashlib, os, subprocess, tempfile
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--sanitize",action="store_true")
options=parser.parse_args()
ROOT=Path(__file__).resolve().parents[2]
BASELINE = r'''#define ML1288_SLOTS 64
static struct { uint64_t tid, pc, ea, seen_ms; uint32_t sys_ms, hits; } ios_stuck[ML1288_SLOTS];
static int ios_stuck_logs;
static unsigned long long ios_stuck_fixed;

/* Effective address and size of the load/store at insn (A64), 0 if not one. */
static int ios_ldst_ea( uint32_t insn, const arm_thread_state64_t *st, uint64_t *ea, unsigned *len )
{
    unsigned rn = (insn >> 5) & 31, size = insn >> 30, v = (insn >> 26) & 1, opc = (insn >> 22) & 3;
    unsigned scale = v ? (size | ((opc & 2) << 1)) : size;
    uint64_t base = rn == 31 ? arm_thread_state64_get_sp( *st ) : st->__x[rn];

    if ((insn & 0x3b000000u) == 0x39000000u)            /* LDR/STR, unsigned immediate */
    {
        *ea = base + ((uint64_t)((insn >> 10) & 0xfff) << scale); *len = 1u << scale; return 1;
    }
    if ((insn & 0x3b200c00u) == 0x38200800u)            /* LDR/STR, register offset */
    {
        unsigned rm = (insn >> 16) & 31, option = (insn >> 13) & 7, s = (insn >> 12) & 1;
        uint64_t m = rm == 31 ? 0 : st->__x[rm];
        if (option == 2) m = (uint32_t)m;
        else if (option == 6) m = (uint64_t)(int64_t)(int32_t)m;
        *ea = base + (m << (s ? scale : 0)); *len = 1u << scale; return 1;
    }
    if ((insn & 0x3b200000u) == 0x38000000u)            /* LDUR/STUR, pre/post-index */
    {
        int64_t imm9 = ((int64_t)((insn >> 12) & 0x1ff) << 55) >> 55;
        *ea = ((insn >> 10) & 3) == 1 ? base : base + imm9; *len = 1u << scale; return 1;
    }
    if ((insn & 0x3a000000u) == 0x28000000u)            /* LDP/STP */
    {
        unsigned psc = v ? 2 + (insn >> 30) : 2 + (insn >> 31);
        int64_t imm7 = ((int64_t)((insn >> 15) & 0x7f) << 57) >> 57;
        *ea = ((insn >> 23) & 3) == 1 ? base : base + (imm7 << psc); *len = 2u << psc; return 1;
    }
    if ((insn & 0x3f200c00u) == 0x19000000u)            /* LDAPUR/STLUR */
    {
        int64_t imm9 = ((int64_t)((insn >> 12) & 0x1ff) << 55) >> 55;
        *ea = base + imm9; *len = 1u << size; return 1;
    }
    if ((insn & 0x3f000000u) == 0x08000000u)            /* LDAR/STLR/LDXR family */
    {
        *ea = base; *len = 1u << size; return 1;
    }
    return 0;
}

int ios_store_split_crossing( uint32_t insn, arm_thread_state64_t *st, const arm_neon_state64_t *neon,
                              uintptr_t rx, uintptr_t rw, size_t sz );   /* ml1289, signal_arm64_ios.c */

static void ios_stuck_store_check( void )
{
    extern void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
    extern size_t ios_jit_pool_size_global;
    mach_port_t self_port = pthread_mach_thread_np( pthread_self() );
    thread_act_array_t tl;
    mach_msg_type_number_t tc;
    struct timespec ts;
    uint64_t now;
    unsigned k;

    clock_gettime( CLOCK_MONOTONIC, &ts );
    now = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
    if (task_threads( mach_task_self(), &tl, &tc ) != KERN_SUCCESS) return;
    for (k = 0; k < tc; k++)
    {
        thread_basic_info_data_t bi;
        thread_identifier_info_data_t idi;
        arm_thread_state64_t st;
        arm_neon_state64_t neon;
        mach_msg_type_number_t bic = THREAD_BASIC_INFO_COUNT, idc = THREAD_IDENTIFIER_INFO_COUNT,
                               cnt = ARM_THREAD_STATE64_COUNT, nc = ARM_NEON_STATE64_COUNT;
        uint64_t pc, bb = 0, ea = 0, dt;
        uint32_t insn = 0, sys, dsys;
        unsigned len = 0, slot, i;
        int got, have_neon, cross;

        if (tl[k] == self_port) continue;
        if (thread_info( tl[k], THREAD_BASIC_INFO, (thread_info_t)&bi, &bic ) != KERN_SUCCESS) continue;
        if (thread_info( tl[k], THREAD_IDENTIFIER_INFO, (thread_info_t)&idi, &idc ) != KERN_SUCCESS) continue;
        sys = bi.system_time.seconds * 1000 + bi.system_time.microseconds / 1000;

        for (slot = 0; slot < ML1288_SLOTS; slot++) if (ios_stuck[slot].tid == idi.thread_id) break;
        if (slot == ML1288_SLOTS)
        {
            for (slot = 0, i = 1; i < ML1288_SLOTS; i++)   /* a free slot, else the longest unseen */
                if (ios_stuck[i].seen_ms < ios_stuck[slot].seen_ms) slot = i;
            ios_stuck[slot].tid = idi.thread_id; ios_stuck[slot].seen_ms = now;
            ios_stuck[slot].sys_ms = sys;
            ios_stuck[slot].pc = 0; ios_stuck[slot].hits = 0;
            continue;
        }
        dt = now - ios_stuck[slot].seen_ms;
        dsys = sys - ios_stuck[slot].sys_ms;
        ios_stuck[slot].seen_ms = now; ios_stuck[slot].sys_ms = sys;
        if (bi.run_state != TH_STATE_RUNNING || !dt || (uint64_t)dsys * 10 < dt * 6)
        {
            ios_stuck[slot].pc = 0; ios_stuck[slot].hits = 0;
            continue;
        }

        /* kernel-bound: read it */
        if (thread_suspend( tl[k] ) != KERN_SUCCESS) continue;
        got = thread_get_state( tl[k], ARM_THREAD_STATE64, (thread_state_t)&st, &cnt ) == KERN_SUCCESS;
        have_neon = thread_get_state( tl[k], ARM_NEON_STATE64, (thread_state_t)&neon, &nc ) == KERN_SUCCESS;
        if (!got || !ios_ts_read( st.__x[28], &bb, 8 ) || bb <= 0x10000)   /* not in FEX state */
        {
            thread_resume( tl[k] );
            continue;
        }
        pc = arm_thread_state64_get_pc( st );
        cross = ios_ts_read( pc, &insn, 4 ) && ios_ldst_ea( insn, &st, &ea, &len ) &&
                ((ea ^ (ea + len - 1)) & ~(uint64_t)(vm_page_size - 1));
        if (cross && ios_stuck[slot].pc == pc && ios_stuck[slot].ea == ea)
        {
            unsigned hits = ++ios_stuck[slot].hits;
            int r = ios_store_split_crossing( insn, &st, have_neon ? &neon : NULL,
                                              (uintptr_t)ios_jit_rx_base_global, (uintptr_t)ios_jit_rw_base_global,
                                              ios_jit_pool_size_global );
            if (r > 0)
            {
                __darwin_arm_thread_state64_set_pc_fptr( st, (void *)(uintptr_t)(pc + 4) );
                if (thread_set_state( tl[k], ARM_THREAD_STATE64, (thread_state_t)&st, ARM_THREAD_STATE64_COUNT ) != KERN_SUCCESS)
                    r = -2;   /* the store is written, pc not moved: the thread redoes the same bytes */
                else
                    ios_stuck_fixed++;
            }
            thread_resume( tl[k] );
            if (ios_stuck_logs < 400 && (r > 0 || hits <= 3 || hits % 10 == 0))
            {
                ios_stuck_logs++;
                wine_log_write( "[stuck-store] ml1292 tid=%llu hits=%u pc=0x%llx insn=%08x ea=0x%llx len=%u "
                                "sys+%u ms in %llu ms: %s (%llu completed so far)",
                                (unsigned long long)idi.thread_id, hits, (unsigned long long)pc, insn,
                                (unsigned long long)ea, len, dsys, (unsigned long long)dt,
                                r > 0 ? "completed, pc+4" : r == -2 ? "written, set_state FAILED"
                                : r < 0 ? "refused (a page not writable)" : "not a store it decodes", ios_stuck_fixed );
            }
            if (r > 0) { ios_stuck[slot].pc = 0; ios_stuck[slot].hits = 0; }
        }
        else
        {
            thread_resume( tl[k] );
            ios_stuck[slot].pc = cross ? pc : 0;
            ios_stuck[slot].ea = cross ? ea : 0;
        }
    }
    for (k = 0; k < tc; k++) mach_port_deallocate( mach_task_self(), tl[k] );
    vm_deallocate( mach_task_self(), (vm_address_t)tl, tc * sizeof(*tl) );
}
'''
assert hashlib.sha256(BASELINE.encode()).hexdigest()=='45239250f063bc32a4f3714641c3b5c8f7c4df3d8f982ccf385b8b29a3cc5885'
PREFIX = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
typedef uintptr_t pthread_t;
static pthread_t fixture_pthread_self(void){return 1;}
#define pthread_self fixture_pthread_self
#include <assert.h>
#include <stdlib.h>
typedef unsigned mach_port_t,thread_t,thread_act_t,mach_msg_type_number_t,kern_return_t;
typedef uintptr_t vm_address_t,mach_vm_address_t;
typedef size_t mach_vm_size_t;
typedef unsigned *thread_act_array_t;
typedef void *thread_info_t,*thread_state_t;
typedef struct {int seconds,microseconds;} time_value;
typedef struct {time_value system_time;unsigned run_state;} thread_basic_info_data_t;
typedef struct {uint64_t thread_id;} thread_identifier_info_data_t;
typedef struct {uint64_t __x[29],__sp,__lr,__fp,__pc;} arm_thread_state64_t;
typedef struct {unsigned char x[512];} arm_neon_state64_t;
#define THREAD_BASIC_INFO_COUNT 1
#define THREAD_IDENTIFIER_INFO_COUNT 1
#define ARM_THREAD_STATE64_COUNT 1
#define ARM_NEON_STATE64_COUNT 1
#define THREAD_BASIC_INFO 1
#define THREAD_IDENTIFIER_INFO 2
#define ARM_THREAD_STATE64 1
#define ARM_NEON_STATE64 2
#define TH_STATE_RUNNING 1
#define KERN_SUCCESS 0
#define arm_thread_state64_get_pc(s) ((s).__pc)
#define arm_thread_state64_get_sp(s) ((s).__sp)
#ifdef __darwin_arm_thread_state64_set_pc_fptr
#undef __darwin_arm_thread_state64_set_pc_fptr
#endif
#define __darwin_arm_thread_state64_set_pc_fptr(s,p) ((s).__pc=(uintptr_t)(p))
static unsigned thread_n,generation,ids[8192],native_ids[8192],helper_calls[8192],suspends[8192],current_port;
static int allocation_failure;
static unsigned fixture_system_ms=100,fixture_run_state=TH_STATE_RUNNING,fixture_state_sets;
static unsigned fail_suspend_generation,fail_state_generation,fail_fex_generation;
static void *history_calloc(size_t n,size_t z){if(allocation_failure)return NULL;return calloc(n,z);}
#define IOS_STUCK_HISTORY_CALLOC history_calloc
#ifndef BASELINE
#include "stuck_store_history.h"
#endif
static const uint64_t test_pc=0x7c30000000ull;
static size_t vm_page_size=16384;
void *ios_jit_rx_base_global,*ios_jit_rw_base_global;
size_t ios_jit_pool_size_global;
static mach_port_t pthread_mach_thread_np(pthread_t t){(void)t;return 0;}
static mach_port_t mach_task_self(void){return 1;}
static int task_threads(unsigned t,thread_act_array_t *out,unsigned *n){(void)t;*out=ids;*n=thread_n;return 0;}
static int thread_info(unsigned t,unsigned flavor,void *out,unsigned *n){(void)n;
 if(flavor==THREAD_BASIC_INFO){thread_basic_info_data_t *p=out;p->system_time.seconds=0;p->system_time.microseconds=generation*fixture_system_ms*1000;p->run_state=fixture_run_state;}
 else ((thread_identifier_info_data_t*)out)->thread_id=native_ids[t]?native_ids[t]:t;
 return 0;}
static int thread_suspend(unsigned t){suspends[t]++;current_port=t;if(t==1&&generation==fail_suspend_generation)return 1;return 0;}
static int thread_resume(unsigned t){(void)t;return 0;}
static int thread_get_state(unsigned t,unsigned flavor,void *out,unsigned *n){(void)n;
 if(t==1&&generation==fail_state_generation&&flavor==ARM_THREAD_STATE64)return 1;
 if(flavor==ARM_THREAD_STATE64){arm_thread_state64_t *p=out;memset(p,0,sizeof(*p));p->__pc=test_pc;p->__x[28]=0x10000;p->__x[8]=0x1ffec;}
 return 0;}
static int thread_set_state(unsigned t,unsigned f,void *out,unsigned n){(void)t;(void)f;(void)out;(void)n;fixture_state_sets++;return 0;}
static int mach_port_deallocate(unsigned t,unsigned p){(void)t;(void)p;return 0;}
static int vm_deallocate(unsigned t,uintptr_t a,size_t n){(void)t;(void)a;(void)n;return 0;}
static int ios_ts_read(uint64_t a,void *out,size_t n){if(a==0x10000&&n==8){if(current_port==1&&generation==fail_fex_generation)return 0;*(uint64_t*)out=0x20000;return 1;}if(a==test_pc&&n==4){*(uint32_t*)out=0x3d800500;return 1;}return 0;}
static void wine_log_write(const char *fmt,...) __attribute__((format(printf,1,2)));
static void wine_log_write(const char *fmt,...){(void)fmt;}
static int fixture_clock_gettime(clockid_t id,struct timespec *t){(void)id;t->tv_sec=generation/10;t->tv_nsec=(generation%10)*100000000;return 0;}
#define clock_gettime fixture_clock_gettime
'''
SUFFIX = r'''
/* Deliberately refuse completion: this fixture tests selection/history only.
 * No guest bytes or instruction pointers are advanced by the adapter. */
int ios_store_split_crossing(uint32_t i,arm_thread_state64_t *s,const arm_neon_state64_t *n,uintptr_t rx,uintptr_t rw,size_t z)
{(void)i;(void)s;(void)n;(void)rx;(void)rw;(void)z;helper_calls[current_port]++;return 0;}
static void reset(unsigned n)
{
#ifdef BASELINE
 memset(&ios_stuck,0,sizeof(ios_stuck));
#else
 ios_stuck_history_destroy(&ios_stuck);
#endif
 thread_n=n;generation=0;allocation_failure=0;fixture_system_ms=100;fixture_run_state=TH_STATE_RUNNING;fixture_state_sets=0;fail_suspend_generation=fail_state_generation=fail_fex_generation=0;
 memset(suspends,0,sizeof(suspends));memset(helper_calls,0,sizeof(helper_calls));memset(native_ids,0,sizeof(native_ids));
 for(unsigned i=0;i<n;i++)ids[i]=i+1;
}
static void pass(void){generation++;ios_stuck_store_check();}
static void stable(unsigned n)
{
 reset(n);for(unsigned i=0;i<5;i++)pass();
 unsigned observed=0;for(unsigned i=1;i<=n;i++)if(helper_calls[i])observed++;
#ifdef BASELINE
 assert(observed==(n==64?64u:63u));if(n>64)assert(!suspends[n]&&!helper_calls[n]);
#else
 assert(observed==n);for(unsigned i=1;i<=n;i++)assert(helper_calls[i]==3&&suspends[i]==4);
#endif
 printf("actual check: threads=%u candidate-identities=%u last-thread-candidates=%u\n",n,observed,helper_calls[n]);
}
#ifndef BASELINE
static void churn(void)
{
 reset(200);pass();pass();pass();
 for(unsigned i=151;i<=200;i++)native_ids[i]=10000+i;
 pass();for(unsigned i=151;i<=200;i++)assert(helper_calls[i]==1);
 pass();for(unsigned i=151;i<=200;i++)assert(helper_calls[i]==1);
 pass();for(unsigned i=151;i<=200;i++)assert(helper_calls[i]==2);
 thread_n=150;pass();
 assert(ios_stuck.tables[ios_stuck.current].count==150);
 for(unsigned i=151;i<=200;i++)assert(!ios_stuck_history_find(&ios_stuck.tables[ios_stuck.current],10000+i));
 thread_n=200;for(unsigned i=151;i<=200;i++)native_ids[i]=20000+i;
 pass();pass();for(unsigned i=151;i<=200;i++)assert(helper_calls[i]==2);
 pass();for(unsigned i=151;i<=200;i++)assert(helper_calls[i]==3);
 puts("PASS native-identifier churn, recyclable port names, late-thread coverage and removal of absent identities");
}
static void failures(void)
{
 reset(200);allocation_failure=1;pass();pass();
 for(unsigned i=1;i<=200;i++)assert(!suspends[i]&&!helper_calls[i]);
 allocation_failure=0;pass();allocation_failure=1;pass();
 for(unsigned i=1;i<=200;i++)assert(!suspends[i]&&!helper_calls[i]);
 allocation_failure=0;pass();pass();pass();
 for(unsigned i=1;i<=200;i++)assert(helper_calls[i]==1);
 reset(IOS_STUCK_HISTORY_MAX_THREADS+1);pass();pass();pass();
 for(unsigned i=1;i<=thread_n;i++)assert(!suspends[i]&&!helper_calls[i]);
 reset(0);pass();assert(!ios_stuck.tables[ios_stuck.current].count);
 assert(2*8192*sizeof(struct ios_stuck_entry)<1048576);
 puts("PASS allocation failures/oversized snapshots decline before suspension; empty snapshots retire history; bounded storage");
}
static void failure_gaps(void)
{
 for(unsigned mode=0;mode<3;mode++){
  reset(1);pass();pass();
  if(mode==0)fail_suspend_generation=3;
  if(mode==1)fail_state_generation=3;
  if(mode==2)fail_fex_generation=3;
  pass();pass();assert(!helper_calls[1]);pass();assert(helper_calls[1]==1);
 }
 puts("PASS failed suspend/context/FEX reads invalidate prior PC/EA; two valid observations required again");
}
static void cpu_gates(void)
{
 for(unsigned mode=0;mode<3;mode++){
  reset(200);
  if(mode==0)fixture_system_ms=0;
  if(mode==1)fixture_system_ms=59;
  if(mode==2)fixture_run_state=2;
  for(unsigned i=0;i<5;i++)pass();
  for(unsigned i=1;i<=200;i++)assert(!suspends[i]&&!helper_calls[i]);
  assert(!fixture_state_sets);
 }
 reset(200);fixture_system_ms=60;for(unsigned i=0;i<5;i++)pass();
 for(unsigned i=1;i<=200;i++)assert(helper_calls[i]==3&&suspends[i]==4);
 assert(!fixture_state_sets); /* Refusal adapter never completes a store. */
 puts("PASS unchanged RUNNING/60% system gate: user-only/59%/waiting threads never suspended or advanced");
}
static void counters(void)
{
 struct ios_stuck_history h={0};struct ios_stuck_entry *e;uint64_t dt,ds;
 assert(ios_stuck_history_begin(&h,1));e=ios_stuck_history_observe(&h,1,100,UINT64_C(4294967290),&dt,&ds);assert(e&&!dt&&!ds);e->pc=123;e->ea=456;e->hits=7;ios_stuck_history_end(&h);
 assert(ios_stuck_history_begin(&h,1));e=ios_stuck_history_observe(&h,1,200,UINT64_C(4294967390),&dt,&ds);assert(e&&dt==100&&ds==100&&e->pc==123);assert(!ios_stuck_history_observe(&h,1,200,0,&dt,&ds));ios_stuck_history_end(&h);
 assert(ios_stuck_history_begin(&h,1));e=ios_stuck_history_observe(&h,1,199,UINT64_C(4294967490),&dt,&ds);assert(e&&!dt&&!ds&&!e->pc&&!e->hits);e->pc=123;ios_stuck_history_end(&h);
 assert(ios_stuck_history_begin(&h,1));e=ios_stuck_history_observe(&h,1,300,0,&dt,&ds);assert(e&&!dt&&!ds&&!e->pc);e->pc=123;ios_stuck_history_end(&h);
 assert(ios_stuck_history_begin(&h,1));e=ios_stuck_history_observe(&h,1,300,0,&dt,&ds);assert(e&&!dt&&!ds&&!e->pc);ios_stuck_history_end(&h);
 assert(ios_stuck_history_begin(&h,1));assert(!ios_stuck_history_observe(&h,0,400,100,&dt,&ds));ios_stuck_history_end(&h);
 ios_stuck_history_destroy(&h);
 puts("PASS 64-bit CPU counter carry, regressing/zero timestamps and CPU counters, duplicate/invalid native identities");
}
static void decoder(void)
{
 arm_thread_state64_t s={0};uint64_t ea;unsigned n;s.__x[8]=0x1ffec;s.__fp=0x30000;s.__lr=0x40000;s.__sp=0x50000;
 assert(ios_ldst_ea(0x3d800500,&s,&ea,&n)&&ea==0x1fffc&&n==16);
 uint32_t pre=0x3c800c00u|(0x1f0u<<12)|(8u<<5);assert(ios_ldst_ea(pre,&s,&ea,&n)&&ea==s.__x[8]-16&&n==16);
 uint32_t post=0x3c800400u|(0x1f0u<<12)|(8u<<5);assert(ios_ldst_ea(post,&s,&ea,&n)&&ea==s.__x[8]&&n==16);
 uint32_t pair=0xad800000u|(126u<<15)|(1u<<10)|(29u<<5);assert(ios_ldst_ea(pair,&s,&ea,&n)&&ea==s.__fp-32&&n==32);
 uint32_t pairpost=(pair&~(3u<<23))|(1u<<23);assert(ios_ldst_ea(pairpost,&s,&ea,&n)&&ea==s.__fp&&n==32);
 uint32_t lr=0x3d800400u|(30u<<5);assert(ios_ldst_ea(lr,&s,&ea,&n)&&ea==s.__lr+16&&n==16);
 uint32_t sp=0x3d800400u|(31u<<5);assert(ios_ldst_ea(sp,&s,&ea,&n)&&ea==s.__sp+16&&n==16);
 uint32_t reg=0x3ca00800u|(30u<<16)|(3u<<13)|(29u<<5);assert(ios_ldst_ea(reg,&s,&ea,&n)&&ea==s.__fp+s.__lr&&n==16);
 uint32_t unscaled=0xd9000000u|(511u<<12)|(29u<<5);assert(ios_ldst_ea(unscaled,&s,&ea,&n)&&ea==s.__fp-1&&n==8);
 puts("PASS actual EA decoder: observed STR Q, negative pre/post/pair/unscaled offsets, FP/LR/SP and register-offset operands");
}
#endif
int main(void)
{
 stable(64);stable(100);stable(200);
#ifndef BASELINE
 churn();failures();failure_gaps();cpu_gates();counters();decoder();ios_stuck_history_destroy(&ios_stuck);
#endif
 return 0;
}
'''

source=(ROOT/'build/ntdll-unix/server_ios.c').read_text()
a=source.index('#include "stuck_store_history.h"')
b=source.index('\nstatic void ios_thread_sampler_main',a)
candidate=source[a:b]
with tempfile.TemporaryDirectory(prefix='madeira-stuck-history-') as td:
    for label,body in [('baseline',BASELINE),('candidate',candidate)]:
        c=Path(td)/(label+'.c');exe=Path(td)/label;c.write_text(PREFIX+body+SUFFIX)
        args=[os.environ.get('CC','cc'),'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter','-I'+str(ROOT/'build/ntdll-unix'),str(c),'-o',str(exe)]
        if options.sanitize:args[1:1]=['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer']
        if label=='baseline':args.insert(1,'-DBASELINE')
        subprocess.run(args,check=True,timeout=60)
        result=subprocess.run([str(exe)],text=True,capture_output=True,timeout=60)
        if result.returncode:
            raise SystemExit(label+' failed:\n'+result.stdout+result.stderr)
        print(label+'\n'+result.stdout,end='')
