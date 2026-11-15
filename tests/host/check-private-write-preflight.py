#!/usr/bin/env python3
"""Actual private-write preflight and legacy probe on owned mappings/files.

The Linux Mach-region adapter queries /proc/self/maps rather than inventing
permissions; Darwin uses real mach_vm_region_recurse. Guest-view metadata is a
fixture, as in the existing VM host tests. Cold residency/short-read/EOF counts
show avoided data-page work. Warm timings are host-only, not iPhone FPS claims.
"""
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'build/ntdll-unix/virtual_ios.c'
text = SOURCE.read_text()

def function(source, signature):
    begin = source.index(signature)
    return source[begin:source.index('\n}', begin) + 2] + '\n'

# Verbatim cbeffbf4 production function, retained for shallow CI checkouts.
legacy = r'''BOOL virtual_check_buffer_for_write( void *ptr, SIZE_T size )
{
    if (!size) return TRUE;
    if (!ptr) return FALSE;

    __TRY
    {
        volatile char *p = ptr;
        SIZE_T count = size;

        while (count > host_page_size)
        {
            *p |= 0;
            p += host_page_size;
            count -= host_page_size;
        }
        p[0] |= 0;
        p[count - 1] |= 0;
    }
    __EXCEPT
    {
        return FALSE;
    }
    __ENDTRY
    return TRUE;
}
'''
assert hashlib.sha256(legacy.encode()).hexdigest() == 'c90bb74cfd17bd3bf3a1947bd12e622dafe6daacd63b5a9f80f3ac9bdf5dbd60'
current = function(text, 'BOOL virtual_check_buffer_for_write(')
assert current.replace('    if (ios_private_write_range_ready( ptr, size )) return TRUE;\n', '') == legacy
helper = function(text, 'static BOOL ios_private_write_range_ready(')
span = function(text, 'static int ios_native_jit_span_has_protection(')
assert 'mach_vm_region_recurse' in span and 'mach_vm_region(' not in span
for check in ('get_page_vprot', 'find_view', 'is_view_valloc', 'ios_kw_has_rw_alias', 'ios_swap_is_fexjit',
              'ios_fex_owner', 'ios_cef_owner', 'ios_flags', 'VM_PROT_EXECUTE'):
    assert check in helper, check
assert all(s not in helper for s in ('memcpy(', 'memset(', 'mprotect(', 'malloc(', 'dprintf('))

prelude = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#else
typedef uintptr_t mach_vm_address_t;
typedef size_t mach_vm_size_t;
typedef unsigned natural_t, mach_msg_type_number_t;
typedef int kern_return_t, vm_prot_t;
typedef int *vm_region_recurse_info_t;
typedef struct { int protection, max_protection, is_submap; unsigned user_tag; uint64_t object_id; } vm_region_submap_info_data_64_t;
#define VM_REGION_SUBMAP_INFO_COUNT_64 1
#define KERN_SUCCESS 0
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
static int mach_task_self(void) { return 1; }
/* Actual owned process mappings/permissions, without accessing their contents. */
static int mach_vm_region_recurse(int task, mach_vm_address_t *a, mach_vm_size_t *n,
                                  natural_t *depth, vm_region_recurse_info_t info, mach_msg_type_number_t *count)
{
    FILE *file = fopen("/proc/self/maps", "r");
    char line[512], rights[8]; unsigned long lo, hi;
    vm_region_submap_info_data_64_t *out = (void *)info;
    (void)task; (void)depth; (void)count;
    assert(file);
    while (fgets(line, sizeof(line), file))
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, rights) == 3 && hi > *a)
        {
            fclose(file); *a = lo; *n = hi-lo; memset(out, 0, sizeof(*out));
            out->protection = (rights[0]=='r'?1:0)|(rights[1]=='w'?2:0)|(rights[2]=='x'?4:0);
            out->max_protection = out->protection;
            return 0;
        }
    fclose(file); return 1;
}
#endif
#define TRUE 1
#define FALSE 0
#define VPROT_READ 0x01
#define VPROT_WRITE 0x02
#define VPROT_EXEC 0x04
#define VPROT_WRITECOPY 0x08
#define VPROT_GUARD 0x10
#define VPROT_COMMITTED 0x20
#define VPROT_WRITEWATCH 0x40
#define VPROT_SYSTEM 0x200
#define VPROT_PLACEHOLDER 0x400
#define SEC_FILE 0x800000
#define SEC_RESERVE 0x4000000
#define SEC_COMMIT 0x8000000
#define SEC_IMAGE 0x1000000
#define min(a,b) ((a)<(b)?(a):(b))
typedef unsigned char BYTE;
typedef int BOOL;
typedef size_t SIZE_T;
#define H 0x4000u
#define G 0x1000u
#define BYTES (16u<<20)
/* mach/mach.h also declares host_page_size(). Match Wine's private
 * identifier isolation after importing the genuine Darwin API declarations. */
#define host_page_size fixture_host_page_size
static const size_t host_page_size=H, host_page_mask=H-1, page_size=G;
struct file_view { void *base; size_t size; unsigned protect, ios_flags; void *ios_fex_owner, *ios_cef_owner; };
static struct file_view view;
static BYTE prot[BYTES/G];
static char *memory;
static uintptr_t alias_lo, alias_hi, native_lo, native_hi;
static pthread_mutex_t virtual_mutex = PTHREAD_MUTEX_INITIALIZER;
static int vm_depth, query_calls, query_fail, fault_calls, watch_faults, guard_faults, fault_mode;
static sigjmp_buf faults;
static volatile sig_atomic_t fault_active;
static void server_enter_uninterrupted_section(pthread_mutex_t *m,sigset_t *s)
{ (void)s; assert(!vm_depth); assert(!pthread_mutex_lock(m)); vm_depth++; }
static void server_leave_uninterrupted_section(pthread_mutex_t *m,sigset_t *s)
{ (void)s; assert(vm_depth==1); vm_depth--; assert(!pthread_mutex_unlock(m)); }
static struct file_view *find_view(const void *p,size_t n)
{ uintptr_t a=(uintptr_t)p,b=(uintptr_t)view.base; assert(vm_depth); return a>=b&&a-b<=view.size&&n<=view.size-(a-b)?&view:NULL; }
static int is_view_valloc(const struct file_view *v) { return !(v->protect&(SEC_FILE|SEC_RESERVE|SEC_COMMIT)); }
static BYTE get_page_vprot(const void *p)
{ size_t o=(const char *)p-memory; assert(vm_depth && o<BYTES); return prot[o/G]; }
static int ios_kw_has_rw_alias(uintptr_t a,uintptr_t b) { return alias_hi && a<alias_hi&&alias_lo<b; }
static int ios_swap_is_fexjit(uintptr_t a,size_t n) { return native_hi && a<native_hi&&native_lo<a+n; }
static kern_return_t query_counted(mach_port_t task,mach_vm_address_t *a,mach_vm_size_t *n,natural_t *depth,
                                   vm_region_recurse_info_t info,mach_msg_type_number_t *count)
{ assert(vm_depth); query_calls++; return query_fail ? 1 : mach_vm_region_recurse(task,a,n,depth,info,count); }
#define mach_vm_region_recurse query_counted
#define __TRY if ((fault_active=1, sigsetjmp(faults,1)) == 0)
#define __EXCEPT else
#define __ENDTRY fault_active=0;
'''.replace('mach_port_t task', 'int task' if os.uname().sysname != 'Darwin' else 'mach_port_t task')

harness = r'''
static void caught(int sig,siginfo_t *info,void *context)
{
    uintptr_t p=(uintptr_t)info->si_addr;
    (void)context;
    if (!fault_active) { fprintf(stderr,"unexpected signal %d at%p\n",sig,info->si_addr); _exit(3); }
    fault_calls++;
    if (fault_mode==1)
    {
        size_t off=p-(uintptr_t)memory; watch_faults++;
        assert(off<BYTES); assert(!mprotect((void *)(p&~(uintptr_t)(H-1)),H,PROT_READ|PROT_WRITE));
        for (size_t i=(off&~(size_t)(H-1))/G;i<((off&~(size_t)(H-1))+H)/G;i++) prot[i]&=~VPROT_WRITEWATCH;
        return;
    }
    if (fault_mode==2)
    {
        size_t off=p-(uintptr_t)memory; guard_faults++;
        assert(!mprotect((void *)(p&~(uintptr_t)(H-1)),H,PROT_READ|PROT_WRITE));
        for(size_t i=(off&~(size_t)(H-1))/G;i<((off&~(size_t)(H-1))+H)/G;i++) prot[i]&=~VPROT_GUARD;
    }
    fault_active=0; siglongjmp(faults,1);
}
static int newfile(size_t n)
{
    char name[]="/tmp/madeira-write-preflight-XXXXXX";
    int fd=mkstemp(name); assert(fd>=0); assert(!unlink(name)); assert(!ftruncate(fd,n)); return fd;
}
static unsigned resident(void)
{
    size_t pages=BYTES/(size_t)sysconf(_SC_PAGESIZE); unsigned sum=0;
    unsigned char *state=calloc(pages,1); assert(state);
    assert(!mincore(memory,BYTES,(void *)state));
    for(size_t i=0;i<pages;i++) sum+=!!(state[i]&1);
    free(state); return sum;
}
static int backing;
static void reset(int filebacked)
{
    if(memory)assert(!munmap(memory,BYTES));
    if(backing>=0)assert(!close(backing));
    backing=filebacked?newfile(BYTES):-1;
    /* Align the owned mapping to the modeled16KB host boundary. */
    char *all=mmap(NULL,BYTES+H,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(all!=MAP_FAILED); uintptr_t aligned=((uintptr_t)all+H-1)&~(uintptr_t)(H-1);
    if(aligned>(uintptr_t)all)assert(!munmap(all,aligned-(uintptr_t)all));
    if(aligned+BYTES<(uintptr_t)all+BYTES+H)assert(!munmap((void *)(aligned+BYTES),(uintptr_t)all+BYTES+H-aligned-BYTES));
    memory=(void *)aligned;
    if(filebacked)assert(mmap(memory,BYTES,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_SHARED,backing,0)==memory);
    view=(struct file_view){memory,BYTES,VPROT_READ|VPROT_WRITE|VPROT_COMMITTED,0,NULL,NULL};
    memset(prot,VPROT_READ|VPROT_WRITE|VPROT_COMMITTED,sizeof(prot));
    alias_lo=alias_hi=native_lo=native_hi=0; query_calls=0; fault_mode=0;
}
static double now(void)
{ struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC,&t)); return t.tv_sec+t.tv_nsec/1e9; }
int main(void)
{
    struct sigaction action={0}; action.sa_sigaction=caught; action.sa_flags=SA_SIGINFO;
    sigemptyset(&action.sa_mask); assert(!sigaction(SIGSEGV,&action,NULL)); assert(!sigaction(SIGBUS,&action,NULL));
    backing=-1;
    int src=newfile(4*H); unsigned char bytes[4*H];
    for(size_t i=0;i<sizeof(bytes);i++)bytes[i]=(unsigned char)(i*17+3);
    assert(pwrite(src,bytes,sizeof(bytes),0)==sizeof(bytes));
    for(int filebacked=0;filebacked<2;filebacked++)
    {
        reset(filebacked); assert(resident()==0);
        assert(old_virtual_check_buffer_for_write(memory,BYTES));
        unsigned oldpages=resident(); assert(oldpages>=BYTES/H);
        reset(filebacked); assert(resident()==0);
        assert(virtual_check_buffer_for_write(memory,BYTES)); assert(query_calls>0);
        unsigned newpages=resident(); assert(newpages==0);
        assert(pread(src,memory,BYTES,0)==sizeof(bytes));
        unsigned partialpages=resident(); assert(partialpages<BYTES/H);
        assert(!memcmp(memory,bytes,sizeof(bytes))); assert(memory[BYTES-1]==0);
        reset(filebacked); assert(virtual_check_buffer_for_write(memory,BYTES));
        assert(pread(src,memory,BYTES,sizeof(bytes))==0); assert(resident()==0);
        printf("PASS %s destination: legacy preflight resident=%u pages, new=%u; short-read=%u pages; EOF=0 pages\n",filebacked?"shared sparse-file":"anonymous",oldpages,newpages,partialpages);
    }
    /* Exact guest-page checks: a hidden4KB watch/guard/read-only/uncommitted
     * neighbor must not be admitted by the16KB union or actualhostRW. */
    reset(0);
    assert(ios_private_write_range_ready(memory+7,4*H));
    assert(resident()==0);
    query_fail=1; assert(!ios_private_write_range_ready(memory,4*H));
    assert(virtual_check_buffer_for_write(memory,4*H)); query_fail=0;
    puts("PASS unaligned complete-host-span admission and failedMachquery retains real faulting fallback");
    BYTE forbidden[]={VPROT_WRITEWATCH,VPROT_GUARD,VPROT_EXEC,VPROT_WRITECOPY,0};
    for(unsigned i=0;i<sizeof(forbidden);i++)
    {
        prot[1]=forbidden[i]?prot[1]|forbidden[i]:0;
        assert(!ios_private_write_range_ready(memory,4*H));
        prot[1]=VPROT_READ|VPROT_WRITE|VPROT_COMMITTED;
    }
    unsigned flags[]={SEC_IMAGE,SEC_FILE,SEC_RESERVE,SEC_COMMIT,VPROT_SYSTEM,VPROT_PLACEHOLDER,VPROT_WRITEWATCH,VPROT_EXEC};
    for(unsigned i=0;i<sizeof(flags)/sizeof(*flags);i++)
    { view.protect|=flags[i]; assert(!ios_private_write_range_ready(memory,4*H)); view.protect&=~flags[i]; }
    view.ios_flags=1;assert(!ios_private_write_range_ready(memory,4*H));view.ios_flags=0;
    view.ios_fex_owner=memory;assert(!ios_private_write_range_ready(memory,4*H));view.ios_fex_owner=NULL;
    view.ios_cef_owner=memory;assert(!ios_private_write_range_ready(memory,4*H));view.ios_cef_owner=NULL;
    alias_lo=(uintptr_t)memory;alias_hi=alias_lo+BYTES;assert(!ios_private_write_range_ready(memory,4*H));alias_hi=0;
    native_lo=(uintptr_t)memory;native_hi=native_lo+BYTES;assert(!ios_private_write_range_ready(memory,4*H));native_hi=0;
    assert(!ios_private_write_range_ready(memory+1,4*H-1)); /* below threshold */
    assert(!ios_private_write_range_ready((void *)(UINTPTR_MAX-H),8*H));
    assert(!ios_private_write_range_ready(memory+BYTES-H,4*H));
    char *saved=view.base;view.base=memory+H;view.size=BYTES-H;
    assert(!ios_private_write_range_ready(memory+1,4*H));view.base=saved;view.size=BYTES;
    puts("PASS strict complete-host-page metadata, section/native/alias ownership, threshold and overflow exclusions");
    /* Actual permissions are required even when fixture metadata is stale. */
    assert(!mprotect(memory+H,H,PROT_NONE));
    assert(!ios_private_write_range_ready(memory,4*H));
    assert(!virtual_check_buffer_for_write(memory,4*H));
    assert(!mprotect(memory+H,H,PROT_READ));
    assert(!ios_private_write_range_ready(memory,4*H));
    assert(!virtual_check_buffer_for_write(memory,4*H));
    assert(!mprotect(memory+H,H,PROT_READ|PROT_WRITE));
    assert(virtual_check_buffer_for_write(memory,4*H));
    puts("PASS actual hostPROT_NONE/read-only cannot receive fabricated successful validation");
    /* Guard/writewatch retain the original faulting probe and its sideeffects. */
    for(unsigned i=H/G;i<2*H/G;i++)prot[i]|=VPROT_WRITEWATCH;
    view.protect|=VPROT_WRITEWATCH;fault_mode=1;
    assert(!mprotect(memory+H,H,PROT_READ));
    assert(virtual_check_buffer_for_write(memory,4*H));assert(watch_faults==1);
    view.protect&=~VPROT_WRITEWATCH;fault_mode=2;
    for(unsigned i=H/G;i<2*H/G;i++)prot[i]|=VPROT_GUARD;
    assert(!mprotect(memory+H,H,PROT_NONE));
    assert(!virtual_check_buffer_for_write(memory,4*H));assert(guard_faults==1);
    fault_mode=0;assert(virtual_check_buffer_for_write(memory,4*H));
    char foreign[64]={0};assert(virtual_check_buffer_for_write(foreign,sizeof(foreign)));
    assert(virtual_check_buffer_for_write(NULL,0));assert(!virtual_check_buffer_for_write(NULL,64));
    puts("PASS original write-watch, one-shot guard and foreign/small-buffer fallback preserved");
    /* Validation never pins a guest allocation; a subsequent protection change
     * is still a real kernelEFAULT, exactly as after the old completed probe. */
    assert(virtual_check_buffer_for_write(memory,4*H));assert(!mprotect(memory,H,PROT_NONE));
    errno=0;assert(pread(src,memory,H,0)==-1&&errno==EFAULT);assert(!mprotect(memory,H,PROT_READ|PROT_WRITE));
    puts("PASS post-validation protection race is not fabricated I/O completion");
    memset(memory,1,BYTES); const int iterations=2000;
    const size_t warm_sizes[]={4*H,16*H,1u<<20,BYTES};
    for(unsigned size_index=0;size_index<sizeof(warm_sizes)/sizeof(*warm_sizes);size_index++)
    {
        size_t warm_bytes=warm_sizes[size_index];
        double a=now();for(int i=0;i<iterations;i++)assert(old_virtual_check_buffer_for_write(memory,warm_bytes));double oldtime=now()-a;
        a=now();for(int i=0;i<iterations;i++)assert(virtual_check_buffer_for_write(memory,warm_bytes));double newtime=now()-a;
        printf("MEASURE warm%zuKiB validation: legacy %.2fus/call, new %.2fus/call (%s host; Linux /proc adapter timing is not DarwinMach timing)\n",warm_bytes>>10,oldtime*1e6/iterations,newtime*1e6/iterations,
#ifdef __APPLE__
        "Darwin"
#else
        "Linux"
#endif
        );
    }
    assert(!vm_depth);assert(!close(src));assert(!munmap(memory,BYTES));if(backing>=0)assert(!close(backing));
    puts("PASS actual production private-write preflight and unmodified legacy probe; no retained staging data or new backing allocations");
    return 0;
}
'''

code=prelude+span+'\n#undef mach_vm_region_recurse\n'+helper+current+legacy.replace('BOOL virtual_check_buffer_for_write(', 'BOOL old_virtual_check_buffer_for_write(')+harness
with tempfile.TemporaryDirectory(prefix='madeira-private-write-preflight-') as temp:
    source=Path(temp)/'test.c'; binary=Path(temp)/'test'; source.write_text(code)
    cc=os.environ.get('CC','cc')
    command=[cc,'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-pthread',str(source),'-o',str(binary)]
    if 'clang' not in subprocess.check_output([cc, '--version'], text=True).lower():
        command.insert(1, '-Wno-clobbered')  # fixture sigsetjmp replaces Wine exception macros
    subprocess.run(command,check=True)
    subprocess.run([str(binary)],check=True)
    sanitized=Path(temp)/'test-sanitized'
    sanitizer_command=command[:-1]+[str(sanitized),'-fsanitize=address,undefined','-fno-omit-frame-pointer']
    subprocess.run(sanitizer_command,check=True)
    environment=dict(os.environ,ASAN_OPTIONS='detect_leaks=0:handle_segv=0:handle_sigbus=0',UBSAN_OPTIONS='halt_on_error=1')
    subprocess.run([str(sanitized)],check=True,env=environment)
print('PASS production fallback is byte-for-byte unchanged from cbeffbf4; no guest data reads/writes or protection changes in fast preflight')
