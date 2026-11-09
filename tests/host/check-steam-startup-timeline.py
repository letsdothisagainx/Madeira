#!/usr/bin/env python3
"""Run the production monotonic observer with exact lifecycle and overlap tests.

This validates observation, not an official redistributable's success or CS2
interactivity. Real process API hooks are checked separately below. Clock and
output plumbing are replaced; classification, state, bounds and intervals are
compiled verbatim from the production header.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
header = ROOT / 'build/ntdll-unix/steam_startup_timeline.h'
status_header = (ROOT / 'wine/include/ntstatus.h').read_text()
match = re.search(r'^#define STATUS_CONFLICTING_ADDRESSES\s+\(\(NTSTATUS\)\s*(0x[0-9A-Fa-f]+)', status_header, re.M)
assert match and int(match[1], 16) == 0xC0000018, 'test status must match Wine NTSTATUS'
process = (ROOT / 'build/ntdll-unix/process_ios.c').read_text()
loader = (ROOT / 'build/ntdll-unix/loader_ios.c').read_text()
thread = (ROOT / 'build/ntdll-unix/thread_ios.c').read_text()
server = (ROOT / 'build/ntdll-unix/server_ios.c').read_text()
start = process.index('NTSTATUS WINAPI NtCreateUserProcess(')
end = process.index('\n\n#ifdef WINE_IOS', process.index('    return status;\n}', start))
create = process[start:end]
assert create.index('ios_startup_process_request(') < create.index('get_pe_file_info(')
assert create.index('ios_startup_process_created(') > create.index('SERVER_END_REQ;', create.index('SERVER_START_REQ( new_process )'))
assert create.index('ios_startup_process_created(') < create.index('spawn_process(')
assert create.index('done:') < create.rindex('ios_startup_process_returned(')
assert create.count('ios_startup_process_returned(') == 2  # native non-PE return and normal done
assert 'MADEIRA_STEAM_STARTUP_TIMELINE_IMPLEMENTATION' in process
assert loader.index('ios_startup_timeline_begin();', loader.index('DECLSPEC_EXPORT void __wine_main(')) < loader.index('init_paths();', loader.index('DECLSPEC_EXPORT void __wine_main('))
assert loader.index('ios_startup_process_bind(') > loader.index('startup_info_size = server_init_process_child(')
assert loader.index('ios_startup_process_pe_entry(') < loader.index('server_init_process_done();', loader.index('ios_startup_process_pe_entry('))
finish = server[server.index('static void ios_finish_process_memory('):server.index('\nvoid process_exit_wrapper(')]
assert finish.index('ios_thread_process_quiescent_lease(dead_peb)') < finish.index('if (lease) ios_startup_process_quiesced(dead_peb);') < finish.index('ios_fd_cache_release(dead_peb);')
assert 'ios_startup_process_quiesced' not in thread
for name, expected in (('abort_process', ', 1 );'), ('exit_process', ', 0 );')):
    begin = thread.index('\nvoid ' + name + '( int status )')
    body = thread[begin:thread.index('\n}', begin)]
    assert 'ios_startup_process_exit_request(' in body and '(uint32_t)status' in body and expected in body
    assert 'if (timing_teb)' in body, 'pre-TEB boot failure must not introduce a dereference'
abort_begin = thread.index('\nvoid abort_process( int status )')
abort_body = thread[abort_begin:thread.index('\n}', abort_begin)]
abort_hook_start = abort_body.index('    {\n        TEB *timing_teb')
abort_hook = abort_body[abort_hook_start:abort_body.index('\n    }', abort_hook_start) + len('\n    }')]
for name in ('abort_thread', 'exit_thread'):
    begin = thread.index('void ' + name + '( int status )')
    body = thread[begin:thread.index('\n}', begin)]
    assert 'ios_startup_process_exit_request(' not in body, 'thread exit is not process completion'

code = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
static _Atomic uint64_t observed_now=1000000000ULL;
static char output[256*1024];
static size_t output_used;
static int capture(int fd,const char *format,...)
{
    assert(fd==2);
    va_list args;va_start(args,format);
    int n=vsnprintf(output+output_used,sizeof(output)-output_used,format,args);
    va_end(args);assert(n>=0&&(size_t)n<sizeof(output)-output_used);
    output_used+=(size_t)n;errno=EINTR;return n;
}
static uint64_t now_ns(void){errno=EAGAIN;return atomic_load(&observed_now);}
#define dprintf capture
#define MADEIRA_STARTUP_NOW_NS() now_ns()
#define MADEIRA_STEAM_STARTUP_TIMELINE_IMPLEMENTATION
#include "HEADER"
#undef dprintf
#define ORIGINAL_WINE_CONFLICT CONFLICT_VALUE
struct timing_teb { void *Peb;struct {void *UniqueProcess;} ClientId; };
typedef struct timing_teb TEB;typedef uintptr_t ULONG_PTR;
static TEB *hook_teb;
static TEB *NtCurrentTeb(void){return hook_teb;}
static void actual_abort_hook(uint32_t status)
{
ABORT_HOOK
}
static size_t wide(uint16_t *out,const char *ascii)
{
    size_t n=strlen(ascii);assert(n<512);
    for(size_t i=0;i<=n;i++)out[i]=(unsigned char)ascii[i];
    return n;
}
static void at(uint64_t ms){atomic_store(&observed_now,1000000000ULL+ms*1000000ULL);}
static uint32_t request(const char *image,const char *cmd,uint32_t parent,uint64_t ms)
{
    uint16_t wimage[512],wcmd[512];size_t ni=wide(wimage,image),nc=wide(wcmd,cmd);
    at(ms);errno=EDOM;
    uint32_t token=ios_startup_process_request(wimage,ni,wcmd,nc,parent);
    assert(errno==EDOM);return token;
}
static void reset(void)
{
    memset(ios_startup_processes,0,sizeof ios_startup_processes);
    ios_startup_origin=ios_startup_started=ios_startup_count=ios_startup_events=0;
    output_used=0;output[0]=0;at(0);
}
static void exact_capture(void)
{
    reset();assert(!unsetenv("MADEIRA_STARTUP_T0_NS"));errno=ERANGE;ios_startup_timeline_begin();assert(errno==ERANGE);
    assert(strstr(output,"event=origin source=wine-entry clock=monotonic t-ms=0"));
    uint32_t steam=request("C:\\Program Files (x86)\\Steam\\Steam.exe","-applaunch 730 -token NEVER_LOG_THIS",0x20,7000);
    assert(steam);at(7010);ios_startup_process_created(steam,0x68);
    at(7020);ios_startup_process_bind(0x68,(void *)0x1000);
    at(7070);ios_startup_process_pe_entry(0x68,(void *)0x1000);
    at(7100);ios_startup_process_returned(steam,0,1);
    assert(strstr(output,"event=create-return phase=steam-client attempt=1 creator=0020 pid=0068 t-ms=7100 duration-ms=100 status=00000000 create-ok=1"));
    size_t saved=output_used;ios_startup_process_returned(steam,0,1);assert(output_used==saved);

    uint32_t dx=request("C:\\PRIVATE_ACCOUNT\\DXSETUP.exe","/silent -password PRIVATE_SECRET",0x68,230000);
    assert(dx==2);at(230010);ios_startup_process_created(dx,0x2f0);
    at(230020);ios_startup_process_bind(0x2f0,(void *)0x2000);
    at(230070);ios_startup_process_pe_entry(0x2f0,(void *)0x2000);
    at(230090);ios_startup_process_returned(dx,0,1);
    uint32_t plugin=request("C:\\TEMP\\DX68af.tmp\\infinst.exe","d3dx9_24_x64.inf",0x2f0,391800);
    assert(plugin==3);at(391810);ios_startup_process_created(plugin,0x308);
    at(391820);ios_startup_process_bind(0x308,(void *)0x3000);
    at(391900);errno=EBUSY;ios_startup_process_exit_request(0x308,(void *)0x3000,ORIGINAL_WINE_CONFLICT,1);assert(errno==EBUSY);
    assert(!ios_startup_processes[plugin-1].closed&&!ios_startup_processes[dx-1].closed);
    at(391950);ios_startup_process_quiesced((void *)0x3000);
    at(391960);ios_startup_process_returned(plugin,ORIGINAL_WINE_CONFLICT,0);
    assert(ios_startup_processes[plugin-1].closed&&!ios_startup_processes[dx-1].closed);
    assert(strstr(output,"event=create-request phase=directx-plugin attempt=3 creator=02f0 pid=0000 t-ms=391800"));
    assert(strstr(output,"event=abort-request phase=directx-plugin attempt=3 creator=02f0 pid=0308 t-ms=391900 duration-ms=100 status=c0000018"));
    assert(strstr(output,"event=owner-quiesced phase=directx-plugin attempt=3 creator=02f0 pid=0308 t-ms=391950 duration-ms=150 status=c0000018"));
    assert(strstr(output,"event=create-return phase=directx-plugin attempt=3 creator=02f0 pid=0308 t-ms=391960 duration-ms=160 status=c0000018 create-ok=0"));
    at(394000);ios_startup_process_exit_request(0x2f0,(void *)0x2000,ORIGINAL_WINE_CONFLICT,0);
    at(394050);ios_startup_process_quiesced((void *)0x2000);
    assert(strstr(output,"event=owner-quiesced phase=directx-setup attempt=2 creator=0068 pid=02f0 t-ms=394050 duration-ms=164050 status=c0000018"));
    uint32_t cs2=request("C:\\Steam\\steamapps\\common\\Counter-Strike Global Offensive\\game\\bin\\win64\\cs2.exe","-steam -joy",0x68,397400);
    assert(cs2==4);at(397410);ios_startup_process_created(cs2,0x320);
    at(397420);ios_startup_process_bind(0x320,(void *)0x4000);
    at(397470);ios_startup_process_pe_entry(0x320,(void *)0x4000);
    at(397600);ios_startup_process_returned(cs2,0,1);
    assert(strstr(output,"phase=cs2 attempt=4 creator=0068 pid=0000 t-ms=397400"));
    assert(!strstr(output,"PRIVATE_ACCOUNT")&&!strstr(output,"PRIVATE_SECRET")&&!strstr(output,"NEVER_LOG_THIS")&&!strstr(output,"Counter-Strike")&&!strstr(output,"d3dx9_24"));
    assert(strstr(output,"intervals=overlap-allowed")&&strstr(output,"cpu-time=unmeasured"));
    assert(!strstr(output,"installer-succeeded")&&!strstr(output,"menu-interactive"));
    puts("PASS exact production timeline: CS2 request397400ms, child create failurec0000018, parent/child overlapping lifetime distinct from API return and native quiescence; no inferred installation/menu success");
}
static void classification_and_errors(void)
{
    reset();uint16_t image[512],command[512];size_t n=wide(image,"C:\\prefix\\SteamService.exe");
    size_t nc=wide(command,"\"C:\\prefix\\SteamService.exe\" /INSTALLSCRIPT \"PRIVATE_ACCOUNT\" 730");
    assert(!strcmp(ios_startup_phase(image,n,command,nc),"installscript"));
    nc=wide(command,"/installscript-fake");assert(!strcmp(ios_startup_phase(image,n,command,nc),"steam-service"));
    n=wide(image,"C:\\vc\\cmd.exe");nc=wide(command,"/c \"C:\\redist\\Microsoft Visual C++ 2019 x64.cmd\"");
    assert(!strcmp(ios_startup_phase(image,n,command,nc),"vcredist-x64-script"));
    assert(!request("evil-cs2.exe","",1,10)&&!request("cs2.exe.evil","",1,10));
    assert(!ios_startup_process_request(NULL,4,NULL,0,0));
    assert(!ios_startup_process_request(image,32768,NULL,0,0));
    uint32_t fail=request("infinst.exe","",1,1000);assert(fail==1);
    at(1010);ios_startup_process_returned(fail,ORIGINAL_WINE_CONFLICT,0);
    assert(strstr(output,"pid=0000 t-ms=10 duration-ms=10 status=c0000018 create-ok=0"));
    size_t saved=output_used;
    ios_startup_process_created(999,7);ios_startup_process_returned(999,0,1);ios_startup_process_bind(99,(void *)1);ios_startup_process_quiesced((void *)1);
    assert(output_used==saved);
    atomic_store(&observed_now,0);errno=ENOTTY;ios_startup_timeline_begin();assert(errno==ENOTTY);assert(!ios_startup_process_request(image,n,NULL,0,0));assert(output_used==saved);
    reset();uint32_t handoff=request("steam.exe","-applaunch 730",0x20,1000);
    ios_startup_process_created(handoff,0x68);ios_startup_process_returned(handoff,0,1);
    assert(!ios_startup_processes[handoff-1].owner&&!ios_startup_processes[handoff-1].pe_entry&&!ios_startup_processes[handoff-1].closed);
    assert(strstr(output,"create-ok=1")&&!strstr(output,"startup-ready")&&!strstr(output,"pe-start-dispatch"));
    at(2000);ios_startup_process_bind(0x68,(void *)0x5000);ios_startup_process_pe_entry(0x68,(void *)0x5000);
    assert(ios_startup_processes[handoff-1].pe_entry);
    puts("PASS exact role/token allowlist, native pre-PID failure, deferred Steam handoff readiness, untracked/invalid/clock-failure paths and errno/privacy preservation");
}
static void before_teb_exit(void)
{
    reset();hook_teb=NULL;errno=ECHILD;actual_abort_hook(ORIGINAL_WINE_CONFLICT);
    assert(errno==ECHILD&&!output_used&&!ios_startup_count);
    uint32_t token=request("infinst.exe","",1,1000);assert(token);
    ios_startup_process_created(token,0x50);ios_startup_process_bind(0x50,(void *)0x3000);
    TEB current={.Peb=(void *)0x3000,.ClientId={.UniqueProcess=(void *)0x50}};
    hook_teb=&current;actual_abort_hook(ORIGINAL_WINE_CONFLICT);
    assert(strstr(output,"event=abort-request phase=directx-plugin")&&ios_startup_processes[token-1].status==ORIGINAL_WINE_CONFLICT);
    hook_teb=NULL;
    puts("PASS actual abort hook declines pre-TEB failure; live TEB preserves genuine raw Windows status before Unix exit normalization");
}
static void shared_app_origin(void)
{
    assert(ios_startup_app_origin("1000000000",2000000000ULL)==1000000000ULL);
    assert(!ios_startup_app_origin("0",2000000000ULL));
    assert(!ios_startup_app_origin("+1",2000000000ULL));
    assert(!ios_startup_app_origin(" 1",2000000000ULL));
    assert(!ios_startup_app_origin("2000000001",2000000000ULL));
    assert(!ios_startup_app_origin("1",86400000000002ULL));
    assert(!ios_startup_app_origin("18446744073709551616",UINT64_MAX));
    assert(!ios_startup_app_origin("000000000000000000001",2000000000ULL));
    reset();at(5000);assert(!setenv("MADEIRA_STARTUP_T0_NS","1000000000",1));
    ios_startup_timeline_begin();assert(strstr(output,"source=app-launch clock=monotonic t-ms=5000"));
    assert(!setenv("MADEIRA_STARTUP_T0_NS","6000000000",1));at(6000);
    uint32_t token=request("cs2.exe","",1,6000);assert(token);
    assert(strstr(output,"phase=cs2 attempt=1 creator=0001 pid=0000 t-ms=6000"));
    /* The app's later env mutation cannot reset a running session's clock. */
    reset();assert(!setenv("MADEIRA_STARTUP_T0_NS","18446744073709551616",1));ios_startup_timeline_begin();
    assert(strstr(output,"source=wine-entry clock=monotonic t-ms=0"));
    assert(!unsetenv("MADEIRA_STARTUP_T0_NS"));
    puts("PASS common app/Wine monotonic epoch, frozen per session; malformed/future/overflow/stale origins safely fall back without launch gating");
}
static void reused_and_concurrent(void)
{
    reset();ios_startup_timeline_begin();uint32_t first=request("cs2.exe","",1,1000);
    ios_startup_process_created(first,0x50);ios_startup_process_bind(0x50,(void *)0x1000);
    ios_startup_process_exit_request(0x50,(void *)0x1000,1603,0);ios_startup_process_quiesced((void *)0x1000);
    uint32_t second=request("cs2.exe","",1,2000);ios_startup_process_created(second,0x50);ios_startup_process_bind(0x50,(void *)0x2000);
    size_t saved=output_used;ios_startup_process_exit_request(0x50,(void *)0x1000,0,0);ios_startup_process_quiesced((void *)0x1000);
    assert(output_used==saved&&!ios_startup_processes[second-1].closed);
    ios_startup_process_quiesced((void *)0x2000);
    assert(strstr(output,"event=owner-quiesced-status-unobserved phase=cs2 attempt=2"));
}
static void *many(void *data)
{
    uint32_t base=(uint32_t)(uintptr_t)data;uint16_t image[32];size_t n=wide(image,"VC_redist.x64.exe");
    for(unsigned i=0;i<40;i++){
        uint32_t token=ios_startup_process_request(image,n,NULL,0,base);
        if(!token)continue;
        uint32_t pid=base+i;void *owner=(void *)(uintptr_t)(pid+0x10000);
        ios_startup_process_created(token,pid);ios_startup_process_bind(pid,owner);
        ios_startup_process_pe_entry(pid,owner);ios_startup_process_returned(token,0,1);
        ios_startup_process_exit_request(pid,owner,0,0);ios_startup_process_quiesced(owner);
    }
    return NULL;
}
static void bounded_parallel(void)
{
    reset();ios_startup_timeline_begin();pthread_t threads[8];
    for(uintptr_t i=0;i<8;i++)assert(!pthread_create(&threads[i],NULL,many,(void *)(0x100+i*0x100)));
    for(unsigned i=0;i<8;i++)assert(!pthread_join(threads[i],NULL));
    assert(ios_startup_count==IOS_STARTUP_RECORD_LIMIT&&ios_startup_events<=IOS_STARTUP_EVENT_LIMIT);
    for(unsigned i=0;i<ios_startup_count;i++)assert(ios_startup_processes[i].token==i+1&&ios_startup_processes[i].closed);
    size_t saved=output_used;uint16_t image[32];size_t n=wide(image,"cs2.exe");
    assert(!ios_startup_process_request(image,n,NULL,0,1)&&output_used==saved);
    puts("PASS128 bounded concurrent process records, unique attempts, no stale owner/PID closure,640-event work/output cap; diagnostic exhaustion never changes process results");
}
int main(void){exact_capture();classification_and_errors();before_teb_exit();shared_app_origin();reused_and_concurrent();bounded_parallel();return 0;}
'''.replace('HEADER',str(header)).replace('CONFLICT_VALUE',match[1]+'u').replace('ABORT_HOOK',abort_hook)
with tempfile.TemporaryDirectory(prefix='madeira-startup-timeline-') as directory:
    path=Path(directory);source=path/'timeline.c';executable=path/'timeline';source.write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread',
                    str(source),'-o',str(executable)],check=True)
    subprocess.run([str(executable)],check=True,timeout=30)
    real=path/'real-clock.c';real_executable=path/'real-clock'
    real.write_text("""#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <time.h>
#define MADEIRA_STEAM_STARTUP_TIMELINE_IMPLEMENTATION
#include \"HEADER\"
int main(void) {
    assert(!unsetenv(\"MADEIRA_STARTUP_T0_NS\"));
    errno=EDOM;ios_startup_timeline_begin();assert(errno==EDOM);
    uint64_t before=ios_startup_now_ns();assert(before);
    struct timespec pause={.tv_nsec=1000000};assert(!nanosleep(&pause,0));
    uint64_t after=ios_startup_now_ns();assert(after>=before);
    puts(\"PASS actual CLOCK_MONOTONIC API and production epoch initialization\");return 0;
}
""".replace('HEADER',str(header)))
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-O1','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread',
                    str(real),'-o',str(real_executable)],check=True)
    subprocess.run([str(real_executable)],check=True,timeout=30)
