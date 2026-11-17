#!/usr/bin/env python3
"""Execute actual staged suspend/resume handlers and the heap-free identity tag.

Handle lookup and count operations use controlled adapters here. A separate
threaded regression verifies genuine continuation through the client wait.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
def load(name,relative):
    spec=importlib.util.spec_from_file_location(name,ROOT/relative)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def block(source,signature):
    start=source.index(signature);opening=source.index('{',start);depth=1;end=opening+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]

stage=load('suspend_identity_stage','build/wineserver/stage-self-suspend.py')
async_stage=load('suspend_async_stage','build/wineserver/stage-async-apc.py')
source=(ROOT/'wine/server/thread.c').read_text()
staged=stage.stage(async_stage.stage(source))
for marker in ('ios_adopt_async_apc','ios_suspend_thread_reply','DECL_HANDLER(suspend_thread)','DECL_HANDLER(resume_thread)'):
    assert marker in staged
for bad in (staged,source+'\nextern void ios_suspend_resume_observe(void);\n',source.replace('THREAD_SUSPEND_RESUME','THREAD_QUERY_INFORMATION'),source.replace('reply->count = resume_thread( thread );','reply->count = altered_resume( thread );')):
    try:stage.stage(bad)
    except ValueError:pass
    else:raise AssertionError('unsupported/already-staged source accepted')
assert (ROOT/'wine/server/thread.c').read_text()==source
build=(ROOT/'build/wineserver/build.sh').read_text()
assert build.index('stage-async-apc.py')<build.index('stage-self-suspend.py')<build.index('stage-steam-lifecycle.py" "$OBJ_DIR/self-suspend/thread.c"')
assert '--output "$OBJ_DIR/self-suspend/thread.c"' in build
mach=(ROOT/'build/wineserver/mach_ios.c').read_text()
producer=block(mach,'void ios_suspend_thread_reply( struct thread *thread, void *padding, int operation )')
observer=block(mach,'void ios_suspend_resume_observe( struct thread *thread, int old_count )')
core=block(staged,'int resume_thread( struct thread *thread )')
assert core.index('ios_thread_mach_release( thread )')<core.index('ios_suspend_resume_observe( thread, old_count )')<core.index('return old_count;')
assert core.index('wake_thread( thread )')<core.index('ios_suspend_resume_observe( thread, old_count )')
for operation in ('suspend','resume'):
    body=block(staged,f'DECL_HANDLER({operation}_thread)')
    assert body.index(f'reply->count = {operation}_thread( thread );')<body.index('if (!get_error()) ios_suspend_thread_reply')<body.index('release_object( thread );')
assert not any(word in producer for word in ('set_reply_data','get_reply_max_size','malloc(', 'calloc(', 'realloc('))
contract='static const volatile char ios_suspend_identity_contract[] = "[self-suspend-identity-v1]";'
assert contract in mach
assertions='\n'.join(line for line in mach.splitlines() if line.startswith('_Static_assert(') and ' reply ABI' in line)
assertions += '\n'+'\n'.join(line for line in mach.splitlines() if line.startswith('_Static_assert(') and (' count ABI' in line or ' padding ABI' in line))
assert assertions.count('_Static_assert')==6
code=r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "wine/server_protocol.h"
#include "self_suspend_protocol.h"
#define WINE_IOS 1
#define TERMINATED 2
#define STATUS_ACCESS_DENIED 0xc0000022u
#define STATUS_INVALID_PARAMETER 0xc000000du
#define STATUS_SUSPEND_COUNT_EXCEEDED 0xc000004au
#define DECL_HANDLER(name) static void handle_##name(void)
struct process {unsigned id,suspend;};
struct thread {unsigned id;struct process*process;int state;unsigned suspend;uintptr_t teb;unsigned ios_mach_suspended;};
struct handle {uint32_t value;struct process*owner;struct thread*thread;unsigned access;};
static struct thread*current;
static struct suspend_thread_request request_data,*req=&request_data;
static struct suspend_thread_reply response_data,*reply=&response_data;
static struct handle handles[6];
static unsigned error,mutations,releases,begin_calls,observe_calls;
static unsigned observed[8];
static uintptr_t observed_teb;
static unsigned get_error(void){return error;}
static void set_error(unsigned e){error=e;}
static unsigned get_thread_id(struct thread*t){return t->id;}
static unsigned get_process_id(struct process*p){return p->id;}
void ios_self_suspend_server_begin(unsigned pid,unsigned tid,uintptr_t teb,unsigned by_pid,unsigned by_tid){assert(pid==current->process->id&&tid==current->id&&teb==current->teb&&by_pid==pid&&by_tid==tid);begin_calls++;}
void ios_self_suspend_server_resume(unsigned pid,unsigned tid,uintptr_t teb,unsigned by_pid,unsigned by_tid,unsigned old,unsigned now,unsigned held,unsigned process_suspend){observed[0]=pid;observed[1]=tid;observed[2]=by_pid;observed[3]=by_tid;observed[4]=old;observed[5]=now;observed[6]=held;observed[7]=process_suspend;observed_teb=teb;observe_calls++;}
static struct thread *get_thread_from_handle(uint32_t handle,unsigned access){
 if(handle==0xfffffffeu)return current;
 for(unsigned n=0;n<6;n++)if(handles[n].value==handle&&handles[n].owner==current->process){
  if((handles[n].access&access)!=access){error=STATUS_ACCESS_DENIED;return NULL;}return handles[n].thread;
 }
 error=STATUS_INVALID_PARAMETER;return NULL;
}
static void release_object(struct thread*t){assert(t);releases++;}
static unsigned suspend_thread(struct thread*t){unsigned old=t->suspend;mutations++;if(old==127)error=STATUS_SUSPEND_COUNT_EXCEEDED;else t->suspend++;return old;}
static unsigned resume_thread(struct thread*t){unsigned old=t->suspend;mutations++;if(old)t->suspend--;return old;}
'''+assertions+'\n'+contract+'\n'+producer+'\n'+observer+'\n'+block(staged,'DECL_HANDLER(suspend_thread)')+'\n'+block(staged,'DECL_HANDLER(resume_thread)')+r'''
static void reset(void){error=mutations=releases=begin_calls=observe_calls=0;memset(&response_data,0xaa,sizeof(response_data));reply->__header.error=0x11223344;reply->count=0x12345678;}
static unsigned tag(void){uint32_t value;memcpy(&value,reply->__pad_12,sizeof(value));assert(reply->__header.error==0x11223344);return value;}
static void identity(unsigned self){assert(tag()==(MADEIRA_SUSPEND_IDENTITY_MAGIC|self));}
int main(void){
 _Static_assert((MADEIRA_SUSPEND_IDENTITY_MAGIC&1)==0,"identity base leaves self bit free");
 struct process first={12,0},second={16,0};struct thread a={24,&first,0,0,0x2400,0},b={28,&first,0,0,0x2800,0},c={32,&second,0,0,0x3200,0};
 handles[0]=(struct handle){0x100,&first,&a,THREAD_SUSPEND_RESUME};
 handles[1]=(struct handle){0x104,&first,&a,THREAD_SUSPEND_RESUME};
 handles[2]=(struct handle){0x108,&first,&b,THREAD_SUSPEND_RESUME};
 handles[3]=(struct handle){0x100,&second,&c,THREAD_SUSPEND_RESUME};
 handles[4]=(struct handle){0x104,&second,&a,THREAD_SUSPEND_RESUME};
 handles[5]=(struct handle){0x10c,&first,&a,THREAD_QUERY_LIMITED_INFORMATION};
 current=&a;
 const uint32_t self_handles[]={0xfffffffeu,0x100,0x104};
 for(unsigned n=0;n<3;n++){
  reset();req->handle=self_handles[n];handle_suspend_thread();identity(1);
  assert(!error&&reply->count==0&&a.suspend==1&&mutations==1&&releases==1&&begin_calls==1);
  reset();handle_resume_thread();identity(1);assert(!error&&reply->count==1&&!a.suspend&&!begin_calls);
 }
 reset();req->handle=0x108;handle_suspend_thread();identity(0);assert(!error&&b.suspend==1&&!begin_calls);
 current=&c;reset();req->handle=0x100;handle_suspend_thread();identity(1);assert(!error&&c.suspend==1);
 reset();req->handle=0x104;handle_suspend_thread();identity(0);assert(!error&&a.suspend==1);
 // Nested requests to a physically held peer do not add malloc/reply-data
 // dependencies or alter the existing hold. Only the real count operation runs.
 a.ios_mach_suspended=1;reset();handle_suspend_thread();identity(0);assert(!error&&a.suspend==2&&a.ios_mach_suspended==1);
 reset();handle_resume_thread();identity(0);assert(!error&&a.suspend==1&&a.ios_mach_suspended==1);
 current=&a;req->handle=0x100;
 reset();a.state=TERMINATED;handle_suspend_thread();assert(error==STATUS_ACCESS_DENIED&&a.suspend==1&&!mutations&&releases==1&&tag()==0xaaaaaaaau&&!begin_calls);a.state=0;
 reset();a.suspend=127;handle_suspend_thread();assert(error==STATUS_SUSPEND_COUNT_EXCEEDED&&a.suspend==127&&mutations==1&&releases==1&&tag()==0xaaaaaaaau&&!begin_calls);
 reset();req->handle=0xdead;handle_suspend_thread();assert(error==STATUS_INVALID_PARAMETER&&!mutations&&!releases&&tag()==0xaaaaaaaau);
 reset();req->handle=0x10c;handle_suspend_thread();assert(error==STATUS_ACCESS_DENIED&&!mutations&&!releases&&tag()==0xaaaaaaaau);
 reset();current=&c;a.suspend=2;a.ios_mach_suspended=1;first.suspend=1;ios_suspend_resume_observe(&a,3);
 assert(observe_calls==1&&observed[0]==12&&observed[1]==24&&observed[2]==16&&observed[3]==32&&observed[4]==3&&observed[5]==2&&observed[6]==1&&observed[7]==1&&observed_teb==a.teb);
 current=NULL;ios_suspend_resume_observe(&a,2);assert(observe_calls==2&&!observed[2]&&!observed[3]&&a.suspend==2&&a.ios_mach_suspended==1&&first.suspend==1);
 puts("PASS actual fixed padding identity: packet16/countoffset8/padding4; real/duplicate/pseudo handles, restricted rights and process-local/cross-process objects");
 puts("PASS no new heap or variable-reply operations: nested Mach-held targets preserve count/hold behavior; genuine errors/status/padding and object lifetime preserved");
 puts("PASS actual passive observer reports exact target/requester/count/hold/process-suspend metadata without changing it");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-self-protocol-') as directory:
    temp=Path(directory);src=temp/'fixture.c';exe=temp/'fixture';src.write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-D__WINESRC__','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I',str(ROOT/'wine/include'),'-I',str(ROOT/'build/ntdll-unix'),str(src),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,timeout=15)
    src=temp/'async/thread.c';src.parent.mkdir();src.write_text(async_stage.stage(source));dst=temp/'self-suspend/thread.c'
    subprocess.run(['python3',str(ROOT/'build/wineserver/stage-self-suspend.py'),'--source',str(src),'--output',str(dst)],check=True)
    assert dst.read_text()==staged and src.read_text()==async_stage.stage(source)
    final=temp/'thread_lifecycle.c'
    subprocess.run(['python3',str(ROOT/'build/wineserver/stage-steam-lifecycle.py'),str(dst),str(final)],check=True)
    for marker in ('ios_adopt_async_apc','ios_suspend_thread_reply','ios_native_thread_terminated'):
        assert marker in final.read_text()
print('PASS fail-closed async -> identity -> lifecycle composition; pinned Wine sources remain byte-exact')
