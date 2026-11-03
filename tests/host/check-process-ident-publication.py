#!/usr/bin/env python3
"""Interleave the actual native identity writers at slot publication fences."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
loader = (root / 'build/ntdll-unix/loader_ios.c').read_text()

def body(source, marker):
    start=source.index(marker); opening=source.index('{',start); depth=0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]',source[opening:],re.S):
        if token.group()=='{': depth+=1
        elif token.group()=='}':
            depth-=1
            if not depth:return source[start:opening+token.end()]
    raise AssertionError(marker)

register=body(loader,'void ios_register_proc_ident(')
release=body(loader,'void ios_proc_ident_release(')
assert 'static pthread_mutex_t ios_proc_ident_writer_lock = PTHREAD_MUTEX_INITIALIZER;' in loader
for function in (register,release):
    assert re.search(r'pthread_mutex_lock\(\s*&ios_proc_ident_writer_lock\s*\)',function)
    assert re.search(r'pthread_mutex_unlock\(\s*&ios_proc_ident_writer_lock\s*\)',function)
# Existing getters remain safe to use from signal/Mach exception diagnostics.
for marker in ('const SECTION_IMAGE_INFORMATION *ios_image_info_for_peb(',
               'const SYSTEM_DLL_INIT_BLOCK *ios_wow64_init_block_for_peb('):
    assert 'pthread_mutex_lock' not in body(loader,marker)

code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define IOS_MAX_PROC_IDENTS 64
#define dprintf(...) ((void)0)
typedef struct { unsigned Machine; } SECTION_IMAGE_INFORMATION;
struct ios_ntdll_funcs { uintptr_t entries[16]; };
typedef struct { uintptr_t entries[16]; } SYSTEM_DLL_INIT_BLOCK;
''' + body(loader,'struct ios_proc_ident\n{') + r''';
static struct ios_proc_ident ios_proc_idents[IOS_MAX_PROC_IDENTS];
static int ios_proc_ident_count;
static pthread_mutex_t ios_proc_ident_writer_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t phase_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t phase_cond=PTHREAD_COND_INITIALIZER;
static _Thread_local unsigned role;
static int paused_release, resume_release, register_attempted, register_done, negative_control;
static void identity_fence(void) {
    __sync_synchronize();
    if(role!=1)return;
    pthread_mutex_lock(&phase_lock);
    if(!paused_release) {
        paused_release=1;pthread_cond_broadcast(&phase_cond);
        while(!resume_release)pthread_cond_wait(&phase_cond,&phase_lock);
    }
    pthread_mutex_unlock(&phase_lock);
}
static int writer_lock(pthread_mutex_t *lock) {
    assert(lock==&ios_proc_ident_writer_lock);
    if(role==2) {
        pthread_mutex_lock(&phase_lock);register_attempted=1;
        pthread_cond_broadcast(&phase_cond);pthread_mutex_unlock(&phase_lock);
    }
    return negative_control?0:pthread_mutex_lock(lock);
}
static int writer_unlock(pthread_mutex_t *lock) {
    assert(lock==&ios_proc_ident_writer_lock);
    return negative_control?0:pthread_mutex_unlock(lock);
}
#define __sync_synchronize identity_fence
#define pthread_mutex_lock writer_lock
#define pthread_mutex_unlock writer_unlock
''' + register + '\n' + release + r'''
#undef pthread_mutex_lock
#undef pthread_mutex_unlock
#undef __sync_synchronize
static void *old_owner=(void *)(uintptr_t)0x100, *new_owner=(void *)(uintptr_t)0x200;
static void *release_old(void *unused) {
    (void)unused;role=1;ios_proc_ident_release(old_owner);return NULL;
}
static void *register_new(void *unused) {
    (void)unused;role=2;
    SECTION_IMAGE_INFORMATION info={0x8664};ios_register_proc_ident(new_owner,&info);
    pthread_mutex_lock(&phase_lock);register_done=1;pthread_cond_broadcast(&phase_cond);
    pthread_mutex_unlock(&phase_lock);return NULL;
}
static void *register_parallel(void *argument) {
    uintptr_t n=(uintptr_t)argument;
    SECTION_IMAGE_INFORMATION info={(unsigned)(0x8000+n)};
    ios_register_proc_ident((void *)(uintptr_t)(0x100000+n*0x10000),&info);return NULL;
}
int main(int argc,char **argv) {
    (void)argv;negative_control=argc>1;
    SECTION_IMAGE_INFORMATION old={0x14c}, sibling={0xaa64};
    void *sibling_owner=(void *)(uintptr_t)0x300;
    ios_register_proc_ident(old_owner,&old);ios_register_proc_ident(sibling_owner,&sibling);
    pthread_t releaser, registrar;
    assert(!pthread_create(&releaser,NULL,release_old,NULL));
    pthread_mutex_lock(&phase_lock);
    while(!paused_release)pthread_cond_wait(&phase_cond,&phase_lock);
    pthread_mutex_unlock(&phase_lock);
    assert(ios_proc_idents[0].peb==NULL); /* exact original vulnerable publication point */
    assert(!pthread_create(&registrar,NULL,register_new,NULL));
    pthread_mutex_lock(&phase_lock);
    while(negative_control?!register_done:!register_attempted)pthread_cond_wait(&phase_cond,&phase_lock);
    if(!negative_control)assert(!register_done);
    resume_release=1;pthread_cond_broadcast(&phase_cond);pthread_mutex_unlock(&phase_lock);
    assert(!pthread_join(releaser,NULL));assert(!pthread_join(registrar,NULL));
    assert(ios_proc_idents[0].peb==new_owner);
    assert(ios_proc_idents[1].peb==sibling_owner&&ios_proc_idents[1].info.Machine==0xaa64);
    if(negative_control) {
        assert(ios_proc_idents[0].info.Machine==0);
        puts("PASS negative control: old release clears a newly registered native identity without writer serialization");
        return 0;
    }
    assert(ios_proc_idents[0].info.Machine==0x8664);
    memset(ios_proc_idents,0,sizeof(ios_proc_idents));ios_proc_ident_count=0;
    pthread_t writers[64];
    for(uintptr_t i=0;i<64;i++)assert(!pthread_create(&writers[i],NULL,register_parallel,(void *)i));
    for(unsigned i=0;i<64;i++)assert(!pthread_join(writers[i],NULL));
    assert(ios_proc_ident_count==64);
    for(uintptr_t i=0;i<64;i++) {
        unsigned found=0;
        for(unsigned j=0;j<64;j++)if(ios_proc_idents[j].peb==(void *)(uintptr_t)(0x100000+i*0x10000)) {
            assert(ios_proc_idents[j].info.Machine==0x8000+i);found++;
        }
        assert(found==1);
    }
    puts("PASS production identity release/register interleaving preserves successor and sibling; 64 concurrent writers occupy distinct complete slots");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-ident-publication-') as temporary:
    path=Path(temporary);src=path/'publication.c';exe=path/'publication';src.write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread',str(src),'-o',str(exe)],check=True)
    for arguments in ([str(exe),'old-writers'],[str(exe)]):
        result=subprocess.run(arguments,capture_output=True,text=True,timeout=30)
        assert result.returncode==0,result.stdout+result.stderr
        print(result.stdout,end='')
