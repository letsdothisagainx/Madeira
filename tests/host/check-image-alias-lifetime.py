#!/usr/bin/env python3
"""Execute real image deletion/alias retirement against repeated shared mappings."""
import os,re,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[2]
s=(root/'build/ntdll-unix/virtual_ios.c').read_text()
# Compile the actual lock-free guard query with an empty legacy bitmap.
g = (root / 'build/ntdll-unix/fex_code_guards.h').read_text()
guard_bitmap = (root / 'build/ntdll-unix/fex_code_buffer_abi.h').read_text() + '\n' + g[g.index('#define IOS_CODE_GUARD_MAX_POOL'):g.index('static uint64_t ios_code_guard_armed')]

def body(source,marker):
 a=source.index(marker);b=source.index('{',a);n=0
 for t in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]',source[b:],re.S):
  if t[0]=='{':n+=1
  elif t[0]=='}':
   n-=1
   if not n:return source[a:b+t.end()]
 raise AssertionError(marker)
delete=body(s,'static void delete_view( struct file_view *view )')
hook=body(delete,'if ((view->protect & (SEC_IMAGE | VPROT_SYSTEM)) == SEC_IMAGE)')
assert delete.index(hook)<delete.index('unmap_area( view->base, view->size )')
assert delete.index('ios_jit_note_image_unmapped(')<delete.index(hook)
legacy=delete.replace(hook,'').replace('static void delete_view(','static void legacy_delete_view(',1)
code=r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <unistd.h>
#define PAGE 0x4000u
#define SEC_IMAGE 0x1000000u
#define VPROT_SYSTEM 0x2000000u
#define VPROT_ARM64EC 0x4000000u
#define ROUND_SIZE(b,s,m) (((size_t)(s)+((uintptr_t)(b)&(m))+(m))&~(size_t)(m))
static size_t host_page_mask=PAGE-1,host_page_size=PAGE;
struct file_view{void* base;size_t size;unsigned protect;};
static struct{uintptr_t user_va,user_va_end,jit_rw_alias,jit_rx_alias;} ios_jit_anon_aliases[3];
static int ios_jit_anon_alias_count=3,ios_jit_anon_alias_live;
static pthread_mutex_t ios_pool_lock=PTHREAD_MUTEX_INITIALIZER;
static unsigned mono_retired,invalidated,unmapped,deleted;
static int ios_retire_trace_armed,expect_retired;
static void ios_mono_alias_retire(uintptr_t b){(void)b;mono_retired++;}
static int diagnostic(int fd,const char* f,...){(void)fd;(void)f;errno=ERANGE;return 0;}
#define dprintf diagnostic
''' +body(s,'int ios_jit_anon_alias_find_cover(')+'\n'+body(s,'int ios_jit_anon_alias_overlaps(')+'\n'+body(s,'static void ios_jit_anon_alias_retire_range(')+r'''
static unsigned physical_protects;
static int protect_native(void* b,size_t n,int p){physical_protects++;return mprotect(b,n,p);}
static int mprotect_exec(void* b,size_t n,int p){return protect_native(b,n,p);}
#define mprotect protect_native
''' +body(s,'static int ios_protect_alias_run(')+r'''
#undef mprotect
static void ios_vh_note(char c,struct file_view* v){assert(c=='d'&&v->base);}
static void ios_retire_mark(const char* text){(void)text;}
static int ios_jit_image_retire_enabled(void){return 0;}
static void ios_jit_retire_image(void* b,size_t n){(void)b;(void)n;}
static void ios_jit_note_image_unmapped(void* b,size_t n){(void)b;assert(n==0xf000);invalidated++;}
/* No extended fixed-image mappings exist in this fixture. Their actual
 * tombstone/lease behavior executes in check-directx-fixed-image.py. */
void ios_subfloor_release_mapping(unsigned long long real,unsigned long long size) {(void)real;(void)size;}
static void ios_swap_release_range(void* b,size_t n,int c){(void)b;(void)n;assert(!c);}
static void set_page_vprot(void* b,size_t n,int p){(void)b;(void)n;assert(!p);}
static void clear_arm64ec_range(void* b,size_t n){(void)b;(void)n;}
static void unregister_view(struct file_view* v){(void)v;}
static void free_view(struct file_view* v){(void)v;deleted++;}
static void unmap_area(void* base,size_t n){
 void *rw,*rx;assert(invalidated==unmapped+1);
 if(expect_retired)assert(!ios_jit_anon_alias_find_cover((char*)base+0xc000,PAGE,&rw,&rx));
 n=ROUND_SIZE(0,n,host_page_mask);assert(n==0x10000);
 assert(mmap(base,n,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==base);unmapped++;
}
''' +delete+'\n'+legacy+r'''
static void* backing[260];static unsigned backing_count;
static void bind_alias(unsigned slot,void* target){
 FILE* f=tmpfile();assert(f&&!ftruncate(fileno(f),PAGE));
 void *rw=mmap(NULL,PAGE,PROT_READ|PROT_WRITE,MAP_SHARED,fileno(f),0);assert(rw!=MAP_FAILED);
 memcpy(rw,target,PAGE);
 assert(mmap(target,PAGE,PROT_READ,MAP_SHARED|MAP_FIXED,fileno(f),0)==target);fclose(f);
 backing[backing_count++]=rw;
 ios_jit_anon_aliases[slot]=(typeof(ios_jit_anon_aliases[slot])){(uintptr_t)target,(uintptr_t)target+PAGE,(uintptr_t)rw,(uintptr_t)target};
 ios_jit_anon_alias_live++;
}
static uint32_t swap(void* target,uint32_t value){
 void* rw=NULL,*rx=NULL;assert(ios_jit_anon_alias_find_cover(target,4,&rw,&rx));
 return __atomic_exchange_n((uint32_t*)rw,value,__ATOMIC_SEQ_CST);
}
static atomic_int stop;static uint32_t* sibling;
static void* sibling_writer(void* unused){(void)unused;__atomic_add_fetch(sibling,1,__ATOMIC_RELAXED);while(!atomic_load(&stop))__atomic_add_fetch(sibling,1,__ATOMIC_RELAXED);return NULL;}
int main(void){
 unsetenv("MADEIRA_ALIAS_PROT_FORCE_RX");
 void *space=mmap(NULL,6*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(space!=MAP_FAILED);
 uintptr_t base=((uintptr_t)space+PAGE-1)&~(uintptr_t)(PAGE-1);void* tail=(void*)(base+0xc000);
 struct file_view image={(void*)base,0xf000,SEC_IMAGE};
 assert(mmap((void*)base,0x10000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==(void*)base);
 bind_alias(0,tail);assert(!swap((char*)tail+0x100,0xfff95f20));
 assert(*(uint32_t*)((char*)tail+0x100)==0xfff95f20);
 // Negative control: old deletion changes the guest backing but keeps alias.
 legacy_delete_view(&image);
 assert(mmap((void*)base,0x10000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==(void*)base);
 void *rw=NULL,*rx=NULL;assert(ios_jit_anon_alias_find_cover(tail,PAGE,&rw,&rx));
 assert(swap((char*)tail+0x100,0xfff95f20)==0xfff95f20);
 assert(!*(uint32_t*)((char*)tail+0x100)); // current guest branch slot is still NULL
 ios_jit_anon_alias_retire_range((void*)base,0x10000);expect_retired=1;
 // A live sibling's backing and alias must survive every image incarnation.
 void* peer=mmap(NULL,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(peer!=MAP_FAILED);
 bind_alias(1,peer);sibling=(uint32_t*)ios_jit_anon_aliases[1].jit_rw_alias;
 pthread_t worker;assert(!pthread_create(&worker,NULL,sibling_writer,NULL));
 for(unsigned cycle=0;cycle<128;cycle++){
  assert(mmap((void*)base,0x10000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==(void*)base);
  // A fresh image cannot discover any earlier generation's backing.
  assert(!ios_jit_anon_alias_find_cover(tail,PAGE,&rw,&rx));bind_alias(0,tail);
  unsigned prior=physical_protects;
  for(unsigned transition=0;transition<32;transition++){
   errno=EAGAIN;assert(!ios_protect_alias_run((uintptr_t)tail,PAGE,PROT_READ|PROT_EXEC,1,NULL)&&errno==EAGAIN);
  }
  assert(physical_protects==prior); // preserve the live backing, not merely its permissions
  assert(!swap((char*)tail+0x100,0xfff95f20));
  assert(*(uint32_t*)((char*)tail+0x100)==0xfff95f20);
  assert(ios_jit_anon_alias_live==2);
  errno=EAGAIN;delete_view(&image);assert(errno==EAGAIN);
  assert(ios_jit_anon_alias_live==1&&ios_jit_anon_alias_find_cover(peer,PAGE,&rw,&rx)&&rw==sibling);
 }
 atomic_store(&stop,1);pthread_join(worker,NULL);assert(*sibling>0);
 assert(deleted==129&&invalidated==129&&unmapped==129&&mono_retired==129);
 // System image storage is deliberately kept by delete_view. Its live
 // binding must not be retired merely because bookkeeping is detached.
 struct file_view system={peer,0xf000,SEC_IMAGE|VPROT_SYSTEM};
 delete_view(&system);assert(ios_jit_anon_alias_live==1&&unmapped==129&&mono_retired==129);
 assert(ios_jit_anon_alias_find_cover(peer,PAGE,&rw,&rx)&&rw==sibling);
 // The explicit strict comparison still propagates the real kernel error.
 assert(!setenv("MADEIRA_ALIAS_PROT_FORCE_RX","1",1));errno=0;
 assert(ios_protect_alias_run(1,PAGE,PROT_READ,1,NULL)==-1&&errno==EINVAL);
 unsetenv("MADEIRA_ALIAS_PROT_FORCE_RX");
 // Metadata retirement never frees the pool storage out from an observer.
 for(unsigned i=0;i<backing_count;i++)assert(backing[i]);
 for(unsigned i=0;i<backing_count;i++)munmap(backing[i],PAGE);
 munmap(peer,PAGE);munmap(space,6*PAGE);
 puts("PASS actual delete_view/retire/lookup: old guest NULL slot reproduced;128 cryptnet-shaped reloads rebind shared storage before swaps;4KiB tail/16KiB host rounding;sibling writes/alias retained;invalidation precedes retirement and backing replacement;errno preserved;pool storage retained");
}
'''
code = code.replace('#include <stdint.h>', '#include <stdint.h>\n#include <stddef.h>\nstatic void *ios_jit_rx_base_global, *ios_jit_rw_base_global;\nstatic size_t ios_jit_pool_size_global;\n' + guard_bitmap, 1)
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'check.c';p.write_text(code);exe=Path(d)/'check'
 subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-g','-O1','-pthread','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True,timeout=30)
