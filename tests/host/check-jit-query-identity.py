#!/usr/bin/env python3
"""Exercise production VM-query dispatch/identity proof at an OS-query boundary.

The Wine/wineserver query callbacks are fixtures, not a second alias mapper.
The old production entry point, unchanged generic reverse translator, actual
unload invalidation, and corrected production entry point all compile here.
This is not a VAC test or an iOS graphics/game acceptance measurement.
"""
import os
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[2]
path = "build/ntdll-unix/virtual_ios.c"
source = (root / path).read_text()
previous = (root / "tests/host/fixtures/jit-query-identity-d6.c").read_text()


def body(text, marker):
    start = text.index(marker)
    brace = text.index("{", start)
    depth = 0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]', text[brace:], re.S):
        if token[0] == "{":
            depth += 1
        elif token[0] == "}":
            depth -= 1
            if not depth:
                return text[start:brace + token.end()]
    raise AssertionError(marker)


def dispatch(text, name):
    entry = body(text, "NTSTATUS WINAPI NtQueryVirtualMemory(")
    # Compile all real address-query branches and pre-dispatch translation.
    # Private UnixLib loading is outside this fixture's OS-query boundary.
    entry = entry[:entry.index("        case MemoryWineLoadUnixLib:")]
    entry += "        default: status = STATUS_INVALID_INFO_CLASS; return status;\n    }\n}\n"
    return entry.replace("NtQueryVirtualMemory(", name + "(", 1)


# The historical function is checked in so a shallow CI checkout can reproduce
# the real old path. Verify both its fixed digest and, when available, the
# actual D6 source object. This is a source fixture, not a simulated decoder.
previous_entry = body(previous, "NTSTATUS WINAPI NtQueryVirtualMemory(")
assert hashlib.sha256(previous_entry.encode()).hexdigest() == "2ecf222e5dc7ead4003ea5446af24f18e29d14b3495e29d93b1a8c010fa1e16d"
historical = subprocess.run(["git", "show", "d6d40213695db7b1ab0f7a9b1dd95edbcda0d7ec:" + path], cwd=root, text=True, capture_output=True)
if historical.returncode == 0:
    assert previous_entry == body(historical.stdout, "NTSTATUS WINAPI NtQueryVirtualMemory(")
    assert body(source, "void *ios_jit_reverse_translate_addr(") == body(historical.stdout, "void *ios_jit_reverse_translate_addr(")
assert "addr = ios_jit_reverse_translate_addr( addr );" in source
mapping = body(source, "struct ios_jit_mapping {") + ";\n"
proof = body(source, "struct ios_jit_query_identity\n") + ";\n"
code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#define WINE_IOS 1
#define WINAPI
#define TRACE(...) ((void)(trace_address=(uintptr_t)addr))
#define IOS_JIT_MAX_MAPPINGS 512
#define IOS_JIT_MAX_CODE_RANGES 96
typedef uint32_t NTSTATUS;
typedef void *HANDLE, *PVOID;
typedef const void *LPCVOID;
typedef size_t SIZE_T;
typedef uintptr_t ULONG_PTR;
typedef struct { struct { HANDLE UniqueProcess; } ClientId; } TEB;
typedef struct { ULONG_PTR UniqueProcessId; } PROCESS_BASIC_INFORMATION;
#define ProcessBasicInformation 0
/* Actual Wine/owned private class values; the public ordering is not dense. */
typedef enum {MemoryBasicInformation=0,MemoryRegionInformation=3,
 MemoryWorkingSetExInformation=4,MemoryImageInformation=6,
 MemoryMappedFilenameInformation=2,MemoryWineLoadUnixLib=1000,
 MemoryWineLoadUnixLibWow64=1001,MemoryWineLoadUnixLibByName=1002,
 MemoryWineLoadUnixLibByNameWow64=1003,MemoryWineUnloadUnixLib=1004,
 MemoryWineIosJitPoolAddress=1005,MemoryWineIosSubfloorWindow=1006} MEMORY_INFORMATION_CLASS;
#define STATUS_SUCCESS 0u
#define STATUS_BUFFER_OVERFLOW 0x80000005u
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004u
#define STATUS_INVALID_INFO_CLASS 0xc0000003u
#define STATUS_INVALID_ADDRESS 0xc0000141u
#define STATUS_ACCESS_DENIED 0xc0000022u
#define STATUS_INVALID_HANDLE 0xc0000008u
#define NtCurrentProcess() ((HANDLE)(intptr_t)-1)
#define RX ((uintptr_t)0x300100000ull)
#define PE ((uintptr_t)0x140000000ull)
#define OWN ((void*)(uintptr_t)0x500310000ull)
#define OTHER ((void*)(uintptr_t)0x400310000ull)
''' + mapping + r'''
static struct ios_jit_mapping ios_jit_mappings[IOS_JIT_MAX_MAPPINGS];
static int ios_jit_mapping_count;
static uintptr_t trace_address;
static pthread_mutex_t ios_pool_lock=PTHREAD_MUTEX_INITIALIZER;
static void *current_owner=OWN;
static TEB current_teb={{(HANDLE)(uintptr_t)0x324}}, *active_teb=&current_teb;
static unsigned process_info_calls;
static TEB *NtCurrentTeb(void) { return active_teb; }
static NTSTATUS NtQueryInformationProcess(HANDLE process,unsigned cls,void *out,size_t len,void *retlen) {
 assert(cls==ProcessBasicInformation&&len==sizeof(PROCESS_BASIC_INFORMATION)&&!retlen);
 assert(process!=NtCurrentProcess());process_info_calls++;
 if(process==(HANDLE)43)return STATUS_INVALID_HANDLE;
 if(process==(HANDLE)44)return STATUS_ACCESS_DENIED;
 PROCESS_BASIC_INFORMATION *pbi=out;
 pbi->UniqueProcessId=process==(HANDLE)41||process==(HANDLE)45 ? 0x324 : 0x328;
 return STATUS_SUCCESS;
}
static unsigned long long current_lease=23, quiescent_lease;
static int guarded, low_calls, subfloor_calls, reload_mode=1;
static void *ios_jit_current_peb(void) { return current_owner; }
static unsigned long long ios_thread_process_lease(void *owner,int create) {
 assert(!create); return owner==current_owner ? __atomic_load_n(&current_lease,__ATOMIC_ACQUIRE) : 0;
}
static unsigned long long ios_thread_process_quiescent_lease(void *owner) {
 return owner==current_owner ? __atomic_load_n(&quiescent_lease,__ATOMIC_ACQUIRE) : 0;
}
static int ios_jit_code_guard_contains(uintptr_t a,size_t n) { assert(n==1);return guarded&&a>=RX&&a<RX+0x10000; }
static int ios_image_reload_mode(void) { return reload_mode; }
static int ios_lowalloc_translate(unsigned long long a,size_t n,unsigned long long *out,void *owner) {
 (void)a;(void)out;(void)owner;assert(n==1);low_calls++;return 0;
}
static int ios_subfloor_image_translate(unsigned long long a,size_t n,unsigned long long *out) {
 (void)a;(void)out;assert(n==1);subfloor_calls++;return 0;
}
int ios_subfloor_enum(int idx,unsigned long long *lo,unsigned long long *re,unsigned long long *sz,void **owner) {
 (void)idx;(void)lo;(void)re;(void)sz;(void)owner;return 0;
}
''' + body(source, "void *ios_jit_reverse_translate_addr(") + "\n" + body(source, "static void ios_jit_note_image_unmapped(") + r'''
/* These are the normal Wine/wineserver query boundary. They deliberately
 * know nothing about RX aliases: only the actual PE interval has a filename
 * and MEM_IMAGE metadata. The host pool has ordinary private reservation
 * metadata in this OS-boundary fixture, not a claim about actual iOS pool
 * metadata and not a manufactured PE identity or publisher trust result. */
struct result { uintptr_t base,allocation;unsigned type,protect;char name[64]; };
static uintptr_t queried;
static HANDLE queried_process;
static unsigned kernel_calls, forced_status, view_present=1, replacement;
static unsigned race_kind;
struct working_set { uintptr_t address, attributes; };
static int working_set_array_mode;
static struct working_set *expected_working_set;
/* Darwin does not provide pthread_barrier_t. Use a reusable generation
 * barrier with real mutex/condition synchronization on every host platform;
 * spurious wakes cannot let a query return before its concurrent mutation. */
struct query_barrier {
 pthread_mutex_t mutex;
 pthread_cond_t condition;
 unsigned participants, waiting, generation;
};
static void query_barrier_init(struct query_barrier *barrier,unsigned participants) {
 assert(participants>0);
 assert(!pthread_mutex_init(&barrier->mutex,NULL));
 assert(!pthread_cond_init(&barrier->condition,NULL));
 barrier->participants=participants;barrier->waiting=0;barrier->generation=0;
}
static void query_barrier_wait(struct query_barrier *barrier) {
 assert(!pthread_mutex_lock(&barrier->mutex));
 unsigned generation=barrier->generation;
 if(++barrier->waiting==barrier->participants) {
  barrier->waiting=0;barrier->generation++;
  assert(!pthread_cond_broadcast(&barrier->condition));
 } else while(generation==barrier->generation)
  assert(!pthread_cond_wait(&barrier->condition,&barrier->mutex));
 assert(!pthread_mutex_unlock(&barrier->mutex));
}
static void query_barrier_destroy(struct query_barrier *barrier) {
 assert(!barrier->waiting);
 assert(!pthread_cond_destroy(&barrier->condition));
 assert(!pthread_mutex_destroy(&barrier->mutex));
}
static struct query_barrier entered, changed;
static void *invalidate_during_query(void *unused) {
 (void)unused;query_barrier_wait(&entered);
 if(race_kind==1) ios_jit_note_image_unmapped((void*)PE,0x10000);
 else if(race_kind==2) {
  __atomic_store_n(&ios_jit_mappings[0].generation,0,__ATOMIC_RELEASE);
  __atomic_store_n(&ios_jit_mappings[0].generation,24,__ATOMIC_RELEASE);
 } else if(race_kind==3) __atomic_store_n(&current_lease,24,__ATOMIC_RELEASE);
 else if(race_kind==4) __atomic_store_n(&quiescent_lease,23,__ATOMIC_RELEASE);
 else if(race_kind==5) __atomic_store_n(&ios_jit_mappings[0].owner_peb,OTHER,__ATOMIC_RELEASE);
 else if(race_kind==6) __atomic_store_n(&ios_jit_mappings[0].size,0,__ATOMIC_RELEASE);
 query_barrier_wait(&changed);return NULL;
}
static unsigned query_kernel(HANDLE process,LPCVOID address,void *buffer,SIZE_T len,SIZE_T *retlen,unsigned cls) {
 queried=(uintptr_t)address;queried_process=process;kernel_calls++;
 assert(!pthread_mutex_trylock(&ios_pool_lock));pthread_mutex_unlock(&ios_pool_lock);
 if(forced_status && forced_status!=STATUS_BUFFER_OVERFLOW)return forced_status;
 if(len<sizeof(struct result))return STATUS_INFO_LENGTH_MISMATCH;
 struct result *out=buffer;memset(out,0,sizeof(*out));
 if(queried>=PE&&queried<PE+0x10000&&view_present) {
  out->base=queried&~(uintptr_t)0xfff;out->allocation=PE;out->type=0x1000000;out->protect=0x20;
  strcpy(out->name,replacement?"replacement.dll":"legitimate.dll");
 } else if(cls==MemoryMappedFilenameInformation)return STATUS_INVALID_ADDRESS;
 else if(cls!=MemoryImageInformation) {
  out->base=queried&~(uintptr_t)0xfff;out->allocation=RX;out->type=0x20000;out->protect=1;
 }
 if(retlen)*retlen=sizeof(*out);
 if(race_kind){query_barrier_wait(&entered);query_barrier_wait(&changed);}
 return forced_status;
}
#define QUERY_CALLBACK(name,cls) static unsigned name(HANDLE p,LPCVOID a,void*b,SIZE_T n,SIZE_T*r){return query_kernel(p,a,b,n,r,cls);}
QUERY_CALLBACK(get_basic_memory_info,MemoryBasicInformation)
QUERY_CALLBACK(get_memory_section_name,MemoryMappedFilenameInformation)
QUERY_CALLBACK(get_memory_region_info,MemoryRegionInformation)
QUERY_CALLBACK(get_memory_image_info,MemoryImageInformation)
static unsigned get_working_set_ex(HANDLE p,LPCVOID a,void *b,SIZE_T n,SIZE_T *r) {
 if(!working_set_array_mode)return query_kernel(p,a,b,n,r,MemoryWorkingSetExInformation);
 assert(p==NtCurrentProcess()&&!a&&b==expected_working_set&&n==2*sizeof(*expected_working_set));
 assert(expected_working_set[0].address==RX+0x1234&&expected_working_set[1].address==PE+0x4321);
 assert(expected_working_set[0].attributes==0&&expected_working_set[1].attributes==0);
 expected_working_set[0].attributes=0x123;expected_working_set[1].attributes=0x456;
 if(r)*r=n;
 return STATUS_SUCCESS;
}
''' + proof + "\n" + "\n".join(body(source, marker) for marker in [
    "static int ios_jit_query_self_process(",
    "static int ios_jit_query_identity_valid(",
    "static LPCVOID ios_jit_query_identity_begin(",
    "static NTSTATUS ios_jit_query_identity_finish(",
]) + "\n" + dispatch(previous, "previous_NtQueryVirtualMemory") + "\n" + dispatch(source, "fixed_NtQueryVirtualMemory") + r'''
static void reset(void) {
 memset(ios_jit_mappings,0,sizeof(ios_jit_mappings));ios_jit_mapping_count=1;
 ios_jit_mappings[0]=(struct ios_jit_mapping){.generation=23,.pe_base=(void*)PE,
  .jit_base=(void*)RX,.size=0x10000,.owner_peb=OWN,.map_peb=OWN};
 current_owner=OWN;current_lease=23;quiescent_lease=0;view_present=1;reload_mode=1;
 active_teb=&current_teb;current_teb.ClientId.UniqueProcess=(HANDLE)(uintptr_t)0x324;process_info_calls=0;
 replacement=guarded=low_calls=subfloor_calls=kernel_calls=forced_status=race_kind=0;
 working_set_array_mode=0;expected_working_set=NULL;
}
static NTSTATUS query(unsigned cls,struct result *r) {
 SIZE_T len=0;return fixed_NtQueryVirtualMemory(NtCurrentProcess(),(void*)(RX+0x1234),cls,r,sizeof(*r),&len);
}
int main(void) {
 struct result out;SIZE_T length;
 /* Failing-before reproduction: actual unload mark leaves the permissive
  * unwind mapping intact; old VM query borrows a replacement file identity. */
 reset();ios_jit_note_image_unmapped((void*)PE,0x10000);replacement=1;
 assert(!ios_jit_mappings[0].generation&&ios_jit_mappings[0].unmapped);
 assert((uintptr_t)ios_jit_reverse_translate_addr((void*)(RX+0x1234))==PE+0x1234);
 assert(!previous_NtQueryVirtualMemory(NtCurrentProcess(),(void*)(RX+0x1234),MemoryMappedFilenameInformation,&out,sizeof(out),&length));
 assert(!strcmp(out.name,"replacement.dll"));
 puts("BEFORE: actual production unload+VM dispatch incorrectly reports replacement.dll for retired RX copy");
 assert(query(MemoryMappedFilenameInformation,&out)==STATUS_INVALID_ADDRESS&&queried==RX+0x1234);
 assert(!query(MemoryBasicInformation,&out)&&out.type==0x20000&&out.protect==1&&out.allocation==RX);
 assert(!query(MemoryImageInformation,&out)&&!out.allocation&&!out.name[0]);
 reset();reload_mode=0;ios_jit_note_image_unmapped((void*)PE,0x10000);replacement=1;
 assert(ios_jit_mappings[0].generation==23&&!ios_jit_mappings[0].unmapped);
 assert(query(MemoryMappedFilenameInformation,&out)==STATUS_INVALID_ADDRESS&&queried==RX+0x1234);
 /* Architectures do not alter legitimate metadata offsets/provenance. */
 const unsigned machines[]={0x014c,0x8664,0xa641,0xaa64};
 const unsigned classes[]={MemoryBasicInformation,MemoryMappedFilenameInformation,
  MemoryRegionInformation,MemoryImageInformation,MemoryWorkingSetExInformation};
 for(unsigned m=0;m<4;m++)for(unsigned c=0;c<5;c++) {
  unsigned cls=classes[c];
  reset();ios_jit_mappings[0].machine_cached=machines[m];
  assert(!query(cls,&out));
  if(cls==MemoryWorkingSetExInformation)assert(queried==RX+0x1234&&!low_calls&&!subfloor_calls);
  else assert(queried==PE+0x1234&&!strcmp(out.name,"legitimate.dll")&&out.type==0x1000000&&out.protect==0x20);
 }
 /* Windows working-set queries pass NULL addr and an in/out array. Preserve
  * the array object, its raw input addresses, and the backend's attributes. */
 reset();struct working_set working_set[2]={{RX+0x1234,0},{PE+0x4321,0}};
 working_set_array_mode=1;expected_working_set=working_set;
 assert(!fixed_NtQueryVirtualMemory(NtCurrentProcess(),NULL,MemoryWorkingSetExInformation,working_set,sizeof(working_set),&length));
 assert(working_set[0].address==RX+0x1234&&working_set[1].address==PE+0x4321);
 assert(working_set[0].attributes==0x123&&working_set[1].attributes==0x456&&length==sizeof(working_set));
 assert(!low_calls&&!subfloor_calls);
 /* All six supported private Wine loader/JIT protocols retain the old
  * pre-dispatch pointer contract, including ByName and already-RX pointers.
  * Their actual implementation is not simulated at this test boundary. */
 for(unsigned cls=1000;cls<=1005;cls++) {
  reset();assert(previous_NtQueryVirtualMemory(NtCurrentProcess(),(void*)(RX+0x1234),cls,&out,sizeof(out),&length)==STATUS_INVALID_INFO_CLASS);
  assert(trace_address==PE+0x1234&&low_calls==1&&subfloor_calls==1);
  reset();assert(fixed_NtQueryVirtualMemory(NtCurrentProcess(),(void*)(RX+0x1234),cls,&out,sizeof(out),&length)==STATUS_INVALID_INFO_CLASS);
  assert(trace_address==PE+0x1234&&low_calls==1&&subfloor_calls==1);
 }
 /* Explicit shared/default ownership, real source-view check, and foreign
  * private identity rejection. No compatibility module is hidden. */
 reset();ios_jit_mappings[0].owner_peb=NULL;ios_jit_mappings[0].map_peb=OTHER;
 assert(!query(MemoryMappedFilenameInformation,&out)&&queried==PE+0x1234);
 view_present=0;assert(query(MemoryMappedFilenameInformation,&out)==STATUS_INVALID_ADDRESS);
 for(unsigned invalid=0;invalid<10;invalid++) {
  reset();
  switch(invalid){case 0:ios_jit_mappings[0].owner_peb=OTHER;break;
   case 1:ios_jit_mappings[0].map_peb=OTHER;break;case 2:current_lease=0;break;
   case 3:quiescent_lease=23;break;case 4:ios_jit_mappings[0].generation=0;break;
   case 5:ios_jit_mappings[0].unmapped=1;break;case 6:ios_jit_mappings[0].size=0;break;
   case 7:guarded=1;break;case 8:ios_jit_mappings[0].pe_base=(void*)(UINTPTR_MAX-0x100);break;
   case 9:current_owner=NULL;break;}
  assert(query(MemoryMappedFilenameInformation,&out)==STATUS_INVALID_ADDRESS&&queried==RX+0x1234);
 }
 /* A remote process sees its own server mapping/access decision. The
  * caller's pool, low-guest and subfloor tables must never rewrite its VA. */
 reset();forced_status=STATUS_ACCESS_DENIED;
 assert(fixed_NtQueryVirtualMemory((HANDLE)42,(void*)(RX+0x1234),MemoryMappedFilenameInformation,&out,sizeof(out),&length)==STATUS_ACCESS_DENIED);
 assert(queried_process==(HANDLE)42&&queried==RX+0x1234&&!low_calls&&!subfloor_calls);
 /* An actual OpenProcess(self) handle keeps exactly its own access checks.
  * It resolves the same live PE identity without substituting pseudo-self. */
 for(unsigned c=0;c<4;c++) {
  reset();assert(!fixed_NtQueryVirtualMemory((HANDLE)41,(void*)(RX+0x1234),classes[c],&out,sizeof(out),&length));
  assert(process_info_calls==1&&queried_process==(HANDLE)41&&queried==PE+0x1234);
 }
 reset();assert(!query(MemoryBasicInformation,&out)&&!process_info_calls);
 for(unsigned handle=43;handle<=45;handle++) {
  reset();forced_status=handle==43?STATUS_INVALID_HANDLE:STATUS_ACCESS_DENIED;
  assert(fixed_NtQueryVirtualMemory((HANDLE)(uintptr_t)handle,(void*)(RX+0x1234),MemoryMappedFilenameInformation,&out,sizeof(out),&length)==forced_status);
  assert(queried_process==(HANDLE)(uintptr_t)handle&&process_info_calls==1);
  assert(queried==(handle==45?PE+0x1234:RX+0x1234));
 }
 for(unsigned unknown=0;unknown<2;unknown++) {
  reset();if(unknown)active_teb=NULL;else current_teb.ClientId.UniqueProcess=NULL;
  assert(fixed_NtQueryVirtualMemory((HANDLE)41,(void*)(RX+0x1234),MemoryMappedFilenameInformation,&out,sizeof(out),&length)==STATUS_INVALID_ADDRESS);
  assert(!process_info_calls&&queried==RX+0x1234&&!low_calls&&!subfloor_calls);
 }
 reset();assert(fixed_NtQueryVirtualMemory(NtCurrentProcess(),(void*)(RX+0x1234),MemoryBasicInformation,&out,1,&length)==STATUS_INFO_LENGTH_MISMATCH);
 reset();forced_status=STATUS_BUFFER_OVERFLOW;assert(query(MemoryMappedFilenameInformation,&out)==STATUS_BUFFER_OVERFLOW);
 /* OS query runs concurrently with teardown/republication/owner reuse.
  * Exercise all four actual production dispatch branches. No lock spans IPC. */
 for(unsigned c=0;c<4;c++)
  for(unsigned race=1;race<=6;race++) {
   unsigned cls=classes[c];
   reset();race_kind=race;pthread_t worker;
   query_barrier_init(&entered,2);query_barrier_init(&changed,2);
   assert(!pthread_create(&worker,NULL,invalidate_during_query,NULL));
   assert(query(cls,&out)==STATUS_INVALID_ADDRESS);
   assert(!pthread_join(worker,NULL));query_barrier_destroy(&entered);query_barrier_destroy(&changed);
  }
 reset();ios_jit_mapping_count=IOS_JIT_MAX_MAPPINGS+1;assert(query(MemoryMappedFilenameInformation,&out)==STATUS_INVALID_ADDRESS);
 reset();assert(fixed_NtQueryVirtualMemory(NtCurrentProcess(),(void*)0x12340000,MemoryMappedFilenameInformation,&out,sizeof(out),&length)==STATUS_INVALID_ADDRESS&&queried==0x12340000);
 puts("AFTER: production query identity/dispatch PASS: live shared/private and mixed PE architectures; real backend errors/metadata; retired/foreign/guarded/unmapped rejection; remote and working-set isolation; concurrent unload, generation ABA, process lease, owner and size changes");
}
'''

with tempfile.TemporaryDirectory() as directory:
    source_path = Path(directory) / "query.c"
    executable = Path(directory) / "query"
    source_path.write_text(code)
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-g", "-O1", "-pthread",
                    "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
                    "-fno-sanitize-recover=all", str(source_path), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=30)
