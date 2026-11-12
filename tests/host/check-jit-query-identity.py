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
self_only = (root / "tests/host/fixtures/jit-query-identity-57.c").read_text()
thread_source = (root / "build/ntdll-unix/thread_ios.c").read_text()


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
self_only_body = self_only[self_only.index('#ifdef WINE_IOS'):].rstrip('\n')
assert hashlib.sha256(self_only_body.encode()).hexdigest() == "e37a9585c60eafac402e735848899d5450e6a40b2d04418ffd19a2b73cd6d4eb"
query_lease = body(thread_source, "unsigned long long ios_thread_process_query_lease(")
assert "pthread_mutex_lock" in query_lease and "trylock" not in query_lease
assert not re.search(r"ios_native_link|ios_thread_group_locked|SERVER_START_REQ|NtQuery|NtAllocate|mmap", query_lease)
self_only_helpers = self_only_body[:self_only_body.index('NTSTATUS WINAPI NtQueryVirtualMemory(')]
self_only_helpers = self_only_helpers.replace('ios_jit_query_', 'previous57_ios_jit_query_')
self_only_dispatch = dispatch(self_only, "self_only_NtQueryVirtualMemory").replace('ios_jit_query_', 'previous57_ios_jit_query_')
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
#include <errno.h>
#include <sched.h>
#define WINE_IOS 1
#define WINAPI
#define TRACE(...) ((void)(trace_address=(uintptr_t)addr))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define IOS_JIT_MAX_MAPPINGS 512
#define IOS_JIT_MAX_CODE_RANGES 96
#define IOS_JIT_MAX_X64_WRITE_RANGES 32
struct madeira_pe_x64_span { size_t offset, size; };
typedef uint32_t NTSTATUS;
typedef void *HANDLE, *PVOID;
typedef const void *LPCVOID;
typedef size_t SIZE_T;
typedef uintptr_t ULONG_PTR;
typedef struct { struct { HANDLE UniqueProcess; } ClientId; } TEB;
typedef struct { ULONG_PTR UniqueProcessId; void *PebBaseAddress; } PROCESS_BASIC_INFORMATION;
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
#define THIRD ((void*)(uintptr_t)0x600310000ull)
''' + mapping + r'''
static struct ios_jit_mapping ios_jit_mappings[IOS_JIT_MAX_MAPPINGS];
static int ios_jit_mapping_count;
static uintptr_t trace_address;
static pthread_mutex_t ios_pool_lock=PTHREAD_MUTEX_INITIALIZER;
static void *current_owner=OWN;
static TEB current_teb={{(HANDLE)(uintptr_t)0x324}}, *active_teb=&current_teb;
static unsigned process_info_calls;
static unsigned canonical_info_calls;
static void *canonical_owner_override;
static unsigned canonical_pid_override;
static unsigned old_wow64_presentation;
static void *last_pbi_peb;
static TEB *NtCurrentTeb(void) { return active_teb; }
static NTSTATUS NtQueryInformationProcess(HANDLE process,unsigned cls,void *out,size_t len,void *retlen) {
 assert(cls==ProcessBasicInformation&&len==sizeof(PROCESS_BASIC_INFORMATION)&&!retlen);
 assert(process!=NtCurrentProcess());process_info_calls++;
 if(process==(HANDLE)43)return STATUS_INVALID_HANDLE;
 if(process==(HANDLE)44)return STATUS_ACCESS_DENIED;
 PROCESS_BASIC_INFORMATION *pbi=out;
 pbi->UniqueProcessId=process==(HANDLE)41||process==(HANDLE)45 ? 0x324 : process==(HANDLE)46?0x32c:0x328;
 pbi->PebBaseAddress=process==(HANDLE)41||process==(HANDLE)45 ? OWN : process==(HANDLE)46?THIRD:OTHER;
 if(old_wow64_presentation)pbi->PebBaseAddress=process==(HANDLE)46?(void*)((uintptr_t)THIRD+0x1000):NULL;
 last_pbi_peb=pbi->PebBaseAddress;
 return STATUS_SUCCESS;
}
/* The canonical server identity precedes public PBI's optional old-WoW64
 * +0x1000/NULL presentation. This request never checks guest PE pointers. */
struct query_request {HANDLE handle;};
struct query_reply {uintptr_t peb;unsigned pid;};
static struct query_reply *active_reply;
#define SERVER_START_REQ(name) do {struct query_request request={0}, *req=&request;struct query_reply reply_data={0}, *reply=&reply_data;active_reply=reply;
#define SERVER_END_REQ }while(0)
static HANDLE wine_server_obj_handle(HANDLE handle){return handle;}
static void *wine_server_get_ptr(uintptr_t address){return (void*)address;}
static NTSTATUS wine_server_call(struct query_request *request) {
 canonical_info_calls++;
 if(request->handle==(HANDLE)43)return STATUS_INVALID_HANDLE;
 if(request->handle==(HANDLE)44)return STATUS_ACCESS_DENIED;
 int self=request->handle==(HANDLE)41||request->handle==(HANDLE)45;
 active_reply->peb=(uintptr_t)(self?OWN:request->handle==(HANDLE)46?THIRD:OTHER);
 active_reply->pid=self?0x324:request->handle==(HANDLE)46?0x32c:0x328;
 if(canonical_owner_override)active_reply->peb=(uintptr_t)canonical_owner_override;
 if(canonical_pid_override)active_reply->pid=canonical_pid_override;
 /* Raw server fields intentionally ignore old_wow64_presentation. */
 (void)old_wow64_presentation;
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
/* Compile the actual passive production registry lookup as well. No caller
 * thread adoption or lifecycle implementation is substituted in this test. */
struct ios_thread_group {void *owner;unsigned long long lease;unsigned pid;int exiting,reclaimed;unsigned native_references;};
static struct ios_thread_group ios_thread_groups[64];
static pthread_mutex_t ios_thread_group_mutex=PTHREAD_MUTEX_INITIALIZER;
''' + body(thread_source, "unsigned long long ios_thread_process_query_lease(") + "\n" + body(source, "void *ios_jit_reverse_translate_addr(") + "\n" + body(source, "static void ios_jit_note_image_unmapped(") + r'''
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
static unsigned race_group;
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
 } else if(race_kind==3) {
  __atomic_store_n(&current_lease,24,__ATOMIC_RELEASE);
  pthread_mutex_lock(&ios_thread_group_mutex);ios_thread_groups[race_group].lease++;pthread_mutex_unlock(&ios_thread_group_mutex);
 } else if(race_kind==4) {
  __atomic_store_n(&quiescent_lease,23,__ATOMIC_RELEASE);
  pthread_mutex_lock(&ios_thread_group_mutex);ios_thread_groups[race_group].exiting=1;ios_thread_groups[race_group].reclaimed=1;pthread_mutex_unlock(&ios_thread_group_mutex);
 }
 else if(race_kind==5) __atomic_store_n(&ios_jit_mappings[0].owner_peb,OTHER,__ATOMIC_RELEASE);
 else if(race_kind==6) __atomic_store_n(&ios_jit_mappings[0].size,0,__ATOMIC_RELEASE);
 else if(race_kind==7) {
  pthread_mutex_lock(&ios_thread_group_mutex);ios_thread_groups[race_group].pid++;pthread_mutex_unlock(&ios_thread_group_mutex);
 } else if(race_kind==8) {
  canonical_owner_override=race_group?OWN:OTHER;canonical_pid_override=race_group?0x324:0x328;
 }
 query_barrier_wait(&changed);return NULL;
}
static unsigned query_kernel(HANDLE process,LPCVOID address,void *buffer,SIZE_T len,SIZE_T *retlen,unsigned cls) {
 queried=(uintptr_t)address;queried_process=process;kernel_calls++;
 assert(!pthread_mutex_trylock(&ios_pool_lock));pthread_mutex_unlock(&ios_pool_lock);
 assert(!pthread_mutex_trylock(&ios_thread_group_mutex));pthread_mutex_unlock(&ios_thread_group_mutex);
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
    "static int ios_jit_query_target_process(",
    "static int ios_jit_query_self_process(",
    "static int ios_jit_query_identity_valid(",
    "static LPCVOID ios_jit_query_identity_begin(",
    "static NTSTATUS ios_jit_query_identity_finish(",
]) + "\n" + self_only_helpers + "\n" + self_only_dispatch + "\n" + dispatch(previous, "previous_NtQueryVirtualMemory") + "\n" + dispatch(source, "fixed_NtQueryVirtualMemory") + r'''
static void reset(void) {
 memset(ios_jit_mappings,0,sizeof(ios_jit_mappings));ios_jit_mapping_count=1;
 ios_jit_mappings[0]=(struct ios_jit_mapping){.generation=23,.pe_base=(void*)PE,
  .jit_base=(void*)RX,.size=0x10000,.owner_peb=OWN,.map_peb=OWN};
 current_owner=OWN;current_lease=23;quiescent_lease=0;view_present=1;reload_mode=1;
 active_teb=&current_teb;current_teb.ClientId.UniqueProcess=(HANDLE)(uintptr_t)0x324;process_info_calls=0;
 memset(ios_thread_groups,0,sizeof(ios_thread_groups));
 ios_thread_groups[0]=(struct ios_thread_group){OWN,23,0x324,0,0,1};
 ios_thread_groups[1]=(struct ios_thread_group){OTHER,31,0x328,0,0,7};
 ios_thread_groups[2]=(struct ios_thread_group){THIRD,41,0x32c,0,0,3};
 canonical_info_calls=0;canonical_owner_override=NULL;canonical_pid_override=old_wow64_presentation=race_group=0;
 last_pbi_peb=NULL;
 replacement=guarded=low_calls=subfloor_calls=kernel_calls=forced_status=race_kind=0;
 working_set_array_mode=0;expected_working_set=NULL;
}
static NTSTATUS query(unsigned cls,struct result *r) {
 SIZE_T len=0;return fixed_NtQueryVirtualMemory(NtCurrentProcess(),(void*)(RX+0x1234),cls,r,sizeof(*r),&len);
}
static atomic_uint lease_query_entered, lease_query_done;
static unsigned long long blocked_lease;
static void *lease_query_worker(void *unused) {
 (void)unused;atomic_store(&lease_query_entered,1);
 blocked_lease=ios_thread_process_query_lease(OTHER,0x328);
 atomic_store(&lease_query_done,1);return NULL;
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
 /* Direct remote Filename/Image queries regressed in 57: an authorized
  * target's own live private alias lost its target image identity. Basic
  * uses a target APC (which can translate there); remote Region is currently
  * unsupported. This flat OS fixture does not claim otherwise. */
 const unsigned remote_classes[]={MemoryMappedFilenameInformation,MemoryImageInformation};
 for(unsigned c=0;c<2;c++) {
  reset();ios_jit_mappings[0].owner_peb=OTHER;ios_jit_mappings[0].map_peb=OTHER;
  assert(!previous_NtQueryVirtualMemory((HANDLE)42,(void*)(RX+0x1234),remote_classes[c],&out,sizeof(out),&length));
  assert(queried_process==(HANDLE)42&&queried==PE+0x1234&&out.allocation==PE);
  NTSTATUS regressed=self_only_NtQueryVirtualMemory((HANDLE)42,(void*)(RX+0x1234),remote_classes[c],&out,sizeof(out),&length);
  assert(queried==RX+0x1234);
  if(c==0)assert(regressed==STATUS_INVALID_ADDRESS);else assert(!regressed&&!out.allocation);
  low_calls=subfloor_calls=0;
  assert(!fixed_NtQueryVirtualMemory((HANDLE)42,(void*)(RX+0x1234),remote_classes[c],&out,sizeof(out),&length));
  assert(queried_process==(HANDLE)42&&queried==PE+0x1234&&out.allocation==PE&&!low_calls&&!subfloor_calls);
 }
 puts("REMOTE BEFORE/AFTER: D6 identifies target live image; 57 self-only loses direct remote Filename/Image identity; corrected target proof preserves actual backend handle and restores identity");
 for(unsigned old_wow=0;old_wow<2;old_wow++)for(unsigned target=42;target<=46;target+=4) {
  reset();old_wow64_presentation=old_wow;
  void *target_owner=target==46?THIRD:OTHER;
  ios_jit_mappings[0].owner_peb=ios_jit_mappings[0].map_peb=target_owner;
  assert(!fixed_NtQueryVirtualMemory((HANDLE)(uintptr_t)target,(void*)(RX+0x1234),MemoryMappedFilenameInformation,&out,sizeof(out),&length));
  assert(queried_process==(HANDLE)(uintptr_t)target&&queried==PE+0x1234&&!low_calls&&!subfloor_calls);
  if(old_wow)assert(last_pbi_peb==(target==46?(void*)((uintptr_t)THIRD+0x1000):NULL));
 }
 /* Missing/foreign/stale owners never inherit the caller's alias rights. */
 for(unsigned invalid=0;invalid<8;invalid++) {
  reset();ios_jit_mappings[0].owner_peb=ios_jit_mappings[0].map_peb=OTHER;
  switch(invalid){case 0:ios_jit_mappings[0].owner_peb=OWN;break;
   case 1:ios_jit_mappings[0].map_peb=OWN;break;
   case 2:ios_thread_groups[1].exiting=1;break;
   case 3:ios_thread_groups[1].reclaimed=1;break;
   case 4:ios_thread_groups[1].lease=0;break;
   case 5:canonical_pid_override=0x444;break;
   case 6:canonical_owner_override=(void*)(uintptr_t)0x777700000;break;
   case 7:ios_jit_mappings[0].unmapped=1;ios_jit_mappings[0].generation=0;break;}
  assert(fixed_NtQueryVirtualMemory((HANDLE)42,(void*)(RX+0x1234),MemoryMappedFilenameInformation,&out,sizeof(out),&length)==STATUS_INVALID_ADDRESS);
  assert(queried==RX+0x1234&&queried_process==(HANDLE)42&&!low_calls&&!subfloor_calls);
 }
 reset();ios_jit_mappings[0].owner_peb=NULL;
 assert(!fixed_NtQueryVirtualMemory((HANDLE)42,(void*)(RX+0x1234),MemoryMappedFilenameInformation,&out,sizeof(out),&length));
 assert(queried==PE+0x1234&&queried_process==(HANDLE)42);
 reset();ios_jit_mappings[0].owner_peb=ios_jit_mappings[0].map_peb=OTHER;forced_status=STATUS_ACCESS_DENIED;
 assert(fixed_NtQueryVirtualMemory((HANDLE)42,(void*)(RX+0x1234),MemoryMappedFilenameInformation,&out,sizeof(out),&length)==STATUS_ACCESS_DENIED);
 assert(queried==PE+0x1234&&queried_process==(HANDLE)42);
 /* Registry contention waits for a real passive snapshot; it cannot turn
  * an active target into a missing image or adopt the caller's thread. */
 reset();atomic_store(&lease_query_entered,0);atomic_store(&lease_query_done,0);
 pthread_t lookup;pthread_mutex_lock(&ios_thread_group_mutex);
 assert(!pthread_create(&lookup,NULL,lease_query_worker,NULL));
 while(!atomic_load(&lease_query_entered))sched_yield();
 assert(!atomic_load(&lease_query_done));pthread_mutex_unlock(&ios_thread_group_mutex);
 assert(!pthread_join(lookup,NULL)&&blocked_lease==31&&atomic_load(&lease_query_done));
 assert(ios_thread_groups[0].native_references==1&&ios_thread_groups[1].native_references==7);
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
   case 1:ios_jit_mappings[0].map_peb=OTHER;break;case 2:current_lease=ios_thread_groups[0].lease=0;break;
   case 3:quiescent_lease=23;ios_thread_groups[0].exiting=ios_thread_groups[0].reclaimed=1;break;case 4:ios_jit_mappings[0].generation=0;break;
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
 /* Preserve the prior self-query contract during nonquiescent exit. The
  * new remote observer conservatively requires an active registry owner. */
 reset();ios_thread_groups[0].exiting=1;
 assert(!query(MemoryMappedFilenameInformation,&out)&&queried==PE+0x1234);
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
 /* Remote target handle, PID lease and image generation are revalidated
  * after the server query, including handle reuse while its reply is pending. */
 for(unsigned c=0;c<2;c++)for(unsigned race=1;race<=8;race++) {
  if(race==5)continue; /* assigning OTHER would not change the remote owner */
  reset();ios_jit_mappings[0].owner_peb=ios_jit_mappings[0].map_peb=OTHER;
  race_group=1;race_kind=race;pthread_t worker;
  query_barrier_init(&entered,2);query_barrier_init(&changed,2);
  assert(!pthread_create(&worker,NULL,invalidate_during_query,NULL));
  assert(fixed_NtQueryVirtualMemory((HANDLE)42,(void*)(RX+0x1234),remote_classes[c],&out,sizeof(out),&length)==STATUS_INVALID_ADDRESS);
  assert(!pthread_join(worker,NULL));query_barrier_destroy(&entered);query_barrier_destroy(&changed);
 }
 /* A real self handle may also be reused for a foreign target while its
  * query is pending. Only the pseudo-handle has immutable self identity. */
 reset();race_kind=8;pthread_t self_reuse;
 query_barrier_init(&entered,2);query_barrier_init(&changed,2);
 assert(!pthread_create(&self_reuse,NULL,invalidate_during_query,NULL));
 assert(fixed_NtQueryVirtualMemory((HANDLE)41,(void*)(RX+0x1234),MemoryMappedFilenameInformation,&out,sizeof(out),&length)==STATUS_INVALID_ADDRESS);
 assert(!pthread_join(self_reuse,NULL));query_barrier_destroy(&entered);query_barrier_destroy(&changed);
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
