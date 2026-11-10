#!/usr/bin/env python3
"""Classify the current FEX guard failure; this is not a guard implementation.

Compile the actual CodeBuffer producer/bounds, the staged Win32 protection
wrapper and Wine's literal local protection decision. Real shared file aliases
show what remains accessible after a direct carve has no Wine view. The view
registry/commit/protection callbacks are fixture boundaries, not replacement
Wine or iOS kernels. No device execute-restoration capability is assumed.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def function(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


native = (ROOT / 'build/ntdll-unix/virtual_ios.c').read_text()
protect = function(native, 'NTSTATUS WINAPI NtProtectVirtualMemory(')
normalization_start = protect.index('    size = ROUND_SIZE( addr, size, page_mask );')
normalization = protect[normalization_start:protect.index('\n#ifdef WINE_IOS', normalization_start)]
decision_start = protect.index('    if ((view = find_view( base, size )))')
decision = protect[decision_start:protect.index('\n    if (!status) VIRTUAL_DEBUG_DUMP_VIEW', decision_start)]
assert 'else status = STATUS_INVALID_PARAMETER;' in decision
assert 'status = set_protection( view, base, size, new_prot );' in decision
assert protect.index('server_enter_uninterrupted_section') < decision_start
assert protect.index('not-called:no-wine-view') > decision_start
assert protect.rindex('else *old_prot = PAGE_NOACCESS;') > decision_start

backend = (ROOT / 'FEX/FEXCore/Source/Interface/Core/CPUBackend.cpp').read_text()
header = (ROOT / 'FEX/FEXCore/Source/Interface/Core/CPUBackend.h').read_text()
structure = header[header.index('  struct CodeBuffer {'):]
structure = structure[:structure.index('\n  };') + 5]
producer = function(backend, '  CodeBuffer::CodeBuffer(size_t Size)')
destructor = function(backend, '  CodeBuffer::~CodeBuffer()')
address_test = function(backend, '  bool CPUBackend::IsAddressInCodeBuffer(')
page_source = (ROOT / 'FEX/FEXCore/include/FEXCore/Utils/TypeDefines.h').read_text()
page = page_source[page_source.index('constexpr size_t FEX_PAGE_SIZE ='):].splitlines()[0]

with tempfile.TemporaryDirectory(prefix='madeira-code-guard-contract-') as temporary:
    directory = Path(temporary)
    staged = directory / 'staged'
    subprocess.run(['python3', str(ROOT / 'tools/build/stage-fex-compat.py'),
                    'stage', str(staged), '--backend', 'both'], check=True)
    hooks = (staged / 'FEXCore/include/FEXCore/Utils/AllocatorHooks.h').read_text()
    wrapper = function(hooks, 'inline bool VirtualProtect(')
    assert 'return ::VirtualProtect(Ptr, Size, prot, &Previous) != 0;' in wrapper
    code = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>
#include <atomic>
#include <sys/mman.h>
#include <unistd.h>
#define FEX_IOS_HOST 1
#define WINE_IOS 1
#define PAGE_NOACCESS 0x01u
#define PAGE_READONLY 0x02u
#define PAGE_READWRITE 0x04u
#define PAGE_WRITECOPY 0x08u
#define PAGE_EXECUTE_READ 0x20u
#define PAGE_EXECUTE_READWRITE 0x40u
#define PAGE_EXECUTE_WRITECOPY 0x80u
#define SEC_IMAGE 0x1000000u
#define VPROT_COMMITTED 0x01u
#define STATUS_SUCCESS 0u
#define STATUS_INVALID_PARAMETER 0xc000000du
#define STATUS_NOT_COMMITTED 0xc000002du
#define STATUS_ACCESS_DENIED 0xc0000022u
#define ROUND_ADDR(a,m) ((char*)((uintptr_t)(a)&~(uintptr_t)(m)))
#define ROUND_SIZE(a,n,m) (((n)+((uintptr_t)(a)&(m))+(m))&~(size_t)(m))
using BYTE=uint8_t;using DWORD=uint32_t;using ULONG=uint32_t;using NTSTATUS=uint32_t;
static constexpr size_t page_mask=4095, host_quantum=16384, bytes=16*1024*1024;
struct file_view {void* base;size_t size;unsigned protect;bool committed;};
static file_view ordinary{};
static unsigned protection_calls, allocations, frees, warnings;
static NTSTATUS last_status, callback_status;
static uintptr_t requested_guard, normalized_guard;
static size_t requested_bytes, normalized_bytes;
static unsigned char *rx,*rw;
static void* reservations[2];
static file_view* find_view(void* base,size_t size) {
  uintptr_t p=(uintptr_t)base,b=(uintptr_t)ordinary.base;
  return ordinary.base&&p>=b&&p-b<=ordinary.size&&size<=ordinary.size-(p-b)?&ordinary:nullptr;
}
static size_t get_committed_size(file_view* view,void*,size_t size,BYTE* prot,unsigned) {
  *prot=view->committed?VPROT_COMMITTED:0;return view->committed?size:0;
}
static DWORD get_win32_prot(BYTE,unsigned) {return PAGE_READWRITE;}
static NTSTATUS set_protection(file_view*,void*,size_t,unsigned) {
  ++protection_calls;return callback_status;
}
// Literal normalization and local-view decision from NtProtectVirtualMemory.
// Fixture callbacks stand in for the OS-backed Wine view/commit operations.
static NTSTATUS production_local_protect(void** addr_ptr,size_t* size_ptr,ULONG new_prot,ULONG* old_prot) {
  file_view* view;NTSTATUS status=STATUS_SUCCESS;char* base;BYTE vprot;
  void* addr=*addr_ptr;size_t size=*size_ptr;DWORD old=PAGE_NOACCESS;
''' + normalization + '\n' + decision + r'''
  normalized_guard=(uintptr_t)base;normalized_bytes=size;
  if(status==STATUS_SUCCESS){*addr_ptr=base;*size_ptr=size;*old_prot=old;}
  else *old_prot=PAGE_NOACCESS;
  return status;
}
static int VirtualProtect(void* pointer,size_t size,DWORD protection,DWORD* previous) {
  assert(previous);requested_guard=(uintptr_t)pointer;requested_bytes=size;
  void* normalized=pointer;size_t length=size;
  last_status=production_local_protect(&normalized,&length,protection,previous);
  return last_status==STATUS_SUCCESS;
}
template<class T>static T AlignDown(T value,size_t alignment) {return value&~(T)(alignment-1);}
namespace LogMan::Msg {
template<class...T>void EFmt(const char* message,T...) {
  if(!std::strcmp(message,"Failed to mprotect last page of code buffer."))++warnings;
}
}
#define LOGMAN_THROW_A_FMT(value,...) assert(value)
#define LOGMAN_MSG_A_FMT(...) do{}while(0)
namespace fextl {template<class T>using unique_ptr=std::unique_ptr<T>;using std::make_unique;}
namespace FEXCore {
namespace Utils {
''' + page + r'''
}
struct GuestToHostMap {};
namespace Allocator {
enum class ProtectOptions:unsigned {None=0,Read=1,Write=2,Exec=4};
constexpr ProtectOptions operator|(ProtectOptions a,ProtectOptions b) {
  return static_cast<ProtectOptions>((unsigned)a|(unsigned)b);
}
enum class THPControl {Enable};
static void* VirtualAlloc(size_t size,bool executable) {
  assert(size==bytes&&executable);++allocations;return rx;
}
static void VirtualFree(void* pointer,size_t size) {
  assert(pointer==rx&&size==bytes);++frees;
}
static void VirtualName(const char*,void*,size_t) {}
static void VirtualTHPControl(void*,size_t,THPControl) {}
''' + wrapper + r'''
}
namespace CPU {
''' + structure + '\n' + producer + '\n' + destructor + r'''
struct IosMigrateLockGuard {explicit IosMigrateLockGuard(std::atomic<uint64_t>&){}};
class CPUBackend {
public:
  mutable std::atomic<uint64_t> IosMigrateLock{};
  std::shared_ptr<CodeBuffer> CurrentCodeBuffer;
  std::vector<std::shared_ptr<CodeBuffer>> SignalHandlerCodeBuffers;
  bool IsAddressInCodeBuffer(uintptr_t Address) const;
};
''' + address_test + r'''
}
}
static unsigned char* alias(int fd,int prot,unsigned which) {
  size_t length=bytes+host_quantum;
  void* reservation=mmap(nullptr,length,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
  assert(reservation!=MAP_FAILED);reservations[which]=reservation;
  uintptr_t aligned=((uintptr_t)reservation+host_quantum-1)&~(host_quantum-1);
  void* mapping=mmap((void*)aligned,bytes,prot,MAP_SHARED|MAP_FIXED,fd,0);
  assert(mapping==(void*)aligned);return (unsigned char*)mapping;
}
static void emit_return_42(size_t offset) {
#if defined(__aarch64__) || defined(__arm64__)
  const uint32_t code[]={0x52800540u,0xd65f03c0u};
#elif defined(__x86_64__)
  const unsigned char code[]={0xb8,42,0,0,0,0xc3};
#else
#error Unsupported executable fixture architecture
#endif
  std::memcpy(rw+offset,code,sizeof(code));
  __builtin___clear_cache((char*)rx+offset,(char*)rx+offset+sizeof(code));
  using Fn=int(*)();assert(reinterpret_cast<Fn>(rx+offset)()==42);
}
int main() {
  size_t native_page=(size_t)sysconf(_SC_PAGESIZE);
  assert(native_page&&host_quantum%native_page==0);
  FILE* file=tmpfile();assert(file&&!ftruncate(fileno(file),bytes));
  rx=alias(fileno(file),PROT_READ|PROT_EXEC,0);
  rw=alias(fileno(file),PROT_READ|PROT_WRITE,1);fclose(file);
  FEXCore::CPU::CPUBackend backend;
  backend.CurrentCodeBuffer=std::make_shared<FEXCore::CPU::CodeBuffer>(bytes);
  auto& buffer=*backend.CurrentCodeBuffer;
  assert(allocations==1&&warnings==1&&!protection_calls);
  assert(last_status==STATUS_INVALID_PARAMETER);
  assert(requested_guard==(uintptr_t)rx+bytes-4096&&requested_bytes==4096);
  assert(normalized_guard==requested_guard&&normalized_bytes==requested_bytes);
  assert(!find_view((void*)requested_guard,4096));
  assert(buffer.UsableSize()==bytes-4096);
  size_t containing_host_page=bytes-host_quantum;
  assert(buffer.UsableSize()-containing_host_page==0x3000);
  for(size_t offset=containing_host_page;offset<bytes;offset+=16)
    assert(backend.IsAddressInCodeBuffer((uintptr_t)rx+offset)==(offset<buffer.UsableSize()));
  // Code immediately before the intended 4KB guard is valid to the actual
  // producer. Rounding PAGE_NOACCESS down to 16KB would revoke this code.
  emit_return_42(buffer.UsableSize()-16);
  rw[bytes-8]=0x5a;assert(rx[bytes-8]==0x5a);
  emit_return_42(bytes-4096+16); // Known limitation: the failed guard stays executable.
  puts("KNOWN LIMITATION: actual FEX code guard fails c000000d before set_protection because the direct carve has no Wine view; RX/RW remain accessible");
  puts("PASS boundary proof: 12 KiB of valid FEX code shares the final 16 KiB host page; last usable code executes, so rounding the 4 KiB request down is unsafe");
  DWORD previous=0;void* region=rx;size_t length=4096;
  ordinary={rx,bytes,0,true};callback_status=STATUS_SUCCESS;
  assert(production_local_protect(&region,&length,PAGE_NOACCESS,&previous)==STATUS_SUCCESS);
  assert(protection_calls==1&&previous==PAGE_READWRITE);
  callback_status=STATUS_ACCESS_DENIED;region=rx;length=4096;
  assert(production_local_protect(&region,&length,PAGE_NOACCESS,&previous)==STATUS_ACCESS_DENIED);
  assert(protection_calls==2&&previous==PAGE_NOACCESS);
  ordinary.committed=false;region=rx;length=4096;
  assert(production_local_protect(&region,&length,PAGE_NOACCESS,&previous)==STATUS_NOT_COMMITTED);
  assert(protection_calls==2);
  puts("PASS literal Wine decision: an ordinary committed view reaches set_protection; uncommitted and failed protections retain their real status");
  backend.CurrentCodeBuffer.reset();assert(frees==1);
  for(void* reservation:reservations)assert(!munmap(reservation,bytes+host_quantum));
  puts("NOT FIXED BY THIS TEST: no physical guard or iOS RX restoration is implemented or claimed");
}
'''
    source = directory / 'guard-contract.cpp'
    source.write_text(code)
    binary = directory / 'guard-contract'
    compiler = shlex.split(os.environ.get('CXX', 'c++'))
    subprocess.run([*compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-fno-omit-frame-pointer', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
