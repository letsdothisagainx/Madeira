#define WIN32_LEAN_AND_MEAN
#define PSAPI_VERSION 1
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>

static unsigned checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; printf("[mapped-reference] FAIL line=%u expression=%s\n", (unsigned)__LINE__, #x); } } while (0)
static void fill(WCHAR *s, size_t n) { size_t i; for (i=0;i<n;i++) s[i]=0x5a5a; }
static int unchanged(const WCHAR *s, size_t n) { size_t i; for(i=0;i<n;i++) if(s[i]!=0x5a5a)return 0; return 1; }
int main(void)
{
 WCHAR exe[2048], expected[2048], full[2048], out[2048];
 HANDLE file, mapping; void *view; DWORD length, wanted, ret, error, bad_zero, bad_full;
 DWORD capacities[4]; size_t i;
 CHECK(GetModuleFileNameW(NULL,exe,2048)>0);
 file=CreateFileW(exe,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);
 CHECK(file!=INVALID_HANDLE_VALUE); if(file==INVALID_HANDLE_VALUE)return 2;
 mapping=CreateFileMappingW(file,NULL,PAGE_READONLY,0,0,NULL); CHECK(mapping!=NULL); if(!mapping)return 2;
 view=MapViewOfFile(mapping,FILE_MAP_READ,0,0,0); CHECK(view!=NULL); if(!view)return 2;
 wanted=GetFinalPathNameByHandleW(file,expected,2048,VOLUME_NAME_NT); CHECK(wanted>0&&wanted<2048);
 fill(full,2048); SetLastError(0x12345678); length=GetMappedFileNameW(GetCurrentProcess(),view,full,2048); error=GetLastError();
 printf("[mapped-reference] full returned=%lu final-path-length=%lu last-error=%lu exact-path=%d\n",length,wanted,error,length==wanted&&!wcscmp(full,expected));
 CHECK(length==wanted&&!wcscmp(full,expected)); CHECK(full[length]==0&&full[length+1]==0x5a5a);
 fill(out,2048); SetLastError(0x12345678); ret=GetMappedFileNameW(GetCurrentProcess(),view,out,0); error=GetLastError();
 printf("[mapped-reference] zero-buffer returned=%lu last-error=%lu canary-unchanged=%d\n",ret,error,unchanged(out,2048));
 CHECK(!ret&&unchanged(out,2048));
 SetLastError(0x12345678);ret=GetMappedFileNameW(GetCurrentProcess(),view,NULL,0);error=GetLastError();
 printf("[mapped-reference] zero-null returned=%lu last-error=%lu\n",ret,error);CHECK(!ret);
 capacities[0]=1;capacities[1]=2;capacities[2]=length;capacities[3]=length+1;
 for(i=0;i<4;i++) {
  DWORD cap=capacities[i], expected_return=length<cap?length:cap;
  fill(out,2048);SetLastError(0x12345678);ret=GetMappedFileNameW(GetCurrentProcess(),view,out,cap);error=GetLastError();
  printf("[mapped-reference] capacity=%lu returned=%lu last-error=%lu null-at=%lu canary=%d\n",cap,ret,error,length<cap?length:cap-1,out[cap]==0x5a5a);
  CHECK(ret==expected_return); CHECK(out[length<cap?length:cap-1]==0); CHECK(out[cap]==0x5a5a);
  CHECK(!memcmp(out,full,(length<cap?length:cap-1)*sizeof(WCHAR)));
 }
 fill(out,2048); SetLastError(0x12345678);ret=GetMappedFileNameW((HANDLE)(intptr_t)0x1234,view,out,2);bad_full=GetLastError();
 printf("[mapped-reference] invalid-handle capacity=2 returned=%lu last-error=%lu unchanged=%d\n",ret,bad_full,unchanged(out,2048));CHECK(!ret&&unchanged(out,2048));
 SetLastError(0x12345678);ret=GetMappedFileNameW((HANDLE)(intptr_t)0x1234,view,out,0);bad_zero=GetLastError();
 printf("[mapped-reference] invalid-handle capacity=0 returned=%lu last-error=%lu matches-query-error=%d\n",ret,bad_zero,bad_zero==bad_full);CHECK(!ret);
 SetLastError(0x12345678);ret=GetMappedFileNameW(GetCurrentProcess(),(void*)(uintptr_t)1,out,2);bad_full=GetLastError();
 printf("[mapped-reference] invalid-address capacity=2 returned=%lu last-error=%lu\n",ret,bad_full);CHECK(!ret);
 SetLastError(0x12345678);ret=GetMappedFileNameW(GetCurrentProcess(),(void*)(uintptr_t)1,out,0);bad_zero=GetLastError();
 printf("[mapped-reference] invalid-address capacity=0 returned=%lu last-error=%lu matches-query-error=%d\n",ret,bad_zero,bad_zero==bad_full);CHECK(!ret);
 CHECK(UnmapViewOfFile(view));CHECK(CloseHandle(mapping));CHECK(CloseHandle(file));
 printf("[mapped-reference] %s checks=%u failures=%u trust=not-evaluated vac=not-evaluated\n",failures?"FAIL":"PASS",checks,failures);
 return !!failures;
}
