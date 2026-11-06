/* SPDX-License-Identifier: MIT
 * Isolated Windows object-manager/32->64 IPC fixture, never a Steam replacement.
 * Sizes/names/layout follow the independently pinned bootstrap contract. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>

#include "bootstrap-contract.h"
#define MAP_BYTES (CAPACITY + MAP_HEADER)
#define WAIT_MS 15000u
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"[htmlipc-fixture] line=%u error=%lu\n",__LINE__,GetLastError()); return 1; } } while (0)
struct ring { volatile LONG read, write, capacity, used; unsigned char bytes[CAPACITY]; };
_Static_assert(sizeof(struct ring)==MAP_BYTES,"ring header/size differs from production-pinned helper");
static void names(DWORD pid, WCHAR *master, WCHAR *response, WCHAR *ready, WCHAR *request, WCHAR *done, WCHAR *stop)
{
    swprintf(master,128,L"MadeiraHTMLIPCFixture_MasterStream_spid%lu_mem-IPCWrapper",pid);
    swprintf(response,128,L"MadeiraHTMLIPCFixture_Response_%lu_mem-IPCWrapper",pid);
    swprintf(ready,128,L"MadeiraHTMLIPCFixture_Ready_%lu",pid);
    swprintf(request,128,L"MadeiraHTMLIPCFixture_Request_%lu",pid);
    swprintf(done,128,L"MadeiraHTMLIPCFixture_Done_%lu",pid);
    swprintf(stop,128,L"MadeiraHTMLIPCFixture_Stop_%lu",pid);
}
static void ring_put(struct ring *r, const unsigned char *bytes, LONG size)
{
    memcpy(r->bytes,bytes,(size_t)size);
    r->read=0; r->write=size; r->capacity=CAPACITY;
    InterlockedExchange(&r->used,size);
}
static int server(DWORD parent)
{
    WCHAR master[128],response[128],ready_name[128],request_name[128],done_name[128],stop_name[128];
    HANDLE mapping, reply_mapping, ready, request, done, stop;
    struct ring *input,*output;
    unsigned char reply[RESPONSE_BYTES]={0}; uint32_t word,request_pid;
    names(parent,master,response,ready_name,request_name,done_name,stop_name);
    ready=OpenEventW(EVENT_MODIFY_STATE,FALSE,ready_name); CHECK(ready);
    request=OpenEventW(SYNCHRONIZE,FALSE,request_name); CHECK(request);
    done=OpenEventW(EVENT_MODIFY_STATE,FALSE,done_name); CHECK(done);
    stop=OpenEventW(SYNCHRONIZE,FALSE,stop_name); CHECK(stop);
    mapping=CreateFileMappingW(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,MAP_BYTES,master); CHECK(mapping);
    CHECK(GetLastError()!=ERROR_ALREADY_EXISTS);
    input=MapViewOfFile(mapping,FILE_MAP_ALL_ACCESS,0,0,MAP_BYTES); CHECK(input);
    input->capacity=CAPACITY; CHECK(SetEvent(ready));
    CHECK(WaitForSingleObject(request,WAIT_MS)==WAIT_OBJECT_0);
    CHECK(InterlockedCompareExchange(&input->used,0,0)==REQUEST_BYTES);
    memcpy(&word,input->bytes,4); CHECK(word==1);
    memcpy(&word,input->bytes+4,4); CHECK(word==1);
    memcpy(&request_pid,input->bytes+8,4); CHECK(request_pid==parent);
    { char expected[64]; int count=snprintf(expected,sizeof(expected),"MadeiraHTMLIPCFixture_Response_%lu",parent);
      CHECK(count>0 && count<64); CHECK(!memcmp(input->bytes+12,expected,(size_t)count+1)); }
    reply_mapping=OpenFileMappingW(FILE_MAP_ALL_ACCESS,FALSE,response); CHECK(reply_mapping);
    output=MapViewOfFile(reply_mapping,FILE_MAP_ALL_ACCESS,0,0,MAP_BYTES); CHECK(output);
    word=2; memcpy(reply,&word,4); word=GetCurrentProcessId(); memcpy(reply+4,&word,4);
    CHECK(snprintf((char*)reply+8,64,"MadeiraHTMLIPCFixture_ClientStream_%lu_%lu",parent,(DWORD)word)>0);
    ring_put(output,reply,sizeof(reply)); CHECK(SetEvent(done));
    CHECK(WaitForSingleObject(stop,WAIT_MS)==WAIT_OBJECT_0);
    CHECK(UnmapViewOfFile(output)); CHECK(CloseHandle(reply_mapping));
    CHECK(UnmapViewOfFile(input)); CHECK(CloseHandle(mapping));
    CloseHandle(ready);CloseHandle(request);CloseHandle(done);CloseHandle(stop);
    return 0;
}
static int client(const WCHAR *helper)
{
    DWORD pid=GetCurrentProcessId(),exit_code; WCHAR command[32768]; STARTUPINFOW startup={0}; PROCESS_INFORMATION child;
    WCHAR master[128],response[128],ready_name[128],request_name[128],done_name[128],stop_name[128];
    HANDLE mapping,reply_mapping,ready,request,done,stop; struct ring *input,*output;
    unsigned char packet[REQUEST_BYTES]={0}; uint32_t word;
    names(pid,master,response,ready_name,request_name,done_name,stop_name);
    SetLastError(0);mapping=OpenFileMappingW(FILE_MAP_ALL_ACCESS,FALSE,master);
    CHECK(!mapping && GetLastError()==ERROR_FILE_NOT_FOUND);
    ready=CreateEventW(NULL,FALSE,FALSE,ready_name);CHECK(ready);
    request=CreateEventW(NULL,FALSE,FALSE,request_name);CHECK(request);
    done=CreateEventW(NULL,FALSE,FALSE,done_name);CHECK(done);
    stop=CreateEventW(NULL,FALSE,FALSE,stop_name);CHECK(stop);
    reply_mapping=CreateFileMappingW(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,MAP_BYTES,response);CHECK(reply_mapping);
    CHECK(GetLastError()!=ERROR_ALREADY_EXISTS);
    output=MapViewOfFile(reply_mapping,FILE_MAP_ALL_ACCESS,0,0,MAP_BYTES);CHECK(output);
    startup.cb=sizeof(startup);memset(&child,0,sizeof(child));
    CHECK(swprintf(command,32768,L"\"%ls\" --server %lu",helper,pid)>0);
    CHECK(CreateProcessW(helper,command,NULL,NULL,FALSE,0,NULL,NULL,&startup,&child));
    CHECK(WaitForSingleObject(ready,WAIT_MS)==WAIT_OBJECT_0);
    mapping=OpenFileMappingW(FILE_MAP_ALL_ACCESS,FALSE,master);CHECK(mapping);
    input=MapViewOfFile(mapping,FILE_MAP_ALL_ACCESS,0,0,MAP_BYTES);CHECK(input);
    CHECK(input->capacity==CAPACITY);
    word=1;memcpy(packet,&word,4);memcpy(packet+4,&word,4);word=pid;memcpy(packet+8,&word,4);
    CHECK(snprintf((char*)packet+12,64,"MadeiraHTMLIPCFixture_Response_%lu",pid)>0);
    ring_put(input,packet,sizeof(packet));CHECK(SetEvent(request));
    CHECK(WaitForSingleObject(done,WAIT_MS)==WAIT_OBJECT_0);
    CHECK(InterlockedCompareExchange(&output->used,0,0)==RESPONSE_BYTES);
    memcpy(&word,output->bytes,4);CHECK(word==2);
    memcpy(&word,output->bytes+4,4);CHECK(word==child.dwProcessId);
    { char expected[64];int n=snprintf(expected,sizeof(expected),"MadeiraHTMLIPCFixture_ClientStream_%lu_%lu",pid,child.dwProcessId);
      CHECK(n>0&&n<64);CHECK(!memcmp(output->bytes+8,expected,(size_t)n+1)); }
    CHECK(SetEvent(stop));CHECK(WaitForSingleObject(child.hProcess,WAIT_MS)==WAIT_OBJECT_0);
    CHECK(GetExitCodeProcess(child.hProcess,&exit_code));CHECK(exit_code==0);
    /* Named object remains alive while a peer still owns a handle/view. */
    { HANDLE remaining=OpenFileMappingW(FILE_MAP_READ,FALSE,master);CHECK(remaining);CHECK(CloseHandle(remaining)); }
    CHECK(UnmapViewOfFile(input));CHECK(CloseHandle(mapping));
    SetLastError(0);mapping=OpenFileMappingW(FILE_MAP_READ,FALSE,master);
    CHECK(!mapping && GetLastError()==ERROR_FILE_NOT_FOUND);
    CHECK(UnmapViewOfFile(output));CHECK(CloseHandle(reply_mapping));
    SetLastError(0);mapping=OpenFileMappingW(FILE_MAP_READ,FALSE,response);
    CHECK(!mapping && GetLastError()==ERROR_FILE_NOT_FOUND);
    CloseHandle(child.hThread);CloseHandle(child.hProcess);
    CloseHandle(ready);CloseHandle(request);CloseHandle(done);CloseHandle(stop);
    puts("[htmlipc-fixture] PASS missing-before-create exact76-72 bootstrap cross-architecture creator-exit peer-retention last-close cleanup");
    return 0;
}
int wmain(int argc,WCHAR **argv)
{
    if(argc==3&&!wcscmp(argv[1],L"--server"))return server(wcstoul(argv[2],NULL,10));
    if(argc==2)return client(argv[1]);
    return 2;
}
