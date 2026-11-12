/* Native Windows reference: genuine message resources and owned UDP loopback.
 * No Steam/CS2 process, authentication material or remote server is accessed. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

static unsigned checks;
static void require(int okay,const char *name)
{
    checks++;
    if (!okay) {printf("FAIL %s last-error=%lu\n",name,GetLastError());ExitProcess(1);}
}
int main(void)
{
    static const DWORD codes[]={10051,10060,10065};
    WSADATA data;
    char text[1024],received[32];
    unsigned i;
    SOCKET socket_handle;
    struct sockaddr_in address={0};
    int length=sizeof(address),timeout=5000;
    DWORD bytes=0;
    WSABUF buffer={5,"owned"};
    require(!WSAStartup(MAKEWORD(2,2),&data),"WSAStartup");
    for(i=0;i<sizeof(codes)/sizeof(*codes);i++)
    {
        DWORD count,after;
        WSASetLastError(codes[i]);
        count=FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,NULL,codes[i],0x409,text,sizeof(text),NULL);
        after=GetLastError();
        require(count>0&&count<sizeof(text),"native system socket message exists");
        while(count&&(text[count-1]=='\r'||text[count-1]=='\n'))text[--count]=0;
        printf("message-id=%lu format-length=%lu error-before=%lu error-after=%lu text=%s\n",codes[i],count,codes[i],after,text);
    }
    WSASetLastError(10065);
    require(!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,NULL,0x01234567,0x409,text,sizeof(text),NULL),"unknown message fails normally");
    require(GetLastError()==ERROR_MR_MID_NOT_FOUND,"missing message legitimately replaces last error with317");
    socket_handle=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    require(socket_handle!=INVALID_SOCKET,"create owned UDP socket");
    address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    require(!bind(socket_handle,(const struct sockaddr*)&address,sizeof(address)),"bind owned loopback UDP");
    require(!getsockname(socket_handle,(struct sockaddr*)&address,&length),"read owned local endpoint");
    require(!setsockopt(socket_handle,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout)),"bounded receive timeout");
    require(!WSASendTo(socket_handle,&buffer,1,&bytes,0,(const struct sockaddr*)&address,sizeof(address),NULL,NULL)&&bytes==5,"real UDP send count");
    require(recvfrom(socket_handle,received,sizeof(received),0,NULL,NULL)==5&&!memcmp(received,"owned",5),"real UDP receive exact bytes");
    require(!closesocket(socket_handle),"close owned UDP socket");
    require(!WSACleanup(),"WSACleanup");
    printf("PASS native Windows Winsock message and owned UDP contract checks=%u pointer-bits=%u\n",checks,(unsigned)(sizeof(void*)*8));
    return 0;
}
