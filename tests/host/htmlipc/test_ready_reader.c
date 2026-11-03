/* SPDX-License-Identifier: MIT. Run with ASan/UBSan; all fixtures are synthetic. */
#include <assert.h>
#include <stdio.h>
#include "htmlipc_ready_reader.h"

#define FIXTURE_SIZE 0x4000u
struct fixture { unsigned char image[FIXTURE_SIZE]; uint64_t base; unsigned reads, fail; };
static void u16(unsigned char *p, unsigned v) { p[0]=v; p[1]=v>>8; }
static void u32(unsigned char *p, uint32_t v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static int read_bytes(void *ctx, uint64_t at, void *out, size_t size)
{
    struct fixture *f=ctx;
    ++f->reads;
    if ((f->fail && f->reads==f->fail) || at<f->base || at-f->base>sizeof(f->image) ||
        size>sizeof(f->image)-(size_t)(at-f->base)) return 0;
    memcpy(out,f->image+(size_t)(at-f->base),size);
    return 1;
}
static void build(struct fixture *f)
{
    unsigned char *p;
    memset(f,0,sizeof(*f)); f->base=UINT64_C(0x7100000000);
    p=f->image; u16(p,0x5a4d); u32(p+60,0x80);
    p+=0x80; u32(p,0x4550); u16(p+4,0x8664); u16(p+6,2); u16(p+20,240);
    p+=24; u16(p,0x20b); u32(p+56,FIXTURE_SIZE); u32(p+60,0x400);
    u32(p+108,16); u32(p+112,0x1000); u32(p+116,0x200);
    p=f->image+0x188; memcpy(p,".rdata",6); u32(p+8,0x1000); u32(p+12,0x1000);
    u32(p+36,0x40000040); p+=40; memcpy(p,".data",5); u32(p+8,0x1000);
    u32(p+12,0x2000); u32(p+36,0xc0000040);
    p=f->image+0x1000; u32(p+20,1); u32(p+24,1); u32(p+28,0x1100);
    u32(p+32,0x1110); u32(p+36,0x1120); u32(f->image+0x1100,0x2080);
    u32(f->image+0x1110,0x1140); u16(f->image+0x1120,0);
    memcpy(f->image+0x1140,"MadeiraRuntimeReady",sizeof("MadeiraRuntimeReady"));
}
static int lookup(struct fixture *f, uint64_t *address)
{
    return madeira_htmlipc_find_ready_export(read_bytes,f,f->base,FIXTURE_SIZE,address);
}
static void reject(struct fixture *f)
{
    uint64_t address=UINT64_MAX;
    assert(!lookup(f,&address)); assert(!address);
}
int main(void)
{
    struct fixture f;
    uint64_t address;
    unsigned calls, i;
    build(&f); assert(lookup(&f,&address)); assert(address==f.base+0x2080); calls=f.reads;
    /* Every failed bounded memory read must close the readiness gate. */
    for(i=1;i<=calls;i++) { build(&f); f.fail=i; reject(&f); }
    build(&f); f.image[0]=0; reject(&f);
    build(&f); u32(f.image+60,UINT32_MAX); reject(&f);
    build(&f); u16(f.image+0x84,0x14c); reject(&f);
    build(&f); u16(f.image+0x86,97); reject(&f);
    build(&f); u16(f.image+0x94,119); reject(&f);
    build(&f); u16(f.image+0x94,120); reject(&f); /* declared directories do not fit */
    build(&f); u16(f.image+0x98,0x10b); reject(&f);
    build(&f); u32(f.image+0x98+56,FIXTURE_SIZE+1); reject(&f);
    build(&f); u32(f.image+0x98+60,0x1b0); reject(&f);
    build(&f); u32(f.image+0x98+108,0); reject(&f);
    build(&f); u32(f.image+0x98+112,0x3ff0); reject(&f);
    build(&f); u32(f.image+0x98+116,UINT32_MAX); reject(&f);
    build(&f); u32(f.image+0x1000+20,4097); reject(&f);
    build(&f); u32(f.image+0x1000+24,4097); reject(&f);
    build(&f); u32(f.image+0x1000+28,0x3fff); reject(&f);
    build(&f); u32(f.image+0x1000+32,UINT32_MAX); reject(&f);
    build(&f); u32(f.image+0x1000+36,0x3fff); reject(&f);
    build(&f); u16(f.image+0x1120,1); reject(&f);
    build(&f); u32(f.image+0x1110,0x3fff); f.image[0x3fff]='x'; reject(&f);
    build(&f); memset(f.image+0x1140,'x',64); reject(&f);
    build(&f); f.image[0x1140]='X'; reject(&f);
    build(&f); u32(f.image+0x1100,0x1180); reject(&f); /* forwarder */
    build(&f); u32(f.image+0x1100,0x3ff0); reject(&f); /* object exceeds image */
    build(&f); u32(f.image+0x1100,0x2fe0); reject(&f); /* object exceeds section */
    build(&f); u32(f.image+0x1b0+36,0xe0000040); reject(&f); /* executable */
    build(&f); u32(f.image+0x1b0+36,0xd0000040); reject(&f); /* shared */
    build(&f); u32(f.image+0x1b0+36,0xc2000040); reject(&f); /* discardable */
    build(&f); u32(f.image+0x1b0+36,0xc0000020); reject(&f); /* code */
    build(&f); u32(f.image+0x1b0+36,0x80000040); reject(&f); /* unreadable */
    build(&f); u32(f.image+0x1b0+12,0x3fff); reject(&f); /* section extent */
    build(&f); u32(f.image+0x188+8,0x2000); reject(&f); /* overlapping membership */
    build(&f); u32(f.image+0x188+12,0x20a8); u32(f.image+0x188+8,80);
    u32(f.image+0x188+36,0x60000020); reject(&f); /* executable overlap of object tail */
    build(&f); u32(f.image+0x1100,0x3000); reject(&f); /* no data section */
    build(&f); u32(f.image+0x1000+24,2); u32(f.image+0x1114,0x1140);
    u16(f.image+0x1122,0); reject(&f); /* duplicate exact export */
    build(&f); f.base=UINT64_MAX-1; reject(&f);
    build(&f); assert(!madeira_htmlipc_find_ready_export(NULL,&f,f.base,FIXTURE_SIZE,&address));
    assert(!madeira_htmlipc_find_ready_export(read_bytes,&f,f.base,FIXTURE_SIZE,NULL));
    /* Export aliases are legal; a different bounded name may share ordinal 0. */
    build(&f); u32(f.image+0x1000+24,2); u32(f.image+0x1114,0x1160);
    memcpy(f.image+0x1160,"OtherData",sizeof("OtherData")); u16(f.image+0x1122,0);
    assert(lookup(&f,&address)); assert(address==f.base+0x2080);
    puts("ready DATA reader: valid lookup, all read failures, malformed PE/export/section cases passed");
    return 0;
}
