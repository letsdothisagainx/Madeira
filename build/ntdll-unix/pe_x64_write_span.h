/* Bounds/ISA proof for an ordinary write to original ARM64EC PE backing.
 * This only classifies bytes; it neither changes protection nor writes code.
 * A CodeMap entry is required: executable section membership alone is not
 * enough to distinguish x64 export thunks from native ARM64 instructions. */
#ifndef MADEIRA_PE_X64_WRITE_SPAN_H
#define MADEIRA_PE_X64_WRITE_SPAN_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef int (*madeira_pe_span_read)(void *, size_t, void *, size_t);
struct madeira_pe_x64_span { size_t offset, size; };
static uint16_t madeira_pe_span_u16(const unsigned char *p) { uint16_t v; memcpy(&v,p,2); return v; }
static uint32_t madeira_pe_span_u32(const unsigned char *p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint64_t madeira_pe_span_u64(const unsigned char *p) { uint64_t v; memcpy(&v,p,8); return v; }
static int madeira_pe_span_bound(size_t off, size_t bytes, size_t size)
{ return off <= size && bytes <= size-off; }

static unsigned madeira_pe_cache_x64_write_spans(size_t size, uintptr_t source, uintptr_t rx, uintptr_t rw,
                                                madeira_pe_span_read read, void *context,
                                                struct madeira_pe_x64_span *spans, unsigned capacity)
{
    unsigned char dos[64], pe[24], opt[200], section[40], config[208], meta[12], entries[256];
    size_t pe_at, opt_at, section_at, image_size, map_at, count, i, previous=0;
    size_t section_starts[96], section_ends[96], map_bytes;
    uintptr_t bases[4];
    uint64_t pointer;
    unsigned section_exec[96];
    unsigned sections, opt_size, machine, found=0;
    if (!read || !spans || !capacity || size<64 ||
        !read(context,0,dos,sizeof(dos)) || madeira_pe_span_u16(dos)!=0x5a4d) return 0;
    pe_at=madeira_pe_span_u32(dos+60);
    if (!madeira_pe_span_bound(pe_at,sizeof(pe),size) || !read(context,pe_at,pe,sizeof(pe)) ||
        memcmp(pe,"PE\0\0",4)) return 0;
    machine=madeira_pe_span_u16(pe+4); sections=madeira_pe_span_u16(pe+6);
    opt_size=madeira_pe_span_u16(pe+20); opt_at=pe_at+sizeof(pe);
    if ((machine!=0x8664 && machine!=0xa641) || !sections || sections>96 || opt_size<sizeof(opt) ||
        !madeira_pe_span_bound(opt_at,opt_size,size) || !read(context,opt_at,opt,sizeof(opt)) ||
        madeira_pe_span_u16(opt)!=0x20b || madeira_pe_span_u32(opt+108)<11) return 0;
    image_size=madeira_pe_span_u32(opt+56);
    if (!image_size || image_size>size || size-image_size>=0x4000) return 0;
    section_at=opt_at+opt_size;
    if (!madeira_pe_span_bound(section_at,40u*sections,image_size)) return 0;
    for (i=0;i<sections;i++)
    {
        size_t start,length,j;
        if (!read(context,section_at+40*i,section,sizeof(section))) return 0;
        start=madeira_pe_span_u32(section+12); length=madeira_pe_span_u32(section+8);
        if (!length) length=madeira_pe_span_u32(section+16);
        if (!madeira_pe_span_bound(start,length,image_size)) return 0;
        section_starts[i]=start; section_ends[i]=start+length;
        for (j=0;j<i;j++) if (length && start<section_ends[j] && section_starts[j]<start+length) return 0;
        /* IMAGE_SCN_MEM_SHARED can alias the file/another process even at
         * different PE VAs. Only non-shared executable sections qualify. */
        section_exec[i]=(madeira_pe_span_u32(section+36)&0x30000000u)==0x20000000u;
    }
    map_at=madeira_pe_span_u32(opt+0x70+10*8);
    count=madeira_pe_span_u32(opt+0x70+10*8+4);
    if (count<sizeof(config) || !madeira_pe_span_bound(map_at,count,image_size) ||
        !read(context,map_at,config,sizeof(config))) return 0;
    pointer=madeira_pe_span_u64(config+0xc8);
    bases[0]=madeira_pe_span_u64(opt+24); bases[1]=source; bases[2]=rx; bases[3]=rw;
    map_at=image_size;
    for (i=0;i<4;i++) if (pointer>=bases[i] && pointer-bases[i]<image_size)
    { map_at=(size_t)(pointer-bases[i]); break; }
    if (!madeira_pe_span_bound(map_at,sizeof(meta),image_size) ||
        !read(context,map_at,meta,sizeof(meta))) return 0;
    map_at=madeira_pe_span_u32(meta+4); count=madeira_pe_span_u32(meta+8);
    if (!count || count>image_size/8 || !madeira_pe_span_bound(map_at,count*8,image_size)) return 0;
    map_bytes=count*8;
    /* Validate the entire ordered CodeMap before authorizing any byte. Read
     * bounded blocks so a malformed/unmapped metadata page fails honestly. */
    for (i=0;i<count;i++)
    {
        size_t index=(i*8)%sizeof(entries), start,length;
        uint32_t entry;
        unsigned kind;
        if (!index)
        {
            size_t length=map_bytes-i*8;
            if (length>sizeof(entries)) length=sizeof(entries);
            if (!read(context,map_at+i*8,entries,length)) return 0;
        }
        entry=madeira_pe_span_u32(entries+index); kind=entry&3;
        start=entry&~3u; length=madeira_pe_span_u32(entries+index+4);
        if (kind>2 || !length || !madeira_pe_span_bound(start,length,image_size) ||
            (kind<2 && (length&3)) || (i && start<previous)) return 0;
        previous=start+length;
        if (kind==2)
        {
            size_t j;
            /* Compiler CodeMaps can cross an executable section's raw
             * padding and continue in .hexpthk. Cache only intersections
             * with declared executable VirtualSize, never authorize that
             * intervening padding or require the map to fit one section. */
            for (j=0;j<sections;j++) if (section_exec[j])
            {
                size_t lo=start>section_starts[j]?start:section_starts[j];
                size_t hi=start+length<section_ends[j]?start+length:section_ends[j];
                if (lo>=hi) continue;
                if (found>=capacity) return 0;
                spans[found].offset=lo; spans[found].size=hi-lo; found++;
            }
        }
    }
    return found;
}
#endif
