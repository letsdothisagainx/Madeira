#!/usr/bin/env python3
"""Classify actual packaged hybrid PEs with the production immutable ISA parser.

Uses only the Python standard library and the host C compiler. The supplied
DLLs are read-only inputs; only temporary mapped-image copies are constructed.
No publisher/signature or VAC verdict is implied by an ISA classification.
"""
import argparse
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
EXPORTS = {'user32.dll': 'SetCursorPos', 'kernel32.dll': 'VirtualAlloc',
           'ntdll.dll': 'LdrLoadDll', 'shell32.dll': 'ShellExecuteExA'}


def u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def mapped_image(path):
    data = path.read_bytes()
    assert data[:2] == b'MZ'
    pe = u32(data, 60)
    assert data[pe:pe + 4] == b'PE\0\0'
    opt = pe + 24
    assert u16(data, opt) == 0x20b
    size = u32(data, opt + 56)
    assert 0 < size <= 64 << 20
    image = bytearray(size)
    headers = u32(data, opt + 60)
    assert headers <= len(data) and headers <= size
    image[:headers] = data[:headers]
    section_at = opt + u16(data, pe + 20)
    section_count = u16(data, pe + 6)
    for i in range(section_count):
        at = section_at + 40 * i
        rva, length, raw = u32(data, at + 12), u32(data, at + 16), u32(data, at + 20)
        assert rva + length <= size and raw + length <= len(data)
        image[rva:rva + length] = data[raw:raw + length]
    export_at = u32(image, opt + 112)
    functions, names = u32(image, export_at + 20), u32(image, export_at + 24)
    eat, name_table, ordinal_table = (u32(image, export_at + off) for off in (28, 32, 36))
    requested = EXPORTS.get(path.name.lower())
    assert requested, f'No owned-runtime test export defined for {path.name}'
    target = None
    for i in range(names):
        name_at = u32(image, name_table + 4 * i)
        end = image.index(0, name_at)
        if image[name_at:end].decode('ascii') == requested:
            ordinal = u16(image, ordinal_table + 2 * i)
            assert ordinal < functions
            target = u32(image, eat + 4 * ordinal)
            break
    assert target is not None, f'{requested} missing in {path.name}'
    return image, target, requested, section_at, section_count


C = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "pe_x64_write_span.h"
struct image {const unsigned char* data;size_t size;};
static int read_image(void* context,size_t offset,void* out,size_t size){struct image* image=context;if(!madeira_pe_span_bound(offset,size,image->size))return 0;memcpy(out,image->data+offset,size);return 1;}
int main(int argc,char** argv){
 assert(argc==4);int fd=open(argv[1],O_RDONLY);assert(fd>=0);struct stat st;assert(!fstat(fd,&st));
 struct image image={mmap(NULL,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,fd,0),(size_t)st.st_size};assert(image.data!=MAP_FAILED);
 struct madeira_pe_x64_span spans[32];unsigned count=madeira_pe_cache_x64_write_spans(image.size,0x7100000000ULL,0x7c00000000ULL,0x7c48000000ULL,read_image,&image,spans,32);
 size_t target=(size_t)strtoull(argv[2],NULL,16);int accepted=0;
 for(unsigned i=0;i<count;i++)if(target>=spans[i].offset&&target-spans[i].offset<=spans[i].size&&5<=spans[i].size-(target-spans[i].offset))accepted=1;
 assert(accepted==atoi(argv[3]));printf("parser-ranges=%u requested-rva=%#lx accepted=%d\n",count,(unsigned long)target,accepted);
 assert(!munmap((void*)image.data,image.size));close(fd);return 0;
}
'''

parser = argparse.ArgumentParser()
parser.add_argument('--pe-images', nargs='+', type=Path)
options = parser.parse_args()
paths = options.pe_images or [ROOT / 'app/Madeira/arm64ec-windows' / name for name in EXPORTS]
with tempfile.TemporaryDirectory(prefix='madeira-real-pe-spans-') as directory:
    temporary = Path(directory)
    source, binary = temporary / 'check.c', temporary / 'check'
    source.write_text(C)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(ROOT / 'build/ntdll-unix'), str(source), '-o', str(binary)], check=True)
    for index, path in enumerate(paths):
        image, target, export, sections, count = mapped_image(path)
        fixture = temporary / f'image-{index}.bin'
        fixture.write_bytes(image)
        subprocess.run([str(binary), str(fixture), f'{target:x}', '1'], check=True)
        # A shared executable section cannot supply private COW authorization.
        for i in range(count):
            at = sections + 40 * i
            struct.pack_into('<I', image, at + 36, u32(image, at + 36) | 0x10000000)
        fixture.write_bytes(image)
        subprocess.run([str(binary), str(fixture), f'{target:x}', '0'], check=True)
        print(f'PASS actual hybrid PE {path.name}!{export}: exact 5-byte span classified; shared sections rejected', flush=True)
