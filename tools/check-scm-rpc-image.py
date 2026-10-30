#!/usr/bin/env python3
"""Check PE import binding with the standard library (also usable on macOS)."""
import struct
import sys
from pathlib import Path

class PE:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        assert self.data[:2] == b'MZ', 'not a PE file'
        pe = self.u32(0x3c)
        assert self.data[pe:pe+4] == b'PE\0\0'
        self.machine, count = self.unpack('<HH', pe+4)
        opt = pe+24
        assert self.unpack('<H', opt)[0] == 0x20b, 'expected 64-bit PE'
        self.base = self.unpack('<Q', opt+24)[0]
        self.dirs = [self.unpack('<II',opt+112+8*i) for i in range(16)]
        sec = opt + self.unpack('<H',pe+20)[0]
        self.sections = []
        for i in range(count):
            size, rva, raw_size, raw = self.unpack('<IIII',sec+40*i+8)
            self.sections.append((rva,max(size,raw_size),raw))
    def unpack(self, fmt, off): return struct.unpack_from(fmt,self.data,off)
    def u32(self, off): return self.unpack('<I',off)[0]
    def offset(self, rva):
        for start,size,raw in self.sections:
            if start <= rva < start+size: return raw+rva-start
        raise AssertionError(f'unmapped RVA {rva:x}')
    def string(self,rva):
        off=self.offset(rva); return self.data[off:self.data.index(b'\0',off)].decode('ascii')
    def imports(self,delay=False):
        rva,size=self.dirs[13 if delay else 1]
        if not rva: return {}
        result={}; stride=32 if delay else 20
        for i in range(size//stride):
            fields=self.unpack('<8I' if delay else '<5I',self.offset(rva)+stride*i)
            if not any(fields): break
            name=fields[1] if delay else fields[3]
            lookup=fields[4] if delay else (fields[0] or fields[4])
            if delay: assert fields[0]&1, 'unsupported VA-form delay descriptor'
            names=[]
            for j in range(len(self.data)//8):
                entry=self.unpack('<Q',self.offset(lookup)+8*j)[0]
                if not entry: break
                if not entry>>63: names.append(self.string(entry+2))
            result[self.string(name).lower()]=names
        return result

def check(path):
    pe=PE(path)
    assert pe.machine in (0x8664,0xa641), 'expected ARM64EC hybrid'
    load,_=pe.dirs[10]
    metadata=pe.unpack('<Q',pe.offset(load)+0xc8)[0]
    assert metadata, 'missing hybrid metadata'
    aux=pe.u32(pe.offset(metadata-pe.base)+44)
    assert aux, 'missing native auxiliary IAT'
    assert 'rpcrt4.dll' not in pe.imports(True), 'unsafe lazy EC RPC binding remains'
    assert 'NdrClientCall2' in pe.imports().get('rpcrt4.dll',[]), 'missing normal NDR import'
    print('PASS SCM producer binds NdrClientCall2 normally with a native auxiliary IAT')

if __name__=='__main__':
    check(sys.argv[1])
    if len(sys.argv)>2:
        assert b'[scm-rpc-bind] native=1 auxiliary=1 pool=' in Path(sys.argv[2]).read_bytes(), 'missing rebuilt loader binding'
        print('PASS ntdll includes the native SCM auxiliary binding')
