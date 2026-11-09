#!/usr/bin/env python3
"""Exercise the real packaged PE export/CHPE/private-writer validators.

These are owned byte fixtures, not executable FEX or Wine. A success proves
provenance and ABI shape only; no installer, game, or runtime success follows.
"""
from pathlib import Path
import contextlib
import importlib.util
import io
import re
import struct
import tempfile

ROOT=Path(__file__).resolve().parents[2]


def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def fex_fixture(backend='arm64ec'):
    data=bytearray(0x3400);pe=0x80;opt=0x98
    def put(fmt,off,*args):struct.pack_into(fmt,data,off,*args)
    data[:2]=b'MZ';put('<I',0x3c,pe);data[pe:pe+4]=b'PE\0\0'
    put('<HHIIIHH',pe+4,0x8664 if backend=='arm64ec' else 0xaa64,3,0,0,0,240,0x2022)
    put('<H',opt,0x20b);put('<Q',opt+24,0x180000000);put('<II',opt+56,0x4000,0x400);put('<I',opt+108,16)
    put('<II',opt+112,0x1000,0x300)
    sections={}
    for index,(name,rva,raw,flags) in enumerate(((b'.edata',0x1000,0x400,0x40000040),(b'.data',0x2000,0x1400,0xc0000040),(b'.text',0x3000,0x2400,0x60000020))):
        off=opt+240+index*40;data[off:off+len(name)]=name
        put('<IIII',off+8,0x1000,rva,0x1000,raw);put('<I',off+36,flags);sections[name.decode()]=off
    def raw(rva):
        for start,base in ((0x1000,0x400),(0x2000,0x1400),(0x3000,0x2400)):
            if start<=rva<start+0x1000:return base+rva-start
        raise AssertionError(rva)
    names=[b'ios_fex_band_base',b'ios_fex_band_end']
    targets=[0x2000,0x2008]
    if backend=='arm64ec':
        names += [b'BTCpu64FlushInstructionCache',b'BTCpu64NotifyMemoryDirty',b'BTCpu64IosAddAliasMapping',b'IosSubfloorProtocolV1']
        targets += [0x3000,0x3004,0x3008,0x2010]
        put('<Q',raw(0x2010),0x4d53460100000001)
        put('<II',opt+112+80,0x1300,208)
        put('<I',raw(0x1300),208);put('<Q',raw(0x1300)+200,0x180001400)
        put('<III',raw(0x1400),1,0x1420,1);put('<II',raw(0x1420),0x3001,0x1000)
    else:
        names += [b'MadeiraBTCpuIosReleaseThreadHolds',b'MadeiraBTCpuIosRetireThread'];targets += [0x3000,0x3004]
    put('<IIIII',raw(0x1000)+20,len(names),len(names),0x1040,0x1080,0x10c0)
    cursor=0x1100;slots={};strings={}
    for index,(name,target) in enumerate(zip(names,targets)):
        put('<I',raw(0x1040)+index*4,target);put('<I',raw(0x1080)+index*4,cursor);put('<H',raw(0x10c0)+index*2,index)
        encoded=name+b'\0';data[raw(cursor):raw(cursor)+len(encoded)]=encoded
        slots[name]=raw(0x1040)+index*4;strings[name]=raw(cursor);cursor+=len(encoded)
    markers=b'[fex-core-init-v1][fex-ir-pool-v1][fex-owner-allocator-v1]'
    if backend=='wow64':markers+=b'MadeiraBTCpuThreadInit[fex-thread-init-v1]MadeiraBTCpuWriteMemory[fex-guest-write-v1][fex-first-use-v1][fex-blocklist-v1][fex-hold-release-v1][fex-thread-retire-v1]'
    data[raw(0x1800):raw(0x1800)+len(markers)]=markers
    return data,{'pe':pe,'opt':opt,'raw':raw,'sections':sections,'slots':slots,'strings':strings}


def ntdll_fixture(machine):
    data=bytearray(0xc400)
    def put(fmt,off,*args):struct.pack_into(fmt,data,off,*args)
    data[:2]=b'MZ';put('<I',0x3c,0x80);data[0x80:0x84]=b'PE\0\0'
    put('<HHIIIHH',0x84,machine,4,0,0,0,240,0x2022)
    opt=0x98;put('<H',opt,0x20b);put('<Q',opt+24,0x180000000)
    put('<II',opt+56,0x10000,0x400);put('<I',opt+108,16)
    put('<II',opt+112,0x1000,0x300);put('<II',opt+152,0xe000,12)
    for index,(name,rva,raw,size,flags) in enumerate(((b'.edata',0x1000,0x400,0x1000,0x40000040),(b'.text',0x2000,0x1400,0x1000,0x60000020),(b'.data',0x4000,0x2400,0x9000,0xc0000040),(b'.reloc',0xe000,0xb400,0x1000,0x42000040))):
        off=opt+240+index*40;data[off:off+len(name)]=name;put('<IIII',off+8,size,rva,size,raw);put('<I',off+36,flags)
    def raw(rva):
        for start,base,size in ((0x1000,0x400,0x1000),(0x2000,0x1400,0x1000),(0x4000,0x2400,0x9000),(0xe000,0xb400,0x1000)):
            if start<=rva<start+size:return base+rva-start
        raise AssertionError(rva)
    put('<IIIII',raw(0x1000)+20,5,5,0x1100,0x1120,0x1140)
    put('<5I',raw(0x1100),0x4000,0xa100,0xa200,0xc240,0xc280)
    put('<5I',raw(0x1120),0x1180,0x11a0,0x11d0,0x11f0,0x1220)
    put('<5H',raw(0x1140),0,1,2,3,4)
    for name,rva in (('ios_xp_nt',0x1180),('ios_xp_nt_write_contract',0x11a0),('ios_srw_ring',0x11d0),('ios_srw_ring_idx',0x11f0),('ios_srw_history_write_contract',0x1220)):
        encoded=name.encode()+b'\0';data[raw(rva):raw(rva)+len(encoded)]=encoded
    abi=(ROOT/'build/ntdll-unix/native_counter_alias_abi.h').read_text()
    counter=int(re.search(r'#define MADEIRA_NATIVE_COUNTER_ABI_V1 (0x[0-9a-fA-F]+)ULL',abi)[1],16)
    history=int(re.search(r'#define MADEIRA_NATIVE_SRW_ABI_V1 (0x[0-9a-fA-F]+)ULL',abi)[1],16)
    put('<QIIQ',raw(0xa100),counter,24712,0,0);put('<QIIQQ',raw(0xc280),history,8192,16,0,0)
    put('<IIHH',raw(0xe000),0xa000,12,0,0)
    return data,raw


def run():
    package=load_module('madeira_io_abi_package',ROOT/'tools/check-io-abi-package.py')
    base,meta=fex_fixture();package.fex_cpu(bytes(base),'arm64ec')
    ec_machine=bytearray(base);struct.pack_into('<H',ec_machine,0x84,0xa641);package.fex_cpu(bytes(ec_machine),'arm64ec')
    native,unused=fex_fixture('wow64');package.fex_cpu(bytes(native),'wow64')
    # The existing allocator-band exports are runtime-initialized variables.
    # They may live in the zero-fill suffix of .data; only the versioned
    # capability's initialized magic must be present in the actual PE file.
    for backend in ('arm64ec','wow64'):
        bss,layout=fex_fixture(backend)
        struct.pack_into('<I',bss,layout['sections']['.data']+16,0x800)
        for index,name in enumerate((b'ios_fex_band_base',b'ios_fex_band_end')):
            struct.pack_into('<I',bss,layout['slots'][name],0x2800+index*8)
        package.fex_cpu(bytes(bss),backend)
    print('PASS existing ARM64EC/WoW64 runtime arena DATA may use private writable BSS; capability still requires initialized file bytes')
    count=0
    def bad(edit,label,reason=None):
        nonlocal count
        changed=bytearray(base);edit(changed)
        try:package.fex_cpu(bytes(changed),'arm64ec')
        except (AssertionError,ValueError,struct.error,IndexError) as error:
            if reason is not None:assert reason in str(error),(label,str(error))
            count+=1
        else:raise AssertionError('accepted invalid '+label)
    cap=meta['slots'][b'IosSubfloorProtocolV1'];cap_raw=meta['raw'](0x2010);data_section=meta['sections']['.data'];text_section=meta['sections']['.text']
    bad(lambda b:b.__setitem__(meta['strings'][b'IosSubfloorProtocolV1'],ord('x')),'missing DATA export')
    bad(lambda b:struct.pack_into('<Q',b,cap_raw,0),'old/mismatched capability')
    bad(lambda b:struct.pack_into('<I',b,cap,0x1100),'forwarded export')
    bad(lambda b:struct.pack_into('<I',b,cap,0x3000),'code pretending to be DATA')
    bad(lambda b:struct.pack_into('<I',b,cap,0x2011),'unaligned DATA')
    bad(lambda b:struct.pack_into('<I',b,cap,0x4000),'unmapped DATA extent')
    bad(lambda b:struct.pack_into('<I',b,cap,0xfffffff8),'out-of-image DATA RVA')
    bad(lambda b:struct.pack_into('<I',b,data_section+12,0x5000),'DATA section beyond image')
    bad(lambda b:struct.pack_into('<I',b,data_section+20,0xfffffff0),'DATA raw section beyond file')
    bad(lambda b:b.__delitem__(slice(cap_raw+4,None)),'truncated file-backed DATA bytes')
    bad(lambda b:struct.pack_into('<I',b,data_section+16,0x10),'zero-fill rather than file-backed capability',
        'IosSubfloorProtocolV1 requires eight file-backed bytes')
    for name in (b'ios_fex_band_base',b'ios_fex_band_end'):
        for rva in (0x2001,0x3000,0x4000,0xfffffff8):
            bad(lambda b,name=name,rva=rva:struct.pack_into('<I',b,meta['slots'][name],rva),
                'unaligned/executable/unmapped/out-of-image runtime arena DATA')
    for flags in (0x40000040,0x80000040,0xe0000040,0xd0000040,0xc2000040):
        bad(lambda b,flags=flags:struct.pack_into('<I',b,data_section+36,flags),'unreadable/nonwritable/executable/shared/discardable DATA')
    bad(lambda b:struct.pack_into('<I',b,meta['opt']+112+80,0),'absent hybrid load configuration')
    bad(lambda b:struct.pack_into('<Q',b,meta['raw'](0x1300)+200,0),'missing CHPE metadata')
    bad(lambda b:struct.pack_into('<II',b,meta['raw'](0x1420),0x3000,0x1000),'AMD64-only code map')
    bad(lambda b:struct.pack_into('<I',b,text_section+36,0xe0000020),'writable native code')
    bad(lambda b:struct.pack_into('<H',b,meta['pe']+4,0xaa64),'wrong backend architecture')
    bad(lambda b:struct.pack_into('<I',b,meta['raw'](0x1000)+24,5),'old backend without named protocol export')
    print(f'PASS production FEX package verifier: valid ARM64EC protocol and unchanged WoW64 accepted; {count} missing/forwarded/wrong-value/protection/bounds/CHPE/old-backend cases rejected')
    with tempfile.TemporaryDirectory(prefix='madeira-subfloor-package-') as directory:
        path=Path(directory)/'ntdll.dll'
        for machine,name in ((0xaa64,'aarch64'),(0x8664,'arm64ec'),(0xa641,'arm64ec')):
            image,raw=ntdll_fixture(machine);path.write_bytes(image)
            with contextlib.redirect_stdout(io.StringIO()):result=package.native_ntdll_contract(path,name)
            assert result['srw_contract_rva']==0xc280 and result['srw_ring_rva']==0xa200
            image[raw(0xc280)]=0;path.write_bytes(image)
            try:package.native_ntdll_contract(path,name)
            except ValueError:pass
            else:raise AssertionError('stale private writer contract accepted')
    print('PASS production final-package native verifier imports safely and checks actual A64/ARM64EC private counter/history contracts; stale bytes rejected, no CPU execution claim')


if __name__=='__main__':run()
