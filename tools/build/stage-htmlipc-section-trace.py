#!/usr/bin/env python3
"""Wrap unchanged native section implementations; observe every returned status."""
from pathlib import Path
import sys

def function_end(source,begin):
    cursor=source.index('{',begin)+1;depth=1
    while depth:
        depth+=(source[cursor]=='{')-(source[cursor]=='}');cursor+=1
    return cursor

def stage(source,header):
    wrappers=[
        ('NtCreateSection',
         'NTSTATUS WINAPI NtCreateSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,\n'
         '                                 const LARGE_INTEGER *size, ULONG protect,\n'
         '                                 ULONG sec_flags, HANDLE file )',
         'size','handle,access,attr,size,protect,sec_flags','protect,sec_flags','create'),
        ('NtOpenSection',
         'NTSTATUS WINAPI NtOpenSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )',
         'NULL','handle,access,attr','0,0','open')]
    for name,signature,size,arguments,protection,operation in wrappers:
        assert source.count(signature)==1,'native section boundary changed: '+name
        begin=source.index(signature);end=function_end(source,begin)
        original=source[begin:end]
        implementation=original.replace('NTSTATUS WINAPI '+name+'(', 'static NTSTATUS WINAPI ios_htmlipc_impl_'+name+'(',1)
        call_arguments=arguments+(',file' if name=='NtCreateSection' else '')
        wrapper=signature+'\n{\n'+(
            '    struct ios_htmlipc_section_snapshot ios_trace;\n'
            '    NTSTATUS status;\n'
            '    ios_htmlipc_section_capture(&ios_trace,attr,'+size+');\n'
            '    status=ios_htmlipc_impl_'+name+'('+call_arguments+');\n'
            '    ios_htmlipc_section_note("'+operation+'",&ios_trace,status,handle,'+protection+');\n'
            '    return status;\n}\n')
        source=source[:begin]+implementation+'\n\n'+wrapper+source[end:]
    include='#include "'+str(header)+'"\n\n'
    position=source.index('static NTSTATUS WINAPI ios_htmlipc_impl_NtCreateSection(')
    return source[:position]+include+source[position:]

if __name__=='__main__':
    path=Path(sys.argv[1]);header=Path(__file__).resolve().parents[2]/'build/ntdll-unix/htmlipc_section_trace.h'
    path.write_text(stage(path.read_text(),header))
