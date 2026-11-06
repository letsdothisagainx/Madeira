#!/usr/bin/env python3
"""Observe actual shared-section results for both Windows guest architectures."""
from pathlib import Path
import sys

def stage(source,header):
    start='NTSTATUS WINAPI NtCreateSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,'
    assert source.count(start)==1,'native section creator boundary changed'
    source=source.replace(start,'#include "'+str(header)+'"\n\n'+start,1)
    begin=source.index(start);end=source.index('NTSTATUS WINAPI NtCreateSectionEx(',begin)
    section=source[begin:end]
    declaration='    struct object_attributes *objattr;'
    assert section.count(declaration)==1
    section=section.replace(declaration,declaration+'\n    struct ios_htmlipc_section_snapshot ios_trace;',1)
    capture='    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;'
    assert section.count(capture)==1
    section=section.replace(capture,capture+'\n    ios_htmlipc_section_capture(&ios_trace,attr,size);',1)
    needle='    free( objattr );\n    return ret;'
    assert section.count(needle)==1,'native section creator completion changed'
    section=section.replace(needle,'    free( objattr );\n    ios_htmlipc_section_note("create",&ios_trace,ret,handle,protect,sec_flags);\n    return ret;',1)
    source=source[:begin]+section+source[end:]
    begin=source.index('NTSTATUS WINAPI NtOpenSection(');end=source.index('NTSTATUS WINAPI NtCreatePort(',begin)
    section=source[begin:end];declaration='    unsigned int ret;'
    assert section.count(declaration)==1
    section=section.replace(declaration,declaration+'\n    struct ios_htmlipc_section_snapshot ios_trace;',1)
    capture='    if ((ret = validate_open_object_attributes( attr ))) return ret;'
    assert section.count(capture)==1
    section=section.replace(capture,capture+'\n    ios_htmlipc_section_capture(&ios_trace,attr,NULL);',1)
    needle='    SERVER_END_REQ;\n    return ret;'
    assert section.count(needle)==1,'native section opener completion changed'
    section=section.replace(needle,'    SERVER_END_REQ;\n    ios_htmlipc_section_note("open",&ios_trace,ret,handle,0,0);\n    return ret;',1)
    return source[:begin]+section+source[end:]

if __name__=='__main__':
    path=Path(sys.argv[1]);header=Path(__file__).resolve().parents[2]/'build/ntdll-unix/htmlipc_section_trace.h'
    path.write_text(stage(path.read_text(),header))
