#!/usr/bin/env python3
"""Compile the exact bounded diagnostic table; no process/emulation behavior."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix="madeira-fault-sites-") as folder:
    binary = Path(folder) / "counters"
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                    "-I" + str(root / "build/ntdll-unix"),
                    str(root / "tests/host/fault_site_counters_test.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    # Compile the actual signal-side snapshot/report functions with bounded
    # Mach-read stubs. This checks native argument widths and printf formats,
    # and proves that the report exposes exact coverage and first-event labels.
    signal = (root / "build/ntdll-unix/signal_arm64_ios.c").read_text()
    begin = signal.index("static struct ios_fault_site_table ios_fault_sites;")
    end = signal.index("/* ml691:", begin)
    integration = Path(folder) / "signal-counters.c"
    integration.write_text(r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "fault_site_counters.h"
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
_Static_assert(sizeof(void *)==8,"native TEB requires 64-bit host");
_Static_assert(offsetof(TEB,Tib.Self)==0x30,"pinned Wine native TEB self");
_Static_assert(offsetof(TEB,ClientId.UniqueProcess)==0x40,"pinned Wine native TEB pid");
_Static_assert(offsetof(TEB,ClientId.UniqueThread)==0x48,"pinned Wine native TEB tid");
_Static_assert(offsetof(TEB,Peb)==0x60,"pinned Wine native TEB Peb");
typedef uintptr_t mach_vm_address_t;
typedef size_t mach_vm_size_t;
static unsigned vm_reads,mapping_reads;
#define KERN_SUCCESS 0
static uintptr_t mach_task_self(void){return 1;}
static int mach_vm_read_overwrite(uintptr_t task,uintptr_t address,size_t bytes,uintptr_t out,size_t *got)
{assert(task==1);vm_reads++;memcpy((void *)out,(void *)address,bytes);*got=bytes;return 0;}
int ios_jit_pool_mapping_snapshot(uintptr_t address,struct ios_fault_mapping_meta *out)
{
    static unsigned long long generation=42;
    assert(address>=0x200000&&address<0x210000);mapping_reads++;
    *out=(struct ios_fault_mapping_meta){.pe_base=0x100000,.rx_base=0x200000,
        .mapped_by=0x500310000,.image_size=0x10000,.generation=42,.generation_address=&generation};
    return 1;
}
''' + signal[begin:end] + r'''
int main(void)
{
    TEB teb={0};teb.Tib.Self=&teb.Tib;teb.ClientId.UniqueProcess=(void *)0x64;
    teb.ClientId.UniqueThread=(void *)0x68;teb.Peb=(PPEB)0x500310000;
    uintptr_t target=0x208010;
    struct ios_fault_site_key key={.pc=0x206000,.teb=(uintptr_t)&teb,
        .target_page=0x208000,.port=17,.insn=0xf9000120,.family=MADEIRA_STORE_GPR};
    for(unsigned n=0;n<IOS_FAULT_SITE_EPOCH;n++)
        ios_fault_site_note(&ios_fault_sites,&key,ios_fault_site_snapshot_first,&target);
    assert(vm_reads==1&&mapping_reads==2);
    ios_fault_site_report_epoch();
    assert(ios_fault_sites.epoch==1&&!ios_fault_sites.total);
    /* A readable address with the wrong native TEB identity cannot authorize
     * attribution. Mapping snapshots remain explicitly first-event evidence. */
    teb.Tib.Self=NULL;
    struct ios_fault_site_metadata invalid={0};
    ios_fault_site_snapshot_first(&target,&key,&invalid);
    assert(!invalid.teb_read&&!invalid.pid&&!invalid.tid&&!invalid.peb);
    assert(vm_reads==2&&mapping_reads==4);
    return 0;
}
''')
    integrated_binary = Path(folder) / "signal-counters"
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                    "-DWINE_UNIX_LIB", "-I" + str(root / "build/ntdll-unix"),
                    "-I" + str(root / "wine/include"), str(integration),
                    "-o", str(integrated_binary)], check=True)
    reported = subprocess.run([str(integrated_binary)], check=True, capture_output=True, text=True).stderr
    assert "total=1000000 tracked=1000000 overflow=0" in reported
    assert "first-pid=64 first-tid=68" in reported
    assert "code-rva=6000" in reported and "data-rva=8010" in reported
    assert "code-owner=" in reported and "code-mapped-by=0x500310000" in reported
    assert "cookies=unchanged metadata=first-event" in reported
    assert reported.count("[fault-site-v1]") == 1
    assert reported.count("[fault-site-coverage-v1]") == 1
    family_increment = signal.index("__atomic_fetch_add(&ios_store_family_counts[")
    note = signal.index("ios_fault_site_note( &ios_fault_sites", family_increment)
    assert note < signal.index("ml680 WHAT DOES A FAULT ACTUALLY COST?", family_increment)
    print("PASS actual signal snapshot/report with pinned Wine TEB: native offsets/Self validated, one Mach read per new key, exact coverage; decoder path unchanged")
