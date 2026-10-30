#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 125hz
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Compile the production service-preparation policy against scripted Win32
outcomes. No Wine, Valve binaries, accounts, services or game data are used."""
from pathlib import Path
import os, subprocess, tempfile
root = Path(__file__).resolve().parents[2]
code = r'''
#include <assert.h>
#include "prepare.h"
static unsigned manager_error, initial, installed, installer_error, start_error;
static unsigned managers, queries, installs, starts;
static uint32_t manager(void) { managers++; return manager_error; }
static uint32_t query(void) { assert(managers == 1); queries++; return queries == 1 ? initial : installed; }
static uint32_t install(void) { assert(initial == 1060 && queries == 1); installs++; return installer_error; }
static uint32_t start(void) { assert(queries && (!installs || queries == 2)); starts++; return start_error; }
static struct service_ops ops = {manager, query, install, start};
static void reset(void) { manager_error=initial=installed=installer_error=start_error=0; managers=queries=installs=starts=0; }
int main(void) {
 reset(); initial=1060; assert(prepare_service(&ops)==0 && installs==1 && queries==2 && starts==1);
 reset(); assert(prepare_service(&ops)==0 && installs==0 && starts==1);
 reset(); manager_error=1722; assert(prepare_service(&ops)==1722 && queries==0 && installs==0 && starts==0);
 reset(); initial=5; assert(prepare_service(&ops)==5 && installs==0 && starts==0);
 reset(); initial=1072; assert(prepare_service(&ops)==1072 && installs==0 && starts==0);
 reset(); initial=1060; installed=1060; assert(prepare_service(&ops)==1060 && installs==1 && starts==0);
 reset(); initial=1060; installed=5; assert(prepare_service(&ops)==5 && starts==0);
 unsigned failures[] = {2,3,5,193,216,1460,1};
 for(unsigned i=0;i<sizeof(failures)/sizeof(failures[0]);i++) {
  reset(); initial=1060; installer_error=failures[i];
  assert(prepare_service(&ops)==failures[i] && queries==1 && starts==0);
 }
 reset(); start_error=1053; assert(prepare_service(&ops)==1053 && installs==0);
 reset(); start_error=1062; assert(prepare_service(&ops)==1062);
 return 0;
}
'''
with tempfile.TemporaryDirectory() as folder:
    t=Path(folder); source=t/'service.c'; source.write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-I'+str(root/'build/steam-service'),str(source),'-o',str(t/'service')],check=True)
    subprocess.run([str(t/'service')],check=True)
print('PASS real preparation policy: SCM ordering, missing-only install, requery, error preservation, start failures')
# Architecture and registry writes remain the genuine installer's responsibility.
s=(root/'build/steam-service/main.c').read_text()
for forbidden in ['CreateServiceW(', 'RegSetValue', 'CreateNamedPipe', 'WriteFile(', 'TerminateProcess(']:
    assert forbidden not in s, forbidden
assert 'SCS_32BIT_BINARY' in s and 'SCS_64BIT_BINARY' in s
assert 'QueryServiceStatusEx' in s and 'SERVICE_RUNNING' in s
swift=(root/'app/Madeira/MadeiraDock.swift').read_text()
assert 'madeira-steam-service.exe' in swift and '&& \\(executable)' in swift
view=(root/'app/Madeira/ContentView.swift').read_text()
assert 'madeira-steam-service.exe' in view and 'if not "%errorlevel%"=="0" exit /b %errorlevel%' in view
print('PASS helper uses real SCM and installer APIs; both launch routes gate on genuine results')
