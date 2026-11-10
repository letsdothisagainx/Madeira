#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 125hz
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Run actual bridge identity/lock/finalization bodies around config-write edges.

The Objective-C config parser and Wine snapshot are not modeled as verifiers:
the controlled edge writes the same environment between the actual production
blocks, including attempted global/game overrides. No Steam auth is simulated.
"""
from pathlib import Path
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--require-swift', action='store_true')
args = parser.parse_args()
source = (ROOT / 'app/Madeira/WineProcessBridge.m').read_text()


def function(marker):
    start = source.index(marker)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


start = source.index('        const char *native_launch = getenv("MADEIRA_NATIVE_STEAM_LAUNCH");')
end = source.index('        unsetenv("MADEIRA_STEAM_APPPATH");', start) + len('        unsetenv("MADEIRA_STEAM_APPPATH");')
early = source[start:end]
start = source.index('        /* standalone-probe-env-final:')
end = source.index('        // Steam S0:', start)
final = source[start:end]
assert source.index('game config env:') < start < source.index('__wine_main(argc, argv);')
assert source.count('if (madeira_env_is_locked(k.UTF8String))') == 2
assert 'standalone_launch && !strcmp(standalone_launch, "1")' in early

code = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#ifdef __APPLE__
#include <crt_externs.h>
#else
extern char **environ;
static char ***_NSGetEnviron(void) { return &environ; }
#endif
#include "steam_client_identity.h"
@LOCK@
@HELPER@
static const char *const identity[]={"SteamAppId","SteamGameId","SteamAppPath","steamappid","sTeAmGaMeId","STEAMAPPPATH"};
static void config(const char *key,const char *value) {
    if(!madeira_env_is_locked(key)) assert(setenv(key,value,1)==0);
}
static void apply(int overrides) {
@EARLY@
    /* The real global and game imports both use the actual lock predicate.
     * Write each twice to exercise last-line/game override ordering. */
    if(overrides) for(unsigned pass=0;pass<2;pass++) {
        config("SteamAppId",pass?"570":"356400");
        config("SteamGameId",pass?"570":"356400");
        config("SteamAppPath",pass?"C:\\Games\\Unrelated":"C:\\Program Files\\Thumper");
        config("steamappid","570");config("sTeAmGaMeId","570");config("STEAMAPPPATH","C:\\Games\\Unrelated");
        config("MADEIRA_STEAM_APPID","570");
        config("MADEIRA_STEAM_APPPATH","C:\\Games\\Unrelated");
        config("MADEIRA_STANDALONE_PROBE",pass?"0":"1");
        config("mAdEiRa_StAnDaLoNe_PrObE","1");
        config("MADEIRA_ENV_TEST_UNRELATED","preserved");
    }
@FINAL@
}
static void seed(const char *image) {
    const char *const names[]={"MADEIRA_NATIVE_STEAM_LAUNCH","MADEIRA_DOCK_SESSION","MADEIRA_STANDALONE_PROBE",
        "MADEIRA_STEAM_APPID","MADEIRA_STEAM_APPPATH","MADEIRA_ENV_LOCKED","MADEIRA_ENV_TEST_UNRELATED",
        "steamappid","sTeAmGaMeId","STEAMAPPPATH","mAdEiRa_StAnDaLoNe_PrObE"};
    for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++) unsetenv(names[i]);
    setenv("MADEIRA_EXE",image,1);
    setenv("SteamAppId","356400",1);setenv("SteamGameId","356400",1);
    setenv("SteamAppPath","C:\\Program Files\\Thumper",1);
}
static void empty(void) {
    for(unsigned i=0;i<sizeof(identity)/sizeof(identity[0]);i++) assert(!getenv(identity[i]));
    assert(!getenv("MADEIRA_STANDALONE_PROBE"));
    assert(!getenv("mAdEiRa_StAnDaLoNe_PrObE"));
    assert(!getenv("MADEIRA_STEAM_APPID")&&!getenv("MADEIRA_STEAM_APPPATH"));
}
int main(void) {
    assert(madeira_env_is_locked("MADEIRA_STANDALONE_PROBE"));
    assert(madeira_env_is_locked("mAdEiRa_StAnDaLoNe_PrObE"));
    assert(!madeira_env_is_locked("MADEIRA_STANDALONE_PROBE_EXTRA"));
    assert(!madeira_env_is_locked(NULL));
    seed("C:\\madeira-graphics-probe-owned\\pixel-readback-x64.exe");
    setenv("MADEIRA_STANDALONE_PROBE","1",1);
    setenv("mAdEiRa_StAnDaLoNe_PrObE","stale",1);
    setenv("steamappid","356400",1);setenv("SteamAppIdExtra","preserved-prefix",1);
    setenv("MADEIRA_STEAM_APPID","730",1);setenv("MADEIRA_STEAM_APPPATH","C:\\Games\\CS2",1);
    apply(1);empty();assert(!strcmp(getenv("MADEIRA_ENV_TEST_UNRELATED"),"preserved"));
    assert(!strcmp(getenv("SteamAppIdExtra"),"preserved-prefix"));
    /* A standalone result cannot clear a later explicit direct-game context. */
    seed("C:\\Games\\CS2\\game\\bin\\win64\\cs2.exe");
    setenv("MADEIRA_STEAM_APPID","730",1);setenv("MADEIRA_STEAM_APPPATH","C:\\Games\\CS2",1);
    apply(0);
    assert(!strcmp(getenv("SteamAppId"),"730")&&!strcmp(getenv("SteamGameId"),"730"));
    assert(!strcmp(getenv("SteamAppPath"),"C:\\Games\\CS2"));
    assert(!getenv("MADEIRA_STEAM_APPID")&&!getenv("MADEIRA_STEAM_APPPATH"));
    seed("C:\\Program Files (x86)\\Steam\\steam.exe");apply(0);empty();
    seed("cmd.exe");setenv("MADEIRA_NATIVE_STEAM_LAUNCH","1",1);apply(0);empty();
    seed("dockhost.exe");setenv("MADEIRA_DOCK_SESSION","1",1);apply(0);empty();
    /* Existing unrelated-title behavior is outside this scoped correction. */
    seed("explorer.exe");apply(0);assert(!strcmp(getenv("SteamAppId"),"356400"));
    /* Config cannot forge the app marker, and only exact host value1 is active. */
    const char *inactive[]={"0","true","1junk"};
    for(unsigned i=0;i<sizeof(inactive)/sizeof(inactive[0]);i++) {
        seed("cmd.exe");setenv("MADEIRA_STANDALONE_PROBE",inactive[i],1);apply(1);
        assert(!strcmp(getenv("SteamAppId"),"570")&&!getenv("MADEIRA_STANDALONE_PROBE"));
    }
    puts("PASS actual bridge standalone environment: stale/default/config Steam identity removed; host-only consumed marker, direct CS2, native Steam, Dock, normal config and later launches preserved");
}
'''.replace('@LOCK@', function('static int madeira_env_is_locked(')).replace('@HELPER@', function('static void madeira_clear_standalone_environment_key(')).replace('@EARLY@', early).replace('@FINAL@', final)
with tempfile.TemporaryDirectory(prefix='madeira-standalone-env-') as directory:
    src = Path(directory) / 'environment.c'
    exe = Path(directory) / 'environment'
    src.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-I' + str(ROOT / 'app/Madeira'), str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)

content = (ROOT / 'app/Madeira/ContentView.swift').read_text()
swift = shutil.which('swift')
if not swift:
    assert not args.require_swift, 'Swift is required for the actual host-marker branch'
    print('SKIP actual Swift host-marker execution: Swift unavailable; C bridge checks passed')
else:
    # Run the actual small branch, not a recreated marker implementation. Its
    # enclosing production entry supplies false for ordinary launch callers.
    assert 'standaloneProbe: Bool = false' in content
    branch = re.search(r'if standaloneProbe \{\s*setenv\("MADEIRA_STANDALONE_PROBE", "1", 1\)\s*\}\s*else \{\s*unsetenv\("MADEIRA_STANDALONE_PROBE"\)\s*\}', content)
    assert branch, 'actual host-owned marker branch missing'
    fixture = '''
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
func apply(standaloneProbe: Bool = false) { BRANCH }
setenv("SteamAppId", "730", 1)
setenv("SteamGameId", "730", 1)
setenv("SteamAppPath", "C:\\\\Games\\\\CS2", 1)
setenv("MADEIRA_STANDALONE_PROBE", "stale", 1)
apply(); assert(getenv("MADEIRA_STANDALONE_PROBE") == nil)
apply(standaloneProbe: true)
assert(String(cString: getenv("MADEIRA_STANDALONE_PROBE")!) == "1")
apply(); assert(getenv("MADEIRA_STANDALONE_PROBE") == nil)
assert(String(cString: getenv("SteamAppId")!) == "730")
assert(String(cString: getenv("SteamGameId")!) == "730")
assert(String(cString: getenv("SteamAppPath")!) == "C:\\\\Games\\\\CS2")
print("PASS actual Swift host marker: owned probe sets1; normal and later launches clear it; genuine direct-game metadata untouched")
'''.replace('BRANCH', branch.group(0))
    with tempfile.TemporaryDirectory(prefix='madeira-standalone-swift-') as directory:
        src = Path(directory) / 'main.swift'
        src.write_text(fixture)
        if sys.platform == 'darwin':
            exe = Path(directory) / 'marker'
            subprocess.run([shutil.which('swiftc'), '-sanitize=address', str(src), '-o', str(exe)], check=True)
            command = [str(exe)]
        else:
            command = [swift, str(src)]
        subprocess.run(command, check=True, timeout=60)
