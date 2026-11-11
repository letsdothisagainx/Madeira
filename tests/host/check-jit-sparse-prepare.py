#!/usr/bin/env python3
"""Exercise the actual MJP2 script at its GDB transport boundary.

The fixture models documented debugserver Z0/z0 state and replies. It proves
request/cleanup contracts and round-trip counts, not iPhone TXM acceptance or
network latency. Native Mach execution remains a separate mandatory gate.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HARNESS = r'''
const emit = typeof testLog === 'function' ? testLog : console.log;
const source = @SOURCE@;
const before = @BEFORE@;
const PAGE=0x4000n, SIZE=0x48000000n, BASE=0x7c00000000n;
function expect(ok, why) {if(!ok)throw Error(why);}
function little(x) {let s='';for(let i=0;i<8;i++){s+=(x&255n).toString(16).padStart(2,'0');x>>=8n;}return s;}
function readLittle(s) {let x=0n;for(let i=7;i>=0;i--)x=x<<8n|BigInt('0x'+s.slice(i*2,i*2+2));return x;}
function escaped(s) {let out='';for(const c of s){const n=c.charCodeAt(0);out+='}#$*'.includes(c)?'}'+String.fromCharCode(n^32):c;}return out;}
function execute(options={}) {
 const address=options.address??BASE,size=options.size??SIZE,cmd=options.command??10n;
 const active=new Set(),packets=[],registers=[],pages=[],serial=[],cleanups=[];
 let delivered=false,value=address,batches=0,queries=0,killed=false,killRequests=0,helper=0,resumes=0,maxBytes=0,failedClear=false;
 const pc=0x100ab8800n;
 const stop=`T05thread:1;20:${little(pc)};10:${little(cmd)};00:${little(address)};01:${little(size)};metype:6;medata:1;`;
 const send=packet=>{
  if(packet.startsWith('vAttach;')||packet.startsWith('QSetIgnoredExceptions:')||packet.startsWith('QPassSignals:'))return'OK';
  if(packet==='c'){resumes++;if(!delivered){delivered=true;return stop;}return'W00';}
  if(packet===`m${pc.toString(16)},4`)return'a0013ed4';
  if(packet.startsWith('P20='))return'OK';
  if(packet.startsWith('P0=')){
   if(registers.length&&options.failFinalRegister)return'E22';
   value=readLittle(packet.slice(3,19));registers.push(value);return'OK';
  }
  if(packet==='qSupported'){
   queries++;if(options.queryThrows)throw Error('owned query transport failure');
   return options.capability??`PacketSize=${(options.packetSize??0x20000).toString(16)};jMultiBreakpoint+;`;
  }
  if(packet.startsWith('jMultiBreakpoint:')){
   expect(registers[0]===address+2n,'must poison x0 before any breakpoint request');
   expect(!killed,'no request after inferior kill');
   const rows=JSON.parse(packet.slice('jMultiBreakpoint:'.length)).breakpoint_requests;
   expect(rows.length>0&&rows.length<=256&&rows.length%2===0,'bounded paired batch');
   expect(packet.length<=Math.min((options.packetSize??0x20000)-4,65536),'advertised complete packet bound');
   maxBytes=Math.max(maxBytes,packet.length);packets.push(packet);batches++;
   const results=[];
   for(let i=0;i<rows.length;i+=2){
    const m=/^Z0,([0-9a-f]{1,16}),4$/.exec(rows[i]);expect(!!m,'full-width set packet');
    const at=BigInt('0x'+m[1]);expect(rows[i+1]===`z0,${at.toString(16)},4`,'clear immediately follows its set');
    expect(at===address+BigInt(pages.length)*PAGE,'complete exact non-overlapping page progression');
    pages.push(at);active.add(at.toString());results.push(options.setFailure===pages.length?'E09':'OK');
    const fail=options.clearFailure===pages.length&&(options.clearAlways||!failedClear);
    if(fail){failedClear=true;results.push('E09');}
    else {active.delete(at.toString());results.push('OK');}
   }
   if(options.transportThrows)throw Error('owned ambiguous batch transport failure');
   let response=JSON.stringify({results});
   if(options.badReply!==undefined)response=options.badReply;
   if(options.escaped)response=escaped(response);
   return response;
  }
  if(packet.startsWith('z0,')){
   cleanups.push(packet);if(options.cleanupThrows)throw Error('owned cleanup transport failure');
   if(options.clearAlways)return'E09';
   const at=packet.split(',')[1];expect(active.has(BigInt('0x'+at).toString()),'only known active breakpoint cleanup');
   active.delete(BigInt('0x'+at).toString());return'OK';
  }
  if(packet==='k'){
   killRequests++;
   if(options.killThrows)throw Error('owned kill transport failure');
   if(options.killFails)return'E09';
   killed=true;active.clear();return'W00';
  }
  if(packet.startsWith('M')){serial.push(packet);return'OK';}
  throw Error('unexpected actual-script request '+packet);
 };
 new Function('get_pid','log','prepare_memory_region','send_command',options.source??source)(()=>73,()=>{},()=>{helper++;return'OK';},send);
 return{value,batches,queries,killed,killRequests,helper,resumes,maxBytes,pages,serial,cleanups,active,registers};
}
let r=execute({source:before});
expect(r.value===BASE&&r.serial.length===73728&&r.batches===0&&r.queries===0,'actual085c remains serial even with the same advertised peer features');
let oldBudgetRejected=false;
try {expect(r.serial.length+r.batches<=576,'sparse request budget');}catch(_){oldBudgetRejected=true;}
expect(oldBudgetRejected,'old production script must fail the new request-count regression');
emit('BEFORE pinned actual085c: 73728 synchronous M requests exceed576-request budget despite available peer batching');
r=execute();
expect(r.value===BASE+1n,'MJP2 zero-restoring marker mode');
expect(r.batches===576&&r.pages.length===73728,'full pool in576 sparse round trips');
expect(r.pages[0]===BASE&&r.pages[r.pages.length-1]===BASE+SIZE-PAGE,'first/last full-width addresses');
expect(!r.active.size&&!r.killed&&!r.serial.length&&!r.helper&&r.queries===1,'completed batches leave no breakpoint or alternate route');
expect(r.registers.length===2&&r.registers[0]===BASE+2n&&r.registers[1]===BASE+1n,'success publication only after complete preparation');
emit('PASS actual full1152MiB script: 73728 pages,576 bounded sparse packets,147456 checked set/clear results, no retained breakpoints');

r=execute({escaped:true});expect(r.value===BASE+1n&&!r.killed,'real debugserver escaped JSON accepted');
r=execute({address:0x123456789abcc000n,packetSize:512});
expect(r.value===0x123456789abcc001n&&r.maxBytes<=508&&!r.active.size,'64-bit precision and smaller packet segmentation');
emit('PASS actual response unescaping, full64-bit addresses and negotiated packet-length boundaries');

for(const badReply of ['', 'OK', '{}', '{"results":[]}', '{"results":["OKgarbage"]}', '{"results":null}', '{"results":[],"extra":1}', '}']){
 r=execute({badReply});expect(r.killed&&r.value===BASE+2n&&r.registers.length===1&&r.resumes===1,'ambiguous reply cannot publish or resume: '+badReply);
}
r=execute({transportThrows:true});expect(r.killed&&r.value===BASE+2n,'unknown transport state kills before resume');
r=execute({clearFailure:3});expect(!r.killed&&r.value===0n&&r.cleanups.length===1&&!r.active.size&&!r.serial.length,'known clear failure is cleaned and reported honestly');
r=execute({setFailure:3});expect(!r.killed&&r.value===0n&&!r.active.size&&!r.serial.length,'set failure with confirmed clear refuses preparation');
for(const opts of [{clearFailure:3,clearAlways:true},{clearFailure:3,cleanupThrows:true}]){
 r=execute(opts);expect(r.killed&&r.value===BASE+2n&&r.resumes===1,'unconfirmed cleanup cannot resume');
}
for(const opts of [{killFails:true},{killThrows:true}]){
 r=execute({clearFailure:3,clearAlways:true,...opts});
 expect(!r.killed&&r.killRequests===1&&r.active.size===1&&r.value===BASE+2n&&r.resumes===1,'failed kill retains poison for C mapping quarantine');
}
r=execute({failFinalRegister:true});expect(r.killed&&r.value===BASE+2n&&r.registers.length===1,'unacknowledged final register write cannot remove poison or resume');
emit('PASS exact error/short/malformed replies, cleanup failures and transport failures never fall through to successful preparation or serial retries');

for(const capability of ['', 'E22', 'PacketSize=20000;', 'PacketSize=20;jMultiBreakpoint+;', 'PacketSize=junk;jMultiBreakpoint+;']){
 r=execute({capability});expect(r.value===BASE&&r.serial.length===73728&&!r.batches&&!r.killed,'unsupported feature falls back before breakpoint writes');
}
r=execute({queryThrows:true});expect(r.value===0n&&!r.batches&&!r.serial.length&&!r.killed,'capability transport error fails without writes');
r=execute({address:0x300000000n});expect(r.value===0x300000000n&&r.helper===1&&!r.queries&&!r.batches,'low native helper remains unchanged');
r=execute({command:1n,size:2n*PAGE});expect(r.value===BASE&&r.serial.length===2&&!r.batches&&!r.queries,'later live-code CMD1 retains exact69 store path');
r=execute({size:2n*PAGE});expect(r.value===BASE&&r.serial.length===2&&!r.batches&&!r.queries,'nonfull CMD10 retains original marker semantics');
emit('PASS iOS26/unsupported fallback, failed capability probe, existing low helper and later live-code requests');
emit('UNMEASURED: real iPhone TXM acceptance/network latency, Steam startup, secure matchmaking and frame output');
'''


def main():
    with tempfile.TemporaryDirectory(prefix='madeira-sparse-prepare-') as directory:
        directory = Path(directory)
        script = directory/'check.cjs'
        old = (ROOT/'tests/host/fixtures/jit-script-085c.js').read_bytes()
        assert hashlib.sha256(old).hexdigest() == '85d961797bc1c947505fcf78e65819cf91a14ab24838bb613cfe42224d204c6d', 'installed085c control changed'
        script.write_text(HARNESS.replace('@SOURCE@', json.dumps((ROOT/'app/Madeira/madeira-jit.js').read_text()))
                         .replace('@BEFORE@', json.dumps(old.decode())))
        if platform.system() == 'Darwin':
            swift = os.environ.get('SWIFTC') or shutil.which('swiftc')
            if not swift:
                raise RuntimeError('Actual JavaScriptCore requires Swift on the Apple host')
            bridge, binary = directory/'engine.swift', directory/'engine'
            bridge.write_text('''import Foundation
import JavaScriptCore
let context=JSContext()!
var failed:String?
context.exceptionHandler={_,value in failed=value?.toString() ?? "JS failure"}
let output:@convention(block)(String)->Void={print($0)}
context.setObject(output,forKeyedSubscript:"testLog" as NSString)
context.evaluateScript(try String(contentsOfFile:CommandLine.arguments[1],encoding:.utf8))
if let failed {fputs(failed+"\\n",stderr);exit(1)}
''')
            subprocess.run([swift,str(bridge),'-framework','JavaScriptCore','-o',str(binary)],check=True,timeout=120)
            subprocess.run([str(binary),str(script)],check=True,timeout=90)
        else:
            node = os.environ.get('NODE') or shutil.which('node')
            if not node:
                raise RuntimeError('Node is required outside the Apple host')
            subprocess.run([node,str(script)],check=True,timeout=90)


if __name__ == '__main__':
    main()
