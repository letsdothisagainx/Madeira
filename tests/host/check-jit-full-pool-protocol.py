#!/usr/bin/env python3
"""Run the actual bundled debugger script through a bounded GDB VM fixture.

This tests parsing and complete address/length forwarding, not a real debugserver
connection. In particular, 73,728 mocked page writes are not a latency benchmark.
"""
from pathlib import Path
import os
import json
import platform
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
node = os.environ.get('NODE') or shutil.which('node')

harness = r'''
const output = typeof testLog === 'function' ? testLog : console.log;
const assert = {
 equal(a,b,message='values differ'){if(a!==b)throw Error(message+': '+String(a)+' != '+String(b));},
 ok(value,message='assertion failed'){if(!value)throw Error(message);},
 deepEqual(a,b){this.equal(JSON.stringify(a),JSON.stringify(b));},
 match(value,expression){this.ok(expression.test(value),'unexpected request '+value);}
};
const actual = @ACTUAL@;
const before = @BEFORE@;
const PAGE = 0x4000n, SIZE = 0x48000000n, MAGIC = 0x4d4a5032n;
const high = 0x7c00004000n;
function little(value) {let s='';for(let i=0;i<8;i++){s+=(value&255n).toString(16).padStart(2,'0');value>>=8n;}return s;}
function decoded(value) {let result=0n;for(let i=7;i>=0;i--)result=result<<8n|BigInt('0x'+value.slice(i*2,i*2+2));return result;}
function execute(source, command, address=0n, size=0n, options={}) {
  const calls=[], packets=[], registerWrites=[];
  let value=address, delivered=false, oldHelperCalls=0;
  const pc=0x100ab8800n;
  const stop=`T05thread:1;20:${little(pc)};10:${little(command)};00:${little(address)};01:${little(size)};metype:6;medata:1;`;
  const context={
    get_pid:()=>73,log:()=>{},
    prepare_memory_region:()=>{oldHelperCalls++;if('legacyReply' in options)return options.legacyReply;throw Error('high full-pool protocol must not call the opaque legacy helper');},
    send_command:(packet)=>{
      calls.push(packet);
      if(packet.startsWith('vAttach;')||packet.startsWith('QSetIgnoredExceptions:')||packet.startsWith('QPassSignals:')) return 'OK';
      if(packet==='c') {if(!delivered){delivered=true;return stop;}return 'W00';}
      if(packet==='qSupported') return '';
      if(packet===`m${pc.toString(16)},4`) return 'a0013ed4'; // BRK #0xf00d
      if(packet.startsWith('P20=')) { assert.equal(packet,`P20=${little(pc+4n)};thread:1;`);return 'OK';}
      if(packet.startsWith('P0=')) {const m=/^P0=([0-9a-f]{16});thread:1;$/.exec(packet);assert.ok(m);value=decoded(m[1]);registerWrites.push(value);return 'OK';}
      if(packet.startsWith('_M')) return 'allocationReply' in options?options.allocationReply:'7000000000';
      if(packet.startsWith('M')) {const index=packets.length;packets.push(packet);return index===options.failAt?(options.failureReply??'E22'):'OK';}
      throw Error('Unexpected script request '+packet);
    }
  };
  new Function('get_pid','log','prepare_memory_region','send_command', source)(
    context.get_pid,context.log,context.prepare_memory_region,context.send_command);
  return {value,calls,packets,registerWrites,oldHelperCalls};
}
// A script from the installed failing source does not advertise this protocol.
// Its unsupported command leaves the caller's deliberately zero x0 unchanged.
const old=execute(before,8n);
assert.equal(old.value,0n);assert.equal(old.oldHelperCalls,0);
assert.ok(!old.calls.some(x=>x.startsWith('_M')||x.startsWith('M')));
output('BEFORE literal5b CAP8 remains zero; a client requiring the new capability must decline');

let result=execute(actual,8n);
assert.equal(result.value,MAGIC,'actual bundled script must advertise strict full-pool capability');
assert.equal(result.oldHelperCalls,0);assert.equal(result.packets.length,0);
for(const [address,size] of [[1n,0n],[0n,PAGE]]) {
  result=execute(actual,8n,address,size);assert.equal(result.value,0n);assert.equal(result.packets.length,0);
}
output('PASS actual CAP8: magic handshake, zero-input contract, no memory side effects');

result=execute(actual,9n,0n,SIZE,{allocationReply:'7000000000'});
assert.equal(result.value,0x7000000000n);
assert.equal(result.oldHelperCalls,0);assert.equal(result.packets.length,0);
assert.equal(result.calls.filter(x=>x.startsWith('_M')).length,1);
assert.match(result.calls.find(x=>x.startsWith('_M')),/^_M48000000,rx$/);
for(const reply of ['',null,'E22','E01','OK','0','7000000001','7000000000junk','0x7000000000',' 7000000000','ffffffffffffc000']) {
  result=execute(actual,9n,0n,SIZE,{allocationReply:reply});assert.equal(result.value,0n,'reject malformed/overflowing allocation reply '+reply);
  assert.equal(result.oldHelperCalls,0);assert.equal(result.packets.length,0);
}
for(const [address,size] of [[1n,SIZE],[0n,0n],[0n,PAGE-1n],[0n,SIZE+PAGE]]) {
  result=execute(actual,9n,address,size);assert.equal(result.value,0n);assert.ok(!result.calls.some(x=>x.startsWith('_M')));
}
output('PASS actual allocate-only command: exact size, strict replies, honest errors, no hidden preparation');

result=execute(actual,10n,high,2n*PAGE);
assert.equal(result.value,high);assert.equal(result.oldHelperCalls,0);
assert.deepEqual(result.packets,['M7c00004000,1:69','M7c00008000,1:69']);
assert.ok(!result.calls.some(x=>x.startsWith('_M')));
for(const failureReply of ['E22','','OKgarbage',null]) {
  result=execute(actual,10n,high,5n*PAGE,{failAt:2,failureReply});
  assert.equal(result.value,0n);assert.equal(result.packets.length,3);assert.equal(result.oldHelperCalls,0);
}
for(const [address,size] of [[0n,PAGE],[high+1n,PAGE],[high,0n],[high,PAGE-1n],[high,SIZE+PAGE],[0xffffffffffffc000n,2n*PAGE]]) {
  result=execute(actual,10n,address,size);assert.equal(result.value,0n);assert.equal(result.packets.length,0);assert.equal(result.oldHelperCalls,0);
}
output('PASS actual strict preparation: full-width high addresses, exact page progression and first-error stop');

// The proven low-host route intentionally retains StikJIT's batched helper.
// Its OK alone is not acceptance: C verifies every page marker and aliases.
result=execute(actual,10n,0x300000000n,SIZE,{legacyReply:'OK'});
assert.equal(result.value,0x300000000n);assert.equal(result.oldHelperCalls,1);assert.equal(result.packets.length,0);
result=execute(actual,10n,0x300000000n,SIZE,{legacyReply:'E22'});
assert.equal(result.value,0n);assert.equal(result.oldHelperCalls,1);
result=execute(actual,1n,high,2n*PAGE);
assert.equal(result.value,high);assert.equal(result.oldHelperCalls,0);
assert.deepEqual(result.packets,['M7c00004000,1:69','M7c00008000,1:69']);
result=execute(actual,1n,high,3n*PAGE,{failAt:1});
assert.equal(result.value,0n);assert.equal(result.oldHelperCalls,0);assert.equal(result.packets.length,2);
output('PASS low batched helper retained and later legacy CMD1 high addresses use full-width strict writes');


result=execute(actual,10n,0x7c00000000n,SIZE);
assert.equal(result.value,0x7c00000000n);assert.equal(result.packets.length,Number(SIZE/PAGE));
assert.equal(result.packets.at(-1),'M7c47ffc000,1:69');
output('PASS actual full1152MiB protocol validation: 73728 mocked pages; real network timing unmeasured');
'''
with tempfile.TemporaryDirectory(prefix='madeira-jit-script-') as temporary:
    file = Path(temporary)/'check.cjs'
    file.write_text(harness.replace('@ACTUAL@', json.dumps((root/'app/Madeira/madeira-jit.js').read_text()))
                          .replace('@BEFORE@', json.dumps((root/'tests/host/fixtures/jit-script-5b.js').read_text())))
    if platform.system() == 'Darwin':
        swiftc = os.environ.get('SWIFTC') or shutil.which('swiftc')
        if not swiftc: raise SystemExit('Swift/JavaScriptCore required for the real Apple debugger engine check')
        bridge = Path(temporary)/'engine.swift'; binary = Path(temporary)/'engine'
        bridge.write_text(r'''import Foundation
import JavaScriptCore
let context = JSContext()!
var failed: String?
context.exceptionHandler = { _, value in failed = value?.toString() ?? "Unknown JS failure" }
let output: @convention(block) (String) -> Void = { print($0) }
context.setObject(output, forKeyedSubscript: "testLog" as NSString)
let script = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)
context.evaluateScript(script)
if let failed { fputs(failed + "\n", stderr); exit(1) }
''')
        subprocess.run([swiftc,str(bridge),'-framework','JavaScriptCore','-o',str(binary)],check=True,timeout=120)
        subprocess.run([str(binary),str(file)],check=True,timeout=30)
    elif node:
        subprocess.run([node,str(file)],check=True,timeout=30)
    else:
        raise SystemExit('Node.js is required for this non-Apple host; Apple CI uses actual JavaScriptCore')
