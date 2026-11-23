#!/usr/bin/env python3
"""Actual recorder, ordinary metadata fixtures only. Never execute guest code."""
from pathlib import Path
import os,shutil,subprocess,tempfile,argparse,re
r=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--require-swift',action='store_true');a=p.parse_args()
with tempfile.TemporaryDirectory() as d:
    t=Path(d)
    subprocess.run([os.getenv('CC','cc'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-pthread','-I'+str(r/'build/ntdll-unix'),str(r/'tests/host/run_evidence_ring_test.c'),'-o',str(t/'ring')],check=True)
    subprocess.run([str(t/'ring')],check=True)
    source=(r/'build/ntdll-unix/virtual_ios.c').read_text()
    for function in ['set_vprot','set_vprot_evidence_impl','decommit_pages','decommit_pages_evidence_impl']:
        assert len(re.findall(r'^static (?:BOOL|NTSTATUS) '+function+r'\([^;]+?\)\n\{',source,re.M))==1, function+' body/prototype confused'
    begin=source.index('void ios_evidence_access(');end=source.index('\n}',begin)+2
    access=source[begin:end]
    assert 'pthread_mutex_trylock' in access and 'mach_vm_region_recurse' in access
    assert 'pthread_mutex_lock(' not in access and 'ios_ts_read' not in access and 'mprotect(' not in access
    assert access.index('pthread_mutex_unlock(&virtual_mutex)') < access.index('kr=mach_vm_region_recurse')
    (t/'actual_evidence_access.h').write_text(access)
    subprocess.run([os.getenv('CC','cc'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-pthread','-I'+str(r/'build/ntdll-unix'),'-I'+str(t),str(r/'tests/host/run_evidence_access_test.c'),'-o',str(t/'access')],check=True)
    subprocess.run([str(t/'access')],check=True)
    swift=os.getenv('SWIFTC') or shutil.which('swiftc')
    if not swift:
        if a.require_swift:raise SystemExit('Swift compiler required')
        print('Swift runtime fixtures unavailable locally');raise SystemExit(0)
    (t/'Stubs.swift').write_text('import Foundation\nenum SteamGameDiagnostics { static func openOwned(_ root: Int32, _ parts: [String]) -> Int32? { nil } }\n')
    (t/'Check.swift').write_text(r'''import Foundation
enum FixtureError: Error { case check(String,Int) }
func verify(_ ok:@autoclosure ()->Bool,_ file:StaticString=#file,_ line:Int=#line) throws {
 if !ok() { throw FixtureError.check(String(describing:file),line) }
}
@main struct Check {
 static func main() { do { try run() } catch { print("FAIL recorder fixture: \(error)"); exit(1) } }
 static func run() throws {
  let root=URL(fileURLWithPath:CommandLine.arguments[1]); let fm=FileManager.default
  let store=try RunEvidenceStore(root:root)
  store.calibration("fixture")
  var w=[UInt64](repeating:0,count:48);w[0]=1;w[1]=3;w[2]=19;w[3]=100;w[4]=0x100;w[5]=34;w[9]=80;w[10]=0x7c3531d840;w[11]=0xc89ffcd3;w[12]=0x7a58142b58;w[13]=8;w[35]=1;w[37]=90;w[38]=3
  let (channel,busy)=RunEvidenceSchema.native(w)!;try verify(channel=="memory-access");try verify(busy["hostProtection"] is NSNull && busy["allocationBytes"] is NSNull && busy["allocationGeneration"] is NSNull);try verify(busy["bookkeepingResult"] as? String == "VM-lock-busy")
  w[35]=3;w[17]=1;w[18]=2;w[39]=2;w[43]=1;w[28]=3;w[29]=7
  let (_,changed)=RunEvidenceSchema.native(w)!;try verify(changed["metadataConsistency"] as? String == "VM-changed-during-query");try verify(changed["instruction"] as? String == "0xc89ffcd3")
  store.record(channel,changed)
  var operation=[UInt64](repeating:0,count:48);operation[0]=1;operation[1]=4;operation[8]=123
  let (_,op)=RunEvidenceSchema.native(operation)!
  try verify(op["nativeThreadLifetimeID"] is NSNull && op["operationToken"] as? String == "123")
  let technical=RunEvidenceSchema.fields("policy=stlr-fallback-v1 password=PRIVATE ticket=SECRET LRCPC2=false",keys:["policy","LRCPC2"])
  try verify(technical.count==2 && technical["policy"]=="stlr-fallback-v1")
  try verify(RunEvidenceRecorder.consoleEvent("11/23 09:19:43 [Networking] closed: NETWORK_DISCONNECT_TIMEDOUT") == "disconnect-network-timeout")
  try verify(RunEvidenceRecorder.consoleEvent("11/23 09:17:02 NetChan Setting Timeout to 30.00") == "timeout-configured")
  try verify(RunEvidenceRecorder.consoleEvent("chat: NETWORK_DISCONNECT_TIMEDOUT SECRET") == nil)
  try verify(RunEvidenceRecorder.consoleStamp("11/23 09:19:43 [Client]") == "09:19:43")
  let installed=RunEvidenceRecorder.installedBuildFields("\"AppState\" { \"buildid\" \"1234567\" \"LastUpdated\" \"12345\" \"username\" \"PRIVATE\" }")
  try verify(installed["buildid"]=="1234567" && installed["LastUpdated"]=="12345" && installed["username"]==nil)
  store.setConfig("effective",technical)
  store.graphic(["API":"CreateTexture2D","HRESULT":"E_OUTOFMEMORY"],category:"allocation")
  store.graphic(["API":"CreateTexture2D","HRESULT":"E_OUTOFMEMORY"],category:"allocation")
  let padding=String(repeating:"x",count:8000)
  for i in 0..<1800 {store.record("thread-frame-memory",["event":"fixture-normal-metadata","index":i,"padding":padding])}
  store.incident("post-activation-fixture");try store.checkpoint()
  try verify(store.overwritten>0)
  let snap=try RunEvidenceStore.snapshotRun(store.directory,destination:root.appendingPathComponent("snapshot"))
  try verify(snap["memory-access.jsonl"] != nil && snap["incident.jsonl"] != nil)
  let termination=try JSONSerialization.jsonObject(with:Data(contentsOf:snap["termination.json"]!)) as! [String:Any]
  try verify(termination["reason"] as? String == "unknown" && termination["cleanHostExitObserved"] as? Bool == false)
  let graphics=try JSONSerialization.jsonObject(with:Data(contentsOf:snap["graphics-summary.json"]!)) as! [String:Any]
  let errors=graphics["errors"] as! [[String:Any]]; try verify(errors.count==1 && (errors[0]["count"] as! NSNumber).intValue==2)
  let second=try RunEvidenceStore(root:root);second.record("timeline",["event":"app-session-start"]);try second.checkpoint()
  let previous=try RunEvidenceStore.snapshotRun(store.directory,destination:root.appendingPathComponent("previous-fixture"))
  let priorSummary=try JSONSerialization.jsonObject(with:Data(contentsOf:previous["run-summary.json"]!)) as! [String:Any]
  try verify(priorSummary["runID"] as? String == store.runID && store.runID != second.runID)
  let all=try fm.contentsOfDirectory(at:store.directory,includingPropertiesForKeys:[.fileSizeKey]);var total=0
  for file in all {total += (try file.resourceValues(forKeys:[.fileSizeKey]).fileSize) ?? 0}
  try verify(total<RunEvidenceSchema.perRunLimit)
  print("actual Swift recorder: schema/nulls, identity, clock separation, privacy, dedup, rotation, pinned incident, incomplete previous run, disk cap PASS; bytes=\(total)")
 }
}''')
    subprocess.run([swift,'-swift-version','5',str(r/'app/Madeira/RunEvidence.swift'),str(t/'Stubs.swift'),str(t/'Check.swift'),'-o',str(t/'check')],check=True)
    subprocess.run([str(t/'check'),str(t/'fixture')],check=True)
