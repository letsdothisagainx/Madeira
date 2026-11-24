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
    server=(r/'build/ntdll-unix/server_ios.c').read_text()
    begin=server.index('static uint64_t ios_ev_frame_count[');end=server.index('void madeira_evidence_host_io',begin)
    (t/'actual_evidence_frames.h').write_text(server[begin:end])
    subprocess.run([os.getenv('CC','cc'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(t),str(r/'tests/host/run_evidence_frame_test.c'),'-o',str(t/'frames')],check=True)
    subprocess.run([str(t/'frames')],check=True)
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
  let retention=root.appendingPathComponent("retention-fixture")
  try fm.createDirectory(at:retention,withIntermediateDirectories:true)
  let older=retention.appendingPathComponent(UUID().uuidString),recent=retention.appendingPathComponent(UUID().uuidString)
  try fm.createDirectory(at:older,withIntermediateDirectories:true);try fm.createDirectory(at:recent,withIntermediateDirectories:true)
  try Data("old incident".utf8).write(to:older.appendingPathComponent("incident.jsonl"))
  try Data("new incomplete journal".utf8).write(to:recent.appendingPathComponent("thread-frame-memory.0.jsonl"))
  try fm.setAttributes([.modificationDate:Date(timeIntervalSince1970:100)],ofItemAtPath:older.path)
  try fm.setAttributes([.modificationDate:Date(timeIntervalSince1970:200)],ofItemAtPath:recent.path)
  try verify(RunEvidenceStore.retainPreceding(in:retention)==recent.lastPathComponent)
  try verify(fm.fileExists(atPath:recent.appendingPathComponent("thread-frame-memory.0.jsonl").path) && !fm.fileExists(atPath:older.path))
  try fm.createDirectory(at:older,withIntermediateDirectories:true)
  try fm.setAttributes([.modificationDate:Date(timeIntervalSince1970:900)],ofItemAtPath:older.path)
  try Data(recent.lastPathComponent.utf8).write(to:retention.appendingPathComponent("last-session"))
  try verify(RunEvidenceStore.retainPreceding(in:retention)==recent.lastPathComponent)
  try fm.removeItem(at:retention)
  let store=try RunEvidenceStore(root:root)
  store.calibration("fixture")
  var w=[UInt64](repeating:0,count:48);w[0]=1;w[1]=3;w[2]=19;w[3]=100;w[4]=0x100;w[5]=34;w[9]=80;w[10]=0x7c3531d840;w[11]=0xc89ffcd3;w[12]=0x7a58142b58;w[13]=8;w[35]=1;w[37]=90;w[38]=3
  let (channel,busy)=RunEvidenceSchema.native(w)!;try verify(channel=="memory-access");try verify(busy["hostProtection"] is NSNull && busy["allocationBytes"] is NSNull && busy["allocationGeneration"] is NSNull);try verify(busy["bookkeepingResult"] as? String == "VM-lock-busy")
  w[35]=3;w[17]=1;w[18]=2;w[39]=2;w[43]=1;w[28]=3;w[29]=7;w[44]=123456
  let (_,changed)=RunEvidenceSchema.native(w)!;try verify(changed["metadataConsistency"] as? String == "VM-changed-during-query");try verify(changed["instruction"] as? String == "0xc89ffcd3")
  try verify(changed["machRegionObjectOffsetBytes"] as? String == "123456" && changed["accessType"] as? String == "store-release")
  try verify(RunEvidenceSchema.accessType(0x889fff56)=="store-release" && RunEvidenceSchema.accessType(0x99000356)=="store-release" && RunEvidenceSchema.accessType(0x3d800500)=="store")
  store.record(channel,changed)
  var page=[UInt64](repeating:0,count:48);page[0]=1;page[1]=11;page[4]=0x100;page[5]=34;page[9]=80;page[14]=88;page[15]=99;page[16]=1;page[17]=1;page[18]=2;page[19]=2;page[39]=2;page[40]=2;page[20]=0x10000;page[21]=100;page[23]=5;page[24]=2;page[28]=0x14000;page[29]=101;page[30]=5;page[36]=2
  let (_,pages)=RunEvidenceSchema.native(page)!
  let entries=pages["pages"] as! [[String:Any]]
  try verify(entries.count==2 && entries[1]["dispositionBits"] is NSNull && pages["allocationOrigin"] as? String == "Wine-private-virtual-allocation")
  var aggregate=page;aggregate[1]=12;aggregate[9]=5;aggregate[10]=2;aggregate[11]=3;aggregate[12]=4096
  let (_,agg)=RunEvidenceSchema.native(aggregate)!
  try verify(agg["execution"] as? String == "deferred" && agg["VM-lock-held"] as? Bool == false && agg["countCumulative"] as? UInt64 == 3)
  try verify(RunEvidenceRecorder.consoleEvent("Host activate: Loopback") == "loopback-activated")
  let connected=RunEvidenceRecorder.attemptAfter("loopback-connected",attempt:0,kind:"unknown")
  let activated=RunEvidenceRecorder.attemptAfter("loopback-activated",attempt:connected.0,kind:connected.1)
  try verify(connected.0==1 && activated.0==1 && activated.1=="loopback")
  for message in ["E_INVALIDARG CreateTexture2D width=32 height=32","shader compilation failed code=5","pipeline failed code=6","material missing"] {try verify(RunEvidenceRecorder.graphicsFailure(message) != nil)}
  try verify(RunEvidenceRecorder.graphicsFailure("chat: shader failed ticket=SECRET") == nil)
  let samples:[[String:Any]]=[
    ["owner":"0x100","lease":"34","registerCaptureBeginNS":"8000","intervalUS":UInt64(2),"userCPUUS":UInt64(0),"kernelCPUUS":UInt64(1)],
    ["owner":"0x100","lease":"34","registerCaptureBeginNS":"6000","intervalUS":UInt64(2),"userCPUUS":UInt64(0),"kernelCPUUS":UInt64(1)],
    ["owner":"0x100","lease":"34","registerCaptureBeginNS":"12000","intervalUS":UInt64(2),"userCPUUS":UInt64(0),"kernelCPUUS":UInt64(1)],
    ["owner":"0x100","lease":"34","registerCaptureBeginNS":"15000","intervalUS":UInt64(2),"userCPUUS":UInt64(0),"kernelCPUUS":UInt64(1)]]
  let cpu=RunEvidenceRecorder.cpuSummary(samples,start:5000,end:15000,lifetime:"0x100-34",background:[(11000,12000)])
  try verify(cpu["includedIntervals"] as? Int == 2 && cpu["boundaryIntervalsExcluded"] as? Int == 1 && cpu["backgroundIntervalsExcluded"] as? Int == 1 && cpu["intervalUS"] as? UInt64 == 4)
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
  let other=RunEvidenceRecorder.correlate(["owner":"0x100","lease":"35"],current:"0x100-34",attempt:1,kind:"remote",phase:"active")
  try verify(other["processLifetimeID"] as? String == "0x100-35" && other["attemptID"] is NSNull && other["phase"] as? String == "unclassified-other-lifetime")
  store.setConfig("effective",technical)
  store.graphic(["API":"CreateTexture2D","HRESULT":"E_OUTOFMEMORY"],category:"allocation")
  store.graphic(["API":"CreateTexture2D","HRESULT":"E_OUTOFMEMORY"],category:"allocation")
  try store.checkpoint()
  let initialWrites=store.persistenceCounters()["metadataWrites"] as! UInt64
  let initialBytes=store.persistenceCounters()["logicalBytesWritten"] as! UInt64
  for _ in 0..<100 {try store.checkpoint()}
  try verify((store.persistenceCounters()["metadataWrites"] as! UInt64)-initialWrites==200)
  print("100 unchanged checkpoints: 200 metadata writes, baseline method unconditionally wrote 500; logical bytes=\((store.persistenceCounters()["logicalBytesWritten"] as! UInt64)-initialBytes); measured checkpoint ns=\(store.persistenceCounters()["checkpointDurationNS"]!) (host fixture, not iPhone)")
  store.flush();let syncs=store.persistenceCounters()["fsyncCount"] as! UInt64;store.flush();try verify(store.persistenceCounters()["fsyncCount"] as! UInt64 == syncs)
  let padding=String(repeating:"x",count:8000)
  for i in 0..<1800 {store.record("thread-frame-memory",["event":"fixture-normal-metadata","index":i,"padding":padding])}
  store.incident("post-activation-fixture");try store.checkpoint()
  try verify(store.overwritten>0)
  let snap=try RunEvidenceStore.snapshotRun(store.directory,destination:root.appendingPathComponent("snapshot"),hostRunning:true)
  try verify(snap["memory-access.jsonl"] != nil && snap["incident.jsonl"] != nil)
  let termination=try JSONSerialization.jsonObject(with:Data(contentsOf:snap["termination.json"]!)) as! [String:Any]
  try verify(termination["reason"] as? String == "unknown" && termination["cleanHostExitObserved"] as? Bool == false && termination["hostRunningAtSnapshot"] as? Bool == true)
  let graphics=try JSONSerialization.jsonObject(with:Data(contentsOf:snap["graphics-summary.json"]!)) as! [String:Any]
  let errors=graphics["errors"] as! [[String:Any]]; try verify(errors.count==1 && (errors[0]["count"] as! NSNumber).intValue==2)
  let second=try RunEvidenceStore(root:root);second.record("timeline",["event":"app-session-start"]);try second.checkpoint()
  let previous=try RunEvidenceStore.snapshotRun(store.directory,destination:root.appendingPathComponent("previous-fixture"),hostRunning:false)
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
