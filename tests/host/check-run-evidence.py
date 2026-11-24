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
    subprocess.run([os.getenv('CC','cc'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-pthread','-I'+str(r/'build/ntdll-unix'),str(r/'tests/host/runtime_progress_test.c'),'-o',str(t/'runtime')],check=True)
    subprocess.run([str(t/'runtime')],check=True)
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
  let fixturePath=CommandLine.arguments[2]
  let fixture=try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:fixturePath))) as! [String:Any]
  RunEvidenceRecorder.start(documents:root.appendingPathComponent("parser-fixture"),bundle:[:])
  let recorder=RunEvidenceRecorder.shared!
  try recorder.queue.sync {
    let console=fixture["console"] as! [String],native=fixture["native"] as! [String]
    for (i,line) in console.enumerated(){recorder.observe(line,console:true,occurrence:"console-\(i)")}
    recorder.observe(console.last!,console:true,occurrence:"console-\(console.count-1)")
    for (i,line) in native.enumerated(){recorder.observe(line,console:false,occurrence:"native-\(i)")}
    for line in fixture["termination"] as! [String] {recorder.observe(line,console:false)}
    try recorder.store.checkpoint()
    let summary=try JSONSerialization.jsonObject(with:Data(contentsOf:recorder.store.directory.appendingPathComponent("graphics-summary.json"))) as! [String:Any]
    let rows=summary["errors"] as! [[String:Any]]
    func count(_ source:String)->Int {rows.filter{($0["fields"] as! [String:String])["sourceKind"]==source}.reduce(0){$0+($1["count"] as! NSNumber).intValue}}
    try verify(count("console-occurrence")==81 && count("native-admission-occurrence")==8)
    try verify((fixture["originalStructuredGraphicsRows"] as! NSNumber).intValue==299)
    let termination=try JSONSerialization.jsonObject(with:Data(contentsOf:recorder.store.directory.appendingPathComponent("termination.json"))) as! [String:Any]
    let exits=termination["observedGuestExits"] as! [[String:Any]]
    try verify(exits.contains{($0["exitStatus"] as? String)=="0xc0000005" && ($0["signedExitStatus"] as? Int64) == -1073741819})
    try verify(termination["hostRunningAtCheckpoint"] as? Bool == true && termination["reason"] as? String == "unknown")
    print("Run19 actual parser: 81 console occurrences + eight native reports, distinct from 299 old structured rows; repeated same occurrence suppressed; guest C0000005 with host running PASS")
  }
  let stallRetention=try RunEvidenceStore(root:root.appendingPathComponent("first-play-stall"))
  stallRetention.record("thread-frame-memory",["event":"main-progress","fixture":"first-post-activation-window"])
  stallRetention.incident("post-activation-frame-stall")
  let originalStall=try Data(contentsOf:stallRetention.directory.appendingPathComponent("incident-post-activation-first.jsonl"))
  for i in 0..<300 {stallRetention.record("thread-frame-memory",["event":"frame-progress","fixture":i]);stallRetention.beginAttempt();stallRetention.incident("post-activation-frame-stall")}
  let retainedStall=try Data(contentsOf:stallRetention.directory.appendingPathComponent("incident-post-activation-first.jsonl"))
  try verify(originalStall == retainedStall && originalStall.count<=256<<10)
  var runtime=[UInt64](repeating:0,count:48);runtime[0]=1;runtime[1]=16;runtime[4]=0x1000;runtime[5]=34;runtime[8]=98;runtime[9]=10;runtime[10]=40;runtime[11]=2;runtime[12]=3;runtime[16]=4;runtime[20]=30;runtime[24]=20;runtime[32]=1
  let (_,runtimeRow)=RunEvidenceSchema.native(runtime)!
  try verify(runtimeRow["event"] as? String == "main-runtime-operations" && runtimeRow["nativeThreadLifetimeID"] as? String == "98")
  try verify(runtimeRow["consistency"] as? String == "changed-during-query")
  let ops=runtimeRow["operations"] as! [[String:Any]];try verify(ops.count==4 && ops[0]["activeAgeNS"] as? UInt64 == 20)
  runtime[1]=17;runtime[13]=0x713000;runtime[14]=0x123;runtime[15]=1;runtime[16]=1
  for i in 20..<25 {runtime[i]=0}
  for(i,c) in "tier0.dll".utf8.enumerated(){runtime[20+i/8] |= UInt64(c)<<UInt64((i%8)*8)}

  let (_,resolved)=RunEvidenceSchema.native(runtime)!
  try verify(resolved["RIPEntryLimit"] as? Int == 256 && resolved["guestPC"] as? String == "0x713000")
  let privateResource=RunEvidenceRecorder.graphicsFailure("Error pipeline missing materials/private/customer.vmat_c")!
  try verify(privateResource.fields["resourceStableID"] != nil && !String(describing:privateResource).contains("customer"))
  try verify(RunEvidenceRecorder.graphicsFailure("chat missing resource materials/private/customer.vmat_c")==nil)
  let run20=try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[3]))) as! [String:Any]
  try verify((run20["console"] as! [String]).count==222 && (run20["native"] as! [String]).count==8)
  try verify(RunEvidenceRecorder.consoleEvent(run20["close"] as! String)=="disconnect-kicked-votedoff")
  try verify(run20["originalRetainedRequestResults"] as? Int == 7 && run20["originalRetainedFailedRequestResults"] as? Int == 0)
  let retained=try RunEvidenceStore(root:root.appendingPathComponent("failure-retention"))
  var deniedWord=[UInt64](repeating:0,count:48);deniedWord[0]=1;deniedWord[1]=13;deniedWord[9]=2;deniedWord[15]=3;deniedWord[16]=1048576;deniedWord[17]=65536;deniedWord[18]=1114112;deniedWord[20]=202196504;deniedWord[23]=201326592;deniedWord[24]=(3<<32)|1;deniedWord[25]=0x8007000e
  for id in 1...222 {
    deniedWord[2]=UInt64(id);deniedWord[8]=UInt64(id)
    let (_,detail)=RunEvidenceSchema.native(deniedWord)!
    retained.record("graphics-errors",detail);retained.record("graphics-errors",detail)
  }
  let firstWindow=try Data(contentsOf:retained.directory.appendingPathComponent("incident-first.jsonl"))
  let recentWindow=try Data(contentsOf:retained.directory.appendingPathComponent("incident.jsonl"))
  let beforeRoutine=retained.persistenceCounters()["logicalBytesWritten"] as! UInt64
  for _ in 0..<6119 {retained.record("graphics-errors",["event":"resource-reclamation-observation","releasedCapacityBytes":UInt64(0)])}
  for id in 0..<5000 {retained.record("graphics-errors",["event":"resource-request-result","HRESULT":"0x0","requestID":"success-\(id)"])}
  try verify(retained.persistenceCounters()["logicalBytesWritten"] as! UInt64 == beforeRoutine)
  for _ in 0..<100 {retained.incident("foreground-frame-stall")}
  let firstAfterStalls=try Data(contentsOf:retained.directory.appendingPathComponent("incident-first.jsonl"));try verify(firstAfterStalls==firstWindow)
  let recentAfterStalls=try Data(contentsOf:retained.directory.appendingPathComponent("incident.jsonl"));try verify(recentAfterStalls==recentWindow)
  for i in 0..<5000 {retained.record("graphics-errors",["event":"resource-request-counters","counter":i])}
  retained.incident("disconnect-kicked-votedoff");try retained.checkpoint();retained.flush()
  let snapshot=try RunEvidenceStore.snapshotRun(retained.directory,destination:root.appendingPathComponent("failure-export"),hostRunning:true)
  func jsonRows(_ name:String)throws->[[String:Any]]{try String(contentsOf:snapshot[name]!).split(separator:"\n").map {try JSONSerialization.jsonObject(with:Data($0.utf8)) as! [String:Any]}}
  let details=try jsonRows("resource-failures.jsonl")
  try verify(details.count==222 && Set(details.compactMap{$0["requestID"] as? String}).count==222)
  try verify(details.allSatisfy{$0["destinationEstimateBytes"] as? UInt64 == 1048576 && $0["temporaryGrowthBytes"] as? UInt64 == 65536 && $0["safetyFloorBytes"] as? UInt64 == 201326592})
  let firstDetails=try jsonRows("resource-failures-first.jsonl");try verify(firstDetails.first?["requestID"] as? String == "1")
  let exportedFirstWindow=try Data(contentsOf:snapshot["incident-first.jsonl"]!);try verify(exportedFirstWindow==firstWindow)
  let coverage=try JSONSerialization.jsonObject(with:Data(contentsOf:snapshot["run-summary.json"]!)) as! [String:Any]
  try verify((coverage["failureDetailRetention"] as! [String:Any])["duplicateDetailsSuppressed"] as? Int == 222)
  let bytes=try fm.contentsOfDirectory(at:retained.directory,includingPropertiesForKeys:[.fileSizeKey]).reduce(0){$0+((try $1.resourceValues(forKeys:[.fileSizeKey]).fileSize) ?? 0)}
  try verify(bytes<16<<20)
  var input=[UInt64](repeating:0,count:64);input[0]=1;input[2]=7;input[4]=3;input[5]=0x100;input[6]=34;input[7]=17;input[31]=1;input[32]=0x10;input[33]=0x20;input[34]=17;input[35]=18;input[36]=0x100;input[37]=34;input[39]=1;input[50]=1;input[48]=47;input[63]=1
  let route=RunEvidenceSchema.input(input)!
  try verify(route["targetMatchesWatchedCS2"] as? Bool == true && route["targetLifetimeID"] as? String == "0x100-34" && route["routeTargetTID"] as? String == "0x12")
  input[37]=35;try verify(RunEvidenceSchema.input(input)!["targetMatchesWatchedCS2"] as? Bool == false)
  input[37]=0;try verify(RunEvidenceSchema.input(input)!["targetMatchesWatchedCS2"] is NSNull)
  retained.record("input-path",route)
  try verify(RunEvidenceSchema.input([UInt64](repeating:0,count:63))==nil)
  print("Run20: 222 console vs 8 native reports vs 7 old successful results remain distinct; 222 unique failure details survive 11119 routine records and later stalls; first + terminal incidents, input identity and fixed disk bound PASS; routine logical writes=0 before aggregate checkpoint")

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
  var request=[UInt64](repeating:0,count:48);request[0]=1;request[1]=13;request[8]=99;request[9]=2;request[15]=(1<<32)|3;request[16]=22543008;request[17]=23003648;request[18]=45546656;request[19]=8388608;request[20]=239208200;request[23]=201326592;request[24]=(3<<32)|1;request[25]=0x8007000e
  let (_,denied)=RunEvidenceSchema.native(request)!
  try verify(denied["requestID"] as? String == "99" && denied["HRESULT"] as? String == "0x8007000e" && denied["chargedBytes"] as? UInt64 == 45546656 && denied["nativeThreadLifetimeID"] is NSNull)
  let unresolved=RunEvidenceRecorder.correlate(denied,current:"0x100-34",attempt:1,kind:"remote",phase:"active")
  try verify(unresolved["attemptID"] is NSNull && unresolved["processLifetimeID"] is NSNull)
  request[9]=6;request[15]=(2<<32);request[24]=0;request[25]=0x80070057
  let (_,view)=RunEvidenceSchema.native(request)!;try verify(view["width"] is NSNull && view["availableBytes"] is NSNull && view["HRESULT"] as? String == "0x80070057")
  request[1]=15;request[9]=0xc0000005;let (_,guest)=RunEvidenceSchema.native(request)!
  try verify(guest["exitStatus"] as? String == "0xc0000005" && guest["signedExitStatus"] as? Int64 == -1073741819)
  try verify(RunEvidenceRecorder.guestTermination("unrelated NtTerminateProcess text") == nil)
  let retired=RunEvidenceRecorder.guestTermination("[process-retire-v1] owner=0x100 known=1 native-threads=4 ready=0 reclaimed=0")!
  try verify(retired["owner"] as? String == "0x100" && retired["event"] as? String == "guest-retirement-or-quarantine")
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
    subprocess.run([str(t/'check'),str(t/'fixture'),str(r/'tests/fixtures/run19-resource-failure.json'),str(r/'tests/fixtures/run20-failure-retention.json')],check=True)
