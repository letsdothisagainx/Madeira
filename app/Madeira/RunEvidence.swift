import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
#if os(iOS)
import UIKit
import os
import MetricKit
@_silgen_name("madeira_evidence_poll") private func nativeEvidencePoll(_ out: UnsafeMutablePointer<UInt64>, _ count: UInt32, _ stats: UnsafeMutablePointer<UInt64>) -> UInt32
@_silgen_name("madeira_evidence_frame") private func nativeEvidenceFrame(_ out: UnsafeMutablePointer<UInt64>)
@_silgen_name("madeira_evidence_host_io") private func nativeEvidenceIO(_ out: UnsafeMutablePointer<UInt64>)
@_silgen_name("madeira_evidence_host_vm_events") private func nativeEvidenceVMEvents(_ out: UnsafeMutablePointer<UInt64>)
@_silgen_name("winios_input_watch") private func nativeInputWatch(_ owner:UInt64,_ lease:UInt64,_ pid:UInt32)
@_silgen_name("winios_input_snapshot") private func nativeInputSnapshot(_ out: UnsafeMutablePointer<UInt64>)
@_silgen_name("madeira_evidence_backing") private func nativeEvidenceBacking()
#endif

/// Typed public Steam stages. Never retain prompt bodies, account data or DOM.
struct SteamLaunchObservation: Equatable {
    static let stages:Set<String>=["UpdatingAppInfo","ProcessingInstallScript","RunningInstallScript","SynchronizingCloud","SynchronizingStats","ShowInterstitials","CreatingProcess","WaitingGameWindow","Completed","DelayLaunch","SiteLicenseSeatCheckout","UpdatingApp","CheckingLegacyCDKeys","CheckingPrerequisites","VerifyingFiles"]
    var appID:Int, actionID:String, stage:String, waiting:Bool, continued:Bool, sourceTimestamp:String
    private static let expression=try? NSRegularExpression(pattern:#"^\[([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})\] GameAction \[AppID ([0-9]{1,10}), ActionID ([0-9]{1,20})\] : LaunchApp (changed task to ([A-Za-z]{1,48})|waiting for user response to ([A-Za-z]{1,48})|continues with user response)"#)
    static func parse(_ line:String)->Self? {
        guard line.utf8.count<=16384,line.contains("GameAction [AppID "),let re=expression,
              let m=re.firstMatch(in:line,range:NSRange(line.startIndex...,in:line)) else{return nil}
        func group(_ n:Int)->String?{Range(m.range(at:n),in:line).map{String(line[$0])}}
        guard let stamp=group(1),let app=group(2).flatMap(Int.init),app>0,let action=group(3) else{return nil}
        let waiting=group(6) != nil,continued=group(4)=="continues with user response"
        let name=group(5) ?? group(6) ?? "unknown"
        return Self(appID:app,actionID:action,stage:stages.contains(name) ? name : "unknown",waiting:waiting,continued:continued,sourceTimestamp:stamp)
    }
    static func date(_ stamp:String,timeZone:TimeZone = .current)->Date? {
        let f=DateFormatter();f.locale=Locale(identifier:"en_US_POSIX");f.timeZone=timeZone;f.dateFormat="yyyy-MM-dd HH:mm:ss";return f.date(from:stamp)
    }
}
struct SteamLaunchState: Equatable {
    static let notification=Notification.Name("MadeiraSteamLaunchProgress")
    var appID:Int,requestID:String,requestedNS:UInt64,requestedWall:Double
    var actionID:String?,stage="requested",waiting=false,observedNS:UInt64=0,stageBeganNS:UInt64=0,sourceTimestamp:String?,sourceWall:Double?,stageBeganSource:String?
    var cs2Lifetime:String?,firstPresentationNS:UInt64?
    mutating func apply(_ o:SteamLaunchObservation,now:UInt64,timeZone:TimeZone = .current)->Bool {
        guard cs2Lifetime==nil,o.appID==appID,let date=SteamLaunchObservation.date(o.sourceTimestamp,timeZone:timeZone),date.timeIntervalSince1970>=requestedWall-2,
              date.timeIntervalSince1970 >= (sourceWall ?? 0) else{return false}
        let next=o.continued ? "response-received" : o.stage
        if actionID != o.actionID || stage != next {stageBeganNS=now;stageBeganSource=o.sourceTimestamp}
        actionID=o.actionID;stage=next;waiting=o.waiting
        observedNS=now;sourceTimestamp=o.sourceTimestamp;sourceWall=date.timeIntervalSince1970;return true
    }
    func fields(now:UInt64)->[String:Any] {
        let age=observedNS>0 && now>=observedNS ? now-observedNS : nil
        var r:[String:Any]=["event":"steam-launch-progress","appID":appID,"requestID":requestID,"stage":stage]
        r["actionID"]=actionID as Any? ?? NSNull();r["captureNS"]=String(now);r["clockDomain"]="CLOCK_MONOTONIC"
        r["stageObservedNS"]=observedNS>0 ? String(observedNS) : NSNull();r["stageAgeNS"]=age as Any? ?? NSNull()
        r["stageBeganReceiptNS"]=String(stageBeganNS>0 ? stageBeganNS : requestedNS);r["stageBeganSourceTimestamp"]=stageBeganSource as Any? ?? NSNull()
        r["requestedNS"]=String(requestedNS);r["requestedWallUnix"]=requestedWall
        r["stageCurrency"]="last-observed; no-proof-stage-remains-current-between-transitions"
        r["source"]=cs2Lifetime != nil ? "native-CS2-lifetime-and-frame-observer" : observedNS>0 ? "appended-Steam-console-GameAction" : "user-launch-request"
        r["sourceTimestamp"]=sourceTimestamp as Any? ?? NSNull();r["sourceClock"]="Steam-local-wall; device-timezone-calibration; second-resolution; receipt-is-not-source-time"
        r["explicitUserResponseRequested"]=waiting;r["promptSubtype"]="unknown";r["promptSubtypeReason"]="private-prompt-body-not-collected; CEF-not-required"
        r["cs2ProcessLifetime"]=cs2Lifetime as Any? ?? NSNull();r["firstObservedCS2PresentationNS"]=firstPresentationNS.map(String.init) as Any? ?? NSNull()
        r["gameplayAcceptance"]="unverified; process-or-presentation-is-not-playability"
        return r
    }
}
/// File identity and byte boundaries, not a presumption based on export time.
struct RunLogSource {
    var initialIdentity:String?,initialBytes:UInt64?,initialNS:UInt64=0
    var identity:String?,bytes:UInt64?,observedNS:UInt64=0,modifiedWall:Double?,rotations=0,truncations=0
    mutating func observe(identity:String?,bytes:UInt64?,now:UInt64,modified:Double?) {
        if let old=self.identity,let identity,old != identity{rotations+=1}
        if self.identity==identity,let old=self.bytes,let bytes,bytes<old{truncations+=1}
        self.identity=identity;self.bytes=bytes;observedNS=now;modifiedWall=modified
    }
    func fields()->[String:Any] {
        let same=identity != nil && identity==initialIdentity && rotations==0 && truncations==0
        let historic=same ? min(initialBytes ?? 0,bytes ?? 0) : nil
        let appended=same && bytes != nil && initialBytes != nil ? max(bytes!,initialBytes!)-initialBytes! : nil
        var r:[String:Any]=["initialObservationNS":String(initialNS),"lastObservationNS":String(observedNS),"rotations":rotations,"truncations":truncations]
        r["initialFileIdentity"]=initialIdentity as Any? ?? NSNull();r["initialBytes"]=initialBytes as Any? ?? NSNull()
        r["lastFileIdentity"]=identity as Any? ?? NSNull();r["lastBytes"]=bytes as Any? ?? NSNull();r["modifiedUnixSeconds"]=modifiedWall as Any? ?? NSNull()
        r["preRunBytePrefix"]=historic as Any? ?? NSNull();r["bytesAppendedSinceInitialObservation"]=appended as Any? ?? NSNull()
        r["relationship"]=identity==nil ? "missing-or-unavailable" : same ? ((appended ?? 0)>0 ? "historical-prefix-and-run-appends" : "preexisting-content; no-run-appends-observed; early-current-startup-may-be-in-prefix") : "changed-file-generation; prior-byte-boundary-not-applicable"
        r["initialSourceState"]=initialIdentity==nil ? "missing-or-unavailable-at-start; not-proof-file-did-not-exist" : "present-at-start"
        r["interpretation"]="byte-relationship-only; source timestamps retain separate clock and uncertainty; no-gameplay-inference"
        return r
    }
}

/// Closed, metadata-only evidence. All persistence/serialization runs on one
/// utility queue. Native producers use a fixed try-only ring, never this queue.
/// Wire addresses are strings to preserve all 64 bits in JSON consumers.
enum RunEvidenceSchema {
    static let version = "madeira-evidence-v1"
    static let recordBytes = 48 * 8
    static let perRunLimit = 16 << 20
    static let channels = ["timeline", "thread-frame-memory", "memory-access", "vm-operations", "graphics-errors", "resource-failures", "input-path", "launch-progress"]
    static func mono() -> UInt64 {
        var t = timespec(); guard clock_gettime(CLOCK_MONOTONIC, &t) == 0 else { return 0 }
        return UInt64(t.tv_sec) * 1_000_000_000 + UInt64(t.tv_nsec)
    }
    static func hex(_ n: UInt64) -> String { "0x" + String(n, radix: 16) }
    static func json(_ object: Any) throws -> Data { try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) }
    static func safeAtom(_ s: String) -> Bool {
        !s.isEmpty && s.utf8.count <= 128 && s.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || "._+-=:".utf8.contains($0)
        }
    }
    /// Accept only numeric or explicitly enumerated values from known native
    /// tags. Unknown text, chat, endpoints and arbitrary arguments never enter.
    private static let allowedValues: Set<String> = ["true","false","fresh","disabled","enabled","effective","requested","balanced","low","already-low","wide","broad","blocks","classic","stlr-fallback-v1","physical-budget","creation-credit-or-owner","capacity-overflow","native-nil","gpu-reservation","initial-upload-failed","E_OUTOFMEMORY","E_INVALIDARG","bounded-hot-v2","nominal","fair","serious","critical","match","mismatch","system","game","steam","unknown"]
    static func fields(_ text: String, keys: Set<String>) -> [String: String] {
        var result: [String: String] = [:]
        for token in text.split(whereSeparator: { $0 == " " || $0 == "\t" }) {
            let pair = token.split(separator: "=", maxSplits: 1)
            guard pair.count == 2 else { continue }
            let k = String(pair[0]), v = String(pair[1])
            let numeric = v.range(of:"^(?:0x[0-9a-fA-F]{1,16}|[0-9a-fA-F]{8,64}|-?[0-9]+(?:\\.[0-9]+)?(?:MB|KB|ms|us)?|[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})$",options:.regularExpression) != nil
            if keys.contains(k), safeAtom(v), numeric || allowedValues.contains(v) { result[k] = v }
        }
        return result
    }
    /// Classify only existing decoded instructions; never execute or replace
    /// them. Unsupported atomic families remain explicit rather than guessed.
    static func accessType(_ insn:UInt64) -> String {
        if insn & 0x3ffffc00 == 0x089ffc00 {return "store-release"}
        if insn & 0x3ffffc00 == 0x08dffc00 {return "load-acquire"}
        let opc=(insn>>22)&3,vector=(insn>>26)&1
        if insn & 0x3f200c00 == 0x19000000 {return opc==0 ? "store-release" : "load-acquire-family"}
        if insn & 0x3b000000 == 0x39000000 || insn & 0x3b200c00 == 0x38200800 || insn & 0x3b200000 == 0x38000000 {
            if vector==0 && insn>>30==3 && opc==2 {return "prefetch-or-load"}
            return (vector==1 ? opc&1 != 0 : opc != 0) ? "load" : "store"
        }
        if insn & 0x3a000000 == 0x28000000 {return insn & (1<<22) != 0 ? "load-pair" : "store-pair"}
        return "unclassified-memory-family; consult-encoding"
    }
    static func input(_ w:[UInt64])->[String:Any]? {
        guard w.count==64,w[0]==1 else{return nil}
        var r:[String:Any]=["event":"input-path-progress","captureNS":String(w[1]),"clockDomain":"CLOCK_MONOTONIC","scope":"whole-host-input-bridge; target-lifetime-is-separate-from-draining-thread","generation":String(w[2]),"blockedReasonsBits":w[3],"queueCapacity":255,"queueDepth":w[4]==UInt64.max ? NSNull() : w[4],"motionRetentionNS":100000000,"drainLimitPerTurn":64]
        let counters=["enqueued","coalesced","motionDropped","edgeOverflowResets","producerLockBusy","dequeued","agedEventsDropped","contextResets","neutralizingReleases","maxQueueDepth","maxQueueAgeNS","contextRejected","textRejected","clippedMotion","drainTurns"]
        for(i,k) in counters.enumerated(){r[k]=w[8+i]}
        r["lastDrainNS"]=w[24]>0 ? String(w[24]) : NSNull()
        r["keyInjectionCalls"]=w[26];r["mouseInjectionCalls"]=w[27];r["injectionFailures"]=w[28];r["lastInjectionStatus"]=w[26]+w[27]>0 ? hex(w[29]) : NSNull()
        r["foregroundHWND"]=w[32]>0 ? hex(w[32]) : NSNull();r["focusHWND"]=w[39]==1 && w[33]>0 ? hex(w[33]) : NSNull()
        r["routeTargetPID"]=w[34]>0 ? hex(w[34]) : NSNull();r["routeTargetTID"]=w[35]>0 ? hex(w[35]) : NSNull()
        r["targetOwner"]=w[36]>0 ? hex(w[36]) : NSNull();r["targetLease"]=w[37]>0 ? String(w[37]) : NSNull()
        r["targetLifetimeID"]=w[36]>0 && w[37]>0 ? hex(w[36])+"-"+String(w[37]) : NSNull()
        r["routeCaptureNS"]=w[38]>0 ? String(w[38]) : NSNull();r["focusQueryStatus"]=w[39]==1 ? "observed" : "not-observed-or-unavailable"
        r["routeSnapshotConsistency"]=w[63]==1 ? "route-sequence-stable; counters-individually-atomic" : "route-changed-during-snapshot"
        r["messageProcedureReturns"]=w[40];r["lastMessageReturnPID"]=w[40]>0 ? hex(w[41]) : NSNull();r["lastMessageReturnTID"]=w[40]>0 ? hex(w[42]) : NSNull();r["lastMessageReturnHWND"]=w[40]>0 ? hex(w[43]) : NSNull();r["lastMessageReturnNS"]=w[40]>0 ? String(w[44]) : NSNull()
        r["lastMessageReturnLifetime"]=w[45]>0 && w[46]>0 ? hex(w[46])+"-"+String(w[45]) : NSNull()
        r["consumptionEvidence"]="successful-observed-input-window-procedure-return-only; no-proof-of-game-action-or-polled-raw-input-consumption"
        r["routingSource"]="existing-wineserver-get_foreground_thread-decision; active-and-focus-window-snapshot; registered-raw-input-sinks-may-also-receive"
        r["watchedCS2LifetimeID"]=w[5]>0 && w[6]>0 ? hex(w[5])+"-"+String(w[6]) : NSNull();r["watchedCS2PID"]=w[7]>0 ? hex(w[7]) : NSNull()
        r["watchedCS2ProcedureReturns"]=w[5]>0 ? w[58] : NSNull();r["lastWatchedCS2ReturnNS"]=w[58]>0 ? String(w[59]) : NSNull();r["lastWatchedCS2ReturnHWND"]=w[58]>0 ? hex(w[60]) : NSNull();r["lastWatchedCS2ReturnTID"]=w[58]>0 ? hex(w[57]) : NSNull()
        r["consumptionLeaseUnavailable"]=w[61];r["watchedIdentityConsistency"]=w[31]==1 ? "watch-sequence-stable; counters-individually-atomic" : "watch-changed-during-query"
        r["targetMatchesWatchedCS2"]=w[36]>0 && w[37]>0 && w[5]>0 && w[6]>0 ? (w[36]==w[5] && w[37]==w[6]) : NSNull()
        r["effectiveSourceFlags"]=w[50]>0 ? w[48] : NSNull();r["sourceSnapshotNS"]=w[55]>0 ? String(w[55]) : NSNull();r["lastContextChangeNS"]=w[56]>0 ? String(w[56]) : NSNull();r["physicalChangeCallbacks"]=w[49];r["physicalSlot0Samples"]=w[50];r["translatedDigitalActions"]=w[51];r["translatedMotionEvents"]=w[52];r["bindingSignature"]=w[53]>0 ? hex(w[53]) : NSNull();r["focusBlockedSamples"]=w[54]
        func age(_ timestamp:UInt64)->Any {timestamp>0 && w[1]>=timestamp ? w[1]-timestamp : NSNull()}
        r["routeAgeNS"]=age(w[38]);r["routeCurrency"]=w[38]==0 ? "unavailable" : "last-known-at-routeCaptureNS; not-a-current-focus-query"
        r["physicalSourceAgeNS"]=age(w[55]);r["bindingSnapshotNS"]=w[25]>0 ? String(w[25]) : NSNull();r["bindingAgeNS"]=age(w[25])
        r["samplerInvocations"]=w[23];r["controllerStateSnapshotNS"]=w[47]>0 ? String(w[47]) : NSNull();r["controllerStateAgeNS"]=age(w[47])
        r["controllerObservation"]=w[47]>0 ? "cached-physical-profile-and-mode-observed; input-changes-and-data-samples-counted-separately" : "physical-profile-observer-unavailable; zero-samples-does-not-prove-disconnection"
        r["physicalSamplingState"]=w[50]>0 ? "slot-zero-data-samples-observed" : "no-slot-zero-data-samples-observed; not-a-connection-status"
        if w[47]>0 {r["effectiveSourceFlags"]=w[48]&63}
        r["lastPhysicalActivity"]=w[50]>0 && w[55]>=w[47] ? w[48]&64 != 0 : NSNull()
        r["physicalActivityCurrency"]="last slot-zero data sample only; unavailable when newer sampler-state overwrote flags"
        r["sourceFlagMeaning"]="1=physical-enabled 2=KBM 4=slot0-connected 8=app-active 16=library-owns 32=native-UI-focus-allows physical activity is separate lastPhysicalActivity; last-sample-not-current-device-query"
        return r
    }
    static func native(_ w: [UInt64]) -> (String, [String: Any])? {
        guard w.count == 48, w[0] == 1 else { return nil }
        var r: [String: Any] = ["nativeSequence": String(w[2]), "nativeMonotonicNS": String(w[3]), "nativeClock": "CLOCK_MONOTONIC",
            "owner": w[4]>0 ? hex(w[4]) : NSNull(), "lease": w[5]>0 ? String(w[5]) : NSNull(), "pid": w[6]>0 ? hex(w[6]) : NSNull(), "tid": w[7]>0 ? hex(w[7]) : NSNull(), "nativeThreadLifetimeID": w[8]>0 ? String(w[8]) : NSNull()]
        if ![UInt64(1),2,3,10,11].contains(w[1]) {r["nativeThreadLifetimeID"]=NSNull()}
        switch w[1] {
        case 13:
            r["event"] = w[9]==8 ? "resource-reclamation-observation" : "resource-request-result"
            r["requestID"] = String(w[8]); r["requestIdentityScope"]="runID-and-native-requestID; distinct-from-console-occurrences"
            r["requireNativeLifetime"]=true
            r["requestBeginNS"]=String(w[29]);r["stage"]=[1:"descriptor",2:"admission-refused",3:"native-allocation",4:"initialization",5:"creation-success",6:"dependent-SRV",7:"GPU-credit-handoff",8:"reclamation",9:"unwound-without-result"][w[9]] ?? "unknown"
            r["source"]="direct-pointer-free-DXMT-creation-boundary"
            if w[9]==8 {
                r["beforeFootprintBytes"]=w[10]>0 ? w[10] : NSNull();r["releasedCapacityBytes"]=w[11]
                r["afterFootprintBytes"]=w[12]>0 ? w[12] : NSNull()
                r["observedFootprintDropBytes"]=w[10]>0 && w[12]>0 ? (w[10]>=w[12] ? w[10]-w[12] : 0) : NSNull()
                r["beforeSnapshotPESteadyNS"]=String(w[13]);r["afterSnapshotPESteadyNS"]=String(w[14])
                r["eligibleCapacityBytes"]=NSNull();r["scope"]="completed-owner-capacity-release-not-physical-guarantee; whole-host-footprint-observed-separately; PE-steady-clock-not-calibrated-to-native"
            } else {
                r["kind"]=w[15]>>32==2 ? "shader-resource-view" : "texture"
                for (index,lo,hi) in [(10,"width","height"),(11,"depth","mipCount"),(12,"arrayCount","sampleCount"),(13,"format","textureType"),(14,"usageFlags","storageOptions")] {
                    r[lo]=w[15]&2 != 0 ? w[index]&0xffffffff : NSNull();r[hi]=w[15]&2 != 0 ? w[index]>>32 : NSNull()
                }
                r["initialDataPresent"]=w[15]&1 != 0
                r["destinationEstimateBytes"]=w[15]&2 != 0 ? w[16] : NSNull()
                for (index,key) in [(17,"temporaryGrowthBytes"),(18,"chargedBytes"),(19,"uploadWindowBytes"),(20,"availableBytes"),(21,"footprintBytes"),(22,"pendingCreditsBytes"),(23,"safetyFloorBytes")] {r[key]=w[24]>>32>0 ? w[index] : NSNull()}
                r["budgetReason"]=w[24]>>32>0 ? w[24]&0xffffffff : NSNull();r["nativePermitStatus"]=w[24]>>32>0 ? w[24]>>32 : NSNull()
                r["HRESULT"]=w[9]==9 ? NSNull() : hex(w[25]&0xffffffff)
                r["resourceIdentity"]=w[26]>0 ? hex(w[26]) : NSNull();r["resourceIdentityScope"]="local-COM-pointer-value; join-with-request-lifetime; no-payload-read"
                r["uploadEventIdentity"]=w[27]>0 ? hex(w[27]) : NSNull();r["uploadCompletionTarget"]=w[28]>0 ? String(w[28]) : NSNull()
                r["uploadPolicy"]=w[19]>0 ? "bounded-format-block-window-v1" : "ordinary-allocator"
                r["layoutStatus"]="Metal-descriptor-and-policy; source-payload-and-caller-pitches-not-recorded"
                r["nativeErrorDetail"]="unavailable-if-not-returned-by-native-API; HRESULT-is-preserved"
                r["detailRetention"]="first-32-and-recent-96-native-failure-lane; try-lock-drops-and-overwrites-counted; successful-detail-one-in-64; aggregate-counts-separate"
            }
            return ("graphics-errors",r)
        case 14:
            r["event"]="resource-request-counters";r["requireNativeLifetime"]=true
            for (i,k) in ["started","nonFailureResults","outOfMemoryResults","invalidArgumentResults","otherFailureResults","admissionRefusals","nativeAllocationFailures","initializationFailures","viewFailures","unwoundWithoutResult","detailsAccepted","detailsTryLockDropped","failureDetailLaneOverwritten","reclamationObservations","firstFailureNS","lastFailureNS"].enumerated() {r[k]=w[9+i]}
            r["scope"]="host-app-session; direct-request-results-not-console-occurrences; stage-subcounts-overlap-results"
            return ("graphics-errors",r)
        case 16:
            r["event"]="main-runtime-operations";r["nativeThreadLifetimeID"]=String(w[8])
            r["registerCaptureBeginNS"]=String(w[9]);r["counterQueryNS"]=String(w[10])
            r["captureToQueryNS"]=w[10]>=w[9] && w[9]>0 ? String(w[10]-w[9]) : "unavailable"
            r["updateBefore"]=String(w[11]);r["updateAfter"]=String(w[12])
            r["consistency"]=w[11]==w[12] ? "no-update-observed; individually-atomic-not-transactional" : "changed-during-query"
            r["scope"]="validated-CS2-initial-native-thread; inclusive-nested-elapsed-not-CPU; uninstrumented-work-unavailable"
            r["operations"]=["server-call-including-direct-and-IPC","uninterrupted-mutex-acquisition","server-select-wait","explicit-VM-operation"].enumerated().map { i,name -> [String:Any] in
                ["kind":name,"begunCumulative":w[16+i],"completedInclusiveNSCumulative":w[20+i],"activeBeginNS":w[24+i]>0 ? String(w[24+i]) : NSNull(),"activeDepth":w[32+i],"lastDetail":hex(w[28+i]),"activeAgeNS":w[24+i]>0 && w[10]>=w[24+i] ? w[10]-w[24+i] : NSNull(),"detailMeaning":"request-opcode / mutex-address-token / select-flags / VM-operation-code; not-call-stack"]
            }
            return ("thread-frame-memory",r)
        case 17:
            r["event"]="main-PC-resolution";r["nativeThreadLifetimeID"]=String(w[8]);r["registerCaptureBeginNS"]=String(w[9]);r["hostPC"]=hex(w[10]);r["queryBeginNS"]=String(w[11]);r["queryDurationNS"]=w[12]
            r["captureToQueryNS"]=w[11]>=w[9] && w[9]>0 ? String(w[11]-w[9]) : "unavailable"
            r["guestPC"]=w[13]>0 ? hex(w[13]) : NSNull();r["RVA"]=w[15]>0 ? hex(w[14]) : NSNull()
            var bytes:[UInt8]=[];for word in w[20..<25] {for n in 0..<8 {let c=UInt8(truncatingIfNeeded:word>>UInt64(n*8));if c==0 {break};bytes.append(c)}}
            let name=String(bytes:bytes,encoding:.ascii) ?? ""
            r["module"]=w[15]>0 && safeAtom(name) ? name : "unavailable"
            r["status"]=[0:"unavailable",1:"bounded-generated-block-lookup",2:"image-mapping",3:"no-generated-mapping-within-budget"][w[16]] ?? "unknown"
            r["moduleStatus"]=w[15]>0 ? "cached-loader-map-matching-owner-and-lease" : "cached-module-unavailable"
            r["confidence"]="post-resume-JIT-metadata; not-atomic-with-register-capture; no-saved-guest-RIP-substitution"
            r["moduleCacheObservedNS"]=w[17]>0 ? String(w[17]) : NSNull()
            r["moduleCacheAgeNS"]=w[17]>0 && w[11]>=w[17] ? w[11]-w[17] : NSNull()
            r["moduleCacheCurrency"]="last-known-loader-map; unload-reload-after-cache-not-excluded"
            r["RIPEntryLimit"]=256
            return ("thread-frame-memory",r)
        case 15:
            r["event"]="guest-process-exit";r["requireNativeLifetime"]=true;r["exitStatus"]=hex(w[9]&0xffffffff)
            r["signedExitStatus"]=Int64(Int32(bitPattern:UInt32(truncatingIfNeeded:w[9])))
            r["source"]="native-process-exit-wrapper";r["confidence"]="observed-guest-exit-status; not-host-termination"
            return ("timeline",r)
        case 1:
            r["event"] = "cs2-start-observed"; r["teb"] = hex(w[9]); r["source"] = "validated-initial-thread"; return ("timeline", r)
        case 2:
            r["event"] = "main-progress"
            r["registerCaptureBeginNS"] = String(w[9])
            r["hostPC"] = hex(w[10])
            r["instruction"] = hex(w[11])
            r["effectiveAddress"] = hex(w[12])
            r["widthBytes"] = w[13]
            r["intervalUS"] = w[14]
            r["userCPUUS"] = w[14]>0 ? w[15] : NSNull()
            r["kernelCPUUS"] = w[14]>0 ? w[16] : NSNull()
            r["cpuScope"] = "one-native-thread"
            r["runState"] = w[17]
            r["observedSuspendCount"] = w[18]
            r["captured"] = w[19] == 1
            r["suspendResult"] = String(Int64(bitPattern: w[20]))
            r["resumeResult"] = String(Int64(bitPattern: w[21]))
            r["observerHoldUS"] = w[22]
            r["hostLR"] = hex(w[23])
            r["imagePC"] = w[24] == 0 ? NSNull() : hex(w[24])
            r["guestResolution"] = "image-PC-if-available; generated-block-resolution-in-sanitized-log"
            r["observer"] = "existing-main-snapshot-no-additional-suspension"
            return ("thread-frame-memory", r)
        case 3:
            r["event"] = "sampled-access-mapping"
            r["registerCaptureBeginNS"] = String(w[9])
            r["hostPC"] = hex(w[10])
            r["instruction"] = hex(w[11])
            r["effectiveAddress"] = hex(w[12])
            r["widthBytes"] = w[13]
            r["accessType"] = accessType(w[11])
            r["alignmentRemainder"] = w[41]
            r["crossesHostPage"] = w[42] == 1
            r["metadataQueryNS"] = String(w[37])
            r["queryDurationNS"] = w[38]
            r["captureToQueryNS"] = w[37] >= w[9] && w[9] != 0 ? String(w[37]-w[9]) : "unavailable"
            r["bookkeepingResult"] = w[35] == 1 ? "VM-lock-busy" : w[35] == 2 ? "view-not-found" : "copied-under-try-lock"
            r["allocationBase"] = w[35]==3 ? hex(w[14]) : NSNull()
            r["allocationBytes"] = w[35]==3 ? w[15] : NSNull()
            r["allocationGeneration"] = w[35]==3 ? String(w[16]) : NSNull()
            r["recordedAllocationOwner"] = w[35]==3 && w[22]>0 ? hex(w[22]) : NSNull()
            r["allocationOwnerLease"] = NSNull()
            r["allocationOwnerLeaseStatus"] = "not-recorded-at-allocation; sampling-owner-lease-is-separate"
            r["recordedOwnerStatus"] = "creation-context-only; inheritance-and-transfers-not-tracked; no-reclaim-permission"
            r["vmEpochBefore"] = w[35] != 1 ? String(w[17]) : NSNull()
            r["vmEpochAfter"] = w[35] != 1 ? String(w[18]) : NSNull()
            r["metadataConsistency"] = w[39] == 1 ? "epoch-unchanged; not-atomic-with-registers" : w[39] == 2 ? "VM-changed-during-query" : "unavailable"
            r["backing"] = [0:"unknown",1:"anonymous-view",2:"Madeira-backing-ledger",3:"image",4:"JIT-or-alias",5:"section"][w[19]] ?? "unknown"
            r["backingFileOpenLifetime"] = w[23]>0 ? String(w[23]) : NSNull()
            r["fileIdentityScope"]="host-app-open-generation; join-with-runID; not-inode-or-pager-object-proof"
            r["extentGeneration"] = w[20] == 0 ? NSNull() : String(w[20])
            r["fileOffsetAtEA"] = w[19] == 2 ? String(w[21]) : NSNull()
            r["guestAllocationFlags"] = w[35]==3 ? hex(w[24]) : NSNull()
            r["guestFourKiBFlagsPacked"] = w[35]==3 ? hex(w[25]) : NSNull()
            r["lifetimeFlags"] = w[35]==3 ? hex(w[40]) : NSNull()
            r["machQueryResult"] = w[35] == 1 ? NSNull() : w[36]
            r["hostRegionBase"] = w[43] == 1 ? hex(w[26]) : NSNull()
            r["hostRegionBytes"] = w[43] == 1 ? w[27] : NSNull()
            r["hostProtection"] = w[43] == 1 ? w[28] : NSNull()
            r["hostMaxProtection"] = w[43] == 1 ? w[29] : NSNull()
            r["shareMode"] = w[43] == 1 ? w[30] : NSNull()
            r["externalPager"] = w[43] == 1 ? w[31] : NSNull()
            r["regionResidentPages"] = w[43] == 1 ? w[32] : NSNull()
            r["regionSwappedPages"] = w[43] == 1 ? w[33] : NSNull()
            r["regionDirtyPages"] = w[43] == 1 ? w[34] : NSNull()
            r["dispositionScope"] = "Mach-region-not-individual-page; no-payload-read"
            r["machRegionQueryStatus"] = w[35]==1 ? "not-attempted-VM-lock-busy" : w[43]==1 ? "resolved-containing-region" : w[43]==2 ? "submap-not-walked" : w[43]==3 ? "returned-region-does-not-contain-EA" : "query-failed"
            r["machRegionObjectOffsetBytes"] = w[43]==1 ? String(w[44]) : NSNull()
            r["objectOffsetMeaning"] = "raw-Mach-memory-object-offset; not-proof-of-vnode-identity"
            r["queryExecutionScope"] = "existing-sampler-after-target-resume; elapsed-is-not-target-CPU"
            r["hostPageBytes"] = w[45]
            r["guestPageBytes"] = w[46]
            r["samplingLeaseRecheck"] = w[47] == 1 ? "matched" : w[47] == 2 ? "changed" : "busy-or-unavailable"
            r["actualMappingIdentity"] = "ledger-and-Mach-observed-separately; not-proof-of-atomic-match"
            return ("memory-access", r)
        case 4, 7:
            r["event"] = w[1] == 4 ? "VM-slow-or-error" : "VM-in-flight"
            r["operation"] = [1:"map-shared-fixed",2:"set-guest-protection-or-commit",3:"protect",4:"discard-MS_KILLPAGES",5:"hole-punch",6:"decommit"][w[10]] ?? "unknown"
            r["operationToken"] = String(w[8]); r["beginNS"] = String(w[9]); r["address"] = hex(w[11]); r["bytes"] = w[12]
            r["generationOrPunchFileOffset"] = String(w[13]); r["VM-lock-held"] = w[14] & 1 != 0
            r["execution"] = w[14] & 2 != 0 ? "deferred" : "synchronous"
            r["backingFileOpenLifetime"] = w[18]>0 ? String(w[18]) : NSNull()
            r["extentGeneration"]=w[19]>0 ? String(w[19]) : NSNull()
            r["fileOffset"] = [UInt64(1),5].contains(w[10]) ? String(w[13]) : NSNull()
            r["pageStateEffect"] = "not-queried-by-operation; syscall-success-is-not-dirty-disposal-or-zeroing"
            if w[1] == 4 { r["result"] = Int64(bitPattern:w[15]); r["errno"] = w[16]; r["durationNS"] = w[17] }
            r["creatorNativeThreadID"]=w[20]>0 ? String(w[20]) : NSNull()
            r["ownerStatus"] = w[4]>0 ? "operation-issued-by-validated-CS2-main; allocation-owner-not-implied" : "issuer-unavailable; range-generation-only"
            return ("vm-operations", r)
        case 11:
            r["event"]="sampled-host-page-metadata";r["registerCaptureBeginNS"]=String(w[9]);r["hostPC"]=hex(w[10]);r["instruction"]=hex(w[11]);r["effectiveAddress"]=hex(w[12]);r["widthBytes"]=w[13]
            r["allocationGeneration"]=w[14]>0 ? String(w[14]) : NSNull();r["extentGeneration"]=w[15]>0 ? String(w[15]) : NSNull()
            r["backingFileOpenLifetime"]=w[16]>0 ? String(w[16]) : NSNull()
            r["allocationOrigin"]=[0:"unknown",1:"Wine-private-virtual-allocation",2:"image-section",3:"file-section"][w[17]] ?? "unknown"
            r["originScope"]="existing-view-classification; creation-context-is-not-current-ownership-or-migration-permission"
            r["vmEpochBeforePages"]=String(w[18]);r["vmEpochAfterPages"]=String(w[19]);r["accessEpochBefore"]=String(w[39]);r["accessEpochAfter"]=String(w[40])
            r["metadataConsistency"]=w[18]==w[19] && w[39]==w[40] && w[40]==w[18] ? "epochs-unchanged; post-resume-not-atomic-with-registers" : "VM-changed-between-observations"
            r["samplingLeaseRecheck"]=[0:"busy-or-unavailable",1:"matched",2:"changed"][w[37]] ?? "unknown"
            r["samplingLeaseCheckNS"]=String(w[41])
            var pages:[[String:Any]]=[]
            for i in 0..<min(2,Int(w[36])) {
                let at=20+i*8
                pages.append(["hostPageBase":hex(w[at]),"queryNS":String(w[at+1]),"result":Int64(bitPattern:w[at+2]),"dispositionBits":w[at+2]==0 ? hex(w[at+3]) : NSNull(),"referenceCount":w[at+2]==0 ? w[at+4] : NSNull(),"durationNS":w[at+5],"captureToQueryNS":w[at+1]>=w[9] ? String(w[at+1]-w[9]) : "unavailable"])
            }
            r["pages"]=pages;r["hostPageBytes"]=w[38];r["scope"]="actual-EA-host-pages; mach_vm_page_query; raw-disposition-not-region-counts; no-payload-read"
            return ("memory-access",r)
        case 12:
            r["event"]="VM-operation-aggregate";r["operation"]=[1:"map-shared-fixed",2:"set-guest-protection-or-commit",3:"protect",4:"discard-MS_KILLPAGES",5:"hole-punch",6:"decommit"][w[9]] ?? "unknown"
            r["VM-lock-held"]=w[10]&1 != 0;r["execution"]=w[10]&2 != 0 ? "deferred" : "synchronous"
            r["countCumulative"]=w[11];r["bytesCumulative"]=w[12];r["errorsCumulative"]=w[13];r["durationNSCumulative"]=w[14]
            r["scope"]="host-app-instrumented-operations; nested-or-overlapping-elapsed-totals-not-main-CPU; try-lock-drops-separate"
            return ("vm-operations",r)
        case 10:
            r["event"]="watched-recovery-progress";r["source"]="existing-recovery-gate-no-new-capture"
            for (i,k) in [(9,"intervalUS"),(10,"userCPUUS"),(11,"kernelCPUUS"),(12,"runState"),(13,"eligible"),(14,"captures"),(15,"completed"),(16,"unhandled"),(17,"refused"),(18,"partial"),(19,"publicationFailed"),(25,"lastHoldUS"),(26,"lastAgeUS"),(27,"captureUS"),(28,"validationUS"),(29,"write0US"),(30,"write1US"),(31,"publicationUS"),(32,"resumeUS"),(33,"recoveryWorker"),(34,"baseQoS"),(35,"heldQoS"),(36,"qosChanged")] {r[k]=w[i]}
            r["lastPC"]=w[14]>0 ? hex(w[20]) : NSNull();r["lastEA"]=w[14]>0 ? hex(w[21]) : NSNull();r["lastInstruction"]=w[14]>0 ? hex(w[22]) : NSNull();r["lastWidth"]=w[14]>0 ? w[23] : NSNull()
            r["lastResult"]=w[14]>0 ? Int64(bitPattern:w[24]) : NSNull();r["lastCaptureResult"]=w[14]>0 ? Int64(bitPattern:w[37]) : NSNull();r["lastResumeResult"]=w[14]>0 ? Int64(bitPattern:w[38]) : NSNull()
            r["cpuScope"]="one-watched-native-thread; phase-and-last-access-age-explicit"
            return ("thread-frame-memory",r)
        case 9:
            r["event"]="executable-copy-mapping-load";r["PEBase"]=hex(w[9]);r["RXCopyBase"]=hex(w[10]);r["mappedBytes"]=w[11];r["loadGeneration"]=String(w[12]);r["identityStatus"]="range-and-native-mapping-generation; module-name-from-loader-row; hash-unavailable"
            return ("timeline",r)
        case 6:
            r["event"] = "backing-progress"; r["scope"] = "host-app-Madeira-backing-ledger"
            r["status"] = w[9] == 1 ? "VM-lock-busy" : "sampled"
            r["initialized"] = w[9] == 2 && w[25] == 1
            r["backingFileOpenLifetime"]=w[26]>0 ? String(w[26]) : NSNull()
            r["retirementPolicy"]=w[27]==1 ? "external-retire-no-killpages-v1" : "unobserved"
            if w[9] == 2 {
                for (i,k) in [(10,"liveBytes"),(11,"extentCount"),(12,"freeRangeCount"),(13,"fileBumpBytes"),(14,"fileCapBytes"),(15,"refusals"),(16,"quarantinedPunchFailures"),(17,"vmEpoch"),(18,"hostPageBytes"),(21,"freeBytes")] { r[k] = w[i] }
                r["punchQueueDepth"] = w[19] == 1 ? w[20] : NSNull()
            }
            return ("thread-frame-memory",r)
        default: return nil
        }
    }
}

struct RunMainInterval {
    let owner:UInt64,lease:UInt64,finishNS:UInt64,intervalUS:UInt64,userUS:UInt64,kernelUS:UInt64
    init?(_ r:[String:Any]) {
        guard let o=r["owner"] as? String,let owner=UInt64(o.replacingOccurrences(of:"0x",with:""),radix:16),let l=r["lease"] as? String,let lease=UInt64(l),let f=r["registerCaptureBeginNS"] as? String,let finish=UInt64(f),let interval=r["intervalUS"] as? UInt64,let u=r["userCPUUS"] as? UInt64,let k=r["kernelCPUUS"] as? UInt64 else{return nil}
        self.owner=owner;self.lease=lease;finishNS=finish;intervalUS=interval;userUS=u;kernelUS=k
    }
}

/// On-disk caps include rolling and pinned incident data. No fixed lifetime
/// sample limit: old ordinary records rotate; the last incident survives it.
final class RunEvidenceStore {
    let runID: String, directory: URL
    private let fm = FileManager.default
    private var sequence: UInt64 = 0, persisted: UInt64 = 0
    private(set) var dropped: UInt64 = 0, overwritten: UInt64 = 0
    private var overwrittenRecords:UInt64=0, segmentRecords:[String:UInt64]=[:], syncSequence:UInt64=0, syncNS:UInt64=0, syncErrors:UInt64=0
    private var files: [String: (slot: Int, bytes: Int)] = [:]
    private var counts: [String: UInt64] = [:]
    private var startedNS = RunEvidenceSchema.mono()
    private var config: [String: Any] = [:], modules: [[String: String]] = [], graphics: [String: [String: Any]] = [:]
    private var lastNS: UInt64 = 0
    private var configDirty=true, modulesDirty=true, graphicsDirty=true
    private var dirtyJournals:Set<String>=[]
    private var logicalBytes:UInt64=0, metadataWrites:UInt64=0, checkpointCount:UInt64=0, checkpointNS:UInt64=0, flushCount:UInt64=0, flushNS:UInt64=0, fsyncCount:UInt64=0, fsyncNS:UInt64=0, rotationNS:UInt64=0, incidentCount:UInt64=0, incidentBytes:UInt64=0, incidentNS:UInt64=0, writeFailures:UInt64=0
    private var lastMemorySequence:UInt64=0
    private var anchors:[(mono:UInt64,wall:Double)]=[]
    private var graphicOccurrences:[String]=[], graphicsDuplicates:UInt64=0
    private var guestExits:[[String:Any]]=[]
    private var lastExceptionContext:[String:Any]?
    private var routineResource:[String:UInt64]=[:],failureOccurrences:[String]=[]
    private var failureDuplicates:UInt64=0,firstFailureBytes=0,firstFailureRecords:UInt64=0,firstFailureDropped:UInt64=0
    private var incidentPriority=0,firstIncidentSaved=false,firstPostActivationStallSaved=false,lastIncidentNS:UInt64=0,suppressedIncidents:UInt64=0
    static func failedRequest(_ row:[String:Any])->Bool {
        guard row["event"] as? String == "resource-request-result" else{return false}
        if row["stage"] as? String == "unwound-without-result" {return true}
        guard let hr=row["HRESULT"] as? String,let code=UInt32(hr.replacingOccurrences(of:"0x",with:""),radix:16) else{return false}
        return code & 0x80000000 != 0
    }
    private func flushRoutineResources() {
        guard !routineResource.isEmpty else{return}
        let value=routineResource;routineResource.removeAll(keepingCapacity:true)
        record("thread-frame-memory",["event":"resource-routine-detail-summary","counts":value,"scope":"retained-native-details-only; exact-host-session-counter-record-is-separate; released-capacity-not-physical-savings"])
    }

    let startWallUnix=Date().timeIntervalSince1970
    func persistenceCounters() -> [String:Any] {
        ["logicalBytesWritten":logicalBytes,"metadataWrites":metadataWrites,"checkpointCount":checkpointCount,"checkpointDurationNS":checkpointNS,"flushCount":flushCount,"flushDurationNS":flushNS,"fsyncCount":fsyncCount,"fsyncDurationNS":fsyncNS,"fsyncFailures":syncErrors,"rotationCount":overwritten,"rotationDurationNS":rotationNS,"incidentCopies":incidentCount,"incidentCopyBytes":incidentBytes,"incidentCopyDurationNS":incidentNS,"writeFailures":writeFailures,"scope":"recorder-owned-logical-writes-and-copies; not-physical-device-IO; excludes-export-copy-and-filesystem-metadata","selfMeasurement":"completed-work-before-this-snapshot; counters-may-lag-current-checkpoint","maximumSummaryLagSeconds":5,"unflushedTail":"unknown-after-abrupt-termination"]
    }
    func monotonic(for wall:Double) -> UInt64? {
        guard let a=anchors.min(by:{abs($0.wall-wall)<abs($1.wall-wall)}) else{return nil}
        let ns=Double(a.mono)+(wall-a.wall)*1e9
        return ns>=0 && ns<Double(UInt64.max) ? UInt64(ns) : nil
    }
    private func persist(_ values:[String:Any],_ name:String) throws {
        let data=try RunEvidenceSchema.json(values);guard data.count<=256<<10 else {throw CocoaError(.fileWriteOutOfSpace)}
        do {try data.write(to:directory.appendingPathComponent(name),options:.atomic);logicalBytes+=UInt64(data.count);metadataWrites+=1;try fm.setAttributes([.posixPermissions:0o600],ofItemAtPath:directory.appendingPathComponent(name).path)}
        catch {writeFailures+=1;throw error}
    }
    private var sourceEvidence:[String:Any]=[:]
    private var cs2Observed=false,resourceCountersObserved=false
    func sourceFreshness(_ value:[String:Any]) {sourceEvidence=value}
    private var facts: [String:Any] = [:]
    func fact(_ key:String,_ value:Any) { if facts.count<32 || facts[key] != nil { facts[key]=value } }
    static let segmentBytes = 256 << 10
    static let slots = ["timeline":4,"thread-frame-memory":12,"memory-access":12,"vm-operations":4,"graphics-errors":2,"resource-failures":4,"input-path":2,"launch-progress":2]
    init(root: URL, runID: String = UUID().uuidString) throws {
        guard UUID(uuidString:runID) != nil else { throw CocoaError(.fileWriteInvalidFileName) }
        self.runID=runID; directory=root.appendingPathComponent(runID,isDirectory:true)
        try fm.createDirectory(at: directory, withIntermediateDirectories:true, attributes:[.posixPermissions:0o700])
        try checkpoint()
    }
    func record(_ channel: String, _ values: [String: Any]) {
        if values["event"] as? String=="cs2-start-observed" {cs2Observed=true}
        if values["event"] as? String=="resource-request-counters" {resourceCountersObserved=true}
        var channel=channel
        let failed=Self.failedRequest(values)
        if failed {
            if let native=values["nativeSequence"] as? String,native != "0" {
                if failureOccurrences.contains(native){failureDuplicates+=1;return}
                failureOccurrences.append(native);if failureOccurrences.count>128{failureOccurrences.removeFirst()}
            }
            channel="resource-failures"
        } else if let event=values["event"] as? String,event=="resource-reclamation-observation" || event=="resource-request-result" {
            routineResource[event,default:0]+=1
            if let released=values["releasedCapacityBytes"] as? UInt64 {routineResource["releasedCapacityBytes",default:0]+=released}
            return
        }
        guard let slots = Self.slots[channel] else { dropped += 1; return }
        sequence += 1
        let now = RunEvidenceSchema.mono()
        var row = values; if channel=="graphics-errors" || channel=="resource-failures" {row["memorySnapshotSequence"]=lastMemorySequence>0 ? String(lastMemorySequence) : NSNull();row["memoryReference"]="latest-utility-queue-host-app-sample; not-atomic-with-request"}; row["schema"] = RunEvidenceSchema.version; row["runID"] = runID; row["sequence"] = String(sequence)
        row["receivedMonotonicNS"] = String(now); row["clock"] = "CLOCK_MONOTONIC"; row["receivedUTC"] = ISO8601DateFormatter().string(from: Date())
        guard var data = try? RunEvidenceSchema.json(row), data.count < 16 << 10 else { dropped += 1; return }
        data.append(10)
        var f=files[channel] ?? (0,0)
        if f.bytes + data.count > Self.segmentBytes {
            let rotationBegin=RunEvidenceSchema.mono()
            defer {rotationNS+=RunEvidenceSchema.mono()-rotationBegin}
            f = ((f.slot+1) % slots,0); overwritten += 1
            let key="\(channel).\(f.slot)";overwrittenRecords+=segmentRecords[key] ?? 0;segmentRecords[key]=0
            try? fm.removeItem(at: directory.appendingPathComponent("\(channel).\(f.slot).jsonl"))
        }
        let path=directory.appendingPathComponent("\(channel).\(f.slot).jsonl")
        let fd=open(path.path,O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0o600)
        guard fd>=0 else { dropped += 1; writeFailures+=1; return }
        defer { close(fd) }
        let n=data.withUnsafeBytes { write(fd,$0.baseAddress,data.count) }
        if n>0 {logicalBytes+=UInt64(n)}
        guard n == data.count else { _ = ftruncate(fd,off_t(f.bytes)); dropped += 1; writeFailures+=1; return }
        if row["event"] as? String == "memory-progress" {lastMemorySequence=sequence}
        dirtyJournals.insert(channel)
        f.bytes += data.count; files[channel]=f; counts[channel,default:0] += 1; segmentRecords["\(channel).\(f.slot)",default:0]+=1; persisted=sequence; lastNS=now
        if failed {
            if firstFailureBytes+data.count<=256<<10 {
                let first=open(directory.appendingPathComponent("resource-failures-first.jsonl").path,O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0o600)
                if first>=0 {let wrote=data.withUnsafeBytes{write(first,$0.baseAddress,data.count)};if wrote != data.count {_ = ftruncate(first,off_t(firstFailureBytes))};close(first)
                    if wrote==data.count {firstFailureBytes+=wrote;firstFailureRecords+=1;logicalBytes+=UInt64(wrote);dirtyJournals.insert("resource-failures-first")} else {firstFailureDropped+=1;writeFailures+=1}}
                else {firstFailureDropped+=1;writeFailures+=1}
            } else {firstFailureDropped+=1}
            incident("resource-request-failure")
        }
    }
    func calibration(_ reason: String) {
        let a=RunEvidenceSchema.mono(), wall=Date(), b=RunEvidenceSchema.mono()
        anchors.append(((a+b)/2,wall.timeIntervalSince1970));if anchors.count>32 {anchors.removeFirst()}
        record("timeline",["event":"clock-calibration","reason":reason,"monotonicBeforeNS":String(a),"monotonicAfterNS":String(b),
            "wallUTC":ISO8601DateFormatter().string(from:wall),"wallUnixSeconds":wall.timeIntervalSince1970,
            "uncertaintyNSAtLeast":b>=a ? b-a : 0,"wallClockUncertainty":"system-wall-resolution-and-adjustments-not-bounded",
            "consoleClock":"console-wall; timestamp-retained-separately; arrival-is-not-packet-arrival"])
    }
    func setConfig(_ tag: String, _ fields: [String:String]) { if (config.count<32 || config[tag] != nil) && config[tag] as? [String:String] != fields { config[tag]=fields;configDirty=true } }
    func module(_ fields: [String:String]) { if modules.count>=256 { modules.removeFirst();dropped+=1 }; modules.append(fields);modulesDirty=true }
    func guestExit(_ fields:[String:Any]) {
        var fields=fields;fields["lastObservedExceptionContext"]=lastExceptionContext as Any? ?? NSNull()
        fields["exceptionAssociation"]="preceding-observation-only; not-proven-producer-or-exact-unwind"
        guestExits.append(fields);if guestExits.count>8 {guestExits.removeFirst()}
        fact("observedGuestExits",guestExits)
    }
    func exceptionContext(_ fields:[String:String]) {
        var value:[String:Any]=["fields":fields,"observedNS":String(RunEvidenceSchema.mono()),"source":"existing-guest-exact-exception-diagnostic; original-native-log-retained"]
        if let address=fields["rip"],let pc=UInt64(address.replacingOccurrences(of:"0x",with:""),radix:16) {
            for module in modules.reversed() {
                if let base=module["PEBase"].flatMap({UInt64($0.replacingOccurrences(of:"0x",with:""),radix:16)}),let size=module["mappedBytesHex"].flatMap({UInt64($0.replacingOccurrences(of:"0x",with:""),radix:16)}),pc>=base,pc-base<size {
                    value["module"]=module["module"];value["RVA"]=RunEvidenceSchema.hex(pc-base);value["mappingConfidence"]="recorded-module-load-range; current-lifetime-and-unload-status-not-atomic";break
                }
            }
        }
        lastExceptionContext=value;record("timeline",["event":"guest-exception-context-observed","context":value])
    }
    func graphic(_ fields: [String:String], category: String, occurrence:String?=nil) {
        if let occurrence {
            if graphicOccurrences.contains(occurrence) {graphicsDuplicates+=1;return}
            graphicOccurrences.append(occurrence);if graphicOccurrences.count>128 {graphicOccurrences.removeFirst()}
        }
        guard let keyData=try? RunEvidenceSchema.json(fields), let key=String(data:keyData,encoding:.utf8) else { return }
        let now=String(RunEvidenceSchema.mono())
        if var old=graphics[key] { old["count"]=(old["count"] as? UInt64 ?? 1)+1; old["lastNS"]=now; graphics[key]=old }
        else if graphics.count<64 { graphics[key]=["fields":fields,"category":category,"count":UInt64(1),"firstNS":now,"lastNS":now] }
        else { dropped += 1 }
        graphicsDirty=true
        record("graphics-errors",["memorySnapshotSequence":lastMemorySequence>0 ? String(lastMemorySequence) : NSNull(),"event":"graphics-error","category":category,"fields":fields,"sourceOccurrenceID":occurrence as Any? ?? NSNull(),"countScope":"one-source-line-occurrence; native-direct-requests-and-console-rows-not-added","memoryReference":"latest-host-app-memory-sample; not-atomic-with-error"])
    }
    /// First important window and recent/terminal window have separate fixed
    /// budgets. Routine stalls cannot replace a higher-priority resource event.
    func beginAttempt() { incidentPriority=0;lastIncidentNS=0 }
    func incident(_ reason:String) {
        let priority=reason.contains("disconnect") || reason.contains("guest-process-exit") ? 4 : reason.contains("texture") || reason.contains("resource") ? 3 : 1
        let now=RunEvidenceSchema.mono()
        if priority<incidentPriority || (priority==incidentPriority && lastIncidentNS>0 && now>=lastIncidentNS && now-lastIncidentNS<10_000_000_000) {suppressedIncidents+=1;return}
        incidentPriority=priority;lastIncidentNS=now
        let begin=now;incidentCount+=1;defer{incidentNS+=RunEvidenceSchema.mono()-begin}
        record("timeline",["event":"incident-window","reason":reason,"priority":priority])
        func capture(_ name:String,focused:Bool=false) {
            let url=directory.appendingPathComponent(name);try? fm.removeItem(at:url)
            let fd=open(url.path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600)
            guard fd>=0 else{writeFailures+=1;return};defer{close(fd)}
            let ordinary=[("resource-failures",192<<10),("input-path",64<<10),("timeline",128<<10),("thread-frame-memory",256<<10),("memory-access",256<<10),("vm-operations",64<<10),("graphics-errors",64<<10)]
            let budgets=focused ? [("timeline",32<<10),("thread-frame-memory",128<<10),("memory-access",64<<10),("vm-operations",16<<10),("input-path",16<<10)] : ordinary
            for(channel,maximum) in budgets {
                guard let f=files[channel] else{continue}
                let copied=Self.copy(directory.appendingPathComponent("\(channel).\(f.slot).jsonl"),to:fd,maximum:maximum,tail:true)
                logicalBytes+=UInt64(copied);incidentBytes+=UInt64(copied)
            }
        }
        if reason=="post-activation-frame-stall" && !firstPostActivationStallSaved {capture("incident-post-activation-first.jsonl",focused:true);firstPostActivationStallSaved=true}
        if priority>=3 && !firstIncidentSaved {capture("incident-first.jsonl");firstIncidentSaved=true}
        capture("incident.jsonl")
    }
    @discardableResult static func copy(_ source: URL, to destination: Int32, maximum: Int, tail:Bool=false) -> Int {
        let fd=open(source.path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); guard fd>=0 else { return 0 }; defer { close(fd) }
        var info=stat(); guard fstat(fd,&info)==0,info.st_uid==getuid(), info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else { return 0 }
        var buffer=[UInt8](repeating:0,count:16<<10), total=0
        var partial=false
        if tail && info.st_size>maximum {guard lseek(fd,info.st_size-off_t(maximum),SEEK_SET)>=0 else{return 0};partial=true}
        while total<maximum {
            let amount=min(buffer.count,maximum-total)
            let n=buffer.withUnsafeMutableBytes { read(fd,$0.baseAddress,amount) }
            guard n>0 else { break }
            var start=0
            if partial {if let newline=buffer.prefix(n).firstIndex(of:10){start=newline+1;partial=false}else{continue}}
            let outputCount=n-start
            let written=buffer.withUnsafeBytes { write(destination,$0.baseAddress!.advanced(by:start),outputCount) }; guard written==outputCount else { break }; total += outputCount
        }
        return total
    }
    func flush() {
        let begin=RunEvidenceSchema.mono();flushCount+=1
        defer {flushNS+=RunEvidenceSchema.mono()-begin}
        var failed=false
        for (channel,f) in files where dirtyJournals.contains(channel) {
            let fd=open(directory.appendingPathComponent("\(channel).\(f.slot).jsonl").path,O_WRONLY|O_NOFOLLOW|O_CLOEXEC)
            if fd<0 { failed=true;continue };let start=RunEvidenceSchema.mono();fsyncCount+=1;if fsync(fd) != 0 {failed=true} else {dirtyJournals.remove(channel)};fsyncNS+=RunEvidenceSchema.mono()-start;close(fd)
        }
        if dirtyJournals.contains("resource-failures-first") {
            let fd=open(directory.appendingPathComponent("resource-failures-first.jsonl").path,O_WRONLY|O_NOFOLLOW|O_CLOEXEC)
            if fd>=0 {let begin=RunEvidenceSchema.mono();fsyncCount+=1;if fsync(fd)==0 {dirtyJournals.remove("resource-failures-first")} else{failed=true};fsyncNS+=RunEvidenceSchema.mono()-begin;close(fd)} else{failed=true}
        }
        if failed {syncErrors+=1} else {syncSequence=persisted;syncNS=RunEvidenceSchema.mono()}
    }
    func reportReceiverIdentity() -> [String:String] {
        let p=config["package-provenance"] as? [String:String] ?? [:]
        return p.filter{["packageSourceRevision","nativeImageUUID","CFBundleVersion","CFBundleShortVersionString"].contains($0.key)}
    }
    func systemSummary(_ report:[String:Any]) {try? persist(report,"system.json")}
    func checkpoint() throws {
        flushRoutineResources()
        let checkpointBegin=RunEvidenceSchema.mono();checkpointCount+=1
        defer {checkpointNS+=RunEvidenceSchema.mono()-checkpointBegin}
        var coverage: [String:Any] = ["schema":RunEvidenceSchema.version,"runID":runID,"startNS":String(startedNS),"latestCapturedSequence":String(sequence),
            "latestPersistedSequence":String(persisted),"lastPersistedNS":String(lastNS),"droppedRecords":dropped,"overwrittenSegments":overwritten,"overwrittenRecords":overwrittenRecords,"retainedJournalRecords":segmentRecords.values.reduce(0,+),
            "lastFsyncedSequence":String(syncSequence),"lastFsyncNS":String(syncNS),"fsyncFailures":syncErrors,"persistence":"write-acknowledged-every-tick; fsync-five-seconds-and-export; final-unflushed-tail-unknown",
            "recorderPersistence":persistenceCounters(),"recordsCollectedByChannel":counts,"observedFacts":facts,"samplingSeconds":1,"units":"NS unless suffixed US/Bytes/Pages",
            "perRunDiskCapBytes":RunEvidenceSchema.perRunLimit,"rollingSegmentCapBytes":Self.segmentBytes,"rollingSlots":Self.slots,
            "limits":"rolling-journals-10.5MiB; incidents-2MiB-plus-first-post-activation-256KiB; first-failures-256KiB; system-1MiB; metadata-1.5MiB; total-less-than-16MiB",
            "failureDetailRetention":["firstBytes":firstFailureBytes,"firstRecords":firstFailureRecords,"firstDetailNotRetained":firstFailureDropped,"duplicateDetailsSuppressed":failureDuplicates,"firstByteLimit":256<<10,"recentByteLimit":1<<20,"nativePriorityBytes":49152],"suppressedLowerPriorityOrRepeatedIncidents":suppressedIncidents,
            "payloadRAM":"native-ring-393216; native-inflight-4608; Swift-native-batch-24576; native-failure-lane-49152; fixed-CPU-history-9216; input-log-window-262144; prefix-65536; copy-16384; record-max-16384; bounded-metadata",
            "allocatorOverhead":"not-measured; payload-bounds-are-not-a-physical-footprint-guarantee",
            "terminationReason":"unknown-unless-authoritative-report; no-clean-host-exit-record",
            "unflushedTail":"unknown-at-abrupt-termination; native-ring-and-log-tail-may-not-be-persisted",
            "nativeObserverIdentityCaps":["CS2LifetimesPerAppSession":4,"workersPerCS2Lifetime":2],
            "observerCoverage":"native-samples-rolling; input-route-and-counters-on-utility-tick; console-and-text-bounded-polling; unavailable-is-not-zero",
            "systemReports":"only-reports-actually-delivered; export-does-not-wait",
            "guestCrashReports":"app-owned-report-metadata-only; no-memory-minidumps-or-kernel-stacks"]
        coverage["gameplayMetrics"]=cs2Observed ? ["state":"process-observed; inspect-sample-and-phase-coverage; not-playability"] : ["state":"unavailable","reason":"no-CS2-process-start-observed; historical-logs-are-not-current-gameplay"]
        coverage["resourceFailureCoverage"]=["state":firstFailureRecords>0 ? "detailed-failure-retained" : !cs2Observed ? "game-workload-not-reached" : resourceCountersObserved ? "no-qualifying-direct-failure-detail-observed; inspect-counters-and-drops" : "direct-observer-unavailable-or-not-reached", "gameProcessObserved":cs2Observed,"directCountersObserved":resourceCountersObserved,"detailedRecords":firstFailureRecords,"droppedFirstDetail":firstFailureDropped]
        try persist(coverage,"run-summary.json")
        if !sourceEvidence.isEmpty {try persist(sourceEvidence,"source-freshness.json")}
        if configDirty {try persist(["schema":RunEvidenceSchema.version,"runID":runID,"effectiveFromInitializedRows":config,"unobserved":"unavailable; requested-is-not-effective"],"runtime-config.json");configDirty=false}
        if modulesDirty {try persist(["schema":RunEvidenceSchema.version,"runID":runID,"modules":modules,"limit":256,"scope":"observed-load-events-not-exhaustive-live-inventory","unloadTracking":"unavailable; entries-not-proof-still-loaded"],"modules.json");modulesDirty=false}
        if graphicsDirty {try persist(["schema":RunEvidenceSchema.version,"runID":runID,"errors":Array(graphics.values),"duplicateSourceOccurrencesSuppressed":graphicsDuplicates,"observerCoverage":"bounded-known-native-tags-and-console-errors; source-occurrences-not-unique-resource-requests; direct-native-counters-in-graphics-journal; zero-entries-not-proof-of-zero-errors"],"graphics-summary.json");graphicsDirty=false}
        try persist(["schema":RunEvidenceSchema.version,"runID":runID,"reason":"unknown","captureState":"live-session-recording; no-crash-inference","hostRunningAtCheckpoint":true,"cleanHostExitObserved":false,"observedGuestExits":guestExits,"latestPersistedSequence":String(persisted),"lastPersistedNS":String(lastNS),"unflushedTail":"unknown","authoritativeReports":"see-system-directory-if-delivered"],"termination.json")
    }
    static func writeJSON(_ values: [String:Any], to url: URL) throws {
        let data=try RunEvidenceSchema.json(values); guard data.count<=256<<10 else { throw CocoaError(.fileWriteOutOfSpace) }
        try data.write(to:url,options:.atomic); try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:url.path)
    }
    /// Preserve the immediate preceding session, including an incomplete one.
    /// Older incidents must not displace a more recent abrupt-ending journal.
    static func retainPreceding(in root:URL) -> String? {
        let runs=(try? FileManager.default.contentsOfDirectory(at:root,includingPropertiesForKeys:[.contentModificationDateKey])) ?? []
        let valid=runs.filter { var st=stat();return UUID(uuidString:$0.lastPathComponent) != nil && lstat($0.path,&st)==0 && st.st_uid==getuid() && st.st_mode & mode_t(S_IFMT)==mode_t(S_IFDIR) }.sorted {
            ((try? $0.resourceValues(forKeys:[.contentModificationDateKey]).contentModificationDate) ?? .distantPast) > ((try? $1.resourceValues(forKeys:[.contentModificationDateKey]).contentModificationDate) ?? .distantPast)
        }
        var previous=valid.first?.lastPathComponent
        // The write-acknowledged app-session pointer survives wall-clock changes.
        // If missing/corrupt, only then fall back to directory timestamps.
        let fd=open(root.appendingPathComponent("last-session").path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC)
        if fd>=0 {
            var st=stat();var data=[UInt8](repeating:0,count:64)
            if fstat(fd,&st)==0,st.st_uid==getuid(),st.st_mode & mode_t(S_IFMT)==mode_t(S_IFREG),st.st_size==36 {
                let n=data.withUnsafeMutableBytes{read(fd,$0.baseAddress,36)}
                if n==36,let id=String(bytes:data.prefix(n),encoding:.utf8),UUID(uuidString:id) != nil,valid.contains(where:{$0.lastPathComponent==id}) {previous=id}
            }
            close(fd)
        }
        for old in valid where old.lastPathComponent != previous {try? FileManager.default.removeItem(at:old)}
        return previous
    }
    /// Snapshot on the recorder queue. The ZIP writer streams these private
    /// files later and never reads mutable recording files concurrently.
    static func snapshotRun(_ source: URL, destination: URL, hostRunning:Bool?=nil) throws -> [String:URL] {
        let fm=FileManager.default; try fm.createDirectory(at:destination,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        var result:[String:URL]=[:], budget=RunEvidenceSchema.perRunLimit
        let names=try fm.contentsOfDirectory(atPath:source.path)
        for channel in RunEvidenceSchema.channels {
            let selected=names.filter { $0.hasPrefix(channel+".") && $0.hasSuffix(".jsonl") }.sorted {
                let a=(try? fm.attributesOfItem(atPath:source.appendingPathComponent($0).path)[.modificationDate] as? Date) ?? .distantPast
                let b=(try? fm.attributesOfItem(atPath:source.appendingPathComponent($1).path)[.modificationDate] as? Date) ?? .distantPast
                return a<b
            }
            let path=destination.appendingPathComponent(channel+".jsonl")
            let fd=open(path.path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600); guard fd>=0 else { continue }
            for file in selected { budget -= copy(source.appendingPathComponent(file),to:fd,maximum:max(0,budget)) }
            close(fd); result[channel+".jsonl"]=path
        }
        for name in ["run-summary.json","runtime-config.json","modules.json","graphics-summary.json","termination.json","incident.jsonl","incident-first.jsonl","incident-post-activation-first.jsonl","resource-failures-first.jsonl","source-freshness.json","system.json"] {
            let path=destination.appendingPathComponent(name)
            let fd=open(path.path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600); guard fd>=0 else { continue }
            let bytes=copy(source.appendingPathComponent(name),to:fd,maximum:min(max(0,budget),name=="resource-failures-first.jsonl" ? 256<<10 : 1<<20)); close(fd)
            if bytes>0 { budget-=bytes; result[name]=path } else { try? fm.removeItem(at:path) }
        }
        if let hostRunning,let termination=result["termination.json"],let bytes=try? Data(contentsOf:termination),bytes.count<256<<10,var value=(try? JSONSerialization.jsonObject(with:bytes)) as? [String:Any] {
            value["hostRunningAtSnapshot"]=hostRunning
            value["snapshotRelationship"]=hostRunning ? "current-live-session; absent-clean-exit-does-not-mean-crash" : "preceding-session; termination-cause-unknown-without-matched-report"
            try Self.writeJSON(value,to:termination)
        }
        return result
    }
}

/// Independent bounded file polling keeps collection running when Live Logs
/// is hidden. No per-log-line queue of closures and no guest/VM lock dependency.
final class RunEvidenceRecorder {
    static private(set) var shared: RunEvidenceRecorder?
    private static let inputConfigLock=NSLock()
    private static var pendingInputConfig:[String:String]=[:]
    static func controllerDiscovery(reason:String,enumeratedNS:UInt64,total:Int?,extended:Int?,micro:Int?,cached:Int,timer:Bool,active:Bool,keyboardMouse:Bool) {
        guard let shared else{return}
        let now=RunEvidenceSchema.mono()
        // Lifecycle/discovery transitions only; no callback/motion payload or device identifier.
        let fields:[String:Any]=["event":"controller-discovery","source":"GameController-framework-enumeration-and-serial-profile-cache","reason":["initial-enumeration","controller-notification","foreground-rescan","app-active-state"].contains(reason) ? reason : "unknown","enumerationNS":enumeratedNS>0 ? String(enumeratedNS) : NSNull(),"captureNS":String(now),"clockDomain":"CLOCK_MONOTONIC","frameworkControllers":total.map{$0 as Any} ?? NSNull(),"frameworkExtendedProfiles":extended.map{$0 as Any} ?? NSNull(),"frameworkMicroProfiles":micro.map{$0 as Any} ?? NSNull(),"cachedExtendedProfiles":cached,"timerRunning":timer,"appActive":active,"keyboardMouseMode":keyboardMouse,"samplingPeriodMS":4,"coverage":"state-transition; enumeration-unavailable-for-app-state-only; zero-input-is-not-disconnection; no-proof-of-guest-consumption"]
        shared.queue.async{shared.store.record("input-path",fields)}
    }
    static func inputBindings(_ fields:[String:String]) {
        // Called only when initialized bindings change, not for typed inputs.
        let allowed:Set<String>=["LS","RS","A","B","X","Y","LB","RB","LT","RT","L3","R3","Menu","View","D↑","D↓","D←","D→","mouseVertical","source"]
        let values=fields.filter{key,value in
            guard allowed.contains(key),value.utf8.count<=80 else{return false}
            if key=="mouseVertical" {return Double(value).map{$0.isFinite && $0>=0.25 && $0<=2} ?? false}
            return ["mouse-left","mouse-right","wasd","arrows","keyboard-toggle","none-or-mouse-stick","native-pad","initialized-per-game-bindings"].contains(value) || value.range(of:"^vk:[0-9a-f]{1,8}$",options:.regularExpression) != nil
        }
        inputConfigLock.lock();pendingInputConfig=values;inputConfigLock.unlock()
        if let shared {shared.queue.async{shared.store.setConfig("effective-controller-bindings",values);shared.store.record("input-path",["event":"controller-bindings-initialized","source":"per-game-PadBindings.build; custom-overrides-preserved"])}}
    }

    static func start(documents: URL, bundle: [String:Any]) {
        guard shared==nil else { return }; shared=try? RunEvidenceRecorder(documents:documents,bundle:bundle)
    }
    static func beginSteamLaunch(_ state:SteamLaunchState) {
        guard let shared else{return};shared.queue.async{shared.launch=state;shared.lastLaunchWindows=Data();shared.lastLaunchViewNS=0;shared.publishLaunch()}
    }
    static func launchView(_ values:[String:Any]) {
        guard let shared else{return};shared.queue.async{
            guard let launch=shared.launch,values["requestID"] as? String==launch.requestID else{return}
            let stableKeys:Set<String>=["HWND","PID","windowGeneration","owner","lease","wineVisibleLastObserved","everGDIPresented","metalSwapchainObserved","hostFlags"]
            let windows=(values["windows"] as? [[String:Any]])?.map{$0.filter{stableKeys.contains($0.key)}}
            let signature=windows.flatMap{try? RunEvidenceSchema.json($0)} ?? Data()
            let now=RunEvidenceSchema.mono(),changed=signature != shared.lastLaunchWindows
            if changed || now-shared.lastLaunchViewNS>=15_000_000_000 || values["revealRequested"] as? Bool==true {
                shared.lastLaunchWindows=signature;shared.lastLaunchViewNS=now;shared.store.record("launch-progress",values)
            }
        }
    }
    static func steamObserver(_ status:String) {
        guard ["disabled","started","timeout","reply","stopped","unavailable"].contains(status),let shared else{return}
        shared.queue.async{shared.observerStatus=status;shared.observerNS=RunEvidenceSchema.mono();if status=="timeout"{shared.observerTimeouts+=1};shared.publishLaunch(record:false)}
    }
    private func publishLaunch(record:Bool=true) {
        guard let launch else{return};var row=launch.fields(now:RunEvidenceSchema.mono())
        row["observerStatus"]=observerStatus;row["observerObservedNS"]=observerNS>0 ? String(observerNS) : NSNull();row["observerTimeouts"]=observerTimeouts
        row["observerAgeNS"]=observerNS>0 && RunEvidenceSchema.mono()>=observerNS ? RunEvidenceSchema.mono()-observerNS : NSNull()
        row["observerCurrency"]="last-observed; timeout-does-not-prove-CEF-exited"
        row["observerDependency"]="optional; opening-real-Steam-does-not-await-CEF"
        if record {store.record("launch-progress",row)}
        store.fact("SteamLaunch",row)
        NotificationCenter.default.post(name:SteamLaunchState.notification,object:launch)
    }
    private static var logPaths:[(String,String)] {
        var paths=[("madeira-session","madeira-log.txt"),("immediately-previous-native-session","madeira-log.prev.txt")]
        for root in ["Program Files (x86)/Steam","Program Files/Steam"] {
            for name in ["console","gameprocess","service","content","connection","bootstrap","cef"] {paths.append(("steam-"+name,"wine/drive_c/\(root)/logs/\(name)_log.txt"))}
            paths.append(("cs2-console","wine/drive_c/\(root)/steamapps/common/Counter-Strike Global Offensive/game/csgo/console.log"))
        }
        return paths
    }
    private func sourceSnapshot(_ relative:String)->(String?,UInt64?,Double?) {
        let rootfd=open(documents.path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);guard rootfd>=0 else{return(nil,nil,nil)};defer{close(rootfd)}
        guard let fd=SteamGameDiagnostics.openOwned(rootfd,relative.split(separator:"/").map(String.init)) else{return(nil,nil,nil)};defer{close(fd)}
        var s=stat();guard fstat(fd,&s)==0,s.st_size>=0 else{return(nil,nil,nil)}
        #if canImport(Darwin)
        let modified=Double(s.st_mtimespec.tv_sec)+Double(s.st_mtimespec.tv_nsec)/1e9
        #else
        let modified=Double(s.st_mtim.tv_sec)+Double(s.st_mtim.tv_nsec)/1e9
        #endif
        return("\(s.st_dev):\(s.st_ino)",UInt64(s.st_size),modified)
    }
    private func captureSources(initial:Bool=false) {
        let now=RunEvidenceSchema.mono()
        for (_,path) in Self.logPaths {
            let (id,bytes,modified)=sourceSnapshot(path)
            if initial {sourceBounds[path]=RunLogSource(initialIdentity:id,initialBytes:bytes,initialNS:now,identity:id,bytes:bytes,observedNS:now,modifiedWall:modified)}
            else {sourceBounds[path]?.observe(identity:id,bytes:bytes,now:now,modified:modified)}
        }
        var rows:[String:Any]=[:]
        for(id,path) in Self.logPaths {
            guard let value=sourceBounds[path] else{continue}
            if rows[id]==nil || value.identity != nil {rows[id]=value.fields()}
        }
        store.sourceFreshness(["schema":RunEvidenceSchema.version,"runID":store.runID,"runStartWallUnix":store.startWallUnix,"captureNS":String(now),"clockDomain":"CLOCK_MONOTONIC","sources":rows])
    }
    private func steamLine(_ line:String) {
        guard let event=SteamLaunchObservation.parse(line),var current=launch,current.apply(event,now:RunEvidenceSchema.mono()) else{return}
        launch=current;publishLaunch()
        #if os(iOS)
        if event.waiting {Task{@MainActor in SteamLibraryDiagnostics.shared.launchAttention()}}
        #endif
    }

    static func presentation(_ text:String) {
        guard let shared else{return}
        let keys:Set<String>=["event","request","completed","code"]
        var values=RunEvidenceSchema.fields(text,keys:keys)
        for name in ["requested","archive-created","share-presented","share-finished","failed"] where text.contains("event="+name) {values["event"]=name}
        let immutableValues=values
        shared.queue.async {shared.store.record("timeline",["event":"export-presentation","fields":immutableValues,"source":"existing-share-coordinator"])}
    }
    let queue=DispatchQueue(label:"com.madeira.run-evidence",qos:.utility)
    let store: RunEvidenceStore
    private let documents:URL, root:URL
    private var timer:DispatchSourceTimer?, ticks=0, foreground=true, foregroundBegan=RunEvidenceSchema.mono(), observers:[NSObjectProtocol]=[]
    private var offsets:[String:(inode:UInt64,offset:UInt64)]=[:], fileDroppedBytes:UInt64=0
    private var process:String?, attempt=0, attemptKind="unknown", activated=false
    private var lastFrame:UInt64=0, stall=false, lastIncident:UInt64=0
    private var maxTickNS:UInt64=0, overruns:UInt64=0
    private var previousIO:[UInt64]?
    private var previous:String?
    private var phase="startup", lastLoopbackConsoleStamp:String?
    private var connectSecond:Int?, mainUserUS:UInt64=0, mainKernelUS:UInt64=0, maxGapNS:UInt64=0, peakFootprint:UInt64=0
    private var mainIntervals:[RunMainInterval]=[], backgroundSpans:[(UInt64,UInt64)]=[], backgroundBegin:UInt64?, activationNS:UInt64?, closeReason:String?, closeReports=0
    private var pendingTextureAPI:String?, consoleLineNumber:UInt64=0, pendingTextureLine:UInt64=0
    private var nativeSourceRead:UInt64=0, consoleSourceRead:UInt64=0, sourceOccurrence:UInt64=0
    private var lastConnectionObservation:String?
    private var launch:SteamLaunchState?,observerStatus="not-observed",observerNS:UInt64=0,observerTimeouts=0
    private var sourceBounds:[String:RunLogSource]=[:]
    private var lastLaunchWindows=Data(),lastLaunchViewNS:UInt64=0
    private var lastInputRoute:String?
    #if os(iOS)
    private var metricSubscriber: RunEvidenceMetrics?
    #endif
    private init(documents:URL,bundle:[String:Any]) throws {
        self.documents=documents; root=documents.appendingPathComponent("RunEvidence",isDirectory:true)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        var rootInfo=stat()
        guard lstat(root.path,&rootInfo)==0,rootInfo.st_uid==getuid(),rootInfo.st_mode & mode_t(S_IFMT)==mode_t(S_IFDIR) else {throw CocoaError(.fileReadNoPermission)}
        previous=RunEvidenceStore.retainPreceding(in:root)
        store=try RunEvidenceStore(root:root)
        captureSources(initial:true)
        do {
            let marker=root.appendingPathComponent("last-session")
            try Data(store.runID.utf8).write(to:marker,options:.atomic)
            try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:marker.path)
            store.fact("sessionPointerPersistence","write-acknowledged; not-fsynced; timestamp-fallback-if-unavailable")
        } catch {store.fact("sessionPointerPersistence","failed; timestamp-fallback; exact-order-after-clock-change-unavailable")}

        var provenance:[String:String]=[:]
        for key in ["CFBundleIdentifier","CFBundleShortVersionString","CFBundleVersion","MadeiraSourceRevision","MadeiraNativeUUID","MadeiraVirtualSourceSHA256","MadeiraJITSourceSHA256"] {
            if let value=bundle[key] as? String,RunEvidenceSchema.safeAtom(value) { provenance[key]=value }
        }
        if let native=bundle["MadeiraNativeBuildProvenance"] as? [String:Any] {
            for key in ["packageSourceRevision","virtualBuildRevision","jitallocatorBuildRevision","expectedVirtualSourceSHA256","expectedJITAllocatorSourceSHA256","nativeImageUUID"] {
                if let value=native[key] as? String,RunEvidenceSchema.safeAtom(value) { provenance[key]=value }
            }
        }
        if let artifact=bundle["MadeiraEvidenceSymbolArtifact"] as? String,RunEvidenceSchema.safeAtom(artifact) { provenance["symbolArtifact"]=artifact }
        if let components=bundle["MadeiraEvidenceComponents"] as? [String:String] {
            store.setConfig("packaged-components",components.filter { RunEvidenceSchema.safeAtom($0.key) && RunEvidenceSchema.safeAtom($0.value) })
        }
        store.setConfig("package-provenance",provenance); store.calibration("app-session-start")
        Self.inputConfigLock.lock();let inputConfig=Self.pendingInputConfig;Self.inputConfigLock.unlock()
        if !inputConfig.isEmpty{store.setConfig("effective-controller-bindings",inputConfig)}
        store.record("timeline",["event":"app-session-start","previousRun":previous as Any? ?? NSNull(),"source":"app-recorder"])
        #if os(iOS)
        for (name,event,active) in [(UIApplication.didEnterBackgroundNotification,"app-background",false),(UIApplication.didBecomeActiveNotification,"app-foreground",true)] {
            observers.append(NotificationCenter.default.addObserver(forName:name,object:nil,queue:nil) { [weak self] _ in
                self?.queue.async { [weak self] in guard let self else { return }; self.foreground=active;let now=RunEvidenceSchema.mono();if active {self.foregroundBegan=now;if let begin=self.backgroundBegin {self.backgroundSpans.append((begin,now));self.backgroundBegin=nil;if self.backgroundSpans.count>64 {self.backgroundSpans.removeFirst()}}} else {self.backgroundBegin=now}; self.store.record("timeline",["event":event,"source":"UIApplication-notification"]); self.store.calibration(event); try? self.store.checkpoint() }
            })
        }
        metricSubscriber=RunEvidenceMetrics(recorder:self)
        #endif
        let t=DispatchSource.makeTimerSource(queue:queue); t.schedule(deadline:.now(),repeating:1,leeway:.milliseconds(150))
        t.setEventHandler { [weak self] in self?.tick() }; t.resume(); timer=t
    }
    static func correlate(_ values:[String:Any], current:String?, attempt:Int, kind:String, phase:String) -> [String:Any] {
        var row=values
        let pair: String?
        if let owner=values["owner"] as? String,let lease=values["lease"] as? String {pair=owner+"-"+lease} else {pair=nil}
        let partialOwner=values["owner"] as? String
        let contextAllowed=values["requireNativeLifetime"] as? Bool != true && (partialOwner==nil || current?.hasPrefix((partialOwner ?? "")+"-")==true)
        let identity=pair ?? (contextAllowed ? current : nil), matches=identity != nil && identity==current
        row["processLifetimeID"]=identity as Any? ?? NSNull()
        row["identitySource"]=pair != nil ? "native-owner-and-lease" : "current-correlation-context; observer-scope-remains-authoritative"
        row["attemptID"]=matches && attempt>0 ? "\(current ?? "unknown")-\(attempt)" : NSNull()
        row["attemptKind"]=matches ? kind : "unclassified-other-lifetime"
        row["phase"]=matches ? phase : "unclassified-other-lifetime"
        row["phaseConfidence"]="observed-message-arrival; not-packet-or-playability-state"
        return row
    }
    private func stamp(_ values:[String:Any]) -> [String:Any] {
        Self.correlate(values,current:process,attempt:attempt,kind:attemptKind,phase:phase)
    }
    private func tick() {
        let begin=RunEvidenceSchema.mono(); ticks+=1
        #if os(iOS)
        nativeEvidenceBacking()
        var input=[UInt64](repeating:0,count:64);nativeInputSnapshot(&input)
        if let row=RunEvidenceSchema.input(input) {
            store.record("input-path",row)
            let signature=[input[2],input[3],input[32],input[33],input[34],input[36],input[37],input[48]&63].map(String.init).joined(separator:":")
            if signature != lastInputRoute {lastInputRoute=signature;store.record("input-path",["event":"input-routing-state-observed","state":row,"confidence":"observed-in-utility-tick; intervening-transitions-available-only-as-cumulative-counters"])}
        }
        var stats=[UInt64](repeating:0,count:9), words=[UInt64](repeating:0,count:48*64)
        for _ in 0..<4 {
            let n=Int(nativeEvidencePoll(&words,64,&stats)); if n==0 { break }
            for i in 0..<n {
                guard let (channel,r)=RunEvidenceSchema.native(Array(words[i*48..<(i+1)*48])) else { continue }
                if r["event"] as? String == "cs2-start-observed" {
                    if var current=launch,current.appID==730 {current.cs2Lifetime="\(r["owner"] ?? "unknown")-\(r["lease"] ?? "unknown")";current.stage="CS2-process-observed";current.waiting=false;current.observedNS=RunEvidenceSchema.mono();launch=current;publishLaunch()}
                    nativeInputWatch(words[i*48+4],words[i*48+5],UInt32(truncatingIfNeeded:words[i*48+6]))
                    process="\(r["owner"] ?? "unknown")-\(r["lease"] ?? "unknown")"; attempt=0; activated=false;phase="CS2-started-unclassified"
                }
                if r["event"] as? String == "executable-copy-mapping-load" {
                    var entry:[String:String]=[:];for (key,value) in r {if let s=value as? String {entry[key]=s}}
                    store.module(entry)
                }
                if r["event"] as? String == "main-progress" {
                    if let interval=RunMainInterval(r){mainIntervals.append(interval);if mainIntervals.count>192 {mainIntervals.removeFirst()}}
                }
                if r["event"] as? String == "guest-process-exit" {
                    let row=stamp(r);store.guestExit(row)
                    if row["processLifetimeID"] as? String == process {activated=false;phase="guest-exited"}
                }
                if r["event"] as? String == "backing-progress",let initialized=r["initialized"] as? Bool,initialized {
                    let base=i*48
                    store.setConfig("effective-native-backing",["capBytes":String(words[base+14]),"minBytes":String(words[base+22]),"reservationMaxBytes":String(words[base+23]),"retirementPolicy":words[base+27]==1 ? "external-retire-no-killpages-v1" : "unobserved","fileOpenLifetime":String(words[base+26]),"coverage":["classic","blocks","wide","broad"][min(3,Int(words[base+24]))]])
                }
                store.record(channel,stamp(r))
            }
            if n<64 { break }
        }
        store.record("thread-frame-memory",["event":"native-recorder-coverage","latestNativeSequence":String(stats[1]),"tryLockDrops":stats[2],"overwrittenNativeRecords":stats[3],"VMOperations":stats[5],"VMBytesCumulative":stats[6],"VMErrors":stats[7],"VMDurationNSCumulative":stats[8],"scope":"host-app-instrumented-operations","status":stats[0]==1 ? "drained" : "drain-busy-or-unavailable"])
        var frame=[UInt64](repeating:0,count:5); nativeEvidenceFrame(&frame)
        let framePair=frame[3]>0 && frame[4]>0 ? RunEvidenceSchema.hex(frame[3])+"-"+String(frame[4]) : nil
        let frameMatches=process != nil && framePair==process
        let gap=frameMatches && frame[1]>0 && frame[2]>=frame[1] ? frame[2]-frame[1] : nil
        store.record("thread-frame-memory",stamp(["event":"frame-progress","scope":"validated-CS2-owner-DXMT-pacing-hook-not-GPU-completion","count":frame[3]>0 ? frame[0] : NSNull(),"owner":frame[3]>0 ? RunEvidenceSchema.hex(frame[3]) : NSNull(),"lease":frame[4]>0 ? String(frame[4]) : NSNull(),"frameIdentityStatus":frameMatches ? "current-lease-matched" : framePair != nil ? "other-live-lifetime" : "identity-busy-or-no-active-observer","lastHookNS":frame[1]>0 ? String(frame[1]) : NSNull(),"gapNS":gap as Any? ?? NSNull(),"foreground":foreground,"foregroundBeganNS":String(foregroundBegan),"GPUCompletion":"available-only-in-existing-frame-logs","intentionalPause":"unknown-unless-observed"] ))
        let activeGap=foreground && frameMatches && frame[2]>=max(frame[1],foregroundBegan) ? frame[2]-max(frame[1],foregroundBegan) : nil
        if let gap=activeGap, gap>3_000_000_000, process != nil, !stall {
            stall=true; store.record("timeline",stamp(["event":"frame-stall-observed","gapNS":gap,"source":"DXMT-pacing-hook","confidence":"no-hook-progress; intentional-pause-not-excluded"]))
            if activated { incident("post-activation-frame-stall") }
        } else if stall, frameMatches, frame[0] != lastFrame {
            stall=false; store.record("timeline",stamp(["event":"frame-progress-recovered","source":"DXMT-pacing-hook"]))
        }
        if frameMatches,frame[0]>0,var current=launch,current.cs2Lifetime==process,current.firstPresentationNS==nil {current.firstPresentationNS=frame[1];launch=current;publishLaunch()}
        lastFrame=frame[0]
        if let gap=activeGap { maxGapNS=max(maxGapNS,gap);store.fact("maxForegroundObservedPacingHookGap",["NS":maxGapNS,"scope":"whole-app foreground portions; includes startup/local; not remote-gameplay benchmark"]) }
        var info=task_vm_info_data_t(); var count=mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size/MemoryLayout<integer_t>.size)
        let kr=withUnsafeMutablePointer(to:&info) { p in p.withMemoryRebound(to:integer_t.self,capacity:Int(count)) { task_info(mach_task_self_,task_flavor_t(TASK_VM_INFO),$0,&count) } }
        var memory:[String:Any]=["event":"memory-progress","scope":"host-app-task","queryResult":kr,"thermalState":ProcessInfo.processInfo.thermalState.rawValue,"availableBytes":os_proc_available_memory()]
        if kr==KERN_SUCCESS { peakFootprint=max(peakFootprint,info.phys_footprint);store.fact("peakSampledHostFootprintBytes",peakFootprint); memory["footprintBytes"]=info.phys_footprint; memory["internalBytes"]=info.internal; memory["compressedBytes"]=info.compressed; memory["externalBytes"]=info.external }
        store.record("thread-frame-memory",stamp(memory))
        var io=[UInt64](repeating:0,count:5);nativeEvidenceIO(&io)
        var ioRow:[String:Any]=["event":"paging-IO-progress","scope":"host-app-proc_pid_rusage-v6","result":Int64(bitPattern:io[0]),"errno":io[1]]
        if io[0]==0 {
            ioRow["pageInsCumulative"]=io[2];ioRow["readBytesCumulative"]=io[3];ioRow["writeBytesCumulative"]=io[4]
            if let previousIO { for (i,k) in [(2,"pageInsDelta"),(3,"readBytesDelta"),(4,"writeBytesDelta")] { ioRow[k]=io[i]>=previousIO[i] ? io[i]-previousIO[i] : NSNull() } }
            previousIO=io
        }
        store.record("thread-frame-memory",ioRow)
        var vm=[UInt64](repeating:0,count:7);nativeEvidenceVMEvents(&vm)
        var vmRow:[String:Any]=["event":"host-task-VM-events","scope":"whole-host-app-task-events; includes-all-native-and-guest-threads; not-main-thread-or-backing-file-attribution","queryResult":vm[0],"queryBeginNS":String(vm[1]),"queryEndNS":String(vm[2]),"counterSemantics":"Mach-natural_t-cumulative-may-wrap; no-deltas-invented; faults-not-necessarily-disk-reads-or-user-signal-handler-invocations"]
        if vm[0]==0 {vmRow["faultsCumulative"]=vm[3];vmRow["pageInsCumulative"]=vm[4];vmRow["copyOnWriteFaultsCumulative"]=vm[5];vmRow["unixSyscallsCumulative"]=vm[6]}
        store.record("thread-frame-memory",vmRow)
        #endif
        tail("madeira-log.txt",console:false)
        for install in ["Program Files (x86)/Steam","Program Files/Steam"] {
            tail("wine/drive_c/\(install)/logs/console_log.txt",console:false,steam:true)
            tail("wine/drive_c/\(install)/steamapps/common/Counter-Strike Global Offensive/game/csgo/console.log",console:true)
        }
        if ticks%30==0 { store.calibration("periodic"); installedBuild() }
        store.fact("textSourceCoverage",["nativeBytesRead":nativeSourceRead,"consoleBytesRead":consoleSourceRead,"skippedBytes":fileDroppedBytes,"samplingSeconds":1,"arrivalClock":"CLOCK_MONOTONIC; console-original-wall-separate","partialLinePolicy":"defer-complete-lines; source-size-bounded-per-tick"] )
        if ticks%5==0 {captureSources();store.flush()}
        if ticks%5==0 {try? store.checkpoint()}
        store.record("thread-frame-memory",["event":"recorder-persistence", "counters":store.persistenceCounters()])
        let elapsed=RunEvidenceSchema.mono()-begin; maxTickNS=max(maxTickNS,elapsed); if elapsed>250_000_000 { overruns+=1 }
        store.record("thread-frame-memory",["event":"recorder-cost","elapsedNS":elapsed,"maxNS":maxTickNS,"over250ms":overruns,"inputBytesSkipped":fileDroppedBytes,"scope":"recorder-utility-queue-wall-time; includes-flush-and-checkpoint; excludes-this-cost-row-write","allocatorOverhead":"unmeasured"])
    }
    static func installedBuildFields(_ text:String) -> [String:String] {
        var fields:[String:String]=[:]
        for key in ["buildid","LastUpdated","StateFlags"] {
            let pattern="\""+key+"\"\\s+\"([0-9]{1,20})\""
            if let regex=try? NSRegularExpression(pattern:pattern),let match=regex.firstMatch(in:text,range:NSRange(text.startIndex...,in:text)),let range=Range(match.range(at:1),in:text) {fields[key]=String(text[range])}
        }
        return fields
    }
    private func installedBuild() {
        let fd=open(documents.path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);guard fd>=0 else {return};defer{close(fd)}
        for install in ["Program Files (x86)/Steam","Program Files/Steam"] {
            let parts=["wine","drive_c",install,"steamapps","appmanifest_730.acf"]
            guard let input=SteamGameDiagnostics.openOwned(fd,parts) else {continue};defer{close(input)}
            var bytes=[UInt8](repeating:0,count:32<<10)
            let n=bytes.withUnsafeMutableBytes{read(input,$0.baseAddress,$0.count)}
            guard n>0,let text=String(bytes:bytes.prefix(n),encoding:.utf8) else {continue}
            let values=Self.installedBuildFields(text)
            if !values.isEmpty {store.setConfig("installed-CS2-manifest",values)}
        }
        // Crash dump payloads may contain account/guest memory. Preserve only
        // app-owned exception-report file metadata at the known report root.
        let crash=documents.appendingPathComponent("wine/drive_c/Program Files (x86)/Steam/dumps")
        if let names=FileManager.default.enumerator(at:crash,includingPropertiesForKeys:[],options:[.skipsSubdirectoryDescendants,.skipsHiddenFiles]) {
            var reports:[[String:Any]]=[];var examined=0
            while examined<128, let path=names.nextObject() as? URL {
                examined+=1;let name=path.lastPathComponent
                guard name.hasSuffix(".dmp") || name.hasSuffix(".txt") else {continue}
                var st=stat()
                if lstat(path.path,&st)==0,st.st_uid==getuid(),st.st_mode & mode_t(S_IFMT)==mode_t(S_IFREG) {
                    #if canImport(Darwin)
                    let modified=Double(st.st_mtimespec.tv_sec)+Double(st.st_mtimespec.tv_nsec)/1e9
                    #else
                    let modified=Double(st.st_mtim.tv_sec)+Double(st.st_mtim.tv_nsec)/1e9
                    #endif
                    reports.append(["fileIdentity":"\(st.st_dev)-\(st.st_ino)","modifiedUnixSeconds":modified,"timeRelation":modified>=store.startWallUnix ? "modified-since-recorder-start; not-proof-of-crash" : "predates-recorder-start","kind":name.hasSuffix(".dmp") ? "minidump" : "text-report","bytes":st.st_size,"payload":"excluded; may-contain-guest-memory-or-identifiers"])
                }
            }
            reports.sort{($0["modifiedUnixSeconds"] as? Double ?? 0)>($1["modifiedUnixSeconds"] as? Double ?? 0)}
            store.fact("appOwnedWineReportMetadata",Array(reports.prefix(32)))
            store.fact("reportMetadataCoverage",["entriesExamined":examined,"scanLimit":128,"retainedLimit":32,"scanReachedLimit":examined==128,"absenceMeaning":"bounded-metadata-only; no-proof-no-crash"])
        }
    }
    private func incident(_ reason:String) {
        store.incident(reason)
    }
    private func tail(_ relative:String,console:Bool,steam:Bool=false) {
        let rootfd=open(documents.path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); guard rootfd>=0 else { return }; defer { close(rootfd) }
        guard let fd=SteamGameDiagnostics.openOwned(rootfd,relative.split(separator:"/").map(String.init)) else { return }; defer { close(fd) }
        var info=stat(); guard fstat(fd,&info)==0,info.st_size>=0 else { return }
        let size=UInt64(info.st_size), inode=UInt64(info.st_ino)
        let baseline=sourceBounds[relative]
        let initial=(baseline?.initialIdentity=="\(info.st_dev):\(info.st_ino)") ? baseline?.initialBytes : nil
        var old=offsets[relative] ?? (inode,(console || steam) ? (initial ?? (baseline?.initialIdentity==nil && baseline != nil ? 0 : size)) : 0)
        if old.inode != inode || old.offset>size { old=(inode,0); store.record("timeline",["event":"input-rotated-or-truncated","source":steam ? "steam-console" : console ? "cs2-console" : "native-log"]) }
        // A startup burst may skip the ordinary tail. Preserve just the typed
        // loaded/package provenance from a bounded prefix, without replaying
        // historical process, failure or console events into this session.
        if !console && !steam && old.offset==0 && size>256<<10 {
            var prefix=[UInt8](repeating:0,count:64<<10)
            let n=prefix.withUnsafeMutableBytes{pread(fd,$0.baseAddress,64<<10,0)}
            if n>0,let text=String(bytes:prefix.prefix(n),encoding:.utf8) {
                nativeSourceRead+=UInt64(n)
                let expected=store.reportReceiverIdentity()
                for line in text.split(separator:"\n") where line.contains("[native-build-provenance-v1]") {
                    let fields=RunEvidenceSchema.fields(String(line),keys:["package-source","native-uuid"])
                    if fields["package-source"]==expected["packageSourceRevision"],fields["native-uuid"]==expected["nativeImageUUID"] {observe(String(line),console:false)}
                }
            }
        }
        let limit:UInt64=256<<10
        var offset=old.offset, partial=false
        if size-offset>limit { fileDroppedBytes+=size-offset-limit; offset=size-limit; partial=true }
        var data=Data(), buffer=[UInt8](repeating:0,count:16<<10), lineOffset=offset
        while offset<size {
            let amount=min(buffer.count,Int(size-offset))
            let n=buffer.withUnsafeMutableBytes { pread(fd,$0.baseAddress,amount,off_t(offset)) }; if n<=0 { break }; offset+=UInt64(n)
            if console { consoleSourceRead+=UInt64(n) } else { nativeSourceRead+=UInt64(n) }
            data.append(contentsOf:buffer.prefix(n))
            while let end=data.firstIndex(of:10) {
                let bytes=data.prefix(end), start=lineOffset;lineOffset+=UInt64(bytes.count)+1;data.removeSubrange(...end)
                if partial { partial=false; continue }
                if bytes.count<=16<<10, let line=String(data:bytes,encoding:.utf8) { if steam {steamLine(line);continue}; if console {guard process != nil else{continue};if let date=Self.consoleDate(line,arrival:Date()),date.timeIntervalSince1970 < store.startWallUnix-2 {continue}}; observe(line,console:console,occurrence:"\(console ? "console" : "native")-\(inode)-\(start)") }
            }
            if data.count>16<<10 { fileDroppedBytes+=UInt64(data.count); data.removeAll(keepingCapacity:false); lineOffset=offset; partial=true }
        }
        // Leave the incomplete final line for the next tick, rather than join
        // bytes from different files. Rotation/inode changes are explicit.
        offsets[relative]=(inode,offset-UInt64(data.count))
    }
    func observe(_ line:String, console:Bool, occurrence:String?=nil) {
        sourceOccurrence+=1
        let occurrence=occurrence ?? "fixture-or-prefix-\(sourceOccurrence)"
        var failure=Self.graphicsFailure(line)
        if console, failure != nil {
            failure!.fields["sourceKind"]="console-occurrence"
            failure!.fields["observedPhase"]=phase;failure!.fields["phaseSource"]="last-parser-observation-not-capture-time-order"
            if let timestamp=Self.consoleStamp(line) {failure!.fields["consoleTimestamp"]=timestamp}
            if line.contains("E_OUTOFMEMORY"),let api=pendingTextureAPI,consoleLineNumber+1-pendingTextureLine<=4 {
                failure!.fields["API"]=api;failure!.fields["association"]="preceding-creation-row-within-four-lines";pendingTextureAPI=nil
            }
        }
        if !console {failure?.fields["sourceKind"]="native-text-occurrence"}
        // Admission has its own closed operands; do not count this same native
        // source occurrence once generically and again as an admission report.
        if let failure,!line.contains("[texture-admission-v1]") {store.graphic(failure.fields,category:failure.category,occurrence:occurrence)}
        if console {
            consoleLineNumber+=1
            if line.contains("D3D11Device()->CreateTexture") {
                pendingTextureAPI=line.contains("Texture3D") ? "CreateTexture3D" : "CreateTexture2D";pendingTextureLine=consoleLineNumber
            }
            guard var event=Self.consoleEvent(line) else { return }
            let originalStamp=Self.consoleStamp(line)
            if event=="remote-connected",originalStamp != nil,originalStamp==lastLoopbackConsoleStamp {event="loopback-connection-confirmation"}
            if event=="loopback-connected" {lastLoopbackConsoleStamp=originalStamp}
            if event == "remote-connected" || event == "loopback-connected" {
                let identity="\(process ?? "unknown")-\(event)-\(originalStamp ?? "unavailable")"
                if originalStamp != nil && lastConnectionObservation==identity {return}
                lastConnectionObservation=identity
                store.beginAttempt()
                let next=Self.attemptAfter(event,attempt:attempt,kind:attemptKind);attempt=next.0;attemptKind=next.1;activated=false;activationNS=nil;closeReason=nil;closeReports=0
            }
            let stampSeconds=Self.consoleStamp(line).flatMap { t -> Int? in
                let p=t.split(separator:":").compactMap { Int($0) };return p.count==3 ? p[0]*3600+p[1]*60+p[2] : nil
            }
            if event == "changelevel-observed" {activated=false;activationNS=nil;phase="remote-changelevel"}
            if event=="changelevel-observed" {phase="remote-map-transition";activated=false;activationNS=nil}
            if event == "remote-connected" { connectSecond=stampSeconds;phase="remote-loading" }
            if event == "loopback-connected" || event == "loopback-activated" {phase="local-loopback"}
            if event == "remote-activated" {
                activated=true;phase="remote-activated-not-playability"
                if let date=Self.consoleDate(line,arrival:Date()) {activationNS=store.monotonic(for:date.timeIntervalSince1970)}
                if let start=connectSecond,let end=stampSeconds,end>=start {
                    store.fact("lastRemoteConnectionToActivation",["seconds":end-start,"clock":"same-console-wall-second; no-packet-arrival-inference","uncertainty":"at-least-timestamp-granularity; console-buffering-unmeasured"])
                }
            }
            if event=="disconnect-network-timeout" || event=="disconnect-kicked-votedoff" {
                closeReports+=1
                if closeReason==nil {
                    closeReason=event=="disconnect-network-timeout" ? "NETWORK_DISCONNECT_TIMEDOUT" : "NETWORK_DISCONNECT_KICKED_VOTEDOFF"
                    store.fact("firstExplicitNetworkClose",["reason":closeReason!,"consoleTimestamp":originalStamp as Any? ?? NSNull(),"source":"explicit-console-token; reporting-time-not-packet-arrival"])
                    if let start=activationNS,let date=Self.consoleDate(line,arrival:Date()),let end=store.monotonic(for:date.timeIntervalSince1970) {
                        var spans=backgroundSpans;if let b=backgroundBegin {spans.append((b,RunEvidenceSchema.mono()))}
                        store.fact("remoteActivationToCloseSampledCPU",Self.cpuSummary(mainIntervals,start:start,end:end,lifetime:process,background:spans))
                    }
                }
                store.fact("networkCloseReportCount",closeReports)
            }
            if event.hasPrefix("disconnect") {store.fact(event=="disconnect-full-signon" ? "lastDisconnectCleanup" : "lastObservedDisconnect",event);activated=false;phase="after-disconnect"}
            let timestamp=Self.consoleStamp(line)
            store.record("timeline",stamp(["event":event,"source":"CS2-console-line","confidence":"observed-message; not-playability-or-packet-arrival","consoleTimestamp":timestamp as Any? ?? NSNull(),"consoleClock":"original-console-wall; year-and-timezone-unverified","consoleArrival":"this-read-tick; not-original-packet-time"]))
            if event.hasPrefix("disconnect") || event == "texture-allocation-failed" { incident(event) }
            return
        }
        if line.contains("[cs2-tso-profile-v1]") {
            store.setConfig("effective-cs2-FEX",RunEvidenceSchema.fields(line,keys:["LRCPC2","tso","halfbar","host-features","code-cache","context","policy"]))
        } else if line.contains("[native-build-provenance-v1]") {
            store.setConfig("loaded-native-provenance",RunEvidenceSchema.fields(line,keys:["package-source","native-uuid","packaged-uuid","uuid-status","virtual-source","expected-virtual","virtual-build","virtual-status","jit-source","expected-jit","jit-build","jit-status","compiled-code-tail-mb","expected-code-tail-mb","policy-status","compiled-hard-image-arena-mb","expected-hard-image-arena-mb","image-policy-status"]))
        } else if line.contains("[cs2-runtime-settings-v1]") {
            store.setConfig("initialized-runtime-settings",RunEvidenceSchema.fields(line,keys:["width","height","resolution","memory-limit","swap-mode","swap-min","swap-cap","recovery","diagnostic-mode"]))
        } else if line.contains("[texture-admission-v1]") {
            let fields=RunEvidenceSchema.fields(line,keys:["result","reason","bytes","available","charged-bytes","temporary-growth","footprint","pending","safety-floor","budget-reason"])
            store.graphic(fields.merging(["sourceKind":"native-admission-occurrence"]){a,_ in a},category:"allocation-admission",occurrence:occurrence); if activated { incident("texture-admission-failure") }
        } else if line.contains("[jit-pool] image "),line.contains(" -> pool ") {
            let pattern="image (0x[0-9a-fA-F]+)\\+(0x[0-9a-fA-F]+) \\(([A-Za-z0-9_.-]{1,96})\\) -> pool (0x[0-9a-fA-F]+)"
            if let regex=try? NSRegularExpression(pattern:pattern),let match=regex.firstMatch(in:line,range:NSRange(line.startIndex...,in:line)) {
                var f:[String:String]=["source":"existing-loader-log","generationStatus":"join-native-copy-mapping-record-by-range"]
                for (index,key) in [(1,"PEBase"),(2,"mappedBytesHex"),(3,"module"),(4,"RXCopyBase")] {
                    if let range=Range(match.range(at:index),in:line) {f[key]=String(line[range])}
                }
                store.module(f)
            }
        } else if line.contains("[cs2-module-v1]") {
            var f=RunEvidenceSchema.fields(line,keys:["pid","tid","machine","hybrid","sequence","path-class","wine-builtin"])
            if let relative=line.split(separator:" ").first(where:{$0.hasPrefix("relative=")}) {
                let name=String(relative.dropFirst(9)).split(separator:"/").last.map(String.init) ?? ""
                if RunEvidenceSchema.safeAtom(name) { f["module"]=name }
            }
            f["addressRangeStatus"]="unavailable-in-this-source"; f["hashStatus"]="unavailable-in-this-source";store.module(f)
        } else if line.contains("[cs2-store-progress-v1]") {
            let f=RunEvidenceSchema.fields(line,keys:["pid","tid","native","slot","sample","interval-us","user-us","kernel-us","captures","completed","unhandled","refused","partial","publication-failed","last-held-us","last-age-us","last-pc","last-ea","last-insn","last-bytes","last-result","phase-capture-us","phase-validation-us","phase-write0-us","phase-write1-us","phase-publication-us","phase-resume-us","recovery-worker","base-qos","held-qos","qos-changed"])
            store.record("thread-frame-memory",stamp(["event":"existing-recovery-progress","fields":f,"source":"existing-native-log; received-time-not-capture-time"]))
        } else if line.contains("[guest-exact]") {
            let fields=RunEvidenceSchema.fields(line,keys:["rip","block","pc","host-pc","code","status"])
            if !fields.isEmpty {store.exceptionContext(fields)}
        } else if line.contains("[gpu-perf]") {
            let pattern="([0-9]+) frames in ([0-9]+) ms.*GPU busy ([0-9]+) ms = ([0-9]+)%"
            if let regex=try? NSRegularExpression(pattern:pattern),let m=regex.firstMatch(in:line,range:NSRange(line.startIndex...,in:line)) {
                var f:[String:Any]=["event":"completed-frame-batch","source":"existing-DXMT-gpu-perf","scope":"DXMT-batch-not-steady-gameplay-or-single-frame"]
                for (i,k) in [(1,"frameCount"),(2,"wallMS"),(3,"GPUExecutionMS"),(4,"reportedGPUBusyPercent")] { if let range=Range(m.range(at:i),in:line),let n=UInt64(line[range]) {f[k]=n} }
                store.record("thread-frame-memory",stamp(f))
            }
        } else if line.contains("[PRESENT_GAP]") || line.contains("[FRAME_STATS]") || line.contains("[frame]") || line.contains("[gpu]") || line.contains("[mem-census]") {
            let f=RunEvidenceSchema.fields(line,keys:["frames","gap_max","gap_max_ms","inside_avg","inside_max","currentAllocatedSize","LIVE","gpu_ms","encoding_ms","submit_ms","readback-waits","commit_avg","sync_cnt","sync_avg","event_stall_max","latency_avg","enc_prep","enc_flush","drawable_block","cmdbufs"])
            if !f.isEmpty { store.record("thread-frame-memory",stamp(["event":"existing-render-counters","fields":f,"source":"native-log","scope":"DXMT-accounting-not-additive-with-footprint"])) }
        } else if let observation=Self.guestTermination(line) {
            let row=stamp(observation);store.record("timeline",row)
            if observation["event"] as? String == "guest-process-exit" {store.guestExit(row)}
        } else if line.contains("[cs2-texture-memory-v1]") || line.contains("[cs2-video-profile-v1]") || line.contains("[swap-config") || line.contains("[runtime-provenance") {
            store.setConfig(String(line.prefix(64).split(separator:"]").first ?? "observed"),RunEvidenceSchema.fields(line,keys:["selected","applied","deferred","mode","min","cap","source","virtual-sha256","jit-sha256","uuid","width","height","policy"]))
        }
    }
    static func attemptAfter(_ event:String,attempt:Int,kind:String) -> (Int,String) {
        if event=="remote-connected" || event=="loopback-connected" {return (attempt+1,event=="remote-connected" ? "remote" : "loopback")}
        return (attempt,kind)
    }
    static func guestTermination(_ line:String) -> [String:Any]? {
        let retire=line.contains("[process-retire-v1]") || line.contains("[process-retire]") || line.contains("[process-quarantine]")
        let exit=line.contains("event=abort-request phase=cs2") || line.contains("process_exit_wrapper(") || line.contains("exit_code=")
        guard retire || exit else{return nil}
        let fields=RunEvidenceSchema.fields(line,keys:["pid","owner","peb","lease","status","exit","exit_code","threads","native","native-threads","known","ready","reclaimed"])
        var row:[String:Any]=["event":exit ? "guest-process-exit" : "guest-retirement-or-quarantine","requireNativeLifetime":true,"fields":fields,"source":"native-log-existing-producer","confidence":exit ? "observed-status; guest-not-host-exit; identity-limited-to-producer-fields" : "retirement-request-not-proof-of-quiescence-or-exit","consoleTimestamp":consoleStamp(line) as Any? ?? NSNull()]
        if let owner=fields["owner"] ?? fields["peb"] {row["owner"]=owner}
        if let pid=fields["pid"] {row["pid"]=pid};if let lease=fields["lease"] {row["lease"]=lease}
        let status:UInt32?
        if let value=fields["exit_code"] ?? fields["status"] ?? fields["exit"] {
            if value.hasPrefix("0x") {status=UInt32(value.dropFirst(2),radix:16)}
            else if value.count==8 {status=UInt32(value,radix:16)}
            else if let n=Int64(value) {status=UInt32(truncatingIfNeeded:n)} else {status=nil}
        } else if let r=line.range(of:"process_exit_wrapper\\((-?[0-9]{1,12})\\)",options:.regularExpression),let n=Int64(line[r].dropFirst("process_exit_wrapper(".count).dropLast()) {status=UInt32(truncatingIfNeeded:n)}
        else {status=nil}
        if let status {row["exitStatus"]=RunEvidenceSchema.hex(UInt64(status));row["signedExitStatus"]=Int64(Int32(bitPattern:status))}
        // Do not publish an empty termination event from unrelated API text.
        return !fields.isEmpty || status != nil ? row : nil
    }
    static func consoleDate(_ text:String,arrival:Date) -> Date? {
        guard let stamp=consoleStamp(text) else{return nil}
        let time=stamp.split(separator:":").compactMap{Int($0)};guard time.count==3 else{return nil}
        var cal=Calendar(identifier:.gregorian);cal.timeZone = .current
        var c=cal.dateComponents([.year,.month,.day],from:arrival);c.hour=time[0];c.minute=time[1];c.second=time[2]
        if let regex=try? NSRegularExpression(pattern:"([0-9]{2})/([0-9]{2}) "),let m=regex.firstMatch(in:text,range:NSRange(text.startIndex...,in:text)),let mr=Range(m.range(at:1),in:text),let dr=Range(m.range(at:2),in:text) {c.month=Int(text[mr]);c.day=Int(text[dr])}
        guard let date=cal.date(from:c) else{return nil}
        return [-1,0,1].compactMap{cal.date(byAdding:.day,value:$0,to:date)}.min(by:{abs($0.timeIntervalSince(arrival))<abs($1.timeIntervalSince(arrival))})
    }
    static func cpuSummary(_ rows:[[String:Any]],start:UInt64,end:UInt64,lifetime:String?,background:[(UInt64,UInt64)]) -> [String:Any] {
        cpuSummary(rows.compactMap(RunMainInterval.init),start:start,end:end,lifetime:lifetime,background:background)
    }
    static func cpuSummary(_ rows:[RunMainInterval],start:UInt64,end:UInt64,lifetime:String?,background:[(UInt64,UInt64)]) -> [String:Any] {
        var user:UInt64=0,kernel:UInt64=0,elapsed:UInt64=0,count=0,boundary=0,bg=0
        for r in rows {
            let finish=r.finishNS,us=r.intervalUS
            guard RunEvidenceSchema.hex(r.owner)+"-"+String(r.lease)==lifetime,us>0,us<=finish/1000 else{continue}
            let begin=finish-us*1000
            guard finish>start && begin<end else {continue}
            guard begin>=start && finish<=end else {boundary+=1;continue}
            guard !background.contains(where:{$0.0<finish && $0.1>begin}) else {bg+=1;continue}
            user+=r.userUS;kernel+=r.kernelUS;elapsed+=us;count+=1
        }
        return ["userUS":user,"kernelUS":kernel,"intervalUS":elapsed,"includedIntervals":count,"boundaryIntervalsExcluded":boundary,"backgroundIntervalsExcluded":bg,"windowBeginNS":String(start),"windowEndNS":String(end),"clockMapping":"original-console-wall mapped through measured nearest app calibration; device-timezone assumption; >=1-second console resolution; not-packet-arrival","intervalRule":"capture-time interval wholly inside activation-to-first-explicit-close; boundary/background overlaps excluded; bounded-192-interval history","kernelShareOfConsumedCPU":user+kernel>0 ? Double(kernel)/Double(user+kernel) : NSNull(),"rule":"whole-capture-interval-contained-in-console-derived-window; no-proration; background-overlaps-excluded","clockConfidence":"measured-app-wall-monotonic-calibration; console-second-resolution-and-device-timezone-assumption; console-buffering-unmeasured","retention":"last-192-main-intervals; missing-intervals-not-zero; not-exhaustive-process-CPU"]
    }
    static func graphicsFailure(_ line:String) -> (category:String,fields:[String:String])? {
        let l=line.lowercased()
        guard !["chat","say ","password","ticket","token","steamid"].contains(where:{l.contains($0)}) else{return nil}
        let category:String
        if l.contains("e_outofmemory") || l.contains("8007000e") {category="allocation"}
        else if l.contains("e_invalidarg") || l.contains("80070057") {category="invalid-argument"}
        else if l.contains("shader") && (l.contains("fail") || l.contains("error")) {category="shader"}
        else if l.contains("pipeline") && (l.contains("fail") || l.contains("error")) {category="pipeline"}
        else if (l.contains("missing") || l.contains("not found") || l.contains("failed loading") || l.contains("error loading")) && (l.contains("material") || l.contains("resource") || l.contains("shader resource view")) {category="missing-resource-or-material"}
        else {return nil}
        var f=RunEvidenceSchema.fields(line,keys:["width","height","depth","mips","mip-count","format","fmt","bytes","usage","storage","flags","shader","pipeline","resource","resource-id","shader-hash","pipeline-hash","errno","code","Code"])
        f["siteCategory"]=category;f["source"]="existing-failure-message; closed-fields-only"
        for api in ["CreateTexture2D","CreateTexture3D","CreateShaderResourceView","CreateRenderPipelineState","CreateComputePipelineState"] where line.contains(api) {f["API"]=api}
        if l.contains("e_outofmemory") || l.contains("8007000e") {f["HRESULT"]="E_OUTOFMEMORY"};if l.contains("e_invalidarg") || l.contains("80070057") {f["HRESULT"]="E_INVALIDARG"}
        for domain in ["MTLLibraryErrorDomain","MTLRenderPipelineErrorDomain","MTLComputePipelineErrorDomain","MTLCommandBufferErrorDomain"] where line.contains(domain) {f["MetalErrorDomain"]=domain}
        if category=="missing-resource-or-material" || category=="pipeline" || category=="shader" {
            f["requiredForGameplay"]="unknown; engine-message-not-proof-of-required-resource"
            if let regex=try? NSRegularExpression(pattern:"[A-Za-z0-9_./\\-]+\\.(?:vmat|vtex|vmdl|vpcf|vcs|vfx|vdata|vsnd|vmesh)(?:_c)?",options:.caseInsensitive),let match=regex.firstMatch(in:line,range:NSRange(line.startIndex...,in:line)),let range=Range(match.range,in:line) {
                let candidate=String(line[range].prefix(512))
                let hash=candidate.utf8.reduce(UInt64(14695981039346656037)){($0 ^ UInt64($1)) &* 1099511628211}
                f["resourceStableID"]="opaque-path-v1-"+String(hash,radix:16)
                f["resourceIdentityScope"]="bounded-path-token-hash; original-path-private; collision-possible; no-resource-contents"
                f["loaderResultClass"]=category
            } else {f["resourceIdentityStatus"]="not-observable-in-retained-message"}
        }
        f["unreportedParameters"]="unavailable; not-inferred-from-error"
        return (category,f)
    }
    static func consoleStamp(_ s:String) -> String? {
        guard let r=s.range(of:"[0-9]{2}:[0-9]{2}:[0-9]{2}",options:.regularExpression) else { return nil }; return String(s[r])
    }
    static func consoleEvent(_ s:String) -> String? {
        // Event names are enum values; no quoted text, endpoint, ID, account or
        // chat payload is copied from console lines.
        let l=s.lowercased(); if l.contains("chat") || l.contains("say ") { return nil }
        if s.contains("NETWORK_DISCONNECT_KICKED_VOTEDOFF") {return "disconnect-kicked-votedoff"}
        if s.contains("NETWORK_DISCONNECT_TIMEDOUT") { return "disconnect-network-timeout" }
        if s.contains("SIGNONSTATE_FULL") && l.contains("disconnect") { return "disconnect-full-signon" }
        if (s.contains("CreateTexture2D") || s.contains("CreateTexture3D")) && s.contains("E_OUTOFMEMORY") { return "texture-allocation-failed" }
        if s.contains("Host activate: Remote Connect") { return "remote-activated" }
        if s.contains("Host activate: Loopback") {return "loopback-activated"}
        if s.contains("loopback") && s.contains("Connected") { return "loopback-connected" }
        if s.contains("CL:") && s.contains("Connected to") { return l.contains("loopback") || l.contains("127.0.0.1") ? "loopback-connected" : "remote-connected" }
        if s.contains("received full update") { return "full-update-observed" }
        if l.contains("physics") && l.contains("created") { return "physics-created-observed" }
        if s.contains("Setting Timeout") { return "timeout-configured" }
        if l.contains("changelevel") { return "changelevel-observed" }
        if l.contains("failed") && l.contains("shader") { return "shader-failure-observed" }
        if l.contains("missing") && l.contains("material") { return "material-missing-observed" }
        return nil
    }
    func snapshot(cancelled:()->Bool) throws -> (URL,[String:URL]) {
        try queue.sync {
            if cancelled() { throw CancellationError() }
            store.record("timeline",stamp(["event":"export-request","source":"existing-Export-Run"]))
            tick(); captureSources();publishLaunch(record:false); store.record("timeline",["event":"capture-cutoff","source":"recorder-queue-snapshot","tailAfterCutoff":"not-in-this-export"]); store.flush(); try store.checkpoint()
            let destination=FileManager.default.temporaryDirectory.appendingPathComponent("madeira-evidence-"+UUID().uuidString,isDirectory:true)
            var complete=false
            defer {if !complete {try? FileManager.default.removeItem(at:destination)}}
            var result=try RunEvidenceStore.snapshotRun(store.directory,destination:destination.appendingPathComponent("current"),hostRunning:true)
            result=Dictionary(uniqueKeysWithValues:result.map { ("evidence/"+$0.key,$0.value) })
            if let previous, !cancelled() {
                let prior=try? RunEvidenceStore.snapshotRun(root.appendingPathComponent(previous),destination:destination.appendingPathComponent("previous"),hostRunning:false)
                for (name,url) in prior ?? [:] { result["evidence/previous/\(previous)/\(name)"]=url }
            }
            if cancelled() {throw CancellationError()}
            complete=true
            return (destination,result)
        }
    }
    #if os(iOS)
    func system(_ payload:MXDiagnosticPayload) {
        queue.async { [weak self] in
            guard let self else { return }
            // Do not materialize an unbounded system JSON/call-stack tree.
            // Typed summaries preserve actual delivery while respecting the
            // recording budget. These are system diagnostics, not kernel stacks.
            var crashes:[[String:Any]]=[]
            for d in (payload.crashDiagnostics ?? []).prefix(8) {
                crashes.append(["exceptionType":d.exceptionType as Any? ?? NSNull(),"exceptionCode":d.exceptionCode as Any? ?? NSNull(),"signal":d.signal as Any? ?? NSNull()])
            }
            let report:[String:Any]=["schema":RunEvidenceSchema.version,"runID":self.store.runID,"source":"MetricKit-delivered-typed-summary","receiverBuildIdentity":self.store.reportReceiverIdentity(),"intervalOverlapsRecording":payload.timeStampEnd.timeIntervalSince1970>=self.store.startWallUnix && payload.timeStampBegin<=Date(),"intervalMatchMeaning":"interval-overlap-not-incident-or-build-match","receivedUTC":ISO8601DateFormatter().string(from:Date()),"beginUTC":ISO8601DateFormatter().string(from:payload.timeStampBegin),"endUTC":ISO8601DateFormatter().string(from:payload.timeStampEnd),"buildTimeMatch":"uncertain; system report may cover another run; build UUID not exposed by these typed fields","crashes":crashes,"hangDurationSeconds":(payload.hangDiagnostics ?? []).prefix(8).map{$0.hangDuration.converted(to:.seconds).value},"CPUExceptionCount":payload.cpuExceptionDiagnostics?.count as Any? ?? NSNull(),"diskWriteExceptionCount":payload.diskWriteExceptionDiagnostics?.count as Any? ?? NSNull(),"fullSystemPayload":"not-materialized: unbounded strings/stacks; typed supported fields only"]
            guard let encoded=try? RunEvidenceSchema.json(report),encoded.count<=1<<20 else { return }
            self.store.systemSummary(report)
        }
    }
    func metrics(_ payload:MXMetricPayload) {
        queue.async { [weak self] in
            guard let self else{return}
            var r:[String:Any]=["event":"MetricKit-periodic-metrics-received","source":"system-delivered","beginUTC":ISO8601DateFormatter().string(from:payload.timeStampBegin),"endUTC":ISO8601DateFormatter().string(from:payload.timeStampEnd),"scope":"system-app-report-interval; attribution-to-run-uncertain"]
            if let cpu=payload.cpuMetrics {r["cumulativeCPUSeconds"]=cpu.cumulativeCPUTime.converted(to:.seconds).value}
            if let memory=payload.memoryMetrics {r["peakMemoryBytes"]=memory.peakMemoryUsage.converted(to:.bytes).value}
            self.store.record("thread-frame-memory",r)
        }
    }
    #endif
}
#if os(iOS)
private final class RunEvidenceMetrics: NSObject, MXMetricManagerSubscriber {
    weak var recorder:RunEvidenceRecorder?
    init(recorder:RunEvidenceRecorder) { self.recorder=recorder; super.init(); MXMetricManager.shared.add(self) }
    deinit { MXMetricManager.shared.remove(self) }
    func didReceive(_ payloads:[MXMetricPayload]) { for payload in payloads.suffix(1) { recorder?.metrics(payload) } }
    func didReceive(_ payloads:[MXDiagnosticPayload]) { for payload in payloads.suffix(1) { recorder?.system(payload) } }
}
#endif
