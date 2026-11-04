from pathlib import Path
import hashlib,json,subprocess,tempfile
root=Path(__file__).resolve().parents[2]
pins={'app/Madeira/SteamNativeBrowserLaunch.swift': 'b10b1a9249345122dfcd50125d2d8782c3b1a15be79167408c0b617949242ec6', 'app/Madeira/SteamBrowserRuntime.swift': 'ab60b06bd1cd1d082c43b63e7e026bc7e59d76a9574b8092a025641c28c8dc8f', 'app/Madeira/SteamRuntime.swift': 'f0354ac3a4351153ae8f89612af75af1f08b0b71c4b1e72226f65cf659a0f48f'}
for name,digest in pins.items():
 assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest,(name,'source pin mismatch')
runtime=(root/'app/Madeira/SteamRuntime.swift').read_text();start=runtime.index('enum SteamRuntimeFiles {');end=runtime.index('\n#if canImport(CryptoKit)',start)
files='import Foundation\nimport zlib\n'+runtime[start:end]
browser=(root/'app/Madeira/SteamBrowserRuntime.swift').read_text();browser=browser[:browser.index('\n#if canImport(CryptoKit)\n// This operation')]
native=(root/'app/Madeira/SteamNativeBrowserLaunch.swift').read_text();native=native[:native.index('\n#if canImport(CryptoKit) && canImport(Combine)')]
main=r'''
import Foundation
import CryptoKit
@main struct Proof {
 static func main() throws {
  typealias F=SteamNativeBrowserLaunchFiles
  let fm=FileManager.default
  let root=fm.temporaryDirectory.appendingPathComponent(UUID().uuidString,isDirectory:true).resolvingSymlinksInPath()
  try fm.createDirectory(at:root,withIntermediateDirectories:true)
  defer{try?fm.removeItem(at:root)}
  func image(_ length:Int,_ last:UInt8)->Data {
   var b=Data(repeating:0,count:length);b[0]=0x4d;b[1]=0x5a;b[0x3c]=0x80
   b[0x80]=0x50;b[0x81]=0x45;b[0x84]=0x64;b[0x85]=0x86;b[0x94]=0xf0;b[0x98]=0x0b;b[0x99]=0x02
   b[b.count-1]=last;return b
  }
  func hash(_ data:Data)->String {SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
  func fileHash(_ file:URL)throws->String{hash(try Data(contentsOf:file))}
  func manifest(_ data:Data)->F.BridgeManifest {
   F.BridgeManifest(format:1,mode:"native-owner",filename:F.bridgeName,bytes:data.count,sha256:hash(data),coreSHA256:SteamBrowserRuntimeFiles.official.coreSHA256,readinessABI:F.ReadinessABI(version:1,size:80,sha256:F.abiSHA256))
  }
  let old=image(512,1),new=image(1024,2),same=image(512,3)
  // Direct Foundation metadata control; no production behavior is changed.
  let metadata=root.appendingPathComponent("metadata.dll")
  try old.write(to:metadata)
  let first=try metadata.resourceValues(forKeys:[.fileSizeKey]).fileSize!
  try new.write(to:metadata,options:.atomic)
  let cached=try metadata.resourceValues(forKeys:[.fileSizeKey]).fileSize!
  let fresh=(try fm.attributesOfItem(atPath:metadata.path)[.size] as! NSNumber).intValue
  print("FOUNDATION "+String(first)+" cached="+String(cached)+" fresh="+String(fresh))
  assert(first==512 && cached==512 && fresh==1024)
  for (label,next,expectFailure) in [("size-changing",new,true),("same-size",same,false)] {
   let drive=root.appendingPathComponent(label,isDirectory:true),system=drive.appendingPathComponent("windows/system32",isDirectory:true)
   try fm.createDirectory(at:system,withIntermediateDirectories:true)
   let source=root.appendingPathComponent(label+"-source.dll"),oldSource=root.appendingPathComponent(label+"-old.dll")
   try old.write(to:oldSource);try next.write(to:source)
   try F.installBridge(oldSource,manifest:manifest(old),drive:drive,digest:fileHash,idle:{true})
   var failed=false
   do{try F.installBridge(source,manifest:manifest(next),drive:drive,digest:fileHash,idle:{true})}
   catch F.Failure.invalidBridge {failed=true}
   assert(failed==expectFailure)
   // Verify actual new target bytes/metadata and exact SHA using fresh access.
   let target=URL(fileURLWithPath:system.appendingPathComponent(F.bridgeName).path)
   let actual=(try fm.attributesOfItem(atPath:target.path)[.size] as! NSNumber).intValue
   let actualHash=try fileHash(target)
   assert(actual==next.count && actualHash==hash(next))
   let actualData=try Data(contentsOf:target)
   assert(SteamBrowserRuntimeFiles.machine(actualData)==0x8664)
   try F.verify(target,fingerprint:manifest(next).fingerprint,digest:fileHash)
   let stamp=try JSONDecoder().decode(F.Stamp.self,from:Data(contentsOf:system.appendingPathComponent(F.stampName)))
   if expectFailure {assert(stamp.installed==manifest(old).fingerprint && stamp.pending==manifest(next).fingerprint)}
   else {assert(stamp.installed==manifest(next).fingerprint && stamp.pending==nil)}
   print("PRODUCTION "+label+" invalidBridge="+String(failed)+" actual-size="+String(actual)+" actual-sha-match=true actual-machine=8664 fresh-verify=pass")
  }
  print("PASS baseline production reproduces size-changing upgrade failure at cached size readback; same-size control passes; no validation predicates modified")
 }
}
'''
with tempfile.TemporaryDirectory(prefix='bridge-baseline-') as temp:
 p=Path(temp)
 for name,source in [('Files.swift',files),('Browser.swift',browser),('Native.swift',native),('Main.swift',main)]: (p/name).write_text(source)
 subprocess.run(['swiftc','-parse-as-library',*[str(p/name) for name in ('Files.swift','Browser.swift','Native.swift','Main.swift')],'-o',str(p/'proof')],check=True)
 subprocess.run([str(p/'proof')],check=True)
