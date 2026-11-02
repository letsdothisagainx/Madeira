#!/usr/bin/env python3
"""Run the real bootstrap transaction; do not download, run or sign in to Steam."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'app/Madeira/SteamClientUpdate.swift').read_text()
pure = source.split('#if canImport(SwiftUI)', 1)[0]
runtime = (root / 'app/Madeira/SteamRuntime.swift').read_text()
start = runtime.index('enum SteamRuntimeFiles {')
end = runtime.index('\n#if canImport(CryptoKit)', start)
files = runtime[start:end]
model = source[source.index('@MainActor final class SteamClientUpdateModel'):]
assert model.index('Self.hash(archive) ==') < model.index('SteamRuntimeFiles.unpack(') < model.index('Self.hash(image) ==') < model.index('SteamClientUpdateFiles.commit(')
assert 'http.statusCode == 200, http.url == url' in model
assert 'completionHandler(nil)' in model
assert 'wineSessionActive' in model and 'wine_process_is_running() == 0' in model
assert 'SteamClientUpdateModel.shared.busy' in (root / 'app/Madeira/ContentView.swift').read_text()
assert source.count('steam_win64.zip.') == 1
assert 'SteamClientUpdate.swift in Sources' in (root / 'app/Madeira.xcodeproj/project.pbxproj').read_text()

main = r'''
import Foundation
let fm=FileManager.default
let temp=fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
try fm.createDirectory(at:temp,withIntermediateDirectories:true)
defer {try? fm.removeItem(at:temp)}
func pe(_ machine:UInt16)->Data {
 var d=Data(repeating:0,count:512)
 func u16(_ p:Int,_ n:UInt16){d[p]=UInt8(n&255);d[p+1]=UInt8(n>>8)}
 d[0]=0x4d;d[1]=0x5a;d[0x3c]=0x80;d[0x80]=0x50;d[0x81]=0x45
 u16(0x84,machine);u16(0x94,240);u16(0x98,machine==0x14c ? 0x10b:0x20b)
 return d
}
let old=pe(0x14c),new=pe(0x8664)
assert(SteamClientUpdateFiles.machine(old)==0x14c&&SteamClientUpdateFiles.machine(new)==0x8664)
for n in 0..<512 {let d=Data(new.prefix(n));if n<392 {assert(SteamClientUpdateFiles.machine(d)==nil)}}
var bad=new;bad[0x3c]=0xff;bad[0x3d]=0xff;bad[0x3e]=0xff;bad[0x3f]=0xff
assert(SteamClientUpdateFiles.machine(bad)==nil)
assert(SteamClientUpdateFiles.machine(pe(0xaa64))==nil)
func snapshot()->[String:Data]{
 var r:[String:Data]=[:]
 for case let u as URL in fm.enumerator(at:temp,includingPropertiesForKeys:nil)! {
  if let d=try? Data(contentsOf:u){r[String(u.path.dropFirst(temp.path.count))]=d}
 }
 return r
}
let root=temp.appendingPathComponent("Program Files (x86)/Steam")
try fm.createDirectory(at:root,withIntermediateDirectories:true)
let exe=root.appendingPathComponent("steam.exe"),backup=root.appendingPathComponent(SteamClientUpdateFiles.backupName)
try old.write(to:exe)
let privateFiles=["config/loginusers.vdf","userdata/account/config/localconfig.vdf","steamapps/appmanifest_730.acf","steamapps/common/Counter-Strike Global Offensive/game/bin/win64/cs2.exe"]
for p in privateFiles {let f=root.appendingPathComponent(p);try fm.createDirectory(at:f.deletingLastPathComponent(),withIntermediateDirectories:true);try Data(p.utf8).write(to:f)}
assert(try! SteamClientUpdateFiles.launcher(drive:temp)==exe)
let before=snapshot()
do {try SteamClientUpdateFiles.commit(new,replacing:old,at:exe,idle:{false});fatalError("live session accepted")}
catch SteamClientUpdateFiles.Failure.active {}
assert(snapshot()==before)
var checks=0
do {try SteamClientUpdateFiles.commit(new,replacing:old,at:exe,idle:{checks+=1;return checks==1});fatalError("session started during preparation")}
catch SteamClientUpdateFiles.Failure.changed {}
assert(try! Data(contentsOf:exe)==old&&Data(contentsOf:backup)==old)
try SteamClientUpdateFiles.commit(new,replacing:old,at:exe,idle:{true})
assert(try! Data(contentsOf:exe)==new&&Data(contentsOf:backup)==old)
for p in privateFiles {assert(try! Data(contentsOf:root.appendingPathComponent(p))==Data(p.utf8))}
do {try SteamClientUpdateFiles.commit(new,replacing:new,at:exe,idle:{true});fatalError("modern client replaced")}
catch SteamClientUpdateFiles.Failure.invalid {}
try old.write(to:exe)
var changed=old;changed[400]=1;try changed.write(to:backup)
let conflict=snapshot()
do {try SteamClientUpdateFiles.commit(new,replacing:old,at:exe,idle:{true});fatalError("backup overwritten")}
catch SteamClientUpdateFiles.Failure.changed {}
assert(snapshot()==conflict)
try fm.removeItem(at:backup);try old.write(to:backup)
try changed.write(to:exe)
do {try SteamClientUpdateFiles.commit(new,replacing:old,at:exe,idle:{true});fatalError("changed launcher replaced")}
catch SteamClientUpdateFiles.Failure.changed {}
try fm.removeItem(at:exe);try fm.createSymbolicLink(at:exe,withDestinationURL:backup)
do {try SteamClientUpdateFiles.commit(new,replacing:old,at:exe,idle:{true});fatalError("symlink replaced")}
catch SteamClientUpdateFiles.Failure.changed {}
assert(try! Data(contentsOf:backup)==old)
print("PASS production Steam bootstrap transaction:real i386/AMD64 headers,truncation,idle rechecks,atomic replace,original backup,changed files and symlinks refused;CS2 manifest/executable and authentication fixtures unchanged")
'''
swift = os.environ.get('SWIFTC') or shutil.which('swiftc') or str(Path.home() / '.local/share/swiftly/bin/swiftc')
with tempfile.TemporaryDirectory(prefix='madeira-steam-update-') as temp:
    p=Path(temp)
    header='/usr/include/zlib.h'
    if os.uname().sysname == 'Darwin':
        header=subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip()+'/usr/include/zlib.h'
    (p/'module.modulemap').write_text('module zlib [system] { header "'+header+'" export * link "z" }')
    (p/'Files.swift').write_text('import Foundation\nimport zlib\n'+files)
    (p/'Update.swift').write_text(pure)
    (p/'main.swift').write_text(main)
    subprocess.run([swift,'-I',str(p),str(p/'Files.swift'),str(p/'Update.swift'),str(p/'main.swift'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True)
