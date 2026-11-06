#!/usr/bin/env python3
"""Real native log policy and production Swift immutable-cache regression."""
from pathlib import Path
import argparse,os,shutil,subprocess,tempfile,hashlib
root=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--require-swift',action='store_true');args=p.parse_args()
with tempfile.TemporaryDirectory(prefix='madeira-logs-') as folder:
    d=Path(folder);binary=d/'route'
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
        '-Wno-misleading-indentation','-I'+str(root/'build/ntdll-unix'),str(root/'tests/host/htmlipc/test_log_file.c'),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
    original=root/'wine/dlls/ntdll/unix/file.c';before=hashlib.sha256(original.read_bytes()).hexdigest()
    staged=d/'file.c';staged.write_bytes(original.read_bytes())
    subprocess.run(['python3',str(root/'tools/build/stage-htmlipc-log-file.py'),str(staged)],check=True)
    text=staged.read_text();a=text.index('NTSTATUS WINAPI NtCreateFile(');b=text.index('\nNTSTATUS WINAPI NtOpenFile(',a);body=text[a:b]
    assert body.index('madeira_htmlipc_default_log_candidate(')<body.index('get_nt_and_unix_names(')<body.index('madeira_htmlipc_mutable_log_owned(')<body.index('open_unix_file(')
    assert 'return io->Status = status;' in body and 'new_attr.RootDirectory' in body
    assert hashlib.sha256(original.read_bytes()).hexdigest()==before
    print('PASS staged NtCreateFile exact-path hook: original Wine untouched, normal resolution/disposition/IOSB/status flow retained')
    if os.uname().sysname!='Darwin' or not shutil.which('swiftc'):
        if args.require_swift:raise SystemExit('FAIL macOS Swift/CryptoKit required')
        print('SKIP Swift log/cache execution: macOS Swift/CryptoKit required');raise SystemExit(0)
    runtime=(root/'app/Madeira/SteamRuntime.swift').read_text();a=runtime.index('enum SteamRuntimeFiles {');b=runtime.index('\n#if canImport(CryptoKit)',a)
    (d/'Files.swift').write_text('import Foundation\nimport zlib\n'+runtime[a:b])
    (d/'Browser.swift').write_text((root/'app/Madeira/SteamBrowserRuntime.swift').read_text())
    (d/'Native.swift').write_text((root/'app/Madeira/SteamNativeBrowserLaunch.swift').read_text())
    (d/'Update.swift').write_text((root/'app/Madeira/SteamClientUpdate.swift').read_text().split('#if canImport(SwiftUI)',1)[0])
    main=r'''
import Foundation
import CryptoKit
let fm=FileManager.default
func hash(_ data:Data)->String {SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
func digest(_ file:URL)throws->String {hash(try Data(contentsOf:file))}
typealias B=SteamBrowserRuntimeFiles
typealias F=SteamNativeBrowserLaunchFiles
let base=fm.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
try fm.createDirectory(at:base,withIntermediateDirectories:true);defer{try?fm.removeItem(at:base)}
let drive=base.appendingPathComponent("drive_c",isDirectory:true),steam=drive.appendingPathComponent("Program Files (x86)/Steam",isDirectory:true)
try fm.createDirectory(at:drive.appendingPathComponent("windows/system32"),withIntermediateDirectories:true)
try fm.createDirectory(at:steam,withIntermediateDirectories:true)
let auth=steam.appendingPathComponent("loginusers.vdf");try Data("private fixture remains".utf8).write(to:auth)
let compat=try F.compatRoot(drive:drive,idle:{true})
let owner=try B.ownerRoot(cacheBase:compat,steamRoot:steam,idle:{true})
let marker=Data("test-only-marker\n".utf8)
var pe=Data(repeating:0,count:512);pe[0]=0x4d;pe[1]=0x5a;pe[0x3c]=0x80;pe[0x80]=0x50;pe[0x81]=0x45;pe[0x84]=0x4c;pe[0x85]=1;pe[0x94]=240;pe[0x98]=0x0b;pe[0x99]=1
let recipe=B.Recipe(id:"fixture-log-v1",coreSHA256:String(repeating:"0",count:64),prefix:"bin/cef/cef.win7/",expectedFiles:3,packages:[],keys:[B.Key(name:"steamwebhelper.exe",sha256:hash(pe)),B.Key(name:"libcef.dll",sha256:hash(pe)),B.Key(name:"chrome_elf.dll",sha256:hash(pe))],marker:B.GeneratedFile(name:".fixture-marker",bytes:marker,sha256:hash(marker)))
let stage=owner.appendingPathComponent(".stage-logging",isDirectory:true),final=owner.appendingPathComponent(recipe.id,isDirectory:true)
try fm.createDirectory(at:stage.appendingPathComponent(recipe.prefix),withIntermediateDirectories:true)
var records:[B.FileRecord]=[]
for key in recipe.keys{let name=recipe.prefix+key.name;try pe.write(to:stage.appendingPathComponent(name));records.append(B.FileRecord(name:name,bytes:pe.count,sha256:hash(pe)))}
let cache=try B.commit(stage:stage,destination:final,recipe:recipe,records:records,digest:digest,idle:{true},recheckCore:{})
let oldDefault=cache.browserRoot.appendingPathComponent("debug.log")
try Data("old default log\n".utf8).write(to:oldDefault)
do{_=try B.validate(final,recipe:recipe,digest:digest);fatalError("baseline cache contamination accepted")}catch let issue as B.ValidationIssue{assert(issue.reason == .unexpectedFile && issue.name == recipe.prefix+"debug.log")}
try fm.removeItem(at:oldDefault)
var reports:[String]=[]
assert(F.prepareMutableLogs(drive:drive,idle:{true},report:{reports.append($0)}))
assert(F.prepareMutableLogs(drive:drive,idle:{true},report:{reports.append($0)}))
let logs=compat.appendingPathComponent(F.logRootName,isDirectory:true),output=logs.appendingPathComponent("debug.log")
let image=try F.windowsPath(cache.helper,drive:drive),directory=try F.windowsPath(cache.browserRoot,drive:drive)
for _ in 0..<2 {
 let process=Process();process.executableURL=URL(fileURLWithPath:CommandLine.arguments[1]);process.arguments=["write","\\??\\"+directory+"\\debug.log",image,directory]
 var environment=ProcessInfo.processInfo.environment;environment["MADEIRA_TEST_HOST_LOG"]=output.path;process.environment=environment
 try process.run();process.waitUntilExit();assert(process.terminationStatus==0)
 _=try B.validate(final,recipe:recipe,digest:digest)
}
assert(!fm.fileExists(atPath:oldDefault.path))
assert(try String(contentsOf:output,encoding:.utf8)==String(repeating:"helper executable log fixture\n",count:2))
var changed=pe;changed[changed.count-1]=1;try changed.write(to:cache.browserRoot.appendingPathComponent("libcef.dll"))
do{_=try B.validate(final,recipe:recipe,digest:digest);fatalError("changed DLL accepted after logging")}catch let issue as B.ValidationIssue{assert(issue.reason == .fileHash)}
let badDrive=base.appendingPathComponent("unowned/drive_c",isDirectory:true)
let unowned=badDrive.appendingPathComponent("windows/madeira-compat/"+F.logRootName,isDirectory:true)
try fm.createDirectory(at:unowned,withIntermediateDirectories:true)
let keep=unowned.appendingPathComponent("keep");try Data("unowned remains".utf8).write(to:keep)
assert(!F.prepareMutableLogs(drive:badDrive,idle:{true},report:{reports.append($0)}))
assert(!F.prepareMutableLogs(drive:drive,idle:{false},report:{reports.append($0)}))
assert(try Data(contentsOf:keep)==Data("unowned remains".utf8))
assert(try Data(contentsOf:auth)==Data("private fixture remains".utf8))
for line in reports{assert(!line.contains(base.path) && !line.contains("\n"))}
print("PASS production Swift logging separation: old default contamination reproduced, routed real writes preserve strict cache reuse; changed DLL rejected, unowned/active logs soft-fail and authentication untouched")
'''
    main=main.replace('assert(try ','assert(try! ')
    (d/'main.swift').write_text(main)
    command=['swiftc','-swift-version','5',*[str(d/name) for name in ['Files.swift','Browser.swift','Native.swift','Update.swift','main.swift']],'-o',str(d/'swift')]
    subprocess.run(command,check=True);subprocess.run([str(d/'swift'),str(binary)],check=True,timeout=60)
