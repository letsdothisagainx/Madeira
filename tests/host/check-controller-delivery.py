#!/usr/bin/env python3
"""Actual translation and routing helpers; normal in-memory input/identity only."""
from pathlib import Path
import argparse,os,shutil,subprocess,tempfile,hashlib
r=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--require-swift',action='store_true');a=p.parse_args()
def body(s,sig):
 b=s.index(sig);e=s.index('{',b);level=1;e+=1
 while level:level+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[b:e]
with tempfile.TemporaryDirectory() as d:
 t=Path(d)
 identity=body((r/'build/ntdll-unix/thread_ios.c').read_text(),'int ios_thread_process_try_pid_identity(')
 route=body((r/'build/wineserver/queue_ios.c').read_text(),'static void ios_input_target_note(')
 assert 'send_request' not in route and 'get_window_thread' not in route and 'get_foreground_thread' not in route
 (t/'route.c').write_text('''#define _POSIX_C_SOURCE 200809L
#define WINE_IOS 1
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>
#include <stdio.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
struct ios_thread_group {unsigned pid,count,exiting,reclaimed;void*owner;unsigned long long lease;};
static struct ios_thread_group ios_thread_groups[8];static pthread_mutex_t ios_thread_group_mutex=PTHREAD_MUTEX_INITIALIZER;
typedef struct {uint64_t active,focus;} input_shm_t;
struct input {input_shm_t*shared;};struct desktop {struct input*foreground_input;};
struct process {unsigned id;};struct thread {struct process*process;unsigned id;};
static uint64_t observation[7];
void winios_input_route(uint64_t a,uint64_t f,unsigned p,unsigned t,uint64_t o,uint64_t l,unsigned s){observation[0]=a;observation[1]=f;observation[2]=p;observation[3]=t;observation[4]=o;observation[5]=l;observation[6]=s;}
'''+identity+'\n'+route+'''
int main(void){uintptr_t o=99;unsigned long long l=99;errno=EDOM;
 ios_thread_groups[0]=(struct ios_thread_group){17,1,0,0,(void*)0x1000,34};
 assert(ios_thread_process_try_pid_identity(17,&o,&l)&&o==0x1000&&l==34&&errno==EDOM);
 pthread_mutex_lock(&ios_thread_group_mutex);assert(!ios_thread_process_try_pid_identity(17,&o,&l)&&!o&&!l);pthread_mutex_unlock(&ios_thread_group_mutex);
 ios_thread_groups[1]=(struct ios_thread_group){17,1,0,0,(void*)0x2000,35};assert(!ios_thread_process_try_pid_identity(17,&o,&l)&&!o&&!l);
 ios_thread_groups[1].exiting=1;assert(ios_thread_process_try_pid_identity(17,&o,&l)&&l==34);
 ios_thread_groups[0].exiting=1;assert(!ios_thread_process_try_pid_identity(17,&o,&l));ios_thread_groups[0].exiting=0;
 input_shm_t shared={0x10,0x20};struct input in={&shared};struct desktop desk={&in};struct process proc={17};struct thread thr={&proc,18};
 ios_input_target_note(&desk,&thr);assert(observation[0]==0x10&&observation[1]==0x20&&observation[2]==17&&observation[3]==18&&observation[4]==0x1000&&observation[5]==34&&errno==EDOM);
 proc.id=19;thr.id=20;ios_input_target_note(&desk,&thr);assert(observation[2]==19&&observation[3]==20&&!observation[4]&&!observation[5]);
 ios_input_target_note(&desk,0);assert(!observation[2]&&!observation[3]);
 puts("actual server route + registry: focus/target distinction, lease, busy/ambiguous/exiting identities, unchanged errno; no diagnostic RPC PASS");}
''')
 subprocess.run([os.getenv('CC','cc'),'-std=c11','-O2','-pthread',str(t/'route.c'),'-o',str(t/'route')],check=True)
 subprocess.run([str(t/'route')],check=True)
 swift=os.getenv('SWIFTC') or shutil.which('swiftc')
 if not swift:
  if a.require_swift:raise SystemExit('Swift compiler required')
  print('Swift translation fixtures unavailable locally');raise SystemExit(0)
 pad=(r/'app/Madeira/PadKeyboardMouse.swift').read_text().replace('import UIKit','')
 hw=(r/'app/Madeira/HardwareInput.swift').read_text()
 helpers='\n'.join(body(hw,s) for s in ['struct MotionCarry {','enum StickVelocity {'])
 baseline=(r/'tests/fixtures/pad-kbm-482ac26f.swift').read_bytes()
 assert hashlib.sha256(baseline).hexdigest()=='ca04bb0d6500da38a2e1b9169f26814cd07c471d87784bfc15b491581f2cf883'
 baseline=baseline.decode().replace('PadKeyboardMouse','BaselinePadKeyboardMouse')
 (t/'Pad.swift').write_text(pad+'\n'+helpers+'\n'+baseline)
 (t/'Stubs.swift').write_text('''import Foundation
var epoch:UInt64=1, ticks:UInt64=1000000
var keys:[(Int32,Int32)]=[],mouse:[UInt32]=[],motions:[(Int32,Int32)]=[]
func winios_input_generation()->UInt64{epoch}
func winios_input_source(_ k:UInt32,_ v:UInt64){}
func winios_post_key(_ k:Int32,_ d:Int32){keys.append((k,d))}
func winios_pointer(_ x:Int32,_ y:Int32,_ f:UInt32,_ d:UInt32){mouse.append(f)}
func mach_absolute_time()->UInt64{ticks+=4000000;return ticks}
struct mach_timebase_info_data_t{var numer:UInt32=1,denom:UInt32=1}
func mach_timebase_info(_ p:inout mach_timebase_info_data_t){}
enum ControlAction:Equatable{case none,key(Int32),mouseLeft,mouseRight,joystickWASD,joystickArrows,keyboardToggle,pad(String)
 var isPad:Bool{if case .pad=self{return true};return false}
 var stickKeys:[Int32]?{switch self{case .joystickWASD:return [0x57,0x44,0x53,0x41];case .joystickArrows:return [0x26,0x27,0x28,0x25];default:return nil}}}
struct TouchControl{var padBinding:String?;var action:ControlAction}
struct InputSettings{static let shared=InputSettings();var sensRel=1.0}
class HardwareInput{static let shared=HardwareInput();func stickMoved(){};func postRelative(_ x:Int32,_ y:Int32){motions.append((x,y))}}
enum MetalBackedView{static func toggleKeyboard(){}}
class CS2VACMarkers{enum Kind{case controller};static let shared=CS2VACMarkers();func noteInput(_ k:Kind){}}
''')
 (t/'Check.swift').write_text('''import Foundation
@main struct Check{static func main(){
 let baseline=BaselinePadKeyboardMouse()
 baseline.feed(buttons:0x1000,lt:0,rt:0,lx:0,ly:32767,rx:0,ry:0,bindings:.template,focused:false)
 assert(keys.contains{$0.0==32 && $0.1==1});baseline.releaseAll("baseline focus fixture");keys=[];mouse=[];motions=[]
 print("baseline reproduced: focused=false still delivers controller button/key-stick presses")
 let p=PadKeyboardMouse();var b=PadBindings.template
 func feed(_ a:UInt16=0,_ focused:Bool=true,_ y:Int16=0,_ rx:Int16=0){p.feed(buttons:a,lt:0,rt:0,lx:0,ly:y,rx:rx,ry:0,bindings:b,focused:focused)}
 feed(0,false);feed(0x1000,false,32767,32767);assert(keys.isEmpty&&mouse.isEmpty&&motions.isEmpty)
 feed(0x1000,true,32767,32767);assert(keys.isEmpty&&motions.isEmpty)
 feed();feed(0x1000,true,32767,32767);assert(keys.contains{$0.0==32&&$0.1==1}&&keys.contains{$0.0==0x57&&$0.1==1} && !motions.isEmpty)
 feed(0,false);assert(keys.contains{$0.0==32&&$0.1==0}&&keys.contains{$0.0==0x57&&$0.1==0})
 feed();keys=[];feed(0x1000);b.buttons["A"] = .key(0x45);feed();assert(keys.last!.0==32&&keys.last!.1==0)
 feed(0x1000);assert(keys.last!.0==0x45&&keys.last!.1==1)
 epoch+=1;keys=[];feed(0x1000);assert(keys.count==1&&keys[0].0==0x45&&keys[0].1==1) // consumer neutralizes old epoch
 p.releaseAll("fixture disconnect");keys=[];feed(0x1000);assert(keys.isEmpty);feed();feed(0x1000);assert(keys.count==1)
 p.releaseAll("fixture app/library inactive");keys=[];feed(0x1000,false);feed(0x1000,true);assert(keys.isEmpty);feed();feed(0x1000);assert(keys.count==1)
 let configured=PadBindings.build(controls:[],binds:["A":.key(0x46)],mouseVertical:1.25);assert(configured.evidence["A"]=="vk:46"&&configured.evidence["mouseVertical"]=="1.25")
 assert(motions.allSatisfy{abs($0.0)<=24&&abs($0.1)<=24})
 print("actual pad translator: all-output focus gate, neutral return, release through original custom binding, epoch resync, disconnect/app/library lifecycle, bounded motion PASS")
}}
''')
 subprocess.run([swift,'-swift-version','5',str(t/'Pad.swift'),str(t/'Stubs.swift'),str(t/'Check.swift'),'-o',str(t/'check')],check=True)
 subprocess.run([str(t/'check')],check=True,timeout=10)
