/* SPDX-License-Identifier: MIT */
#include "stream_codec.h"
#include "domain_registry.h"
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>
using namespace madeira_stream_codec;
#if defined(MADEIRA_STREAM_HOST_TEST_ABI)
#define MSABI
#else
#define MSABI __attribute__((ms_abi))
#endif
static std::atomic<unsigned long long> checks{0};
#define CHECK(x) do {++checks;if(!(x)){std::fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x);std::abort();}}while(0)
struct Harness;
struct Ring {
    Harness *owner=nullptr;
    std::mutex mutex;
    std::condition_variable changed;
    std::deque<Byte> bytes,ahead;
    Size capacity=256,max_chunk=256,prefetch=0;
    U32 put_calls=0,get_calls=0,clear_calls=0,last_expected=0,wait_calls=0;
    U32 put_zero_every=0,get_zero_every=0;
    bool aborted=false,over_put=false,over_get=false;
    std::vector<Byte> append_before_clear,append_after_zero_observation;
    void feed(const Byte *p,Size n){std::lock_guard<std::mutex> g(mutex);CHECK(bytes.size()+n<=capacity);for(Size i=0;i<n;++i)bytes.push_back(p[i]);changed.notify_all();}
    std::vector<Byte> drain(Size limit){std::lock_guard<std::mutex> g(mutex);std::vector<Byte> out;while(!bytes.empty()&&out.size()<limit){out.push_back(bytes.front());bytes.pop_front();}changed.notify_all();return out;}
};
static thread_local bool codec_locked=false;
static void enter(void *p){CHECK(!codec_locked);static_cast<std::mutex*>(p)->lock();codec_locked=true;}
static void leave(void *p){CHECK(codec_locked);codec_locked=false;static_cast<std::mutex*>(p)->unlock();}
static U32 MSABI original_available(Stream stream){auto &r=*static_cast<Ring*>(stream);std::lock_guard<std::mutex> g(r.mutex);U32 n=U32(r.bytes.size()+r.ahead.size());
    if(!n&&!r.append_after_zero_observation.empty()){for(Byte b:r.append_after_zero_observation)r.bytes.push_back(b);r.append_after_zero_observation.clear();r.changed.notify_all();}return n;}
static U32 MSABI original_writable(Stream stream){auto &r=*static_cast<Ring*>(stream);std::lock_guard<std::mutex> g(r.mutex);return U32(r.capacity-r.bytes.size());}
static U32 MSABI original_put(Stream stream,const void *data,U32 count){auto &r=*static_cast<Ring*>(stream);std::lock_guard<std::mutex> g(r.mutex);++r.put_calls;
    if(r.over_put)return count+1;
    if(r.put_zero_every&&r.put_calls%r.put_zero_every==0)return 0;
    Size n=std::min({Size(count),r.max_chunk,r.capacity-r.bytes.size()});auto p=static_cast<const Byte*>(data);
    for(Size i=0;i<n;++i)r.bytes.push_back(p[i]);
    r.changed.notify_all();return U32(n);}
static U32 MSABI original_get(Stream stream,void *data,U32 count){auto &r=*static_cast<Ring*>(stream);std::lock_guard<std::mutex> g(r.mutex);++r.get_calls;
    if(r.over_get)return count+1;
    if(r.get_zero_every&&r.get_calls%r.get_zero_every==0)return 0;
    if(r.ahead.empty()){Size n=std::min(r.bytes.size(),r.prefetch?r.prefetch:Size(count));while(n--){r.ahead.push_back(r.bytes.front());r.bytes.pop_front();}}
    Size n=std::min({Size(count),r.max_chunk,r.ahead.size()});auto p=static_cast<Byte*>(data);
    for(Size i=0;i<n;++i){p[i]=r.ahead.front();r.ahead.pop_front();}r.changed.notify_all();return U32(n);}
static bool MSABI original_clear(Stream stream,U32 expected){auto &r=*static_cast<Ring*>(stream);std::lock_guard<std::mutex> g(r.mutex);++r.clear_calls;r.last_expected=expected;
    for(Byte b:r.append_before_clear)r.bytes.push_back(b);
    r.append_before_clear.clear();
    if(expected&&expected!=r.bytes.size()+r.ahead.size())return false;
    r.bytes.clear();r.ahead.clear();r.changed.notify_all();return true;}
static bool MSABI original_wait(Stream,bool,U32);
static const madeira_wire::MapEntry entries[]={{11,101,madeira_wire::MessageKind::OpaqueCommon},{12,102,madeira_wire::MessageKind::BrowserCreate},{13,103,madeira_wire::MessageKind::OpaqueCommon}};
struct Harness {
    State state;
    Ring tx,rx;
    std::mutex codec_mutex;
    std::vector<Byte> input,output;
    Scope scope;
    explicit Harness(Size workspace=4096,Control control={},U32 budget=64):input(workspace),output(workspace),scope{this,7,&tx,&rx}{
        tx.owner=rx.owner=this;
        Settings p{scope,{original_available,original_writable,original_put,original_get,original_clear,original_wait},
            {entries,3},{input.data(),input.size(),output.data(),output.size()},{&codec_mutex,enter,leave},budget,control};
        CHECK(configure(&state,p));
    }
};
static bool MSABI original_wait(Stream stream,bool infinite,U32 timeout){auto &r=*static_cast<Ring*>(stream);CHECK(!codec_locked);++r.wait_calls;
    auto until=std::chrono::steady_clock::now()+std::chrono::milliseconds(infinite?2000:(timeout?timeout:50));
    for(;;){{std::lock_guard<std::mutex> g(r.mutex);if(r.aborted)return false;}
        if(available(&r.owner->state,r.owner->scope,stream))return true;
        std::unique_lock<std::mutex> g(r.mutex);if(r.aborted)return false;
        if(r.changed.wait_until(g,until)==std::cv_status::timeout)return false;
    }}
static void set32(std::vector<Byte>&v,Size at,U32 n){for(U32 i=0;i<4;++i)v[at+i]=Byte(n>>(8*i));}
static std::vector<Byte> frame(U32 id,const std::vector<Byte>&body={},U32 browser=3){std::vector<Byte> v(12+body.size());set32(v,0,U32(body.size()));set32(v,4,id);set32(v,8,browser);std::copy(body.begin(),body.end(),v.begin()+12);return v;}
static std::vector<Byte> converted(const std::vector<Byte>&v){std::vector<Byte> out(v.size()+512);auto r=madeira_wire::convert_frame(madeira_wire::Direction::CurrentToLegacy,{entries,3},v.data(),v.size(),out.data(),out.size());CHECK(r.error==madeira_wire::Error::Ok);out.resize(r.written);return out;}
static void append(std::vector<Byte>&a,const std::vector<Byte>&b){a.insert(a.end(),b.begin(),b.end());}
static void assert_ok(Harness &h){CHECK(status(&h.state).error==Error::None);}
static void tx_final_ack(){
    Harness h;h.tx.capacity=13;h.tx.max_chunk=3;h.tx.put_zero_every=4;
    auto input=frame(12,{0x50,0x04,0x12,0x03,'u','a','x'});auto expect=converted(input);
    U32 n=put(&h.state,h.scope,&h.tx,input.data(),U32(input.size()));CHECK(n==input.size()-1);CHECK(h.state.tx_final_unacked);
    Size retained=h.state.tx_used;auto settings=h.state.settings;
    CHECK(!configure(&h.state,settings));CHECK(h.state.tx_final_unacked&&h.state.tx_used==retained);
    std::vector<Byte> seen;Size attempts=0;
    while(n<input.size()&&attempts++<100){append(seen,h.tx.drain(2));U32 got=put(&h.state,h.scope,&h.tx,input.data()+n,U32(input.size()-n));
        if(got)CHECK(h.state.tx_sent==0&&!h.state.tx_final_unacked);
        n+=got;assert_ok(h);}
    CHECK(n==input.size());append(seen,h.tx.drain(100));CHECK(seen==expect);CHECK(attempts>1);
    auto empty=frame(11);h.tx.put_zero_every=0;h.tx.capacity=4;h.tx.max_chunk=2;
    n=put(&h.state,h.scope,&h.tx,empty.data(),U32(empty.size()));CHECK(n==11);seen.clear();
    for(U32 i=0;n<empty.size()&&i<20;++i){append(seen,h.tx.drain(4));n+=put(&h.state,h.scope,&h.tx,empty.data()+n,U32(empty.size()-n));}
    CHECK(n==empty.size());append(seen,h.tx.drain(100));CHECK(seen==converted(empty));
}
static void retry_mismatch(){Harness h;h.tx.capacity=4;auto in=frame(11,{1,2,3});CHECK(put(&h.state,h.scope,&h.tx,in.data(),U32(in.size()))==in.size()-1);
    for(U32 i=0;i<20&&h.state.tx_sent<h.state.tx_size;++i){h.tx.drain(100);(void)writable(&h.state,h.scope,&h.tx);}
    Byte wrong=Byte(in.back()^1);CHECK(put(&h.state,h.scope,&h.tx,&wrong,1)==0);CHECK(status(&h.state).error==Error::RetryByteMismatch);
    Harness pending;pending.tx.capacity=4;CHECK(put(&pending.state,pending.scope,&pending.tx,in.data(),U32(in.size()))==in.size()-1);
    pending.tx.drain(4);U32 calls=pending.tx.put_calls;Size sent=pending.state.tx_sent;
    CHECK(put(&pending.state,pending.scope,&pending.tx,&wrong,1)==0);
    CHECK(pending.tx.put_calls==calls&&pending.state.tx_sent==sent);
    CHECK(status(&pending.state).error==Error::RetryByteMismatch);
}
static void read_ahead_and_clear(){
    Harness h;h.rx.capacity=200;h.rx.prefetch=64;auto in=frame(101,std::vector<Byte>(88,0x5a));h.rx.feed(in.data(),in.size());
    CHECK(available(&h.state,h.scope,&h.rx)==100);CHECK(h.rx.bytes.size()==36&&h.rx.ahead.size()==52);
    Byte first[4];CHECK(get(&h.state,h.scope,&h.rx,first,4)==4);CHECK(available(&h.state,h.scope,&h.rx)==96);
    CHECK(!clear(&h.state,h.scope,&h.rx,95));CHECK(h.rx.clear_calls==0);
    h.rx.append_before_clear={0x77};CHECK(!clear(&h.state,h.scope,&h.rx,96));CHECK(h.rx.last_expected==88);
    CHECK(available(&h.state,h.scope,&h.rx)==97);CHECK(clear(&h.state,h.scope,&h.rx,0));CHECK(available(&h.state,h.scope,&h.rx)==0);
    auto zero=frame(101);h.rx.feed(zero.data(),zero.size());CHECK(available(&h.state,h.scope,&h.rx)==12);
    auto next=frame(103,{},9);h.rx.append_after_zero_observation=next;U32 calls=h.rx.clear_calls;
    CHECK(clear(&h.state,h.scope,&h.rx,12));CHECK(h.rx.clear_calls==calls);
    std::vector<Byte> got(12);CHECK(get(&h.state,h.scope,&h.rx,got.data(),12)==12);CHECK(got==frame(13,{},9));
    h.rx.feed(zero.data(),zero.size());CHECK(available(&h.state,h.scope,&h.rx)==12);
    CHECK(wait(&h.state,h.scope,&h.rx,false,1));h.rx.aborted=true;CHECK(!wait(&h.state,h.scope,&h.rx,false,1));
}
static void incoming_chunks(){
    Harness h;h.rx.capacity=37;h.rx.max_chunk=3;h.rx.prefetch=17;h.rx.get_zero_every=5;
    std::vector<Byte> legacy,expect;
    for(U32 i=0;i<200;++i){std::vector<Byte> body(i%83);for(Size j=0;j<body.size();++j)body[j]=Byte(i+j);append(legacy,frame(i%2?101:103,body,i));append(expect,frame(i%2?11:13,body,i));}
    std::atomic<bool> failed{false};
    std::thread producer([&]{Size at=0;for(Size count=0;at<legacy.size()&&count<2000000;++count){U32 n=original_put(&h.rx,legacy.data()+at,U32(std::min<Size>(11,legacy.size()-at)));at+=n;if(!n)std::this_thread::yield();}if(at!=legacy.size())failed=true;});
    std::vector<Byte> seen;Byte b[19];
    for(Size count=0;seen.size()<expect.size()&&count<2000000;++count){
        if(!available(&h.state,h.scope,&h.rx)){(void)wait(&h.state,h.scope,&h.rx,false,1);continue;}
        U32 n=get(&h.state,h.scope,&h.rx,b,sizeof(b));seen.insert(seen.end(),b,b+n);if(!n)std::this_thread::yield();assert_ok(h);
    }
    producer.join();CHECK(!failed);CHECK(seen==expect);CHECK(h.rx.wait_calls>0);assert_ok(h);
}
static void outgoing_chunks(){
    Harness h;h.tx.capacity=53;h.tx.max_chunk=7;h.tx.put_zero_every=5;
    std::vector<Byte> source,expect;
    for(U32 i=0;i<300;++i){std::vector<Byte> body(i%127);for(Size j=0;j<body.size();++j)body[j]=Byte(i^j);auto f=frame(11,body,i);append(source,f);append(expect,converted(f));}
    std::atomic<bool> done{false};std::vector<Byte> seen;
    std::thread consumer([&]{for(Size n=0;n<3000000;++n){auto v=h.tx.drain(13);append(seen,v);if(done&&v.empty())return;if(v.empty())std::this_thread::yield();}});
    Size at=0;for(Size n=0;at<source.size()&&n<3000000;++n){U32 want=U32(std::min<Size>(1+n%17,source.size()-at));U32 got=put(&h.state,h.scope,&h.tx,source.data()+at,want);CHECK(got<=want);at+=got;if(!got)std::this_thread::yield();assert_ok(h);}
    CHECK(at==source.size());CHECK(!h.state.tx_final_unacked);done=true;consumer.join();append(seen,h.tx.drain(100));CHECK(seen==expect);
}
static void large_ring(){
    Harness h(max_frame);h.tx.capacity=25u*1024u*1024u;h.tx.max_chunk=1024u*1024u;
    auto source=frame(11,std::vector<Byte>(26u*1024u*1024u,0x5a));
    CHECK(put(&h.state,h.scope,&h.tx,source.data(),U32(source.size()))==source.size()-1);
    CHECK(h.state.tx_final_unacked);CHECK(h.state.tx_sent==25u*1024u*1024u);
    auto seen=h.tx.drain(h.tx.capacity);CHECK(put(&h.state,h.scope,&h.tx,source.data()+source.size()-1,1)==1);
    append(seen,h.tx.drain(h.tx.capacity));set32(source,4,101);CHECK(seen==source);assert_ok(h);
}
static void failures(){
    for(U32 id:{91u,92u,93u}){Harness h;auto f=frame(id);(void)put(&h.state,h.scope,&h.tx,f.data(),U32(f.size()));CHECK(status(&h.state).wire==madeira_wire::Error::UnsupportedCommand);CHECK(original_available(&h.tx)==0);}
    {Harness h;auto f=frame(11);set32(f,0,madeira_wire::max_outgoing_payload+1);(void)put(&h.state,h.scope,&h.tx,f.data(),12);CHECK(status(&h.state).wire==madeira_wire::Error::FrameTooLarge);}
    {Harness h(64);auto f=frame(11);set32(f,0,65);(void)put(&h.state,h.scope,&h.tx,f.data(),12);CHECK(status(&h.state).wire==madeira_wire::Error::Capacity);}
    {Harness h;auto f=frame(12,{0x50,0x7f});(void)put(&h.state,h.scope,&h.tx,f.data(),U32(f.size()));CHECK(status(&h.state).wire==madeira_wire::Error::UnsupportedBrowserType);}
    {Harness h;auto f=frame(999);h.rx.feed(f.data(),f.size());CHECK(available(&h.state,h.scope,&h.rx)==0);CHECK(status(&h.state).wire==madeira_wire::Error::UnsupportedCommand);}
    {Harness h;auto f=frame(102);h.rx.feed(f.data(),f.size());CHECK(available(&h.state,h.scope,&h.rx)==0);CHECK(status(&h.state).wire==madeira_wire::Error::WrongDirection);}
    {Harness h;auto f=frame(101);set32(f,0,madeira_wire::max_incoming_payload+1);h.rx.feed(f.data(),f.size());CHECK(available(&h.state,h.scope,&h.rx)==0);CHECK(status(&h.state).wire==madeira_wire::Error::FrameTooLarge);}
    {Harness h;auto f=frame(101,{1,2,3});set32(f,0,madeira_wire::max_incoming_payload);h.rx.feed(f.data(),f.size());Byte b[15];CHECK(get(&h.state,h.scope,&h.rx,b,15)==15);CHECK(h.state.rx_body_left==madeira_wire::max_incoming_payload-3);assert_ok(h);}
    {Harness h;h.tx.over_put=true;auto f=frame(11);(void)put(&h.state,h.scope,&h.tx,f.data(),12);CHECK(status(&h.state).error==Error::OriginalOverreported);}
    {Harness h;h.rx.over_get=true;auto f=frame(101);h.rx.feed(f.data(),f.size());CHECK(available(&h.state,h.scope,&h.rx)==0);CHECK(status(&h.state).error==Error::OriginalOverreported);}
    {Harness h;Scope wrong=h.scope;++wrong.generation;CHECK(available(&h.state,wrong,&h.rx)==0);CHECK(status(&h.state).error==Error::WrongScope);}
}

struct DomainControl {
    madeira_domain::Registry registry{};U32 calls=0;bool fail=false;
    static void *alloc(void *,Size n){return std::malloc(n);}
    static void free(void *,void *p){std::free(p);}
    DomainControl(){CHECK(madeira_domain::open(&registry,{1,7},{nullptr,alloc,free})==madeira_domain::Error::Ok);}
    ~DomainControl(){CHECK(madeira_domain::close(&registry,{1,7})==madeira_domain::Error::Ok);}
    static bool handles(void *,U32 command){return command==54;}
    static bool consume(void *p,const Scope &scope,U32 command,U32 browser,const Byte *body,Size n){
        auto &d=*static_cast<DomainControl *>(p);++d.calls;
        if(d.fail||scope.generation!=7||command!=54||browser!=0xffffffffu)return false;
        madeira_domain::Registration r{};
        return madeira_domain::parse_registration({body,n},&r)==madeira_domain::Error::Ok&&
            madeira_domain::update(&d.registry,{1,scope.generation},r)==madeira_domain::Error::Ok;
    }
    Control api(){return {this,handles,consume};}
};
static void local_controls(){
    const std::vector<Byte> body={0x0a,4,'d','.','h','t',0x12,4,'p','a','t','h'};
    auto registration=frame(54,body,0xffffffffu);
    for(Size cut=1;cut<registration.size();++cut){DomainControl d;Harness h(4096,d.api());
        CHECK(put(&h.state,h.scope,&h.tx,registration.data(),U32(cut))==cut);CHECK(d.calls==0&&d.registry.records==0);
        CHECK(put(&h.state,h.scope,&h.tx,registration.data()+cut,U32(registration.size()-cut))==registration.size()-cut);
        CHECK(d.calls==1&&d.registry.records==1&&h.tx.put_calls==0);assert_ok(h);
    }
    {DomainControl d;Harness h(4096,d.api(),1);
        CHECK(put(&h.state,h.scope,&h.tx,registration.data(),U32(registration.size()))==registration.size()-1);
        CHECK(d.calls==1&&h.state.tx_final_unacked&&writable(&h.state,h.scope,&h.tx)==1);
        CHECK(put(&h.state,h.scope,&h.tx,registration.data()+registration.size()-1,1)==1);
        CHECK(d.calls==1&&h.tx.put_calls==0);assert_ok(h);
    }
    {DomainControl d;Harness h(4096,d.api());auto before=frame(11,{1,2}),after=frame(13,{3,4});
        std::vector<Byte> input=before;append(input,registration);append(input,after);
        CHECK(put(&h.state,h.scope,&h.tx,input.data(),U32(input.size()))==input.size());
        auto expected=converted(before);append(expected,converted(after));CHECK(h.tx.drain(4096)==expected);
        CHECK(d.calls==1&&d.registry.records==1);assert_ok(h);
    }
    for(unsigned mode=0;mode<3;++mode){DomainControl d;Harness h(4096,d.api());auto bad=registration;
        if(mode==0)d.fail=true;
        if(mode==1)set32(bad,8,123);
        if(mode==2)bad[12]=0;
        CHECK(put(&h.state,h.scope,&h.tx,bad.data(),U32(bad.size()))==bad.size()-1);
        CHECK(status(&h.state).error==Error::ControlFailure&&d.registry.records==0&&h.tx.put_calls==0);
    }
    for(U32 command:{53u,108u}){DomainControl d;Harness h(4096,d.api());auto bad=frame(command);
        CHECK(put(&h.state,h.scope,&h.tx,bad.data(),U32(bad.size()))==bad.size()-1);
        CHECK(status(&h.state).wire==madeira_wire::Error::UnsupportedCommand&&d.calls==0&&h.tx.put_calls==0);
    }
    {DomainControl d;Harness h(4096,d.api());CHECK(put(&h.state,h.scope,&h.tx,registration.data(),13)==13);
        CHECK(d.calls==0);CHECK(clear(&h.state,h.scope,&h.tx,0));CHECK(d.registry.records==0);assert_ok(h);}
}

int main(){local_controls();tx_final_ack();retry_mismatch();read_ahead_and_clear();incoming_chunks();outgoing_chunks();large_ring();failures();std::printf("stream codec: %llu checks passed\n",checks.load());}
