/* SPDX-License-Identifier: MIT */
#include "stream_codec.h"
namespace madeira_stream_codec {
namespace {
struct Guard {State *s;explicit Guard(State *p):s(p){s->settings.lock.enter(s->settings.lock.context);}~Guard(){s->settings.lock.leave(s->settings.lock.context);}};
static U32 read32(const Byte *p){return U32(p[0])|U32(p[1])<<8|U32(p[2])<<16|U32(p[3])<<24;}
static void write32(Byte *p,U32 v){for(U32 i=0;i<4;++i)p[i]=Byte(v>>(i*8));}
static void copy(Byte *to,const Byte *from,Size n){for(Size i=0;i<n;++i)to[i]=from[i];}
static bool error(State *s,Error e,madeira_wire::Error w=madeira_wire::Error::Ok){
    if(s->failure.error==Error::None)s->failure={e,w};
    return false;
}
static bool healthy(const State *s){return s&&s->configured&&s->failure.error==Error::None;}
static bool same_scope(State *s,const Scope &p,Stream stream){
    const Scope &q=s->settings.scope;
    return p.controller==q.controller&&p.generation==q.generation&&
      p.to_helper==q.to_helper&&p.from_helper==q.from_helper&&
      (stream==q.to_helper||stream==q.from_helper);
}
static bool checked(State *s,const Scope &p,Stream stream){
    if(!healthy(s))return false;
    return same_scope(s,p,stream)||error(s,Error::WrongScope);
}
static bool disjoint(const Byte *a,Size an,const Byte *b,Size bn){
    Size x=reinterpret_cast<Size>(a),y=reinterpret_cast<Size>(b),max=~Size(0);
    if(!a||!b||an>max-x||bn>max-y)return false;
    return x+an<=y||y+bn<=x;
}
static bool valid_map(madeira_wire::MapView m){
    if(m.count&&!m.entries)return false;
    for(Size i=0;i<m.count;++i){auto &a=m.entries[i];
        if(a.kind!=madeira_wire::MessageKind::OpaqueCommon&&a.kind!=madeira_wire::MessageKind::BrowserCreate)return false;
        for(Size j=0;j<i;++j)if(m.entries[j].current_command==a.current_command||m.entries[j].legacy_command==a.legacy_command)return false;}
    return true;
}
static const madeira_wire::MapEntry *lookup(State *s,U32 command,bool incoming){
    const auto m=s->settings.map;
    for(Size i=0;i<m.count;++i)if((incoming?m.entries[i].legacy_command:m.entries[i].current_command)==command)return m.entries+i;
    return nullptr;
}
static void reset_tx(State *s){s->tx_used=s->tx_expected=s->tx_size=s->tx_sent=0;s->tx_final_unacked=false;s->tx_final_byte=0;}
static void reset_rx(State *s){s->rx_collected=s->rx_delivered=s->rx_body_left=0;s->rx_ready=false;}
static bool tx_header(State *s){
    U32 bytes=read32(s->settings.workspace.input);
    if(bytes>madeira_wire::max_outgoing_payload)return error(s,Error::WireFailure,madeira_wire::Error::FrameTooLarge);
    s->tx_expected=Size(bytes)+12;
    if(s->tx_expected>s->settings.workspace.input_capacity)return error(s,Error::WireFailure,madeira_wire::Error::Capacity);
    if(!lookup(s,read32(s->settings.workspace.input+4),false))return error(s,Error::WireFailure,madeira_wire::Error::UnsupportedCommand);
    return true;
}
static bool convert(State *s){
    auto &w=s->settings.workspace;
    auto r=madeira_wire::convert_frame(madeira_wire::Direction::CurrentToLegacy,
       s->settings.map,w.input,s->tx_used,w.output,w.output_capacity);
    if(r.error!=madeira_wire::Error::Ok)return error(s,Error::WireFailure,r.error);
    s->tx_size=r.written;s->tx_sent=0;return true;
}
static void flush(State *s,U32 &budget){
    while(healthy(s)&&s->tx_sent<s->tx_size&&budget){
        U32 wanted=U32(s->tx_size-s->tx_sent);--budget;
        U32 n=s->settings.original.put(s->settings.scope.to_helper,
             s->settings.workspace.output+s->tx_sent,wanted);
        if(n>wanted){error(s,Error::OriginalOverreported);return;}
        s->tx_sent+=n;if(!n)return;
    }
}
static void pump_header(State *s,U32 &budget){
    if(s->rx_ready||s->rx_body_left)return;
    while(healthy(s)&&s->rx_collected<12&&budget){
        U32 present=s->settings.original.available(s->settings.scope.from_helper);
        if(!present)return;
        U32 wanted=12-s->rx_collected;if(wanted>present)wanted=present;--budget;
        U32 got=s->settings.original.get(s->settings.scope.from_helper,s->rx_header+s->rx_collected,wanted);
        if(got>wanted){error(s,Error::OriginalOverreported);return;}
        s->rx_collected+=got;if(!got)return;
    }
    if(s->rx_collected!=12||!healthy(s))return;
    U32 payload=read32(s->rx_header);
    if(payload>madeira_wire::max_incoming_payload){error(s,Error::WireFailure,madeira_wire::Error::FrameTooLarge);return;}
    auto e=lookup(s,read32(s->rx_header+4),true);
    if(!e){error(s,Error::WireFailure,madeira_wire::Error::UnsupportedCommand);return;}
    if(e->kind!=madeira_wire::MessageKind::OpaqueCommon){error(s,Error::WireFailure,madeira_wire::Error::WrongDirection);return;}
    write32(s->rx_header+4,e->current_command);s->rx_delivered=0;s->rx_body_left=payload;s->rx_ready=true;
}
static U32 incoming_available(State *s,U32 &budget){
    pump_header(s,budget);if(!healthy(s))return 0;
    if(!s->rx_ready&&!s->rx_body_left)return 0;
    U32 owned=s->rx_ready?12-s->rx_delivered:0;
    U32 raw=s->settings.original.available(s->settings.scope.from_helper);
    if(raw>0xffffffffu-owned){error(s,Error::CounterOverflow);return 0;}
    return owned+raw;
}
}
bool configure(State *s,const Settings &p){
    if(!s||s->configured)return false;
    s->configured=false;s->failure={Error::None,madeira_wire::Error::Ok};
    if(!p.scope.controller||!p.scope.generation||!p.scope.to_helper||!p.scope.from_helper||p.scope.to_helper==p.scope.from_helper||
       !p.original.available||!p.original.writable||!p.original.put||!p.original.get||!p.original.clear||!p.original.wait||
       !p.lock.enter||!p.lock.leave||!p.io_budget||p.io_budget>4096||
       p.workspace.input_capacity<12||p.workspace.input_capacity>max_frame||p.workspace.output_capacity<12||p.workspace.output_capacity>max_frame||
       !disjoint(p.workspace.input,p.workspace.input_capacity,p.workspace.output,p.workspace.output_capacity)||!valid_map(p.map))
        return error(s,Error::InvalidConfiguration,madeira_wire::Error::InvalidMap);
    s->settings=p;reset_tx(s);reset_rx(s);s->configured=true;return true;
}
Failure status(State *s){
    if(!s)return {Error::InvalidConfiguration,madeira_wire::Error::InvalidArgument};
    if(!s->configured)return s->failure;
    Guard guard(s);return s->failure;
}
U32 put(State *s,const Scope &scope,Stream stream,const void *source,U32 bytes){
    if(!s||!s->configured)return 0;
    Guard guard(s);if(!checked(s,scope,stream))return 0;
    if(!source&&bytes){error(s,Error::InvalidArgument);return 0;}if(!bytes)return 0;
    if(stream!=s->settings.scope.to_helper)return s->settings.original.put(stream,source,bytes);
    const Byte *input=static_cast<const Byte*>(source);U32 accepted=0,budget=s->settings.io_budget;
    while(accepted<bytes&&healthy(s)&&budget){
        if(s->tx_final_unacked){
            if(input[accepted]!=s->tx_final_byte){error(s,Error::RetryByteMismatch);return accepted;}
            flush(s,budget);if(!healthy(s)||s->tx_sent!=s->tx_size)return accepted;
            ++accepted;reset_tx(s);continue;
        }
        if(!s->tx_expected){
            Size n=12-s->tx_used;if(n>bytes-accepted)n=bytes-accepted;
            /* The last header byte of a zero-payload frame is also its final
             * byte. Keep it unacknowledged until conversion has drained. */
            if(n&&s->tx_used+n==12){
                Size prefix=n-1;copy(s->settings.workspace.input+s->tx_used,input+accepted,prefix);
                s->tx_used+=prefix;accepted+=U32(prefix);
                s->settings.workspace.input[s->tx_used++]=input[accepted];
                if(!tx_header(s))return accepted;
                if(s->tx_expected==12){
                    s->tx_final_byte=input[accepted];s->tx_final_unacked=true;
                    if(!convert(s))return accepted;
                    continue;
                }
                ++accepted;
            }else{copy(s->settings.workspace.input+s->tx_used,input+accepted,n);s->tx_used+=n;accepted+=U32(n);}
            continue;
        }
        Size left=s->tx_expected-s->tx_used;
        Size n=left;if(n>bytes-accepted)n=bytes-accepted;
        if(n==left){
            Size prefix=n-1;copy(s->settings.workspace.input+s->tx_used,input+accepted,prefix);
            s->tx_used+=prefix;accepted+=U32(prefix);
            s->tx_final_byte=input[accepted];s->settings.workspace.input[s->tx_used++]=s->tx_final_byte;
            s->tx_final_unacked=true;if(!convert(s))return accepted;
        }else{copy(s->settings.workspace.input+s->tx_used,input+accepted,n);s->tx_used+=n;accepted+=U32(n);}
    }
    return accepted;
}
U32 get(State *s,const Scope &scope,Stream stream,void *destination,U32 bytes){
    if(!s||!s->configured)return 0;
    Guard guard(s);if(!checked(s,scope,stream))return 0;
    if(!destination&&bytes){error(s,Error::InvalidArgument);return 0;}if(!bytes)return 0;
    if(stream!=s->settings.scope.from_helper)return s->settings.original.get(stream,destination,bytes);
    Byte *output=static_cast<Byte*>(destination);U32 total=0,budget=s->settings.io_budget;
    while(total<bytes&&healthy(s)&&budget){
        pump_header(s,budget);if(!healthy(s))return total;
        if(s->rx_ready){U32 n=12-s->rx_delivered;if(n>bytes-total)n=bytes-total;
            copy(output+total,s->rx_header+s->rx_delivered,n);s->rx_delivered+=n;total+=n;
            if(s->rx_delivered!=12)return total;
            s->rx_ready=false;s->rx_collected=s->rx_delivered=0;
            if(!s->rx_body_left)continue;
        }
        if(!s->rx_body_left)return total;
        if(!budget)return total;
        U32 wanted=bytes-total;if(wanted>s->rx_body_left)wanted=s->rx_body_left;--budget;
        U32 got=s->settings.original.get(stream,output+total,wanted);
        if(got>wanted){error(s,Error::OriginalOverreported);return total;}
        total+=got;s->rx_body_left-=got;if(!got)return total;
    }
    return total;
}
U32 available(State *s,const Scope &scope,Stream stream){
    if(!s||!s->configured)return 0;
    Guard guard(s);if(!checked(s,scope,stream))return 0;
    if(stream!=s->settings.scope.from_helper)return s->settings.original.available(stream);
    U32 budget=s->settings.io_budget;return incoming_available(s,budget);
}
U32 writable(State *s,const Scope &scope,Stream stream){
    if(!s||!s->configured)return 0;
    Guard guard(s);if(!checked(s,scope,stream))return 0;
    if(stream!=s->settings.scope.to_helper)return s->settings.original.writable(stream);
    if(s->tx_final_unacked){U32 budget=s->settings.io_budget;flush(s,budget);
        return healthy(s)&&s->tx_sent==s->tx_size?1:0;}
    return U32(s->settings.workspace.input_capacity-s->tx_used);
}
bool clear(State *s,const Scope &scope,Stream stream,U32 expected){
    if(!s||!s->configured)return false;
    Guard guard(s);if(!checked(s,scope,stream))return false;
    if(stream==s->settings.scope.to_helper){if(!s->settings.original.clear(stream,expected))return false;reset_tx(s);return true;}
    U32 budget=s->settings.io_budget;
    if(expected){U32 visible=incoming_available(s,budget);if(!healthy(s)||visible!=expected)return false;
        U32 owned=s->rx_ready?12-s->rx_delivered:0;if(expected<owned)return false;
        U32 physical=expected-owned;
        if(!physical){
            /* The original Available observation was zero. Linearize here:
             * clear only owned bytes and preserve every later remote append.
             * Never use original Clear(0)'s wildcard for a conditional clear. */
            reset_rx(s);return true;
        }
        if(!s->settings.original.clear(stream,physical))return false;
    }else if(!s->settings.original.clear(stream,0))return false;
    reset_rx(s);return true;
}
bool wait(State *s,const Scope &scope,Stream stream,bool infinite,U32 timeout){
    if(!s||!s->configured)return false;
    {Guard guard(s);if(!checked(s,scope,stream))return false;}
    /* Genuine Wait checks abort and calls the hooked Available. Holding this
     * state lock here would deadlock that deliberate same-thread re-entry. */
    bool result=s->settings.original.wait(stream,infinite,timeout);
    {Guard guard(s);if(!checked(s,scope,stream))return false;}
    return result;
}
}
