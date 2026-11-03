/* SPDX-License-Identifier: MIT. Incremental connected-stream boundary only. */
#ifndef MADEIRA_HTMLIPC_STREAM_CODEC_H
#define MADEIRA_HTMLIPC_STREAM_CODEC_H
#include "../wire-codec/wire_codec.h"
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define MADEIRA_STREAM_ABI __attribute__((ms_abi))
#elif defined(_M_X64)
#define MADEIRA_STREAM_ABI
#else
#error "This guest stream boundary requires AMD64 Microsoft ABI"
#endif
namespace madeira_stream_codec {
using Byte=madeira_wire::Byte;using U32=madeira_wire::U32;
using U64=madeira_wire::U64;using Size=madeira_wire::Size;
using Stream=void *;
struct Original {
    using Count=U32 (MADEIRA_STREAM_ABI *)(Stream);
    using Put=U32 (MADEIRA_STREAM_ABI *)(Stream,const void *,U32);
    using Get=U32 (MADEIRA_STREAM_ABI *)(Stream,void *,U32);
    using Clear=bool (MADEIRA_STREAM_ABI *)(Stream,U32);
    using Wait=bool (MADEIRA_STREAM_ABI *)(Stream,bool,U32);
    Count available,writable;Put put;Get get;Clear clear;Wait wait;
};
struct Lock {
    void *context;
    void (*enter)(void *);
    void (*leave)(void *);
};
struct Scope {void *controller;U64 generation;Stream to_helper,from_helper;};
struct Workspace {Byte *input;Size input_capacity;Byte *output;Size output_capacity;};
enum class Error:U32 {
    None,InvalidConfiguration,WrongScope,InvalidArgument,WireFailure,
    OriginalOverreported,RetryByteMismatch,CounterOverflow
};
struct Failure {Error error;madeira_wire::Error wire;};
struct Settings {
    Scope scope;Original original;madeira_wire::MapView map;Workspace workspace;
    Lock lock;
    /* Maximum original Put/Get calls made while one codec call holds the
     * lock. Zero stops pumping. Positive short writes continue within this
     * bound. Recommended:64 for the genuine 1MiB chunks/32MiB frame limit. */
    U32 io_budget;
};
/* All memory is caller-owned. Allocate sizeof(State), plus two disjoint
 * workspaces of max_frame bytes to support the full outgoing limit. Smaller
 * workspaces are allowed and produce explicit Capacity failure for a frame
 * that does not fit. No heap allocation occurs here. */
constexpr Size max_frame=Size(madeira_wire::max_outgoing_payload)+12;
struct State {
    Settings settings{};Failure failure{Error::None,madeira_wire::Error::Ok};
    bool configured=false;
    Size tx_used=0,tx_expected=0,tx_size=0,tx_sent=0;
    bool tx_final_unacked=false;Byte tx_final_byte=0;
    Byte rx_header[12]{};U32 rx_collected=0,rx_delivered=0,rx_body_left=0;
    bool rx_ready=false;
};
/* Settings and map stay immutable through this generation. The external
 * owner closes admission and drains callbacks before freeing State/buffers.
 * Lock must serialize all local state operations, including original Get's
 * private read-ahead. Original Wait is ALWAYS called outside this lock: it
 * re-enters the hooked Available and also owns the genuine abort semantics.
 * An admission lock in the provider must likewise allow that re-entry. */
/* Configure a fresh value-initialized State once. Reconfiguration of an
 * already configured generation is rejected without discarding its buffers. */
bool configure(State *,const Settings &);
Failure status(State *);
U32 put(State *,const Scope &,Stream,const void *,U32);
U32 get(State *,const Scope &,Stream,void *,U32);
U32 available(State *,const Scope &,Stream);
U32 writable(State *,const Scope &,Stream);
bool clear(State *,const Scope &,Stream,U32 expected);
bool wait(State *,const Scope &,Stream,bool infinite,U32 timeout);
}
#undef MADEIRA_STREAM_ABI
#endif
