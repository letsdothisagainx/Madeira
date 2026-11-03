/* SPDX-License-Identifier: MIT
 * HTMLIPC wire boundary only. Does not replace controller/callback C++ objects.
 */
#ifndef MADEIRA_HTMLIPC_WIRE_CODEC_H
#define MADEIRA_HTMLIPC_WIRE_CODEC_H
namespace madeira_wire {
using Byte = unsigned char;
using U32 = unsigned int;
using U64 = unsigned long long;
using Size = decltype(sizeof(0));
static_assert(sizeof(U32)==4 && sizeof(U64)==8);

enum class Direction { CurrentToLegacy, LegacyToCurrent };
enum class MessageKind { OpaqueCommon, BrowserCreate };
/* The owner must supply its independently proven current/legacy command map.
 * There is no default identity map or guessed command ID. A configured pair
 * must have the same pinned message name and schema, except BrowserCreate.
 * Unknown/new/removed commands must be absent. No C++ protobuf object crosses
 * this boundary. IDs in the fixture are exclusively test fixtures. */
struct MapEntry { U32 current_command; U32 legacy_command; MessageKind kind; };
struct MapView { const MapEntry *entries; Size count; };
enum class Error {
    Ok, InvalidArgument, InvalidMap, MalformedFrame, MalformedProtobuf,
    UnsupportedCommand, UnsupportedBrowserType, WrongDirection,
    FrameTooLarge, Capacity, Overlap,
};
struct Result { Error error; Size written; Size required; };
constexpr U32 max_outgoing_payload=32u*1024u*1024u;
constexpr U32 max_incoming_payload=128u*1024u*1024u;

/* Frame = LE u32 PB-byte-count, LE u32 command, LE u32 browser, PB bytes.
 * Exactly one complete frame is accepted, with no trailing bytes.
 * Common bodies remain completely opaque and byte-identical. BrowserCreate
 * is outgoing only, validates all fields/wires, remaps the 16 known fields,
 * and appends explicit legacy offscreen/borderless booleans derived from the
 * last current type field10 (default zero). Supported types:0..4,12,13.
 * Unknown Create fields fail, rather than being silently discarded.
 * Two passes guarantee that EVERY error leaves output untouched. Capacity
 * errors return required size. Null output with zero capacity is a size query.
 * Input/output storage must remain valid for this synchronous call and must
 * not overlap. There is no allocation, library dependency, or retained state. */
Result convert_frame(Direction, MapView, const Byte *input, Size input_size,
                     Byte *output, Size output_capacity);
}
#endif
