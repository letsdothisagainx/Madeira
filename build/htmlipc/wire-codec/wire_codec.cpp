/* SPDX-License-Identifier: MIT */
#include "wire_codec.h"
namespace madeira_wire {
namespace {
constexpr Size frame_header=12;
constexpr Size size_max=~Size(0);
static U32 read32(const Byte *p) {
    return U32(p[0]) | U32(p[1])<<8 | U32(p[2])<<16 | U32(p[3])<<24;
}
static void write32(Byte *p,U32 n) {
    p[0]=Byte(n);p[1]=Byte(n>>8);p[2]=Byte(n>>16);p[3]=Byte(n>>24);
}
static void copy(Byte *to,const Byte *from,Size count) {
    for (Size i=0;i<count;++i) to[i]=from[i];
}
static Result failure(Error e,Size required=0) { return {e,0,required}; }
static bool kind_valid(MessageKind kind) {
    return kind==MessageKind::OpaqueCommon || kind==MessageKind::BrowserCreate;
}
static bool map_valid(MapView map) {
    if (map.count && !map.entries) return false;
    for (Size i=0;i<map.count;++i) {
        if (!kind_valid(map.entries[i].kind)) return false;
        for (Size j=0;j<i;++j)
            if (map.entries[i].current_command==map.entries[j].current_command ||
                map.entries[i].legacy_command==map.entries[j].legacy_command)
                return false;
    }
    return true;
}
static const MapEntry *lookup(MapView map,Direction d,U32 id) {
    for (Size i=0;i<map.count;++i)
        if ((d==Direction::CurrentToLegacy ? map.entries[i].current_command
                                         : map.entries[i].legacy_command)==id)
            return &map.entries[i];
    return nullptr;
}
static bool varint(const Byte *bytes,Size size,Size *position,U64 *value) {
    U64 result=0;
    for (unsigned i=0;i<10;++i) {
        if (*position==size) return false;
        Byte b=bytes[(*position)++];
        if (i==9 && b>1) return false;
        result|=U64(b&0x7f)<<(7*i);
        if (!(b&0x80)) { *value=result;return true; }
    }
    return false;
}
static Size varint_size(U64 value) {
    Size size=1;while (value>=128) { value>>=7;++size; }return size;
}
static void emit_varint(Byte *output,Size *position,U64 value) {
    while (value>=128) {
        output[(*position)++]=Byte((value&127)|128);value>>=7;
    }
    output[(*position)++]=Byte(value);
}
/* Index0 is deliberately invalid. Each genuine current field retains its wire
 * value representation; only the field number is re-encoded. */
constexpr Byte old_field[17]={0,1,3,5,6,7,9,10,11,13,14,15,16,17,18,19,20};
constexpr Byte field_wire[17]={0,0,2,2,0,5,0,0,2,2,0,0,0,0,2,1,0};
struct CreatePlan { Size output_size; U64 browser_type; };
/* A linear, bounded-by-frame-size scan. Even repeated one-byte fields consume
 * input and count toward the genuine 32MiB limit; no arbitrary field-count cap
 * rejects valid genuine messages. No allocation or recursive group parsing. */
static Error scan_create(const Byte *input,Size size,CreatePlan *plan,Byte *output) {
    Size position=0,emitted=0;
    U64 type=0;
    while (position<size) {
        U64 key;
        if (!varint(input,size,&position,&key) || key>0xffffffffu)
            return Error::MalformedProtobuf;
        U64 field=key>>3;
        unsigned wire=unsigned(key&7);
        if (!field || field>16 || wire!=field_wire[field])
            return Error::MalformedProtobuf;
        Size value_start=position;
        U64 value=0;
        if (wire==0) {
            if (!varint(input,size,&position,&value)) return Error::MalformedProtobuf;
            if (field==10) type=value;
        } else if (wire==1 || wire==5) {
            Size count=wire==1 ? 8 : 4;
            if (size-position<count) return Error::MalformedProtobuf;
            position+=count;
        } else {
            U64 length;
            if (!varint(input,size,&position,&length) || length>size-position)
                return Error::MalformedProtobuf;
            position+=Size(length);
        }
        U64 mapped_key=U64(old_field[field])*8+wire;
        Size value_size=position-value_start;
        Size addition=varint_size(mapped_key)+value_size;
        if (addition>max_outgoing_payload || emitted>max_outgoing_payload-addition)
            return Error::FrameTooLarge;
        if (output) {
            emit_varint(output,&emitted,mapped_key);
            copy(output+emitted,input+value_start,value_size);emitted+=value_size;
        } else emitted+=addition;
    }
    if (!(type<=4 || type==12 || type==13)) return Error::UnsupportedBrowserType;
    /* Explicit legacy fields8 (offscreen) and12 (borderless), including false. */
    if (emitted>max_outgoing_payload-4) return Error::FrameTooLarge;
    bool offscreen=type<=2 || type==12 || type==13;
    bool borderless=type==4;
    if (output) {
        output[emitted++]=8*8;output[emitted++]=Byte(offscreen);
        output[emitted++]=12*8;output[emitted++]=Byte(borderless);
    } else emitted+=4;
    *plan={emitted,type};
    return Error::Ok;
}
static bool address_range(const void *pointer,Size length,Size *begin,Size *end) {
    *begin=reinterpret_cast<Size>(pointer);
    if (*begin>size_max-length) return false;
    *end=*begin+length;return true;
}
}

Result convert_frame(Direction direction,MapView map,const Byte *input,
                     Size input_size,Byte *output,Size output_capacity) {
    if (direction!=Direction::CurrentToLegacy && direction!=Direction::LegacyToCurrent)
        return failure(Error::InvalidArgument);
    if (!input || (!output && output_capacity)) return failure(Error::InvalidArgument);
    if (input_size<frame_header) return failure(Error::MalformedFrame);
    U32 payload=read32(input);
    U32 limit=direction==Direction::CurrentToLegacy ? max_outgoing_payload
                                                  : max_incoming_payload;
    if (payload>limit) return failure(Error::FrameTooLarge);
    if (input_size-frame_header!=payload) return failure(Error::MalformedFrame);
    if (!map_valid(map)) return failure(Error::InvalidMap);
    U32 command=read32(input+4);
    const MapEntry *entry=lookup(map,direction,command);
    if (!entry) return failure(Error::UnsupportedCommand);
    /* Cache configuration before writing caller-owned storage, which may also
     * be reused by the caller after this conversion. */
    MapEntry selected=*entry;
    Size output_payload=payload;
    CreatePlan create{};
    if (selected.kind==MessageKind::BrowserCreate) {
        if (direction!=Direction::CurrentToLegacy) return failure(Error::WrongDirection);
        Error error=scan_create(input+frame_header,payload,&create,nullptr);
        if (error!=Error::Ok) return failure(error);
        output_payload=create.output_size;
    }
    Size required=frame_header+output_payload;
    if (!output || output_capacity<required) return failure(Error::Capacity,required);
    Size in_begin,in_end,out_begin,out_end;
    if (!address_range(input,input_size,&in_begin,&in_end) ||
        !address_range(output,required,&out_begin,&out_end))
        return failure(Error::InvalidArgument);
    if (in_begin<out_end && out_begin<in_end) return failure(Error::Overlap);
    /* Everything which can fail has completed. The second pass sees the same
     * immutable input and cannot fail: no output byte changes before here. */
    if (selected.kind==MessageKind::BrowserCreate) {
        CreatePlan emitted{};
        (void)scan_create(input+frame_header,payload,&emitted,output+frame_header);
    } else copy(output+frame_header,input+frame_header,payload);
    write32(output,U32(output_payload));
    write32(output+4,direction==Direction::CurrentToLegacy ? selected.legacy_command
                                                        : selected.current_command);
    write32(output+8,read32(input+8));
    return {Error::Ok,required,required};
}
}
