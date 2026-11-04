/* SPDX-License-Identifier: MIT. Helper-side routing state; no request policy bypass. */
#ifndef MADEIRA_DOMAIN_REGISTRY_H
#define MADEIRA_DOMAIN_REGISTRY_H
namespace madeira_domain {
using Byte=unsigned char;using U32=unsigned int;using U64=unsigned long long;using Size=decltype(sizeof(0));
struct Bytes {const Byte *data;Size size;};
struct Owner {U64 process,generation;};
struct Memory {void *context;void *(*allocate)(void *,Size);void (*release)(void *,void *);};
enum class Error {Ok,InvalidArgument,WrongOwner,Malformed,UnsupportedField,TooLarge,NoMemory,Capacity,NotFound};
struct Registration {Bytes domain,path;};
struct Result {Error error;Size required;};
constexpr Size max_registration_bytes=32u*1024u*1024u;
/* Exact pinned command54 schema. Missing strings default empty; repeated fields
 * retain the last value, as the genuine protobuf parser does. No URL/path
 * normalization is invented here. Unknown fields fail explicitly. */
Error parse_registration(Bytes,Registration *);
struct Node;
struct Registry {Owner owner{};Memory memory{};Node *head=nullptr;Size records=0,reserved=0;bool live=false;};
/* Caller serializes access and waits for all callbacks before close/reset.
 * No borrowed node or path pointer escapes. Owner generation must match even
 * when the same process address is recycled. */
Error open(Registry *,Owner,Memory);
Error update(Registry *,Owner,Registration);
/* host must already be parsed by the genuine CEF URL parser. Exact bytewise
 * matching reproduces the helper's strcmp map key. Caller retains browser-type,
 * explicit BrowserView opt-in, empty-existing-map and pre-navigation checks.
 * Returns a copied NUL-terminated path; insufficient output changes no bytes. */
Result lookup(const Registry *,Owner,Bytes parsed_host,Byte *output,Size capacity);
Error close(Registry *,Owner);
}
#endif
