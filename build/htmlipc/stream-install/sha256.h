/* SPDX-License-Identifier: MIT. Bounded SHA-256, no allocation or imports. */
#ifndef MADEIRA_STREAM_SHA256_H
#define MADEIRA_STREAM_SHA256_H
#include "installer.h"
namespace madeira_stream_install {
static U32 rotate(U32 x,U32 n) {return (x>>n)|(x<<(32-n));}
static void sha_block(U32 h[8],const U8 b[64]) {
    static constexpr U32 k[64]={
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    U32 w[64];
    for(U32 i=0;i<16;++i) w[i]=(U32(b[i*4])<<24)|(U32(b[i*4+1])<<16)|(U32(b[i*4+2])<<8)|b[i*4+3];
    for(U32 i=16;i<64;++i) {
        U32 a=w[i-15],z=w[i-2];
        w[i]=w[i-16]+(rotate(a,7)^rotate(a,18)^(a>>3))+w[i-7]+(rotate(z,17)^rotate(z,19)^(z>>10));
    }
    U32 a=h[0],b0=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],z=h[7];
    for(U32 i=0;i<64;++i) {
        U32 t=z+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        U32 u=(rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b0)^(a&c)^(b0&c));
        z=g;g=f;f=e;e=d+t;d=c;c=b0;b0=a;a=t+u;
    }
    h[0]+=a;h[1]+=b0;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=z;
}
static void sha256(const U8 *data,Size length,U8 out[32]) {
    U32 h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    Size n=0;for(;length-n>=64;n+=64)sha_block(h,data+n);
    U8 block[64]{};Size tail=length-n;for(Size i=0;i<tail;++i)block[i]=data[n+i];
    block[tail]=0x80;
    if(tail>=56){sha_block(h,block);for(U32 i=0;i<64;++i)block[i]=0;}
    U64 bits=U64(length)*8;for(U32 i=0;i<8;++i)block[63-i]=U8(bits>>(i*8));
    sha_block(h,block);
    for(U32 i=0;i<8;++i)for(U32 j=0;j<4;++j)out[i*4+j]=U8(h[i]>>(24-j*8));
}
}
#endif
