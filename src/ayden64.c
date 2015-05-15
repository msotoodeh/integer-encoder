/* 
 * Copyright Mehdi Sotoodeh.  All rights reserved. 
 * <mehdisotoodeh@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that source code retains the 
 * above copyright notice and following disclaimer.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "ayden/ayden.h"

static U32 L_PRF32(
    IN const U8 *S1, 
    IN const U8 *S2, 
    IN int round,
    IN const M32 din)
{
    M32 dout;
    U8 t1, t2, t3, t4;

    t1 = S1[din.u8.b0 ^ round ^ S2[din.u8.b1]] + din.u8.b2;
    t2 = S1[din.u8.b1 ^ round ^ S2[din.u8.b3 ^ round]] ^ din.u8.b0;
    t3 = S1[din.u8.b2 ^ round ^ S2[t1]] - din.u8.b1;
    t4 = S1[din.u8.b3 ^ round ^ S2[t2]] ^ t3;

    dout.u8.b0 = S1[t4 ^ S2[t2]] ^ t1;
    dout.u8.b1 = S1[t3 ^ S2[t1]] ^ t2;
    dout.u8.b2 = S1[t2 ^ S2[t4]] ^ t3;
    dout.u8.b3 = S1[t1 ^ S2[t3]] ^ t4; 

    return dout.u32;
}

static U32 R_PRF32(
    IN const U8 *S1, 
    IN const U8 *S2, 
    IN int round,
    IN const M32 din)
{
    M32 dout;
    U8 t1, t2, t3, t4;

    t1 = S2[din.u8.b0 ^ round ^ S1[din.u8.b1]] ^ din.u8.b2;
    t2 = S2[din.u8.b1 ^ round ^ S1[din.u8.b3 ^ round]] + din.u8.b0;
    t3 = S2[din.u8.b2 ^ round ^ S1[t1]] ^ din.u8.b1;
    t4 = S2[din.u8.b3 ^ round ^ S1[t2]] - t3;

    dout.u8.b0 = S2[t4 ^ S1[t2]] ^ t1;
    dout.u8.b1 = S2[t3 ^ S1[t1]] ^ t2;
    dout.u8.b2 = S2[t2 ^ S1[t4]] ^ t3;
    dout.u8.b3 = S2[t1 ^ S1[t3]] ^ t4; 

    return dout.u32;
}

#define L   din.m32.hi
#define R   din.m32.lo

U64 I64_Encrypt(
    IN const INT_NCODER_CTX *ctx, 
    IN U64 data)
{
    int i;
    M64 din;
    din.u64 = data;

    L.u32 += ctx->L0;
    R.u32 += ctx->R0;

    for (i = 0; i < I64_ROUNDS; i++)
    {
        R.u32 += R_PRF32(ctx->S1, ctx->S2, i, L);
        L.u32 -= L_PRF32(ctx->S1, ctx->S2, i, R);
    }
    return din.u64;
}

U64 I64_Decrypt(
    IN const INT_NCODER_CTX *ctx, 
    IN U64 data)
{
    int i;
    M64 din;
    din.u64 = data;

    for (i = I64_ROUNDS; i-- > 0; )
    {
        L.u32 += L_PRF32(ctx->S1, ctx->S2, i, R);
        R.u32 -= R_PRF32(ctx->S1, ctx->S2, i, L);
    }

    L.u32 -= ctx->L0;
    R.u32 -= ctx->R0;
    return din.u64;
}