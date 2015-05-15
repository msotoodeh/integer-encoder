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

static U16 PRF16(
    IN const U8 *S1, 
    IN const U8 *S2, 
    IN int round,
    IN const M16 din)
{
    M16 dout;
    U8 t1, t2, t3, t4;

    t1 = S1[din.u8.b0 ^ round ^ S2[din.u8.b1]];
    t2 = S1[din.u8.b1 ^ round ^ S2[din.u8.b0 ^ round]] + t1;
    t3 = S1[t1 ^ round ^ S2[t2]] - din.u8.b1;
    t4 = S1[t2 ^ round ^ S2[t3]] + t3;

    dout.u8.b0 = S1[t4 ^ S2[t2]] ^ t1;
    dout.u8.b1 = S1[t3 ^ S2[t1]] ^ t2;

    return dout.u16;
}

#define L   din.m16.hi
#define R   din.m16.lo

U32 I32_Encrypt(
    IN const INT_NCODER_CTX *ctx, 
    IN U32 data)
{
    int i;
    M32 din;
    din.u32 = data;

    L.u16 += (U16)ctx->L0;
    R.u16 += (U16)ctx->R0;

    for (i = 0; i < I32_ROUNDS; i++)
    {
        R.u16 += PRF16(ctx->S2, ctx->S1, i, L);
        L.u16 -= PRF16(ctx->S1, ctx->S2, i, R);
    }
    return din.u32;
}

U32 I32_Decrypt(
    IN const INT_NCODER_CTX *ctx, 
    IN U32 data)
{
    int i;
    M32 din;
    din.u32 = data;

    for (i = I32_ROUNDS; i-- > 0; )
    {
        L.u16 += PRF16(ctx->S1, ctx->S2, i, R);
        R.u16 -= PRF16(ctx->S2, ctx->S1, i, L);
    }

    L.u16 -= (U16)ctx->L0;
    R.u16 -= (U16)ctx->R0;
    return din.u32;
}
