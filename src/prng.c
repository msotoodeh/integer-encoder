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

#include <string.h>
#include "ayden/prng.h"
#include "ayden/sha256.h"

/*
    Implementation of SHA256-based PRNG
*/

void PRNG_Init( 
    PRNG_CTX *ctx, 
    const U8 *key, 
    SZ len )
{
    SHA256_CTX hash;
    SHA256_Init( &hash );
    SHA256_Update( &hash, key, len );
    SHA256_Final( &hash, &ctx->State[0] );

    SHA256_Init( &hash );
    SHA256_Update( &hash, &ctx->State[0], 32 );
    SHA256_Update( &hash, key, len );
    SHA256_Final( &hash, &ctx->State[16] );
}

U32 PRNG_ReadInt( PRNG_CTX *ctx )
{
    int i;
    U8 *p;
    SHA256_CTX hash;
    U8 digest[SHA256_DIGEST_SIZE];

    SHA256_Init( &hash );
    SHA256_Update( &hash, &ctx->State[0], 48 );
    SHA256_Final( &hash, digest );

    p = &ctx->State[(ctx->State[47]++) & 15];
    for (i = 0; i < SHA256_DIGEST_SIZE; i++, p++) *p ^= digest[i];
    return hash.Digest[0];
}

void PRNG_ReadBytes (
    PRNG_CTX *ctx, 
    U8 *data, 
    SZ size)
{
    while( size-- > 0 ) *data++ = (U8)PRNG_ReadInt(ctx);
}

void PRNG_ShuffleBytes (
    PRNG_CTX *ctx, 
    U8 *data, 
    U32 size)
{
    while( size > 1 )
    {
        U32 i = PRNG_ReadInt(ctx) % size;
        U8 t = data[--size];
        data[size] = data[i];
        data[i] = t;
    }
}

void PRNG_ShuffleWords (
    PRNG_CTX *ctx, 
    U16 *data, 
    U32 size)
{
    while (size > 1)
    {
        U32 i = PRNG_ReadInt(ctx) % size;
        U16 t = data[--size];
        data[size] = data[i];
        data[i] = t;
    }
}

void PRNG_ShuffleSeqBytes (
    PRNG_CTX *ctx, 
    U8 *data, 
    U32 size, 
    U8 first)
{
    U32 i;
    for (i = 0; i < size; i++) data[i] = first++;
    PRNG_ShuffleBytes(ctx, data, size);
}

void PRNG_ShuffleSeqWords (
    PRNG_CTX *ctx, 
    U16 *data, 
    U32 size, 
    U16 first)
{
    U32 i;
    for (i = 0; i < size; i++) data[i] = first++;
    PRNG_ShuffleWords(ctx, data, size);
}