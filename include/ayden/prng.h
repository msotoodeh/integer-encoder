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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "basetypes.h"

typedef struct
{
    U8 State[48];
} PRNG_CTX;

void PRNG_Init (
    PRNG_CTX *ctx, 
    const U8 *key, 
    SZ len);

U32  PRNG_ReadInt (
    PRNG_CTX *ctx);

void PRNG_ReadBytes (
    PRNG_CTX *ctx,
    U8 *data, 
    SZ size);

void PRNG_ShuffleBytes (
    PRNG_CTX *ctx, 
    U8 *data, 
    U32 size);

void PRNG_ShuffleWords (
    PRNG_CTX *ctx, 
    U16 *data, 
    U32 size);

void PRNG_ShuffleSeqBytes (
    PRNG_CTX *ctx, 
    U8 *data, 
    U32 size, 
    U8 first);

void PRNG_ShuffleSeqWords (
    PRNG_CTX *ctx, 
    U16 *data, 
    U32 size, 
    U16 first);

#ifdef __cplusplus
}
#endif