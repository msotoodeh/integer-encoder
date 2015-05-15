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

#define I32_ROUNDS    12
#define I64_ROUNDS    16

typedef struct
{
    U32 L0, R0;
    U8 S1[256], S2[256];
} INT_NCODER_CTX;

void INT_NCODER_Init(
    IN const U8 *key, 
    IN SZ len, 
    OUT INT_NCODER_CTX *ctx);

// 32-bit encrypt/decrypt

U32 I32_Encrypt(
    IN const INT_NCODER_CTX *ctx, 
    IN U32 data);

U32 I32_Decrypt(
    IN const INT_NCODER_CTX *ctx, 
    IN U32 data);

// 64-bit encrypt/decrypt

U64 I64_Encrypt(
    IN const INT_NCODER_CTX *ctx, 
    IN U64 data);
    
U64 I64_Decrypt(
    IN const INT_NCODER_CTX *ctx, 
    IN U64 data);

#ifdef __cplusplus
}
#endif