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

#define SHA256_BLOCK_SIZE   64
#define SHA256_DIGEST_SIZE  32

typedef struct
{
    U64 MsgLength;
    int BufferLength;
    U32 Digest[8];
    U8  Buffer[64];
    
} SHA256_CTX;

void SHA256_Init (
    SHA256_CTX *ctx);

void SHA256_Update (
    SHA256_CTX *ctx, 
    const void *data, 
    SZ len);

U32* SHA256_Final (
    SHA256_CTX *ctx, 
    U8 *hash);

void SHA256_Hash (
    const void *data, 
    SZ len, 
    U8 *hash, 
    SZ hash_size);

int SHA256_SelfTest( void );

#ifdef __cplusplus
}
#endif