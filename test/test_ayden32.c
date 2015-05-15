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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ayden/ayden.h"
#include "ayden/random.h"

static const U8 test_key_secret[] =
{
    0xBE,0xBE,0x4B,0x05,0x6E,0xD4,0x6F,0x17, 0x55,0x36,0x74,0x08,0xA5,0xDC,0x4D,0x02,
    0x1C,0x89,0x99,0x60,0x0A,0x42,0xF4,0x6C, 0xC1,0x16,0xCB,0xE2,0x83,0x61,0xAB,0x87
};

// Self test values using test_key_secret
static struct { U32 plain_text, cipher_text; } test_vectors[10] = {
    {0x00000000, 0xdd88efec},
    {0x00000001, 0x9c3af872},
    {0x10000000, 0x2bedadb3},
    {0x44e0aac2, 0x108aa84a},
    {0x8bcfe6af, 0x2fe50f00},
    {0x2434b90b, 0x31cd013c},
    {0xe5d02a2a, 0xe2133d51},
    {0x266c9a72, 0x92a28d83},
    {0x156769bc, 0xf097563f},
    {0xa57c5777, 0xcc0c5db0}
};

void print_key_context(IN INT_NCODER_CTX *ctx, IN const char *name)
{
    int i;
    printf("static const INT_NCODER_CTX %s = {\n"
        "    0x%08X,0x%08X,\n"
        "   {0x%02X",
        name, ctx->L0, ctx->R0, ctx->S1[0]);

    for (i = 1; i < 256; i++) 
        if (i & 15) printf(",0x%02X", ctx->S1[i]); else printf(",\n    0x%02X", ctx->S1[i]);

    printf("},\n   {0x%02X", ctx->S2[0]);
    for (i = 1; i < 256; i++) 
        if (i & 15) printf(",0x%02X", ctx->S2[i]); else printf(",\n    0x%02X", ctx->S2[i]);
    printf("}\n};\n");
}

int main (int argc, char** argv)
{
    int i, rc = 0;
    U32 pt, ct, rt;
    INT_NCODER_CTX key_context;
    
    if (argc > 2)
    {
        // Loading pre-defined key
        INT_NCODER_Init((const U8*)argv[1], strlen(argv[1]), &key_context );

        print_key_context(&key_context, "test_key_ctx");

        // Random data test
        for (i = 2; i < argc; i++)
        {
            pt = atol(argv[i]);
            ct = I32_Encrypt(&key_context, pt);
            rt = I32_Decrypt(&key_context, ct);

            printf ("%08x --E--> %08x --D--> %08x -- %s\n",
                pt, ct, rt, (rt == pt)? "PASS" : "FAILED");

            if (rt != pt) rc = 1;
        }
    }
    else
    {
        U8 key[32];
        printf("Testing statically defined key ...\n");
        // Loading pre-defined key
        INT_NCODER_Init(test_key_secret, sizeof(test_key_secret), &key_context );

        // Known answer test
        printf("Known Answer Tests ...\n");
        for (i = 0; i < 10; i++)
        {
            pt = test_vectors[i].plain_text;
            ct = I32_Encrypt(&key_context, pt);
            rt = I32_Decrypt(&key_context, ct);

            printf ("%08x --E--> %08x --D--> %08x -- %s\n",
                pt, ct, rt, (ct == test_vectors[i].cipher_text && rt == pt)? "PASS" : "FAILED");

            if (rt != pt || ct != test_vectors[i].cipher_text) rc = 1;
        }

        // Random data test
        printf("Random data Test ...\n");
        for (i = 0; i < 10; i++)
        {
            RNG_Bytes(&pt, sizeof(pt));
            ct = I32_Encrypt(&key_context, pt);
            rt = I32_Decrypt(&key_context, ct);

            printf ("%08x --E--> %08x --D--> %08x -- %s\n",
                pt, ct, rt, (rt == pt)? "PASS" : "FAILED");

            if (rt != pt) rc = 1;
        }

        // Now generate a new random key 
        RNG_Bytes(key, sizeof(key));
    
        printf("Testing randomly generated key ...\n");
        INT_NCODER_Init(key, sizeof(key), &key_context );

        // Random data test
        for (i = 0; i < 10; i++)
        {
            RNG_Bytes(&pt, sizeof(pt));
            ct = I32_Encrypt(&key_context, pt);
            rt = I32_Decrypt(&key_context, ct);

            printf ("%08x --E--> %08x --D--> %08x -- %s\n",
                pt, ct, rt, (rt == pt)? "PASS" : "FAILED");

            if (rt != pt) rc = 1;
        }
    }
    return rc;
}