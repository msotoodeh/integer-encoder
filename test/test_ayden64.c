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
static struct { U64 plain_text, cipher_text; } test_vectors[10] = {
    {0x0000000000000000LL, 0xf13fcadb0422ac00LL},
    {0x0000000000000001LL, 0xbb632c03d107b9bfLL},
    {0x0000000000000010LL, 0x879dd8f434557e8eLL},
    {0x9999999999999999LL, 0x6b7f89de31467cc3LL},
    {0x931deb4ceb4802b6LL, 0x001030484a3265a6LL},
    {0x5e046fe51654b354LL, 0xcd57eec3d5230573LL},
    {0xf22ab69390799033LL, 0x9a13f3c575cf8e12LL},
    {0x8ab554aca02eae5fLL, 0xfa75b0d449c138a0LL},
    {0x8801f649c7ebf6c5LL, 0xe8076a3e6173be3dLL},
    {0x09f43ac6689830e2LL, 0x134640b5807035d8LL}
};

#if defined(_MSC_VER)
#define atoll(S) _atoi64(S)
#endif

int main (int argc, char** argv)
{
    int i, rc = 0;
    U64 pt, ct, rt;
    INT_NCODER_CTX key_context;
    
    if (argc > 2)
    {
        // Loading pre-defined key
        INT_NCODER_Init((const U8*)argv[1], strlen(argv[1]), &key_context );

        // Random data test
        for (i = 2; i < argc; i++)
        {
            pt = atoll(argv[i]);
            ct = I64_Encrypt(&key_context, pt);
            rt = I64_Decrypt(&key_context, ct);

            printf ("%016llx --E--> %016llx --D--> %016llx -- %s\n",
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
        printf("Known Answer Test ...\n");
        for (i = 0; i < 10; i++)
        {
            pt = test_vectors[i].plain_text;
            ct = I64_Encrypt(&key_context, pt);
            rt = I64_Decrypt(&key_context, ct);

            printf ("%016llx --E--> %016llx --D--> %016llx -- %s\n",
                pt, ct, rt, (ct == test_vectors[i].cipher_text && rt == pt)? "PASS" : "FAILED");

            if (rt != pt || ct != test_vectors[i].cipher_text) rc = 1;
        }

        // Random data test
        printf("Random data Test ...\n");
        for (i = 0; i < 10; i++)
        {
            RNG_Bytes(&pt, sizeof(pt));
            ct = I64_Encrypt(&key_context, pt);
            rt = I64_Decrypt(&key_context, ct);

            printf ("%016llx --E--> %016llx --D--> %016llx -- %s\n",
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
            ct = I64_Encrypt(&key_context, pt);
            rt = I64_Decrypt(&key_context, ct);

            printf ("%016llx --E--> %016llx --D--> %016llx -- %s\n",
                pt, ct, rt, (rt == pt)? "PASS" : "FAILED");

            if (rt != pt) rc = 1;
        }
    }
    return rc;
}
