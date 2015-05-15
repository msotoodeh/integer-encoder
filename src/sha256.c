/** **********************************************************************
 ** KryptoPlus crypto software library version @VERSION@
 ** Copyright 2013-2015 KryptoLogik.com.  All rights reserved.
 ** ----------------------------------------------------------------------
 ** THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS
 ** OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 ** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 ** LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 ** CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 ** SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 ** BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 ** WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 ** OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 ** EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ** ----------------------------------------------------------------------
 ** info: <info@kryptoplus.com>
 ** @author mehdi sotoodeh   <mehdisotoodeh@gmail.com>
 **/

#include <string.h>
#include "ayden/sha256.h"

#define DO_SELFTEST

#ifdef CONFIG_BIG_ENDIAN
#define BIG_ENDIAN
#endif

// Make default as LITTLE_ENDIAN 
#ifndef BIG_ENDIAN
#define LITTLE_ENDIAN
#endif

/* 32-bit Shift operations */
#define SHR(x,n)    ((x & 0xFFFFFFFF) >> n)
#define SHL(x,n)    ((x << (n)) & 0xFFFFFFFF)
#define ROR(x,n)    (SHR(x,n) | SHL(x,(32-n)))

#define S0(x)       (ROR(x, 2) ^ ROR(x,13) ^ ROR(x,22))
#define S1(x)       (ROR(x, 6) ^ ROR(x,11) ^ ROR(x,25))
#define S2(x)       (ROR(x, 7) ^ ROR(x,18) ^ SHR(x, 3))
#define S3(x)       (ROR(x,17) ^ ROR(x,19) ^ SHR(x,10))

#define F0(x,y,z)   S0(x) + (((x | y) & z) | (x & y))
#define F1(x,y,z)   S1(x) + (z ^ (x & (y ^ z)))

#define TF1(a,b,c,d,e,f,g,h,i,K) \
    h += F1(e,f,g) + K + W[i]; d += h; h += F0(a,b,c);

#define TF2(a,b,c,d,e,f,g,h,i,K) \
    W[i&15] += S3(W[(i-2)&15]) + W[(i-7)&15] + S2(W[(i-15)&15]); \
    h += F1(e,f,g) + K + W[i&15]; d += h; h += F0(a,b,c);

#ifdef LITTLE_ENDIAN
/* change endianness of data */
static void U32Copy( U8 *out, U8 *in, int count )
{
    while (count > 0)
    {
        out[0] = in[3];
        out[1] = in[2];
        out[2] = in[1];
        out[3] = in[0];
        in += 4;
        out += 4;
        count -= 4;
    }
}
#else
#define U32Copy memcpy
#endif /* LITTLE_ENDIAN */

void SHA256_Init( SHA256_CTX *ctx )
{
    ctx->Digest[0] = 0x6A09E667L;
    ctx->Digest[1] = 0xBB67AE85L;
    ctx->Digest[2] = 0x3C6EF372L;
    ctx->Digest[3] = 0xA54FF53AL;
    ctx->Digest[4] = 0x510E527FL;
    ctx->Digest[5] = 0x9B05688CL;
    ctx->Digest[6] = 0x1F83D9ABL;
    ctx->Digest[7] = 0x5BE0CD19L;

    ctx->BufferLength = 0;
    ctx->MsgLength = 0;
}

static void SHA256_Transform( SHA256_CTX *ctx, U32 *W )
{
    U32 a,b,c,d,e,f,g,h;

    a = ctx->Digest[0];
    b = ctx->Digest[1];
    c = ctx->Digest[2];
    d = ctx->Digest[3];
    e = ctx->Digest[4];
    f = ctx->Digest[5];
    g = ctx->Digest[6];
    h = ctx->Digest[7];

    TF1(a,b,c,d,e,f,g,h, 0,0x428a2f98); TF1(h,a,b,c,d,e,f,g, 1,0x71374491);
    TF1(g,h,a,b,c,d,e,f, 2,0xb5c0fbcf); TF1(f,g,h,a,b,c,d,e, 3,0xe9b5dba5);
    TF1(e,f,g,h,a,b,c,d, 4,0x3956c25b); TF1(d,e,f,g,h,a,b,c, 5,0x59f111f1);
    TF1(c,d,e,f,g,h,a,b, 6,0x923f82a4); TF1(b,c,d,e,f,g,h,a, 7,0xab1c5ed5);
    TF1(a,b,c,d,e,f,g,h, 8,0xd807aa98); TF1(h,a,b,c,d,e,f,g, 9,0x12835b01);
    TF1(g,h,a,b,c,d,e,f,10,0x243185be); TF1(f,g,h,a,b,c,d,e,11,0x550c7dc3);
    TF1(e,f,g,h,a,b,c,d,12,0x72be5d74); TF1(d,e,f,g,h,a,b,c,13,0x80deb1fe);
    TF1(c,d,e,f,g,h,a,b,14,0x9bdc06a7); TF1(b,c,d,e,f,g,h,a,15,0xc19bf174);
    TF2(a,b,c,d,e,f,g,h,16,0xe49b69c1); TF2(h,a,b,c,d,e,f,g,17,0xefbe4786);
    TF2(g,h,a,b,c,d,e,f,18,0x0fc19dc6); TF2(f,g,h,a,b,c,d,e,19,0x240ca1cc);
    TF2(e,f,g,h,a,b,c,d,20,0x2de92c6f); TF2(d,e,f,g,h,a,b,c,21,0x4a7484aa);
    TF2(c,d,e,f,g,h,a,b,22,0x5cb0a9dc); TF2(b,c,d,e,f,g,h,a,23,0x76f988da);
    TF2(a,b,c,d,e,f,g,h,24,0x983e5152); TF2(h,a,b,c,d,e,f,g,25,0xa831c66d);
    TF2(g,h,a,b,c,d,e,f,26,0xb00327c8); TF2(f,g,h,a,b,c,d,e,27,0xbf597fc7);
    TF2(e,f,g,h,a,b,c,d,28,0xc6e00bf3); TF2(d,e,f,g,h,a,b,c,29,0xd5a79147);
    TF2(c,d,e,f,g,h,a,b,30,0x06ca6351); TF2(b,c,d,e,f,g,h,a,31,0x14292967);
    TF2(a,b,c,d,e,f,g,h,32,0x27b70a85); TF2(h,a,b,c,d,e,f,g,33,0x2e1b2138);
    TF2(g,h,a,b,c,d,e,f,34,0x4d2c6dfc); TF2(f,g,h,a,b,c,d,e,35,0x53380d13);
    TF2(e,f,g,h,a,b,c,d,36,0x650a7354); TF2(d,e,f,g,h,a,b,c,37,0x766a0abb);
    TF2(c,d,e,f,g,h,a,b,38,0x81c2c92e); TF2(b,c,d,e,f,g,h,a,39,0x92722c85);
    TF2(a,b,c,d,e,f,g,h,40,0xa2bfe8a1); TF2(h,a,b,c,d,e,f,g,41,0xa81a664b);
    TF2(g,h,a,b,c,d,e,f,42,0xc24b8b70); TF2(f,g,h,a,b,c,d,e,43,0xc76c51a3);
    TF2(e,f,g,h,a,b,c,d,44,0xd192e819); TF2(d,e,f,g,h,a,b,c,45,0xd6990624);
    TF2(c,d,e,f,g,h,a,b,46,0xf40e3585); TF2(b,c,d,e,f,g,h,a,47,0x106aa070);
    TF2(a,b,c,d,e,f,g,h,48,0x19a4c116); TF2(h,a,b,c,d,e,f,g,49,0x1e376c08);
    TF2(g,h,a,b,c,d,e,f,50,0x2748774c); TF2(f,g,h,a,b,c,d,e,51,0x34b0bcb5);
    TF2(e,f,g,h,a,b,c,d,52,0x391c0cb3); TF2(d,e,f,g,h,a,b,c,53,0x4ed8aa4a);
    TF2(c,d,e,f,g,h,a,b,54,0x5b9cca4f); TF2(b,c,d,e,f,g,h,a,55,0x682e6ff3);
    TF2(a,b,c,d,e,f,g,h,56,0x748f82ee); TF2(h,a,b,c,d,e,f,g,57,0x78a5636f);
    TF2(g,h,a,b,c,d,e,f,58,0x84c87814); TF2(f,g,h,a,b,c,d,e,59,0x8cc70208);
    TF2(e,f,g,h,a,b,c,d,60,0x90befffa); TF2(d,e,f,g,h,a,b,c,61,0xa4506ceb);
    TF2(c,d,e,f,g,h,a,b,62,0xbef9a3f7); TF2(b,c,d,e,f,g,h,a,63,0xc67178f2);
     
    ctx->Digest[0] += a;
    ctx->Digest[1] += b;
    ctx->Digest[2] += c;
    ctx->Digest[3] += d;
    ctx->Digest[4] += e;
    ctx->Digest[5] += f;
    ctx->Digest[6] += g;
    ctx->Digest[7] += h;
}

void SHA256_Update( SHA256_CTX *ctx, const void *data, SZ len )
{
    while( len ) 
    {
        SZ n = SHA256_BLOCK_SIZE - ctx->BufferLength;
        if( n > len ) n = len;

        memcpy( &ctx->Buffer[ctx->BufferLength], data, n );

        ctx->BufferLength += n;
        data = (U8*)data + n;
        len -= n;

        if( ctx->BufferLength == SHA256_BLOCK_SIZE ) 
        {
            U32 W[16];

            U32Copy( (U8*)&W[0], &ctx->Buffer[0], SHA256_BLOCK_SIZE );

            SHA256_Transform( ctx, W );
            ctx->MsgLength += SHA256_BLOCK_SIZE;
            ctx->BufferLength = 0;
        }
    }
}

U32 *SHA256_Final( SHA256_CTX *ctx, U8 *hash )
{
    U32 W[16];

    ctx->MsgLength += ctx->BufferLength;  /* before adding pads */

    ctx->Buffer[ctx->BufferLength++] = 0x80;  /* add 1 */

    /* pad with zeros */
    if( ctx->BufferLength > 56 ) 
    {
        memset( &ctx->Buffer[ctx->BufferLength], 0, SHA256_BLOCK_SIZE - ctx->BufferLength );
        U32Copy( (U8*)&W[0], &ctx->Buffer[0], SHA256_BLOCK_SIZE );

        SHA256_Transform( ctx, W );
        ctx->BufferLength = 0;
    }
    memset( &ctx->Buffer[ctx->BufferLength], 0, 56 - ctx->BufferLength );

    U32Copy( (U8*)&W[0], &ctx->Buffer[0], 56 );

    // Append size in bits
    W[14] = (U32)(ctx->MsgLength >> 29);
    W[15] = (U32)(ctx->MsgLength << 3);

    SHA256_Transform( ctx, W );

    if (hash)
        U32Copy( hash, (U8 *)&ctx->Digest[0], SHA256_DIGEST_SIZE );

    return &ctx->Digest[0];
}

void SHA256_Hash( const void *data, SZ len, U8 *hash, SZ hash_size )
{
    U8 digest[SHA256_DIGEST_SIZE];
    SHA256_CTX hash_ctx;
    SHA256_Init( &hash_ctx );
    SHA256_Update( &hash_ctx, data, len );
    SHA256_Final( &hash_ctx, digest );
    if( hash_size > SHA256_DIGEST_SIZE ) hash_size = SHA256_DIGEST_SIZE;
    memcpy( hash, digest, hash_size );
}

#ifdef DO_SELFTEST
/* == SelfTest ============================================================ */
static const U8 msg_abc[] = {0x61,0x62,0x63};   /* "abc" */

static const U8 sha256_abc_1[] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
};

static const U8 sha256_abc_2[] = {
    0x4f,0x8b,0x42,0xc2,0x2d,0xd3,0x72,0x9b,0x51,0x9b,0xa6,0xf6,0x8d,0x2d,0xa7,0xcc,
    0x5b,0x2d,0x60,0x6d,0x05,0xda,0xed,0x5a,0xd5,0x12,0x8c,0xc0,0x3e,0x6c,0x63,0x58
};

static const U8 sha256_abc_3[] = {
    0x06,0x3f,0x5e,0x0d,0xa9,0xdb,0xb0,0x39,0x03,0xb0,0xcd,0xf2,0xf8,0x50,0xb0,0x39,
    0xbd,0xfb,0x99,0x8c,0x47,0xaa,0xa0,0x90,0x03,0x19,0x51,0x74,0xb2,0x6e,0xcb,0x16
};

int SHA256_SelfTest( void )
{
    U8 digest[SHA256_DIGEST_SIZE];
    SHA256_CTX h;

    SHA256_Init( &h );
    SHA256_Update( &h, msg_abc, 3 );  // "abc"
    if (SHA256_Final( &h, digest )[0] != 0xba7816bf)
        return 0;
    if( memcmp(digest, sha256_abc_1, SHA256_DIGEST_SIZE) != 0 )
        return 0;

    SHA256_Init( &h );
    SHA256_Update( &h, sha256_abc_1, SHA256_DIGEST_SIZE );
    SHA256_Final( &h, digest );
    if( memcmp(digest, sha256_abc_2, SHA256_DIGEST_SIZE) != 0 )
        return 0;

    SHA256_Init( &h );
    SHA256_Update( &h, sha256_abc_1, 30 );
    SHA256_Update( &h, sha256_abc_2, 20 );
    SHA256_Update( &h, sha256_abc_1, 10 );
    SHA256_Update( &h, sha256_abc_2, 31 );
    SHA256_Update( &h, sha256_abc_1, 32 );
    if( SHA256_Final( &h, digest )[7] != 0xb26ecb16 )
        return 0;
    if( memcmp(digest, sha256_abc_3, SHA256_DIGEST_SIZE) != 0 )
        return 0;

    return 1;
}
#endif  // DO_SELFTEST
