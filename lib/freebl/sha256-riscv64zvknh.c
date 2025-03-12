/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef USE_HW_SHA2

#if !defined(__riscv_zvknha) || !defined(__riscv_zvkb)
#error "Compiler option is invalid"
#endif

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

#include "prcpucfg.h"
#include "prtypes.h" /* for PRUintXX */
#include "prlong.h"
#include "blapi.h"
#include "sha256.h"

#include <riscv_vector.h>

vuint32m1_t vsha2cl_vv(vuint32m1_t vd, vuint32m1_t vs2, vuint32m1_t vs1) {
    __asm__("vsha2cl.vv %0, %1, %2" : "+vr"(vd) : "vr"(vs2), "vr"(vs1));
    return vd;
}

vuint32m1_t vsha2ch_vv(vuint32m1_t vd, vuint32m1_t vs2, vuint32m1_t vs1) {
    __asm__("vsha2ch.vv %0, %1, %2" : "+vr"(vd) : "vr"(vs2), "vr"(vs1));
    return vd;
}

vuint32m1_t vsha2ms_vv_u32m1(vuint32m1_t vd, vuint32m1_t vs2, vuint32m1_t vs1) {
    __asm__("vsha2ms.vv %0, %1, %2" : "+vr"(vd) : "vr"(vs2), "vr"(vs1));
    return vd;
}

vuint32m1_t vrev8_v_u32m1(vuint32m1_t vs2) {
    vuint32m1_t vd;
    __asm__("vrev8.v %0, %1" : "=vr"(vd) : "vr"(vs2));
    return vd;
}

/* SHA-256 constants, K256. */
static const PRUint32 __attribute__((aligned(16))) K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROUND(n, a, b, c, d)                                  \
    {                                                         \
        t = __riscv_vadd_vv_u32m1(a, k##n, 4);                \
        w1 = vsha2cl_vv(w1, w0, t);                           \
        w0 = vsha2ch_vv(w0, w1, t);                           \
        if (n < 12) {                                         \
            t = __riscv_vmerge_vvm_u32m1(c, b, roundMask, 4); \
            a = vsha2ms_vv_u32m1(a, t, d);                    \
        }                                                     \
    }

static const PRUint8 HASH_MASK[4] = { 0x14, 0x10, 0x04, 0x00 };

void
SHA256_Compress_Native(SHA256Context *ctx)
{
    vuint32m1_t k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15;
    vuint32m1_t h0, h1, w0, w1;
    vuint32m1_t a, b, c, d;
    vuint32m1_t t;
    vuint8mf4_t hashMask;
    vbool32_t roundMask;

    k0 = __riscv_vle32_v_u32m1(K256, 4);
    k1 = __riscv_vle32_v_u32m1(K256 + 4, 4);
    k2 = __riscv_vle32_v_u32m1(K256 + 8, 4);
    k3 = __riscv_vle32_v_u32m1(K256 + 12, 4);
    k4 = __riscv_vle32_v_u32m1(K256 + 16, 4);
    k5 = __riscv_vle32_v_u32m1(K256 + 20, 4);
    k6 = __riscv_vle32_v_u32m1(K256 + 24, 4);
    k7 = __riscv_vle32_v_u32m1(K256 + 28, 4);
    k8 = __riscv_vle32_v_u32m1(K256 + 32, 4);
    k9 = __riscv_vle32_v_u32m1(K256 + 36, 4);
    k10 = __riscv_vle32_v_u32m1(K256 + 40, 4);
    k11 = __riscv_vle32_v_u32m1(K256 + 44, 4);
    k12 = __riscv_vle32_v_u32m1(K256 + 48, 4);
    k13 = __riscv_vle32_v_u32m1(K256 + 52, 4);
    k14 = __riscv_vle32_v_u32m1(K256 + 56, 4);
    k15 = __riscv_vle32_v_u32m1(K256 + 60, 4);
    roundMask = __riscv_vreinterpret_v_u8m1_b32(__riscv_vmv_v_x_u8m1(1, 1));

    /* H0123:4567 -> H01256:H2367 */
    // m = __riscv_vmv_v_x_u32mf2(0x41014, 1);
    // m = __riscv_vreinterpret_v_u32mf2_u8mf2(m);
    //
    hashMask = __riscv_vle8_v_u8mf4(HASH_MASK, 4);
    h0 = __riscv_vluxei8_v_u32m1(ctx->h, hashMask, 4);
    h1 = __riscv_vluxei8_v_u32m1(ctx->h + 4, hashMask, 4);

    PRUint32 *input = ctx->u.w;

    a = vrev8_v_u32m1(__riscv_vle32_v_u32m1(input, 4));
    b = vrev8_v_u32m1(__riscv_vle32_v_u32m1(input + 4, 4));
    c = vrev8_v_u32m1(__riscv_vle32_v_u32m1(input + 8, 4));
    d = vrev8_v_u32m1(__riscv_vle32_v_u32m1(input + 12, 4));

    w0 = h0;
    w1 = h1;

    ROUND(0, a, b, c, d)
    ROUND(1, b, c, d, a)
    ROUND(2, c, d, a, b)
    ROUND(3, d, a, b, c)
    ROUND(4, a, b, c, d)
    ROUND(5, b, c, d, a)
    ROUND(6, c, d, a, b)
    ROUND(7, d, a, b, c)
    ROUND(8, a, b, c, d)
    ROUND(9, b, c, d, a)
    ROUND(10, c, d, a, b)
    ROUND(11, d, a, b, c)
    ROUND(12, a, b, c, d)
    ROUND(13, b, c, d, a)
    ROUND(14, c, d, a, b)
    ROUND(15, d, a, b, c)

    h0 = __riscv_vadd_vv_u32m1(h0, w0, 4);
    h1 = __riscv_vadd_vv_u32m1(h1, w1, 4);

    /* H0145:2367 -> H0123:4567 */
    __riscv_vsuxei8_v_u32m1(ctx->h, hashMask, h0, 4);
    __riscv_vsuxei8_v_u32m1(ctx->h + 4, hashMask, h1, 4);
}

void
SHA256_Update_Native(SHA256Context *ctx, const unsigned char *input,
                     unsigned int inputLen)
{
    vuint32m1_t k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15;
    vuint32m1_t h0, h1, w0, w1;
    vuint32m1_t a, b, c, d;
    vuint32m1_t t;
    vbool32_t roundMask;
    vuint8mf4_t hashMask;

    if (!inputLen) {
        return;
    }

    k0 = __riscv_vle32_v_u32m1(K256, 4);
    k1 = __riscv_vle32_v_u32m1(K256 + 4, 4);
    k2 = __riscv_vle32_v_u32m1(K256 + 8, 4);
    k3 = __riscv_vle32_v_u32m1(K256 + 12, 4);
    k4 = __riscv_vle32_v_u32m1(K256 + 16, 4);
    k5 = __riscv_vle32_v_u32m1(K256 + 20, 4);
    k6 = __riscv_vle32_v_u32m1(K256 + 24, 4);
    k7 = __riscv_vle32_v_u32m1(K256 + 28, 4);
    k8 = __riscv_vle32_v_u32m1(K256 + 32, 4);
    k9 = __riscv_vle32_v_u32m1(K256 + 36, 4);
    k10 = __riscv_vle32_v_u32m1(K256 + 40, 4);
    k11 = __riscv_vle32_v_u32m1(K256 + 44, 4);
    k12 = __riscv_vle32_v_u32m1(K256 + 48, 4);
    k13 = __riscv_vle32_v_u32m1(K256 + 52, 4);
    k14 = __riscv_vle32_v_u32m1(K256 + 56, 4);
    k15 = __riscv_vle32_v_u32m1(K256 + 60, 4);
    roundMask = __riscv_vreinterpret_v_u32m1_b32(__riscv_vmv_v_x_u32m1(1, 1));

    unsigned int inBuf = ctx->sizeLo & 0x3f;

    /* Add inputLen into the count of bytes processed, before processing */
    if ((ctx->sizeLo += inputLen) < inputLen) {
        ctx->sizeHi++;
    }

    /* if data already in buffer, attemp to fill rest of buffer */
    if (inBuf) {
        unsigned int todo = SHA256_BLOCK_LENGTH - inBuf;
        if (inputLen < todo) {
            todo = inputLen;
        }
        memcpy(ctx->u.b + inBuf, input, todo);
        input += todo;
        inputLen -= todo;
        if (inBuf + todo == SHA256_BLOCK_LENGTH) {
            SHA256_Compress_Native(ctx);
        }
    }

    /* H0123:4567 -> H01256:H2367 */
    hashMask = __riscv_vle8_v_u8mf4(HASH_MASK, 4);
    h0 = __riscv_vluxei8_v_u32m1(ctx->h, hashMask, 4);
    h1 = __riscv_vluxei8_v_u32m1(ctx->h + 4, hashMask, 4);

    /* if enough data to fill one or more whole buffers, process them. */
    while (inputLen >= SHA256_BLOCK_LENGTH) {
        a = vrev8_v_u32m1(__riscv_vle32_v_u32m1((const PRUint32*)input, 4));
        b = vrev8_v_u32m1(__riscv_vle32_v_u32m1((const PRUint32*)(input + 4), 4));
        c = vrev8_v_u32m1(__riscv_vle32_v_u32m1((const PRUint32*)(input + 8), 4));
        d = vrev8_v_u32m1(__riscv_vle32_v_u32m1((const PRUint32*)(input + 12), 4));
        input += SHA256_BLOCK_LENGTH;
        inputLen -= SHA256_BLOCK_LENGTH;

        w0 = h0;
        w1 = h1;

        ROUND(0, a, b, c, d)
        ROUND(1, b, c, d, a)
        ROUND(2, c, d, a, b)
        ROUND(3, d, a, b, c)
        ROUND(4, a, b, c, d)
        ROUND(5, b, c, d, a)
        ROUND(6, c, d, a, b)
        ROUND(7, d, a, b, c)
        ROUND(8, a, b, c, d)
        ROUND(9, b, c, d, a)
        ROUND(10, c, d, a, b)
        ROUND(11, d, a, b, c)
        ROUND(12, a, b, c, d)
        ROUND(13, b, c, d, a)
        ROUND(14, c, d, a, b)
        ROUND(15, d, a, b, c)

        h0 = __riscv_vadd_vv_u32m1(h0, w0, 4);
        h1 = __riscv_vadd_vv_u32m1(h1, w1, 4);
    }

    /* H0145:2367 -> H0123:4567 */
    __riscv_vsuxei8_v_u32m1(ctx->h, hashMask, h0, 4);
    __riscv_vsuxei8_v_u32m1(ctx->h + 4, hashMask, h1, 4);

    /* if data left over, fill it into buffer */
    if (inputLen) {
        memcpy(ctx->u.b, input, inputLen);
    }
}

#endif /* USE_HW_SHA2 */
