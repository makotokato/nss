/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef USE_HW_SHA2

#if !(defined(__riscv_zvknha) || defined(__riscv_zvknhb)) || !defined(__riscv_zvkb)
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

#define ROUND(n, a, b, c, d)                              \
    {                                                     \
        t = __riscv_vadd_vv_u32m1(a, k##n, vl);           \
        w1 = __riscv_vsha2cl_vv_u32m1(w1, w0, t, vl);     \
        w0 = __riscv_vsha2ch_vv_u32m1(w0, w1, t, vl);     \
        if (n < 12) {                                     \
            t = __riscv_vmerge_vvm_u32m1(c, b, mask, vl); \
            a = __riscv_vsha2ms_vv_u32m1(a, t, d, vl);    \
        }                                                 \
    }

#define LOAD_K256()                                 \
    {                                               \
        k0 = __riscv_vle32_v_u32m1(K256, vl);       \
        k1 = __riscv_vle32_v_u32m1(K256 + 4, vl);   \
        k2 = __riscv_vle32_v_u32m1(K256 + 8, vl);   \
        k3 = __riscv_vle32_v_u32m1(K256 + 12, vl);  \
        k4 = __riscv_vle32_v_u32m1(K256 + 16, vl);  \
        k5 = __riscv_vle32_v_u32m1(K256 + 20, vl);  \
        k6 = __riscv_vle32_v_u32m1(K256 + 24, vl);  \
        k7 = __riscv_vle32_v_u32m1(K256 + 28, vl);  \
        k8 = __riscv_vle32_v_u32m1(K256 + 32, vl);  \
        k9 = __riscv_vle32_v_u32m1(K256 + 36, vl);  \
        k10 = __riscv_vle32_v_u32m1(K256 + 40, vl); \
        k11 = __riscv_vle32_v_u32m1(K256 + 44, vl); \
        k12 = __riscv_vle32_v_u32m1(K256 + 48, vl); \
        k13 = __riscv_vle32_v_u32m1(K256 + 52, vl); \
        k14 = __riscv_vle32_v_u32m1(K256 + 56, vl); \
        k15 = __riscv_vle32_v_u32m1(K256 + 60, vl); \
    }

void
SHA256_Compress_Native(SHA256Context *ctx)
{
    vuint32m1_t k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15;
    vuint32m1_t h0, h1, w0, w1;
    vuint32m1_t a, b, c, d;
    vuint32m1_t t;
    vuint8mf4_t index;
    vbool32_t mask;
    size_t vl = __riscv_vsetvl_e32m1(4);

    /* H0123:4567 -> H01256:H2367 */
    uint32_t maskValue = 0x00041014;
    __asm__("vsetivli zero, 1, e32, m1, ta, ma\n"
            "vmv.v.x %0, %1"
            : "=vr"(index)
            : "r"(maskValue));

    LOAD_K256()

    h0 = __riscv_vluxei8_v_u32m1(ctx->h, index, vl);
    h1 = __riscv_vluxei8_v_u32m1(ctx->h + 2, index, vl);

    a = __riscv_vrev8_v_u32m1(__riscv_vle32_v_u32m1(ctx->u.w, vl), vl);
    b = __riscv_vrev8_v_u32m1(__riscv_vle32_v_u32m1(ctx->u.w + 4, vl), vl);
    c = __riscv_vrev8_v_u32m1(__riscv_vle32_v_u32m1(ctx->u.w + 8, vl), vl);
    d = __riscv_vrev8_v_u32m1(__riscv_vle32_v_u32m1(ctx->u.w + 12, vl), vl);

    mask = __riscv_vreinterpret_v_u8m1_b32(__riscv_vmv_v_x_u8m1(1, 1));
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

    h0 = __riscv_vadd_vv_u32m1(h0, w0, vl);
    h1 = __riscv_vadd_vv_u32m1(h1, w1, vl);

    /* H0145:2367 -> H0123:4567 */
    __riscv_vsuxei8_v_u32m1(ctx->h, index, h0, vl);
    __riscv_vsuxei8_v_u32m1(ctx->h + 2, index, h1, vl);
}

void
SHA256_Update_Native(SHA256Context *ctx, const unsigned char *input,
                     unsigned int inputLen)
{
    vuint32m1_t k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15;
    vuint32m1_t h0, h1, w0, w1;
    vuint32m1_t a, b, c, d;
    vuint32m1_t t;
    vbool32_t mask;
    vuint8mf4_t index;
    size_t vl = __riscv_vsetvl_e32m1(4);
    unsigned int inBuf = ctx->sizeLo & 0x3f;

    if (!inputLen) {
        return;
    }

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

    /* H0123:4567 -> H0145:H2367 */
    uint32_t maskValue = 0x00041014;
    __asm__("vsetivli zero, 1, e32, m1, ta, ma\n"
            "vmv.v.x %0, %1"
            : "=vr"(index)
            : "r"(maskValue));

    LOAD_K256()

    h0 = __riscv_vluxei8_v_u32m1(ctx->h, index, vl);
    h1 = __riscv_vluxei8_v_u32m1(ctx->h + 2, index, vl);
    mask = __riscv_vreinterpret_v_u8m1_b32(__riscv_vmv_v_x_u8m1(1, 1));

    /* if enough data to fill one or more whole buffers, process them. */
    while (inputLen >= SHA256_BLOCK_LENGTH) {
        a = __riscv_vrev8_v_u32m1(__riscv_vle32_v_u32m1((const PRUint32 *)input, vl), vl);
        b = __riscv_vrev8_v_u32m1(__riscv_vle32_v_u32m1((const PRUint32 *)(input + 16), vl), vl);
        c = __riscv_vrev8_v_u32m1(__riscv_vle32_v_u32m1((const PRUint32 *)(input + 32), vl), vl);
        d = __riscv_vrev8_v_u32m1(__riscv_vle32_v_u32m1((const PRUint32 *)(input + 48), vl), vl);
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

        h0 = __riscv_vadd_vv_u32m1(h0, w0, vl);
        h1 = __riscv_vadd_vv_u32m1(h1, w1, vl);
    }

    /* H0145:2367 -> H0123:4567 */
    __riscv_vsuxei8_v_u32m1(ctx->h, index, h0, vl);
    __riscv_vsuxei8_v_u32m1(ctx->h + 2, index, h1, vl);

    /* if data left over, fill it into buffer */
    if (inputLen) {
        memcpy(ctx->u.b, input, inputLen);
    }
}

#endif /* USE_HW_SHA2 */
