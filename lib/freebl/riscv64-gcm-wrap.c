/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* RISC-V 64 platform AES-GCM using the vector crypto extensions.
 *
 * Full blocks are processed by a fused AES-CTR (Zvkned) + GHASH (Zvkg) loop.
 * AAD hashing, J0 derivation when ivLen != 12, partial blocks and the length
 * block are delegated to the freebl gcmHashContext, which on RISC-V uses
 * ghash-riscv64zvkg.c. That implementation keeps X and H in GCM byte order,
 * which is also what vghsh.vv consumes, so no conversion is needed.
 */

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

#include "blapii.h"
#include "blapit.h"
#include "gcm.h"
#include "platform-gcm.h"
#include "secerr.h"
#include "prtypes.h"
#include "pkcs11t.h"

#include <limits.h>
#include <string.h>

#include "rijndael.h"

#if !defined(__riscv_zvkned) || !defined(__riscv_zvkg) || !defined(__riscv_zvkb)
#error "Compiler option is invalid"
#endif

#include <riscv_vector.h>

struct platform_AES_GCMContextStr {
    gcmHashContext *ghash_context;
    /* E(K, J0), XORed into the GHASH output to form the tag. */
    unsigned char tagKey[AES_BLOCK_SIZE];
    /* Next AES-CTR counter block. */
    unsigned char CTR[AES_BLOCK_SIZE];
    AESContext *aes_context;
    unsigned long tagBits;
    freeblCipherFunc cipher;
    PRBool ctr_context_init;
    gcmIVContext gcm_iv;
};

/* inlen is at most 2^32 - 1 bytes, below the GCM limit of 2^39 - 256 bits. */
PR_STATIC_ASSERT(sizeof(unsigned int) <= 4);

static void
aes_encrypt_block(const AESContext *aes, unsigned char out[AES_BLOCK_SIZE],
                  const unsigned char in[AES_BLOCK_SIZE])
{
    const PRUint32 *rk = aes->k.expandedKey;
    unsigned int nr = aes->Nr;
    unsigned int r;
    vuint32m1_t state;

    state = __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(in, 16));
    state = __riscv_vxor_vv_u32m1(state, __riscv_vle32_v_u32m1(rk, 4), 4);
    for (r = 1; r < nr; r++) {
        state = __riscv_vaesem_vv_u32m1(
            state, __riscv_vle32_v_u32m1(rk + 4 * r, 4), 4);
    }
    state = __riscv_vaesef_vv_u32m1(
        state, __riscv_vle32_v_u32m1(rk + 4 * nr, 4), 4);
    __riscv_vse8_v_u8m1(out, __riscv_vreinterpret_v_u32m1_u8m1(state), 16);
}

/* Added to the byte-reversed counter block to increment its last 32 bits. */
static const PRUint32 ctr_inc_one[4] = { 0, 0, 0, 1 };

static inline void
ctr_inc(unsigned char CTR[AES_BLOCK_SIZE])
{
    vuint32m1_t ctr = __riscv_vrev8_v_u32m1(
        __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(CTR, 16)), 4);
    ctr = __riscv_vadd_vv_u32m1(ctr, __riscv_vle32_v_u32m1(ctr_inc_one, 4), 4);
    __riscv_vse8_v_u8m1(
        CTR, __riscv_vreinterpret_v_u32m1_u8m1(__riscv_vrev8_v_u32m1(ctr, 4)),
        16);
}

/* AES-CTR + GHASH over nblocks full blocks. Advances gcm->CTR and the running
 * hash in gcm->ghash_context, but not its length counter. */
static void
gcm_ctr_ghash_encrypt_128(platform_AES_GCMContext *gcm, unsigned char *out,
                          const unsigned char *in, unsigned int nblocks)
{
    gcmHashContext *ghash = gcm->ghash_context;
    const PRUint32 *rk = gcm->aes_context->k.expandedKey;
    unsigned int i;
    vuint32m1_t h = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->h, 16));
    vuint32m1_t y = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->x, 16));
    vuint32m1_t ctr = __riscv_vrev8_v_u32m1(
        __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(gcm->CTR, 16)), 4);
    vuint32m1_t inc = __riscv_vle32_v_u32m1(ctr_inc_one, 4);
    vuint32m1_t k1 = __riscv_vle32_v_u32m1(rk, 4);
    vuint32m1_t k2 = __riscv_vle32_v_u32m1(rk + 4, 4);
    vuint32m1_t k3 = __riscv_vle32_v_u32m1(rk + 8, 4);
    vuint32m1_t k4 = __riscv_vle32_v_u32m1(rk + 12, 4);
    vuint32m1_t k5 = __riscv_vle32_v_u32m1(rk + 16, 4);
    vuint32m1_t k6 = __riscv_vle32_v_u32m1(rk + 20, 4);
    vuint32m1_t k7 = __riscv_vle32_v_u32m1(rk + 24, 4);
    vuint32m1_t k8 = __riscv_vle32_v_u32m1(rk + 28, 4);
    vuint32m1_t k9 = __riscv_vle32_v_u32m1(rk + 32, 4);
    vuint32m1_t k10 = __riscv_vle32_v_u32m1(rk + 36, 4);
    vuint32m1_t k11 = __riscv_vle32_v_u32m1(rk + 40, 4);

    for (i = 0; i < nblocks; i++, in += 16, out += 16) {
        vuint32m1_t s, x;
        s = __riscv_vrev8_v_u32m1(ctr, 4);
        ctr = __riscv_vadd_vv_u32m1(ctr, inc, 4);
        s = __riscv_vxor_vv_u32m1(s, k1, 4);
        s = __riscv_vaesem_vv_u32m1(s, k2, 4);
        s = __riscv_vaesem_vv_u32m1(s, k3, 4);
        s = __riscv_vaesem_vv_u32m1(s, k4, 4);
        s = __riscv_vaesem_vv_u32m1(s, k5, 4);
        s = __riscv_vaesem_vv_u32m1(s, k6, 4);
        s = __riscv_vaesem_vv_u32m1(s, k7, 4);
        s = __riscv_vaesem_vv_u32m1(s, k8, 4);
        s = __riscv_vaesem_vv_u32m1(s, k9, 4);
        s = __riscv_vaesem_vv_u32m1(s, k10, 4);
        s = __riscv_vaesef_vv_u32m1(s, k11, 4);
        x = __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(in, 16));
        x = __riscv_vxor_vv_u32m1(x, s, 4);
        __riscv_vse8_v_u8m1(out, __riscv_vreinterpret_v_u32m1_u8m1(x), 16);
        y = __riscv_vghsh_vv_u32m1(y, h, x, 4);
    }

    __riscv_vse8_v_u8m1((uint8_t *)ghash->x,
                        __riscv_vreinterpret_v_u32m1_u8m1(y), 16);
    __riscv_vse8_v_u8m1(
        gcm->CTR,
        __riscv_vreinterpret_v_u32m1_u8m1(__riscv_vrev8_v_u32m1(ctr, 4)), 16);
}

static void
gcm_ctr_ghash_encrypt_192(platform_AES_GCMContext *gcm, unsigned char *out,
                          const unsigned char *in, unsigned int nblocks)
{
    gcmHashContext *ghash = gcm->ghash_context;
    const PRUint32 *rk = gcm->aes_context->k.expandedKey;
    unsigned int i;
    vuint32m1_t h = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->h, 16));
    vuint32m1_t y = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->x, 16));
    vuint32m1_t ctr = __riscv_vrev8_v_u32m1(
        __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(gcm->CTR, 16)), 4);
    vuint32m1_t inc = __riscv_vle32_v_u32m1(ctr_inc_one, 4);
    vuint32m1_t k1 = __riscv_vle32_v_u32m1(rk, 4);
    vuint32m1_t k2 = __riscv_vle32_v_u32m1(rk + 4, 4);
    vuint32m1_t k3 = __riscv_vle32_v_u32m1(rk + 8, 4);
    vuint32m1_t k4 = __riscv_vle32_v_u32m1(rk + 12, 4);
    vuint32m1_t k5 = __riscv_vle32_v_u32m1(rk + 16, 4);
    vuint32m1_t k6 = __riscv_vle32_v_u32m1(rk + 20, 4);
    vuint32m1_t k7 = __riscv_vle32_v_u32m1(rk + 24, 4);
    vuint32m1_t k8 = __riscv_vle32_v_u32m1(rk + 28, 4);
    vuint32m1_t k9 = __riscv_vle32_v_u32m1(rk + 32, 4);
    vuint32m1_t k10 = __riscv_vle32_v_u32m1(rk + 36, 4);
    vuint32m1_t k11 = __riscv_vle32_v_u32m1(rk + 40, 4);
    vuint32m1_t k12 = __riscv_vle32_v_u32m1(rk + 44, 4);
    vuint32m1_t k13 = __riscv_vle32_v_u32m1(rk + 48, 4);

    for (i = 0; i < nblocks; i++, in += 16, out += 16) {
        vuint32m1_t s, x;
        s = __riscv_vrev8_v_u32m1(ctr, 4);
        ctr = __riscv_vadd_vv_u32m1(ctr, inc, 4);
        s = __riscv_vxor_vv_u32m1(s, k1, 4);
        s = __riscv_vaesem_vv_u32m1(s, k2, 4);
        s = __riscv_vaesem_vv_u32m1(s, k3, 4);
        s = __riscv_vaesem_vv_u32m1(s, k4, 4);
        s = __riscv_vaesem_vv_u32m1(s, k5, 4);
        s = __riscv_vaesem_vv_u32m1(s, k6, 4);
        s = __riscv_vaesem_vv_u32m1(s, k7, 4);
        s = __riscv_vaesem_vv_u32m1(s, k8, 4);
        s = __riscv_vaesem_vv_u32m1(s, k9, 4);
        s = __riscv_vaesem_vv_u32m1(s, k10, 4);
        s = __riscv_vaesem_vv_u32m1(s, k11, 4);
        s = __riscv_vaesem_vv_u32m1(s, k12, 4);
        s = __riscv_vaesef_vv_u32m1(s, k13, 4);
        x = __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(in, 16));
        x = __riscv_vxor_vv_u32m1(x, s, 4);
        __riscv_vse8_v_u8m1(out, __riscv_vreinterpret_v_u32m1_u8m1(x), 16);
        y = __riscv_vghsh_vv_u32m1(y, h, x, 4);
    }

    __riscv_vse8_v_u8m1((uint8_t *)ghash->x,
                        __riscv_vreinterpret_v_u32m1_u8m1(y), 16);
    __riscv_vse8_v_u8m1(
        gcm->CTR,
        __riscv_vreinterpret_v_u32m1_u8m1(__riscv_vrev8_v_u32m1(ctr, 4)), 16);
}

static void
gcm_ctr_ghash_encrypt_256(platform_AES_GCMContext *gcm, unsigned char *out,
                          const unsigned char *in, unsigned int nblocks)
{
    gcmHashContext *ghash = gcm->ghash_context;
    const PRUint32 *rk = gcm->aes_context->k.expandedKey;
    unsigned int i;
    vuint32m1_t h = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->h, 16));
    vuint32m1_t y = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->x, 16));
    vuint32m1_t ctr = __riscv_vrev8_v_u32m1(
        __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(gcm->CTR, 16)), 4);
    vuint32m1_t inc = __riscv_vle32_v_u32m1(ctr_inc_one, 4);
    vuint32m1_t k1 = __riscv_vle32_v_u32m1(rk, 4);
    vuint32m1_t k2 = __riscv_vle32_v_u32m1(rk + 4, 4);
    vuint32m1_t k3 = __riscv_vle32_v_u32m1(rk + 8, 4);
    vuint32m1_t k4 = __riscv_vle32_v_u32m1(rk + 12, 4);
    vuint32m1_t k5 = __riscv_vle32_v_u32m1(rk + 16, 4);
    vuint32m1_t k6 = __riscv_vle32_v_u32m1(rk + 20, 4);
    vuint32m1_t k7 = __riscv_vle32_v_u32m1(rk + 24, 4);
    vuint32m1_t k8 = __riscv_vle32_v_u32m1(rk + 28, 4);
    vuint32m1_t k9 = __riscv_vle32_v_u32m1(rk + 32, 4);
    vuint32m1_t k10 = __riscv_vle32_v_u32m1(rk + 36, 4);
    vuint32m1_t k11 = __riscv_vle32_v_u32m1(rk + 40, 4);
    vuint32m1_t k12 = __riscv_vle32_v_u32m1(rk + 44, 4);
    vuint32m1_t k13 = __riscv_vle32_v_u32m1(rk + 48, 4);
    vuint32m1_t k14 = __riscv_vle32_v_u32m1(rk + 52, 4);
    vuint32m1_t k15 = __riscv_vle32_v_u32m1(rk + 56, 4);

    for (i = 0; i < nblocks; i++, in += 16, out += 16) {
        vuint32m1_t s, x;
        s = __riscv_vrev8_v_u32m1(ctr, 4);
        ctr = __riscv_vadd_vv_u32m1(ctr, inc, 4);
        s = __riscv_vxor_vv_u32m1(s, k1, 4);
        s = __riscv_vaesem_vv_u32m1(s, k2, 4);
        s = __riscv_vaesem_vv_u32m1(s, k3, 4);
        s = __riscv_vaesem_vv_u32m1(s, k4, 4);
        s = __riscv_vaesem_vv_u32m1(s, k5, 4);
        s = __riscv_vaesem_vv_u32m1(s, k6, 4);
        s = __riscv_vaesem_vv_u32m1(s, k7, 4);
        s = __riscv_vaesem_vv_u32m1(s, k8, 4);
        s = __riscv_vaesem_vv_u32m1(s, k9, 4);
        s = __riscv_vaesem_vv_u32m1(s, k10, 4);
        s = __riscv_vaesem_vv_u32m1(s, k11, 4);
        s = __riscv_vaesem_vv_u32m1(s, k12, 4);
        s = __riscv_vaesem_vv_u32m1(s, k13, 4);
        s = __riscv_vaesem_vv_u32m1(s, k14, 4);
        s = __riscv_vaesef_vv_u32m1(s, k15, 4);
        x = __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(in, 16));
        x = __riscv_vxor_vv_u32m1(x, s, 4);
        __riscv_vse8_v_u8m1(out, __riscv_vreinterpret_v_u32m1_u8m1(x), 16);
        y = __riscv_vghsh_vv_u32m1(y, h, x, 4);
    }

    __riscv_vse8_v_u8m1((uint8_t *)ghash->x,
                        __riscv_vreinterpret_v_u32m1_u8m1(y), 16);
    __riscv_vse8_v_u8m1(
        gcm->CTR,
        __riscv_vreinterpret_v_u32m1_u8m1(__riscv_vrev8_v_u32m1(ctr, 4)), 16);
}

static void
gcm_ctr_ghash_decrypt_128(platform_AES_GCMContext *gcm, unsigned char *out,
                          const unsigned char *in, unsigned int nblocks)
{
    gcmHashContext *ghash = gcm->ghash_context;
    const PRUint32 *rk = gcm->aes_context->k.expandedKey;
    unsigned int i;
    vuint32m1_t h = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->h, 16));
    vuint32m1_t y = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->x, 16));
    vuint32m1_t ctr = __riscv_vrev8_v_u32m1(
        __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(gcm->CTR, 16)), 4);
    vuint32m1_t inc = __riscv_vle32_v_u32m1(ctr_inc_one, 4);
    vuint32m1_t k1 = __riscv_vle32_v_u32m1(rk, 4);
    vuint32m1_t k2 = __riscv_vle32_v_u32m1(rk + 4, 4);
    vuint32m1_t k3 = __riscv_vle32_v_u32m1(rk + 8, 4);
    vuint32m1_t k4 = __riscv_vle32_v_u32m1(rk + 12, 4);
    vuint32m1_t k5 = __riscv_vle32_v_u32m1(rk + 16, 4);
    vuint32m1_t k6 = __riscv_vle32_v_u32m1(rk + 20, 4);
    vuint32m1_t k7 = __riscv_vle32_v_u32m1(rk + 24, 4);
    vuint32m1_t k8 = __riscv_vle32_v_u32m1(rk + 28, 4);
    vuint32m1_t k9 = __riscv_vle32_v_u32m1(rk + 32, 4);
    vuint32m1_t k10 = __riscv_vle32_v_u32m1(rk + 36, 4);
    vuint32m1_t k11 = __riscv_vle32_v_u32m1(rk + 40, 4);

    for (i = 0; i < nblocks; i++, in += 16, out += 16) {
        vuint32m1_t s, x;
        s = __riscv_vrev8_v_u32m1(ctr, 4);
        ctr = __riscv_vadd_vv_u32m1(ctr, inc, 4);
        s = __riscv_vxor_vv_u32m1(s, k1, 4);
        s = __riscv_vaesem_vv_u32m1(s, k2, 4);
        s = __riscv_vaesem_vv_u32m1(s, k3, 4);
        s = __riscv_vaesem_vv_u32m1(s, k4, 4);
        s = __riscv_vaesem_vv_u32m1(s, k5, 4);
        s = __riscv_vaesem_vv_u32m1(s, k6, 4);
        s = __riscv_vaesem_vv_u32m1(s, k7, 4);
        s = __riscv_vaesem_vv_u32m1(s, k8, 4);
        s = __riscv_vaesem_vv_u32m1(s, k9, 4);
        s = __riscv_vaesem_vv_u32m1(s, k10, 4);
        s = __riscv_vaesef_vv_u32m1(s, k11, 4);
        x = __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(in, 16));
        y = __riscv_vghsh_vv_u32m1(y, h, x, 4);
        x = __riscv_vxor_vv_u32m1(x, s, 4);
        __riscv_vse8_v_u8m1(out, __riscv_vreinterpret_v_u32m1_u8m1(x), 16);
    }

    __riscv_vse8_v_u8m1((uint8_t *)ghash->x,
                        __riscv_vreinterpret_v_u32m1_u8m1(y), 16);
    __riscv_vse8_v_u8m1(
        gcm->CTR,
        __riscv_vreinterpret_v_u32m1_u8m1(__riscv_vrev8_v_u32m1(ctr, 4)), 16);
}

static void
gcm_ctr_ghash_decrypt_192(platform_AES_GCMContext *gcm, unsigned char *out,
                          const unsigned char *in, unsigned int nblocks)
{
    gcmHashContext *ghash = gcm->ghash_context;
    const PRUint32 *rk = gcm->aes_context->k.expandedKey;
    unsigned int i;
    vuint32m1_t h = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->h, 16));
    vuint32m1_t y = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->x, 16));
    vuint32m1_t ctr = __riscv_vrev8_v_u32m1(
        __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(gcm->CTR, 16)), 4);
    vuint32m1_t inc = __riscv_vle32_v_u32m1(ctr_inc_one, 4);
    vuint32m1_t k1 = __riscv_vle32_v_u32m1(rk, 4);
    vuint32m1_t k2 = __riscv_vle32_v_u32m1(rk + 4, 4);
    vuint32m1_t k3 = __riscv_vle32_v_u32m1(rk + 8, 4);
    vuint32m1_t k4 = __riscv_vle32_v_u32m1(rk + 12, 4);
    vuint32m1_t k5 = __riscv_vle32_v_u32m1(rk + 16, 4);
    vuint32m1_t k6 = __riscv_vle32_v_u32m1(rk + 20, 4);
    vuint32m1_t k7 = __riscv_vle32_v_u32m1(rk + 24, 4);
    vuint32m1_t k8 = __riscv_vle32_v_u32m1(rk + 28, 4);
    vuint32m1_t k9 = __riscv_vle32_v_u32m1(rk + 32, 4);
    vuint32m1_t k10 = __riscv_vle32_v_u32m1(rk + 36, 4);
    vuint32m1_t k11 = __riscv_vle32_v_u32m1(rk + 40, 4);
    vuint32m1_t k12 = __riscv_vle32_v_u32m1(rk + 44, 4);
    vuint32m1_t k13 = __riscv_vle32_v_u32m1(rk + 48, 4);

    for (i = 0; i < nblocks; i++, in += 16, out += 16) {
        vuint32m1_t s, x;
        s = __riscv_vrev8_v_u32m1(ctr, 4);
        ctr = __riscv_vadd_vv_u32m1(ctr, inc, 4);
        s = __riscv_vxor_vv_u32m1(s, k1, 4);
        s = __riscv_vaesem_vv_u32m1(s, k2, 4);
        s = __riscv_vaesem_vv_u32m1(s, k3, 4);
        s = __riscv_vaesem_vv_u32m1(s, k4, 4);
        s = __riscv_vaesem_vv_u32m1(s, k5, 4);
        s = __riscv_vaesem_vv_u32m1(s, k6, 4);
        s = __riscv_vaesem_vv_u32m1(s, k7, 4);
        s = __riscv_vaesem_vv_u32m1(s, k8, 4);
        s = __riscv_vaesem_vv_u32m1(s, k9, 4);
        s = __riscv_vaesem_vv_u32m1(s, k10, 4);
        s = __riscv_vaesem_vv_u32m1(s, k11, 4);
        s = __riscv_vaesem_vv_u32m1(s, k12, 4);
        s = __riscv_vaesef_vv_u32m1(s, k13, 4);
        x = __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(in, 16));
        y = __riscv_vghsh_vv_u32m1(y, h, x, 4);
        x = __riscv_vxor_vv_u32m1(x, s, 4);
        __riscv_vse8_v_u8m1(out, __riscv_vreinterpret_v_u32m1_u8m1(x), 16);
    }

    __riscv_vse8_v_u8m1((uint8_t *)ghash->x,
                        __riscv_vreinterpret_v_u32m1_u8m1(y), 16);
    __riscv_vse8_v_u8m1(
        gcm->CTR,
        __riscv_vreinterpret_v_u32m1_u8m1(__riscv_vrev8_v_u32m1(ctr, 4)), 16);
}

static void
gcm_ctr_ghash_decrypt_256(platform_AES_GCMContext *gcm, unsigned char *out,
                          const unsigned char *in, unsigned int nblocks)
{
    gcmHashContext *ghash = gcm->ghash_context;
    const PRUint32 *rk = gcm->aes_context->k.expandedKey;
    unsigned int i;
    vuint32m1_t h = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->h, 16));
    vuint32m1_t y = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->x, 16));
    vuint32m1_t ctr = __riscv_vrev8_v_u32m1(
        __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(gcm->CTR, 16)), 4);
    vuint32m1_t inc = __riscv_vle32_v_u32m1(ctr_inc_one, 4);
    vuint32m1_t k1 = __riscv_vle32_v_u32m1(rk, 4);
    vuint32m1_t k2 = __riscv_vle32_v_u32m1(rk + 4, 4);
    vuint32m1_t k3 = __riscv_vle32_v_u32m1(rk + 8, 4);
    vuint32m1_t k4 = __riscv_vle32_v_u32m1(rk + 12, 4);
    vuint32m1_t k5 = __riscv_vle32_v_u32m1(rk + 16, 4);
    vuint32m1_t k6 = __riscv_vle32_v_u32m1(rk + 20, 4);
    vuint32m1_t k7 = __riscv_vle32_v_u32m1(rk + 24, 4);
    vuint32m1_t k8 = __riscv_vle32_v_u32m1(rk + 28, 4);
    vuint32m1_t k9 = __riscv_vle32_v_u32m1(rk + 32, 4);
    vuint32m1_t k10 = __riscv_vle32_v_u32m1(rk + 36, 4);
    vuint32m1_t k11 = __riscv_vle32_v_u32m1(rk + 40, 4);
    vuint32m1_t k12 = __riscv_vle32_v_u32m1(rk + 44, 4);
    vuint32m1_t k13 = __riscv_vle32_v_u32m1(rk + 48, 4);
    vuint32m1_t k14 = __riscv_vle32_v_u32m1(rk + 52, 4);
    vuint32m1_t k15 = __riscv_vle32_v_u32m1(rk + 56, 4);

    for (i = 0; i < nblocks; i++, in += 16, out += 16) {
        vuint32m1_t s, x;
        s = __riscv_vrev8_v_u32m1(ctr, 4);
        ctr = __riscv_vadd_vv_u32m1(ctr, inc, 4);
        s = __riscv_vxor_vv_u32m1(s, k1, 4);
        s = __riscv_vaesem_vv_u32m1(s, k2, 4);
        s = __riscv_vaesem_vv_u32m1(s, k3, 4);
        s = __riscv_vaesem_vv_u32m1(s, k4, 4);
        s = __riscv_vaesem_vv_u32m1(s, k5, 4);
        s = __riscv_vaesem_vv_u32m1(s, k6, 4);
        s = __riscv_vaesem_vv_u32m1(s, k7, 4);
        s = __riscv_vaesem_vv_u32m1(s, k8, 4);
        s = __riscv_vaesem_vv_u32m1(s, k9, 4);
        s = __riscv_vaesem_vv_u32m1(s, k10, 4);
        s = __riscv_vaesem_vv_u32m1(s, k11, 4);
        s = __riscv_vaesem_vv_u32m1(s, k12, 4);
        s = __riscv_vaesem_vv_u32m1(s, k13, 4);
        s = __riscv_vaesem_vv_u32m1(s, k14, 4);
        s = __riscv_vaesef_vv_u32m1(s, k15, 4);
        x = __riscv_vreinterpret_v_u8m1_u32m1(__riscv_vle8_v_u8m1(in, 16));
        y = __riscv_vghsh_vv_u32m1(y, h, x, 4);
        x = __riscv_vxor_vv_u32m1(x, s, 4);
        __riscv_vse8_v_u8m1(out, __riscv_vreinterpret_v_u32m1_u8m1(x), 16);
    }

    __riscv_vse8_v_u8m1((uint8_t *)ghash->x,
                        __riscv_vreinterpret_v_u32m1_u8m1(y), 16);
    __riscv_vse8_v_u8m1(
        gcm->CTR,
        __riscv_vreinterpret_v_u32m1_u8m1(__riscv_vrev8_v_u32m1(ctr, 4)), 16);
}

static inline unsigned int
gcm_tag_bytes(const platform_AES_GCMContext *gcm)
{
    return (unsigned int)((gcm->tagBits + (PR_BITS_PER_BYTE - 1)) / PR_BITS_PER_BYTE);
}

static void
ctr_xor_partial(platform_AES_GCMContext *gcm, unsigned char *outbuf,
                const unsigned char *inbuf, unsigned int remLen)
{
    unsigned char keystream[AES_BLOCK_SIZE];
    unsigned int j;

    aes_encrypt_block(gcm->aes_context, keystream, gcm->CTR);
    for (j = 0; j < remLen; j++) {
        outbuf[j] = inbuf[j] ^ keystream[j];
    }
    ctr_inc(gcm->CTR);
    PORT_SafeZero(keystream, AES_BLOCK_SIZE);
}

static SECStatus
encrypt_partial(platform_AES_GCMContext *gcm, unsigned char *outbuf,
                const unsigned char *inbuf, unsigned int remLen)
{
    ctr_xor_partial(gcm, outbuf, inbuf, remLen);
    return gcmHash_Update(gcm->ghash_context, outbuf, remLen);
}

static SECStatus
decrypt_partial(platform_AES_GCMContext *gcm, unsigned char *outbuf,
                const unsigned char *inbuf, unsigned int remLen)
{
    if (gcmHash_Update(gcm->ghash_context, inbuf, remLen) != SECSuccess) {
        return SECFailure;
    }
    ctr_xor_partial(gcm, outbuf, inbuf, remLen);
    return SECSuccess;
}

/* The platform update functions are one-shot and gcmHash_Reset leaves the
 * AAD fully absorbed, so the GHASH buffer is empty when the bulk loop runs. */
static SECStatus
check_bulk_state(const platform_AES_GCMContext *gcm)
{
    PORT_Assert(gcm->ghash_context->hw);
    PORT_Assert(gcm->ghash_context->bufLen == 0);
    if (!gcm->ghash_context->hw || gcm->ghash_context->bufLen != 0) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }
    return SECSuccess;
}

static SECStatus
process_payload_encrypt(platform_AES_GCMContext *gcm, unsigned char *outbuf,
                        const unsigned char *inbuf, unsigned int inlen)
{
    unsigned int nblocks = inlen / AES_BLOCK_SIZE;
    unsigned int fullLen = nblocks * AES_BLOCK_SIZE;

    if (nblocks > 0) {
        if (check_bulk_state(gcm) != SECSuccess) {
            return SECFailure;
        }
        switch (gcm->aes_context->Nr) {
            case 10:
                gcm_ctr_ghash_encrypt_128(gcm, outbuf, inbuf, nblocks);
                break;
            case 12:
                gcm_ctr_ghash_encrypt_192(gcm, outbuf, inbuf, nblocks);
                break;
            case 14:
                gcm_ctr_ghash_encrypt_256(gcm, outbuf, inbuf, nblocks);
                break;
            default:
                PORT_Assert(0);
                PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
                return SECFailure;
        }
        gcm->ghash_context->cLen += (uint64_t)fullLen * PR_BITS_PER_BYTE;
    }

    if (inlen > fullLen) {
        return encrypt_partial(gcm, outbuf + fullLen,
                               inbuf + fullLen, inlen - fullLen);
    }
    return SECSuccess;
}

static SECStatus
process_payload_decrypt(platform_AES_GCMContext *gcm, unsigned char *outbuf,
                        const unsigned char *inbuf, unsigned int inlen)
{
    unsigned int nblocks = inlen / AES_BLOCK_SIZE;
    unsigned int fullLen = nblocks * AES_BLOCK_SIZE;

    if (nblocks > 0) {
        if (check_bulk_state(gcm) != SECSuccess) {
            return SECFailure;
        }
        switch (gcm->aes_context->Nr) {
            case 10:
                gcm_ctr_ghash_decrypt_128(gcm, outbuf, inbuf, nblocks);
                break;
            case 12:
                gcm_ctr_ghash_decrypt_192(gcm, outbuf, inbuf, nblocks);
                break;
            case 14:
                gcm_ctr_ghash_decrypt_256(gcm, outbuf, inbuf, nblocks);
                break;
            default:
                PORT_Assert(0);
                PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
                return SECFailure;
        }
        gcm->ghash_context->cLen += (uint64_t)fullLen * PR_BITS_PER_BYTE;
    }

    if (inlen > fullLen) {
        return decrypt_partial(gcm, outbuf + fullLen,
                               inbuf + fullLen, inlen - fullLen);
    }
    return SECSuccess;
}

static SECStatus
compute_tag(platform_AES_GCMContext *gcm, unsigned char T[AES_BLOCK_SIZE])
{
    unsigned int outlen;

    if (gcmHash_Final(gcm->ghash_context, T, &outlen, AES_BLOCK_SIZE) !=
        SECSuccess) {
        return SECFailure;
    }
    __riscv_vse8_v_u8m1(T,
                        __riscv_vxor_vv_u8m1(__riscv_vle8_v_u8m1(T, 16),
                                             __riscv_vle8_v_u8m1(gcm->tagKey, 16),
                                             16),
                        16);
    return SECSuccess;
}

static SECStatus
emit_tag(platform_AES_GCMContext *gcm, unsigned char *tag_out)
{
    unsigned char T[AES_BLOCK_SIZE];
    SECStatus rv = compute_tag(gcm, T);

    if (rv == SECSuccess) {
        PORT_Memcpy(tag_out, T, gcm_tag_bytes(gcm));
    }
    PORT_SafeZero(T, AES_BLOCK_SIZE);
    return rv;
}

/* Compare the computed tag with intag in constant time. On failure the
 * plaintext in outbuf is wiped. */
static SECStatus
verify_tag(platform_AES_GCMContext *gcm, const unsigned char *intag,
           unsigned char *outbuf, unsigned int inlen, unsigned int *outlen)
{
    unsigned char T[AES_BLOCK_SIZE];
    SECStatus rv = compute_tag(gcm, T);

    if (rv == SECSuccess &&
        NSS_SecureMemcmp(T, intag, gcm_tag_bytes(gcm)) != 0) {
        PORT_SetError(SEC_ERROR_BAD_DATA);
        rv = SECFailure;
    }
    PORT_SafeZero(T, AES_BLOCK_SIZE);
    if (rv != SECSuccess) {
        PORT_SafeZero(outbuf, inlen);
        *outlen = 0;
        return SECFailure;
    }
    *outlen = inlen;
    return SECSuccess;
}

PRBool
platform_gcm_support(void)
{
    return rv_vaes_support() && rv_zvkg_support() && rv_zvkb_support();
}

SECStatus platform_aes_gcmInitCounter(platform_AES_GCMContext *gcm,
                                      const unsigned char *iv,
                                      unsigned long ivLen, unsigned long tagBits,
                                      const unsigned char *aad,
                                      unsigned long aadLen);

platform_AES_GCMContext *
platform_AES_GCM_CreateContext(void *context,
                               freeblCipherFunc cipher,
                               const unsigned char *params)
{
    platform_AES_GCMContext *gcm;
    AESContext *aes = (AESContext *)context;
    const CK_NSS_GCM_PARAMS *gcmParams = (const CK_NSS_GCM_PARAMS *)params;
    unsigned char H[AES_BLOCK_SIZE];
    SECStatus rv;

    gcm = PORT_ZNew(platform_AES_GCMContext);
    if (gcm == NULL) {
        return NULL;
    }

    gcm->aes_context = aes;
    gcm->cipher = cipher;
    gcm->ctr_context_init = PR_FALSE;

    gcm->ghash_context = PORT_ZNewAligned(gcmHashContext, 16, mem);
    if (gcm->ghash_context == NULL) {
        PORT_Free(gcm);
        return NULL;
    }

    /* H = E(K, 0^128) */
    PORT_Memset(H, 0, AES_BLOCK_SIZE);
    aes_encrypt_block(aes, H, H);
    rv = gcmHash_InitContext(gcm->ghash_context, H, PR_FALSE);
    PORT_SafeZero(H, AES_BLOCK_SIZE);
    if (rv != SECSuccess) {
        goto loser;
    }
    if (!gcm->ghash_context->hw) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        goto loser;
    }

    gcm_InitIVContext(&gcm->gcm_iv);

    /* A NULL params means the message (AEAD) interface will be used. */
    if (gcmParams == NULL) {
        return gcm;
    }

    rv = platform_aes_gcmInitCounter(gcm, gcmParams->pIv, gcmParams->ulIvLen,
                                     gcmParams->ulTagBits, gcmParams->pAAD,
                                     gcmParams->ulAADLen);
    if (rv != SECSuccess) {
        goto loser;
    }
    gcm->ctr_context_init = PR_TRUE;

    return gcm;

loser:
    platform_AES_GCM_DestroyContext(gcm, PR_TRUE);
    return NULL;
}

SECStatus
platform_aes_gcmInitCounter(platform_AES_GCMContext *gcm,
                            const unsigned char *iv, unsigned long ivLen,
                            unsigned long tagBits,
                            const unsigned char *aad, unsigned long aadLen)
{
    unsigned int outlen;
    SECStatus rv;

    if (ivLen == 0 || ivLen > UINT_MAX || aadLen > UINT_MAX) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    if (tagBits != 128 && tagBits != 120 && tagBits != 112 &&
        tagBits != 104 && tagBits != 96 && tagBits != 64 &&
        tagBits != 32) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    gcm->tagBits = tagBits;

    if (ivLen == 12) {
        PORT_Memcpy(gcm->CTR, iv, 12);
        PORT_Memset(gcm->CTR + 12, 0, 4);
        ctr_inc(gcm->CTR);
    } else {
        /* J0 = GHASH(IV || pad || len(IV)) */
        rv = gcmHash_Reset(gcm->ghash_context, NULL, 0);
        if (rv != SECSuccess) {
            return SECFailure;
        }
        rv = gcmHash_Update(gcm->ghash_context, iv, (unsigned int)ivLen);
        if (rv != SECSuccess) {
            return SECFailure;
        }
        rv = gcmHash_Final(gcm->ghash_context, gcm->CTR, &outlen,
                           AES_BLOCK_SIZE);
        if (rv != SECSuccess) {
            return SECFailure;
        }
    }

    aes_encrypt_block(gcm->aes_context, gcm->tagKey, gcm->CTR);
    ctr_inc(gcm->CTR);

    return gcmHash_Reset(gcm->ghash_context, aad, (unsigned int)aadLen);
}

void
platform_AES_GCM_DestroyContext(platform_AES_GCMContext *gcm, PRBool freeit)
{
    if (gcm->ghash_context) {
        void *mem = gcm->ghash_context->mem;
        PORT_SafeZero(gcm->ghash_context, sizeof(gcmHashContext));
        PORT_Free(mem);
    }
    PORT_SafeZero(gcm, sizeof(platform_AES_GCMContext));
    if (freeit) {
        PORT_Free(gcm);
    }
}

SECStatus
platform_AES_GCM_EncryptUpdate(platform_AES_GCMContext *gcm,
                               unsigned char *outbuf,
                               unsigned int *outlen, unsigned int maxout,
                               const unsigned char *inbuf, unsigned int inlen,
                               unsigned int blocksize)
{
    unsigned int tagBytes;

    if (!gcm->ctr_context_init) {
        PORT_SetError(SEC_ERROR_NOT_INITIALIZED);
        return SECFailure;
    }

    tagBytes = gcm_tag_bytes(gcm);
    if (UINT_MAX - inlen < tagBytes) {
        PORT_SetError(SEC_ERROR_INPUT_LEN);
        return SECFailure;
    }
    if (maxout < inlen + tagBytes) {
        *outlen = inlen + tagBytes;
        PORT_SetError(SEC_ERROR_OUTPUT_LEN);
        return SECFailure;
    }

    if (process_payload_encrypt(gcm, outbuf, inbuf, inlen) !=
        SECSuccess) {
        return SECFailure;
    }
    if (emit_tag(gcm, outbuf + inlen) != SECSuccess) {
        return SECFailure;
    }
    *outlen = inlen + tagBytes;
    return SECSuccess;
}

SECStatus
platform_AES_GCM_DecryptUpdate(platform_AES_GCMContext *gcm,
                               unsigned char *outbuf,
                               unsigned int *outlen, unsigned int maxout,
                               const unsigned char *inbuf, unsigned int inlen,
                               unsigned int blocksize)
{
    unsigned int tagBytes;
    const unsigned char *intag;

    if (!gcm->ctr_context_init) {
        PORT_SetError(SEC_ERROR_NOT_INITIALIZED);
        return SECFailure;
    }

    tagBytes = gcm_tag_bytes(gcm);
    if (inlen < tagBytes) {
        PORT_SetError(SEC_ERROR_INPUT_LEN);
        return SECFailure;
    }
    inlen -= tagBytes;
    intag = inbuf + inlen;

    if (maxout < inlen) {
        *outlen = inlen;
        PORT_SetError(SEC_ERROR_OUTPUT_LEN);
        return SECFailure;
    }

    if (process_payload_decrypt(gcm, outbuf, inbuf, inlen) !=
        SECSuccess) {
        PORT_SafeZero(outbuf, inlen);
        *outlen = 0;
        return SECFailure;
    }

    return verify_tag(gcm, intag, outbuf, inlen, outlen);
}

static SECStatus
aead_check_params(const platform_AES_GCMContext *gcm, unsigned int paramLen,
                  unsigned int maxout, unsigned int inlen,
                  unsigned int *outlen)
{
    if (paramLen != sizeof(CK_GCM_MESSAGE_PARAMS)) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    if (gcm->ctr_context_init) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }
    if (maxout < inlen) {
        *outlen = inlen;
        PORT_SetError(SEC_ERROR_OUTPUT_LEN);
        return SECFailure;
    }
    return SECSuccess;
}

SECStatus
platform_AES_GCM_EncryptAEAD(platform_AES_GCMContext *gcm,
                             unsigned char *outbuf,
                             unsigned int *outlen, unsigned int maxout,
                             const unsigned char *inbuf, unsigned int inlen,
                             void *params, unsigned int paramLen,
                             const unsigned char *aad, unsigned int aadLen,
                             unsigned int blocksize)
{
    const CK_GCM_MESSAGE_PARAMS *gcmParams =
        (const CK_GCM_MESSAGE_PARAMS *)params;

    if (aead_check_params(gcm, paramLen, maxout, inlen, outlen) !=
        SECSuccess) {
        return SECFailure;
    }
    if (gcm_GenerateIV(&gcm->gcm_iv, gcmParams->pIv,
                       (unsigned int)gcmParams->ulIvLen,
                       (unsigned int)gcmParams->ulIvFixedBits,
                       gcmParams->ivGenerator) != SECSuccess) {
        return SECFailure;
    }
    if (platform_aes_gcmInitCounter(gcm, gcmParams->pIv, gcmParams->ulIvLen,
                                    gcmParams->ulTagBits, aad,
                                    aadLen) != SECSuccess) {
        return SECFailure;
    }
    if (process_payload_encrypt(gcm, outbuf, inbuf, inlen) !=
        SECSuccess) {
        return SECFailure;
    }
    if (emit_tag(gcm, gcmParams->pTag) != SECSuccess) {
        return SECFailure;
    }
    *outlen = inlen;
    return SECSuccess;
}

SECStatus
platform_AES_GCM_DecryptAEAD(platform_AES_GCMContext *gcm,
                             unsigned char *outbuf,
                             unsigned int *outlen, unsigned int maxout,
                             const unsigned char *inbuf, unsigned int inlen,
                             void *params, unsigned int paramLen,
                             const unsigned char *aad, unsigned int aadLen,
                             unsigned int blocksize)
{
    const CK_GCM_MESSAGE_PARAMS *gcmParams =
        (const CK_GCM_MESSAGE_PARAMS *)params;

    if (aead_check_params(gcm, paramLen, maxout, inlen, outlen) !=
        SECSuccess) {
        return SECFailure;
    }
    if (platform_aes_gcmInitCounter(gcm, gcmParams->pIv, gcmParams->ulIvLen,
                                    gcmParams->ulTagBits, aad,
                                    aadLen) != SECSuccess) {
        return SECFailure;
    }
    if (process_payload_decrypt(gcm, outbuf, inbuf, inlen) !=
        SECSuccess) {
        PORT_SafeZero(outbuf, inlen);
        *outlen = 0;
        return SECFailure;
    }

    return verify_tag(gcm, gcmParams->pTag, outbuf, inlen, outlen);
}
