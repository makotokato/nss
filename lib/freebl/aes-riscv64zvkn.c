/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "secerr.h"
#include "rijndael.h"

#include <riscv_vector.h>

static vuint32m1_t
vaesz_vs(vuint32m1_t rd, vuint32m1_t vs2)
{
    __asm__("vaesz.vs %0, %1" : "+vr"(rd) : "vr"(vs2));
    return rd;
}

static vuint32m1_t
vaesem_vs(vuint32m1_t rd, vuint32m1_t vs2)
{
    __asm__("vaesem.vs %0, %1" : "+vr"(rd) : "vr"(vs2));
    return rd;
}

static vuint32m1_t
vaesef_vs(vuint32m1_t rd, vuint32m1_t vs2)
{
    __asm__("vaesef.vs %0, %1" : "+vr"(rd) : "vr"(vs2));
    return rd;
}

static vuint32m1_t
vaesdm_vs(vuint32m1_t rd, vuint32m1_t vs2)
{
    __asm__("vaesdm.vs %0, %1" : "+vr"(rd) : "vr"(vs2));
    return rd;
}

static vuint32m1_t
vaesdf_vs(vuint32m1_t rd, vuint32m1_t vs2)
{
    __asm__("vaesdf.vs %0, %1" : "+vr"(rd) : "vr"(vs2));
    return rd;
}

static vuint32m1_t
vaeskf1_vi(vuint32m1_t vs2, int uimm)
{
    vuint32m1_t vd;
    __asm__("vaeskf1.vi %0, %1, %2" : "=vr"(vd) : "vr"(vs2), "n"(uimm));
    return vd;
}

static vuint32m1_t
vaeskf2_vi(vuint32m1_t vd, vuint32m1_t vs2, int uimm)
{
    __asm__("vaeskf2.vi %0, %1, %2" : "+vr"(vd) : "vr"(vs2), "n"(uimm));
    return vd;
}

#define load_aes_key_128()                                   \
    vl = __riscv_vsetvl_e32m1(4);                            \
    K1 = __riscv_vle32_v_u32m1(cx->k.expandedKey, vl);       \
    K2 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 4, vl);   \
    K3 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 8, vl);   \
    K4 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 12, vl);  \
    K5 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 16, vl);  \
    K6 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 20, vl);  \
    K7 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 24, vl);  \
    K8 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 28, vl);  \
    K9 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 32, vl);  \
    K10 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 36, vl); \
    K11 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 40, vl);

#define load_aes_key_192()                                   \
    vl = __riscv_vsetvl_e32m1(4);                            \
    K1 = __riscv_vle32_v_u32m1(cx->k.expandedKey, vl);       \
    K2 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 4, vl);   \
    K3 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 8, vl);   \
    K4 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 12, vl);  \
    K5 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 16, vl);  \
    K6 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 20, vl);  \
    K7 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 24, vl);  \
    K8 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 28, vl);  \
    K9 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 32, vl);  \
    K10 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 36, vl); \
    K11 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 40, vl); \
    K12 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 44, vl); \
    K13 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 48, vl);

#define load_aes_key_256()                                   \
    vl = __riscv_vsetvl_e32m1(4);                            \
    K1 = __riscv_vle32_v_u32m1(cx->k.expandedKey, vl);       \
    K2 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 4, vl);   \
    K3 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 8, vl);   \
    K4 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 12, vl);  \
    K5 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 16, vl);  \
    K6 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 20, vl);  \
    K7 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 24, vl);  \
    K8 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 28, vl);  \
    K9 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 32, vl);  \
    K10 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 36, vl); \
    K11 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 40, vl); \
    K12 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 44, vl); \
    K13 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 48, vl); \
    K14 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 52, vl); \
    K15 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 56, vl);

SECStatus
riscv64zvkn_aes_encrypt_ecb_128(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t state;
    vuint32m1_t K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_128();

    while (inputLen > 0) {
        vl = __riscv_vsetvl_e32m1(4);
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = vaesz_vs(state, K1);
        state = vaesem_vs(state, K2);
        state = vaesem_vs(state, K3);
        state = vaesem_vs(state, K4);
        state = vaesem_vs(state, K5);
        state = vaesem_vs(state, K6);
        state = vaesem_vs(state, K7);
        state = vaesem_vs(state, K8);
        state = vaesem_vs(state, K9);
        state = vaesem_vs(state, K10);
        state = vaesef_vs(state, K11);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        input += 16;
        inputLen -= 16;
        output += 16;
    }
    return SECSuccess;
}

SECStatus
riscv64zvkn_aes_encrypt_ecb_192(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t state;
    vuint32m1_t K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11, K12, K13;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_192();

    while (inputLen > 0) {
        vl = __riscv_vsetvl_e32m1(4);
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = vaesz_vs(state, K1);
        state = vaesem_vs(state, K2);
        state = vaesem_vs(state, K3);
        state = vaesem_vs(state, K4);
        state = vaesem_vs(state, K5);
        state = vaesem_vs(state, K6);
        state = vaesem_vs(state, K7);
        state = vaesem_vs(state, K8);
        state = vaesem_vs(state, K9);
        state = vaesem_vs(state, K10);
        state = vaesem_vs(state, K11);
        state = vaesem_vs(state, K12);
        state = vaesef_vs(state, K13);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        input += 16;
        inputLen -= 16;
        output += 16;
    }
    return SECSuccess;
}

SECStatus
riscv64zvkn_aes_encrypt_ecb_256(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t state;
    vuint32m1_t K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11, K12, K13, K14, K15;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_256();

    while (inputLen > 0) {
        vl = __riscv_vsetvl_e32m1(4);
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = vaesz_vs(state, K1);
        state = vaesem_vs(state, K2);
        state = vaesem_vs(state, K3);
        state = vaesem_vs(state, K4);
        state = vaesem_vs(state, K5);
        state = vaesem_vs(state, K6);
        state = vaesem_vs(state, K7);
        state = vaesem_vs(state, K8);
        state = vaesem_vs(state, K9);
        state = vaesem_vs(state, K10);
        state = vaesem_vs(state, K11);
        state = vaesem_vs(state, K12);
        state = vaesem_vs(state, K13);
        state = vaesem_vs(state, K14);
        state = vaesef_vs(state, K15);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        input += 16;
        inputLen -= 16;
        output += 16;
    }
    return SECSuccess;
}

SECStatus
riscv64zvkn_aes_encrypt_cbc_128(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t state, iv;
    vuint32m1_t K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_128();

    vl = __riscv_vsetvl_e32m1(4);
    iv = __riscv_vle32_v_u32m1((const PRUint32 *)(cx->iv), vl);

    while (inputLen > 0) {
        vl = __riscv_vsetvl_e32m1(4);
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);
        state = vaesz_vs(state, K1);
        state = vaesem_vs(state, K2);
        state = vaesem_vs(state, K3);
        state = vaesem_vs(state, K4);
        state = vaesem_vs(state, K5);
        state = vaesem_vs(state, K6);
        state = vaesem_vs(state, K7);
        state = vaesem_vs(state, K8);
        state = vaesem_vs(state, K9);
        state = vaesem_vs(state, K10);
        state = vaesef_vs(state, K11);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        iv = state;
        input += 16;
        inputLen -= 16;
        output += 16;
    }

    __riscv_vse32_v_u32m1((PRUint32 *)(cx->iv), iv, vl);
    return SECSuccess;
}

SECStatus
riscv64zvkn_aes_encrypt_cbc_192(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t state, iv;
    vuint32m1_t K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11, K12, K13;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_192();

    iv = __riscv_vle32_v_u32m1((const PRUint32 *)(cx->iv), vl);

    while (inputLen > 0) {
        vl = __riscv_vsetvl_e32m1(4);
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);
        state = vaesz_vs(state, K1);
        state = vaesem_vs(state, K2);
        state = vaesem_vs(state, K3);
        state = vaesem_vs(state, K4);
        state = vaesem_vs(state, K5);
        state = vaesem_vs(state, K6);
        state = vaesem_vs(state, K7);
        state = vaesem_vs(state, K8);
        state = vaesem_vs(state, K9);
        state = vaesem_vs(state, K10);
        state = vaesem_vs(state, K11);
        state = vaesem_vs(state, K12);
        state = vaesef_vs(state, K13);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        iv = state;
        input += 16;
        inputLen -= 16;
        output += 16;
    }

    __riscv_vse32_v_u32m1((PRUint32 *)(cx->iv), iv, vl);
    return SECSuccess;
}

SECStatus
riscv64zvkn_aes_encrypt_cbc_256(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t state, iv;
    vuint32m1_t K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11, K12, K13, K14, K15;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_256();

    vl = __riscv_vsetvl_e32m1(4);
    iv = __riscv_vle32_v_u32m1((const PRUint32 *)(cx->iv), vl);

    while (inputLen > 0) {
        vl = __riscv_vsetvl_e32m1(4);
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        input += 16;
        inputLen -= 16;

        state = __riscv_vxor_vv_u32m1(state, iv, vl);
        state = vaesz_vs(state, K1);
        state = vaesem_vs(state, K2);
        state = vaesem_vs(state, K3);
        state = vaesem_vs(state, K4);
        state = vaesem_vs(state, K5);
        state = vaesem_vs(state, K6);
        state = vaesem_vs(state, K7);
        state = vaesem_vs(state, K8);
        state = vaesem_vs(state, K9);
        state = vaesem_vs(state, K10);
        state = vaesem_vs(state, K11);
        state = vaesem_vs(state, K12);
        state = vaesem_vs(state, K13);
        state = vaesem_vs(state, K14);
        state = vaesef_vs(state, K15);

        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        iv = state;
        output += 16;
    }

    __riscv_vse32_v_u32m1((PRUint32 *)(cx->iv), iv, vl);
    return SECSuccess;
}

SECStatus
riscv64zvkn_aes_decrypt_ecb_128(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11;
    vuint32m1_t state;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_128();

    while (inputLen > 0) {
        vl = __riscv_vsetvl_e32m1(inputLen / 4);
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);

        state = vaesz_vs(state, K11);
        state = vaesdm_vs(state, K10);
        state = vaesdm_vs(state, K9);
        state = vaesdm_vs(state, K8);
        state = vaesdm_vs(state, K7);
        state = vaesdm_vs(state, K6);
        state = vaesdm_vs(state, K5);
        state = vaesdm_vs(state, K4);
        state = vaesdm_vs(state, K3);
        state = vaesdm_vs(state, K2);
        state = vaesdf_vs(state, K1);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
	vl = vl * 4;
        input += vl;
        inputLen -= vl;
        output += vl;
    }

    return SECSuccess;
}

SECStatus
riscv64zvkn_aes_decrypt_ecb_192(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11, K12, K13;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_192();

    while (inputLen > 0) {
        vuint32m1_t state;
        vl = __riscv_vsetvl_e32m1(4);
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        input += 16;
        inputLen -= 16;

        state = vaesz_vs(state, K13);
        state = vaesdm_vs(state, K12);
        state = vaesdm_vs(state, K11);
        state = vaesdm_vs(state, K10);
        state = vaesdm_vs(state, K9);
        state = vaesdm_vs(state, K8);
        state = vaesdm_vs(state, K7);
        state = vaesdm_vs(state, K6);
        state = vaesdm_vs(state, K5);
        state = vaesdm_vs(state, K4);
        state = vaesdm_vs(state, K3);
        state = vaesdm_vs(state, K2);
        state = vaesdf_vs(state, K1);

        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        output += 16;
    }
    return SECSuccess;
}

SECStatus
riscv64zvkn_aes_decrypt_ecb_256(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t state;
    vuint32m1_t K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11, K12, K13, K14, K15;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_256();

    while (inputLen > 0) {
        vl = __riscv_vsetvl_e32m1(4);
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        input += 16;
        inputLen -= 16;

        state = vaesz_vs(state, K15);
        state = vaesdm_vs(state, K14);
        state = vaesdm_vs(state, K13);
        state = vaesdm_vs(state, K12);
        state = vaesdm_vs(state, K11);
        state = vaesdm_vs(state, K10);
        state = vaesdm_vs(state, K9);
        state = vaesdm_vs(state, K8);
        state = vaesdm_vs(state, K7);
        state = vaesdm_vs(state, K6);
        state = vaesdm_vs(state, K5);
        state = vaesdm_vs(state, K4);
        state = vaesdm_vs(state, K3);
        state = vaesdm_vs(state, K2);
        state = vaesdf_vs(state, K1);

        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        output += 16;
    }
    return SECSuccess;
}

SECStatus
riscv64zvkn_aes_decrypt_cbc_128(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t state, iv, old_state;
    vuint32m1_t K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_128();

    vl = __riscv_vsetvl_e32m1(4);
    iv = __riscv_vle32_v_u32m1((const PRUint32 *)(cx->iv), vl);

    while (inputLen > 0) {
        vl = __riscv_vsetvl_e32m1(4);
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        old_state = state;
        input += 16;
        inputLen -= 16;

        state = vaesz_vs(state, K11);
        state = vaesdm_vs(state, K10);
        state = vaesdm_vs(state, K9);
        state = vaesdm_vs(state, K8);
        state = vaesdm_vs(state, K7);
        state = vaesdm_vs(state, K6);
        state = vaesdm_vs(state, K5);
        state = vaesdm_vs(state, K4);
        state = vaesdm_vs(state, K3);
        state = vaesdm_vs(state, K2);
        state = vaesdf_vs(state, K1);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);

        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        iv = old_state;
        output += 16;
    }

    __riscv_vse32_v_u32m1((PRUint32 *)(cx->iv), iv, vl);
    return SECSuccess;
}

SECStatus
riscv64zvkn_aes_decrypt_cbc_192(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t state, old_state, iv;
    vuint32m1_t K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11, K12, K13;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_192();

    vl = __riscv_vsetvl_e32m1(4);
    iv = __riscv_vle32_v_u32m1((const PRUint32 *)(cx->iv), vl);

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        old_state = state;
        input += 16;
        inputLen -= 16;

        state = vaesz_vs(state, K13);
        state = vaesdm_vs(state, K12);
        state = vaesdm_vs(state, K11);
        state = vaesdm_vs(state, K10);
        state = vaesdm_vs(state, K9);
        state = vaesdm_vs(state, K8);
        state = vaesdm_vs(state, K7);
        state = vaesdm_vs(state, K6);
        state = vaesdm_vs(state, K5);
        state = vaesdm_vs(state, K4);
        state = vaesdm_vs(state, K3);
        state = vaesdm_vs(state, K2);
        state = vaesdf_vs(state, K1);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);

        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        iv = old_state;
        output += 16;
    }

    __riscv_vse32_v_u32m1((PRUint32 *)(cx->iv), iv, vl);
    return SECSuccess;
}

SECStatus
riscv64zvkn_aes_decrypt_cbc_256(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t state, old_state, iv;
    vuint32m1_t K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11, K12, K13, K14, K15;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_256();

    vl = __riscv_vsetvl_e32m1(4);
    iv = __riscv_vle32_v_u32m1((const PRUint32 *)(cx->iv), vl);

    while (inputLen > 0) {
        vl = __riscv_vsetvl_e32m1(4);
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        old_state = state;
        input += 16;
        inputLen -= 16;

        state = vaesz_vs(state, K15);
        state = vaesdm_vs(state, K14);
        state = vaesdm_vs(state, K13);
        state = vaesdm_vs(state, K12);
        state = vaesdm_vs(state, K11);
        state = vaesdm_vs(state, K10);
        state = vaesdm_vs(state, K9);
        state = vaesdm_vs(state, K8);
        state = vaesdm_vs(state, K7);
        state = vaesdm_vs(state, K6);
        state = vaesdm_vs(state, K5);
        state = vaesdm_vs(state, K4);
        state = vaesdm_vs(state, K3);
        state = vaesdm_vs(state, K2);
        state = vaesdf_vs(state, K1);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);

        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        iv = old_state;
        output += 16;
    }

    __riscv_vse32_v_u32m1((PRUint32 *)(cx->iv), iv, vl);
    return SECSuccess;
}

void
riscv64zvkn_key_expansion_128(AESContext *cx, const unsigned char *key)
{
    vuint32m1_t t;
    size_t vl;

    vl = __riscv_vsetvl_e32m1(4);
    t = __riscv_vle32_v_u32m1((const PRUint32 *)key, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey, t, vl);

    t = vaeskf1_vi(t, 1);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 4, t, vl);

    t = vaeskf1_vi(t, 2);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 8, t, vl);

    t = vaeskf1_vi(t, 3);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 12, t, vl);

    t = vaeskf1_vi(t, 4);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 16, t, vl);

    t = vaeskf1_vi(t, 5);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 20, t, vl);

    t = vaeskf1_vi(t, 6);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 24, t, vl);

    t = vaeskf1_vi(t, 7);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 28, t, vl);

    t = vaeskf1_vi(t, 8);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 32, t, vl);

    t = vaeskf1_vi(t, 9);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 36, t, vl);

    t = vaeskf1_vi(t, 10);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 40, t, vl);
}

void
riscv64zvkn_key_expansion_256(AESContext *cx, const unsigned char *key)
{
    vuint32m1_t t0, t1;
    size_t vl;
    PRUint32 *expandedKey;

    expandedKey = (PRUint32 *)(cx->k.expandedKey);

    vl = __riscv_vsetvl_e32m1(4);
    t0 = __riscv_vle32_v_u32m1((const PRUint32 *)key, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey, t0, vl);

    t1 = __riscv_vle32_v_u32m1((const PRUint32 *)key, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 4, t1, vl);

    t0 = vaeskf2_vi(t0, t1, 2);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 8, t0, vl);

    t1 = vaeskf2_vi(t1, t0, 3);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 12, t1, vl);

    t0 = vaeskf2_vi(t0, t1, 4);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 16, t0, vl);

    t1 = vaeskf2_vi(t1, t0, 5);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 20, t1, vl);

    t0 = vaeskf2_vi(t0, t1, 6);
    __riscv_vse32_v_u32m1(expandedKey, t0, vl);
    expandedKey += 4;

    t1 = vaeskf2_vi(t1, t0, 7);
    __riscv_vse32_v_u32m1(expandedKey, t1, vl);
    expandedKey += 4;

    t0 = vaeskf2_vi(t0, t1, 8);
    __riscv_vse32_v_u32m1(expandedKey, t0, vl);
    expandedKey += 4;

    t1 = vaeskf2_vi(t1, t0, 9);
    __riscv_vse32_v_u32m1(expandedKey, t1, vl);
    expandedKey += 4;

    t0 = vaeskf2_vi(t0, t1, 10);
    __riscv_vse32_v_u32m1(expandedKey, t0, vl);
    expandedKey += 4;

    t1 = vaeskf2_vi(t1, t0, 11);
    __riscv_vse32_v_u32m1(expandedKey, t1, vl);
    expandedKey += 4;

    t0 = vaeskf2_vi(t0, t1, 12);
    __riscv_vse32_v_u32m1(expandedKey, t0, vl);
    expandedKey += 4;

    t1 = vaeskf2_vi(t1, t0, 13);
    __riscv_vse32_v_u32m1(expandedKey, t1, vl);
    expandedKey += 4;

    t0 = vaeskf2_vi(t0, t1, 14);
    __riscv_vse32_v_u32m1(expandedKey, t0, vl);
}

void riscv64zvkn_invkey_expansion_128(AESContext *cx, const unsigned char *key)
{
    vuint32m1_t t;
    size_t vl;

    vl = __riscv_vsetvl_e32m1(4);
    t = __riscv_vle32_v_u32m1((const PRUint32 *)key, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey, t, vl);
}
