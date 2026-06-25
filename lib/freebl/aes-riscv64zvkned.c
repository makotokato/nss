/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef USE_HW_AES

#if !defined(__riscv_zvkned)
#error "Compiler option is invalid"
#endif

#include "secerr.h"
#include "rijndael.h"

#include <riscv_vector.h>

static vuint32m1_t
vaesz_vs_u32m1(vuint32m1_t rd, vuint32m1_t vs2)
{
    __asm__("vaesz.vs %0, %1" : "+vr"(rd) : "vr"(vs2));
    return rd;
}

static vuint32m1_t
vaesem_vs_u32m1(vuint32m1_t rd, vuint32m1_t vs2)
{
    __asm__("vaesem.vs %0, %1" : "+vr"(rd) : "vr"(vs2));
    return rd;
}

static vuint32m1_t
vaesef_vs_u32m1(vuint32m1_t rd, vuint32m1_t vs2)
{
    __asm__("vaesef.vs %0, %1" : "+vr"(rd) : "vr"(vs2));
    return rd;
}

static vuint32m1_t
vaesdm_vs_u32m1(vuint32m1_t rd, vuint32m1_t vs2)
{
    __asm__("vaesdm.vs %0, %1" : "+vr"(rd) : "vr"(vs2));
    return rd;
}

static vuint32m1_t
vaesdf_vs_u32m1(vuint32m1_t rd, vuint32m1_t vs2)
{
    __asm__("vaesdf.vs %0, %1" : "+vr"(rd) : "vr"(vs2));
    return rd;
}

#define load_aes_key_128()                                  \
    k1 = __riscv_vle32_v_u32m1(cx->k.expandedKey, 4);       \
    k2 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 4, 4);   \
    k3 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 8, 4);   \
    k4 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 12, 4);  \
    k5 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 16, 4);  \
    k6 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 20, 4);  \
    k7 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 24, 4);  \
    k8 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 28, 4);  \
    k9 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 32, 4);  \
    k10 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 36, 4); \
    k11 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 40, 4);

#define load_aes_key_192()                                  \
    k1 = __riscv_vle32_v_u32m1(cx->k.expandedKey, 4);       \
    k2 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 4, 4);   \
    k3 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 8, 4);   \
    k4 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 12, 4);  \
    k5 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 16, 4);  \
    k6 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 20, 4);  \
    k7 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 24, 4);  \
    k8 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 28, 4);  \
    k9 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 32, 4);  \
    k10 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 36, 4); \
    k11 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 40, 4); \
    k12 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 44, 4); \
    k13 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 48, 4);

#define load_aes_key_256()                                   \
    k1 = __riscv_vle32_v_u32m1(cx->k.expandedKey, vl);       \
    k2 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 4, vl);   \
    k3 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 8, vl);   \
    k4 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 12, vl);  \
    k5 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 16, vl);  \
    k6 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 20, vl);  \
    k7 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 24, vl);  \
    k8 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 28, vl);  \
    k9 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 32, vl);  \
    k10 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 36, vl); \
    k11 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 40, vl); \
    k12 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 44, vl); \
    k13 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 48, vl); \
    k14 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 52, vl); \
    k15 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 56, vl);

SECStatus
riscv64zvkn_aes_encrypt_ecb_128(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11;
    vuint32m1_t state;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    vl = __riscv_vsetvl_e32m1(4);
    load_aes_key_128();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = vaesz_vs_u32m1(state, k1);
        state = vaesem_vs_u32m1(state, k2);
        state = vaesem_vs_u32m1(state, k3);
        state = vaesem_vs_u32m1(state, k4);
        state = vaesem_vs_u32m1(state, k5);
        state = vaesem_vs_u32m1(state, k6);
        state = vaesem_vs_u32m1(state, k7);
        state = vaesem_vs_u32m1(state, k8);
        state = vaesem_vs_u32m1(state, k9);
        state = vaesem_vs_u32m1(state, k10);
        state = vaesef_vs_u32m1(state, k11);
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
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13;
    vuint32m1_t state;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    vl = __riscv_vsetvl_e32m1(4);
    load_aes_key_192();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = vaesz_vs_u32m1(state, k1);
        state = vaesem_vs_u32m1(state, k2);
        state = vaesem_vs_u32m1(state, k3);
        state = vaesem_vs_u32m1(state, k4);
        state = vaesem_vs_u32m1(state, k5);
        state = vaesem_vs_u32m1(state, k6);
        state = vaesem_vs_u32m1(state, k7);
        state = vaesem_vs_u32m1(state, k8);
        state = vaesem_vs_u32m1(state, k9);
        state = vaesem_vs_u32m1(state, k10);
        state = vaesem_vs_u32m1(state, k11);
        state = vaesem_vs_u32m1(state, k12);
        state = vaesef_vs_u32m1(state, k13);
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
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15;
    vuint32m1_t state;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    vl = __riscv_vsetvl_e32m1(4);
    load_aes_key_256();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = vaesz_vs_u32m1(state, k1);
        state = vaesem_vs_u32m1(state, k2);
        state = vaesem_vs_u32m1(state, k3);
        state = vaesem_vs_u32m1(state, k4);
        state = vaesem_vs_u32m1(state, k5);
        state = vaesem_vs_u32m1(state, k6);
        state = vaesem_vs_u32m1(state, k7);
        state = vaesem_vs_u32m1(state, k8);
        state = vaesem_vs_u32m1(state, k9);
        state = vaesem_vs_u32m1(state, k10);
        state = vaesem_vs_u32m1(state, k11);
        state = vaesem_vs_u32m1(state, k12);
        state = vaesem_vs_u32m1(state, k13);
        state = vaesem_vs_u32m1(state, k14);
        state = vaesef_vs_u32m1(state, k15);
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
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11;
    vuint32m1_t state, iv;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    vl = __riscv_vsetvl_e32m1(4);
    iv = __riscv_vle32_v_u32m1((const PRUint32 *)cx->iv, vl);
    load_aes_key_128();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);
        state = vaesz_vs_u32m1(state, k1);
        state = vaesem_vs_u32m1(state, k2);
        state = vaesem_vs_u32m1(state, k3);
        state = vaesem_vs_u32m1(state, k4);
        state = vaesem_vs_u32m1(state, k5);
        state = vaesem_vs_u32m1(state, k6);
        state = vaesem_vs_u32m1(state, k7);
        state = vaesem_vs_u32m1(state, k8);
        state = vaesem_vs_u32m1(state, k9);
        state = vaesem_vs_u32m1(state, k10);
        state = vaesef_vs_u32m1(state, k11);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        iv = state;
        input += 16;
        inputLen -= 16;
        output += 16;
    }

    __riscv_vse32_v_u32m1((PRUint32 *)cx->iv, iv, 4);
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
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13;
    vuint32m1_t state, iv;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    vl = __riscv_vsetvl_e32m1(4);
    iv = __riscv_vle32_v_u32m1((const PRUint32 *)cx->iv, vl);
    load_aes_key_192();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);
        state = vaesz_vs_u32m1(state, k1);
        state = vaesem_vs_u32m1(state, k2);
        state = vaesem_vs_u32m1(state, k3);
        state = vaesem_vs_u32m1(state, k4);
        state = vaesem_vs_u32m1(state, k5);
        state = vaesem_vs_u32m1(state, k6);
        state = vaesem_vs_u32m1(state, k7);
        state = vaesem_vs_u32m1(state, k8);
        state = vaesem_vs_u32m1(state, k9);
        state = vaesem_vs_u32m1(state, k10);
        state = vaesem_vs_u32m1(state, k11);
        state = vaesem_vs_u32m1(state, k12);
        state = vaesef_vs_u32m1(state, k13);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        iv = state;
        input += 16;
        inputLen -= 16;
        output += 16;
    }

    __riscv_vse32_v_u32m1((PRUint32 *)cx->iv, iv, vl);
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
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15;
    vuint32m1_t state, iv;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    vl = __riscv_vsetvl_e32m1(4);
    iv = __riscv_vle32_v_u32m1((const PRUint32 *)cx->iv, vl);
    load_aes_key_256();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);
        state = vaesz_vs_u32m1(state, k1);
        state = vaesem_vs_u32m1(state, k2);
        state = vaesem_vs_u32m1(state, k3);
        state = vaesem_vs_u32m1(state, k4);
        state = vaesem_vs_u32m1(state, k5);
        state = vaesem_vs_u32m1(state, k6);
        state = vaesem_vs_u32m1(state, k7);
        state = vaesem_vs_u32m1(state, k8);
        state = vaesem_vs_u32m1(state, k9);
        state = vaesem_vs_u32m1(state, k10);
        state = vaesem_vs_u32m1(state, k11);
        state = vaesem_vs_u32m1(state, k12);
        state = vaesem_vs_u32m1(state, k13);
        state = vaesem_vs_u32m1(state, k14);
        state = vaesef_vs_u32m1(state, k15);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        iv = state;
        input += 16;
        inputLen -= 16;
        output += 16;
    }

    __riscv_vse32_v_u32m1((PRUint32 *)cx->iv, iv, vl);
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
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11;
    vuint32m1_t state;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    vl = __riscv_vsetvl_e32m1(4);
    load_aes_key_128();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = vaesz_vs_u32m1(state, k11);
        state = vaesdm_vs_u32m1(state, k10);
        state = vaesdm_vs_u32m1(state, k9);
        state = vaesdm_vs_u32m1(state, k8);
        state = vaesdm_vs_u32m1(state, k7);
        state = vaesdm_vs_u32m1(state, k6);
        state = vaesdm_vs_u32m1(state, k5);
        state = vaesdm_vs_u32m1(state, k4);
        state = vaesdm_vs_u32m1(state, k3);
        state = vaesdm_vs_u32m1(state, k2);
        state = vaesdf_vs_u32m1(state, k1);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        input += 16;
        inputLen -= 16;
        output += 16;
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
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13;
    vuint32m1_t state;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    vl = __riscv_vsetvl_e32m1(4);
    load_aes_key_192();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = vaesz_vs_u32m1(state, k13);
        state = vaesdm_vs_u32m1(state, k12);
        state = vaesdm_vs_u32m1(state, k11);
        state = vaesdm_vs_u32m1(state, k10);
        state = vaesdm_vs_u32m1(state, k9);
        state = vaesdm_vs_u32m1(state, k8);
        state = vaesdm_vs_u32m1(state, k7);
        state = vaesdm_vs_u32m1(state, k6);
        state = vaesdm_vs_u32m1(state, k5);
        state = vaesdm_vs_u32m1(state, k4);
        state = vaesdm_vs_u32m1(state, k3);
        state = vaesdm_vs_u32m1(state, k2);
        state = vaesdf_vs_u32m1(state, k1);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        input += 16;
        inputLen -= 16;
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
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15;
    vuint32m1_t state;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    vl = __riscv_vsetvl_e32m1(4);
    load_aes_key_256();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = vaesz_vs_u32m1(state, k15);
        state = vaesdm_vs_u32m1(state, k14);
        state = vaesdm_vs_u32m1(state, k13);
        state = vaesdm_vs_u32m1(state, k12);
        state = vaesdm_vs_u32m1(state, k11);
        state = vaesdm_vs_u32m1(state, k10);
        state = vaesdm_vs_u32m1(state, k9);
        state = vaesdm_vs_u32m1(state, k8);
        state = vaesdm_vs_u32m1(state, k7);
        state = vaesdm_vs_u32m1(state, k6);
        state = vaesdm_vs_u32m1(state, k5);
        state = vaesdm_vs_u32m1(state, k4);
        state = vaesdm_vs_u32m1(state, k3);
        state = vaesdm_vs_u32m1(state, k2);
        state = vaesdf_vs_u32m1(state, k1);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        input += 16;
        inputLen -= 16;
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
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11;
    vuint32m1_t state, iv, old_state;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    vl = __riscv_vsetvl_e32m1(4);
    iv = __riscv_vle32_v_u32m1((const PRUint32 *)(cx->iv), vl);
    load_aes_key_128();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        old_state = state;
        state = vaesz_vs_u32m1(state, k11);
        state = vaesdm_vs_u32m1(state, k10);
        state = vaesdm_vs_u32m1(state, k9);
        state = vaesdm_vs_u32m1(state, k8);
        state = vaesdm_vs_u32m1(state, k7);
        state = vaesdm_vs_u32m1(state, k6);
        state = vaesdm_vs_u32m1(state, k5);
        state = vaesdm_vs_u32m1(state, k4);
        state = vaesdm_vs_u32m1(state, k3);
        state = vaesdm_vs_u32m1(state, k2);
        state = vaesdf_vs_u32m1(state, k1);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        iv = old_state;
        input += 16;
        inputLen -= 16;
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
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13;
    vuint32m1_t state, old_state, iv;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    vl = __riscv_vsetvl_e32m1(4);
    iv = __riscv_vle32_v_u32m1((const PRUint32 *)(cx->iv), vl);
    load_aes_key_192();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        old_state = state;
        state = vaesz_vs_u32m1(state, k13);
        state = vaesdm_vs_u32m1(state, k12);
        state = vaesdm_vs_u32m1(state, k11);
        state = vaesdm_vs_u32m1(state, k10);
        state = vaesdm_vs_u32m1(state, k9);
        state = vaesdm_vs_u32m1(state, k8);
        state = vaesdm_vs_u32m1(state, k7);
        state = vaesdm_vs_u32m1(state, k6);
        state = vaesdm_vs_u32m1(state, k5);
        state = vaesdm_vs_u32m1(state, k4);
        state = vaesdm_vs_u32m1(state, k3);
        state = vaesdm_vs_u32m1(state, k2);
        state = vaesdf_vs_u32m1(state, k1);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        iv = old_state;
        input += 16;
        inputLen -= 16;
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
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15;
    vuint32m1_t state, old_state, iv;
    size_t vl;

    if (inputLen == 0) {
        return SECSuccess;
    }

    vl = __riscv_vsetvl_e32m1(4);
    iv = __riscv_vle32_v_u32m1((const PRUint32 *)(cx->iv), vl);
    load_aes_key_256();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        old_state = state;
        state = vaesz_vs_u32m1(state, k15);
        state = vaesdm_vs_u32m1(state, k14);
        state = vaesdm_vs_u32m1(state, k13);
        state = vaesdm_vs_u32m1(state, k12);
        state = vaesdm_vs_u32m1(state, k11);
        state = vaesdm_vs_u32m1(state, k10);
        state = vaesdm_vs_u32m1(state, k9);
        state = vaesdm_vs_u32m1(state, k8);
        state = vaesdm_vs_u32m1(state, k7);
        state = vaesdm_vs_u32m1(state, k6);
        state = vaesdm_vs_u32m1(state, k5);
        state = vaesdm_vs_u32m1(state, k4);
        state = vaesdm_vs_u32m1(state, k3);
        state = vaesdm_vs_u32m1(state, k2);
        state = vaesdf_vs_u32m1(state, k1);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);
        __riscv_vse32_v_u32m1((PRUint32 *)output, state, vl);
        iv = old_state;
        input += 16;
        inputLen -= 16;
        output += 16;
    }

    __riscv_vse32_v_u32m1((PRUint32 *)(cx->iv), iv, vl);
    return SECSuccess;
}

void
riscv64zvkn_key_expansion_128(AESContext *cx, const unsigned char *key)
{
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11;
    size_t vl;

    vl = __riscv_vsetvl_e32m1(4);
    k1 = __riscv_vle32_v_u32m1((const PRUint32 *)key, vl);

    // gcc will throw an warning if imm value of vaeskf1.vi is not a constant,
    // so we use inline assembly to avoid the warning.
    __asm__(
        "vaeskf1.vi %0, %10, 1\n"
        "vaeskf1.vi %1, %0, 2\n"
        "vaeskf1.vi %2, %1, 3\n"
        "vaeskf1.vi %3, %2, 4\n"
        "vaeskf1.vi %4, %3, 5\n"
        "vaeskf1.vi %5, %4, 6\n"
        "vaeskf1.vi %6, %5, 7\n"
        "vaeskf1.vi %7, %6, 8\n"
        "vaeskf1.vi %8, %7, 9\n"
        "vaeskf1.vi %9, %8, 10\n"
        : "=vr"(k2), "=vr"(k3), "=vr"(k4), "=vr"(k5), "=vr"(k6), "=vr"(k7),
          "=vr"(k8), "=vr"(k9), "=vr"(k10), "=vr"(k11)
        : "vr"(k1));

    __riscv_vse32_v_u32m1(cx->k.expandedKey, k1, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 4, k2, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 8, k3, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 12, k4, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 16, k5, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 20, k6, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 24, k7, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 28, k8, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 32, k9, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 36, k10, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 40, k11, vl);
}

void
riscv64zvkn_key_expansion_256(AESContext *cx, const unsigned char *key)
{
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15;
    size_t vl;

    vl = __riscv_vsetvl_e32m1(4);
    k1 = __riscv_vle32_v_u32m1((const PRUint32 *)key, vl);
    k2 = __riscv_vle32_v_u32m1((const PRUint32 *)(key + 16), vl);

    // gcc will throw an warning if imm value of vaeskf2.vi is not a constant,
    // so we use inline assembly to avoid the warning.
    __asm__(
        "vmv.v.v    %0, %13\n"
        "vaeskf2.vi %0, %1, 2\n"
        "vmv.v.v    %1, %14\n"
        "vaeskf2.vi %1, %0, 3\n"
        "vmv.v.v    %2, %0\n"
        "vaeskf2.vi %2, %1, 4\n"
        "vmv.v.v    %3, %1\n"
        "vaeskf2.vi %3, %2, 5\n"
        "vmv.v.v    %4, %2\n"
        "vaeskf2.vi %4, %3, 6\n"
        "vmv.v.v    %5, %3\n"
        "vaeskf2.vi %5, %4, 7\n"
        "vmv.v.v    %6, %4\n"
        "vaeskf2.vi %6, %5, 8\n"
        "vmv.v.v    %7, %5\n"
        "vaeskf2.vi %7, %6, 9\n"
        "vmv.v.v    %8, %6\n"
        "vaeskf2.vi %8, %7, 10\n"
        "vmv.v.v    %9, %7\n"
        "vaeskf2.vi %9, %8, 11\n"
        "vmv.v.v    %10, %8\n"
        "vaeskf2.vi %10, %9, 12\n"
        "vmv.v.v    %11, %9\n"
        "vaeskf2.vi %11, %10, 13\n"
        "vmv.v.v    %12, %10\n"
        "vaeskf2.vi %12, %11, 13\n"
        : "=vr"(k3), "=vr"(k4), "=vr"(k5), "=vr"(k6), "=vr"(k7), "=vr"(k8),
          "=vr"(k9), "=vr"(k10), "=vr"(k11), "=vr"(k12), "=vr"(k13),
          "=vr"(k14), "=vr"(k15)
        : "vr"(k1), "vr"(k2));

    __riscv_vse32_v_u32m1(cx->k.expandedKey, k1, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 4, k2, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 8, k3, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 12, k4, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 16, k5, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 20, k6, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 24, k7, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 28, k8, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 32, k9, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 36, k10, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 40, k11, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 44, k12, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 48, k13, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 52, k14, vl);
    __riscv_vse32_v_u32m1(cx->k.expandedKey + 56, k15, vl);
}

#endif /* USE_HW_AES */
