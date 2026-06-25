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

#define load_aes_key_256()                                  \
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
    k13 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 48, 4); \
    k14 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 52, 4); \
    k15 = __riscv_vle32_v_u32m1(cx->k.expandedKey + 56, 4);

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
    size_t vl = __riscv_vsetvl_e32m1(4);

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_128();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, k1, vl);
        state = __riscv_vaesem_vv_u32m1(state, k2, vl);
        state = __riscv_vaesem_vv_u32m1(state, k3, vl);
        state = __riscv_vaesem_vv_u32m1(state, k4, vl);
        state = __riscv_vaesem_vv_u32m1(state, k5, vl);
        state = __riscv_vaesem_vv_u32m1(state, k6, vl);
        state = __riscv_vaesem_vv_u32m1(state, k7, vl);
        state = __riscv_vaesem_vv_u32m1(state, k8, vl);
        state = __riscv_vaesem_vv_u32m1(state, k9, vl);
        state = __riscv_vaesem_vv_u32m1(state, k10, vl);
        state = __riscv_vaesef_vv_u32m1(state, k11, vl);
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
    size_t vl = __riscv_vsetvl_e32m1(4);

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_192();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, k1, vl);
        state = __riscv_vaesem_vv_u32m1(state, k2, vl);
        state = __riscv_vaesem_vv_u32m1(state, k3, vl);
        state = __riscv_vaesem_vv_u32m1(state, k4, vl);
        state = __riscv_vaesem_vv_u32m1(state, k5, vl);
        state = __riscv_vaesem_vv_u32m1(state, k6, vl);
        state = __riscv_vaesem_vv_u32m1(state, k7, vl);
        state = __riscv_vaesem_vv_u32m1(state, k8, vl);
        state = __riscv_vaesem_vv_u32m1(state, k9, vl);
        state = __riscv_vaesem_vv_u32m1(state, k10, vl);
        state = __riscv_vaesem_vv_u32m1(state, k11, vl);
        state = __riscv_vaesem_vv_u32m1(state, k12, vl);
        state = __riscv_vaesef_vv_u32m1(state, k13, vl);
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
    size_t vl = __riscv_vsetvl_e32m1(4);

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_256();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, k1, vl);
        state = __riscv_vaesem_vv_u32m1(state, k2, vl);
        state = __riscv_vaesem_vv_u32m1(state, k3, vl);
        state = __riscv_vaesem_vv_u32m1(state, k4, vl);
        state = __riscv_vaesem_vv_u32m1(state, k5, vl);
        state = __riscv_vaesem_vv_u32m1(state, k6, vl);
        state = __riscv_vaesem_vv_u32m1(state, k7, vl);
        state = __riscv_vaesem_vv_u32m1(state, k8, vl);
        state = __riscv_vaesem_vv_u32m1(state, k9, vl);
        state = __riscv_vaesem_vv_u32m1(state, k10, vl);
        state = __riscv_vaesem_vv_u32m1(state, k11, vl);
        state = __riscv_vaesem_vv_u32m1(state, k12, vl);
        state = __riscv_vaesem_vv_u32m1(state, k13, vl);
        state = __riscv_vaesem_vv_u32m1(state, k14, vl);
        state = __riscv_vaesef_vv_u32m1(state, k15, vl);
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
    size_t vl = __riscv_vsetvl_e32m1(4);

    if (inputLen == 0) {
        return SECSuccess;
    }

    iv = __riscv_vle32_v_u32m1((const PRUint32 *)cx->iv, vl);
    load_aes_key_128();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);
        state = __riscv_vxor_vv_u32m1(state, k1, vl);
        state = __riscv_vaesem_vv_u32m1(state, k2, vl);
        state = __riscv_vaesem_vv_u32m1(state, k3, vl);
        state = __riscv_vaesem_vv_u32m1(state, k4, vl);
        state = __riscv_vaesem_vv_u32m1(state, k5, vl);
        state = __riscv_vaesem_vv_u32m1(state, k6, vl);
        state = __riscv_vaesem_vv_u32m1(state, k7, vl);
        state = __riscv_vaesem_vv_u32m1(state, k8, vl);
        state = __riscv_vaesem_vv_u32m1(state, k9, vl);
        state = __riscv_vaesem_vv_u32m1(state, k10, vl);
        state = __riscv_vaesef_vv_u32m1(state, k11, vl);
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
riscv64zvkn_aes_encrypt_cbc_192(AESContext *cx, unsigned char *output,
                                unsigned int *outputLen,
                                unsigned int maxOutputLen,
                                const unsigned char *input,
                                unsigned int inputLen,
                                unsigned int blocksize)
{
    vuint32m1_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13;
    vuint32m1_t state, iv;
    size_t vl = __riscv_vsetvl_e32m1(4);

    if (inputLen == 0) {
        return SECSuccess;
    }

    iv = __riscv_vle32_v_u32m1((const PRUint32 *)cx->iv, vl);
    load_aes_key_192();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);
        state = __riscv_vxor_vv_u32m1(state, k1, vl);
        state = __riscv_vaesem_vv_u32m1(state, k2, vl);
        state = __riscv_vaesem_vv_u32m1(state, k3, vl);
        state = __riscv_vaesem_vv_u32m1(state, k4, vl);
        state = __riscv_vaesem_vv_u32m1(state, k5, vl);
        state = __riscv_vaesem_vv_u32m1(state, k6, vl);
        state = __riscv_vaesem_vv_u32m1(state, k7, vl);
        state = __riscv_vaesem_vv_u32m1(state, k8, vl);
        state = __riscv_vaesem_vv_u32m1(state, k9, vl);
        state = __riscv_vaesem_vv_u32m1(state, k10, vl);
        state = __riscv_vaesem_vv_u32m1(state, k11, vl);
        state = __riscv_vaesem_vv_u32m1(state, k12, vl);
        state = __riscv_vaesef_vv_u32m1(state, k13, vl);
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
    size_t vl = __riscv_vsetvl_e32m1(4);

    if (inputLen == 0) {
        return SECSuccess;
    }

    iv = __riscv_vle32_v_u32m1((const PRUint32 *)cx->iv, vl);
    load_aes_key_256();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, iv, vl);
        state = __riscv_vxor_vv_u32m1(state, k1, vl);
        state = __riscv_vaesem_vv_u32m1(state, k2, vl);
        state = __riscv_vaesem_vv_u32m1(state, k3, vl);
        state = __riscv_vaesem_vv_u32m1(state, k4, vl);
        state = __riscv_vaesem_vv_u32m1(state, k5, vl);
        state = __riscv_vaesem_vv_u32m1(state, k6, vl);
        state = __riscv_vaesem_vv_u32m1(state, k7, vl);
        state = __riscv_vaesem_vv_u32m1(state, k8, vl);
        state = __riscv_vaesem_vv_u32m1(state, k9, vl);
        state = __riscv_vaesem_vv_u32m1(state, k10, vl);
        state = __riscv_vaesem_vv_u32m1(state, k11, vl);
        state = __riscv_vaesem_vv_u32m1(state, k12, vl);
        state = __riscv_vaesem_vv_u32m1(state, k13, vl);
        state = __riscv_vaesem_vv_u32m1(state, k14, vl);
        state = __riscv_vaesef_vv_u32m1(state, k15, vl);
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
    size_t vl = __riscv_vsetvl_e32m1(4);

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_128();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, k11, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k10, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k9, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k8, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k7, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k6, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k5, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k4, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k3, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k2, vl);
        state = __riscv_vaesdf_vv_u32m1(state, k1, vl);
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
    size_t vl = __riscv_vsetvl_e32m1(4);

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_192();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, k13, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k12, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k11, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k10, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k9, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k8, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k7, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k6, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k5, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k4, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k3, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k2, vl);
        state = __riscv_vaesdf_vv_u32m1(state, k1, vl);
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
    size_t vl = __riscv_vsetvl_e32m1(4);

    if (inputLen == 0) {
        return SECSuccess;
    }

    load_aes_key_256();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        state = __riscv_vxor_vv_u32m1(state, k15, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k14, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k13, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k12, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k11, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k10, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k9, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k8, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k7, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k6, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k5, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k4, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k3, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k2, vl);
        state = __riscv_vaesdf_vv_u32m1(state, k1, vl);
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
    size_t vl = __riscv_vsetvl_e32m1(4);

    if (inputLen == 0) {
        return SECSuccess;
    }

    iv = __riscv_vle32_v_u32m1((const PRUint32 *)(cx->iv), vl);
    load_aes_key_128();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        old_state = state;
        state = __riscv_vxor_vv_u32m1(state, k11, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k10, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k9, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k8, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k7, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k6, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k5, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k4, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k3, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k2, vl);
        state = __riscv_vaesdf_vv_u32m1(state, k1, vl);
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
    size_t vl = __riscv_vsetvl_e32m1(4);

    if (inputLen == 0) {
        return SECSuccess;
    }

    iv = __riscv_vle32_v_u32m1((const PRUint32 *)(cx->iv), vl);
    load_aes_key_192();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        old_state = state;
        state = __riscv_vxor_vv_u32m1(state, k13, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k12, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k11, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k10, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k9, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k8, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k7, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k6, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k5, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k4, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k3, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k2, vl);
        state = __riscv_vaesdf_vv_u32m1(state, k1, vl);
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
    size_t vl = __riscv_vsetvl_e32m1(4);

    if (inputLen == 0) {
        return SECSuccess;
    }

    iv = __riscv_vle32_v_u32m1((const PRUint32 *)(cx->iv), vl);
    load_aes_key_256();

    while (inputLen > 0) {
        state = __riscv_vle32_v_u32m1((const PRUint32 *)input, vl);
        old_state = state;
        state = __riscv_vxor_vv_u32m1(state, k15, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k14, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k13, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k12, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k11, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k10, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k9, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k8, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k7, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k6, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k5, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k4, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k3, vl);
        state = __riscv_vaesdm_vv_u32m1(state, k2, vl);
        state = __riscv_vaesdf_vv_u32m1(state, k1, vl);
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
    size_t vl = __riscv_vsetvl_e32m1(4);

    k1 = __riscv_vle32_v_u32m1((const PRUint32 *)key, vl);
    k2 = __riscv_vaeskf1_vi_u32m1(k1, 1, vl);
    k3 = __riscv_vaeskf1_vi_u32m1(k2, 2, vl);
    k4 = __riscv_vaeskf1_vi_u32m1(k3, 3, vl);
    k5 = __riscv_vaeskf1_vi_u32m1(k4, 4, vl);
    k6 = __riscv_vaeskf1_vi_u32m1(k5, 5, vl);
    k7 = __riscv_vaeskf1_vi_u32m1(k6, 6, vl);
    k8 = __riscv_vaeskf1_vi_u32m1(k7, 7, vl);
    k9 = __riscv_vaeskf1_vi_u32m1(k8, 8, vl);
    k10 = __riscv_vaeskf1_vi_u32m1(k9, 9, vl);
    k11 = __riscv_vaeskf1_vi_u32m1(k10, 10, vl);

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
    size_t vl = __riscv_vsetvl_e32m1(4);

    k1 = __riscv_vle32_v_u32m1((const PRUint32 *)key, vl);
    k2 = __riscv_vle32_v_u32m1((const PRUint32 *)(key + 16), vl);
    k3 = __riscv_vaeskf2_vi_u32m1(k1, k2, 2, vl);
    k4 = __riscv_vaeskf2_vi_u32m1(k2, k3, 3, vl);
    k5 = __riscv_vaeskf2_vi_u32m1(k3, k4, 4, vl);
    k6 = __riscv_vaeskf2_vi_u32m1(k4, k5, 5, vl);
    k7 = __riscv_vaeskf2_vi_u32m1(k5, k6, 6, vl);
    k8 = __riscv_vaeskf2_vi_u32m1(k6, k7, 7, vl);
    k9 = __riscv_vaeskf2_vi_u32m1(k7, k8, 8, vl);
    k10 = __riscv_vaeskf2_vi_u32m1(k8, k9, 9, vl);
    k11 = __riscv_vaeskf2_vi_u32m1(k9, k10, 10, vl);
    k12 = __riscv_vaeskf2_vi_u32m1(k10, k11, 11, vl);
    k13 = __riscv_vaeskf2_vi_u32m1(k11, k12, 12, vl);
    k14 = __riscv_vaeskf2_vi_u32m1(k12, k13, 13, vl);
    k15 = __riscv_vaeskf2_vi_u32m1(k13, k14, 14, vl);

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
