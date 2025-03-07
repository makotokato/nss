/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _AES_RISCV64ZVKN_H_
#define _AES_RISCV64ZVKN_H_

SECStatus riscv64zvkn_aes_encrypt_ecb_128(AESContext *cx, unsigned char *output,
                                          unsigned int *outputLen,
                                          unsigned int maxOutputLen,
                                          const unsigned char *input,
                                          unsigned int inputLen,
                                          unsigned int blocksize);
SECStatus riscv64zvkn_aes_encrypt_ecb_192(AESContext *cx, unsigned char *output,
                                          unsigned int *outputLen,
                                          unsigned int maxOutputLen,
                                          const unsigned char *input,
                                          unsigned int inputLen,
                                          unsigned int blocksize);
SECStatus riscv64zvkn_aes_encrypt_ecb_256(AESContext *cx, unsigned char *output,
                                          unsigned int *outputLen,
                                          unsigned int maxOutputLen,
                                          const unsigned char *input,
                                          unsigned int inputLen,
                                          unsigned int blocksize);
SECStatus riscv64zvkn_aes_encrypt_cbc_128(AESContext *cx, unsigned char *output,
                                          unsigned int *outputLen,
                                          unsigned int maxOutputLen,
                                          const unsigned char *input,
                                          unsigned int inputLen,
                                          unsigned int blocksize);
SECStatus riscv64zvkn_aes_encrypt_cbc_192(AESContext *cx, unsigned char *output,
                                          unsigned int *outputLen,
                                          unsigned int maxOutputLen,
                                          const unsigned char *input,
                                          unsigned int inputLen,
                                          unsigned int blocksize);
SECStatus riscv64zvkn_aes_encrypt_cbc_256(AESContext *cx, unsigned char *output,
                                          unsigned int *outputLen,
                                          unsigned int maxOutputLen,
                                          const unsigned char *input,
                                          unsigned int inputLen,
                                          unsigned int blocksize);
SECStatus riscv64zvkn_aes_decrypt_ecb_128(AESContext *cx, unsigned char *output,
                                          unsigned int *outputLen,
                                          unsigned int maxOutputLen,
                                          const unsigned char *input,
                                          unsigned int inputLen,
                                          unsigned int blocksize);
SECStatus riscv64zvkn_aes_decrypt_ecb_192(AESContext *cx, unsigned char *output,
                                          unsigned int *outputLen,
                                          unsigned int maxOutputLen,
                                          const unsigned char *input,
                                          unsigned int inputLen,
                                          unsigned int blocksize);
SECStatus riscv64zvkn_aes_decrypt_ecb_256(AESContext *cx, unsigned char *output,
                                          unsigned int *outputLen,
                                          unsigned int maxOutputLen,
                                          const unsigned char *input,
                                          unsigned int inputLen,
                                          unsigned int blocksize);
SECStatus riscv64zvkn_aes_decrypt_cbc_128(AESContext *cx, unsigned char *output,
                                          unsigned int *outputLen,
                                          unsigned int maxOutputLen,
                                          const unsigned char *input,
                                          unsigned int inputLen,
                                          unsigned int blocksize);
SECStatus riscv64zvkn_aes_decrypt_cbc_192(AESContext *cx, unsigned char *output,
                                          unsigned int *outputLen,
                                          unsigned int maxOutputLen,
                                          const unsigned char *input,
                                          unsigned int inputLen,
                                          unsigned int blocksize);
SECStatus riscv64zvkn_aes_decrypt_cbc_256(AESContext *cx, unsigned char *output,
                                          unsigned int *outputLen,
                                          unsigned int maxOutputLen,
                                          const unsigned char *input,
                                          unsigned int inputLen,
                                          unsigned int blocksize);
void riscv64zvkn_key_expansion_128(AESContext *cx, const unsigned char *key);
void riscv64zvkn_key_expansion_192(AESContext *cx, const unsigned char *key);
void riscv64zvkn_key_expansion_256(AESContext *cx, const unsigned char *key);
void riscv64zvkn_invkey_expansion_128(AESContext *cx, const unsigned char *key);
void riscv64zvkn_invkey_expansion_192(AESContext *cx, const unsigned char *key);
void riscv64zvkn_invkey_expansion_256(AESContext *cx, const unsigned char *key);

#define native_aes_init(encrypt, keysize)           \
    do {                                            \
        if (encrypt) {                              \
            rijndael_key_expansion(cx, key, Nk);    \
        } else {                                    \
            rijndael_invkey_expansion(cx, key, Nk); \
        }                                           \
    } while (0)

#endif
