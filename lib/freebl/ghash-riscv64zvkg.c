/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif
#include "gcm.h"
#include "secerr.h"

#if !defined(__riscv_zvkg)
#error "Compiler option is invalid"
#endif

#include <riscv_vector.h>

/*
 * GHASH for the RISC-V vector GCM (Zvkg) extension.
 *
 * The Zvkg vghsh.vv instruction performs a single GHASH iteration:
 *
 *     Y = (Y ^ X) . H        (multiplication over GF(2^128))
 *
 * with vd = Y (partial hash), vs2 = H (subkey) and vs1 = X (input block).
 * It internally bit-reverses each byte (brev8) of its operands, so the
 * values are read from / written to memory in the natural GCM byte order
 * (block byte 0 at the lowest address).  No software bswap/bit-reflection
 * is therefore needed: blocks coming from the caller are loaded directly.
 *
 * RVV vector types are sizeless and cannot be stored in gcmHashContext, so
 * the running state and subkey are kept in the context's 64-bit halves:
 *   - x_low / x_high hold the two little-endian halves of the 128-bit hash
 *     value (x_low = bytes 0..7, x_high = bytes 8..15);
 *   - h_high / h_low hold the subkey loaded big-endian by gcmHash_InitContext
 *     (h_high = bytes 0..7, h_low = bytes 8..15), so byte-swapping each yields
 *     the little-endian halves used to rebuild H.
 */

PRBool
platform_ghash_support()
{
    return rv_zvkg_support();
}

SECStatus
gcm_HashWrite_hw(gcmHashContext *ghash, unsigned char *outbuf)
{
    uint64_t x[2] = { ghash->x_low, ghash->x_high };
    /* RISC-V is little-endian: the halves are already in GCM byte order. */
    vuint8m1_t v = __riscv_vle8_v_u8m1((const uint8_t *)x, 16);
    __riscv_vse8_v_u8m1(outbuf, v, 16);
    return SECSuccess;
}

SECStatus
gcm_HashMult_hw(gcmHashContext *ghash, const unsigned char *buf,
                unsigned int count)
{
    size_t vl = __riscv_vsetvl_e32m1(4);
    uint64_t harr[2] = { __builtin_bswap64(ghash->h_high),
                         __builtin_bswap64(ghash->h_low) };
    uint64_t xarr[2] = { ghash->x_low, ghash->x_high };
    vuint32m1_t h = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)harr, 16));
    vuint32m1_t y = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)xarr, 16));
    unsigned int i;

    for (i = 0; i < count; i++, buf += 16) {
        vuint32m1_t x = __riscv_vreinterpret_v_u8m1_u32m1(
            __riscv_vle8_v_u8m1(buf, 16));
        /* Y = (Y ^ X) . H */
        y = __riscv_vghsh_vv_u32m1(y, h, x, vl);
    }

    __riscv_vse8_v_u8m1((uint8_t *)xarr,
                        __riscv_vreinterpret_v_u32m1_u8m1(y), 16);
    ghash->x_low = xarr[0];
    ghash->x_high = xarr[1];
    return SECSuccess;
}

SECStatus
gcm_HashInit_hw(gcmHashContext *ghash)
{
    ghash->ghash_mul = gcm_HashMult_hw;
    ghash->x_low = 0;
    ghash->x_high = 0;
    ghash->hw = PR_TRUE;
    return SECSuccess;
}

SECStatus
gcm_HashZeroX_hw(gcmHashContext *ghash)
{
    ghash->x_low = 0;
    ghash->x_high = 0;
    return SECSuccess;
}
