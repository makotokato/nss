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

PRBool
platform_ghash_support()
{
    return rv_zvkg_support();
}

SECStatus
gcm_HashWrite_hw(gcmHashContext *ghash, unsigned char *outbuf)
{
    vuint8m1_t v = __riscv_vle8_v_u8m1((const uint8_t *)ghash->x, 16);
    __riscv_vse8_v_u8m1(outbuf, v, 16);
    return SECSuccess;
}

SECStatus
gcm_HashMult_hw(gcmHashContext *ghash, const unsigned char *buf,
                unsigned int count)
{
    size_t vl = __riscv_vsetvl_e32m1(4);

    vuint32m1_t h = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->h, 16));
    vuint32m1_t y = __riscv_vreinterpret_v_u8m1_u32m1(
        __riscv_vle8_v_u8m1((const uint8_t *)ghash->x, 16));
    unsigned int i;

    for (i = 0; i < count; i++, buf += 16) {
        vuint32m1_t x = __riscv_vreinterpret_v_u8m1_u32m1(
            __riscv_vle8_v_u8m1(buf, 16));
        /* Y = (Y ^ X) . H */
        y = __riscv_vghsh_vv_u32m1(y, h, x, vl);
    }

    __riscv_vse8_v_u8m1((uint8_t *)ghash->x,
                        __riscv_vreinterpret_v_u32m1_u8m1(y), 16);
    return SECSuccess;
}

SECStatus
gcm_HashInit_hw(gcmHashContext *ghash)
{
    ghash->ghash_mul = gcm_HashMult_hw;
    ghash->hw = PR_TRUE;
    ghash->h[0] = __builtin_bswap64(ghash->h_high);
    ghash->h[1] = __builtin_bswap64(ghash->h_low);
    ghash->x[0] = 0;
    ghash->x[1] = 0;
    return SECSuccess;
}

SECStatus
gcm_HashZeroX_hw(gcmHashContext *ghash)
{
    ghash->x[0] = 0;
    ghash->x[1] = 0;
    return SECSuccess;
}
