/* Copyright 2016-2018 INRIA and Microsoft Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* This file was auto-generated by KreMLin! */
#ifndef __FStar_H
#define __FStar_H

#include "kremlib_base.h"

typedef struct
{
    uint64_t low;
    uint64_t high;
} FStar_UInt128_uint128;

typedef FStar_UInt128_uint128 FStar_UInt128_t;

extern void FStar_UInt128_constant_time_carry_ok(uint64_t x0, uint64_t x1);

FStar_UInt128_uint128 FStar_UInt128_add(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b);

FStar_UInt128_uint128 FStar_UInt128_add_mod(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b);

FStar_UInt128_uint128 FStar_UInt128_sub(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b);

FStar_UInt128_uint128 FStar_UInt128_sub_mod(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b);

FStar_UInt128_uint128 FStar_UInt128_logand(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b);

FStar_UInt128_uint128 FStar_UInt128_logxor(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b);

FStar_UInt128_uint128 FStar_UInt128_logor(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b);

FStar_UInt128_uint128 FStar_UInt128_lognot(FStar_UInt128_uint128 a);

FStar_UInt128_uint128 FStar_UInt128_shift_left(FStar_UInt128_uint128 a, uint32_t s);

FStar_UInt128_uint128 FStar_UInt128_shift_right(FStar_UInt128_uint128 a, uint32_t s);

FStar_UInt128_uint128 FStar_UInt128_eq_mask(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b);

FStar_UInt128_uint128 FStar_UInt128_gte_mask(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b);

FStar_UInt128_uint128 FStar_UInt128_uint64_to_uint128(uint64_t a);

uint64_t FStar_UInt128_uint128_to_uint64(FStar_UInt128_uint128 a);

typedef struct
{
    uint64_t fst;
    uint64_t snd;
    uint64_t thd;
    uint64_t f3;
} K___uint64_t_uint64_t_uint64_t_uint64_t;

FStar_UInt128_uint128 FStar_UInt128_mul_wide(uint64_t x, uint64_t y);
#endif
