/*
 * Copyright (c) 2015, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Integer transcription of Intel's published RECIP14 reference equations and
 * coefficient tables.  Keeping all intermediate values in their documented
 * fixed-point domains avoids depending on the host floating-point mode while
 * preserving the reference implementation's exact result bits.
 *
 * Reference:
 * https://www.intel.com/content/dam/develop/external/us/en/documents/recip14.c
 */

#include "qemu/osdep.h"
#include "approx_14.h"

#define MXCSR_DAZ (1U << 6)
#define MXCSR_FTZ (1U << 15)

/* a[i] is the odd entry and b[i] the even entry for each interval. */
static const uint32_t rcp14_coeff[128] = {
    1009, 260119, 977, 256148, 949, 252296, 921, 248558,
    893, 244929, 869, 241405, 843, 237981, 821, 234652,
    797, 231416, 777, 228266, 755, 225202, 735, 222220,
    717, 219314, 699, 216485, 681, 213727, 663, 211038,
    647, 208417, 631, 205859, 617, 203364, 601, 200929,
    587, 198551, 573, 196229, 561, 193960, 547, 191743,
    535, 189576, 523, 187458, 513, 185387, 501, 183360,
    491, 181377, 479, 179439, 469, 177540, 459, 175681,
    451, 173860, 441, 172077, 433, 170330, 423, 168618,
    415, 166940, 407, 165295, 399, 163682, 391, 162101,
    385, 160550, 377, 159027, 369, 157535, 363, 156069,
    357, 154631, 349, 153219, 343, 151832, 337, 150470,
    331, 149133, 325, 147819, 319, 146528, 315, 145260,
    309, 144012, 303, 142787, 299, 141582, 293, 140397,
    289, 139232, 285, 138085, 279, 136959, 275, 135853,
    271, 134763, 267, 133689, 263, 132631, 259, 131589,
};

/* c[i] is the odd entry and d[i] the even entry for each interval. */
static const uint32_t rsqrt14_coeff[128] = {
    1001, 520261, 707, 367881, 955, 512437, 675, 362349,
    915, 504953, 647, 357056, 877, 497790, 619, 351992,
    841, 490922, 595, 347136, 807, 484331, 571, 342475,
    775, 478001, 549, 337997, 747, 471909, 527, 333693,
    719, 466046, 509, 329545, 693, 460397, 491, 325551,
    669, 454947, 473, 321697, 647, 449688, 457, 317977,
    625, 444606, 441, 314385, 603, 439694, 427, 310910,
    585, 434939, 413, 307549, 567, 430335, 401, 304295,
    549, 425875, 389, 301139, 533, 421551, 377, 298079,
    517, 417355, 365, 295115, 501, 413284, 355, 292237,
    487, 409329, 345, 289439, 473, 405487, 335, 286722,
    461, 401748, 325, 284080, 449, 398111, 317, 281508,
    437, 394571, 309, 279006, 425, 391127, 301, 276569,
    415, 387770, 293, 274195, 403, 384498, 285, 271882,
    393, 381307, 279, 269625, 385, 378194, 271, 267425,
    375, 375155, 265, 265276, 367, 372190, 259, 263178,
};

static uint64_t rcp14_core(uint64_t fraction, unsigned int fraction_bits,
                           unsigned int exponent_bias)
{
    uint64_t fraction16;
    unsigned int interval;
    int64_t delta;
    int64_t numerator;
    uint64_t significand17;

    /* The reference handles the exact power-of-two endpoint separately. */
    if (fraction == 0) {
        return (uint64_t)exponent_bias << fraction_bits;
    }

    fraction16 = fraction >> (fraction_bits - 16);
    interval = fraction16 >> 10;
    delta = (int64_t)fraction16 - (int64_t)((2 * interval + 1) << 9);
    numerator = (int64_t)rcp14_coeff[2 * interval + 1] * 256 -
                (int64_t)rcp14_coeff[2 * interval] * delta;
    significand17 = (uint64_t)(numerator / 512);

    if (significand17 == (UINT64_C(1) << 17)) {
        return (uint64_t)exponent_bias << fraction_bits;
    }
    return ((uint64_t)(exponent_bias - 1) << fraction_bits) |
           ((significand17 - (UINT64_C(1) << 16)) <<
            (fraction_bits - 16));
}

static uint64_t rsqrt14_core(uint64_t fraction, unsigned int fraction_bits,
                             unsigned int exponent_bias, bool odd_exponent)
{
    uint64_t fraction15;
    unsigned int interval;
    unsigned int coefficient_offset;
    int64_t delta;
    int64_t numerator;
    uint64_t significand17;

    /* The Intel reference has an architecturally exact special case for 1.0. */
    if (!odd_exponent && fraction == 0) {
        return (uint64_t)exponent_bias << fraction_bits;
    }

    fraction15 = fraction >> (fraction_bits - 15);
    interval = fraction15 >> 10;
    coefficient_offset = odd_exponent ? 2 : 0;
    delta = (int64_t)fraction15 - (int64_t)((2 * interval + 1) << 9);
    numerator =
        (int64_t)rsqrt14_coeff[4 * interval + 1 + coefficient_offset] * 128 -
        (int64_t)rsqrt14_coeff[4 * interval + coefficient_offset] * delta;
    significand17 = (uint64_t)(numerator / 512);

    if (significand17 == (UINT64_C(1) << 17)) {
        return (uint64_t)exponent_bias << fraction_bits;
    }
    return ((uint64_t)(exponent_bias - 1) << fraction_bits) |
           ((significand17 - (UINT64_C(1) << 16)) <<
            (fraction_bits - 16));
}

static uint64_t rcp14(uint32_t mxcsr, uint64_t argument,
                      unsigned int fraction_bits, unsigned int exponent_bits)
{
    const uint64_t sign_bit = UINT64_C(1)
                              << (fraction_bits + exponent_bits);
    const uint64_t exponent_max = (UINT64_C(1) << exponent_bits) - 1;
    const uint64_t exponent_mask = exponent_max << fraction_bits;
    const uint64_t fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const uint64_t quiet_bit = UINT64_C(1) << (fraction_bits - 1);
    const unsigned int exponent_bias =
        (1U << (exponent_bits - 1)) - 1;
    const uint64_t sign = argument & sign_bit;
    const uint64_t exponent = (argument >> fraction_bits) & exponent_max;
    const uint64_t fraction = argument & fraction_mask;
    uint64_t normalized_fraction;
    uint64_t base;
    uint64_t significand;
    uint64_t result;
    unsigned int output_exponent;

    if (exponent == exponent_max) {
        return fraction ? argument | quiet_bit : sign;
    }
    if (exponent == 0) {
        if (fraction == 0 || (mxcsr & MXCSR_DAZ) ||
            fraction <= (UINT64_C(1) << (fraction_bits - 2))) {
            return sign | exponent_mask;
        }

        output_exponent = (unsigned int)exponent_max - 3;
        normalized_fraction = fraction;
        while (!(normalized_fraction & (UINT64_C(1) << fraction_bits))) {
            normalized_fraction <<= 1;
            ++output_exponent;
        }
        base = rcp14_core(normalized_fraction & fraction_mask, fraction_bits,
                          exponent_bias);
        if (base == ((uint64_t)exponent_bias << fraction_bits)) {
            ++output_exponent;
        }
        return sign | ((uint64_t)output_exponent << fraction_bits) |
               (base & fraction_mask);
    }
    if (fraction == 0) {
        if (exponent == exponent_max - 1) {
            result = sign | quiet_bit;
            return (mxcsr & MXCSR_FTZ) ? sign : result;
        }
        return sign | ((exponent_max - 1 - exponent) << fraction_bits);
    }

    base = rcp14_core(fraction, fraction_bits, exponent_bias);
    significand = (UINT64_C(1) << fraction_bits) | (base & fraction_mask);
    if (exponent == exponent_max - 1) {
        result = sign | (significand >> 2);
    } else if (exponent == exponent_max - 2) {
        result = sign | (significand >> 1);
    } else {
        result = sign | ((exponent_max - 2 - exponent) << fraction_bits) |
                 (base & fraction_mask);
    }
    if ((mxcsr & MXCSR_FTZ) && !(result & exponent_mask)) {
        return sign;
    }
    return result;
}

static uint64_t rsqrt14(uint32_t mxcsr, uint64_t argument,
                        unsigned int fraction_bits,
                        unsigned int exponent_bits)
{
    const uint64_t sign_bit = UINT64_C(1)
                              << (fraction_bits + exponent_bits);
    const uint64_t exponent_max = (UINT64_C(1) << exponent_bits) - 1;
    const uint64_t exponent_mask = exponent_max << fraction_bits;
    const uint64_t fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const uint64_t quiet_bit = UINT64_C(1) << (fraction_bits - 1);
    const unsigned int exponent_bias =
        (1U << (exponent_bits - 1)) - 1;
    uint64_t sign = argument & sign_bit;
    uint64_t exponent = (argument >> fraction_bits) & exponent_max;
    uint64_t fraction = argument & fraction_mask;
    uint64_t significand;
    uint64_t base;
    int unbiased_exponent;
    int scale;
    int base_exponent;
    bool odd_exponent;

    if ((mxcsr & MXCSR_DAZ) && exponent == 0) {
        argument = sign;
        fraction = 0;
    }
    if (exponent == exponent_max) {
        if (fraction) {
            return argument | quiet_bit;
        }
        return sign ? sign_bit | exponent_mask | quiet_bit : 0;
    }
    if (sign && (exponent || fraction)) {
        return sign_bit | exponent_mask | quiet_bit;
    }
    if (exponent == 0 && fraction == 0) {
        return sign | exponent_mask;
    }

    if (exponent == 0) {
        unbiased_exponent = 1 - (int)exponent_bias;
        significand = fraction;
        while (!(significand & (UINT64_C(1) << fraction_bits))) {
            significand <<= 1;
            --unbiased_exponent;
        }
        fraction = significand & fraction_mask;
    } else {
        unbiased_exponent = (int)exponent - (int)exponent_bias;
    }

    odd_exponent = (unbiased_exponent & 1) != 0;
    scale = odd_exponent ? (unbiased_exponent - 1) / 2
                         : unbiased_exponent / 2;
    base = rsqrt14_core(fraction, fraction_bits, exponent_bias,
                        odd_exponent);
    base_exponent = (int)((base >> fraction_bits) & exponent_max);
    return ((uint64_t)(base_exponent - scale) << fraction_bits) |
           (base & fraction_mask);
}

uint32_t x86_approx_rcp14_f32(uint32_t mxcsr, uint32_t argument)
{
    return (uint32_t)rcp14(mxcsr, argument, 23, 8);
}

uint64_t x86_approx_rcp14_f64(uint32_t mxcsr, uint64_t argument)
{
    return rcp14(mxcsr, argument, 52, 11);
}

uint32_t x86_approx_rsqrt14_f32(uint32_t mxcsr, uint32_t argument)
{
    return (uint32_t)rsqrt14(mxcsr, argument, 23, 8);
}

uint64_t x86_approx_rsqrt14_f64(uint32_t mxcsr, uint64_t argument)
{
    return rsqrt14(mxcsr, argument, 52, 11);
}
