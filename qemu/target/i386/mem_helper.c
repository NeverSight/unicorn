/*
 *  x86 memory access helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "fpu/softfloat.h"
#include "qemu/host-utils.h"
#include "qemu/int128.h"
#include "qemu/atomic128.h"
#include "tcg/tcg.h"
#include "uc_priv.h"
#include "approx_14.h"
#include "approx_28.h"

void x86_cpu_do_unaligned_access(CPUState *cs, vaddr addr,
                                 MMUAccessType access_type, int mmu_idx,
                                 uintptr_t retaddr)
{
    X86CPU *cpu = X86_CPU(cs);

    /* Aligned SSE/AVX memory operands raise #GP(0), not #AC. */
    raise_exception_ra(&cpu->env, EXCP0D_GPF, retaddr);
}

/* Keep the architectural XSAVE in-use bitmap synchronized with every custom
 * EVEX destination commit.  Callers reach these helpers only after all
 * validation, memory access, and floating-point exception checks have
 * completed, so a fault cannot expose a speculative XINUSE update. */
static void evex_commit_zmm(CPUX86State *env, unsigned int dst,
                            const ZMMReg *value)
{
    g_assert(dst < 32);
    env->xmm_regs[dst] = *value;
    env->xstate_bv |= dst < 16 ? XSTATE_ZMM_Hi256_MASK
                               : XSTATE_Hi16_ZMM_MASK;
}

static void evex_commit_opmask(CPUX86State *env, unsigned int dst,
                               uint64_t value)
{
    g_assert(dst < NB_OPMASK_REGS);
    env->opmask_regs[dst] = value;
    env->xstate_bv |= XSTATE_OPMASK_MASK;
}

static uint64_t evex_integer_get_element(const ZMMReg *reg, int element,
                                         int element_bytes)
{
    switch (element_bytes) {
    case 1:
        return reg->ZMM_B(element);
    case 2:
        return reg->ZMM_W(element);
    case 4:
        return reg->ZMM_L(element);
    case 8:
        return reg->ZMM_Q(element);
    default:
        g_assert_not_reached();
    }
}

static void evex_integer_set_element(ZMMReg *reg, int element,
                                     int element_bytes, uint64_t value)
{
    switch (element_bytes) {
    case 1:
        reg->ZMM_B(element) = value;
        return;
    case 2:
        reg->ZMM_W(element) = value;
        return;
    case 4:
        reg->ZMM_L(element) = value;
        return;
    case 8:
        reg->ZMM_Q(element) = value;
        return;
    default:
        g_assert_not_reached();
    }
}

static uint64_t evex_vmovdqu_mask(CPUX86State *env, uint32_t desc)
{
    const int mask_reg = (desc >> EVEX_VMOV_MASK_SHIFT) & 7;

    return mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
}

void helper_evex_vmovdqu_reg(CPUX86State *env, uint32_t desc)
{
    const int dst = (desc >> EVEX_VMOV_REG_SHIFT) & EVEX_VMOV_REG_MASK;
    const int src = (desc >> EVEX_VMOV_SRC_SHIFT) & EVEX_VMOV_REG_MASK;
    const int element_shift = (desc >> EVEX_VMOV_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int vector_bytes = 16 << ((desc >> EVEX_VMOV_VL_SHIFT) & 3);
    const uint64_t mask = evex_vmovdqu_mask(env, desc);
    ZMMReg result = env->xmm_regs[dst];

    for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
        const int element = byte >> element_shift;

        if ((mask >> element) & 1) {
            evex_integer_set_element(
                &result, element, element_bytes,
                evex_integer_get_element(&env->xmm_regs[src], element,
                                         element_bytes));
        } else if (desc & EVEX_VMOV_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }
    for (int byte = vector_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

static int64_t evex_integer_signed_element(uint64_t value, int element_bytes)
{
    switch (element_bytes) {
    case 1:
        return (int8_t)value;
    case 2:
        return (int16_t)value;
    case 4:
        return (int32_t)value;
    case 8:
        return (int64_t)value;
    default:
        g_assert_not_reached();
    }
}

static uint64_t evex_integer_element_mask(int element_bytes)
{
    return element_bytes == 8
               ? UINT64_MAX
               : (UINT64_C(1) << (element_bytes * 8)) - 1;
}

static uint64_t evex_packed_int_value(EVEXPackedIntOp operation,
                                      uint64_t left, uint64_t right,
                                      int element_bytes)
{
    const uint64_t element_mask = evex_integer_element_mask(element_bytes);
    const int64_t signed_left =
        evex_integer_signed_element(left, element_bytes);
    const int64_t signed_right =
        evex_integer_signed_element(right, element_bytes);

    switch (operation) {
    case EVEX_PINT_ADD:
        return left + right;
    case EVEX_PINT_SUB:
        return left - right;
    case EVEX_PINT_SAT_ADD_SIGNED:
    case EVEX_PINT_SAT_SUB_SIGNED: {
        const int bits = element_bytes * 8;
        const int64_t minimum = -(INT64_C(1) << (bits - 1));
        const int64_t maximum = (INT64_C(1) << (bits - 1)) - 1;
        int64_t value;

        g_assert(element_bytes <= 2);
        value = operation == EVEX_PINT_SAT_ADD_SIGNED
                    ? signed_left + signed_right
                    : signed_left - signed_right;
        return value < minimum ? (uint64_t)minimum
               : value > maximum ? (uint64_t)maximum
                                 : (uint64_t)value;
    }
    case EVEX_PINT_SAT_ADD_UNSIGNED:
        g_assert(element_bytes <= 2);
        return left + right > element_mask ? element_mask : left + right;
    case EVEX_PINT_SAT_SUB_UNSIGNED:
        g_assert(element_bytes <= 2);
        return left < right ? 0 : left - right;
    case EVEX_PINT_AVG_UNSIGNED:
        g_assert(element_bytes <= 2);
        return (left + right + 1) >> 1;
    case EVEX_PINT_AND:
        return left & right;
    case EVEX_PINT_AND_NOT:
        return ~left & right;
    case EVEX_PINT_OR:
        return left | right;
    case EVEX_PINT_XOR:
        return left ^ right;
    case EVEX_PINT_MIN_SIGNED:
        return signed_left < signed_right ? left : right;
    case EVEX_PINT_MIN_UNSIGNED:
        return left < right ? left : right;
    case EVEX_PINT_MAX_SIGNED:
        return signed_left > signed_right ? left : right;
    case EVEX_PINT_MAX_UNSIGNED:
        return left > right ? left : right;
    case EVEX_PINT_ABS:
        return right & (UINT64_C(1) << (element_bytes * 8 - 1))
                   ? UINT64_C(0) - right
                   : right;
    case EVEX_PINT_LZCNT:
        g_assert(element_bytes == 4 || element_bytes == 8);
        return element_bytes == 4 ? clz32(right) : clz64(right);
    case EVEX_PINT_POPCNT:
        return ctpop64(right & element_mask);
    case EVEX_PINT_MUL_LOW:
        return left * right;
    case EVEX_PINT_MUL_HIGH_SIGNED:
        g_assert(element_bytes == 2);
        return ((uint32_t)((int32_t)(int16_t)left *
                           (int32_t)(int16_t)right)) >>
               16;
    case EVEX_PINT_MUL_HIGH_UNSIGNED:
        g_assert(element_bytes == 2);
        return ((uint32_t)(uint16_t)left * (uint32_t)(uint16_t)right) >> 16;
    case EVEX_PINT_MUL_HRSW: {
        int32_t value;

        g_assert(element_bytes == 2);
        value = ((int32_t)(int16_t)left * (int32_t)(int16_t)right + 0x4000) >>
                15;
        if (value > INT16_MAX) {
            value = INT16_MAX;
        } else if (value < INT16_MIN) {
            value = INT16_MIN;
        }
        return (uint16_t)value;
    }
    case EVEX_PINT_MUL_DQ_SIGNED:
        g_assert(element_bytes == 8);
        return (uint64_t)((int64_t)(int32_t)left * (int64_t)(int32_t)right);
    case EVEX_PINT_MUL_DQ_UNSIGNED:
        g_assert(element_bytes == 8);
        return (uint64_t)(uint32_t)left * (uint64_t)(uint32_t)right;
    default:
        g_assert_not_reached();
    }
}

static uint64_t evex_packed_dot_value(EVEXPackedIntOp operation,
                                      uint64_t accumulator, uint64_t left,
                                      uint64_t right)
{
    const bool words = operation == EVEX_PINT_DOT_WORD ||
                       operation == EVEX_PINT_DOT_WORD_SATURATE;
    const bool saturate = operation == EVEX_PINT_DOT_BYTE_SATURATE ||
                          operation == EVEX_PINT_DOT_WORD_SATURATE;
    const int element_bits = words ? 16 : 8;
    const int element_count = words ? 2 : 4;
    int64_t sum = (int32_t)accumulator;

    for (int element = 0; element < element_count; ++element) {
        const unsigned int shift = element * element_bits;

        if (words) {
            sum += (int64_t)(int16_t)(left >> shift) *
                   (int64_t)(int16_t)(right >> shift);
        } else {
            sum += (int64_t)(uint8_t)(left >> shift) *
                   (int64_t)(int8_t)(right >> shift);
        }
    }
    if (saturate) {
        if (sum > INT32_MAX) {
            sum = INT32_MAX;
        } else if (sum < INT32_MIN) {
            sum = INT32_MIN;
        }
    }
    return (uint32_t)sum;
}

static uint64_t evex_packed_madd52_value(EVEXPackedIntOp operation,
                                         uint64_t accumulator, uint64_t left,
                                         uint64_t right)
{
    const uint64_t operand_mask = UINT64_C(0x000fffffffffffff);
    const uint64_t half_mask = (UINT64_C(1) << 26) - 1;
    const uint64_t a = left & operand_mask;
    const uint64_t b = right & operand_mask;
    uint64_t contribution;

    if (operation == EVEX_PINT_MADD52_LOW) {
        contribution = (a * b) & operand_mask;
    } else {
        const uint64_t a0 = a & half_mask;
        const uint64_t a1 = a >> 26;
        const uint64_t b0 = b & half_mask;
        const uint64_t b1 = b >> 26;
        const uint64_t cross = a0 * b1 + a1 * b0 + ((a0 * b0) >> 26);

        contribution = (a1 * b1 + (cross >> 26)) & operand_mask;
    }
    return accumulator + contribution;
}

void helper_evex_packed_int_reg(CPUX86State *env, uint32_t desc)
{
    const int dst = (desc >> EVEX_PINT_DST_SHIFT) & EVEX_PINT_REG_MASK;
    const int src1 = (desc >> EVEX_PINT_SRC1_SHIFT) & EVEX_PINT_REG_MASK;
    const int src2 = (desc >> EVEX_PINT_SRC2_SHIFT) & EVEX_PINT_REG_MASK;
    const int element_shift = (desc >> EVEX_PINT_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int vector_bytes = 16 << ((desc >> EVEX_PINT_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_PINT_MASK_SHIFT) & 7;
    const EVEXPackedIntOp operation =
        (desc >> EVEX_PINT_OP_SHIFT) & EVEX_PINT_OP_MASK;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    ZMMReg result = env->xmm_regs[dst];

    for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
        const int element = byte >> element_shift;
        const bool active = (mask >> element) & 1;

        if (operation == EVEX_PINT_BLEND) {
            const uint64_t value =
                active
                    ? evex_integer_get_element(&env->xmm_regs[src2], element,
                                               element_bytes)
                : (desc & EVEX_PINT_ZERO)
                    ? 0
                    : evex_integer_get_element(&env->xmm_regs[src1], element,
                                               element_bytes);

            evex_integer_set_element(&result, element, element_bytes, value);
        } else if (active) {
            uint64_t value;

            if (operation == EVEX_PINT_PERMUTE) {
                const uint64_t index = evex_integer_get_element(
                    &env->xmm_regs[src1], element, element_bytes);
                const int element_count = vector_bytes / element_bytes;

                value = evex_integer_get_element(
                    &env->xmm_regs[src2], index & (element_count - 1),
                    element_bytes);
            } else if (operation == EVEX_PINT_PERMUTE_IN_LANE) {
                const uint64_t control = evex_integer_get_element(
                    &env->xmm_regs[src2], element, element_bytes);
                const int elements_per_lane = 16 / element_bytes;
                const int lane_base = element & ~(elements_per_lane - 1);
                const int selected = element_bytes == 4
                                         ? control & 3
                                         : (control >> 1) & 1;

                value = evex_integer_get_element(
                    &env->xmm_regs[src1], lane_base + selected,
                    element_bytes);
            } else if (operation == EVEX_PINT_PERMUTE_TWO_INDEX ||
                       operation == EVEX_PINT_PERMUTE_TWO_TABLE) {
                const bool overwrite_index =
                    operation == EVEX_PINT_PERMUTE_TWO_INDEX;
                const int index_reg = overwrite_index ? dst : src1;
                const int table1_reg = overwrite_index ? src1 : dst;
                const int element_count = vector_bytes / element_bytes;
                const uint64_t index = evex_integer_get_element(
                    &env->xmm_regs[index_reg], element, element_bytes);
                const int table_reg =
                    index & element_count ? src2 : table1_reg;

                value = evex_integer_get_element(
                    &env->xmm_regs[table_reg],
                    index & (element_count - 1), element_bytes);
            } else if (operation == EVEX_PINT_MULTISHIFT) {
                const uint64_t control =
                    env->xmm_regs[src1].ZMM_B(element) & 63;
                const uint64_t data =
                    env->xmm_regs[src2].ZMM_Q(element / 8);
                const uint64_t rotated =
                    control == 0
                        ? data
                        : (data >> control) | (data << (64 - control));

                value = rotated & 0xff;
            } else if (operation == EVEX_PINT_CONFLICT) {
                const uint64_t current = evex_integer_get_element(
                    &env->xmm_regs[src2], element, element_bytes);

                value = 0;
                for (int previous = 0; previous < element; ++previous) {
                    if (evex_integer_get_element(&env->xmm_regs[src2],
                                                 previous, element_bytes) ==
                        current) {
                        value |= UINT64_C(1) << previous;
                    }
                }
            } else if (operation == EVEX_PINT_BROADCAST) {
                value = evex_integer_get_element(&env->xmm_regs[src2], 0,
                                                 element_bytes);
            } else {
                const bool dword_to_qword =
                    operation == EVEX_PINT_MUL_DQ_SIGNED ||
                    operation == EVEX_PINT_MUL_DQ_UNSIGNED;
                const int source_element =
                    dword_to_qword ? element * 2 : element;
                const int source_bytes =
                    dword_to_qword ? 4 : element_bytes;
                const uint64_t left = evex_integer_get_element(
                    &env->xmm_regs[src1], source_element, source_bytes);
                const uint64_t right = evex_integer_get_element(
                    &env->xmm_regs[src2], source_element, source_bytes);

                if (operation >= EVEX_PINT_DOT_BYTE &&
                    operation <= EVEX_PINT_DOT_WORD_SATURATE) {
                    value = evex_packed_dot_value(
                        operation,
                        evex_integer_get_element(&env->xmm_regs[dst], element,
                                                 element_bytes),
                        left, right);
                } else if (operation == EVEX_PINT_MADD52_LOW ||
                           operation == EVEX_PINT_MADD52_HIGH) {
                    value = evex_packed_madd52_value(
                        operation,
                        evex_integer_get_element(&env->xmm_regs[dst], element,
                                                 element_bytes),
                        left, right);
                } else {
                    value = evex_packed_int_value(operation, left, right,
                                                  element_bytes);
                }
            }

            evex_integer_set_element(&result, element, element_bytes, value);
        } else if (desc & EVEX_PINT_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }
    for (int byte = vector_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

static uint64_t evex_packed_shift_value(EVEXPackedShiftOp operation,
                                        uint64_t primary,
                                        uint64_t secondary,
                                        uint64_t count, int element_bytes)
{
    const unsigned int bits = element_bytes * 8;
    const uint64_t element_mask = evex_integer_element_mask(element_bytes);

    primary &= element_mask;
    secondary &= element_mask;
    switch (operation) {
    case EVEX_SHIFT_LEFT:
        return count >= bits ? 0 : (primary << count) & element_mask;
    case EVEX_SHIFT_RIGHT_LOGICAL:
        return count >= bits ? 0 : primary >> count;
    case EVEX_SHIFT_RIGHT_ARITHMETIC:
        if (count >= bits) {
            return primary & (UINT64_C(1) << (bits - 1)) ? element_mask : 0;
        }
        if (count == 0 || !(primary & (UINT64_C(1) << (bits - 1)))) {
            return primary >> count;
        }
        return (primary >> count) |
               (element_mask << (bits - (unsigned int)count));
    case EVEX_ROTATE_LEFT:
        count &= bits - 1;
        return count == 0
                   ? primary
                   : ((primary << count) |
                      (primary >> (bits - (unsigned int)count))) &
                         element_mask;
    case EVEX_ROTATE_RIGHT:
        count &= bits - 1;
        return count == 0
                   ? primary
                   : (primary >> count) |
                         ((primary << (bits - (unsigned int)count)) &
                          element_mask);
    case EVEX_DOUBLE_SHIFT_LEFT:
        count &= bits - 1;
        return count == 0
                   ? primary
                   : ((primary << count) |
                      (secondary >> (bits - (unsigned int)count))) &
                         element_mask;
    case EVEX_DOUBLE_SHIFT_RIGHT:
        count &= bits - 1;
        return count == 0
                   ? primary
                   : (primary >> count) |
                         ((secondary << (bits - (unsigned int)count)) &
                          element_mask);
    default:
        g_assert_not_reached();
    }
}

void helper_evex_packed_shift_reg(CPUX86State *env, uint32_t desc,
                                  uint32_t immediate)
{
    const int dst = (desc >> EVEX_SHIFT_DST_SHIFT) & EVEX_SHIFT_REG_MASK;
    const int src1 = (desc >> EVEX_SHIFT_SRC1_SHIFT) & EVEX_SHIFT_REG_MASK;
    const int src2 = (desc >> EVEX_SHIFT_SRC2_SHIFT) & EVEX_SHIFT_REG_MASK;
    const int element_shift = (desc >> EVEX_SHIFT_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int vector_bytes = 16 << ((desc >> EVEX_SHIFT_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_SHIFT_MASK_SHIFT) & 7;
    const EVEXPackedShiftOp operation =
        (desc >> EVEX_SHIFT_OP_SHIFT) & EVEX_SHIFT_OP_MASK;
    const bool variable = (desc & EVEX_SHIFT_VARIABLE) != 0;
    const bool double_shift = operation == EVEX_DOUBLE_SHIFT_LEFT ||
                              operation == EVEX_DOUBLE_SHIFT_RIGHT;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    ZMMReg result = env->xmm_regs[dst];

    if (operation == EVEX_SHIFT_BYTES_LEFT ||
        operation == EVEX_SHIFT_BYTES_RIGHT) {
        const unsigned int count = MIN(immediate, 16);

        for (int byte = 0; byte < vector_bytes; ++byte) {
            const int within_lane = byte & 15;
            const int lane_base = byte & ~15;
            const int source_within =
                operation == EVEX_SHIFT_BYTES_LEFT
                    ? within_lane - (int)count
                    : within_lane + (int)count;

            result.ZMM_B(byte) = source_within >= 0 && source_within < 16
                                     ? env->xmm_regs[src1].ZMM_B(lane_base +
                                                                 source_within)
                                     : 0;
        }
        for (int byte = vector_bytes; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
        evex_commit_zmm(env, dst, &result);
        return;
    }

    if (operation == EVEX_SHIFT_ALIGN_ELEMENTS) {
        const int element_count = vector_bytes / element_bytes;
        const unsigned int count = immediate & (element_count - 1);

        for (int element = 0; element < element_count; ++element) {
            if ((mask >> element) & 1) {
                const int concatenated_element = element + count;
                const int source = concatenated_element < element_count
                                       ? src2
                                       : src1;
                const int source_element =
                    concatenated_element & (element_count - 1);

                evex_integer_set_element(
                    &result, element, element_bytes,
                    evex_integer_get_element(&env->xmm_regs[source],
                                             source_element,
                                             element_bytes));
            } else if (desc & EVEX_SHIFT_ZERO) {
                evex_integer_set_element(&result, element, element_bytes, 0);
            }
        }
        for (int byte = vector_bytes; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
        evex_commit_zmm(env, dst, &result);
        return;
    }

    for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
        const int element = byte >> element_shift;

        if ((mask >> element) & 1) {
            uint64_t primary;
            uint64_t secondary = 0;
            uint64_t count = immediate;

            if (double_shift && variable) {
                primary = evex_integer_get_element(
                    &env->xmm_regs[dst], element, element_bytes);
                secondary = evex_integer_get_element(
                    &env->xmm_regs[src1], element, element_bytes);
            } else {
                primary = evex_integer_get_element(
                    &env->xmm_regs[src1], element, element_bytes);
                if (double_shift) {
                    secondary = evex_integer_get_element(
                        &env->xmm_regs[src2], element, element_bytes);
                }
            }
            if (variable) {
                count = evex_integer_get_element(
                    &env->xmm_regs[src2], element, element_bytes);
            }
            evex_integer_set_element(
                &result, element, element_bytes,
                evex_packed_shift_value(operation, primary, secondary, count,
                                        element_bytes));
        } else if (desc & EVEX_SHIFT_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }
    for (int byte = vector_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_bit_shuffle_reg(CPUX86State *env, uint32_t desc)
{
    const int dst = (desc >> EVEX_BITSHUF_DST_SHIFT) & 7;
    const int src1 =
        (desc >> EVEX_BITSHUF_SRC1_SHIFT) & EVEX_BITSHUF_REG_MASK;
    const int src2 =
        (desc >> EVEX_BITSHUF_SRC2_SHIFT) & EVEX_BITSHUF_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_BITSHUF_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_BITSHUF_MASK_SHIFT) & 7;
    const uint64_t write_mask =
        mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    uint64_t result = 0;

    for (int byte = 0; byte < vector_bytes; ++byte) {
        const uint64_t count = env->xmm_regs[src2].ZMM_B(byte) & 63;
        const uint64_t data = env->xmm_regs[src1].ZMM_Q(byte / 8);

        if (((write_mask >> byte) & 1) && ((data >> count) & 1)) {
            result |= UINT64_C(1) << byte;
        }
    }
    evex_commit_opmask(env, dst, result);
}

void helper_evex_mask_test_reg(CPUX86State *env, uint32_t desc)
{
    const int dst = (desc >> EVEX_MTEST_DST_SHIFT) & 7;
    const int src1 = (desc >> EVEX_MTEST_SRC1_SHIFT) & EVEX_MTEST_REG_MASK;
    const int src2 = (desc >> EVEX_MTEST_SRC2_SHIFT) & EVEX_MTEST_REG_MASK;
    const int element_shift = (desc >> EVEX_MTEST_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int vector_bytes = 16 << ((desc >> EVEX_MTEST_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_MTEST_MASK_SHIFT) & 7;
    const uint64_t write_mask =
        mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const bool negated = (desc & EVEX_MTEST_NEGATED) != 0;
    uint64_t result = 0;

    for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
        const int element = byte >> element_shift;
        const uint64_t left = evex_integer_get_element(
            &env->xmm_regs[src1], element, element_bytes);
        const uint64_t right = evex_integer_get_element(
            &env->xmm_regs[src2], element, element_bytes);
        const uint64_t tested = negated ? ~left & right : left & right;

        if (((write_mask >> element) & 1) && tested != 0) {
            result |= UINT64_C(1) << element;
        }
    }
    evex_commit_opmask(env, dst, result);
}

void helper_evex_ternlog_reg(CPUX86State *env, uint32_t desc,
                             uint32_t immediate)
{
    const int dst = (desc >> EVEX_TLOG_DST_SHIFT) & EVEX_TLOG_REG_MASK;
    const int src1 = (desc >> EVEX_TLOG_SRC1_SHIFT) & EVEX_TLOG_REG_MASK;
    const int src2 = (desc >> EVEX_TLOG_SRC2_SHIFT) & EVEX_TLOG_REG_MASK;
    const int element_shift = (desc >> EVEX_TLOG_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int vector_bytes = 16 << ((desc >> EVEX_TLOG_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_TLOG_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const uint64_t element_mask = evex_integer_element_mask(element_bytes);
    ZMMReg result = env->xmm_regs[dst];

    for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
        const int element = byte >> element_shift;

        if ((mask >> element) & 1) {
            const uint64_t a = evex_integer_get_element(
                &env->xmm_regs[dst], element, element_bytes);
            const uint64_t b = evex_integer_get_element(
                &env->xmm_regs[src1], element, element_bytes);
            const uint64_t c = evex_integer_get_element(
                &env->xmm_regs[src2], element, element_bytes);
            uint64_t value = 0;

            for (unsigned int selector = 0; selector < 8; ++selector) {
                if ((immediate >> selector) & 1) {
                    value |= (selector & 4 ? a : ~a) &
                             (selector & 2 ? b : ~b) &
                             (selector & 1 ? c : ~c);
                }
            }
            evex_integer_set_element(&result, element, element_bytes,
                                     value & element_mask);
        } else if (desc & EVEX_TLOG_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }
    for (int byte = vector_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_shuffle_imm_reg(CPUX86State *env, uint32_t desc,
                                 uint32_t immediate)
{
    const int dst = (desc >> EVEX_SHUF_DST_SHIFT) & EVEX_SHUF_REG_MASK;
    const int src = (desc >> EVEX_SHUF_SRC_SHIFT) & EVEX_SHUF_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_SHUF_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_SHUF_MASK_SHIFT) & 7;
    const bool dwords = (desc & EVEX_SHUF_DWORDS) != 0;
    const bool high_words = (desc & EVEX_SHUF_HIGH_WORDS) != 0;
    const int element_bytes = dwords ? 4 : 2;
    const int elements_per_lane = 16 / element_bytes;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    ZMMReg result = env->xmm_regs[dst];

    for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
        const int element = byte / element_bytes;

        if ((mask >> element) & 1) {
            const int lane_base = element - element % elements_per_lane;
            const int within_lane = element % elements_per_lane;
            const bool shuffled = dwords ||
                                  (high_words ? within_lane >= 4
                                              : within_lane < 4);
            int source_element = element;

            if (shuffled) {
                const int selector = dwords ? within_lane
                                           : high_words ? within_lane - 4
                                                        : within_lane;
                const int source_base = lane_base +
                                        (!dwords && high_words ? 4 : 0);

                source_element =
                    source_base + ((immediate >> (selector * 2)) & 3);
            }
            evex_integer_set_element(
                &result, element, element_bytes,
                evex_integer_get_element(&env->xmm_regs[src], source_element,
                                         element_bytes));
        } else if (desc & EVEX_SHUF_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }
    for (int byte = vector_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

static int evex_lane_int_element_bytes(EVEXLaneIntOp operation)
{
    switch (operation) {
    case EVEX_LANE_PACKSSWB:
    case EVEX_LANE_PACKUSWB:
    case EVEX_LANE_UNPACK_LOW_B:
    case EVEX_LANE_UNPACK_HIGH_B:
    case EVEX_LANE_SHUFFLE_BYTES:
    case EVEX_LANE_ALIGN_RIGHT:
        return 1;
    case EVEX_LANE_PACKSSDW:
    case EVEX_LANE_PACKUSDW:
    case EVEX_LANE_UNPACK_LOW_W:
    case EVEX_LANE_UNPACK_HIGH_W:
    case EVEX_LANE_MADDUBSW:
        return 2;
    case EVEX_LANE_UNPACK_LOW_D:
    case EVEX_LANE_UNPACK_HIGH_D:
    case EVEX_LANE_MADDWD:
        return 4;
    case EVEX_LANE_UNPACK_LOW_Q:
    case EVEX_LANE_UNPACK_HIGH_Q:
    case EVEX_LANE_SADBW:
        return 8;
    case EVEX_LANE_SHUFFLE_PS:
    case EVEX_LANE_DUP_LOW_D:
    case EVEX_LANE_DUP_HIGH_D:
        return 4;
    case EVEX_LANE_SHUFFLE_PD:
    case EVEX_LANE_DUP_LOW_Q:
        return 8;
    case EVEX_LANE_SHUFFLE_128_D:
    case EVEX_LANE_INSERT_128_D:
    case EVEX_LANE_INSERT_256_D:
    case EVEX_LANE_EXTRACT_128_D:
    case EVEX_LANE_EXTRACT_256_D:
        return 4;
    case EVEX_LANE_SHUFFLE_128_Q:
    case EVEX_LANE_INSERT_128_Q:
    case EVEX_LANE_INSERT_256_Q:
    case EVEX_LANE_EXTRACT_128_Q:
    case EVEX_LANE_EXTRACT_256_Q:
        return 8;
    default:
        g_assert_not_reached();
    }
}

static uint64_t evex_lane_int_value(CPUX86State *env,
                                    EVEXLaneIntOp operation, int src1,
                                    int src2, int byte, int element_bytes,
                                    int vector_bytes, uint32_t immediate)
{
    const int lane_base = byte & ~15;
    const int within_lane = (byte & 15) / element_bytes;

    if (operation <= EVEX_LANE_PACKUSDW) {
        const int input_bytes = element_bytes * 2;
        const int output_count = 16 / element_bytes;
        const int half = output_count / 2;
        const int source = within_lane < half ? src1 : src2;
        const int input_index = lane_base / input_bytes + within_lane % half;
        const int64_t input = evex_integer_signed_element(
            evex_integer_get_element(&env->xmm_regs[source], input_index,
                                     input_bytes),
            input_bytes);

        if (operation == EVEX_LANE_PACKSSWB ||
            operation == EVEX_LANE_PACKSSDW) {
            const int bits = element_bytes * 8;
            const int64_t minimum = -(INT64_C(1) << (bits - 1));
            const int64_t maximum = (INT64_C(1) << (bits - 1)) - 1;

            return input < minimum ? (uint64_t)minimum
                   : input > maximum ? (uint64_t)maximum
                                     : (uint64_t)input;
        }
        return input < 0 ? 0
               : (uint64_t)input > evex_integer_element_mask(element_bytes)
                   ? evex_integer_element_mask(element_bytes)
                   : (uint64_t)input;
    }

    if (operation >= EVEX_LANE_UNPACK_LOW_B &&
        operation <= EVEX_LANE_UNPACK_HIGH_Q) {
        const bool high = operation >= EVEX_LANE_UNPACK_HIGH_B;
        const int element_count = 16 / element_bytes;
        const int source = (within_lane & 1) ? src2 : src1;
        const int source_within = (high ? element_count / 2 : 0) +
                                  within_lane / 2;
        const int source_element = lane_base / element_bytes + source_within;

        return evex_integer_get_element(&env->xmm_regs[source],
                                        source_element, element_bytes);
    }

    switch (operation) {
    case EVEX_LANE_SHUFFLE_BYTES: {
        const uint8_t control = env->xmm_regs[src2].ZMM_B(byte);

        return control & 0x80
                   ? 0
                   : env->xmm_regs[src1].ZMM_B(lane_base + (control & 15));
    }
    case EVEX_LANE_ALIGN_RIGHT: {
        const unsigned int source_byte = (byte & 15) + immediate;

        if (source_byte < 16) {
            return env->xmm_regs[src2].ZMM_B(lane_base + source_byte);
        }
        if (source_byte < 32) {
            return env->xmm_regs[src1].ZMM_B(lane_base + source_byte - 16);
        }
        return 0;
    }
    case EVEX_LANE_MADDUBSW: {
        const int input = lane_base + within_lane * 2;
        int32_t sum = 0;

        for (int index = 0; index < 2; ++index) {
            sum += (int32_t)env->xmm_regs[src1].ZMM_B(input + index) *
                   (int32_t)(int8_t)env->xmm_regs[src2].ZMM_B(input + index);
        }
        if (sum > INT16_MAX) {
            sum = INT16_MAX;
        } else if (sum < INT16_MIN) {
            sum = INT16_MIN;
        }
        return (uint16_t)sum;
    }
    case EVEX_LANE_MADDWD: {
        const int input = lane_base / 2 + within_lane * 2;
        int64_t sum = 0;

        for (int index = 0; index < 2; ++index) {
            sum += (int64_t)(int16_t)env->xmm_regs[src1].ZMM_W(input + index) *
                   (int64_t)(int16_t)env->xmm_regs[src2].ZMM_W(input + index);
        }
        return (uint32_t)sum;
    }
    case EVEX_LANE_SADBW: {
        const int input = lane_base + within_lane * 8;
        uint64_t sum = 0;

        for (int index = 0; index < 8; ++index) {
            const int difference =
                (int)env->xmm_regs[src1].ZMM_B(input + index) -
                (int)env->xmm_regs[src2].ZMM_B(input + index);

            sum += difference < 0 ? -difference : difference;
        }
        return sum;
    }
    case EVEX_LANE_DUP_LOW_D:
    case EVEX_LANE_DUP_HIGH_D:
    case EVEX_LANE_DUP_LOW_Q: {
        const int element = byte / element_bytes;
        const int source_element =
            operation == EVEX_LANE_DUP_HIGH_D ? element | 1 : element & ~1;

        return evex_integer_get_element(&env->xmm_regs[src1],
                                        source_element, element_bytes);
    }
    case EVEX_LANE_SHUFFLE_PS: {
        const int source = within_lane < 2 ? src1 : src2;
        const int source_within =
            (immediate >> (within_lane * 2)) & 3;
        const int source_element = lane_base / 4 + source_within;

        return evex_integer_get_element(&env->xmm_regs[source],
                                        source_element, 4);
    }
    case EVEX_LANE_SHUFFLE_PD: {
        const int lane = byte / 16;
        const int source = within_lane == 0 ? src1 : src2;
        const int source_within =
            (immediate >> (lane * 2 + within_lane)) & 1;
        const int source_element = lane_base / 8 + source_within;

        return evex_integer_get_element(&env->xmm_regs[source],
                                        source_element, 8);
    }
    case EVEX_LANE_SHUFFLE_128_D:
    case EVEX_LANE_SHUFFLE_128_Q: {
        const int lane_count = vector_bytes / 16;
        const int destination_lane = byte / 16;
        const int elements_per_lane = 16 / element_bytes;
        const int source = destination_lane < lane_count / 2 ? src1 : src2;
        const int selector_shift = lane_count == 2
                                       ? destination_lane
                                       : destination_lane * 2;
        const int selector_mask = lane_count == 2 ? 1 : 3;
        const int source_lane =
            (immediate >> selector_shift) & selector_mask;
        const int source_element = source_lane * elements_per_lane +
                                   within_lane;

        return evex_integer_get_element(&env->xmm_regs[source],
                                        source_element, element_bytes);
    }
    case EVEX_LANE_INSERT_128_D:
    case EVEX_LANE_INSERT_128_Q:
    case EVEX_LANE_INSERT_256_D:
    case EVEX_LANE_INSERT_256_Q: {
        const bool insert_256 = operation == EVEX_LANE_INSERT_256_D ||
                                operation == EVEX_LANE_INSERT_256_Q;
        const int inserted_bytes = insert_256 ? 32 : 16;
        const int inserted_base =
            (immediate & (vector_bytes / inserted_bytes - 1)) *
            inserted_bytes;

        if (byte >= inserted_base && byte < inserted_base + inserted_bytes) {
            return evex_integer_get_element(
                &env->xmm_regs[src2],
                (byte - inserted_base) / element_bytes, element_bytes);
        }
        return evex_integer_get_element(&env->xmm_regs[src1],
                                        byte / element_bytes,
                                        element_bytes);
    }
    case EVEX_LANE_EXTRACT_128_D:
    case EVEX_LANE_EXTRACT_128_Q:
    case EVEX_LANE_EXTRACT_256_D:
    case EVEX_LANE_EXTRACT_256_Q: {
        const bool extract_256 = operation == EVEX_LANE_EXTRACT_256_D ||
                                 operation == EVEX_LANE_EXTRACT_256_Q;
        const int extracted_bytes = extract_256 ? 32 : 16;
        const int extracted_base =
            (immediate & (vector_bytes / extracted_bytes - 1)) *
            extracted_bytes;

        return evex_integer_get_element(
            &env->xmm_regs[src1],
            (extracted_base + byte) / element_bytes, element_bytes);
    }
    default:
        g_assert_not_reached();
    }
}

void helper_evex_lane_int_reg(CPUX86State *env, uint32_t desc,
                              uint32_t immediate)
{
    const int dst = (desc >> EVEX_LANE_DST_SHIFT) & EVEX_LANE_REG_MASK;
    const int src1 = (desc >> EVEX_LANE_SRC1_SHIFT) & EVEX_LANE_REG_MASK;
    const int src2 = (desc >> EVEX_LANE_SRC2_SHIFT) & EVEX_LANE_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_LANE_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_LANE_MASK_SHIFT) & 7;
    const EVEXLaneIntOp operation =
        (desc >> EVEX_LANE_OP_SHIFT) & EVEX_LANE_OP_MASK;
    const int element_bytes = evex_lane_int_element_bytes(operation);
    const bool extract_128 = operation == EVEX_LANE_EXTRACT_128_D ||
                             operation == EVEX_LANE_EXTRACT_128_Q;
    const bool extract_256 = operation == EVEX_LANE_EXTRACT_256_D ||
                             operation == EVEX_LANE_EXTRACT_256_Q;
    const int result_bytes = extract_128 ? 16 : extract_256 ? 32
                                                               : vector_bytes;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    ZMMReg result = env->xmm_regs[dst];

    for (int byte = 0; byte < result_bytes; byte += element_bytes) {
        const int element = byte / element_bytes;

        if ((mask >> element) & 1) {
            evex_integer_set_element(
                &result, element, element_bytes,
                evex_lane_int_value(env, operation, src1, src2, byte,
                                    element_bytes, vector_bytes, immediate));
        } else if (desc & EVEX_LANE_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }
    for (int byte = result_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

static void evex_dbpsadbw_apply(CPUX86State *env, uint32_t desc,
                                uint32_t immediate,
                                const ZMMReg *source2)
{
    const int dst = (desc >> EVEX_LANE_DST_SHIFT) & EVEX_LANE_REG_MASK;
    const int src1 = (desc >> EVEX_LANE_SRC1_SHIFT) & EVEX_LANE_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_LANE_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_LANE_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    ZMMReg shuffled = {0};
    ZMMReg result = env->xmm_regs[dst];

    /* The immediate independently selects each dword inside every 128-bit
     * lane, exactly like PSHUFD. */
    for (int lane = 0; lane < vector_bytes; lane += 16) {
        for (int dword = 0; dword < 4; ++dword) {
            const int selected = (immediate >> (dword * 2)) & 3;

            shuffled.ZMM_L((lane >> 2) + dword) =
                source2->ZMM_L((lane >> 2) + selected);
        }
    }

    /* Each qword superblock produces four 16-bit SAD results.  Results 0/1
     * use the low source1 dword and sliding offsets 0/1; results 2/3 use the
     * high source1 dword and sliding offsets 2/3. */
    for (int base = 0; base < vector_bytes; base += 8) {
        for (int word = 0; word < 4; ++word) {
            const int output_word = (base >> 1) + word;

            if ((mask >> output_word) & 1) {
                const int source1_base = base + (word >= 2 ? 4 : 0);
                const int shuffled_base = base + word;
                uint16_t sum = 0;

                for (int byte = 0; byte < 4; ++byte) {
                    const int difference =
                        (int)env->xmm_regs[src1].ZMM_B(source1_base + byte) -
                        (int)shuffled.ZMM_B(shuffled_base + byte);

                    sum += difference < 0 ? -difference : difference;
                }
                result.ZMM_W(output_word) = sum;
            } else if (desc & EVEX_LANE_ZERO) {
                result.ZMM_W(output_word) = 0;
            }
        }
    }
    for (int byte = vector_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_dbpsadbw_reg(CPUX86State *env, uint32_t desc,
                              uint32_t immediate)
{
    const int src2 =
        (desc >> EVEX_LANE_SRC2_SHIFT) & EVEX_LANE_REG_MASK;

    evex_dbpsadbw_apply(env, desc, immediate, &env->xmm_regs[src2]);
}

void helper_evex_dbpsadbw_load(CPUX86State *env, target_ulong address,
                               uint32_t desc, uint32_t immediate)
{
    const int vector_bytes = 16 << ((desc >> EVEX_LANE_VL_SHIFT) & 3);
    const uintptr_t ra = GETPC();
    ZMMReg source2 = {0};

    /* Full-Mem tuple: masking does not suppress source memory accesses. */
    for (int byte = 0; byte < vector_bytes; ++byte) {
        source2.ZMM_B(byte) = cpu_ldub_data_ra(env, address + byte, ra);
    }
    evex_dbpsadbw_apply(env, desc, immediate, &source2);
}

uint64_t helper_evex_extract_scalar_lane(CPUX86State *env, uint32_t desc)
{
    const int src =
        (desc >> EVEX_SCALAR_LANE_SRC_SHIFT) & EVEX_SCALAR_LANE_REG_MASK;
    const int element_shift = (desc >> EVEX_SCALAR_LANE_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int element_count = 16 / element_bytes;
    const int index =
        ((desc >> EVEX_SCALAR_LANE_INDEX_SHIFT) &
         EVEX_SCALAR_LANE_INDEX_MASK) &
        (element_count - 1);

    return evex_integer_get_element(&env->xmm_regs[src], index,
                                    element_bytes);
}

void helper_evex_insert_scalar_lane(CPUX86State *env, uint32_t desc,
                                    uint64_t value)
{
    const int dst =
        (desc >> EVEX_SCALAR_LANE_DST_SHIFT) & EVEX_SCALAR_LANE_REG_MASK;
    const int src =
        (desc >> EVEX_SCALAR_LANE_SRC_SHIFT) & EVEX_SCALAR_LANE_REG_MASK;
    const int element_shift = (desc >> EVEX_SCALAR_LANE_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int element_count = 16 / element_bytes;
    const int index =
        ((desc >> EVEX_SCALAR_LANE_INDEX_SHIFT) &
         EVEX_SCALAR_LANE_INDEX_MASK) &
        (element_count - 1);
    const unsigned int zero_mask =
        (desc >> EVEX_SCALAR_LANE_ZERO_MASK_SHIFT) &
        EVEX_SCALAR_LANE_ZERO_MASK;
    ZMMReg result = env->xmm_regs[src];

    evex_integer_set_element(&result, index, element_bytes, value);
    for (int dword = 0; dword < 4; ++dword) {
        if ((zero_mask >> dword) & 1) {
            result.ZMM_L(dword) = 0;
        }
    }
    for (int byte = 16; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_set_vector_scalar(CPUX86State *env, uint32_t desc,
                                   uint64_t value)
{
    const int dst =
        (desc >> EVEX_SCALAR_LANE_DST_SHIFT) & EVEX_SCALAR_LANE_REG_MASK;
    const int element_shift = (desc >> EVEX_SCALAR_LANE_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    ZMMReg result = {0};

    evex_integer_set_element(&result, 0, element_bytes, value);
    evex_commit_zmm(env, dst, &result);
}

static bool evex_scalar_move_active(CPUX86State *env, uint32_t desc)
{
    const int mask_reg = (desc >> EVEX_SCALAR_MOVE_MASK_SHIFT) & 7;

    return !mask_reg || (env->opmask_regs[mask_reg] & 1);
}

void helper_evex_scalar_move_reg(CPUX86State *env, uint32_t desc)
{
    const int dst =
        (desc >> EVEX_SCALAR_MOVE_DST_SHIFT) & EVEX_SCALAR_MOVE_REG_MASK;
    const int src1 =
        (desc >> EVEX_SCALAR_MOVE_SRC1_SHIFT) & EVEX_SCALAR_MOVE_REG_MASK;
    const int src2 =
        (desc >> EVEX_SCALAR_MOVE_SRC2_SHIFT) & EVEX_SCALAR_MOVE_REG_MASK;
    const int element_bytes = (desc & EVEX_SCALAR_MOVE_QWORD) ? 8 : 4;
    ZMMReg result = env->xmm_regs[dst];

    /* Register forms always merge bits 127:element-width from SRC1, even
     * when the low element is masked off.  Snapshotting the destination and
     * committing once keeps every source/destination alias exact. */
    for (int byte = element_bytes; byte < 16; ++byte) {
        result.ZMM_B(byte) = env->xmm_regs[src1].ZMM_B(byte);
    }
    if (evex_scalar_move_active(env, desc)) {
        evex_integer_set_element(
            &result, 0, element_bytes,
            evex_integer_get_element(&env->xmm_regs[src2], 0,
                                     element_bytes));
    } else if (desc & EVEX_SCALAR_MOVE_ZERO) {
        evex_integer_set_element(&result, 0, element_bytes, 0);
    }
    for (int byte = 16; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_scalar_move_load(CPUX86State *env, target_ulong address,
                                  uint32_t desc)
{
    const int dst =
        (desc >> EVEX_SCALAR_MOVE_DST_SHIFT) & EVEX_SCALAR_MOVE_REG_MASK;
    const int element_bytes = (desc & EVEX_SCALAR_MOVE_QWORD) ? 8 : 4;
    ZMMReg result = env->xmm_regs[dst];

    /* An inactive mask suppresses the memory access.  Unlike register
     * forms, every bit above the scalar destination is then cleared. */
    if (evex_scalar_move_active(env, desc)) {
        const uintptr_t ra = GETPC();
        const uint64_t value = element_bytes == 8
                                   ? cpu_ldq_data_ra(env, address, ra)
                                   : cpu_ldl_data_ra(env, address, ra);

        evex_integer_set_element(&result, 0, element_bytes, value);
    } else if (desc & EVEX_SCALAR_MOVE_ZERO) {
        evex_integer_set_element(&result, 0, element_bytes, 0);
    }
    for (int byte = element_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_scalar_move_store(CPUX86State *env, target_ulong address,
                                   uint32_t desc)
{
    const int src =
        (desc >> EVEX_SCALAR_MOVE_DST_SHIFT) & EVEX_SCALAR_MOVE_REG_MASK;
    const int element_bytes = (desc & EVEX_SCALAR_MOVE_QWORD) ? 8 : 4;
    const uintptr_t ra = GETPC();
    uint64_t value;

    if (!evex_scalar_move_active(env, desc)) {
        return;
    }
    value = evex_integer_get_element(&env->xmm_regs[src], 0,
                                     element_bytes);
    if (element_bytes == 8) {
        cpu_stq_data_ra(env, address, value, ra);
    } else {
        cpu_stl_data_ra(env, address, value, ra);
    }
}

static void evex_broadcast_lane_apply(CPUX86State *env, uint32_t desc,
                                      const ZMMReg *source)
{
    const int dst = (desc >> EVEX_BCAST_DST_SHIFT) & EVEX_BCAST_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_BCAST_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_BCAST_MASK_SHIFT) & 7;
    const int element_shift = (desc >> EVEX_BCAST_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int tuple_bytes =
        1 << ((desc >> EVEX_BCAST_TUPLE_SHIFT) & EVEX_BCAST_TUPLE_MASK);
    const int tuple_elements = tuple_bytes / element_bytes;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    ZMMReg result = env->xmm_regs[dst];

    for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
        const int element = byte >> element_shift;

        if ((mask >> element) & 1) {
            evex_integer_set_element(
                &result, element, element_bytes,
                evex_integer_get_element(source, element % tuple_elements,
                                         element_bytes));
        } else if (desc & EVEX_BCAST_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }
    for (int byte = vector_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_broadcast_lane_reg(CPUX86State *env, uint32_t desc)
{
    const int src = (desc >> EVEX_BCAST_SRC_SHIFT) & EVEX_BCAST_REG_MASK;

    evex_broadcast_lane_apply(env, desc, &env->xmm_regs[src]);
}

void helper_evex_broadcast_lane_load(CPUX86State *env,
                                     target_ulong address, uint32_t desc)
{
    const int vector_bytes = 16 << ((desc >> EVEX_BCAST_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_BCAST_MASK_SHIFT) & 7;
    const int element_shift = (desc >> EVEX_BCAST_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int tuple_bytes =
        1 << ((desc >> EVEX_BCAST_TUPLE_SHIFT) & EVEX_BCAST_TUPLE_MASK);
    const int tuple_elements = tuple_bytes / element_bytes;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const uintptr_t ra = GETPC();
    uint64_t needed = 0;
    ZMMReg source = {0};

    /* A destination mask can suppress individual components of the repeated
     * source tuple.  Read each component that is actually referenced once;
     * commit the destination only after every required access succeeds. */
    for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
        const int element = byte >> element_shift;

        if ((mask >> element) & 1) {
            needed |= UINT64_C(1) << (element % tuple_elements);
        }
    }
    for (int element = 0; element < tuple_elements; ++element) {
        uint64_t value;

        if (!((needed >> element) & 1)) {
            continue;
        }
        switch (element_bytes) {
        case 1:
            value = cpu_ldub_data_ra(env, address + element, ra);
            break;
        case 2:
            value = cpu_lduw_data_ra(env, address + element * 2, ra);
            break;
        case 4:
            value = cpu_ldl_data_ra(env, address + element * 4, ra);
            break;
        default:
            value = cpu_ldq_data_ra(env, address + element * 8, ra);
            break;
        }
        evex_integer_set_element(&source, element, element_bytes, value);
    }
    evex_broadcast_lane_apply(env, desc, &source);
}

static void evex_crypto_copy_lane(ZMMReg *dst, const ZMMReg *src, int lane)
{
    memset(dst, 0, sizeof(*dst));
    for (int byte = 0; byte < 16; ++byte) {
        dst->ZMM_B(byte) = src->ZMM_B(lane * 16 + byte);
    }
}

static void evex_crypto_apply(CPUX86State *env, uint32_t desc,
                              uint32_t immediate, const ZMMReg *source)
{
    const int dst = (desc >> EVEX_CRYPTO_DST_SHIFT) & EVEX_CRYPTO_REG_MASK;
    const int src1 =
        (desc >> EVEX_CRYPTO_SRC1_SHIFT) & EVEX_CRYPTO_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_CRYPTO_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_CRYPTO_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const EVEXCryptoOp operation =
        (desc >> EVEX_CRYPTO_OP_SHIFT) & EVEX_CRYPTO_OP_MASK;
    ZMMReg result = env->xmm_regs[dst];

    for (int lane = 0; lane < vector_bytes / 16; ++lane) {
        ZMMReg left;
        ZMMReg right;
        ZMMReg lane_result = {0};

        evex_crypto_copy_lane(&left, &env->xmm_regs[src1], lane);
        evex_crypto_copy_lane(&right, source, lane);
        switch (operation) {
        case EVEX_CRYPTO_AES_DEC:
            lane_result = left;
            helper_aesdec_xmm(env, &lane_result, &right);
            break;
        case EVEX_CRYPTO_AES_DEC_LAST:
            lane_result = left;
            helper_aesdeclast_xmm(env, &lane_result, &right);
            break;
        case EVEX_CRYPTO_AES_ENC:
            lane_result = left;
            helper_aesenc_xmm(env, &lane_result, &right);
            break;
        case EVEX_CRYPTO_AES_ENC_LAST:
            lane_result = left;
            helper_aesenclast_xmm(env, &lane_result, &right);
            break;
        case EVEX_CRYPTO_GF_MUL:
            helper_gf2p8mulb_xmm(env, &lane_result, &left, &right);
            break;
        case EVEX_CRYPTO_GF_AFFINE:
            helper_gf2p8affineqb_xmm(env, &lane_result, &left, &right,
                                     immediate);
            break;
        case EVEX_CRYPTO_GF_AFFINE_INV:
            helper_gf2p8affineinvqb_xmm(env, &lane_result, &left, &right,
                                        immediate);
            break;
        case EVEX_CRYPTO_PCLMUL:
            lane_result = left;
            helper_pclmulqdq_xmm(env, &lane_result, &right, immediate);
            break;
        default:
            g_assert_not_reached();
        }

        for (int byte = 0; byte < 16; ++byte) {
            const int output_byte = lane * 16 + byte;

            if ((mask >> output_byte) & 1) {
                result.ZMM_B(output_byte) = lane_result.ZMM_B(byte);
            } else if (desc & EVEX_CRYPTO_ZERO) {
                result.ZMM_B(output_byte) = 0;
            }
        }
    }
    for (int byte = vector_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_crypto_reg(CPUX86State *env, uint32_t desc,
                            uint32_t immediate)
{
    const int src2 =
        (desc >> EVEX_CRYPTO_SRC2_SHIFT) & EVEX_CRYPTO_REG_MASK;

    evex_crypto_apply(env, desc, immediate, &env->xmm_regs[src2]);
}

void helper_evex_crypto_load(CPUX86State *env, target_ulong address,
                             uint32_t desc, uint32_t immediate)
{
    const int vector_bytes = 16 << ((desc >> EVEX_CRYPTO_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_CRYPTO_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const EVEXCryptoOp operation =
        (desc >> EVEX_CRYPTO_OP_SHIFT) & EVEX_CRYPTO_OP_MASK;
    const uintptr_t ra = GETPC();
    ZMMReg source = {0};

    if (operation == EVEX_CRYPTO_GF_MUL) {
        /* VGF2P8MULB has per-byte fault suppression. */
        for (int byte = 0; byte < vector_bytes; ++byte) {
            if ((mask >> byte) & 1) {
                source.ZMM_B(byte) =
                    cpu_ldub_data_ra(env, address + byte, ra);
            }
        }
    } else if (desc & EVEX_CRYPTO_BROADCAST) {
        uint8_t qword[8];

        for (int byte = 0; byte < 8; ++byte) {
            qword[byte] = cpu_ldub_data_ra(env, address + byte, ra);
        }
        for (int byte = 0; byte < vector_bytes; ++byte) {
            source.ZMM_B(byte) = qword[byte & 7];
        }
    } else {
        /* VAES, VPCLMULQDQ, and affine GFNI forms do not suppress faults. */
        for (int byte = 0; byte < vector_bytes; ++byte) {
            source.ZMM_B(byte) = cpu_ldub_data_ra(env, address + byte, ra);
        }
    }
    evex_crypto_apply(env, desc, immediate, &source);
}

void helper_evex_mask_convert_reg(CPUX86State *env, uint32_t desc)
{
    const int dst = (desc >> EVEX_MCONV_DST_SHIFT) & EVEX_MCONV_REG_MASK;
    const int src = (desc >> EVEX_MCONV_SRC_SHIFT) & EVEX_MCONV_REG_MASK;
    const int element_shift = (desc >> EVEX_MCONV_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int vector_bytes = 16 << ((desc >> EVEX_MCONV_VL_SHIFT) & 3);
    const EVEXMaskConvertOp operation =
        (desc >> EVEX_MCONV_OP_SHIFT) & EVEX_MCONV_OP_MASK;

    if (operation == EVEX_MCONV_VECTOR_TO_MASK) {
        uint64_t result = 0;

        for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
            const int element = byte >> element_shift;
            const uint64_t value = evex_integer_get_element(
                &env->xmm_regs[src], element, element_bytes);

            if (value & (UINT64_C(1) << (element_bytes * 8 - 1))) {
                result |= UINT64_C(1) << element;
            }
        }
        evex_commit_opmask(env, dst & 7, result);
        return;
    }

    {
        const uint64_t source_mask = env->opmask_regs[src & 7];
        const uint64_t broadcast =
            element_bytes == 8 ? source_mask & 0xff : source_mask & 0xffff;
        ZMMReg result = {0};

        for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
            const int element = byte >> element_shift;
            const uint64_t value =
                operation == EVEX_MCONV_MASK_TO_VECTOR
                    ? ((source_mask >> element) & 1
                           ? evex_integer_element_mask(element_bytes)
                           : 0)
                    : broadcast;

            evex_integer_set_element(&result, element, element_bytes, value);
        }
        evex_commit_zmm(env, dst, &result);
    }
}

void helper_evex_widen_reg(CPUX86State *env, uint32_t desc)
{
    const int dst = (desc >> EVEX_WIDEN_DST_SHIFT) & EVEX_WIDEN_REG_MASK;
    const int src = (desc >> EVEX_WIDEN_SRC_SHIFT) & EVEX_WIDEN_REG_MASK;
    const int input_shift = (desc >> EVEX_WIDEN_INPUT_SHIFT) & 3;
    const int output_shift = (desc >> EVEX_WIDEN_OUTPUT_SHIFT) & 3;
    const int input_bytes = 1 << input_shift;
    const int output_bytes = 1 << output_shift;
    const int vector_bytes = 16 << ((desc >> EVEX_WIDEN_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_WIDEN_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const bool sign_extend = (desc & EVEX_WIDEN_SIGNED) != 0;
    ZMMReg result = env->xmm_regs[dst];

    for (int byte = 0; byte < vector_bytes; byte += output_bytes) {
        const int element = byte >> output_shift;

        if ((mask >> element) & 1) {
            const uint64_t input = evex_integer_get_element(
                &env->xmm_regs[src], element, input_bytes);
            const uint64_t output =
                sign_extend
                    ? (uint64_t)evex_integer_signed_element(input, input_bytes)
                    : input;

            evex_integer_set_element(&result, element, output_bytes, output);
        } else if (desc & EVEX_WIDEN_ZERO) {
            evex_integer_set_element(&result, element, output_bytes, 0);
        }
    }
    for (int byte = vector_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_narrow_reg(CPUX86State *env, uint32_t desc)
{
    const int dst = (desc >> EVEX_NARROW_DST_SHIFT) & EVEX_NARROW_REG_MASK;
    const int src = (desc >> EVEX_NARROW_SRC_SHIFT) & EVEX_NARROW_REG_MASK;
    const int input_shift = (desc >> EVEX_NARROW_INPUT_SHIFT) & 3;
    const int output_shift = (desc >> EVEX_NARROW_OUTPUT_SHIFT) & 3;
    const int input_bytes = 1 << input_shift;
    const int output_bytes = 1 << output_shift;
    const int source_bytes = 16 << ((desc >> EVEX_NARROW_VL_SHIFT) & 3);
    const int element_count = source_bytes / input_bytes;
    const int packed_bytes = element_count * output_bytes;
    const int mask_reg = (desc >> EVEX_NARROW_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const EVEXNarrowMode mode =
        (desc >> EVEX_NARROW_MODE_SHIFT) & EVEX_NARROW_MODE_MASK;
    ZMMReg result = env->xmm_regs[dst];

    for (int element = 0; element < element_count; ++element) {
        if ((mask >> element) & 1) {
            const uint64_t input = evex_integer_get_element(
                &env->xmm_regs[src], element, input_bytes);
            uint64_t output = input;

            if (mode != EVEX_NARROW_TRUNCATE) {
                const int64_t signed_input =
                    evex_integer_signed_element(input, input_bytes);

                if (mode == EVEX_NARROW_SATURATE_SIGNED) {
                    const int bits = output_bytes * 8;
                    const int64_t minimum = -(INT64_C(1) << (bits - 1));
                    const int64_t maximum = (INT64_C(1) << (bits - 1)) - 1;

                    output = signed_input < minimum ? (uint64_t)minimum
                             : signed_input > maximum ? (uint64_t)maximum
                                                      : (uint64_t)signed_input;
                } else {
                    const uint64_t maximum =
                        evex_integer_element_mask(output_bytes);

                    output = signed_input < 0 ? 0
                             : (uint64_t)signed_input > maximum
                                 ? maximum
                                 : (uint64_t)signed_input;
                }
            }
            evex_integer_set_element(&result, element, output_bytes, output);
        } else if (desc & EVEX_NARROW_ZERO) {
            evex_integer_set_element(&result, element, output_bytes, 0);
        }
    }
    for (int byte = packed_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

static bool evex_integer_compare(uint64_t left, uint64_t right,
                                 int element_bytes, bool unsigned_compare,
                                 int predicate)
{
    const bool equal = left == right;
    const bool less =
        unsigned_compare
            ? left < right
            : evex_integer_signed_element(left, element_bytes) <
                  evex_integer_signed_element(right, element_bytes);

    switch (predicate) {
    case 0:
        return equal;
    case 1:
        return less;
    case 2:
        return less || equal;
    case 3:
        return false;
    case 4:
        return !equal;
    case 5:
        return !less;
    case 6:
        return !less && !equal;
    case 7:
        return true;
    default:
        g_assert_not_reached();
    }
}

void helper_evex_packed_compare_reg(CPUX86State *env, uint32_t desc)
{
    const int dst = (desc >> EVEX_PCMP_DST_SHIFT) & 7;
    const int src1 = (desc >> EVEX_PCMP_SRC1_SHIFT) & EVEX_PCMP_REG_MASK;
    const int src2 = (desc >> EVEX_PCMP_SRC2_SHIFT) & EVEX_PCMP_REG_MASK;
    const int element_shift = (desc >> EVEX_PCMP_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int vector_bytes = 16 << ((desc >> EVEX_PCMP_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_PCMP_MASK_SHIFT) & 7;
    const int predicate = (desc >> EVEX_PCMP_PRED_SHIFT) & 7;
    const uint64_t write_mask =
        mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    uint64_t result = 0;

    for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
        const int element = byte >> element_shift;
        const uint64_t left = evex_integer_get_element(&env->xmm_regs[src1],
                                                       element, element_bytes);
        const uint64_t right = evex_integer_get_element(&env->xmm_regs[src2],
                                                        element, element_bytes);

        if (((write_mask >> element) & 1) &&
            evex_integer_compare(left, right, element_bytes,
                                 (desc & EVEX_PCMP_UNSIGNED) != 0, predicate)) {
            result |= UINT64_C(1) << element;
        }
    }
    evex_commit_opmask(env, dst, result);
}

void helper_evex_compress_expand_reg(CPUX86State *env, uint32_t desc)
{
    const int dst = (desc >> EVEX_CE_DST_SHIFT) & EVEX_CE_REG_MASK;
    const int src = (desc >> EVEX_CE_SRC_SHIFT) & EVEX_CE_REG_MASK;
    const int element_shift = (desc >> EVEX_CE_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int vector_bytes = 16 << ((desc >> EVEX_CE_VL_SHIFT) & 3);
    const int element_count = vector_bytes >> element_shift;
    const int mask_reg = (desc >> EVEX_CE_MASK_SHIFT) & 7;
    const uint64_t mask =
        mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const ZMMReg source = env->xmm_regs[src];
    ZMMReg result = env->xmm_regs[dst];
    int packed = 0;

    if (desc & EVEX_CE_EXPAND) {
        for (int output = 0; output < element_count; ++output) {
            if ((mask >> output) & 1) {
                evex_integer_set_element(
                    &result, output, element_bytes,
                    evex_integer_get_element(&source, packed, element_bytes));
                ++packed;
            } else if (desc & EVEX_CE_ZERO) {
                evex_integer_set_element(&result, output, element_bytes, 0);
            }
        }
    } else {
        for (int input = 0; input < element_count; ++input) {
            if ((mask >> input) & 1) {
                evex_integer_set_element(
                    &result, packed, element_bytes,
                    evex_integer_get_element(&source, input, element_bytes));
                ++packed;
            }
        }
        if (desc & EVEX_CE_ZERO) {
            while (packed < element_count) {
                evex_integer_set_element(&result, packed, element_bytes, 0);
                ++packed;
            }
        }
    }

    for (int byte = vector_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

static uint64_t evex_vmovdqu_load_element(CPUX86State *env,
                                          target_ulong address,
                                          int element_bytes, uintptr_t ra);
static void evex_vmovdqu_store_element(CPUX86State *env,
                                       target_ulong address,
                                       int element_bytes, uint64_t value,
                                       uintptr_t ra);
static void apx_evex_check_memory_range(CPUX86State *env, uint64_t address,
                                        uint32_t access_bytes,
                                        uint32_t desc, uintptr_t ra);

static target_ulong evex_compress_expand_element_address(
    CPUX86State *env, target_ulong address, int packed, int element_bytes,
    uint32_t desc, uintptr_t ra)
{
    const uint64_t offset = (uint64_t)packed * element_bytes;

#ifdef TARGET_X86_64
    if ((uint64_t)address > UINT64_MAX - offset) {
        const int exception =
            (desc & EVEX_CE_STACK) ? EXCP0C_STACK : EXCP0D_GPF;

        raise_exception_err_ra(env, exception, 0, ra);
    }
#endif
    address += (target_ulong)offset;
    apx_evex_check_memory_range(
        env, address, element_bytes,
        (desc & EVEX_CE_STACK) ? APX_MEMORY_SS : 0, ra);
    return address;
}

void helper_evex_compress_expand_mem(CPUX86State *env,
                                     target_ulong address, uint32_t desc,
                                     target_ulong fault_eip)
{
    const int dst = (desc >> EVEX_CE_DST_SHIFT) & EVEX_CE_REG_MASK;
    const int src = (desc >> EVEX_CE_SRC_SHIFT) & EVEX_CE_REG_MASK;
    const int element_shift = (desc >> EVEX_CE_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int vector_bytes = 16 << ((desc >> EVEX_CE_VL_SHIFT) & 3);
    const int element_count = vector_bytes >> element_shift;
    const int mask_reg = (desc >> EVEX_CE_MASK_SHIFT) & 7;
    const uint64_t mask =
        mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const uintptr_t ra = GETPC();
    int packed = 0;

#ifndef TARGET_X86_64
    (void)fault_eip;
#endif
    if (desc & EVEX_CE_EXPAND) {
        ZMMReg result = env->xmm_regs[dst];

        /* Stage every selected load before committing the destination. */
        for (int output = 0; output < element_count; ++output) {
            if ((mask >> output) & 1) {
                const target_ulong element_address =
                    evex_compress_expand_element_address(
                        env, address, packed, element_bytes, desc, ra);
                const uint64_t value = evex_vmovdqu_load_element(
                    env, element_address, element_bytes, ra);

                evex_integer_set_element(&result, output, element_bytes,
                                         value);
                ++packed;
            } else if (desc & EVEX_CE_ZERO) {
                evex_integer_set_element(&result, output, element_bytes, 0);
            }
        }
        for (int byte = vector_bytes; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
        evex_commit_zmm(env, dst, &result);
        return;
    }

    {
        const ZMMReg source = env->xmm_regs[src];

        /* Stores are architecturally ordered: if a later store faults, the
         * earlier selected elements remain visible. */
        for (int input = 0; input < element_count; ++input) {
            if ((mask >> input) & 1) {
                const target_ulong element_address =
                    evex_compress_expand_element_address(
                        env, address, packed, element_bytes, desc, ra);
                const uint64_t value = evex_integer_get_element(
                    &source, input, element_bytes);

#ifdef TARGET_X86_64
                if (!x86_evex_store_preflight(
                        env, element_address, element_bytes, value, ra)) {
                    env->eip = fault_eip;
                    cpu_loop_exit(env_cpu(env));
                }
#endif
                evex_vmovdqu_store_element(
                    env, element_address, element_bytes, value, ra);
                ++packed;
            }
        }
    }
}

static void evex_approx14_apply(CPUX86State *env, uint32_t desc,
                                const ZMMReg *second_source)
{
    const int dst =
        (desc >> EVEX_APPROX14_DST_SHIFT) & EVEX_APPROX14_REG_MASK;
    const int src1 =
        (desc >> EVEX_APPROX14_SRC1_SHIFT) & EVEX_APPROX14_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_APPROX14_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_APPROX14_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_APPROX14_MASK_SHIFT) & 7;
    const uint64_t mask =
        mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const ZMMReg first_source = env->xmm_regs[src1];
    ZMMReg result = env->xmm_regs[dst];
    int elements = vector_bytes / element_bytes;

    if (desc & EVEX_APPROX14_SCALAR) {
        elements = 1;
    }
    for (int element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            uint64_t input = evex_integer_get_element(
                second_source, element, element_bytes);
            uint64_t output;

            if (element_bytes == 8) {
                output = (desc & EVEX_APPROX14_RSQRT)
                             ? x86_approx_rsqrt14_f64(env->mxcsr, input)
                             : x86_approx_rcp14_f64(env->mxcsr, input);
            } else {
                output = (desc & EVEX_APPROX14_RSQRT)
                             ? x86_approx_rsqrt14_f32(env->mxcsr,
                                                      (uint32_t)input)
                             : x86_approx_rcp14_f32(env->mxcsr,
                                                    (uint32_t)input);
            }
            evex_integer_set_element(&result, element, element_bytes,
                                     output);
        } else if (desc & EVEX_APPROX14_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }

    if (desc & EVEX_APPROX14_SCALAR) {
        for (int byte = element_bytes; byte < 16; ++byte) {
            result.ZMM_B(byte) = first_source.ZMM_B(byte);
        }
        for (int byte = 16; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    } else {
        for (int byte = vector_bytes; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_approx14_reg(CPUX86State *env, uint32_t desc)
{
    const int src2 =
        (desc >> EVEX_APPROX14_SRC2_SHIFT) & EVEX_APPROX14_REG_MASK;
    const ZMMReg second_source = env->xmm_regs[src2];

    evex_approx14_apply(env, desc, &second_source);
}

void helper_evex_approx14_load(CPUX86State *env, target_ulong address,
                               uint32_t desc)
{
    const int vector_bytes = 16 << ((desc >> EVEX_APPROX14_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_APPROX14_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_APPROX14_MASK_SHIFT) & 7;
    const uint64_t mask =
        mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const bool scalar = (desc & EVEX_APPROX14_SCALAR) != 0;
    const int elements = scalar ? 1 : vector_bytes / element_bytes;
    const uintptr_t ra = GETPC();
    ZMMReg memory_source = {0};

    /* Stage every active element before evaluating the operation so a later
     * memory fault cannot partially commit the destination. */
    if (desc & EVEX_APPROX14_BROADCAST) {
        if (mask & ((UINT64_C(1) << elements) - 1)) {
            const uint64_t value = evex_vmovdqu_load_element(
                env, address, element_bytes, ra);

            for (int element = 0; element < elements; ++element) {
                if ((mask >> element) & 1) {
                    evex_integer_set_element(&memory_source, element,
                                             element_bytes, value);
                }
            }
        }
    } else {
        for (int element = 0; element < elements; ++element) {
            if ((mask >> element) & 1) {
                const uint64_t value = evex_vmovdqu_load_element(
                    env, address + element * element_bytes, element_bytes,
                    ra);

                evex_integer_set_element(&memory_source, element,
                                         element_bytes, value);
            }
        }
    }
    evex_approx14_apply(env, desc, &memory_source);
}

enum {
    EVEX_MXCSR_IE = 1U << 0,
    EVEX_MXCSR_DE = 1U << 1,
    EVEX_MXCSR_ZE = 1U << 2,
    EVEX_MXCSR_OE = 1U << 3,
    EVEX_MXCSR_UE = 1U << 4,
    EVEX_MXCSR_PE = 1U << 5,
    EVEX_MXCSR_DAZ = 1U << 6,
};

static uint32_t evex_scalef_softfloat_flags(int flags);

static bool evex_float_is_nan(uint64_t value, uint64_t exponent_mask,
                              uint64_t fraction_mask)
{
    return (value & exponent_mask) == exponent_mask &&
           (value & fraction_mask) != 0;
}

static bool evex_float_is_snan(uint64_t value, uint64_t exponent_mask,
                               uint64_t fraction_mask, uint64_t quiet_bit)
{
    return evex_float_is_nan(value, exponent_mask, fraction_mask) &&
           !(value & quiet_bit);
}

static uint64_t evex_range_lane(uint64_t src1, uint64_t src2, int fraction_bits,
                                int exponent_bits, unsigned int imm,
                                uint32_t mxcsr, uint32_t *exception_flags)
{
    const uint64_t sign_bit = UINT64_C(1) << (fraction_bits + exponent_bits);
    const uint64_t exponent_mask = ((UINT64_C(1) << exponent_bits) - 1)
                                   << fraction_bits;
    const uint64_t fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const uint64_t magnitude_mask = sign_bit - 1;
    const uint64_t quiet_bit = UINT64_C(1) << (fraction_bits - 1);
    const uint64_t width_mask =
        fraction_bits == 52 ? UINT64_MAX : UINT64_C(0xffffffff);
    const bool src1_snan =
        evex_float_is_snan(src1, exponent_mask, fraction_mask, quiet_bit);
    const bool src2_snan =
        evex_float_is_snan(src2, exponent_mask, fraction_mask, quiet_bit);
    bool src1_qnan;
    bool src2_qnan;
    uint64_t compare1 = src1;
    uint64_t compare2 = src2;
    uint64_t result;
    uint64_t magnitude1;
    uint64_t magnitude2;
    bool less_equal;

    if (src1_snan) {
        *exception_flags |= EVEX_MXCSR_IE;
        return (src1 | quiet_bit) & width_mask;
    }
    if (src2_snan) {
        *exception_flags |= EVEX_MXCSR_IE;
        return (src2 | quiet_bit) & width_mask;
    }

    src1_qnan = evex_float_is_nan(src1, exponent_mask, fraction_mask);
    src2_qnan = evex_float_is_nan(src2, exponent_mask, fraction_mask);
    if (!(src1 & exponent_mask) && (src1 & fraction_mask)) {
        if (mxcsr & EVEX_MXCSR_DAZ) {
            compare1 = src1 & sign_bit;
        } else if (!src2_qnan) {
            *exception_flags |= EVEX_MXCSR_DE;
        }
    }
    if (!(src2 & exponent_mask) && (src2 & fraction_mask)) {
        if (mxcsr & EVEX_MXCSR_DAZ) {
            compare2 = src2 & sign_bit;
        } else if (!src1_qnan) {
            *exception_flags |= EVEX_MXCSR_DE;
        }
    }

    if (src2_qnan) {
        result = compare1;
    } else if (src1_qnan) {
        result = compare2;
    } else {
        magnitude1 = compare1 & magnitude_mask;
        magnitude2 = compare2 & magnitude_mask;
        if (!magnitude1 && !magnitude2 && ((compare1 ^ compare2) & sign_bit)) {
            result = (imm & 1) ? 0 : sign_bit;
        } else if (magnitude1 == magnitude2 &&
                   ((compare1 ^ compare2) & sign_bit) && (imm & 2)) {
            result = (imm & 1) ? (compare1 & sign_bit ? compare2 : compare1)
                               : (compare1 & sign_bit ? compare1 : compare2);
        } else {
            if ((compare1 ^ compare2) & sign_bit) {
                less_equal = (compare1 & sign_bit) != 0;
            } else if (compare1 & sign_bit) {
                less_equal = magnitude1 >= magnitude2;
            } else {
                less_equal = magnitude1 <= magnitude2;
            }
            switch (imm & 3) {
            case 0:
                result = less_equal ? compare1 : compare2;
                break;
            case 1:
                result = less_equal ? compare2 : compare1;
                break;
            case 2:
                result = magnitude1 <= magnitude2 ? compare1 : compare2;
                break;
            default:
                result = magnitude1 <= magnitude2 ? compare2 : compare1;
                break;
            }
        }
    }

    switch ((imm >> 2) & 3) {
    case 0:
        result = (result & ~sign_bit) | (src1 & sign_bit);
        break;
    case 1:
        break;
    case 2:
        result &= ~sign_bit;
        break;
    default:
        result |= sign_bit;
        break;
    }
    return result & width_mask;
}

static void evex_range_apply(CPUX86State *env, uint32_t desc,
                             const ZMMReg *second_source)
{
    const int dst = (desc >> EVEX_RANGE_DST_SHIFT) & EVEX_RANGE_REG_MASK;
    const int src1 = (desc >> EVEX_RANGE_SRC1_SHIFT) & EVEX_RANGE_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_RANGE_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_RANGE_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_RANGE_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const unsigned int imm = (desc >> EVEX_RANGE_IMM_SHIFT) & 15;
    const ZMMReg first_source = env->xmm_regs[src1];
    ZMMReg result = env->xmm_regs[dst];
    const bool scalar = (desc & EVEX_RANGE_SCALAR) != 0;
    const int elements = scalar ? 1 : vector_bytes / element_bytes;
    uint32_t exception_flags = 0;

    for (int element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            const uint64_t left =
                evex_integer_get_element(&first_source, element, element_bytes);
            const uint64_t right =
                evex_integer_get_element(second_source, element, element_bytes);
            const uint64_t output =
                element_bytes == 8
                    ? evex_range_lane(left, right, 52, 11, imm, env->mxcsr,
                                      &exception_flags)
                    : evex_range_lane((uint32_t)left, (uint32_t)right, 23, 8,
                                      imm, env->mxcsr, &exception_flags);

            evex_integer_set_element(&result, element, element_bytes, output);
        } else if (desc & EVEX_RANGE_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }

    if (scalar) {
        for (int byte = element_bytes; byte < 16; ++byte) {
            result.ZMM_B(byte) = first_source.ZMM_B(byte);
        }
        for (int byte = 16; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    } else {
        for (int byte = vector_bytes; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    }

    if (!(desc & EVEX_RANGE_SAE) && exception_flags) {
        const uint32_t exception_masks = (env->mxcsr >> 7) & 0x3f;
        const uint32_t unmasked = exception_flags & ~exception_masks;

        cpu_set_mxcsr(env, env->mxcsr | exception_flags);
        if (unmasked) {
            if (!(env->cr[4] & CR4_OSXMMEXCPT_MASK)) {
                raise_exception_ra(env, EXCP06_ILLOP, GETPC());
            }
            raise_exception_ra(env, EXCP13_XM, GETPC());
        }
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_range_reg(CPUX86State *env, uint32_t desc)
{
    const int src2 = (desc >> EVEX_RANGE_SRC2_SHIFT) & EVEX_RANGE_REG_MASK;
    const ZMMReg second_source = env->xmm_regs[src2];

    evex_range_apply(env, desc, &second_source);
}

void helper_evex_range_load(CPUX86State *env, target_ulong address,
                            uint32_t desc)
{
    const int vector_bytes = 16 << ((desc >> EVEX_RANGE_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_RANGE_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_RANGE_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const bool scalar = (desc & EVEX_RANGE_SCALAR) != 0;
    const int elements = scalar ? 1 : vector_bytes / element_bytes;
    const uintptr_t ra = GETPC();
    ZMMReg memory_source = {0};

    if (desc & EVEX_RANGE_BROADCAST) {
        if (mask & ((UINT64_C(1) << elements) - 1)) {
            const uint64_t value =
                evex_vmovdqu_load_element(env, address, element_bytes, ra);

            for (int element = 0; element < elements; ++element) {
                if ((mask >> element) & 1) {
                    evex_integer_set_element(&memory_source, element,
                                             element_bytes, value);
                }
            }
        }
    } else {
        for (int element = 0; element < elements; ++element) {
            if ((mask >> element) & 1) {
                const uint64_t value = evex_vmovdqu_load_element(
                    env, address + element * element_bytes, element_bytes, ra);

                evex_integer_set_element(&memory_source, element, element_bytes,
                                         value);
            }
        }
    }
    evex_range_apply(env, desc, &memory_source);
}

static unsigned int evex_fp_transform_token(uint64_t value,
                                             int fraction_bits,
                                             int exponent_bits)
{
    const uint64_t sign_bit = UINT64_C(1) << (fraction_bits + exponent_bits);
    const uint64_t exponent_mask = ((UINT64_C(1) << exponent_bits) - 1)
                                   << fraction_bits;
    const uint64_t fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const uint64_t magnitude = value & ~sign_bit;
    const uint64_t positive_one =
        ((uint64_t)((1U << (exponent_bits - 1)) - 1) << fraction_bits);

    if (evex_float_is_nan(value, exponent_mask, fraction_mask)) {
        return value & (UINT64_C(1) << (fraction_bits - 1)) ? 0 : 1;
    }
    if (!magnitude)
        return 2;
    if (magnitude == exponent_mask)
        return value & sign_bit ? 4 : 5;
    if (magnitude == positive_one)
        return value & sign_bit ? 6 : 3;
    return value & sign_bit ? 6 : 7;
}

static uint64_t evex_fp_transform_fixup(uint64_t destination, uint64_t source,
                                        uint64_t table, unsigned int immediate,
                                        int fraction_bits, int exponent_bits,
                                        uint32_t mxcsr,
                                        uint32_t *exception_flags)
{
    const uint64_t sign_bit = UINT64_C(1) << (fraction_bits + exponent_bits);
    const uint64_t exponent_mask = ((UINT64_C(1) << exponent_bits) - 1)
                                   << fraction_bits;
    const uint64_t quiet_bit = UINT64_C(1) << (fraction_bits - 1);
    const unsigned int token =
        evex_fp_transform_token((mxcsr & EVEX_MXCSR_DAZ) &&
                                    !(source & exponent_mask)
                                ? source & sign_bit
                                : source,
                                fraction_bits, exponent_bits);
    const unsigned int response = (table >> (token * 4)) & 0xf;

    if ((mxcsr & EVEX_MXCSR_DAZ) && !(source & exponent_mask))
        source &= sign_bit;
    switch (response) {
    case 0:
        break;
    case 1:
        destination = source;
        break;
    case 2:
        destination = evex_float_is_nan(source, exponent_mask,
                                        (UINT64_C(1) << fraction_bits) - 1)
                          ? source | quiet_bit
                          : (source & sign_bit) | exponent_mask | quiet_bit;
        break;
    case 3:
        destination = sign_bit | exponent_mask | quiet_bit;
        break;
    case 4:
        destination = sign_bit | exponent_mask;
        break;
    case 5:
        destination = exponent_mask;
        break;
    case 6:
        destination = (source & sign_bit) | exponent_mask;
        break;
    case 7:
        destination = sign_bit;
        break;
    case 8:
        destination = 0;
        break;
    case 9:
        destination = sign_bit | (fraction_bits == 52
                                      ? UINT64_C(0x3ff0000000000000)
                                      : UINT64_C(0x3f800000));
        break;
    case 10:
        destination = fraction_bits == 52 ? UINT64_C(0x3ff0000000000000)
                                          : UINT64_C(0x3f800000);
        break;
    case 11:
        destination = fraction_bits == 52 ? UINT64_C(0x3fe0000000000000)
                                          : UINT64_C(0x3f000000);
        break;
    case 12:
        destination = fraction_bits == 52 ? UINT64_C(0x4056800000000000)
                                          : UINT64_C(0x42b40000);
        break;
    case 13:
        destination = fraction_bits == 52 ? UINT64_C(0x3ff921fb54442d18)
                                          : UINT64_C(0x3fc90fdb);
        break;
    case 14:
        destination = fraction_bits == 52 ? UINT64_C(0x7fefffffffffffff)
                                          : UINT64_C(0x7f7fffff);
        break;
    default:
        destination = fraction_bits == 52 ? UINT64_C(0xffefffffffffffff)
                                          : UINT64_C(0xff7fffff);
        break;
    }
    switch (token) {
    case 0:
        break;
    case 1:
        if (immediate & (1U << 4))
            *exception_flags |= EVEX_MXCSR_IE;
        break;
    case 2:
        if (immediate & (1U << 0))
            *exception_flags |= EVEX_MXCSR_ZE;
        if (immediate & (1U << 1))
            *exception_flags |= EVEX_MXCSR_IE;
        break;
    case 3:
        if (immediate & (1U << 2))
            *exception_flags |= EVEX_MXCSR_ZE;
        if (immediate & (1U << 3))
            *exception_flags |= EVEX_MXCSR_IE;
        break;
    case 4:
        if (immediate & (1U << 5))
            *exception_flags |= EVEX_MXCSR_IE;
        break;
    case 5:
        if (immediate & (1U << 7))
            *exception_flags |= EVEX_MXCSR_IE;
        break;
    case 6:
        if (immediate & (1U << 6))
            *exception_flags |= EVEX_MXCSR_IE;
        break;
    default:
        break;
    }
    return destination;
}

static uint64_t evex_fp_transform_round(uint64_t source, int fraction_bits,
                                        int exponent_bits, unsigned int scale,
                                        unsigned int rounding_mode,
                                        bool reduce, float_status base_status,
                                        uint32_t *exception_flags)
{
    const uint64_t sign_bit = UINT64_C(1) << (fraction_bits + exponent_bits);
    const uint64_t exponent_mask = ((UINT64_C(1) << exponent_bits) - 1)
                                   << fraction_bits;
    const uint64_t fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const uint64_t quiet_bit = UINT64_C(1) << (fraction_bits - 1);
    const uint64_t magnitude = source & ~sign_bit;
    const unsigned int exponent_field =
        (source & exponent_mask) >> fraction_bits;
    const unsigned int exponent_bias = (1U << (exponent_bits - 1)) - 1;
    const int exponent = exponent_field ?
        (int)exponent_field - (int)exponent_bias : 1 - (int)exponent_bias;
    float_status status = base_status;
    uint64_t result;

    if (evex_float_is_nan(source, exponent_mask, fraction_mask)) {
        if (!(source & quiet_bit))
            *exception_flags |= EVEX_MXCSR_IE;
        return source | quiet_bit;
    }
    if (exponent_field == (1U << exponent_bits) - 1) {
        if (reduce) {
            *exception_flags |= EVEX_MXCSR_IE;
            return 0;
        }
        return source;
    }
    if (!magnitude) {
        if (reduce) {
            /* Intel specifies the reduction zero sign independently of the
             * source sign: round toward negative infinity produces -0, all
             * other controls produce +0. */
            return rounding_mode == float_round_down ? sign_bit : 0;
        }
        return source;
    }
    if (exponent + (int)scale + 1 >= fraction_bits + 1)
        return reduce ? (rounding_mode == float_round_down ? sign_bit : 0)
                      : source;

    set_float_exception_flags(0, &status);
    set_float_rounding_mode(rounding_mode, &status);
    set_flush_inputs_to_zero(false, &status);
    set_flush_to_zero(false, &status);
    if (fraction_bits == 52) {
        float64 scaled = float64_scalbn(source, (int)scale, &status);
        float64 rounded = float64_round_to_int(scaled, &status);
        float64 unscaled = float64_scalbn(rounded, -(int)scale, &status);
        result = reduce ? float64_sub(source, unscaled, &status) : unscaled;
    } else {
        float32 scaled = float32_scalbn((float32)source, (int)scale, &status);
        float32 rounded = float32_round_to_int(scaled, &status);
        float32 unscaled = float32_scalbn(rounded, -(int)scale, &status);
        result = reduce ? (uint32_t)float32_sub((float32)source, unscaled,
                                                 &status)
                        : unscaled;
    }
    {
        const int softfloat_flags = get_float_exception_flags(&status);

        /* These transforms report only Invalid and Precision.  The
         * intermediate scale is architecturally unbounded and must not leak
         * SoftFloat overflow/underflow status into MXCSR. */
        if (softfloat_flags & float_flag_invalid) {
            *exception_flags |= EVEX_MXCSR_IE;
        }
        if (softfloat_flags & float_flag_inexact) {
            *exception_flags |= EVEX_MXCSR_PE;
        }
    }
    return result;
}

static void evex_fp_transform_apply(CPUX86State *env, uint32_t desc,
                                    const ZMMReg *second_source,
                                    uint32_t immediate)
{
    const int dst = (desc >> EVEX_FP_TRANSFORM_DST_SHIFT) &
                    EVEX_FP_TRANSFORM_REG_MASK;
    const int src1 = (desc >> EVEX_FP_TRANSFORM_SRC1_SHIFT) &
                     EVEX_FP_TRANSFORM_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_FP_TRANSFORM_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_FP_TRANSFORM_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_FP_TRANSFORM_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const EVEXFPTransformKind kind =
        (desc >> EVEX_FP_TRANSFORM_KIND_SHIFT) & EVEX_FP_TRANSFORM_KIND_MASK;
    const bool scalar = (desc & EVEX_FP_TRANSFORM_SCALAR) != 0;
    const int elements = scalar ? 1 : vector_bytes / element_bytes;
    const ZMMReg first_source = env->xmm_regs[src1];
    ZMMReg result = env->xmm_regs[dst];
    uint32_t exception_flags = 0;
    float_status base_status = env->fp_status;

    for (int element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            const uint64_t left = evex_integer_get_element(
                &first_source, element, element_bytes);
            uint64_t right = evex_integer_get_element(second_source, element,
                                                      element_bytes);
            uint64_t output;

            if (kind == EVEX_FP_TRANSFORM_FIXUP) {
                output = evex_fp_transform_fixup(
                    evex_integer_get_element(&result, element, element_bytes),
                    left, right, immediate, element_bytes == 8 ? 52 : 23,
                    element_bytes == 8 ? 11 : 8, env->mxcsr, &exception_flags);
            } else {
                const uint64_t sign_bit = element_bytes == 8
                    ? UINT64_C(0x8000000000000000) : UINT64_C(0x80000000);
                const uint64_t exponent_mask = element_bytes == 8
                    ? UINT64_C(0x7ff0000000000000) : UINT64_C(0x7f800000);

                /* DAZ applies to the floating-point source, and preserves
                 * its sign.  In particular, a negative denormal becomes -0.
                 */
                if ((env->mxcsr & EVEX_MXCSR_DAZ) &&
                    !(right & exponent_mask) && (right & ~sign_bit)) {
                    right &= sign_bit;
                }
                output = evex_fp_transform_round(
                    right, element_bytes == 8 ? 52 : 23,
                    element_bytes == 8 ? 11 : 8, immediate >> 4,
                    (immediate & 4) ? ((env->mxcsr >> 13) & 3)
                                    : (immediate & 3),
                    kind == EVEX_FP_TRANSFORM_REDUCE, base_status,
                    &exception_flags);
            }
            evex_integer_set_element(&result, element, element_bytes, output);
        } else if (desc & EVEX_FP_TRANSFORM_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }

    if (scalar) {
        for (int byte = element_bytes; byte < 16; ++byte) {
            result.ZMM_B(byte) = first_source.ZMM_B(byte);
        }
        for (int byte = 16; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    } else {
        for (int byte = vector_bytes; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    }

    if (kind != EVEX_FP_TRANSFORM_FIXUP && (immediate & (1U << 3))) {
        exception_flags &= ~EVEX_MXCSR_PE;
    }
    if (desc & EVEX_FP_TRANSFORM_SAE) {
        exception_flags = 0;
    }
    if (exception_flags) {
        const uint32_t exception_masks = (env->mxcsr >> 7) & 0x3f;
        const uint32_t unmasked = exception_flags & ~exception_masks;

        cpu_set_mxcsr(env, env->mxcsr | exception_flags);
        /* VFIXUP's imm8 reporting is sticky-only; it does not trap on the
         * corresponding MXCSR mask bits. */
        if (kind != EVEX_FP_TRANSFORM_FIXUP && unmasked) {
            if (!(env->cr[4] & CR4_OSXMMEXCPT_MASK)) {
                raise_exception_ra(env, EXCP06_ILLOP, GETPC());
            }
            raise_exception_ra(env, EXCP13_XM, GETPC());
        }
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_fp_transform_reg(CPUX86State *env, uint32_t desc,
                                  uint32_t immediate)
{
    const int src2 = (desc >> EVEX_FP_TRANSFORM_SRC2_SHIFT) &
                     EVEX_FP_TRANSFORM_REG_MASK;
    const ZMMReg second_source = env->xmm_regs[src2];

    evex_fp_transform_apply(env, desc, &second_source, immediate);
}

void helper_evex_fp_transform_load(CPUX86State *env, target_ulong address,
                                   uint32_t desc, uint32_t immediate)
{
    const int vector_bytes = 16 << ((desc >> EVEX_FP_TRANSFORM_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_FP_TRANSFORM_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_FP_TRANSFORM_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const bool scalar = (desc & EVEX_FP_TRANSFORM_SCALAR) != 0;
    const int elements = scalar ? 1 : vector_bytes / element_bytes;
    const uintptr_t ra = GETPC();
    ZMMReg memory_source = {0};

    if (desc & EVEX_FP_TRANSFORM_BROADCAST) {
        if (mask & ((UINT64_C(1) << elements) - 1)) {
            const uint64_t value =
                evex_vmovdqu_load_element(env, address, element_bytes, ra);
            for (int element = 0; element < elements; ++element) {
                if ((mask >> element) & 1) {
                    evex_integer_set_element(&memory_source, element,
                                             element_bytes, value);
                }
            }
        }
    } else {
        for (int element = 0; element < elements; ++element) {
            if ((mask >> element) & 1) {
                const uint64_t value = evex_vmovdqu_load_element(
                    env, address + element * element_bytes, element_bytes, ra);
                evex_integer_set_element(&memory_source, element, element_bytes,
                                         value);
            }
        }
    }
    evex_fp_transform_apply(env, desc, &memory_source, immediate);
}

static uint64_t evex_small_signed_to_float(int value, int fraction_bits,
                                           int exponent_bits)
{
    const uint64_t sign_bit = UINT64_C(1) << (fraction_bits + exponent_bits);
    const int exponent_bias = (1 << (exponent_bits - 1)) - 1;
    unsigned int magnitude;
    unsigned int probe;
    int highest = 0;
    uint64_t fraction;

    if (!value) {
        return 0;
    }
    magnitude = value < 0 ? (unsigned int)-value : (unsigned int)value;
    probe = magnitude;
    while (probe >>= 1) {
        ++highest;
    }
    fraction = ((uint64_t)magnitude - (UINT64_C(1) << highest))
               << (fraction_bits - highest);
    return (value < 0 ? sign_bit : 0) |
           ((uint64_t)(exponent_bias + highest) << fraction_bits) | fraction;
}

static uint64_t evex_getexp_lane(uint64_t input, int fraction_bits,
                                 int exponent_bits, uint32_t mxcsr,
                                 uint32_t *exception_flags)
{
    const uint64_t sign_bit = UINT64_C(1) << (fraction_bits + exponent_bits);
    const uint64_t exponent_mask = ((UINT64_C(1) << exponent_bits) - 1)
                                   << fraction_bits;
    const uint64_t fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const uint64_t quiet_bit = UINT64_C(1) << (fraction_bits - 1);
    const int exponent_bias = (1 << (exponent_bits - 1)) - 1;
    const uint64_t exponent_field = (input & exponent_mask) >> fraction_bits;
    const uint64_t fraction = input & fraction_mask;
    int unbiased_exponent;

    if (exponent_field == (UINT64_C(1) << exponent_bits) - 1) {
        if (fraction) {
            if (!(fraction & quiet_bit)) {
                *exception_flags |= EVEX_MXCSR_IE;
            }
            return input | quiet_bit;
        }
        return exponent_mask;
    }
    if (!exponent_field) {
        uint64_t probe;
        int highest = -1;

        if (!fraction || (mxcsr & EVEX_MXCSR_DAZ)) {
            return sign_bit | exponent_mask;
        }
        *exception_flags |= EVEX_MXCSR_DE;
        probe = fraction;
        while (probe) {
            ++highest;
            probe >>= 1;
        }
        unbiased_exponent = highest + 1 - exponent_bias - fraction_bits;
    } else {
        unbiased_exponent = (int)exponent_field - exponent_bias;
    }
    return evex_small_signed_to_float(unbiased_exponent, fraction_bits,
                                      exponent_bits);
}

static uint64_t evex_getmant_lane(uint64_t input, int fraction_bits,
                                  int exponent_bits, unsigned int immediate,
                                  uint32_t mxcsr,
                                  uint32_t *exception_flags)
{
    const uint64_t sign_bit = UINT64_C(1) << (fraction_bits + exponent_bits);
    const uint64_t exponent_mask = ((UINT64_C(1) << exponent_bits) - 1)
                                   << fraction_bits;
    const uint64_t fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const uint64_t quiet_bit = UINT64_C(1) << (fraction_bits - 1);
    const int exponent_bias = (1 << (exponent_bits - 1)) - 1;
    const uint64_t exponent_field = (input & exponent_mask) >> fraction_bits;
    uint64_t fraction = input & fraction_mask;
    const bool negative = (input & sign_bit) != 0;
    const unsigned int interval = immediate & 3;
    const unsigned int sign_control = (immediate >> 2) & 3;
    const uint64_t one = (uint64_t)exponent_bias << fraction_bits;
    const uint64_t signed_one = one | ((negative && !(sign_control & 1))
                                           ? sign_bit
                                           : 0);
    const uint64_t indefinite = sign_bit | exponent_mask | quiet_bit;
    int unbiased_exponent;
    bool signaling_bit;
    uint64_t output_exponent;
    uint64_t output_sign;

    if (exponent_field == (UINT64_C(1) << exponent_bits) - 1) {
        if (fraction) {
            if (!(fraction & quiet_bit)) {
                *exception_flags |= EVEX_MXCSR_IE;
            }
            return input | quiet_bit;
        }
        if (!negative) {
            return one;
        }
        if (sign_control & 2) {
            *exception_flags |= EVEX_MXCSR_IE;
            return indefinite;
        }
        return signed_one;
    }

    if (!exponent_field && (!fraction || (mxcsr & EVEX_MXCSR_DAZ))) {
        return negative ? signed_one : one;
    }
    if (negative && (sign_control & 2)) {
        *exception_flags |= EVEX_MXCSR_IE;
        return indefinite;
    }

    if (!exponent_field) {
        uint64_t probe = fraction;
        int highest = -1;
        int shift;

        while (probe) {
            ++highest;
            probe >>= 1;
        }
        shift = fraction_bits - highest;
        fraction = (fraction << shift) & fraction_mask;
        unbiased_exponent = highest + 1 - exponent_bias - fraction_bits;
        *exception_flags |= EVEX_MXCSR_DE;
    } else {
        unbiased_exponent = (int)exponent_field - exponent_bias;
    }

    signaling_bit = (fraction & quiet_bit) != 0;
    switch (interval) {
    case 0:
        output_exponent = exponent_bias;
        break;
    case 1:
        output_exponent = (unbiased_exponent % 2) != 0 ? exponent_bias - 1
                                                       : exponent_bias;
        break;
    case 2:
        output_exponent = exponent_bias - 1;
        break;
    default:
        output_exponent = signaling_bit ? exponent_bias - 1 : exponent_bias;
        break;
    }
    output_sign = negative && !(sign_control & 1) ? sign_bit : 0;
    return output_sign | (output_exponent << fraction_bits) | fraction;
}

static void evex_get_fp_apply(CPUX86State *env, uint32_t desc,
                              const ZMMReg *source)
{
    const int dst =
        (desc >> EVEX_GET_FP_DST_SHIFT) & EVEX_GET_FP_REG_MASK;
    const int src1 =
        (desc >> EVEX_GET_FP_SRC1_SHIFT) & EVEX_GET_FP_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_GET_FP_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_GET_FP_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_GET_FP_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const unsigned int immediate = (desc >> EVEX_GET_FP_IMM_SHIFT) & 15;
    const bool scalar = (desc & EVEX_GET_FP_SCALAR) != 0;
    const bool mantissa = (desc & EVEX_GET_FP_MANTISSA) != 0;
    const int elements = scalar ? 1 : vector_bytes / element_bytes;
    const ZMMReg upper_source = env->xmm_regs[src1];
    ZMMReg result = env->xmm_regs[dst];
    uint32_t exception_flags = 0;

    for (int element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            const uint64_t input =
                evex_integer_get_element(source, element, element_bytes);
            const uint64_t output =
                mantissa
                    ? (element_bytes == 8
                           ? evex_getmant_lane(input, 52, 11, immediate,
                                               env->mxcsr, &exception_flags)
                           : evex_getmant_lane((uint32_t)input, 23, 8,
                                               immediate, env->mxcsr,
                                               &exception_flags))
                    : (element_bytes == 8
                           ? evex_getexp_lane(input, 52, 11, env->mxcsr,
                                              &exception_flags)
                           : evex_getexp_lane((uint32_t)input, 23, 8,
                                              env->mxcsr, &exception_flags));

            evex_integer_set_element(&result, element, element_bytes, output);
        } else if (desc & EVEX_GET_FP_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }

    if (scalar) {
        for (int byte = element_bytes; byte < 16; ++byte) {
            result.ZMM_B(byte) = upper_source.ZMM_B(byte);
        }
        for (int byte = 16; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    } else {
        for (int byte = vector_bytes; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    }

    if (!(desc & EVEX_GET_FP_SAE) && exception_flags) {
        const uint32_t exception_masks = (env->mxcsr >> 7) & 0x3f;
        const uint32_t unmasked = exception_flags & ~exception_masks;

        cpu_set_mxcsr(env, env->mxcsr | exception_flags);
        if (unmasked) {
            if (!(env->cr[4] & CR4_OSXMMEXCPT_MASK)) {
                raise_exception_ra(env, EXCP06_ILLOP, GETPC());
            }
            raise_exception_ra(env, EXCP13_XM, GETPC());
        }
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_get_fp_reg(CPUX86State *env, uint32_t desc)
{
    const int src2 =
        (desc >> EVEX_GET_FP_SRC2_SHIFT) & EVEX_GET_FP_REG_MASK;
    const ZMMReg source = env->xmm_regs[src2];

    evex_get_fp_apply(env, desc, &source);
}

void helper_evex_get_fp_load(CPUX86State *env, target_ulong address,
                             uint32_t desc)
{
    const int vector_bytes = 16 << ((desc >> EVEX_GET_FP_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_GET_FP_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_GET_FP_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const bool scalar = (desc & EVEX_GET_FP_SCALAR) != 0;
    const int elements = scalar ? 1 : vector_bytes / element_bytes;
    const uintptr_t ra = GETPC();
    ZMMReg memory_source = {0};

    /* Stage every active element before computing any result or updating
     * MXCSR so a later memory fault cannot partially commit architectural
     * state. */
    if (desc & EVEX_GET_FP_BROADCAST) {
        if (mask & ((UINT64_C(1) << elements) - 1)) {
            const uint64_t value = evex_vmovdqu_load_element(
                env, address, element_bytes, ra);

            for (int element = 0; element < elements; ++element) {
                if ((mask >> element) & 1) {
                    evex_integer_set_element(&memory_source, element,
                                             element_bytes, value);
                }
            }
        }
    } else {
        for (int element = 0; element < elements; ++element) {
            if ((mask >> element) & 1) {
                const uint64_t value = evex_vmovdqu_load_element(
                    env, address + element * element_bytes, element_bytes,
                    ra);

                evex_integer_set_element(&memory_source, element,
                                         element_bytes, value);
            }
        }
    }
    evex_get_fp_apply(env, desc, &memory_source);
}

static bool evex_float_is_subnormal(uint64_t value, uint64_t exponent_mask,
                                    uint64_t fraction_mask)
{
    return !(value & exponent_mask) && (value & fraction_mask);
}

static int evex_scalef_floor(uint64_t value, int fraction_bits,
                             int exponent_bits, bool daz)
{
    const uint64_t sign_bit = UINT64_C(1) << (fraction_bits + exponent_bits);
    const uint64_t exponent_field =
        (value >> fraction_bits) & ((UINT64_C(1) << exponent_bits) - 1);
    const uint64_t fraction = value & ((UINT64_C(1) << fraction_bits) - 1);
    const int exponent_bias = (1 << (exponent_bits - 1)) - 1;
    int unbiased_exponent;
    int shift;
    uint64_t significand;
    uint64_t magnitude;
    bool discarded;

    if (!exponent_field) {
        if (!fraction || daz) {
            return 0;
        }
        return value & sign_bit ? -1 : 0;
    }

    unbiased_exponent = (int)exponent_field - exponent_bias;
    if (unbiased_exponent < 0) {
        return value & sign_bit ? -1 : 0;
    }
    /* SoftFloat also bounds scalbn's exponent adjustment to 16 bits. */
    if (unbiased_exponent >= 16) {
        return value & sign_bit ? -0x10000 : 0x10000;
    }

    significand = (UINT64_C(1) << fraction_bits) | fraction;
    shift = fraction_bits - unbiased_exponent;
    magnitude = significand >> shift;
    discarded = (significand & ((UINT64_C(1) << shift) - 1)) != 0;
    if (value & sign_bit) {
        return -(int)magnitude - (discarded ? 1 : 0);
    }
    return (int)magnitude;
}

static uint32_t evex_scalef_softfloat_flags(int flags)
{
    uint32_t result = 0;

    if (flags & float_flag_invalid) {
        result |= EVEX_MXCSR_IE;
    }
    if (flags & float_flag_overflow) {
        result |= EVEX_MXCSR_OE;
    }
    if (flags & float_flag_underflow) {
        result |= EVEX_MXCSR_UE;
    }
    if (flags & float_flag_inexact) {
        result |= EVEX_MXCSR_PE;
    }
    if (flags & float_flag_output_denormal) {
        result |= EVEX_MXCSR_UE | EVEX_MXCSR_PE;
    }
    return result;
}

static uint64_t evex_scalef_lane(uint64_t src1, uint64_t src2,
                                 int fraction_bits, int exponent_bits,
                                 unsigned int rounding_mode, uint32_t mxcsr,
                                 float_status base_status,
                                 uint32_t *exception_flags)
{
    const uint64_t sign_bit = UINT64_C(1) << (fraction_bits + exponent_bits);
    const uint64_t exponent_mask = ((UINT64_C(1) << exponent_bits) - 1)
                                   << fraction_bits;
    const uint64_t fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const uint64_t quiet_bit = UINT64_C(1) << (fraction_bits - 1);
    const uint64_t indefinite = fraction_bits == 52
                                    ? UINT64_C(0xfff8000000000000)
                                    : UINT64_C(0xffc00000);
    const bool src1_nan = evex_float_is_nan(src1, exponent_mask, fraction_mask);
    const bool src2_nan = evex_float_is_nan(src2, exponent_mask, fraction_mask);
    const bool src1_snan =
        evex_float_is_snan(src1, exponent_mask, fraction_mask, quiet_bit);
    const bool src2_snan =
        evex_float_is_snan(src2, exponent_mask, fraction_mask, quiet_bit);
    bool src1_inf;
    bool src2_inf;
    bool src2_negative;
    int scale;
    int softfloat_flags;

    /* NaN selection precedes the source-one denormal check.  In particular,
     * a NaN in source two suppresses the denormal exception for source one. */
    if (src1_nan || src2_nan) {
        if (src1_snan || src2_snan) {
            *exception_flags |= EVEX_MXCSR_IE;
        }
        return (src1_nan ? src1 : src2) | quiet_bit;
    }

    if (evex_float_is_subnormal(src1, exponent_mask, fraction_mask)) {
        if (mxcsr & EVEX_MXCSR_DAZ) {
            src1 &= sign_bit;
        } else {
            *exception_flags |= EVEX_MXCSR_DE;
        }
    }
    if ((mxcsr & EVEX_MXCSR_DAZ) &&
        evex_float_is_subnormal(src2, exponent_mask, fraction_mask)) {
        src2 &= sign_bit;
    }

    src1_inf = (src1 & ~sign_bit) == exponent_mask;
    src2_inf = (src2 & ~sign_bit) == exponent_mask;
    src2_negative = (src2 & sign_bit) != 0;
    if (src1_inf) {
        if (src2_inf && src2_negative) {
            *exception_flags |= EVEX_MXCSR_IE;
            return indefinite;
        }
        return src1;
    }
    if (!(src1 & ~sign_bit)) {
        if (src2_inf && !src2_negative) {
            *exception_flags |= EVEX_MXCSR_IE;
            return indefinite;
        }
        return src1;
    }
    if (src2_inf) {
        return (src1 & sign_bit) | (src2_negative ? 0 : exponent_mask);
    }

    scale = evex_scalef_floor(src2, fraction_bits, exponent_bits,
                              (mxcsr & EVEX_MXCSR_DAZ) != 0);
    set_float_exception_flags(0, &base_status);
    set_float_rounding_mode(rounding_mode, &base_status);
    /* DAZ has already been applied separately to both architectural inputs;
     * disabling SoftFloat input flushing prevents a spurious source-two DE. */
    set_flush_inputs_to_zero(false, &base_status);
    set_flush_to_zero((mxcsr & (1U << 15)) != 0, &base_status);
    if (fraction_bits == 52) {
        src1 = float64_val(
            float64_scalbn(make_float64(src1), scale, &base_status));
    } else {
        src1 = float32_val(
            float32_scalbn(make_float32((uint32_t)src1), scale, &base_status));
    }
    softfloat_flags = get_float_exception_flags(&base_status);
    *exception_flags |= evex_scalef_softfloat_flags(softfloat_flags);
    return src1;
}

static void evex_scalef_apply(CPUX86State *env, uint32_t desc,
                              const ZMMReg *second_source)
{
    const int dst = (desc >> EVEX_SCALEF_DST_SHIFT) & EVEX_SCALEF_REG_MASK;
    const int src1 = (desc >> EVEX_SCALEF_SRC1_SHIFT) & EVEX_SCALEF_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_SCALEF_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_SCALEF_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_SCALEF_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const unsigned int rounding_mode =
        (desc & EVEX_SCALEF_SAE)
            ? (desc >> EVEX_SCALEF_RC_SHIFT) & EVEX_SCALEF_RC_MASK
            : (env->mxcsr >> 13) & 3;
    const ZMMReg first_source = env->xmm_regs[src1];
    ZMMReg result = env->xmm_regs[dst];
    const bool scalar = (desc & EVEX_SCALEF_SCALAR) != 0;
    const int elements = scalar ? 1 : vector_bytes / element_bytes;
    uint32_t exception_flags = 0;

    for (int element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            const uint64_t left =
                evex_integer_get_element(&first_source, element, element_bytes);
            const uint64_t right =
                evex_integer_get_element(second_source, element, element_bytes);
            const uint64_t output =
                element_bytes == 8
                    ? evex_scalef_lane(left, right, 52, 11, rounding_mode,
                                       env->mxcsr, env->sse_status,
                                       &exception_flags)
                    : evex_scalef_lane((uint32_t)left, (uint32_t)right, 23, 8,
                                       rounding_mode, env->mxcsr,
                                       env->sse_status, &exception_flags);

            evex_integer_set_element(&result, element, element_bytes, output);
        } else if (desc & EVEX_SCALEF_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }

    if (scalar) {
        for (int byte = element_bytes; byte < 16; ++byte) {
            result.ZMM_B(byte) = first_source.ZMM_B(byte);
        }
        for (int byte = 16; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    } else {
        for (int byte = vector_bytes; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    }

    if (!(desc & EVEX_SCALEF_SAE) && exception_flags) {
        const uint32_t exception_masks = (env->mxcsr >> 7) & 0x3f;
        const uint32_t unmasked = exception_flags & ~exception_masks;

        cpu_set_mxcsr(env, env->mxcsr | exception_flags);
        if (unmasked) {
            if (!(env->cr[4] & CR4_OSXMMEXCPT_MASK)) {
                raise_exception_ra(env, EXCP06_ILLOP, GETPC());
            }
            raise_exception_ra(env, EXCP13_XM, GETPC());
        }
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_scalef_reg(CPUX86State *env, uint32_t desc)
{
    const int src2 = (desc >> EVEX_SCALEF_SRC2_SHIFT) & EVEX_SCALEF_REG_MASK;
    const ZMMReg second_source = env->xmm_regs[src2];

    evex_scalef_apply(env, desc, &second_source);
}

void helper_evex_scalef_load(CPUX86State *env, target_ulong address,
                             uint32_t desc)
{
    const int vector_bytes = 16 << ((desc >> EVEX_SCALEF_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_SCALEF_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_SCALEF_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const bool scalar = (desc & EVEX_SCALEF_SCALAR) != 0;
    const int elements = scalar ? 1 : vector_bytes / element_bytes;
    const uintptr_t ra = GETPC();
    ZMMReg memory_source = {0};

    /* Load every active element before computing any result or exception so
     * a later page fault cannot partially commit either destination or MXCSR.
     */
    if (desc & EVEX_SCALEF_BROADCAST) {
        if (mask & ((UINT64_C(1) << elements) - 1)) {
            const uint64_t value =
                evex_vmovdqu_load_element(env, address, element_bytes, ra);

            for (int element = 0; element < elements; ++element) {
                if ((mask >> element) & 1) {
                    evex_integer_set_element(&memory_source, element,
                                             element_bytes, value);
                }
            }
        }
    } else {
        for (int element = 0; element < elements; ++element) {
            if ((mask >> element) & 1) {
                const uint64_t value = evex_vmovdqu_load_element(
                    env, address + element * element_bytes, element_bytes, ra);

                evex_integer_set_element(&memory_source, element, element_bytes,
                                         value);
            }
        }
    }
    evex_scalef_apply(env, desc, &memory_source);
}

static void evex_approx28_apply(CPUX86State *env, uint32_t desc,
                                const ZMMReg *second_source)
{
    const int dst =
        (desc >> EVEX_APPROX28_DST_SHIFT) & EVEX_APPROX28_REG_MASK;
    const int src1 =
        (desc >> EVEX_APPROX28_SRC1_SHIFT) & EVEX_APPROX28_REG_MASK;
    const int element_bytes = (desc & EVEX_APPROX28_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_APPROX28_MASK_SHIFT) & 7;
    const uint64_t mask =
        mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const ZMMReg first_source = env->xmm_regs[src1];
    ZMMReg result = env->xmm_regs[dst];
    const bool scalar = (desc & EVEX_APPROX28_SCALAR) != 0;
    const int elements = scalar ? 1 : 64 / element_bytes;
    uint32_t exception_flags = 0;

    for (int element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            const uint64_t input = evex_integer_get_element(
                second_source, element, element_bytes);
            uint32_t lane_flags;
            uint64_t output;

            if (element_bytes == 8) {
                if (desc & EVEX_APPROX28_EXP2) {
                    output = x86_approx_exp2_f64(input, &lane_flags);
                } else if (desc & EVEX_APPROX28_RSQRT) {
                    output = x86_approx_rsqrt28_f64(input, &lane_flags);
                } else {
                    output = x86_approx_rcp28_f64(input, &lane_flags);
                }
            } else {
                if (desc & EVEX_APPROX28_EXP2) {
                    output = x86_approx_exp2_f32((uint32_t)input,
                                                 &lane_flags);
                } else if (desc & EVEX_APPROX28_RSQRT) {
                    output = x86_approx_rsqrt28_f32((uint32_t)input,
                                                    &lane_flags);
                } else {
                    output = x86_approx_rcp28_f32((uint32_t)input,
                                                  &lane_flags);
                }
            }
            exception_flags |= lane_flags;
            evex_integer_set_element(&result, element, element_bytes,
                                     output);
        } else if (desc & EVEX_APPROX28_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }

    if (scalar) {
        for (int byte = element_bytes; byte < 16; ++byte) {
            result.ZMM_B(byte) = first_source.ZMM_B(byte);
        }
        for (int byte = 16; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    }

    if (!(desc & EVEX_APPROX28_SAE) && exception_flags) {
        const uint32_t exception_masks = (env->mxcsr >> 7) & 0x3f;
        const uint32_t unmasked = exception_flags & ~exception_masks;

        cpu_set_mxcsr(env, env->mxcsr | exception_flags);
        if (unmasked) {
            if (!(env->cr[4] & CR4_OSXMMEXCPT_MASK)) {
                raise_exception_ra(env, EXCP06_ILLOP, GETPC());
            }
            raise_exception_ra(env, EXCP13_XM, GETPC());
        }
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_approx28_reg(CPUX86State *env, uint32_t desc)
{
    const int src2 =
        (desc >> EVEX_APPROX28_SRC2_SHIFT) & EVEX_APPROX28_REG_MASK;
    const ZMMReg second_source = env->xmm_regs[src2];

    evex_approx28_apply(env, desc, &second_source);
}

void helper_evex_approx28_load(CPUX86State *env, target_ulong address,
                               uint32_t desc)
{
    const int element_bytes = (desc & EVEX_APPROX28_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_APPROX28_MASK_SHIFT) & 7;
    const uint64_t mask =
        mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const bool scalar = (desc & EVEX_APPROX28_SCALAR) != 0;
    const int elements = scalar ? 1 : 64 / element_bytes;
    const uintptr_t ra = GETPC();
    ZMMReg memory_source = {0};

    /* Load every active element into temporary state before evaluating any
     * lane.  A later page fault therefore wins over SIMD exceptions and
     * cannot partially commit either destination or MXCSR. */
    if (desc & EVEX_APPROX28_BROADCAST) {
        if (mask & ((UINT64_C(1) << elements) - 1)) {
            const uint64_t value = evex_vmovdqu_load_element(
                env, address, element_bytes, ra);

            for (int element = 0; element < elements; ++element) {
                if ((mask >> element) & 1) {
                    evex_integer_set_element(&memory_source, element,
                                             element_bytes, value);
                }
            }
        }
    } else {
        for (int element = 0; element < elements; ++element) {
            if ((mask >> element) & 1) {
                const uint64_t value = evex_vmovdqu_load_element(
                    env, address + element * element_bytes, element_bytes,
                    ra);
                evex_integer_set_element(&memory_source, element,
                                         element_bytes, value);
            }
        }
    }
    evex_approx28_apply(env, desc, &memory_source);
}

static uint64_t evex_vmovdqu_load_element(CPUX86State *env,
                                          target_ulong address,
                                          int element_bytes, uintptr_t ra)
{
    switch (element_bytes) {
    case 1:
        return cpu_ldub_data_ra(env, address, ra);
    case 2:
        return cpu_lduw_data_ra(env, address, ra);
    case 4:
        return cpu_ldl_data_ra(env, address, ra);
    case 8:
        return cpu_ldq_data_ra(env, address, ra);
    default:
        g_assert_not_reached();
    }
}

static uint32_t evex_fp_arith_softfloat_flags(int flags)
{
    uint32_t result = 0;

    if (flags & float_flag_invalid) {
        result |= EVEX_MXCSR_IE;
    }
    if (flags & float_flag_input_denormal) {
        result |= EVEX_MXCSR_DE;
    }
    if (flags & float_flag_divbyzero) {
        result |= EVEX_MXCSR_ZE;
    }
    if (flags & float_flag_overflow) {
        result |= EVEX_MXCSR_OE;
    }
    if (flags & float_flag_underflow) {
        result |= EVEX_MXCSR_UE;
    }
    if (flags & float_flag_inexact) {
        result |= EVEX_MXCSR_PE;
    }
    if (flags & float_flag_output_denormal) {
        result |= EVEX_MXCSR_UE | EVEX_MXCSR_PE;
    }
    return result;
}

static uint64_t evex_fp_arith_lane(EVEXFPArithOp operation, uint64_t left,
                                    uint64_t right, int element_bytes,
                                    float_status *status)
{
    if (element_bytes == 8) {
        switch (operation) {
        case EVEX_FP_ARITH_ADD:
            return float64_add(left, right, status);
        case EVEX_FP_ARITH_SUB:
            return float64_sub(left, right, status);
        case EVEX_FP_ARITH_MUL:
            return float64_mul(left, right, status);
        case EVEX_FP_ARITH_DIV:
            return float64_div(left, right, status);
        case EVEX_FP_ARITH_MIN:
            return float64_lt(left, right, status) ? left : right;
        case EVEX_FP_ARITH_MAX:
            return float64_lt(right, left, status) ? left : right;
        case EVEX_FP_ARITH_SQRT:
            return float64_sqrt(right, status);
        default:
            g_assert_not_reached();
        }
    }

    switch (operation) {
    case EVEX_FP_ARITH_ADD:
        return float32_add((uint32_t)left, (uint32_t)right, status);
    case EVEX_FP_ARITH_SUB:
        return float32_sub((uint32_t)left, (uint32_t)right, status);
    case EVEX_FP_ARITH_MUL:
        return float32_mul((uint32_t)left, (uint32_t)right, status);
    case EVEX_FP_ARITH_DIV:
        return float32_div((uint32_t)left, (uint32_t)right, status);
    case EVEX_FP_ARITH_MIN:
        return float32_lt((uint32_t)left, (uint32_t)right, status)
                   ? (uint32_t)left
                   : (uint32_t)right;
    case EVEX_FP_ARITH_MAX:
        return float32_lt((uint32_t)right, (uint32_t)left, status)
                   ? (uint32_t)left
                   : (uint32_t)right;
    case EVEX_FP_ARITH_SQRT:
        return float32_sqrt((uint32_t)right, status);
    default:
        g_assert_not_reached();
    }
}

static void evex_fp_arith_apply(CPUX86State *env, uint32_t desc,
                                const ZMMReg *second_source)
{
    const int dst =
        (desc >> EVEX_FP_ARITH_DST_SHIFT) & EVEX_FP_ARITH_REG_MASK;
    const int src1 =
        (desc >> EVEX_FP_ARITH_SRC1_SHIFT) & EVEX_FP_ARITH_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_FP_ARITH_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_FP_ARITH_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_FP_ARITH_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const EVEXFPArithOp operation =
        (desc >> EVEX_FP_ARITH_OP_SHIFT) & EVEX_FP_ARITH_OP_MASK;
    const bool scalar = (desc & EVEX_FP_ARITH_SCALAR) != 0;
    const bool sae = (desc & EVEX_FP_ARITH_SAE) != 0;
    const int elements = scalar ? 1 : vector_bytes / element_bytes;
    const ZMMReg first_source = env->xmm_regs[src1];
    ZMMReg result = env->xmm_regs[dst];
    float_status status = env->sse_status;
    uint32_t exception_flags;

    set_float_exception_flags(0, &status);
    if (sae) {
        set_float_rounding_mode(
            (desc >> EVEX_FP_ARITH_RC_SHIFT) & EVEX_FP_ARITH_RC_MASK,
            &status);
    }

    for (int element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            const uint64_t left = evex_integer_get_element(
                &first_source, element, element_bytes);
            const uint64_t right = evex_integer_get_element(
                second_source, element, element_bytes);
            const uint64_t output = evex_fp_arith_lane(
                operation, left, right, element_bytes, &status);

            evex_integer_set_element(&result, element, element_bytes, output);
        } else if (desc & EVEX_FP_ARITH_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }

    if (scalar) {
        for (int byte = element_bytes; byte < 16; ++byte) {
            result.ZMM_B(byte) = first_source.ZMM_B(byte);
        }
        for (int byte = 16; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    } else {
        for (int byte = vector_bytes; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    }

    exception_flags = evex_fp_arith_softfloat_flags(
        get_float_exception_flags(&status));
    if (!sae && exception_flags) {
        const uint32_t exception_masks = (env->mxcsr >> 7) & 0x3f;
        const uint32_t unmasked = exception_flags & ~exception_masks;

        cpu_set_mxcsr(env, env->mxcsr | exception_flags);
        if (unmasked) {
            if (!(env->cr[4] & CR4_OSXMMEXCPT_MASK)) {
                raise_exception_ra(env, EXCP06_ILLOP, GETPC());
            }
            raise_exception_ra(env, EXCP13_XM, GETPC());
        }
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_fp_arith_reg(CPUX86State *env, uint32_t desc)
{
    const int src2 =
        (desc >> EVEX_FP_ARITH_SRC2_SHIFT) & EVEX_FP_ARITH_REG_MASK;
    const ZMMReg second_source = env->xmm_regs[src2];

    evex_fp_arith_apply(env, desc, &second_source);
}

void helper_evex_fp_arith_load(CPUX86State *env, target_ulong address,
                               uint32_t desc)
{
    const int vector_bytes = 16 << ((desc >> EVEX_FP_ARITH_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_FP_ARITH_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_FP_ARITH_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const bool scalar = (desc & EVEX_FP_ARITH_SCALAR) != 0;
    const int elements = scalar ? 1 : vector_bytes / element_bytes;
    const uintptr_t ra = GETPC();
    ZMMReg memory_source = {0};

    /* Stage active elements first.  Writemasking therefore suppresses faults
     * and no architectural result is committed if a later load faults. */
    if (desc & EVEX_FP_ARITH_BROADCAST) {
        if (mask & ((UINT64_C(1) << elements) - 1)) {
            const uint64_t value = evex_vmovdqu_load_element(
                env, address, element_bytes, ra);

            for (int element = 0; element < elements; ++element) {
                if ((mask >> element) & 1) {
                    evex_integer_set_element(&memory_source, element,
                                             element_bytes, value);
                }
            }
        }
    } else {
        for (int element = 0; element < elements; ++element) {
            if ((mask >> element) & 1) {
                const uint64_t value = evex_vmovdqu_load_element(
                    env, address + element * element_bytes, element_bytes,
                    ra);

                evex_integer_set_element(&memory_source, element,
                                         element_bytes, value);
            }
        }
    }
    evex_fp_arith_apply(env, desc, &memory_source);
}

static int evex_fma_lane_flags(unsigned int variant, int element)
{
    if (variant == 4) {
        return (element & 1) ? 0 : float_muladd_negate_c;
    }
    if (variant == 5) {
        return (element & 1) ? float_muladd_negate_c : 0;
    }
    return (variant & 1 ? float_muladd_negate_c : 0) |
           (variant & 2 ? float_muladd_negate_product : 0);
}

static uint32_t evex_fma32(float_status *status, uint32_t a, uint32_t b,
                           uint32_t c, int flags)
{
    const flag ftz = get_flush_to_zero(status);
    const int old_flags = get_float_exception_flags(status);
    int new_flags;
    uint32_t result;

    set_float_exception_flags(0, status);
    if (ftz) {
        set_flush_to_zero(false, status);
    }
    result = float32_muladd(a, b, c, flags, status);
    new_flags = get_float_exception_flags(status);
    if (!get_flush_inputs_to_zero(status) &&
        (((a & UINT32_C(0x7f800000)) == 0 &&
          (a & UINT32_C(0x007fffff)) != 0) ||
         ((b & UINT32_C(0x7f800000)) == 0 &&
          (b & UINT32_C(0x007fffff)) != 0) ||
         ((c & UINT32_C(0x7f800000)) == 0 &&
          (c & UINT32_C(0x007fffff)) != 0))) {
        new_flags |= float_flag_input_denormal;
    }
    if (ftz && (result & UINT32_C(0x7f800000)) == 0 &&
        (result & UINT32_C(0x007fffff)) != 0) {
        result &= UINT32_C(0x80000000);
        new_flags |= float_flag_output_denormal;
    }
    if (ftz) {
        set_flush_to_zero(true, status);
    }
    set_float_exception_flags(old_flags | new_flags, status);
    return result;
}

static uint64_t evex_fma64(float_status *status, uint64_t a, uint64_t b,
                           uint64_t c, int flags)
{
    const flag ftz = get_flush_to_zero(status);
    const int old_flags = get_float_exception_flags(status);
    int new_flags;
    uint64_t result;

    set_float_exception_flags(0, status);
    if (ftz) {
        set_flush_to_zero(false, status);
    }
    result = float64_muladd(a, b, c, flags, status);
    new_flags = get_float_exception_flags(status);
    if (!get_flush_inputs_to_zero(status) &&
        (((a & UINT64_C(0x7ff0000000000000)) == 0 &&
          (a & UINT64_C(0x000fffffffffffff)) != 0) ||
         ((b & UINT64_C(0x7ff0000000000000)) == 0 &&
          (b & UINT64_C(0x000fffffffffffff)) != 0) ||
         ((c & UINT64_C(0x7ff0000000000000)) == 0 &&
          (c & UINT64_C(0x000fffffffffffff)) != 0))) {
        new_flags |= float_flag_input_denormal;
    }
    if (ftz && (result & UINT64_C(0x7ff0000000000000)) == 0 &&
        (result & UINT64_C(0x000fffffffffffff)) != 0) {
        result &= UINT64_C(0x8000000000000000);
        new_flags |= float_flag_output_denormal;
    }
    if (ftz) {
        set_flush_to_zero(true, status);
    }
    set_float_exception_flags(old_flags | new_flags, status);
    return result;
}

static void evex_fma_apply(CPUX86State *env, uint32_t desc,
                           const ZMMReg *third_source)
{
    const int dst = (desc >> EVEX_FMA_DST_SHIFT) & EVEX_FMA_REG_MASK;
    const int src1 = (desc >> EVEX_FMA_SRC1_SHIFT) & EVEX_FMA_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_FMA_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_FMA_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_FMA_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const unsigned int permutation = (desc >> EVEX_FMA_PERM_SHIFT) & 3;
    const unsigned int variant =
        (desc >> EVEX_FMA_VARIANT_SHIFT) & EVEX_FMA_VARIANT_MASK;
    const bool scalar = (desc & EVEX_FMA_SCALAR) != 0;
    const bool sae = (desc & EVEX_FMA_SAE) != 0;
    const int elements = scalar ? 1 : vector_bytes / element_bytes;
    const ZMMReg old_destination = env->xmm_regs[dst];
    const ZMMReg second_source = env->xmm_regs[src1];
    ZMMReg result = old_destination;
    float_status status = env->sse_status;
    uint32_t exception_flags;

    set_float_exception_flags(0, &status);
    if (sae) {
        set_float_rounding_mode((desc >> EVEX_FMA_RC_SHIFT) & EVEX_FMA_RC_MASK,
                                &status);
    }

    for (int element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            const uint64_t first = evex_integer_get_element(
                &old_destination, element, element_bytes);
            const uint64_t second = evex_integer_get_element(
                &second_source, element, element_bytes);
            const uint64_t third = evex_integer_get_element(
                third_source, element, element_bytes);
            uint64_t a, b, c;
            uint64_t output;

            switch (permutation) {
            case 0: /* 132: first * third + second. */
                a = first;
                b = third;
                c = second;
                break;
            case 1: /* 213: second * first + third. */
                a = second;
                b = first;
                c = third;
                break;
            case 2: /* 231: second * third + first. */
                a = second;
                b = third;
                c = first;
                break;
            default:
                g_assert_not_reached();
            }
            output = element_bytes == 8
                         ? evex_fma64(&status, a, b, c,
                                      evex_fma_lane_flags(variant, element))
                         : evex_fma32(&status, a, b, c,
                                      evex_fma_lane_flags(variant, element));
            evex_integer_set_element(&result, element, element_bytes, output);
        } else if (desc & EVEX_FMA_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }

    if (scalar) {
        for (int byte = 16; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    } else {
        for (int byte = vector_bytes; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    }

    exception_flags = evex_fp_arith_softfloat_flags(
        get_float_exception_flags(&status));
    if (!sae && exception_flags) {
        const uint32_t exception_masks = (env->mxcsr >> 7) & 0x3f;
        const uint32_t unmasked = exception_flags & ~exception_masks;

        cpu_set_mxcsr(env, env->mxcsr | exception_flags);
        if (unmasked) {
            if (!(env->cr[4] & CR4_OSXMMEXCPT_MASK)) {
                raise_exception_ra(env, EXCP06_ILLOP, GETPC());
            }
            raise_exception_ra(env, EXCP13_XM, GETPC());
        }
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_fma_reg(CPUX86State *env, uint32_t desc)
{
    const int src2 = (desc >> EVEX_FMA_SRC2_SHIFT) & EVEX_FMA_REG_MASK;
    const ZMMReg third_source = env->xmm_regs[src2];

    evex_fma_apply(env, desc, &third_source);
}

void helper_evex_fma_load(CPUX86State *env, target_ulong address,
                          uint32_t desc)
{
    const int vector_bytes = 16 << ((desc >> EVEX_FMA_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_FMA_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_FMA_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const bool scalar = (desc & EVEX_FMA_SCALAR) != 0;
    const int elements = scalar ? 1 : vector_bytes / element_bytes;
    const uintptr_t ra = GETPC();
    ZMMReg memory_source = {0};

    if (desc & EVEX_FMA_BROADCAST) {
        if (mask & ((UINT64_C(1) << elements) - 1)) {
            const uint64_t value = evex_vmovdqu_load_element(
                env, address, element_bytes, ra);

            for (int element = 0; element < elements; ++element) {
                if ((mask >> element) & 1) {
                    evex_integer_set_element(&memory_source, element,
                                             element_bytes, value);
                }
            }
        }
    } else {
        for (int element = 0; element < elements; ++element) {
            if ((mask >> element) & 1) {
                const uint64_t value = evex_vmovdqu_load_element(
                    env, address + element * element_bytes, element_bytes,
                    ra);

                evex_integer_set_element(&memory_source, element,
                                         element_bytes, value);
            }
        }
    }
    evex_fma_apply(env, desc, &memory_source);
}

static void evex_four_raise_unmasked(CPUX86State *env,
                                     float_status *status)
{
    const uint32_t exception_flags = evex_fp_arith_softfloat_flags(
        get_float_exception_flags(status));

    if (exception_flags) {
        const uint32_t exception_masks = (env->mxcsr >> 7) & 0x3f;
        const uint32_t unmasked = exception_flags & ~exception_masks;

        cpu_set_mxcsr(env, env->mxcsr | exception_flags);
        if (unmasked) {
            if (!(env->cr[4] & CR4_OSXMMEXCPT_MASK)) {
                raise_exception_ra(env, EXCP06_ILLOP, GETPC());
            }
            raise_exception_ra(env, EXCP13_XM, GETPC());
        }
    }
}

void helper_evex_four_fma_load(CPUX86State *env, target_ulong address,
                               uint32_t desc)
{
    const int dst = (desc >> EVEX_FOUR_DST_SHIFT) & EVEX_FOUR_REG_MASK;
    const int source_base =
        ((desc >> EVEX_FOUR_SRC_SHIFT) & EVEX_FOUR_REG_MASK) & ~3;
    const int mask_reg = (desc >> EVEX_FOUR_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const bool scalar = (desc & EVEX_FOUR_SCALAR) != 0;
    const int elements = scalar ? 1 : 16;
    const uint64_t active_mask = mask & ((UINT64_C(1) << elements) - 1);
    const uintptr_t ra = GETPC();
    ZMMReg result = env->xmm_regs[dst];
    uint32_t memory[4] = {0};
    float_status status = env->sse_status;

    /* Tuple1_4X fault suppression is all-or-nothing for the 16-byte source. */
    if (active_mask) {
        for (int index = 0; index < 4; ++index) {
            memory[index] = cpu_ldl_data_ra(env, address + 4 * index, ra);
        }
    }
    set_float_exception_flags(0, &status);
    for (int source = 0; source < 4; ++source) {
        for (int element = 0; element < elements; ++element) {
            if ((mask >> element) & 1) {
                const uint32_t multiplier =
                    env->xmm_regs[source_base + source].ZMM_L(element);
                const uint32_t accumulator = result.ZMM_L(element);
                const int flags = (desc & EVEX_FOUR_NEGATIVE)
                                      ? float_muladd_negate_product
                                      : 0;

                result.ZMM_L(element) = evex_fma32(
                    &status, multiplier, memory[source], accumulator, flags);
                /* These instructions define exception priority at each
                 * sequential FMA boundary, not after a vector aggregate. */
                evex_four_raise_unmasked(env, &status);
            } else if (desc & EVEX_FOUR_ZERO) {
                result.ZMM_L(element) = 0;
            }
        }
    }
    if (scalar) {
        for (int byte = 16; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    }
    evex_four_raise_unmasked(env, &status);
    evex_commit_zmm(env, dst, &result);
}

static int32_t evex_signed_dword_saturate(int64_t value)
{
    if (value > INT32_MAX) {
        return INT32_MAX;
    }
    if (value < INT32_MIN) {
        return INT32_MIN;
    }
    return (int32_t)value;
}

void helper_evex_four_vnni_load(CPUX86State *env, target_ulong address,
                                uint32_t desc)
{
    const int dst = (desc >> EVEX_FOUR_DST_SHIFT) & EVEX_FOUR_REG_MASK;
    const int source_base =
        ((desc >> EVEX_FOUR_SRC_SHIFT) & EVEX_FOUR_REG_MASK) & ~3;
    const int mask_reg = (desc >> EVEX_FOUR_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const uintptr_t ra = GETPC();
    ZMMReg result = env->xmm_regs[dst];
    uint32_t memory[4] = {0};

    /* Any active dword makes the complete Tuple1_4X source accessible. */
    if (mask & UINT64_C(0xffff)) {
        for (int index = 0; index < 4; ++index) {
            memory[index] = cpu_ldl_data_ra(env, address + 4 * index, ra);
        }
    }
    for (int element = 0; element < 16; ++element) {
        if ((mask >> element) & 1) {
            uint32_t accumulator = result.ZMM_L(element);

            for (int source = 0; source < 4; ++source) {
                const uint32_t source_dword =
                    env->xmm_regs[source_base + source].ZMM_L(element);
                const int64_t products =
                    (int64_t)(int16_t)source_dword *
                        (int64_t)(int16_t)memory[source] +
                    (int64_t)(int16_t)(source_dword >> 16) *
                        (int64_t)(int16_t)(memory[source] >> 16);

                if (desc & EVEX_FOUR_SATURATING) {
                    accumulator = (uint32_t)evex_signed_dword_saturate(
                        (int64_t)(int32_t)accumulator + products);
                } else {
                    accumulator += (uint32_t)products;
                }
            }
            result.ZMM_L(element) = accumulator;
        } else if (desc & EVEX_FOUR_ZERO) {
            result.ZMM_L(element) = 0;
        }
    }
    evex_commit_zmm(env, dst, &result);
}

static bool evex_fpclass_lane(uint64_t value, int element_bytes,
                              uint32_t immediate, bool daz)
{
    const int fraction_bits = element_bytes == 8 ? 52 : 23;
    const int exponent_bits = element_bytes == 8 ? 11 : 8;
    const uint64_t fraction_mask =
        (UINT64_C(1) << fraction_bits) - 1;
    const uint64_t exponent_mask =
        (UINT64_C(1) << exponent_bits) - 1;
    const uint64_t fraction = value & fraction_mask;
    const uint64_t exponent =
        (value >> fraction_bits) & exponent_mask;
    const bool negative = (value >> (element_bytes * 8 - 1)) != 0;
    const bool exponent_zero = exponent == 0;
    const bool exponent_ones = exponent == exponent_mask;
    const bool fraction_zero = fraction == 0 || (daz && exponent_zero);
    uint32_t classes = 0;

    if (exponent_ones && !fraction_zero) {
        classes = (fraction >> (fraction_bits - 1)) & 1 ? 1U << 0
                                                        : 1U << 7;
    } else if (exponent_zero && fraction_zero) {
        classes = negative ? 1U << 2 : 1U << 1;
    } else if (exponent_ones) {
        classes = negative ? 1U << 4 : 1U << 3;
    } else if (exponent_zero) {
        classes = 1U << 5;
        if (negative) {
            classes |= 1U << 6;
        }
    } else if (negative) {
        classes = 1U << 6;
    } else {
        return false;
    }
    return (immediate & classes) != 0;
}

static void evex_fpclass_apply(CPUX86State *env, uint32_t desc,
                               uint32_t immediate, const ZMMReg *source)
{
    const int dst = (desc >> EVEX_FPCLASS_DST_SHIFT) & 7;
    const int vector_bytes = 16 << ((desc >> EVEX_FPCLASS_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_FPCLASS_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_FPCLASS_MASK_SHIFT) & 7;
    const uint64_t write_mask =
        mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const int elements = (desc & EVEX_FPCLASS_SCALAR)
                             ? 1
                             : vector_bytes / element_bytes;
    const bool daz = (env->mxcsr & EVEX_MXCSR_DAZ) != 0;
    uint64_t result = 0;

    for (int element = 0; element < elements; ++element) {
        if (((write_mask >> element) & 1) &&
            evex_fpclass_lane(
                evex_integer_get_element(source, element, element_bytes),
                element_bytes, immediate, daz)) {
            result |= UINT64_C(1) << element;
        }
    }
    evex_commit_opmask(env, dst, result);
}

void helper_evex_fpclass_reg(CPUX86State *env, uint32_t desc,
                             uint32_t immediate)
{
    const int src =
        (desc >> EVEX_FPCLASS_SRC_SHIFT) & EVEX_FPCLASS_REG_MASK;

    evex_fpclass_apply(env, desc, immediate, &env->xmm_regs[src]);
}

void helper_evex_fpclass_load(CPUX86State *env, target_ulong address,
                              uint32_t desc, uint32_t immediate)
{
    const int vector_bytes = 16 << ((desc >> EVEX_FPCLASS_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_FPCLASS_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_FPCLASS_MASK_SHIFT) & 7;
    const uint64_t write_mask =
        mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const int elements = (desc & EVEX_FPCLASS_SCALAR)
                             ? 1
                             : vector_bytes / element_bytes;
    const uintptr_t ra = GETPC();
    ZMMReg source = {0};

    if (desc & EVEX_FPCLASS_BROADCAST) {
        if (write_mask & ((UINT64_C(1) << elements) - 1)) {
            const uint64_t value = evex_vmovdqu_load_element(
                env, address, element_bytes, ra);

            for (int element = 0; element < elements; ++element) {
                if ((write_mask >> element) & 1) {
                    evex_integer_set_element(&source, element,
                                             element_bytes, value);
                }
            }
        }
    } else {
        for (int element = 0; element < elements; ++element) {
            if ((write_mask >> element) & 1) {
                const uint64_t value = evex_vmovdqu_load_element(
                    env, address + element * element_bytes,
                    element_bytes, ra);

                evex_integer_set_element(&source, element,
                                         element_bytes, value);
            }
        }
    }
    evex_fpclass_apply(env, desc, immediate, &source);
}

static void evex_comi_apply(CPUX86State *env, uint32_t desc,
                            uint64_t right)
{
    static const uint32_t flags[4] = {
        CC_C, CC_Z, 0, CC_Z | CC_P | CC_C
    };
    const int left_reg =
        (desc >> EVEX_COMI_LEFT_SHIFT) & EVEX_COMI_REG_MASK;
    const bool is_double = (desc & EVEX_COMI_DOUBLE) != 0;
    const uint64_t left = evex_integer_get_element(
        &env->xmm_regs[left_reg], 0, is_double ? 8 : 4);
    float_status status = env->sse_status;
    int relation;
    uint32_t exception_flags;

    set_float_exception_flags(0, &status);
    if (is_double) {
        relation = (desc & EVEX_COMI_QUIET)
                       ? float64_compare_quiet(left, right, &status)
                       : float64_compare(left, right, &status);
    } else {
        relation = (desc & EVEX_COMI_QUIET)
                       ? float32_compare_quiet((uint32_t)left,
                                               (uint32_t)right, &status)
                       : float32_compare((uint32_t)left,
                                         (uint32_t)right, &status);
    }
    exception_flags = evex_fp_arith_softfloat_flags(
        get_float_exception_flags(&status));
    if (!(desc & EVEX_COMI_SAE) && exception_flags) {
        const uint32_t exception_masks = (env->mxcsr >> 7) & 0x3f;
        const uint32_t unmasked = exception_flags & ~exception_masks;

        cpu_set_mxcsr(env, env->mxcsr | exception_flags);
        /* Architectural flags remain unchanged when a SIMD exception is
         * delivered. */
        if (unmasked) {
            if (!(env->cr[4] & CR4_OSXMMEXCPT_MASK)) {
                raise_exception_ra(env, EXCP06_ILLOP, GETPC());
            }
            raise_exception_ra(env, EXCP13_XM, GETPC());
        }
    }
    env->cc_src = flags[relation + 1];
}

void helper_evex_comi_reg(CPUX86State *env, uint32_t desc)
{
    const int right_reg =
        (desc >> EVEX_COMI_RIGHT_SHIFT) & EVEX_COMI_REG_MASK;
    const int element_bytes = (desc & EVEX_COMI_DOUBLE) ? 8 : 4;

    evex_comi_apply(
        env, desc,
        evex_integer_get_element(&env->xmm_regs[right_reg], 0,
                                 element_bytes));
}

void helper_evex_comi_load(CPUX86State *env, target_ulong address,
                           uint32_t desc)
{
    const int element_bytes = (desc & EVEX_COMI_DOUBLE) ? 8 : 4;

    evex_comi_apply(
        env, desc,
        evex_vmovdqu_load_element(env, address, element_bytes, GETPC()));
}

static bool evex_fcmp_predicate_is_signaling(uint32_t predicate)
{
    static const bool signaling[32] = {
        false, true,  true,  false, false, true,  true,  false,
        false, true,  true,  false, false, true,  true,  false,
        true,  false, false, true,  true,  false, false, true,
        true,  false, false, true,  true,  false, false, true,
    };

    return signaling[predicate & 0x1f];
}

static bool evex_fcmp_predicate_matches(uint32_t predicate, int relation)
{
    /* Bits are ordered as less, equal, greater, unordered.  Predicates
     * 16..31 have the same truth table as 0..15 and differ only in their
     * quiet/signaling NaN behavior. */
    static const uint8_t truth[16] = {
        0x2, 0x1, 0x3, 0x8, 0xd, 0xe, 0xc, 0x7,
        0xa, 0x9, 0xb, 0x0, 0x5, 0x6, 0x4, 0xf,
    };
    const unsigned int relation_bit = (unsigned int)(relation + 1);

    g_assert(relation_bit < 4);
    return ((truth[predicate & 0xf] >> relation_bit) & 1) != 0;
}

#ifdef TARGET_X86_64
static bool x86_canonical_address(CPUX86State *env, uint64_t address);
#endif

static int evex_fcmp_lane(uint64_t left, uint64_t right, int element_bytes,
                          bool signaling, bool daz, float_status *status)
{
    if (element_bytes == 8) {
        const bool unordered = float64_is_any_nan(left) ||
                               float64_is_any_nan(right);

        if (!unordered) {
            const bool denormal = float64_is_denormal(left) ||
                                  float64_is_denormal(right);

            if (daz) {
                if (float64_is_denormal(left)) {
                    left &= UINT64_C(0x8000000000000000);
                }
                if (float64_is_denormal(right)) {
                    right &= UINT64_C(0x8000000000000000);
                }
            } else if (denormal) {
                set_float_exception_flags(
                    get_float_exception_flags(status) |
                        float_flag_input_denormal,
                    status);
            }
        }
        return signaling ? float64_compare(left, right, status)
                         : float64_compare_quiet(left, right, status);
    }
    {
        uint32_t left32 = left;
        uint32_t right32 = right;
        const bool unordered = float32_is_any_nan(left32) ||
                               float32_is_any_nan(right32);

        if (!unordered) {
            const bool denormal = float32_is_denormal(left32) ||
                                  float32_is_denormal(right32);

            if (daz) {
                if (float32_is_denormal(left32)) {
                    left32 &= UINT32_C(0x80000000);
                }
                if (float32_is_denormal(right32)) {
                    right32 &= UINT32_C(0x80000000);
                }
            } else if (denormal) {
                set_float_exception_flags(
                    get_float_exception_flags(status) |
                        float_flag_input_denormal,
                    status);
            }
        }
        return signaling ? float32_compare(left32, right32, status)
                         : float32_compare_quiet(left32, right32, status);
    }
}

static void evex_fcmp_apply(CPUX86State *env, uint32_t desc,
                            uint32_t immediate, const ZMMReg *right_source)
{
    const int dst = (desc >> EVEX_FCMP_DST_SHIFT) & 7;
    const int src1 =
        (desc >> EVEX_FCMP_SRC1_SHIFT) & EVEX_FCMP_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_FCMP_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_FCMP_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_FCMP_MASK_SHIFT) & 7;
    const uint64_t write_mask =
        mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const int elements = (desc & EVEX_FCMP_SCALAR)
                             ? 1
                             : vector_bytes / element_bytes;
    const bool signaling = evex_fcmp_predicate_is_signaling(immediate);
    const bool daz = (env->mxcsr & EVEX_MXCSR_DAZ) != 0;
    float_status status = env->sse_status;
    uint64_t result = 0;
    uint32_t exception_flags;

    set_float_exception_flags(0, &status);
    /* Apply DAZ explicitly below.  SoftFloat only reports an input denormal
     * while flushing it, whereas x86 comparisons also report DE with DAZ
     * clear.  Explicit handling also preserves the architectural rule that
     * a NaN in the same lane takes priority over a denormal operand. */
    set_flush_inputs_to_zero(false, &status);
    for (int element = 0; element < elements; ++element) {
        int relation;

        if (!((write_mask >> element) & 1)) {
            continue;
        }
        relation = evex_fcmp_lane(
            evex_integer_get_element(&env->xmm_regs[src1], element,
                                     element_bytes),
            evex_integer_get_element(right_source, element, element_bytes),
            element_bytes, signaling, daz, &status);
        if (evex_fcmp_predicate_matches(immediate, relation)) {
            result |= UINT64_C(1) << element;
        }
    }

    exception_flags = evex_fp_arith_softfloat_flags(
        get_float_exception_flags(&status));
    if (!(desc & EVEX_FCMP_SAE) && exception_flags) {
        const uint32_t exception_masks = (env->mxcsr >> 7) & 0x3f;
        const uint32_t unmasked = exception_flags & ~exception_masks;

        cpu_set_mxcsr(env, env->mxcsr | exception_flags);
        /* The destination mask is not modified when a SIMD exception is
         * delivered. */
        if (unmasked) {
            if (!(env->cr[4] & CR4_OSXMMEXCPT_MASK)) {
                raise_exception_ra(env, EXCP06_ILLOP, GETPC());
            }
            raise_exception_ra(env, EXCP13_XM, GETPC());
        }
    }
    evex_commit_opmask(env, dst, result);
}

void helper_evex_fcmp_reg(CPUX86State *env, uint32_t desc,
                          uint32_t immediate)
{
    const int src2 =
        (desc >> EVEX_FCMP_SRC2_SHIFT) & EVEX_FCMP_REG_MASK;

    evex_fcmp_apply(env, desc, immediate, &env->xmm_regs[src2]);
}

static void evex_fcmp_check_address(CPUX86State *env,
                                    target_ulong address,
                                    int element_bytes, uint32_t desc,
                                    uintptr_t ra)
{
#ifdef TARGET_X86_64
    if (address > UINT64_MAX - (element_bytes - 1) ||
        !x86_canonical_address(env, address) ||
        !x86_canonical_address(env, address + element_bytes - 1)) {
        const int exception =
            (desc & EVEX_FCMP_STACK) ? EXCP0C_STACK : EXCP0D_GPF;

        raise_exception_err_ra(env, exception, 0, ra);
    }
#else
    (void)env;
    (void)address;
    (void)element_bytes;
    (void)desc;
    (void)ra;
#endif
}

void helper_evex_fcmp_load(CPUX86State *env, target_ulong address,
                           uint32_t desc, uint32_t immediate)
{
    const int vector_bytes = 16 << ((desc >> EVEX_FCMP_VL_SHIFT) & 3);
    const int element_bytes = (desc & EVEX_FCMP_DOUBLE) ? 8 : 4;
    const int mask_reg = (desc >> EVEX_FCMP_MASK_SHIFT) & 7;
    const uint64_t write_mask =
        mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const int elements = (desc & EVEX_FCMP_SCALAR)
                             ? 1
                             : vector_bytes / element_bytes;
    const uintptr_t ra = GETPC();
    ZMMReg right_source = {0};

    if (desc & EVEX_FCMP_BROADCAST) {
        if (write_mask & ((UINT64_C(1) << elements) - 1)) {
            evex_fcmp_check_address(env, address, element_bytes, desc, ra);
            const uint64_t value = evex_vmovdqu_load_element(
                env, address, element_bytes, ra);

            for (int element = 0; element < elements; ++element) {
                if ((write_mask >> element) & 1) {
                    evex_integer_set_element(&right_source, element,
                                             element_bytes, value);
                }
            }
        }
    } else {
        for (int element = 0; element < elements; ++element) {
            if ((write_mask >> element) & 1) {
                evex_fcmp_check_address(
                    env, address + element * element_bytes,
                    element_bytes, desc, ra);
                const uint64_t value = evex_vmovdqu_load_element(
                    env, address + element * element_bytes, element_bytes,
                    ra);

                evex_integer_set_element(&right_source, element,
                                         element_bytes, value);
            }
        }
    }
    evex_fcmp_apply(env, desc, immediate, &right_source);
}

static int evex_convert_element_bytes(EVEXConvertType type)
{
    switch (type) {
    case EVEX_CVT_F16:
        return 2;
    case EVEX_CVT_I32:
    case EVEX_CVT_U32:
    case EVEX_CVT_F32:
        return 4;
    case EVEX_CVT_I64:
    case EVEX_CVT_U64:
    case EVEX_CVT_F64:
        return 8;
    default:
        g_assert_not_reached();
    }
}

static uint64_t evex_convert_float_to_integer(uint64_t input,
                                              EVEXConvertType src_type,
                                              EVEXConvertType dst_type,
                                              bool truncate,
                                              float_status *status)
{
    const int old_flags = get_float_exception_flags(status);
    int new_flags;
    uint64_t result;

    set_float_exception_flags(0, status);
    if (src_type == EVEX_CVT_F32) {
        const uint32_t value = input;

        switch (dst_type) {
        case EVEX_CVT_I32:
            result = (uint32_t)(truncate
                                    ? float32_to_int32_round_to_zero(value,
                                                                      status)
                                    : float32_to_int32(value, status));
            break;
        case EVEX_CVT_U32:
            result = truncate ? float32_to_uint32_round_to_zero(value, status)
                              : float32_to_uint32(value, status);
            break;
        case EVEX_CVT_I64:
            result = (uint64_t)(truncate
                                    ? float32_to_int64_round_to_zero(value,
                                                                      status)
                                    : float32_to_int64(value, status));
            break;
        case EVEX_CVT_U64:
            result = truncate ? float32_to_uint64_round_to_zero(value, status)
                              : float32_to_uint64(value, status);
            break;
        default:
            g_assert_not_reached();
        }
    } else {
        switch (dst_type) {
        case EVEX_CVT_I32:
            result = (uint32_t)(truncate
                                    ? float64_to_int32_round_to_zero(input,
                                                                      status)
                                    : float64_to_int32(input, status));
            break;
        case EVEX_CVT_U32:
            result = truncate ? float64_to_uint32_round_to_zero(input, status)
                              : float64_to_uint32(input, status);
            break;
        case EVEX_CVT_I64:
            result = (uint64_t)(truncate
                                    ? float64_to_int64_round_to_zero(input,
                                                                      status)
                                    : float64_to_int64(input, status));
            break;
        case EVEX_CVT_U64:
            result = truncate ? float64_to_uint64_round_to_zero(input, status)
                              : float64_to_uint64(input, status);
            break;
        default:
            g_assert_not_reached();
        }
    }

    new_flags = get_float_exception_flags(status);
    if (new_flags & float_flag_invalid) {
        switch (dst_type) {
        case EVEX_CVT_I32:
            result = UINT32_C(0x80000000);
            break;
        case EVEX_CVT_U32:
            result = UINT32_MAX;
            break;
        case EVEX_CVT_I64:
            result = UINT64_C(0x8000000000000000);
            break;
        case EVEX_CVT_U64:
            result = UINT64_MAX;
            break;
        default:
            g_assert_not_reached();
        }
    }
    set_float_exception_flags(old_flags | new_flags, status);
    return result;
}

static uint64_t evex_convert_lane(uint64_t input, EVEXConvertType src_type,
                                  EVEXConvertType dst_type, bool truncate,
                                  float_status *status)
{
    switch (src_type) {
    case EVEX_CVT_I32:
        return dst_type == EVEX_CVT_F32
                   ? int32_to_float32((int32_t)input, status)
                   : int32_to_float64((int32_t)input, status);
    case EVEX_CVT_U32:
        return dst_type == EVEX_CVT_F32
                   ? uint32_to_float32((uint32_t)input, status)
                   : uint32_to_float64((uint32_t)input, status);
    case EVEX_CVT_I64:
        return dst_type == EVEX_CVT_F32
                   ? int64_to_float32((int64_t)input, status)
                   : int64_to_float64((int64_t)input, status);
    case EVEX_CVT_U64:
        return dst_type == EVEX_CVT_F32
                   ? uint64_to_float32(input, status)
                   : uint64_to_float64(input, status);
    case EVEX_CVT_F16: {
        const int old_flags = get_float_exception_flags(status);
        const flag old_daz = get_flush_inputs_to_zero(status);
        uint32_t result;

        set_flush_inputs_to_zero(false, status);
        result = float16_to_float32((uint16_t)input, true, status);
        set_flush_inputs_to_zero(old_daz, status);
        /* VCVTPH2PS is exact and architecturally reports no FP exception. */
        set_float_exception_flags(old_flags, status);
        return result;
    }
    case EVEX_CVT_F32:
        if (dst_type == EVEX_CVT_F16) {
            const flag old_ftz = get_flush_to_zero(status);
            uint16_t result;

            set_flush_to_zero(false, status);
            result = float32_to_float16((uint32_t)input, true, status);
            set_flush_to_zero(old_ftz, status);
            return result;
        }
        if (dst_type == EVEX_CVT_F64) {
            return float32_to_float64((uint32_t)input, status);
        }
        return evex_convert_float_to_integer(input, src_type, dst_type,
                                             truncate, status);
    case EVEX_CVT_F64:
        if (dst_type == EVEX_CVT_F32) {
            return float64_to_float32(input, status);
        }
        return evex_convert_float_to_integer(input, src_type, dst_type,
                                             truncate, status);
    default:
        g_assert_not_reached();
    }
}

static void evex_convert_apply(CPUX86State *env, uint32_t desc,
                               const ZMMReg *source)
{
    const int dst = (desc >> EVEX_CVT_DST_SHIFT) & EVEX_CVT_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_CVT_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_CVT_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const EVEXConvertType src_type =
        (desc >> EVEX_CVT_SRC_TYPE_SHIFT) & EVEX_CVT_TYPE_MASK;
    const EVEXConvertType dst_type =
        (desc >> EVEX_CVT_DST_TYPE_SHIFT) & EVEX_CVT_TYPE_MASK;
    const int src_bytes = evex_convert_element_bytes(src_type);
    const int dst_bytes = evex_convert_element_bytes(dst_type);
    const int elements = vector_bytes / MAX(src_bytes, dst_bytes);
    const int destination_bytes = elements * dst_bytes;
    const bool sae = (desc & EVEX_CVT_SAE) != 0;
    ZMMReg result = env->xmm_regs[dst];
    float_status status = env->sse_status;
    uint32_t exception_flags;

    set_float_exception_flags(0, &status);
    if (desc & EVEX_CVT_EMBEDDED_RC) {
        set_float_rounding_mode((desc >> EVEX_CVT_RC_SHIFT) & EVEX_CVT_RC_MASK,
                                &status);
    }

    for (int element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            const uint64_t input =
                evex_integer_get_element(source, element, src_bytes);
            const uint64_t output = evex_convert_lane(
                input, src_type, dst_type, (desc & EVEX_CVT_TRUNCATE) != 0,
                &status);

            evex_integer_set_element(&result, element, dst_bytes, output);
        } else if (desc & EVEX_CVT_ZERO) {
            evex_integer_set_element(&result, element, dst_bytes, 0);
        }
    }
    for (int byte = destination_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }

    exception_flags = evex_fp_arith_softfloat_flags(
        get_float_exception_flags(&status));
    if (!sae && exception_flags) {
        const uint32_t exception_masks = (env->mxcsr >> 7) & 0x3f;
        const uint32_t unmasked = exception_flags & ~exception_masks;

        cpu_set_mxcsr(env, env->mxcsr | exception_flags);
        if (unmasked) {
            if (!(env->cr[4] & CR4_OSXMMEXCPT_MASK)) {
                raise_exception_ra(env, EXCP06_ILLOP, GETPC());
            }
            raise_exception_ra(env, EXCP13_XM, GETPC());
        }
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_convert_reg(CPUX86State *env, uint32_t desc)
{
    const int src = (desc >> EVEX_CVT_SRC_SHIFT) & EVEX_CVT_REG_MASK;
    const ZMMReg source = env->xmm_regs[src];

    evex_convert_apply(env, desc, &source);
}

void helper_evex_convert_load(CPUX86State *env, target_ulong address,
                              uint32_t desc)
{
    const int vector_bytes = 16 << ((desc >> EVEX_CVT_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_CVT_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const EVEXConvertType src_type =
        (desc >> EVEX_CVT_SRC_TYPE_SHIFT) & EVEX_CVT_TYPE_MASK;
    const EVEXConvertType dst_type =
        (desc >> EVEX_CVT_DST_TYPE_SHIFT) & EVEX_CVT_TYPE_MASK;
    const int src_bytes = evex_convert_element_bytes(src_type);
    const int dst_bytes = evex_convert_element_bytes(dst_type);
    const int elements = vector_bytes / MAX(src_bytes, dst_bytes);
    const uintptr_t ra = GETPC();
    ZMMReg memory_source = {0};

    if (desc & EVEX_CVT_BROADCAST) {
        if (mask & ((UINT64_C(1) << elements) - 1)) {
            const uint64_t value = evex_vmovdqu_load_element(
                env, address, src_bytes, ra);

            for (int element = 0; element < elements; ++element) {
                if ((mask >> element) & 1) {
                    evex_integer_set_element(&memory_source, element,
                                             src_bytes, value);
                }
            }
        }
    } else {
        for (int element = 0; element < elements; ++element) {
            if ((mask >> element) & 1) {
                const uint64_t value = evex_vmovdqu_load_element(
                    env, address + element * src_bytes, src_bytes, ra);

                evex_integer_set_element(&memory_source, element, src_bytes,
                                         value);
            }
        }
    }
    evex_convert_apply(env, desc, &memory_source);
}

void helper_evex_convert_store(CPUX86State *env, target_ulong address,
                               uint32_t desc, target_ulong fault_eip)
{
    const int src = (desc >> EVEX_CVT_SRC_SHIFT) & EVEX_CVT_REG_MASK;
    const int vector_bytes = 16 << ((desc >> EVEX_CVT_VL_SHIFT) & 3);
    const int mask_reg = (desc >> EVEX_CVT_MASK_SHIFT) & 7;
    const uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const EVEXConvertType src_type =
        (desc >> EVEX_CVT_SRC_TYPE_SHIFT) & EVEX_CVT_TYPE_MASK;
    const EVEXConvertType dst_type =
        (desc >> EVEX_CVT_DST_TYPE_SHIFT) & EVEX_CVT_TYPE_MASK;
    const int src_bytes = evex_convert_element_bytes(src_type);
    const int dst_bytes = evex_convert_element_bytes(dst_type);
    const int elements = vector_bytes / MAX(src_bytes, dst_bytes);
    const bool sae = (desc & EVEX_CVT_SAE) != 0;
    const uintptr_t ra = GETPC();
    const ZMMReg source = env->xmm_regs[src];
    ZMMReg converted = {0};
    float_status status = env->sse_status;
    uint32_t exception_flags;

    set_float_exception_flags(0, &status);
    if (desc & EVEX_CVT_EMBEDDED_RC) {
        set_float_rounding_mode((desc >> EVEX_CVT_RC_SHIFT) & EVEX_CVT_RC_MASK,
                                &status);
    }
    for (int element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            const uint64_t input = evex_integer_get_element(
                &source, element, src_bytes);
            const uint64_t output = evex_convert_lane(
                input, src_type, dst_type, (desc & EVEX_CVT_TRUNCATE) != 0,
                &status);

            evex_integer_set_element(&converted, element, dst_bytes, output);
        }
    }

    exception_flags = evex_fp_arith_softfloat_flags(
        get_float_exception_flags(&status));
    if (!sae && exception_flags) {
        const uint32_t exception_masks = (env->mxcsr >> 7) & 0x3f;
        const uint32_t unmasked = exception_flags & ~exception_masks;

        cpu_set_mxcsr(env, env->mxcsr | exception_flags);
        if (unmasked) {
            if (!(env->cr[4] & CR4_OSXMMEXCPT_MASK)) {
                raise_exception_ra(env, EXCP06_ILLOP, GETPC());
            }
            raise_exception_ra(env, EXCP13_XM, GETPC());
        }
    }

    for (int element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            const uint64_t value = evex_integer_get_element(
                &converted, element, dst_bytes);

            if (!x86_evex_store_preflight(env, address + element * dst_bytes,
                                          dst_bytes, value, ra)) {
                env->eip = fault_eip;
                cpu_loop_exit(env_cpu(env));
            }
        }
    }
    for (int element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            evex_vmovdqu_store_element(
                env, address + element * dst_bytes, dst_bytes,
                evex_integer_get_element(&converted, element, dst_bytes), ra);
        }
    }
}

#ifdef TARGET_X86_64
static uint64_t evex_scalar_convert_get_gpr(CPUX86State *env, int reg)
{
    return reg < 16 ? env->regs[reg] : env->apx_regs[reg - 16];
}

static void evex_scalar_convert_set_gpr(CPUX86State *env, int reg,
                                        int bytes, uint64_t value)
{
    if (bytes == 4) {
        value = (uint32_t)value;
    }
    if (reg < 16) {
        env->regs[reg] = value;
    } else {
        env->apx_regs[reg - 16] = value;
        env->xstate_bv |= XSTATE_APX_MASK;
    }
}
#endif

static void evex_scalar_convert_apply(CPUX86State *env, uint32_t desc,
                                      uint64_t input, bool active)
{
    const int dst = (desc >> EVEX_SCVT_DST_SHIFT) & EVEX_SCVT_REG_MASK;
    const int src1 = (desc >> EVEX_SCVT_SRC1_SHIFT) & EVEX_SCVT_REG_MASK;
    const EVEXConvertType src_type =
        (desc >> EVEX_SCVT_SRC_TYPE_SHIFT) & EVEX_SCVT_TYPE_MASK;
    const EVEXConvertType dst_type =
        (desc >> EVEX_SCVT_DST_TYPE_SHIFT) & EVEX_SCVT_TYPE_MASK;
    const int dst_bytes = evex_convert_element_bytes(dst_type);
    const bool gpr_destination =
        (desc & EVEX_SCVT_GPR_DESTINATION) != 0;
    const bool sae = (desc & EVEX_SCVT_SAE) != 0;
    const ZMMReg merge_source = env->xmm_regs[src1];
    ZMMReg result = gpr_destination ? (ZMMReg){0} : env->xmm_regs[dst];
    float_status status = env->sse_status;
    uint64_t output = 0;
    uint32_t exception_flags;

    set_float_exception_flags(0, &status);
    if (desc & EVEX_SCVT_EMBEDDED_RC) {
        set_float_rounding_mode(
            (desc >> EVEX_SCVT_RC_SHIFT) & EVEX_SCVT_RC_MASK, &status);
    }
    if (active) {
        output = evex_convert_lane(input, src_type, dst_type,
                                   (desc & EVEX_SCVT_TRUNCATE) != 0, &status);
        if (!gpr_destination) {
            evex_integer_set_element(&result, 0, dst_bytes, output);
        }
    } else if (desc & EVEX_SCVT_ZERO) {
        evex_integer_set_element(&result, 0, dst_bytes, 0);
    }

    if (!gpr_destination) {
        for (int byte = dst_bytes; byte < 16; ++byte) {
            result.ZMM_B(byte) = merge_source.ZMM_B(byte);
        }
        for (int byte = 16; byte < 64; ++byte) {
            result.ZMM_B(byte) = 0;
        }
    }

    exception_flags = evex_fp_arith_softfloat_flags(
        get_float_exception_flags(&status));
    if (!sae && exception_flags) {
        const uint32_t exception_masks = (env->mxcsr >> 7) & 0x3f;
        const uint32_t unmasked = exception_flags & ~exception_masks;

        cpu_set_mxcsr(env, env->mxcsr | exception_flags);
        if (unmasked) {
            if (!(env->cr[4] & CR4_OSXMMEXCPT_MASK)) {
                raise_exception_ra(env, EXCP06_ILLOP, GETPC());
            }
            raise_exception_ra(env, EXCP13_XM, GETPC());
        }
    }

    if (gpr_destination) {
#ifdef TARGET_X86_64
        evex_scalar_convert_set_gpr(env, dst, dst_bytes, output);
#else
        g_assert_not_reached();
#endif
    } else {
        evex_commit_zmm(env, dst, &result);
    }
}

void helper_evex_scalar_convert_reg(CPUX86State *env, uint32_t desc)
{
    const int src2 = (desc >> EVEX_SCVT_SRC2_SHIFT) & EVEX_SCVT_REG_MASK;
    const int mask_reg = (desc >> EVEX_SCVT_MASK_SHIFT) & 7;
    const bool active = !mask_reg || (env->opmask_regs[mask_reg] & 1);
    const EVEXConvertType src_type =
        (desc >> EVEX_SCVT_SRC_TYPE_SHIFT) & EVEX_SCVT_TYPE_MASK;
    uint64_t input;

    if (desc & EVEX_SCVT_GPR_SOURCE) {
#ifdef TARGET_X86_64
        input = evex_scalar_convert_get_gpr(env, src2);
#else
        g_assert_not_reached();
#endif
    } else {
        input = evex_integer_get_element(&env->xmm_regs[src2], 0,
                                         evex_convert_element_bytes(src_type));
    }
    evex_scalar_convert_apply(env, desc, input, active);
}

void helper_evex_scalar_convert_load(CPUX86State *env, target_ulong address,
                                     uint32_t desc)
{
    const int mask_reg = (desc >> EVEX_SCVT_MASK_SHIFT) & 7;
    const bool active = !mask_reg || (env->opmask_regs[mask_reg] & 1);
    const EVEXConvertType src_type =
        (desc >> EVEX_SCVT_SRC_TYPE_SHIFT) & EVEX_SCVT_TYPE_MASK;
    uint64_t input = 0;

    if (active) {
        input = evex_vmovdqu_load_element(
            env, address, evex_convert_element_bytes(src_type), GETPC());
    }
    evex_scalar_convert_apply(env, desc, input, active);
}

static void evex_vmovdqu_store_element(CPUX86State *env,
                                       target_ulong address,
                                       int element_bytes, uint64_t value,
                                       uintptr_t ra)
{
    switch (element_bytes) {
    case 1:
        cpu_stb_data_ra(env, address, value, ra);
        return;
    case 2:
        cpu_stw_data_ra(env, address, value, ra);
        return;
    case 4:
        cpu_stl_data_ra(env, address, value, ra);
        return;
    case 8:
        cpu_stq_data_ra(env, address, value, ra);
        return;
    default:
        g_assert_not_reached();
    }
}

void helper_evex_vmovdqu_load(CPUX86State *env, target_ulong address,
                              uint32_t desc)
{
    const int dst = (desc >> EVEX_VMOV_REG_SHIFT) & EVEX_VMOV_REG_MASK;
    const int element_shift = (desc >> EVEX_VMOV_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int vector_bytes = 16 << ((desc >> EVEX_VMOV_VL_SHIFT) & 3);
    const uint64_t mask = evex_vmovdqu_mask(env, desc);
    const uintptr_t ra = GETPC();
    ZMMReg result = env->xmm_regs[dst];

    if ((desc & EVEX_VMOV_ALIGNED) && (address & (vector_bytes - 1))) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }

    for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
        const int element = byte >> element_shift;

        if ((mask >> element) & 1) {
            uint64_t value = evex_vmovdqu_load_element(
                env, address + byte, element_bytes, ra);
            evex_integer_set_element(&result, element, element_bytes, value);
        } else if (desc & EVEX_VMOV_ZERO) {
            evex_integer_set_element(&result, element, element_bytes, 0);
        }
    }
    for (int byte = vector_bytes; byte < 64; ++byte) {
        result.ZMM_B(byte) = 0;
    }
    evex_commit_zmm(env, dst, &result);
}

void helper_evex_vmovdqu_store(CPUX86State *env, target_ulong address,
                               uint32_t desc, target_ulong fault_eip)
{
    const int src = (desc >> EVEX_VMOV_REG_SHIFT) & EVEX_VMOV_REG_MASK;
    const int element_shift = (desc >> EVEX_VMOV_ELEM_SHIFT) & 3;
    const int element_bytes = 1 << element_shift;
    const int vector_bytes = 16 << ((desc >> EVEX_VMOV_VL_SHIFT) & 3);
    const uint64_t mask = evex_vmovdqu_mask(env, desc);
    const uintptr_t ra = GETPC();

    if ((desc & EVEX_VMOV_ALIGNED) && (address & (vector_bytes - 1))) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }

    /* Preflight every active lane so a later mapping fault cannot leave a
     * partially committed vector store.  Masked-off lanes are never probed. */
    for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
        const int element = byte >> element_shift;

        if ((mask >> element) & 1) {
            const uint64_t value = evex_integer_get_element(
                &env->xmm_regs[src], element, element_bytes);

            if (!x86_evex_store_preflight(env, address + byte,
                                          element_bytes, value, ra)) {
                env->eip = fault_eip;
                cpu_loop_exit(env_cpu(env));
            }
        }
    }

    for (int byte = 0; byte < vector_bytes; byte += element_bytes) {
        const int element = byte >> element_shift;

        if ((mask >> element) & 1) {
            evex_vmovdqu_store_element(
                env, address + byte, element_bytes,
                evex_integer_get_element(&env->xmm_regs[src], element,
                                         element_bytes),
                ra);
        }
    }
}

#ifdef TARGET_X86_64
static uint64_t apx_pair_get_gpr(CPUX86State *env, unsigned int reg)
{
    return reg < 16 ? env->regs[reg] : env->apx_regs[reg - 16];
}

static void apx_pair_set_gpr(CPUX86State *env, unsigned int reg,
                             uint64_t value)
{
    if (reg < 16) {
        env->regs[reg] = value;
    } else {
        env->apx_regs[reg - 16] = value;
        env->xstate_bv |= XSTATE_APX_MASK;
    }
}

static bool x86_canonical_address(CPUX86State *env, uint64_t address)
{
    const int shift = (env->cr[4] & CR4_LA57_MASK) ? 56 : 47;
    const int64_t sign_extension = (int64_t)address >> shift;

    return sign_extension == 0 || sign_extension == -1;
}

/* ENTER checks write access at the final stack pointer after completing the
 * frame stores, but before publishing BP or SP. The check itself stores no
 * data. Earlier stores remain visible if this check faults. */
void helper_enter_probe(CPUX86State *env, target_ulong address, uint32_t size)
{
    const uintptr_t ra = GETPC();

    if ((env->hflags & HF_CS64_MASK) &&
        (address > UINT64_MAX - (size - 1) ||
         !x86_canonical_address(env, address) ||
         !x86_canonical_address(env, address + size - 1))) {
        raise_exception_err_ra(env, EXCP0C_STACK, 0, ra);
    }
    if (!x86_probe_write(env, address, size, ra)) {
        cpu_loop_exit_restore(env_cpu(env), ra);
    }
}

void helper_apx_push_pop_check(CPUX86State *env, uint32_t desc)
{
    const bool push = (desc & APX_PUSH_POP_PUSH) != 0;
    const uint64_t width = (desc & APX_PUSH_POP_16) ? 2 : 8;
    const uint64_t stack = env->regs[R_ESP];
    const uint64_t address = push ? stack - width : stack;

    if (address > UINT64_MAX - (width - 1) ||
        !x86_canonical_address(env, address) ||
        !x86_canonical_address(env, address + width - 1)) {
        raise_exception_err_ra(env, EXCP0C_STACK, 0, GETPC());
    }
}

void helper_apx_memory_check(CPUX86State *env, target_ulong address,
                             uint32_t desc)
{
    if (!x86_canonical_address(env, address)) {
        const int exception =
            (desc & APX_MEMORY_SS) ? EXCP0C_STACK : EXCP0D_GPF;

        raise_exception_err_ra(env, exception, 0, GETPC());
    }
}

static void apx_evex_check_memory_range(CPUX86State *env, uint64_t address,
                                        uint32_t access_bytes,
                                        uint32_t desc, uintptr_t ra)
{
    if (address > UINT64_MAX - (access_bytes - 1) ||
        !x86_canonical_address(env, address) ||
        !x86_canonical_address(env, address + access_bytes - 1)) {
        const int exception =
            (desc & APX_MEMORY_SS) ? EXCP0C_STACK : EXCP0D_GPF;

        raise_exception_err_ra(env, exception, 0, ra);
    }
}

void helper_apx_evex_memory_check(CPUX86State *env, target_ulong address,
                                  uint32_t mask_reg,
                                  uint32_t active_elements,
                                  uint32_t access_desc, uint32_t desc)
{
    uint64_t mask = mask_reg ? env->opmask_regs[mask_reg] : UINT64_MAX;
    const uint32_t modulo_elements =
        access_desc >> APX_MEMORY_MODULO_ELEMENTS_SHIFT;
    const uint32_t access_bytes =
        access_desc & APX_MEMORY_ACCESS_BYTES_MASK;
    const uintptr_t ra = GETPC();

    if (active_elements < 64) {
        mask &= (UINT64_C(1) << active_elements) - 1;
    }
    if (modulo_elements) {
        uint64_t needed = 0;

        for (uint32_t element = 0; element < active_elements; ++element) {
            if ((mask >> element) & 1) {
                needed |= UINT64_C(1) << (element % modulo_elements);
            }
        }
        mask = needed;
        active_elements = modulo_elements;
    }
    if (!mask) {
        return;
    }
    if (desc & APX_MEMORY_TUPLE) {
        apx_evex_check_memory_range(env, address, access_bytes, desc, ra);
        return;
    }

    for (uint32_t element = 0; element < active_elements; ++element) {
        uint64_t element_address;

        if (!((mask >> element) & 1)) {
            continue;
        }
        if (element > (UINT64_MAX - address) / access_bytes) {
            const int exception =
                (desc & APX_MEMORY_SS) ? EXCP0C_STACK : EXCP0D_GPF;

            raise_exception_err_ra(env, exception, 0, ra);
        }
        element_address = address + (uint64_t)element * access_bytes;
        apx_evex_check_memory_range(env, element_address, access_bytes,
                                    desc, ra);
    }
}

void helper_apx_invpcid(CPUX86State *env, target_ulong address,
                        uint64_t type, uint32_t desc)
{
    const uintptr_t ra = GETPC();
    uint64_t descriptor_low;
    uint64_t descriptor_address;

    if (address > UINT64_MAX - 15 || !x86_canonical_address(env, address) ||
        !x86_canonical_address(env, address + 15)) {
        raise_exception_err_ra(
            env, (desc & APX_MEMORY_SS) ? EXCP0C_STACK : EXCP0D_GPF, 0, ra);
    }

    /* Both descriptor qwords are architecturally read before their contents
     * are validated.  Keeping that order preserves a page fault on the high
     * qword even when the low qword will later cause #GP(0). */
    descriptor_low = cpu_ldq_data_ra(env, address, ra);
    descriptor_address = cpu_ldq_data_ra(env, address + 8, ra);

    if (type > 3 || (descriptor_low & ~UINT64_C(0xfff)) != 0 ||
        (!(env->cr[4] & CR4_PCIDE_MASK) && type <= 1 && descriptor_low != 0) ||
        (type == 0 && !x86_canonical_address(env, descriptor_address))) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }

    /* Unicorn's software TLB has no externally useful PCID/global
     * partition.  Intel explicitly permits INVPCID to invalidate additional
     * addresses, PCIDs, and global translations, so a full flush is the exact
     * conservative implementation for all four architectural types. */
    tlb_flush(env_cpu(env));
}

void helper_apx_enqueue(CPUX86State *env, target_ulong source_address,
                        target_ulong destination_address, uint32_t desc)
{
    const uintptr_t ra = GETPC();
    uint64_t source[8];

    /* Intel orders the feature-specific #GP checks before the ordinary
     * 64-byte source load. */
    if ((desc & APX_ENQUEUE_SUPERVISOR) != 0) {
        if ((env->hflags & HF_CPL_MASK) != 0) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
        }
    } else if (!(env->msr_ia32_pasid & UINT32_C(0x80000000))) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }

    if (source_address > UINT64_MAX - (sizeof(source) - 1) ||
        !x86_canonical_address(env, source_address) ||
        !x86_canonical_address(env, source_address + sizeof(source) - 1)) {
        raise_exception_err_ra(
            env,
            (desc & APX_ENQUEUE_SOURCE_SS) ? EXCP0C_STACK : EXCP0D_GPF,
            0, ra);
    }

    /* The load is not atomic.  Complete it before validating source data or
     * attempting destination translation, as required by the instruction. */
    for (unsigned int index = 0; index < ARRAY_SIZE(source); ++index) {
        source[index] = cpu_ldq_data_ra(
            env, source_address + index * sizeof(source[index]), ra);
    }

    if ((desc & APX_ENQUEUE_SUPERVISOR) != 0) {
        if (source[0] & UINT64_C(0x7ff00000)) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
        }
    } else if (source[0] & UINT64_C(0xffffffff)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }

    if ((destination_address & 63) ||
        destination_address > UINT64_MAX - (sizeof(source) - 1) ||
        !x86_canonical_address(env, destination_address) ||
        !x86_canonical_address(env, destination_address + sizeof(source) - 1)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }

    /* Translation and write permission are still architecturally checked.
     * Unicorn does not expose enqueue-register device transactions, so every
     * ordinary RAM/MMIO destination has the architectural retry completion:
     * no bytes are written and ZF is set. */
    (void)probe_write(env, destination_address, sizeof(source),
                      cpu_mmu_index(env, false), ra);
    CC_SRC = CC_Z;
    CC_OP = CC_OP_EFLAGS;
}

void helper_apx_movdir64b(CPUX86State *env, target_ulong source_address,
                          uint32_t desc, target_ulong fault_eip)
{
    const unsigned int destination_reg =
        (desc >> APX_MOVDIR64B_DST_SHIFT) & APX_MOVDIR64B_REG_MASK;
    const uintptr_t ra = GETPC();
    uint64_t destination = apx_pair_get_gpr(env, destination_reg);
    uint64_t source[8];

    if (desc & APX_MOVDIR64B_ADDRESS32) {
        destination = (uint32_t)destination;
    }

    /* The complete ordinary-memory source read precedes every destination
     * check.  This also snapshots overlapping source and destination ranges. */
    for (unsigned int index = 0; index < 8; ++index) {
        source[index] = cpu_ldq_data_ra(
            env, source_address + index * sizeof(source[index]), ra);
    }

    if ((destination & 63) || destination > UINT64_MAX - (sizeof(source) - 1) ||
        !x86_canonical_address(env, destination) ||
        !x86_canonical_address(env, destination + sizeof(source) - 1)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }

    /* Unicorn has no write-combining transaction object.  Preflight the
     * entire cache line before committing its qwords so architectural state
     * is all-or-nothing even when a later destination page would fault. */
    for (unsigned int index = 0; index < 8; ++index) {
        if (!x86_evex_store_preflight(
                env, destination + index * sizeof(source[index]),
                sizeof(source[index]), source[index], ra)) {
            env->eip = fault_eip;
            cpu_loop_exit(env_cpu(env));
        }
    }
    for (unsigned int index = 0; index < 8; ++index) {
        cpu_stq_data_ra(env, destination + index * sizeof(source[index]),
                        source[index], ra);
        if (env->uc->invalid_error != UC_ERR_OK) {
            env->eip = fault_eip;
            cpu_loop_exit(env_cpu(env));
        }
    }
}

static uint32_t apx_cmpcc_sub_flags(uint64_t old_value,
                                    uint64_t compare_value, bool qword)
{
    const uint64_t mask = qword ? UINT64_MAX : UINT32_MAX;
    const uint64_t sign = qword ? (UINT64_C(1) << 63)
                                : (UINT64_C(1) << 31);
    const uint64_t old_masked = old_value & mask;
    const uint64_t compare_masked = compare_value & mask;
    const uint64_t result = (old_masked - compare_masked) & mask;
    uint32_t flags = parity_table[result & 0xff];

    if (old_masked < compare_masked) {
        flags |= CC_C;
    }
    flags |= (result ^ old_masked ^ compare_masked) & CC_A;
    if (result == 0) {
        flags |= CC_Z;
    }
    if (result & sign) {
        flags |= CC_S;
    }
    if ((old_masked ^ compare_masked) & (old_masked ^ result) & sign) {
        flags |= CC_O;
    }
    return flags;
}

static bool apx_cmpcc_condition_holds(uint32_t condition, uint32_t flags)
{
    const bool overflow = (flags & CC_O) != 0;
    const bool carry = (flags & CC_C) != 0;
    const bool zero = (flags & CC_Z) != 0;
    const bool sign = (flags & CC_S) != 0;
    const bool parity = (flags & CC_P) != 0;

    switch (condition & APX_CMPCC_CONDITION_MASK) {
    case 0x0:
        return overflow;
    case 0x1:
        return !overflow;
    case 0x2:
        return carry;
    case 0x3:
        return !carry;
    case 0x4:
        return zero;
    case 0x5:
        return !zero;
    case 0x6:
        return carry || zero;
    case 0x7:
        return !carry && !zero;
    case 0x8:
        return sign;
    case 0x9:
        return !sign;
    case 0xa:
        return parity;
    case 0xb:
        return !parity;
    case 0xc:
        return sign != overflow;
    case 0xd:
        return sign == overflow;
    case 0xe:
        return zero || sign != overflow;
    case 0xf:
        return !zero && sign == overflow;
    default:
        g_assert_not_reached();
    }
}

void helper_apx_cmpccxadd(CPUX86State *env, target_ulong address,
                          uint32_t desc)
{
    const bool qword = (desc & APX_CMPCC_64) != 0;
    const bool parallel = (desc & APX_CMPCC_PARALLEL) != 0;
    const unsigned int width = qword ? 8 : 4;
    const unsigned int compare_reg =
        (desc >> APX_CMPCC_COMPARE_SHIFT) & APX_CMPCC_REG_MASK;
    const unsigned int add_reg =
        (desc >> APX_CMPCC_ADD_SHIFT) & APX_CMPCC_REG_MASK;
    const uint32_t condition =
        (desc >> APX_CMPCC_CONDITION_SHIFT) & APX_CMPCC_CONDITION_MASK;
    const uint64_t compare_value = apx_pair_get_gpr(env, compare_reg);
    const uint64_t add_value = apx_pair_get_gpr(env, add_reg);
    const uintptr_t ra = GETPC();
    const int mem_idx = cpu_mmu_index(env, false);
    const TCGMemOpIdx oi = make_memop_idx(
        (qword ? MO_LEQ : MO_LEUL) | MO_ALIGN, mem_idx);
    uint64_t old_value;
    uint32_t flags;

    if (address & (width - 1)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }

    if (!parallel) {
        uint64_t candidate;

        old_value = qword ? cpu_ldq_data_ra(env, address, ra)
                          : cpu_ldl_data_ra(env, address, ra);
        if (env->uc->invalid_error != UC_ERR_OK) {
            cpu_loop_exit(env_cpu(env));
        }
        flags = apx_cmpcc_sub_flags(old_value, compare_value, qword);
        candidate = apx_cmpcc_condition_holds(condition, flags)
                        ? old_value + add_value
                        : old_value;
        if (qword) {
            cpu_stq_data_ra(env, address, candidate, ra);
        } else {
            cpu_stl_data_ra(env, address, (uint32_t)candidate, ra);
            old_value = (uint32_t)old_value;
        }
        if (env->uc->invalid_error != UC_ERR_OK) {
            cpu_loop_exit(env_cpu(env));
        }
    } else if (qword) {
#ifdef CONFIG_ATOMIC64
        old_value = cpu_ldq_data_ra(env, address, ra);
        for (;;) {
            const uint64_t expected = old_value;
            const uint64_t candidate = expected + add_value;

            flags = apx_cmpcc_sub_flags(expected, compare_value, true);
            old_value = helper_atomic_cmpxchgq_le_mmu(
                env, address, expected,
                apx_cmpcc_condition_holds(condition, flags)
                    ? candidate
                    : expected,
                oi, ra);
            if (env->uc->invalid_error != UC_ERR_OK) {
                cpu_loop_exit(env_cpu(env));
            }
            if (old_value == expected) {
                break;
            }
        }
#else
        cpu_loop_exit_atomic(env_cpu(env), ra);
#endif
    } else {
        uint32_t old32 = cpu_ldl_data_ra(env, address, ra);

        for (;;) {
            const uint32_t expected = old32;
            const uint32_t candidate = expected + (uint32_t)add_value;

            flags = apx_cmpcc_sub_flags(expected, compare_value, false);
            old32 = helper_atomic_cmpxchgl_le_mmu(
                env, address, expected,
                apx_cmpcc_condition_holds(condition, flags)
                    ? candidate
                    : expected,
                oi, ra);
            if (env->uc->invalid_error != UC_ERR_OK) {
                cpu_loop_exit(env_cpu(env));
            }
            if (old32 == expected) {
                old_value = old32;
                break;
            }
        }
    }

    /* No register or flag state is committed until the locked write-back
     * succeeds, including when the selected condition is false. */
    apx_pair_set_gpr(env, compare_reg, qword ? old_value
                                             : (uint32_t)old_value);
    CC_SRC = flags;
    CC_OP = CC_OP_EFLAGS;
}

static uint16_t amx_tile_colsb(const CPUX86State *env, unsigned int tile)
{
    const unsigned int offset = 16 + tile * 2;

    return env->xtilecfg[offset] | ((uint16_t)env->xtilecfg[offset + 1] << 8);
}

static uint8_t amx_tile_rows(const CPUX86State *env, unsigned int tile)
{
    return env->xtilecfg[48 + tile];
}

static bool amx_palette1_valid(const uint8_t config[64])
{
    if (config[0] != 1) {
        return false;
    }
    for (unsigned int i = 2; i < 16; ++i) {
        if (config[i]) {
            return false;
        }
    }
    for (unsigned int i = 32; i < 48; ++i) {
        if (config[i]) {
            return false;
        }
    }
    for (unsigned int i = 56; i < 64; ++i) {
        if (config[i]) {
            return false;
        }
    }
    for (unsigned int tile = 0; tile < 8; ++tile) {
        const unsigned int offset = 16 + tile * 2;
        const uint16_t colsb =
            config[offset] | ((uint16_t)config[offset + 1] << 8);
        const uint8_t rows = config[48 + tile];

        if (colsb > 64 || rows > 16 || ((colsb == 0) != (rows == 0))) {
            return false;
        }
    }
    return true;
}

static void amx_raise_ud(CPUX86State *env)
{
    raise_exception_ra(env, EXCP06_ILLOP, GETPC());
}

static void amx_check_canonical_range(CPUX86State *env, uint64_t address,
                                      size_t size, bool stack)
{
    const uint64_t last = address + size - 1;

    if (address > UINT64_MAX - (size - 1) ||
        !x86_canonical_address(env, address) ||
        !x86_canonical_address(env, last)) {
        raise_exception_err_ra(env, stack ? EXCP0C_STACK : EXCP0D_GPF, 0,
                               GETPC());
    }
}

void helper_amx_ldtilecfg(CPUX86State *env, target_ulong address,
                          uint32_t desc)
{
    uint8_t config[64];
    const uintptr_t ra = GETPC();

    amx_check_canonical_range(env, address, sizeof(config),
                              (desc & AMX_MEM_SS) != 0);
    for (unsigned int i = 0; i < sizeof(config); ++i) {
        config[i] = cpu_ldub_data_ra(env, address + i, ra);
    }

    if (config[0] > 1 || (config[0] == 1 && !amx_palette1_valid(config))) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }

    memset(env->xtiledata, 0, sizeof(env->xtiledata));
    if (config[0] == 0) {
        memset(env->xtilecfg, 0, sizeof(env->xtilecfg));
        env->xstate_bv &=
            ~(XSTATE_XTILE_CFG_MASK | XSTATE_XTILE_DATA_MASK);
    } else {
        memcpy(env->xtilecfg, config, sizeof(env->xtilecfg));
        env->xstate_bv |= XSTATE_XTILE_CFG_MASK;
        env->xstate_bv &= ~XSTATE_XTILE_DATA_MASK;
    }
}

static void QEMU_NORETURN amx_memory_exit(CPUX86State *env,
                                           target_ulong fault_eip)
{
    env->eip = fault_eip;
    cpu_loop_exit(env_cpu(env));
}

void helper_amx_sttilecfg(CPUX86State *env, target_ulong address,
                          uint32_t desc, target_ulong fault_eip)
{
    const uintptr_t ra = GETPC();

    amx_check_canonical_range(env, address, sizeof(env->xtilecfg),
                              (desc & AMX_MEM_SS) != 0);
    for (unsigned int i = 0; i < sizeof(env->xtilecfg); ++i) {
        cpu_stb_data_ra(env, address + i, env->xtilecfg[i], ra);
        if (env->uc->invalid_error != UC_ERR_OK) {
            amx_memory_exit(env, fault_eip);
        }
    }
}

void helper_amx_tilerelease(CPUX86State *env)
{
    memset(env->xtilecfg, 0, sizeof(env->xtilecfg));
    memset(env->xtiledata, 0, sizeof(env->xtiledata));
    env->xstate_bv &=
        ~(XSTATE_XTILE_CFG_MASK | XSTATE_XTILE_DATA_MASK);
}

void helper_amx_tilezero(CPUX86State *env, uint32_t tile)
{
    if (tile >= 8 || !amx_palette1_valid(env->xtilecfg) ||
        !amx_tile_colsb(env, tile) || !amx_tile_rows(env, tile)) {
        amx_raise_ud(env);
        return;
    }

    memset(env->xtiledata[tile], 0, sizeof(env->xtiledata[tile]));
    env->xtilecfg[1] = 0;
    env->xstate_bv |= XSTATE_XTILE_DATA_MASK;
}

static uint64_t amx_row_address(CPUX86State *env, uint64_t base,
                                uint64_t stride, unsigned int row,
                                uint32_t desc)
{
    uint64_t offset = base + stride * row;

    if (desc & AMX_MEM_ADDR32) {
        offset = (uint32_t)offset;
    }
    if (desc & AMX_MEM_ADD_SEG) {
        const unsigned int seg =
            (desc >> AMX_MEM_SEG_SHIFT) & AMX_MEM_SEG_MASK;

        offset += env->segs[seg].base;
    }
    return offset;
}

void helper_amx_tileloadstore(CPUX86State *env, target_ulong base,
                              target_ulong stride, uint32_t desc,
                              target_ulong fault_eip)
{
    const unsigned int tile = desc & AMX_MEM_TILE_MASK;
    const bool store = (desc & AMX_MEM_STORE) != 0;
    const bool stack = (desc & AMX_MEM_SS) != 0;
    const uintptr_t ra = GETPC();
    uint16_t colsb;
    uint8_t rows;
    uint8_t start;

    if (tile >= 8 || !amx_palette1_valid(env->xtilecfg)) {
        amx_raise_ud(env);
        return;
    }
    colsb = amx_tile_colsb(env, tile);
    rows = amx_tile_rows(env, tile);
    start = env->xtilecfg[1];
    if (!colsb || !rows || (colsb & 3) || start >= rows) {
        amx_raise_ud(env);
        return;
    }

    if (!store) {
        /* A valid TILELOAD begins modifying tile data before its first
         * restartable memory operation.  Preserve that architectural
         * partial-progress state if a later row faults. */
        env->xstate_bv |= XSTATE_XTILE_DATA_MASK;
        memset(&env->xtiledata[tile][start * 64], 0,
               sizeof(env->xtiledata[tile]) - start * 64);
    }

    while (start < rows) {
        const uint64_t address =
            amx_row_address(env, base, stride, start, desc);

        env->xtilecfg[1] = start;
        amx_check_canonical_range(env, address, colsb, stack);
        if (store) {
            for (unsigned int byte = 0; byte < colsb; ++byte) {
                cpu_stb_data_ra(env, address + byte,
                                env->xtiledata[tile][start * 64 + byte], ra);
                if (env->uc->invalid_error != UC_ERR_OK) {
                    amx_memory_exit(env, fault_eip);
                }
            }
        } else {
            uint8_t row[64];

            for (unsigned int byte = 0; byte < colsb; ++byte) {
                row[byte] = cpu_ldub_data_ra(env, address + byte, ra);
            }
            memcpy(&env->xtiledata[tile][start * 64], row, colsb);
        }
        ++start;
        env->xtilecfg[1] = start;
    }
    env->xtilecfg[1] = 0;
}

static bool amx_compute_shape_valid(const CPUX86State *env,
                                    unsigned int dst, unsigned int src1,
                                    unsigned int src2,
                                    unsigned int operation)
{
    uint16_t dst_colsb;
    uint16_t src1_colsb;
    uint16_t src2_colsb;
    uint8_t dst_rows;
    uint8_t src1_rows;
    uint8_t src2_rows;

    if (operation >= AMX_COMPUTE_COUNT || dst >= 8 || src1 >= 8 ||
        src2 >= 8 || dst == src1 || dst == src2 || src1 == src2 ||
        !amx_palette1_valid(env->xtilecfg)) {
        return false;
    }

    dst_colsb = amx_tile_colsb(env, dst);
    src1_colsb = amx_tile_colsb(env, src1);
    src2_colsb = amx_tile_colsb(env, src2);
    dst_rows = amx_tile_rows(env, dst);
    src1_rows = amx_tile_rows(env, src1);
    src2_rows = amx_tile_rows(env, src2);

    return dst_colsb && src1_colsb && src2_colsb && dst_rows && src1_rows &&
           src2_rows && !(dst_colsb & 3) && !(src1_colsb & 3) &&
           !(src2_colsb & 3) && dst_colsb == src2_colsb &&
           dst_rows == src1_rows && src1_colsb / 4 == src2_rows;
}

static int32_t amx_compute_byte(uint8_t value, bool is_signed)
{
    return is_signed ? (int8_t)value : value;
}

static void amx_compute_int8(CPUX86State *env, unsigned int dst,
                             unsigned int src1, unsigned int src2,
                             bool src1_signed, bool src2_signed,
                             uint8_t result[1024])
{
    const unsigned int rows = amx_tile_rows(env, dst);
    const unsigned int columns = amx_tile_colsb(env, dst) / 4;
    const unsigned int inner = amx_tile_colsb(env, src1) / 4;

    for (unsigned int m = 0; m < rows; ++m) {
        for (unsigned int n = 0; n < columns; ++n) {
            uint32_t accumulator =
                ldl_le_p(&env->xtiledata[dst][m * 64 + n * 4]);

            for (unsigned int k = 0; k < inner; ++k) {
                int32_t dot = 0;

                for (unsigned int lane = 0; lane < 4; ++lane) {
                    const int32_t left = amx_compute_byte(
                        env->xtiledata[src1][m * 64 + k * 4 + lane],
                        src1_signed);
                    const int32_t right = amx_compute_byte(
                        env->xtiledata[src2][k * 64 + n * 4 + lane],
                        src2_signed);

                    dot += left * right;
                }
                accumulator += (uint32_t)dot;
            }
            stl_le_p(&result[m * 64 + n * 4], accumulator);
        }
    }
}

static float_status amx_float_status(bool daz)
{
    float_status status = {0};

    set_float_detect_tininess(float_tininess_after_rounding, &status);
    set_float_rounding_mode(float_round_nearest_even, &status);
    set_float_exception_flags(0, &status);
    set_flush_inputs_to_zero(daz, &status);
    set_flush_to_zero(false, &status);
    set_default_nan_mode(false, &status);
    set_snan_bit_is_one(false, &status);
    set_float_2nan_prop_rule(float_2nan_prop_ab, &status);
    return status;
}

static float32 amx_float32_flush(float32 value)
{
    if (float32_is_denormal(value)) {
        return make_float32(float32_val(value) & UINT32_C(0x80000000));
    }
    return value;
}

static float32 amx_float32_fma(float32 left, float32 right,
                               float32 accumulator, float_status *status)
{
    return amx_float32_flush(
        float32_muladd(left, right, accumulator, 0, status));
}

static float32 amx_float32_add(float32 left, float32 right,
                               float_status *status)
{
    return amx_float32_flush(float32_add(left, right, status));
}

static float32 amx_bfloat16_to_float32(uint16_t value)
{
    return make_float32((uint32_t)value << 16);
}

static float32 amx_float16_to_float32(uint16_t value,
                                      float_status *conversion_status)
{
    return float16_to_float32(make_float16(value), true,
                              conversion_status);
}

static void amx_compute_pair_float(CPUX86State *env, unsigned int dst,
                                   unsigned int src1, unsigned int src2,
                                   unsigned int operation,
                                   uint8_t result[1024])
{
    const unsigned int rows = amx_tile_rows(env, dst);
    const unsigned int columns = amx_tile_colsb(env, dst) / 4;
    const unsigned int inner = amx_tile_colsb(env, src1) / 4;
    const bool bfloat = operation == AMX_COMPUTE_TDPBF16PS;
    const bool complex_real = operation == AMX_COMPUTE_TCMMRLFP16PS;
    const bool complex_imag = operation == AMX_COMPUTE_TCMMIMFP16PS;
    float_status arithmetic_status = amx_float_status(true);
    float_status conversion_status = amx_float_status(false);

    for (unsigned int m = 0; m < rows; ++m) {
        for (unsigned int n = 0; n < columns; ++n) {
            float32 even = make_float32(0);
            float32 odd = make_float32(0);

            for (unsigned int k = 0; k < inner; ++k) {
                const uint8_t *a =
                    &env->xtiledata[src1][m * 64 + k * 4];
                const uint8_t *b =
                    &env->xtiledata[src2][k * 64 + n * 4];
                uint16_t a0_bits = lduw_le_p(a);
                uint16_t a1_bits = lduw_le_p(a + 2);
                const uint16_t b0_bits = lduw_le_p(b);
                const uint16_t b1_bits = lduw_le_p(b + 2);
                float32 a0;
                float32 a1;
                float32 b0;
                float32 b1;

                if (complex_real) {
                    a1_bits ^= UINT16_C(0x8000);
                }
                if (bfloat) {
                    a0 = amx_bfloat16_to_float32(a0_bits);
                    a1 = amx_bfloat16_to_float32(a1_bits);
                    b0 = amx_bfloat16_to_float32(b0_bits);
                    b1 = amx_bfloat16_to_float32(b1_bits);
                } else {
                    a0 = amx_float16_to_float32(a0_bits,
                                                &conversion_status);
                    a1 = amx_float16_to_float32(a1_bits,
                                                &conversion_status);
                    b0 = amx_float16_to_float32(b0_bits,
                                                &conversion_status);
                    b1 = amx_float16_to_float32(b1_bits,
                                                &conversion_status);
                }

                if (complex_imag) {
                    even = amx_float32_fma(a1, b0, even,
                                           &arithmetic_status);
                    odd = amx_float32_fma(a0, b1, odd,
                                          &arithmetic_status);
                } else {
                    even = amx_float32_fma(a0, b0, even,
                                           &arithmetic_status);
                    odd = amx_float32_fma(a1, b1, odd,
                                          &arithmetic_status);
                }
            }

            {
                const float32 dot =
                    amx_float32_add(even, odd, &arithmetic_status);
                const float32 accumulator = make_float32(ldl_le_p(
                    &env->xtiledata[dst][m * 64 + n * 4]));
                const float32 value = amx_float32_add(
                    accumulator, dot, &arithmetic_status);

                stl_le_p(&result[m * 64 + n * 4], float32_val(value));
            }
        }
    }
}

static bool amx_fp8_is_nan(uint8_t value, bool hf8)
{
    if (hf8) {
        return (value & UINT8_C(0x7f)) == UINT8_C(0x7f);
    }
    return (value & UINT8_C(0x7c)) == UINT8_C(0x7c) &&
           (value & UINT8_C(0x03));
}

static bool amx_fp8_is_infinity(uint8_t value, bool hf8)
{
    return !hf8 && (value & UINT8_C(0x7f)) == UINT8_C(0x7c);
}

static bool amx_fp8_is_zero(uint8_t value)
{
    return (value & UINT8_C(0x7f)) == 0;
}

static int64_t amx_fp8_to_fixed(uint8_t value, bool hf8)
{
    const bool negative = (value & UINT8_C(0x80)) != 0;
    unsigned int exponent;
    unsigned int fraction;
    uint64_t mantissa;
    uint64_t magnitude;

    if (hf8) {
        exponent = (value >> 3) & 15;
        fraction = value & 7;
        mantissa = exponent ? fraction | 8 : fraction;
    } else {
        exponent = (value >> 2) & 31;
        fraction = value & 3;
        mantissa = exponent ? fraction | 4 : fraction;
    }
    magnitude = mantissa << (exponent ? exponent - 1 : 0);
    return negative ? -(int64_t)magnitude : (int64_t)magnitude;
}

static Int128 amx_int128_mul(int64_t left, int64_t right)
{
    uint64_t low;
    uint64_t high;

    muls64(&low, &high, left, right);
    return int128_make128(low, high);
}

static float32 amx_fixed_to_float32(Int128 value, bool src1_hf8,
                                    bool src2_hf8)
{
    const bool negative = !int128_nonneg(value);
    const unsigned int factor = src1_hf8 ? (src2_hf8 ? 18 : 25)
                                         : (src2_hf8 ? 25 : 32);
    Int128 magnitude;
    uint64_t high;
    uint64_t low;
    unsigned int highest;
    unsigned int significand;
    int exponent;

    if (!int128_nz(value)) {
        return make_float32(0);
    }
    magnitude = negative ? int128_neg(value) : value;
    high = (uint64_t)int128_gethi(magnitude);
    low = int128_getlo(magnitude);
    highest = high ? 64 + 63 - clz64(high) : 63 - clz64(low);

    if (highest <= 23) {
        significand = low << (23 - highest);
    } else {
        const unsigned int shift = highest - 23;
        const uint64_t truncated =
            int128_getlo(int128_rshift(magnitude, shift));
        const uint64_t remainder = low & ((UINT64_C(1) << shift) - 1);
        const uint64_t halfway = UINT64_C(1) << (shift - 1);

        significand = truncated;
        if (remainder > halfway ||
            (remainder == halfway && (significand & 1))) {
            ++significand;
        }
        if (significand == (UINT32_C(1) << 24)) {
            significand >>= 1;
            ++highest;
        }
    }

    exponent = 127 + (int)highest - (int)factor;
    return make_float32((negative ? UINT32_C(0x80000000) : 0) |
                        ((uint32_t)exponent << 23) |
                        (significand & UINT32_C(0x007fffff)));
}

static void amx_compute_fp8(CPUX86State *env, unsigned int dst,
                            unsigned int src1, unsigned int src2,
                            unsigned int operation, uint8_t result[1024])
{
    const unsigned int rows = amx_tile_rows(env, dst);
    const unsigned int columns = amx_tile_colsb(env, dst) / 4;
    const unsigned int inner = amx_tile_colsb(env, src1) / 4;
    const bool src1_hf8 = operation == AMX_COMPUTE_TDPHBF8PS ||
                          operation == AMX_COMPUTE_TDPHF8PS;
    const bool src2_hf8 = operation == AMX_COMPUTE_TDPBHF8PS ||
                          operation == AMX_COMPUTE_TDPHF8PS;
    float_status status = amx_float_status(false);

    for (unsigned int m = 0; m < rows; ++m) {
        for (unsigned int n = 0; n < columns; ++n) {
            const float32 accumulator = make_float32(ldl_le_p(
                &env->xtiledata[dst][m * 64 + n * 4]));
            Int128 fixed = int128_zero();
            int infinity_sign = 0;
            bool indefinite = float32_is_any_nan(accumulator);

            for (unsigned int k = 0; k < inner && !indefinite; ++k) {
                for (unsigned int lane = 0; lane < 4; ++lane) {
                    const uint8_t left =
                        env->xtiledata[src1][m * 64 + k * 4 + lane];
                    const uint8_t right =
                        env->xtiledata[src2][k * 64 + n * 4 + lane];
                    const bool left_inf =
                        amx_fp8_is_infinity(left, src1_hf8);
                    const bool right_inf =
                        amx_fp8_is_infinity(right, src2_hf8);

                    if (amx_fp8_is_nan(left, src1_hf8) ||
                        amx_fp8_is_nan(right, src2_hf8) ||
                        (left_inf && amx_fp8_is_zero(right)) ||
                        (right_inf && amx_fp8_is_zero(left))) {
                        indefinite = true;
                        break;
                    }
                    if (left_inf || right_inf) {
                        const int product_sign =
                            ((left ^ right) & UINT8_C(0x80)) ? -1 : 1;

                        if (infinity_sign && infinity_sign != product_sign) {
                            indefinite = true;
                            break;
                        }
                        infinity_sign = product_sign;
                    } else {
                        int128_addto(
                            &fixed,
                            amx_int128_mul(amx_fp8_to_fixed(left, src1_hf8),
                                           amx_fp8_to_fixed(right,
                                                           src2_hf8)));
                    }
                }
            }

            if (!indefinite && infinity_sign &&
                float32_is_infinity(accumulator) &&
                (float32_is_neg(accumulator) != (infinity_sign < 0))) {
                indefinite = true;
            }

            if (indefinite) {
                stl_le_p(&result[m * 64 + n * 4], UINT32_C(0xffc00000));
            } else if (infinity_sign) {
                stl_le_p(&result[m * 64 + n * 4],
                         infinity_sign < 0 ? UINT32_C(0xff800000)
                                           : UINT32_C(0x7f800000));
            } else if (float32_is_infinity(accumulator)) {
                stl_le_p(&result[m * 64 + n * 4],
                         float32_val(accumulator));
            } else {
                const float32 dot = amx_fixed_to_float32(
                    fixed, src1_hf8, src2_hf8);
                const float32 value =
                    amx_float32_add(accumulator, dot, &status);

                stl_le_p(&result[m * 64 + n * 4], float32_val(value));
            }
        }
    }
}

void helper_amx_compute(CPUX86State *env, uint32_t desc)
{
    const unsigned int dst =
        (desc >> AMX_COMPUTE_DST_SHIFT) & AMX_COMPUTE_TILE_MASK;
    const unsigned int src1 =
        (desc >> AMX_COMPUTE_SRC1_SHIFT) & AMX_COMPUTE_TILE_MASK;
    const unsigned int src2 =
        (desc >> AMX_COMPUTE_SRC2_SHIFT) & AMX_COMPUTE_TILE_MASK;
    const unsigned int operation =
        (desc >> AMX_COMPUTE_OP_SHIFT) & AMX_COMPUTE_OP_MASK;
    uint8_t result[1024] = {0};

    if (!amx_compute_shape_valid(env, dst, src1, src2, operation)) {
        amx_raise_ud(env);
        return;
    }

    switch (operation) {
    case AMX_COMPUTE_TDPBSSD:
        amx_compute_int8(env, dst, src1, src2, true, true, result);
        break;
    case AMX_COMPUTE_TDPBSUD:
        amx_compute_int8(env, dst, src1, src2, true, false, result);
        break;
    case AMX_COMPUTE_TDPBUSD:
        amx_compute_int8(env, dst, src1, src2, false, true, result);
        break;
    case AMX_COMPUTE_TDPBUUD:
        amx_compute_int8(env, dst, src1, src2, false, false, result);
        break;
    case AMX_COMPUTE_TDPBF16PS:
    case AMX_COMPUTE_TDPFP16PS:
    case AMX_COMPUTE_TCMMIMFP16PS:
    case AMX_COMPUTE_TCMMRLFP16PS:
        amx_compute_pair_float(env, dst, src1, src2, operation, result);
        break;
    case AMX_COMPUTE_TDPBF8PS:
    case AMX_COMPUTE_TDPBHF8PS:
    case AMX_COMPUTE_TDPHBF8PS:
    case AMX_COMPUTE_TDPHF8PS:
        amx_compute_fp8(env, dst, src1, src2, operation, result);
        break;
    default:
        amx_raise_ud(env);
        return;
    }

    memcpy(env->xtiledata[dst], result, sizeof(result));
    env->xtilecfg[1] = 0;
    env->xstate_bv |= XSTATE_XTILE_DATA_MASK;
}

static uint16_t amx_float32_to_bfloat16(uint32_t value)
{
    const uint32_t exponent = value & UINT32_C(0x7f800000);
    const uint32_t fraction = value & UINT32_C(0x007fffff);

    if (exponent == 0) {
        return value >> 16 & UINT16_C(0x8000);
    }
    if (exponent == UINT32_C(0x7f800000)) {
        uint16_t result = value >> 16;

        if (fraction) {
            result |= UINT16_C(0x0040);
        }
        return result;
    }

    value += UINT32_C(0x00007fff) + ((value >> 16) & 1);
    return value >> 16;
}

static uint16_t amx_float32_to_float16(uint32_t value,
                                       float_status *status)
{
    if ((value & UINT32_C(0x7f800000)) == 0) {
        return value >> 16 & UINT16_C(0x8000);
    }
    return float16_val(float32_to_float16(make_float32(value), true,
                                          status));
}

void helper_amx_tile_row(CPUX86State *env, uint32_t desc)
{
    const unsigned int dst =
        (desc >> AMX_ROW_DST_SHIFT) & AMX_ROW_DST_MASK;
    const unsigned int src =
        (desc >> AMX_ROW_SRC_SHIFT) & AMX_ROW_SRC_MASK;
    const unsigned int operation =
        (desc >> AMX_ROW_OP_SHIFT) & AMX_ROW_OP_MASK;
    const bool immediate = (desc & AMX_ROW_IMMEDIATE) != 0;
    const unsigned int encoded_selector =
        (desc >> AMX_ROW_SELECTOR_SHIFT) & AMX_ROW_SELECTOR_MASK;
    uint32_t selector;
    unsigned int row;
    unsigned int chunk;
    unsigned int row_offset;
    uint16_t colsb;
    uint8_t rows;
    ZMMReg result = {0};
    float_status status = amx_float_status(false);

    if (dst >= 32 || src >= 8 || operation >= AMX_ROW_OP_COUNT ||
        (!immediate && encoded_selector >= 32) ||
        !amx_palette1_valid(env->xtilecfg)) {
        amx_raise_ud(env);
        return;
    }

    selector = immediate ? encoded_selector
                         : (uint32_t)apx_pair_get_gpr(env,
                                                     encoded_selector);
    row = selector & (immediate ? 0x3f : 0xffff);
    chunk = immediate ? selector >> 6 : selector >> 16;
    row_offset = chunk * 64;

    colsb = amx_tile_colsb(env, src);
    rows = amx_tile_rows(env, src);
    if (!colsb || !rows || (colsb & 3)) {
        amx_raise_ud(env);
        return;
    }
    if (row >= rows || row_offset >= colsb) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
        return;
    }

    switch (operation) {
    case AMX_ROW_MOVE:
        for (unsigned int byte = 0; byte < 64; ++byte) {
            if (row_offset + byte < colsb) {
                result.ZMM_B(byte) =
                    env->xtiledata[src][row * 64 + row_offset + byte];
            }
        }
        break;
    case AMX_ROW_D2PS:
        for (unsigned int element = 0; element < 16; ++element) {
            const unsigned int byte = row_offset + element * 4;

            if (byte < colsb) {
                const int32_t value = (int32_t)ldl_le_p(
                    &env->xtiledata[src][row * 64 + byte]);

                result.ZMM_L(element) =
                    float32_val(int32_to_float32(value, &status));
            }
        }
        break;
    case AMX_ROW_PS2BF16H:
    case AMX_ROW_PS2BF16L:
    case AMX_ROW_PS2PHH:
    case AMX_ROW_PS2PHL:
        for (unsigned int element = 0; element < 16; ++element) {
            const unsigned int byte = row_offset + element * 4;

            if (byte < colsb) {
                const uint32_t value = ldl_le_p(
                    &env->xtiledata[src][row * 64 + byte]);
                const bool high = operation == AMX_ROW_PS2BF16H ||
                                  operation == AMX_ROW_PS2PHH;
                const uint16_t converted =
                    operation == AMX_ROW_PS2BF16H ||
                            operation == AMX_ROW_PS2BF16L
                        ? amx_float32_to_bfloat16(value)
                        : amx_float32_to_float16(value, &status);

                result.ZMM_L(element) =
                    high ? (uint32_t)converted << 16 : converted;
            }
        }
        break;
    default:
        g_assert_not_reached();
    }

    evex_commit_zmm(env, dst, &result);
    env->xtilecfg[1] = 0;
}

static void QEMU_NORETURN apx_pair_memory_exit(CPUX86State *env,
                                                target_ulong fault_eip)
{
    env->eip = fault_eip;
    cpu_loop_exit(env_cpu(env));
}

void helper_apx_push2_pop2(CPUX86State *env, uint32_t desc,
                           target_ulong fault_eip)
{
    const unsigned int v =
        (desc >> APX_PAIR_V_SHIFT) & APX_PAIR_REG_MASK;
    const unsigned int b =
        (desc >> APX_PAIR_B_SHIFT) & APX_PAIR_REG_MASK;
    const bool push = (desc & APX_PAIR_PUSH) != 0;
    const uint64_t stack = env->regs[R_ESP];
    const uintptr_t ra = GETPC();
    uint64_t value;

    if (stack & 15) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }

    if (push) {
        const uint64_t v_address = stack - 8;
        const uint64_t b_address = stack - 16;
        const uint64_t v_value = apx_pair_get_gpr(env, v);
        const uint64_t b_value = apx_pair_get_gpr(env, b);

        if (!x86_canonical_address(env, v_address) ||
            !x86_canonical_address(env, b_address)) {
            raise_exception_err_ra(env, EXCP0C_STACK, 0, ra);
        }

        /* PUSH2 must make both architectural writes or neither. */
        if (!x86_evex_store_preflight(env, v_address, 8, v_value, ra) ||
            !x86_evex_store_preflight(env, b_address, 8, b_value, ra)) {
            apx_pair_memory_exit(env, fault_eip);
        }
        cpu_stq_data_ra(env, v_address, v_value, ra);
        if (env->uc->invalid_error != UC_ERR_OK) {
            apx_pair_memory_exit(env, fault_eip);
        }
        cpu_stq_data_ra(env, b_address, b_value, ra);
        if (env->uc->invalid_error != UC_ERR_OK) {
            apx_pair_memory_exit(env, fault_eip);
        }
        env->regs[R_ESP] = b_address;
        return;
    }

    if (!x86_canonical_address(env, stack)) {
        raise_exception_err_ra(env, EXCP0C_STACK, 0, ra);
    }
    value = cpu_ldq_data_ra(env, stack, ra);
    if (env->uc->invalid_error != UC_ERR_OK) {
        apx_pair_memory_exit(env, fault_eip);
    }
    apx_pair_set_gpr(env, v, value);
    env->regs[R_ESP] = stack + 8;

    if (!x86_canonical_address(env, stack + 8)) {
        raise_exception_err_ra(env, EXCP0C_STACK, 0, ra);
    }
    value = cpu_ldq_data_ra(env, stack + 8, ra);
    if (env->uc->invalid_error != UC_ERR_OK) {
        apx_pair_memory_exit(env, fault_eip);
    }
    apx_pair_set_gpr(env, b, value);
    env->regs[R_ESP] = stack + 16;
}
#endif


void helper_cmpxchg8b_unlocked(CPUX86State *env, target_ulong a0)
{
    uintptr_t ra = GETPC();
    uint64_t oldv, cmpv, newv;
    int eflags;

    eflags = cpu_cc_compute_all(env, CC_OP);

    cmpv = deposit64(env->regs[R_EAX], 32, 32, env->regs[R_EDX]);
    newv = deposit64(env->regs[R_EBX], 32, 32, env->regs[R_ECX]);

    oldv = cpu_ldq_data_ra(env, a0, ra);
    newv = (cmpv == oldv ? newv : oldv);
    /* always do the store */
    cpu_stq_data_ra(env, a0, newv, ra);

    if (oldv == cmpv) {
        eflags |= CC_Z;
    } else {
        env->regs[R_EAX] = (uint32_t)oldv;
        env->regs[R_EDX] = (uint32_t)(oldv >> 32);
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
}

void helper_cmpxchg8b(CPUX86State *env, target_ulong a0)
{
#ifdef CONFIG_ATOMIC64
    uint64_t oldv, cmpv, newv;
    int eflags;

    eflags = cpu_cc_compute_all(env, CC_OP);

    cmpv = deposit64(env->regs[R_EAX], 32, 32, env->regs[R_EDX]);
    newv = deposit64(env->regs[R_EBX], 32, 32, env->regs[R_ECX]);

    {
        uintptr_t ra = GETPC();
        int mem_idx = cpu_mmu_index(env, false);
        TCGMemOpIdx oi = make_memop_idx(MO_TEQ, mem_idx);
        oldv = helper_atomic_cmpxchgq_le_mmu(env, a0, cmpv, newv, oi, ra);
    }

    if (oldv == cmpv) {
        eflags |= CC_Z;
    } else {
        env->regs[R_EAX] = (uint32_t)oldv;
        env->regs[R_EDX] = (uint32_t)(oldv >> 32);
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
#else
    cpu_loop_exit_atomic(env_cpu(env), GETPC());
#endif /* CONFIG_ATOMIC64 */
}

#ifdef TARGET_X86_64
void helper_cmpxchg16b_unlocked(CPUX86State *env, target_ulong a0)
{
    uintptr_t ra = GETPC();
    Int128 oldv, cmpv, newv;
    uint64_t o0, o1;
    int eflags;
    bool success;

    if ((a0 & 0xf) != 0) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    eflags = cpu_cc_compute_all(env, CC_OP);

    cmpv = int128_make128(env->regs[R_EAX], env->regs[R_EDX]);
    newv = int128_make128(env->regs[R_EBX], env->regs[R_ECX]);

    o0 = cpu_ldq_data_ra(env, a0 + 0, ra);
    o1 = cpu_ldq_data_ra(env, a0 + 8, ra);

    oldv = int128_make128(o0, o1);
    success = int128_eq(oldv, cmpv);
    if (!success) {
        newv = oldv;
    }

    cpu_stq_data_ra(env, a0 + 0, int128_getlo(newv), ra);
    cpu_stq_data_ra(env, a0 + 8, int128_gethi(newv), ra);

    if (success) {
        eflags |= CC_Z;
    } else {
        env->regs[R_EAX] = int128_getlo(oldv);
        env->regs[R_EDX] = int128_gethi(oldv);
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
}

void helper_cmpxchg16b(CPUX86State *env, target_ulong a0)
{
    uintptr_t ra = GETPC();

    if ((a0 & 0xf) != 0) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    } else {
#if HAVE_CMPXCHG128 == 1
        int eflags = cpu_cc_compute_all(env, CC_OP);

        Int128 cmpv = int128_make128(env->regs[R_EAX], env->regs[R_EDX]);
        Int128 newv = int128_make128(env->regs[R_EBX], env->regs[R_ECX]);

        int mem_idx = cpu_mmu_index(env, false);
        TCGMemOpIdx oi = make_memop_idx(MO_TEQ | MO_ALIGN_16, mem_idx);
        Int128 oldv = helper_atomic_cmpxchgo_le_mmu(env, a0, cmpv,
                                                    newv, oi, ra);

        if (int128_eq(oldv, cmpv)) {
            eflags |= CC_Z;
        } else {
            env->regs[R_EAX] = int128_getlo(oldv);
            env->regs[R_EDX] = int128_gethi(oldv);
            eflags &= ~CC_Z;
        }
        CC_SRC = eflags;
#else
        cpu_loop_exit_atomic(env_cpu(env), ra);
#endif
    }
}
#endif

void helper_boundw(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldsw_data_ra(env, a0, GETPC());
    high = cpu_ldsw_data_ra(env, a0 + 2, GETPC());
    v = (int16_t)v;
    if (v < low || v > high) {
        if (env->hflags & HF_MPX_EN_MASK) {
            env->bndcs_regs.sts = 0;
        }
        raise_exception_ra(env, EXCP05_BOUND, GETPC());
    }
}

void helper_boundl(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldl_data_ra(env, a0, GETPC());
    high = cpu_ldl_data_ra(env, a0 + 4, GETPC());
    if (v < low || v > high) {
        if (env->hflags & HF_MPX_EN_MASK) {
            env->bndcs_regs.sts = 0;
        }
        raise_exception_ra(env, EXCP05_BOUND, GETPC());
    }
}
