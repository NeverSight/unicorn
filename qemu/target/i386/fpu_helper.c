/*
 *  x86 FPU, MMX/3DNow!/SSE/SSE2/SSE3/SSSE3/SSE4/PNI helpers
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
#include <math.h>
#include "cpu.h"
#include "exec/helper-proto.h"
#include "qemu/host-utils.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "fpu/softfloat.h"

#define FPU_RC_MASK         0xc00
#define FPU_RC_NEAR         0x000
#define FPU_RC_DOWN         0x400
#define FPU_RC_UP           0x800
#define FPU_RC_CHOP         0xc00

#define MAXTAN 9223372036854775808.0

/* the following deal with x86 long double-precision numbers */
#define MAXEXPD 0x7fff
#define EXPBIAS 16383
#define EXPD(fp)        (fp.l.upper & 0x7fff)
#define SIGND(fp)       ((fp.l.upper) & 0x8000)
#define MANTD(fp)       (fp.l.lower)
#define BIASEXPONENT(fp) fp.l.upper = (fp.l.upper & ~(0x7fff)) | EXPBIAS

#define FPUS_IE (1 << 0)
#define FPUS_DE (1 << 1)
#define FPUS_ZE (1 << 2)
#define FPUS_OE (1 << 3)
#define FPUS_UE (1 << 4)
#define FPUS_PE (1 << 5)
#define FPUS_SF (1 << 6)
#define FPUS_SE (1 << 7)
#define FPUS_B  (1 << 15)

#define FPUC_EM 0x3f

#define floatx80_lg2 make_floatx80(0x3ffd, 0x9a209a84fbcff799LL)
#define floatx80_l2e make_floatx80(0x3fff, 0xb8aa3b295c17f0bcLL)
#define floatx80_l2t make_floatx80(0x4000, 0xd49a784bcd1b8afeLL)

static void cpu_clear_ignne(CPUX86State *env)
{
    env->hflags2 &= ~HF2_IGNNE_MASK;
}

void cpu_set_ignne(CPUX86State *env)
{
    env->hflags2 |= HF2_IGNNE_MASK;
    /*
     * We get here in response to a write to port F0h.  The chipset should
     * deassert FP_IRQ and FERR# instead should stay signaled until FPSW_SE is
     * cleared, because FERR# and FP_IRQ are two separate pins on real
     * hardware.  However, we don't model FERR# as a qemu_irq, so we just
     * do directly what the chipset would do, i.e. deassert FP_IRQ.
     */
    // qemu_irq_lower(ferr_irq);
}


static inline void fpush(CPUX86State *env)
{
    env->fpstt = (env->fpstt - 1) & 7;
    env->fptags[env->fpstt] = 0; /* validate stack entry */
}

static inline void fpop(CPUX86State *env)
{
    env->fptags[env->fpstt] = 1; /* invalidate stack entry */
    env->fpstt = (env->fpstt + 1) & 7;
}

static inline floatx80 helper_fldt(CPUX86State *env, target_ulong ptr,
                                   uintptr_t retaddr)
{
    CPU_LDoubleU temp;

    temp.l.lower = cpu_ldq_data_ra(env, ptr, retaddr);
    temp.l.upper = cpu_lduw_data_ra(env, ptr + 8, retaddr);
    return temp.d;
}

static inline void helper_fstt(CPUX86State *env, floatx80 f, target_ulong ptr,
                               uintptr_t retaddr)
{
    CPU_LDoubleU temp;

    temp.d = f;
    cpu_stq_data_ra(env, ptr, temp.l.lower, retaddr);
    cpu_stw_data_ra(env, ptr + 8, temp.l.upper, retaddr);
}

/* x87 FPU helpers */

static inline double floatx80_to_double(CPUX86State *env, floatx80 a)
{
    union {
        float64 f64;
        double d;
    } u;

    u.f64 = floatx80_to_float64(a, &env->fp_status);
    return u.d;
}

static inline floatx80 double_to_floatx80(CPUX86State *env, double a)
{
    union {
        float64 f64;
        double d;
    } u;

    u.d = a;
    return float64_to_floatx80(u.f64, &env->fp_status);
}

static void fpu_set_exception(CPUX86State *env, int mask)
{
    env->fpus |= mask;
    if (env->fpus & (~env->fpuc & FPUC_EM)) {
        env->fpus |= FPUS_SE | FPUS_B;
    }
}

static inline floatx80 helper_fdiv(CPUX86State *env, floatx80 a, floatx80 b)
{
    if (floatx80_is_zero(b)) {
        fpu_set_exception(env, FPUS_ZE);
    }
    return floatx80_div(a, b, &env->fp_status);
}

static void fpu_raise_exception(CPUX86State *env, uintptr_t retaddr)
{
    if (env->cr[0] & CR0_NE_MASK) {
        raise_exception_ra(env, EXCP10_COPR, retaddr);
    }
}

void helper_flds_FT0(CPUX86State *env, uint32_t val)
{
    union {
        float32 f;
        uint32_t i;
    } u;

    u.i = val;
    FT0 = float32_to_floatx80(u.f, &env->fp_status);
}

void helper_fldl_FT0(CPUX86State *env, uint64_t val)
{
    union {
        float64 f;
        uint64_t i;
    } u;

    u.i = val;
    FT0 = float64_to_floatx80(u.f, &env->fp_status);
}

void helper_fildl_FT0(CPUX86State *env, int32_t val)
{
    FT0 = int32_to_floatx80(val, &env->fp_status);
}

void helper_flds_ST0(CPUX86State *env, uint32_t val)
{
    int new_fpstt;
    union {
        float32 f;
        uint32_t i;
    } u;

    new_fpstt = (env->fpstt - 1) & 7;
    u.i = val;
    env->fpregs[new_fpstt].d = float32_to_floatx80(u.f, &env->fp_status);
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
}

void helper_fldl_ST0(CPUX86State *env, uint64_t val)
{
    int new_fpstt;
    union {
        float64 f;
        uint64_t i;
    } u;

    new_fpstt = (env->fpstt - 1) & 7;
    u.i = val;
    env->fpregs[new_fpstt].d = float64_to_floatx80(u.f, &env->fp_status);
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
}

void helper_fildl_ST0(CPUX86State *env, int32_t val)
{
    int new_fpstt;

    new_fpstt = (env->fpstt - 1) & 7;
    env->fpregs[new_fpstt].d = int32_to_floatx80(val, &env->fp_status);
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
}

void helper_fildll_ST0(CPUX86State *env, int64_t val)
{
    int new_fpstt;

    new_fpstt = (env->fpstt - 1) & 7;
    env->fpregs[new_fpstt].d = int64_to_floatx80(val, &env->fp_status);
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
}

uint32_t helper_fsts_ST0(CPUX86State *env)
{
    union {
        float32 f;
        uint32_t i;
    } u;

    u.f = floatx80_to_float32(ST0, &env->fp_status);
    return u.i;
}

uint64_t helper_fstl_ST0(CPUX86State *env)
{
    union {
        float64 f;
        uint64_t i;
    } u;

    u.f = floatx80_to_float64(ST0, &env->fp_status);
    return u.i;
}

int32_t helper_fist_ST0(CPUX86State *env)
{
    int32_t val;

    val = floatx80_to_int32(ST0, &env->fp_status);
    if (val != (int16_t)val) {
        val = -32768;
    }
    return val;
}

int32_t helper_fistl_ST0(CPUX86State *env)
{
    int32_t val;
    signed char old_exp_flags;

    old_exp_flags = get_float_exception_flags(&env->fp_status);
    set_float_exception_flags(0, &env->fp_status);

    val = floatx80_to_int32(ST0, &env->fp_status);
    if (get_float_exception_flags(&env->fp_status) & float_flag_invalid) {
        val = 0x80000000;
    }
    set_float_exception_flags(get_float_exception_flags(&env->fp_status)
                                | old_exp_flags, &env->fp_status);
    return val;
}

int64_t helper_fistll_ST0(CPUX86State *env)
{
    int64_t val;
    signed char old_exp_flags;

    old_exp_flags = get_float_exception_flags(&env->fp_status);
    set_float_exception_flags(0, &env->fp_status);

    val = floatx80_to_int64(ST0, &env->fp_status);
    if (get_float_exception_flags(&env->fp_status) & float_flag_invalid) {
        val = 0x8000000000000000ULL;
    }
    set_float_exception_flags(get_float_exception_flags(&env->fp_status)
                                | old_exp_flags, &env->fp_status);
    return val;
}

int32_t helper_fistt_ST0(CPUX86State *env)
{
    int32_t val;

    val = floatx80_to_int32_round_to_zero(ST0, &env->fp_status);
    if (val != (int16_t)val) {
        val = -32768;
    }
    return val;
}

int32_t helper_fisttl_ST0(CPUX86State *env)
{
    return floatx80_to_int32_round_to_zero(ST0, &env->fp_status);
}

int64_t helper_fisttll_ST0(CPUX86State *env)
{
    return floatx80_to_int64_round_to_zero(ST0, &env->fp_status);
}

void helper_fldt_ST0(CPUX86State *env, target_ulong ptr)
{
    int new_fpstt;

    new_fpstt = (env->fpstt - 1) & 7;
    env->fpregs[new_fpstt].d = helper_fldt(env, ptr, GETPC());
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
}

void helper_fstt_ST0(CPUX86State *env, target_ulong ptr)
{
    helper_fstt(env, ST0, ptr, GETPC());
}

void helper_fpush(CPUX86State *env)
{
    fpush(env);
}

void helper_fpop(CPUX86State *env)
{
    fpop(env);
}

void helper_fdecstp(CPUX86State *env)
{
    env->fpstt = (env->fpstt - 1) & 7;
    env->fpus &= ~0x4700;
}

void helper_fincstp(CPUX86State *env)
{
    env->fpstt = (env->fpstt + 1) & 7;
    env->fpus &= ~0x4700;
}

/* FPU move */

void helper_ffree_STN(CPUX86State *env, int st_index)
{
    env->fptags[(env->fpstt + st_index) & 7] = 1;
}

void helper_fmov_ST0_FT0(CPUX86State *env)
{
    ST0 = FT0;
}

void helper_fmov_FT0_STN(CPUX86State *env, int st_index)
{
    FT0 = ST(st_index);
}

void helper_fmov_ST0_STN(CPUX86State *env, int st_index)
{
    ST0 = ST(st_index);
}

void helper_fmov_STN_ST0(CPUX86State *env, int st_index)
{
    ST(st_index) = ST0;
}

void helper_fxchg_ST0_STN(CPUX86State *env, int st_index)
{
    floatx80 tmp;

    tmp = ST(st_index);
    ST(st_index) = ST0;
    ST0 = tmp;
}

/* FPU operations */

static const int fcom_ccval[4] = {0x0100, 0x4000, 0x0000, 0x4500};

void helper_fcom_ST0_FT0(CPUX86State *env)
{
    int ret;

    ret = floatx80_compare(ST0, FT0, &env->fp_status);
    env->fpus = (env->fpus & ~0x4500) | fcom_ccval[ret + 1];
}

void helper_fucom_ST0_FT0(CPUX86State *env)
{
    int ret;

    ret = floatx80_compare_quiet(ST0, FT0, &env->fp_status);
    env->fpus = (env->fpus & ~0x4500) | fcom_ccval[ret + 1];
}

static const int fcomi_ccval[4] = {CC_C, CC_Z, 0, CC_Z | CC_P | CC_C};

void helper_fcomi_ST0_FT0(CPUX86State *env)
{
    int ret;

    ret = floatx80_compare(ST0, FT0, &env->fp_status);
    /* OF, SF, and AF are unconditionally cleared to zero. */
    CC_SRC = fcomi_ccval[ret + 1];
}

void helper_fucomi_ST0_FT0(CPUX86State *env)
{
    int ret;

    ret = floatx80_compare_quiet(ST0, FT0, &env->fp_status);
    /* OF, SF, and AF are unconditionally cleared to zero. */
    CC_SRC = fcomi_ccval[ret + 1];
}

void helper_fadd_ST0_FT0(CPUX86State *env)
{
    ST0 = floatx80_add(ST0, FT0, &env->fp_status);
}

void helper_fmul_ST0_FT0(CPUX86State *env)
{
    ST0 = floatx80_mul(ST0, FT0, &env->fp_status);
}

void helper_fsub_ST0_FT0(CPUX86State *env)
{
    ST0 = floatx80_sub(ST0, FT0, &env->fp_status);
}

void helper_fsubr_ST0_FT0(CPUX86State *env)
{
    ST0 = floatx80_sub(FT0, ST0, &env->fp_status);
}

void helper_fdiv_ST0_FT0(CPUX86State *env)
{
    ST0 = helper_fdiv(env, ST0, FT0);
}

void helper_fdivr_ST0_FT0(CPUX86State *env)
{
    ST0 = helper_fdiv(env, FT0, ST0);
}

/* fp operations between STN and ST0 */

void helper_fadd_STN_ST0(CPUX86State *env, int st_index)
{
    ST(st_index) = floatx80_add(ST(st_index), ST0, &env->fp_status);
}

void helper_fmul_STN_ST0(CPUX86State *env, int st_index)
{
    ST(st_index) = floatx80_mul(ST(st_index), ST0, &env->fp_status);
}

void helper_fsub_STN_ST0(CPUX86State *env, int st_index)
{
    ST(st_index) = floatx80_sub(ST(st_index), ST0, &env->fp_status);
}

void helper_fsubr_STN_ST0(CPUX86State *env, int st_index)
{
    ST(st_index) = floatx80_sub(ST0, ST(st_index), &env->fp_status);
}

void helper_fdiv_STN_ST0(CPUX86State *env, int st_index)
{
    floatx80 *p;

    p = &ST(st_index);
    *p = helper_fdiv(env, *p, ST0);
}

void helper_fdivr_STN_ST0(CPUX86State *env, int st_index)
{
    floatx80 *p;

    p = &ST(st_index);
    *p = helper_fdiv(env, ST0, *p);
}

/* misc FPU operations */
void helper_fchs_ST0(CPUX86State *env)
{
    ST0 = floatx80_chs(ST0);
}

void helper_fabs_ST0(CPUX86State *env)
{
    ST0 = floatx80_abs(ST0);
}

void helper_fld1_ST0(CPUX86State *env)
{
    //ST0 = floatx80_one;
    floatx80 one = { 0x8000000000000000LL, 0x3fff };
    ST0 = one;
}

void helper_fldl2t_ST0(CPUX86State *env)
{
    //ST0 = floatx80_l2t;
    floatx80 l2t = { 0xd49a784bcd1b8afeLL, 0x4000 };
    ST0 = l2t;
}

void helper_fldl2e_ST0(CPUX86State *env)
{
    //ST0 = floatx80_l2e;
    floatx80 l2e = { 0xb8aa3b295c17f0bcLL, 0x3fff };
    ST0 = l2e;
}

void helper_fldpi_ST0(CPUX86State *env)
{
    //ST0 = floatx80_pi;
    floatx80 pi = { 0xc90fdaa22168c235LL, 0x4000 };
    ST0 = pi;
}

void helper_fldlg2_ST0(CPUX86State *env)
{
    //ST0 = floatx80_lg2;
    floatx80 lg2 = { 0x9a209a84fbcff799LL, 0x3ffd };
    ST0 = lg2;
}

void helper_fldln2_ST0(CPUX86State *env)
{
    //ST0 = floatx80_ln2;
    floatx80 ln2 = { 0xb17217f7d1cf79acLL, 0x3ffe };
    ST0 = ln2;
}

void helper_fldz_ST0(CPUX86State *env)
{
    //ST0 = floatx80_zero;
    floatx80 zero = { 0x0000000000000000LL, 0x0000 };
    ST0 = zero;
}

void helper_fldz_FT0(CPUX86State *env)
{
    //FT0 = floatx80_zero;
    floatx80 zero = { 0x0000000000000000LL, 0x0000 };
    FT0 = zero;
}

uint32_t helper_fnstsw(CPUX86State *env)
{
    return (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11;
}

uint32_t helper_fnstcw(CPUX86State *env)
{
    return env->fpuc;
}

void update_fp_status(CPUX86State *env)
{
    int rnd_type;

    /* set rounding mode */
    switch (env->fpuc & FPU_RC_MASK) {
    default:
    case FPU_RC_NEAR:
        rnd_type = float_round_nearest_even;
        break;
    case FPU_RC_DOWN:
        rnd_type = float_round_down;
        break;
    case FPU_RC_UP:
        rnd_type = float_round_up;
        break;
    case FPU_RC_CHOP:
        rnd_type = float_round_to_zero;
        break;
    }
    set_float_rounding_mode(rnd_type, &env->fp_status);
    switch ((env->fpuc >> 8) & 3) {
    case 0:
        rnd_type = 32;
        break;
    case 2:
        rnd_type = 64;
        break;
    case 3:
    default:
        rnd_type = 80;
        break;
    }
    set_floatx80_rounding_precision(rnd_type, &env->fp_status);
}

void helper_fldcw(CPUX86State *env, uint32_t val)
{
    cpu_set_fpuc(env, val);
}

void helper_fclex(CPUX86State *env)
{
    env->fpus &= 0x7f00;
}

void helper_fwait(CPUX86State *env)
{
    if (env->fpus & FPUS_SE) {
        fpu_raise_exception(env, GETPC());
    }
}

static void do_fninit(CPUX86State *env)
{
    env->fpus = 0;
    env->fpstt = 0;
    env->fpcs = 0;
    env->fpds = 0;
    env->fpip = 0;
    env->fpdp = 0;
    cpu_set_fpuc(env, 0x37f);
    env->fptags[0] = 1;
    env->fptags[1] = 1;
    env->fptags[2] = 1;
    env->fptags[3] = 1;
    env->fptags[4] = 1;
    env->fptags[5] = 1;
    env->fptags[6] = 1;
    env->fptags[7] = 1;
}

void helper_fninit(CPUX86State *env)
{
    do_fninit(env);
}

/* BCD ops */

void helper_fbld_ST0(CPUX86State *env, target_ulong ptr)
{
    floatx80 tmp;
    uint64_t val;
    unsigned int v;
    int i;

    val = 0;
    for (i = 8; i >= 0; i--) {
        v = cpu_ldub_data_ra(env, ptr + i, GETPC());
        val = (val * 100) + ((v >> 4) * 10) + (v & 0xf);
    }
    tmp = int64_to_floatx80(val, &env->fp_status);
    if (cpu_ldub_data_ra(env, ptr + 9, GETPC()) & 0x80) {
        tmp = floatx80_chs(tmp);
    }
    fpush(env);
    ST0 = tmp;
}

void helper_fbst_ST0(CPUX86State *env, target_ulong ptr)
{
    int v;
    target_ulong mem_ref, mem_end;
    int64_t val;

    val = floatx80_to_int64(ST0, &env->fp_status);
    mem_ref = ptr;
    mem_end = mem_ref + 9;
    if (val < 0) {
        cpu_stb_data_ra(env, mem_end, 0x80, GETPC());
        if (val != 0x8000000000000000LL) {
            val = -val;
        }
    } else {
        cpu_stb_data_ra(env, mem_end, 0x00, GETPC());
    }
    while (mem_ref < mem_end) {
        if (val == 0) {
            break;
        }
        v = val % 100;
        val = val / 100;
        v = (int)((unsigned int)(v / 10) << 4) | (v % 10);
        cpu_stb_data_ra(env, mem_ref++, v, GETPC());
    }
    while (mem_ref < mem_end) {
        cpu_stb_data_ra(env, mem_ref++, 0, GETPC());
    }
}

void helper_f2xm1(CPUX86State *env)
{
    double val = floatx80_to_double(env, ST0);

    val = pow(2.0, val) - 1.0;
    ST0 = double_to_floatx80(env, val);
}

void helper_fyl2x(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if (fptemp > 0.0) {
        fptemp = log(fptemp) / log(2.0); /* log2(ST) */
        fptemp *= floatx80_to_double(env, ST1);
        ST1 = double_to_floatx80(env, fptemp);
        fpop(env);
    } else {
        env->fpus &= ~0x4700;
        env->fpus |= 0x400;
    }
}

void helper_fptan(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        env->fpus |= 0x400;
    } else {
        floatx80 one = { 0x8000000000000000LL, 0x3fff };
        fptemp = tan(fptemp);
        ST0 = double_to_floatx80(env, fptemp);
        fpush(env);
        ST0 = one;
        env->fpus &= ~0x400; /* C2 <-- 0 */
        /* the above code is for |arg| < 2**52 only */
    }
}

void helper_fpatan(CPUX86State *env)
{
    double fptemp, fpsrcop;

    fpsrcop = floatx80_to_double(env, ST1);
    fptemp = floatx80_to_double(env, ST0);
    ST1 = double_to_floatx80(env, atan2(fpsrcop, fptemp));
    fpop(env);
}

void helper_fxtract(CPUX86State *env)
{
    CPU_LDoubleU temp;

    temp.d = ST0;

    if (floatx80_is_zero(ST0)) {
        /* Easy way to generate -inf and raising division by 0 exception */
        floatx80 zero = { 0x0000000000000000LL, 0x0000 };
        floatx80 one  = { 0x8000000000000000LL, 0x3fff };
        ST0 = floatx80_div(floatx80_chs(one), zero,
                           &env->fp_status);
        fpush(env);
        ST0 = temp.d;
    } else {
        int expdif;

        expdif = EXPD(temp) - EXPBIAS;
        /* DP exponent bias */
        ST0 = int32_to_floatx80(expdif, &env->fp_status);
        fpush(env);
        BIASEXPONENT(temp);
        ST0 = temp.d;
    }
}

static void helper_fprem_common(CPUX86State *env, bool mod)
{
    uint64_t quotient;
    CPU_LDoubleU temp0, temp1;
    int exp0, exp1, expdiff;

    temp0.d = ST0;
    temp1.d = ST1;
    exp0 = EXPD(temp0);
    exp1 = EXPD(temp1);

    env->fpus &= ~0x4700; /* (C3,C2,C1,C0) <-- 0000 */
    if (floatx80_is_zero(ST0) || floatx80_is_zero(ST1) ||
        exp0 == MAXEXPD || exp1 == MAXEXPD ||
        floatx80_invalid_encoding(ST0) ||
        floatx80_invalid_encoding(ST1)) {
        ST0 = floatx80_modrem(ST0, ST1, mod, &quotient, &env->fp_status);
        return;
    }

    if (exp0 == 0) {
        exp0 = 1 - clz64(temp0.l.lower);
    }
    if (exp1 == 0) {
        exp1 = 1 - clz64(temp1.l.lower);
    }
    expdiff = exp0 - exp1;

    if (expdiff < 64) {
        ST0 = floatx80_modrem(ST0, ST1, mod, &quotient, &env->fp_status);
        /* (C0,C3,C1) <-- (q2,q1,q0) */
        env->fpus |= (quotient & 0x4) << (8 - 2);
        env->fpus |= (quotient & 0x2) << (14 - 1);
        env->fpus |= (quotient & 0x1) << (9 - 0);
    } else {
        /*
         * Process 63 quotient bits per partial reduction.  x87 permits an
         * implementation-selected N in [32, 63]; use a deterministic value.
         */
        const int n = 63;

        temp1.d = floatx80_scalbn(temp1.d, expdiff - n,
                                  &env->fp_status);
        ST0 = floatx80_modrem(ST0, temp1.d, true, &quotient,
                             &env->fp_status);
        env->fpus |= 0x400; /* C2 <-- 1 */
    }
}

void helper_fprem1(CPUX86State *env)
{
    helper_fprem_common(env, false);
}

void helper_fprem(CPUX86State *env)
{
    helper_fprem_common(env, true);
}

void helper_fyl2xp1(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp + 1.0) > 0.0) {
        fptemp = log(fptemp + 1.0) / log(2.0); /* log2(ST + 1.0) */
        fptemp *= floatx80_to_double(env, ST1);
        ST1 = double_to_floatx80(env, fptemp);
        fpop(env);
    } else {
        env->fpus &= ~0x4700;
        env->fpus |= 0x400;
    }
}

void helper_fsqrt(CPUX86State *env)
{
    if (floatx80_is_neg(ST0)) {
        env->fpus &= ~0x4700;  /* (C3,C2,C1,C0) <-- 0000 */
        env->fpus |= 0x400;
    }
    ST0 = floatx80_sqrt(ST0, &env->fp_status);
}

void helper_fsincos(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        env->fpus |= 0x400;
    } else {
        ST0 = double_to_floatx80(env, sin(fptemp));
        fpush(env);
        ST0 = double_to_floatx80(env, cos(fptemp));
        env->fpus &= ~0x400;  /* C2 <-- 0 */
        /* the above code is for |arg| < 2**63 only */
    }
}

void helper_frndint(CPUX86State *env)
{
    ST0 = floatx80_round_to_int(ST0, &env->fp_status);
}

void helper_fscale(CPUX86State *env)
{
    if (floatx80_is_any_nan(ST1)) {
        ST0 = ST1;
    } else {
        int n = floatx80_to_int32_round_to_zero(ST1, &env->fp_status);
        int saved_precision =
            get_floatx80_rounding_precision(&env->fp_status);
        set_floatx80_rounding_precision(80, &env->fp_status);
        ST0 = floatx80_scalbn(ST0, n, &env->fp_status);
        set_floatx80_rounding_precision(saved_precision, &env->fp_status);
    }
}

void helper_fsin(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        env->fpus |= 0x400;
    } else {
        ST0 = double_to_floatx80(env, sin(fptemp));
        env->fpus &= ~0x400;  /* C2 <-- 0 */
        /* the above code is for |arg| < 2**53 only */
    }
}

void helper_fcos(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        env->fpus |= 0x400;
    } else {
        ST0 = double_to_floatx80(env, cos(fptemp));
        env->fpus &= ~0x400;  /* C2 <-- 0 */
        /* the above code is for |arg| < 2**63 only */
    }
}

void helper_fxam_ST0(CPUX86State *env)
{
    CPU_LDoubleU temp;
    int expdif;

    temp.d = ST0;

    env->fpus &= ~0x4700; /* (C3,C2,C1,C0) <-- 0000 */
    if (SIGND(temp)) {
        env->fpus |= 0x200; /* C1 <-- 1 */
    }

    if (env->fptags[env->fpstt]) {
        env->fpus |= 0x4100; /* Empty */
        return;
    }

    expdif = EXPD(temp);
    if (expdif == MAXEXPD) {
        if (MANTD(temp) == 0x8000000000000000ULL) {
            env->fpus |= 0x500; /* Infinity */
        } else {
            env->fpus |= 0x100; /* NaN */
        }
    } else if (expdif == 0) {
        if (MANTD(temp) == 0) {
            env->fpus |=  0x4000; /* Zero */
        } else {
            env->fpus |= 0x4400; /* Denormal */
        }
    } else {
        env->fpus |= 0x400;
    }
}

static void do_fstenv(CPUX86State *env, target_ulong ptr, int data32,
                      uintptr_t retaddr)
{
    int fpus, fptag, exp, i;
    uint64_t mant;
    CPU_LDoubleU tmp;

    fpus = (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11;
    fptag = 0;
    for (i = 7; i >= 0; i--) {
        fptag <<= 2;
        if (env->fptags[i]) {
            fptag |= 3;
        } else {
            tmp.d = env->fpregs[i].d;
            exp = EXPD(tmp);
            mant = MANTD(tmp);
            if (exp == 0 && mant == 0) {
                /* zero */
                fptag |= 1;
            } else if (exp == 0 || exp == MAXEXPD
                       || (mant & (1ULL << 63)) == 0) {
                /* NaNs, infinity, denormal */
                fptag |= 2;
            }
        }
    }

    if (data32) {
        /* 32 bit */
        cpu_stl_data_ra(env, ptr, env->fpuc, retaddr);
        cpu_stl_data_ra(env, ptr + 4, fpus, retaddr);
        cpu_stl_data_ra(env, ptr + 8, fptag, retaddr);
        cpu_stl_data_ra(env, ptr + 12, env->fpip, retaddr); /* fpip */
        cpu_stl_data_ra(env, ptr + 16, env->fpcs, retaddr); /* fpcs */
        cpu_stl_data_ra(env, ptr + 20, env->fpdp, retaddr); /* fpoo */
        cpu_stl_data_ra(env, ptr + 24, env->fpds, retaddr); /* fpos */
    } else {
        /* 16 bit */
        cpu_stw_data_ra(env, ptr, env->fpuc, retaddr);
        cpu_stw_data_ra(env, ptr + 2, fpus, retaddr);
        cpu_stw_data_ra(env, ptr + 4, fptag, retaddr);
        cpu_stw_data_ra(env, ptr + 6, env->fpip, retaddr);
        cpu_stw_data_ra(env, ptr + 8, env->fpcs, retaddr);
        cpu_stw_data_ra(env, ptr + 10, env->fpdp, retaddr);
        cpu_stw_data_ra(env, ptr + 12, env->fpds, retaddr);
    }
}

void helper_fstenv(CPUX86State *env, target_ulong ptr, int data32)
{
    do_fstenv(env, ptr, data32, GETPC());
}

static void cpu_set_fpus(CPUX86State *env, uint16_t fpus)
{
    env->fpstt = (fpus >> 11) & 7;
    env->fpus = fpus & ~0x3800 & ~FPUS_B;
    env->fpus |= env->fpus & FPUS_SE ? FPUS_B : 0;
    if (!(env->fpus & FPUS_SE)) {
        /*
         * Here the processor deasserts FERR#; in response, the chipset deasserts
         * IGNNE#.
         */
        cpu_clear_ignne(env);
    }
}

static void do_fldenv(CPUX86State *env, target_ulong ptr, int data32,
                      uintptr_t retaddr)
{
    int i, fpus, fptag;

    if (data32) {
        cpu_set_fpuc(env, cpu_lduw_data_ra(env, ptr, retaddr));
        fpus = cpu_lduw_data_ra(env, ptr + 4, retaddr);
        fptag = cpu_lduw_data_ra(env, ptr + 8, retaddr);
    } else {
        cpu_set_fpuc(env, cpu_lduw_data_ra(env, ptr, retaddr));
        fpus = cpu_lduw_data_ra(env, ptr + 2, retaddr);
        fptag = cpu_lduw_data_ra(env, ptr + 4, retaddr);
    }
    cpu_set_fpus(env, fpus);
    for (i = 0; i < 8; i++) {
        env->fptags[i] = ((fptag & 3) == 3);
        fptag >>= 2;
    }
}

void helper_fldenv(CPUX86State *env, target_ulong ptr, int data32)
{
    do_fldenv(env, ptr, data32, GETPC());
}

void helper_fsave(CPUX86State *env, target_ulong ptr, int data32)
{
    floatx80 tmp;
    int i;

    do_fstenv(env, ptr, data32, GETPC());

    ptr += (14 << data32);
    for (i = 0; i < 8; i++) {
        tmp = ST(i);
        helper_fstt(env, tmp, ptr, GETPC());
        ptr += 10;
    }

    do_fninit(env);
}

void helper_frstor(CPUX86State *env, target_ulong ptr, int data32)
{
    floatx80 tmp;
    int i;

    do_fldenv(env, ptr, data32, GETPC());
    ptr += (14 << data32);

    for (i = 0; i < 8; i++) {
        tmp = helper_fldt(env, ptr, GETPC());
        ST(i) = tmp;
        ptr += 10;
    }
}

#define XO(X)  offsetof(X86XSaveArea, X)

static void do_xsave_fpu(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    int fpus, fptag, i;
    target_ulong addr;

    fpus = (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11;
    fptag = 0;
    for (i = 0; i < 8; i++) {
        fptag |= (env->fptags[i] << i);
    }

    cpu_stw_data_ra(env, ptr + XO(legacy.fcw), env->fpuc, ra);
    cpu_stw_data_ra(env, ptr + XO(legacy.fsw), fpus, ra);
    cpu_stw_data_ra(env, ptr + XO(legacy.ftw), fptag ^ 0xff, ra);
    cpu_stw_data_ra(env, ptr + XO(legacy.fpop), env->fpop, ra);

    /* In 32-bit mode this is eip, sel, dp, sel.
       In 64-bit mode this is rip, rdp.
       But in either case we don't write actual data, just zeros.  */
    cpu_stq_data_ra(env, ptr + XO(legacy.fpip), env->fpip, ra); /* eip+sel; rip */
    cpu_stq_data_ra(env, ptr + XO(legacy.fpdp), 0, ra); /* edp+sel; rdp */

    addr = ptr + XO(legacy.fpregs);
    for (i = 0; i < 8; i++) {
        floatx80 tmp = ST(i);
        helper_fstt(env, tmp, addr, ra);
        cpu_stl_data_ra(env, addr + 10, 0, ra);
        cpu_stw_data_ra(env, addr + 14, 0, ra);
        addr += 16;
    }
}

static void do_xsave_mxcsr(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    update_mxcsr_from_sse_status(env);
    cpu_stl_data_ra(env, ptr + XO(legacy.mxcsr), env->mxcsr, ra);
    cpu_stl_data_ra(env, ptr + XO(legacy.mxcsr_mask), 0x0000ffff, ra);
}

static void do_xsave_sse(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    int i, nb_xmm_regs;
    target_ulong addr;

    if (env->hflags & HF_CS64_MASK) {
        nb_xmm_regs = 16;
    } else {
        nb_xmm_regs = 8;
    }

    addr = ptr + XO(legacy.xmm_regs);
    for (i = 0; i < nb_xmm_regs; i++) {
        cpu_stq_data_ra(env, addr, env->xmm_regs[i].ZMM_Q(0), ra);
        cpu_stq_data_ra(env, addr + 8, env->xmm_regs[i].ZMM_Q(1), ra);
        addr += 16;
    }
}

static void do_xsave_ymmh(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    int i, nb_xmm_regs;

    if (env->hflags & HF_CS64_MASK) {
        nb_xmm_regs = 16;
    } else {
        nb_xmm_regs = 8;
    }

    for (i = 0; i < nb_xmm_regs; i++, ptr += 16) {
        cpu_stq_data_ra(env, ptr, env->xmm_regs[i].ZMM_Q(2), ra);
        cpu_stq_data_ra(env, ptr + 8, env->xmm_regs[i].ZMM_Q(3), ra);
    }
}

static void do_xsave_bndregs(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    target_ulong addr = ptr + offsetof(XSaveBNDREG, bnd_regs);
    int i;

    for (i = 0; i < 4; i++, addr += 16) {
        cpu_stq_data_ra(env, addr, env->bnd_regs[i].lb, ra);
        cpu_stq_data_ra(env, addr + 8, env->bnd_regs[i].ub, ra);
    }
}

static void do_xsave_bndcsr(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    cpu_stq_data_ra(env, ptr + offsetof(XSaveBNDCSR, bndcsr.cfgu),
                    env->bndcs_regs.cfgu, ra);
    cpu_stq_data_ra(env, ptr + offsetof(XSaveBNDCSR, bndcsr.sts),
                    env->bndcs_regs.sts, ra);
}

static void do_xsave_opmask(CPUX86State *env, target_ulong ptr,
                            uintptr_t ra)
{
    int i;

    for (i = 0; i < NB_OPMASK_REGS; i++, ptr += 8) {
        cpu_stq_data_ra(env, ptr, env->opmask_regs[i], ra);
    }
}

static void do_xsave_zmm_hi256(CPUX86State *env, target_ulong ptr,
                               uintptr_t ra)
{
    int i, qword;

#ifdef TARGET_X86_64
    for (i = 0; i < 16; i++) {
        for (qword = 4; qword < 8; qword++, ptr += 8) {
            cpu_stq_data_ra(env, ptr, env->xmm_regs[i].ZMM_Q(qword), ra);
        }
    }
#else
    for (i = 0; i < 16; i++) {
        for (qword = 4; qword < 8; qword++, ptr += 8) {
            uint64_t value = i < CPU_NB_REGS
                                 ? env->xmm_regs[i].ZMM_Q(qword)
                                 : 0;

            cpu_stq_data_ra(env, ptr, value, ra);
        }
    }
#endif
}

static void do_xsave_hi16_zmm(CPUX86State *env, target_ulong ptr,
                              uintptr_t ra)
{
    int i, qword;

    for (i = 16; i < 32; i++) {
        for (qword = 0; qword < 8; qword++, ptr += 8) {
#ifdef TARGET_X86_64
            uint64_t value = env->xmm_regs[i].ZMM_Q(qword);
#else
            uint64_t value = 0;
#endif

            cpu_stq_data_ra(env, ptr, value, ra);
        }
    }
}

static void do_xsave_bytes(CPUX86State *env, target_ulong ptr,
                           const uint8_t *state, size_t size, uintptr_t ra)
{
    size_t offset;

    for (offset = 0; offset < size; offset += 8) {
        cpu_stq_data_ra(env, ptr + offset, ldq_le_p(state + offset), ra);
    }
}

static void do_xsave_xtilecfg(CPUX86State *env, target_ulong ptr,
                              uintptr_t ra)
{
    do_xsave_bytes(env, ptr, env->xtilecfg, sizeof(env->xtilecfg), ra);
}

static void do_xsave_xtiledata(CPUX86State *env, target_ulong ptr,
                               uintptr_t ra)
{
    do_xsave_bytes(env, ptr, &env->xtiledata[0][0],
                   sizeof(env->xtiledata), ra);
}

static void do_xsave_apx(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
#ifdef TARGET_X86_64
    int i;

    for (i = 0; i < 16; i++, ptr += 8) {
        cpu_stq_data_ra(env, ptr, env->apx_regs[i], ra);
    }
#endif
}

static void do_xsave_pkru(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    cpu_stq_data_ra(env, ptr, env->pkru, ra);
}

void helper_fxsave(CPUX86State *env, target_ulong ptr)
{
    uintptr_t ra = GETPC();

    /* The operand must be 16 byte aligned */
    if (ptr & 0xf) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    do_xsave_fpu(env, ptr, ra);

    if (env->cr[4] & CR4_OSFXSR_MASK) {
        do_xsave_mxcsr(env, ptr, ra);
        /* Fast FXSAVE leaves out the XMM registers */
        if (!(env->efer & MSR_EFER_FFXSR)
            || (env->hflags & HF_CPL_MASK)
            || !(env->hflags & HF_LMA_MASK)) {
            do_xsave_sse(env, ptr, ra);
        }
    }
}

static uint64_t get_xinuse(CPUX86State *env)
{
    uint64_t inuse = -1;
    const uint64_t explicitly_tracked =
        XSTATE_OPMASK_MASK | XSTATE_ZMM_Hi256_MASK |
        XSTATE_Hi16_ZMM_MASK | XSTATE_XTILE_CFG_MASK |
        XSTATE_XTILE_DATA_MASK | XSTATE_APX_MASK;

    /* For the most part, we don't track XINUSE.  We could calculate it
       here for all components, but it's probably less work to simply
       indicate in use.  That said, the state of BNDREGS is important
       enough to track in HFLAGS, so we might as well use that here.  */
    if ((env->hflags & HF_MPX_IU_MASK) == 0) {
       inuse &= ~XSTATE_BNDREGS_MASK;
    }
    inuse = (inuse & ~explicitly_tracked) |
            (env->xstate_bv & explicitly_tracked);
    return inuse;
}

static void do_xsave(CPUX86State *env, target_ulong ptr, uint64_t rfbm,
                     uint64_t inuse, uint64_t opt, uintptr_t ra)
{
    uint64_t old_bv, new_bv;

    /* The OS must have enabled XSAVE.  */
    if (!(env->cr[4] & CR4_OSXSAVE_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }

    /* The operand must be 64 byte aligned.  */
    if (ptr & 63) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    /* Never save anything not enabled by XCR0.  */
    rfbm &= env->xcr0;
    opt &= rfbm;

    if (opt & XSTATE_FP_MASK) {
        do_xsave_fpu(env, ptr, ra);
    }
    if (rfbm & XSTATE_SSE_MASK) {
        /* Note that saving MXCSR is not suppressed by XSAVEOPT.  */
        do_xsave_mxcsr(env, ptr, ra);
    }
    if (opt & XSTATE_SSE_MASK) {
        do_xsave_sse(env, ptr, ra);
    }
    if (opt & XSTATE_YMM_MASK) {
        do_xsave_ymmh(env, ptr + XO(avx_state), ra);
    }
    if (opt & XSTATE_BNDREGS_MASK) {
        do_xsave_bndregs(env, ptr + XO(bndreg_state), ra);
    }
    if (opt & XSTATE_BNDCSR_MASK) {
        do_xsave_bndcsr(env, ptr + XO(bndcsr_state), ra);
    }
    if (opt & XSTATE_OPMASK_MASK) {
        do_xsave_opmask(env, ptr + XO(opmask_state), ra);
    }
    if (opt & XSTATE_ZMM_Hi256_MASK) {
        do_xsave_zmm_hi256(env, ptr + XO(zmm_hi256_state), ra);
    }
    if (opt & XSTATE_Hi16_ZMM_MASK) {
        do_xsave_hi16_zmm(env, ptr + XO(hi16_zmm_state), ra);
    }
    if (opt & XSTATE_APX_MASK) {
        do_xsave_apx(env, ptr + XO(apx_state), ra);
    }
    if (opt & XSTATE_PKRU_MASK) {
        do_xsave_pkru(env, ptr + XO(pkru_state), ra);
    }
    if (opt & XSTATE_XTILE_CFG_MASK) {
        do_xsave_xtilecfg(env, ptr + XO(xtilecfg_state), ra);
    }
    if (opt & XSTATE_XTILE_DATA_MASK) {
        do_xsave_xtiledata(env, ptr + XO(xtiledata_state), ra);
    }

    /* Update the XSTATE_BV field.  */
    old_bv = cpu_ldq_data_ra(env, ptr + XO(header.xstate_bv), ra);
    new_bv = (old_bv & ~rfbm) | (inuse & rfbm);
    cpu_stq_data_ra(env, ptr + XO(header.xstate_bv), new_bv, ra);
}

void helper_xsave(CPUX86State *env, target_ulong ptr, uint64_t rfbm)
{
    do_xsave(env, ptr, rfbm, get_xinuse(env), -1, GETPC());
}

void helper_xsaveopt(CPUX86State *env, target_ulong ptr, uint64_t rfbm)
{
    uint64_t inuse = get_xinuse(env);
    do_xsave(env, ptr, rfbm, inuse, inuse, GETPC());
}

static void do_xrstor_fpu(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    int i, fpuc, fpus, fptag;
    target_ulong addr;

    fpuc = cpu_lduw_data_ra(env, ptr + XO(legacy.fcw), ra);
    fpus = cpu_lduw_data_ra(env, ptr + XO(legacy.fsw), ra);
    fptag = cpu_lduw_data_ra(env, ptr + XO(legacy.ftw), ra);
    cpu_set_fpuc(env, fpuc);
    cpu_set_fpus(env, fpus);
    fptag ^= 0xff;
    for (i = 0; i < 8; i++) {
        env->fptags[i] = ((fptag >> i) & 1);
    }

    addr = ptr + XO(legacy.fpregs);
    for (i = 0; i < 8; i++) {
        floatx80 tmp = helper_fldt(env, addr, ra);
        ST(i) = tmp;
        addr += 16;
    }
}

static uint32_t load_xrstor_mxcsr(CPUX86State *env, target_ulong ptr,
                                  uintptr_t ra)
{
    uint32_t mxcsr = cpu_ldl_data_ra(env, ptr + XO(legacy.mxcsr), ra);

    if (mxcsr & 0xffff0000U) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }
    return mxcsr;
}

static void do_xrstor_sse(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    int i, nb_xmm_regs;
    target_ulong addr;

    if (env->hflags & HF_CS64_MASK) {
        nb_xmm_regs = 16;
    } else {
        nb_xmm_regs = 8;
    }

    addr = ptr + XO(legacy.xmm_regs);
    for (i = 0; i < nb_xmm_regs; i++) {
        env->xmm_regs[i].ZMM_Q(0) = cpu_ldq_data_ra(env, addr, ra);
        env->xmm_regs[i].ZMM_Q(1) = cpu_ldq_data_ra(env, addr + 8, ra);
        addr += 16;
    }
}

static void do_xrstor_ymmh(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    int i, nb_xmm_regs;

    if (env->hflags & HF_CS64_MASK) {
        nb_xmm_regs = 16;
    } else {
        nb_xmm_regs = 8;
    }

    for (i = 0; i < nb_xmm_regs; i++, ptr += 16) {
        env->xmm_regs[i].ZMM_Q(2) = cpu_ldq_data_ra(env, ptr, ra);
        env->xmm_regs[i].ZMM_Q(3) = cpu_ldq_data_ra(env, ptr + 8, ra);
    }
}

static void do_clear_sse(CPUX86State *env)
{
    int i, nb_xmm_regs;

    if (env->hflags & HF_CS64_MASK) {
        nb_xmm_regs = 16;
    } else {
        nb_xmm_regs = 8;
    }

    for (i = 0; i < nb_xmm_regs; i++) {
        env->xmm_regs[i].ZMM_Q(0) = 0;
        env->xmm_regs[i].ZMM_Q(1) = 0;
    }
}

static void do_clear_ymmh(CPUX86State *env)
{
    int i, nb_xmm_regs;

    if (env->hflags & HF_CS64_MASK) {
        nb_xmm_regs = 16;
    } else {
        nb_xmm_regs = 8;
    }

    for (i = 0; i < nb_xmm_regs; i++) {
        env->xmm_regs[i].ZMM_Q(2) = 0;
        env->xmm_regs[i].ZMM_Q(3) = 0;
    }
}

static void do_xrstor_bndregs(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    target_ulong addr = ptr + offsetof(XSaveBNDREG, bnd_regs);
    int i;

    for (i = 0; i < 4; i++, addr += 16) {
        env->bnd_regs[i].lb = cpu_ldq_data_ra(env, addr, ra);
        env->bnd_regs[i].ub = cpu_ldq_data_ra(env, addr + 8, ra);
    }
}

static void do_xrstor_bndcsr(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    /* FIXME: Extend highest implemented bit of linear address.  */
    env->bndcs_regs.cfgu
        = cpu_ldq_data_ra(env, ptr + offsetof(XSaveBNDCSR, bndcsr.cfgu), ra);
    env->bndcs_regs.sts
        = cpu_ldq_data_ra(env, ptr + offsetof(XSaveBNDCSR, bndcsr.sts), ra);
}

static void do_xrstor_opmask(CPUX86State *env, target_ulong ptr,
                             uintptr_t ra)
{
    int i;

    for (i = 0; i < NB_OPMASK_REGS; i++, ptr += 8) {
        env->opmask_regs[i] = cpu_ldq_data_ra(env, ptr, ra);
    }
}

static void do_clear_opmask(CPUX86State *env)
{
    memset(env->opmask_regs, 0, sizeof(env->opmask_regs));
}

static void do_xrstor_zmm_hi256(CPUX86State *env, target_ulong ptr,
                                uintptr_t ra)
{
    int i, qword;
#ifdef TARGET_X86_64
    const int count = 16;
#else
    const int count = CPU_NB_REGS;
#endif

    for (i = 0; i < count; i++) {
        for (qword = 4; qword < 8; qword++, ptr += 8) {
            env->xmm_regs[i].ZMM_Q(qword) = cpu_ldq_data_ra(env, ptr, ra);
        }
    }
}

static void do_clear_zmm_hi256(CPUX86State *env)
{
    int i, qword;
#ifdef TARGET_X86_64
    const int count = 16;
#else
    const int count = CPU_NB_REGS;
#endif

    for (i = 0; i < count; i++) {
        for (qword = 4; qword < 8; qword++) {
            env->xmm_regs[i].ZMM_Q(qword) = 0;
        }
    }
}

static void do_xrstor_hi16_zmm(CPUX86State *env, target_ulong ptr,
                               uintptr_t ra)
{
#ifdef TARGET_X86_64
    int i, qword;

    for (i = 16; i < 32; i++) {
        for (qword = 0; qword < 8; qword++, ptr += 8) {
            env->xmm_regs[i].ZMM_Q(qword) = cpu_ldq_data_ra(env, ptr, ra);
        }
    }
#else
    (void)env;
    (void)ptr;
    (void)ra;
#endif
}

static void do_clear_hi16_zmm(CPUX86State *env)
{
#ifdef TARGET_X86_64
    memset(&env->xmm_regs[16], 0, 16 * sizeof(env->xmm_regs[16]));
#else
    (void)env;
#endif
}

static void do_xrstor_bytes(CPUX86State *env, target_ulong ptr,
                            uint8_t *state, size_t size, uintptr_t ra)
{
    size_t offset;

    for (offset = 0; offset < size; offset += 8) {
        stq_le_p(state + offset, cpu_ldq_data_ra(env, ptr + offset, ra));
    }
}

static bool xrstor_xtilecfg_palette1_valid(const uint8_t config[64])
{
    unsigned int i;

    if (config[0] != 1) {
        return false;
    }
    for (i = 2; i < 16; i++) {
        if (config[i]) {
            return false;
        }
    }
    for (i = 32; i < 48; i++) {
        if (config[i]) {
            return false;
        }
    }
    for (i = 56; i < 64; i++) {
        if (config[i]) {
            return false;
        }
    }
    for (i = 0; i < 8; i++) {
        const unsigned int offset = 16 + i * 2;
        const uint16_t colsb =
            config[offset] | ((uint16_t)config[offset + 1] << 8);
        const uint8_t rows = config[48 + i];

        if (colsb > 64 || rows > 16 || ((colsb == 0) != (rows == 0))) {
            return false;
        }
    }
    return true;
}

static void do_xrstor_xtilecfg(CPUX86State *env, target_ulong ptr,
                               uintptr_t ra)
{
    uint8_t config[64];

    do_xrstor_bytes(env, ptr, config, sizeof(config), ra);
    if (xrstor_xtilecfg_palette1_valid(config)) {
        memcpy(env->xtilecfg, config, sizeof(env->xtilecfg));
    } else {
        /* Palette zero and unsupported/invalid palettes restore init state. */
        memset(env->xtilecfg, 0, sizeof(env->xtilecfg));
    }
}

static void do_xrstor_xtiledata(CPUX86State *env, target_ulong ptr,
                                uintptr_t ra)
{
    do_xrstor_bytes(env, ptr, &env->xtiledata[0][0],
                    sizeof(env->xtiledata), ra);
}

static void do_clear_xtilecfg(CPUX86State *env)
{
    memset(env->xtilecfg, 0, sizeof(env->xtilecfg));
}

static void do_clear_xtiledata(CPUX86State *env)
{
    memset(env->xtiledata, 0, sizeof(env->xtiledata));
}

static void do_xrstor_apx(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
#ifdef TARGET_X86_64
    int i;

    for (i = 0; i < 16; i++, ptr += 8) {
        env->apx_regs[i] = cpu_ldq_data_ra(env, ptr, ra);
    }
#endif
}

static void do_clear_apx(CPUX86State *env)
{
#ifdef TARGET_X86_64
    memset(env->apx_regs, 0, sizeof(env->apx_regs));
#endif
}

static void do_xrstor_pkru(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    env->pkru = cpu_ldq_data_ra(env, ptr, ra);
}

void helper_fxrstor(CPUX86State *env, target_ulong ptr)
{
    uintptr_t ra = GETPC();
    uint32_t mxcsr = 0;
    bool restore_mxcsr;

    /* The operand must be 16 byte aligned */
    if (ptr & 0xf) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    restore_mxcsr = env->cr[4] & CR4_OSFXSR_MASK;
    if (restore_mxcsr) {
        /* Reject reserved MXCSR bits before modifying any x87/SSE state. */
        mxcsr = load_xrstor_mxcsr(env, ptr, ra);
    }

    do_xrstor_fpu(env, ptr, ra);

    if (restore_mxcsr) {
        cpu_set_mxcsr(env, mxcsr);
        /* Fast FXRSTOR leaves out the XMM registers */
        if (!(env->efer & MSR_EFER_FFXSR)
            || (env->hflags & HF_CPL_MASK)
            || !(env->hflags & HF_LMA_MASK)) {
            do_xrstor_sse(env, ptr, ra);
        }
    }
}

void helper_xrstor(CPUX86State *env, target_ulong ptr, uint64_t rfbm)
{
    uintptr_t ra = GETPC();
    uint64_t xstate_bv, xcomp_bv, reserve0;
    uint32_t mxcsr = 0;
    size_t offset;

    rfbm &= env->xcr0;

    /* The OS must have enabled XSAVE.  */
    if (!(env->cr[4] & CR4_OSXSAVE_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }

    /* The operand must be 64 byte aligned.  */
    if (ptr & 63) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    xstate_bv = cpu_ldq_data_ra(env, ptr + XO(header.xstate_bv), ra);

    if ((int64_t)xstate_bv < 0) {
        /* FIXME: Compact form.  */
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    /* Standard form.  */

    /* The XSTATE_BV field must not set bits not present in XCR0.  */
    if (xstate_bv & ~env->xcr0) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    /* The XCOMP_BV field must be zero.  Note that, as of the April 2016
       revision, the description of the XSAVE Header (Vol 1, Sec 13.4.2)
       describes only XCOMP_BV, but the description of the standard form
       of XRSTOR (Vol 1, Sec 13.8.1) checks bytes 23:8 for zero, which
       includes the next 64-bit field.  */
    xcomp_bv = cpu_ldq_data_ra(env, ptr + XO(header.xcomp_bv), ra);
    reserve0 = cpu_ldq_data_ra(env, ptr + XO(header.reserve0), ra);
    if (xcomp_bv || reserve0) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }
    for (offset = 0; offset < sizeof(((X86XSaveHeader *)0)->reserved);
         offset += sizeof(uint64_t)) {
        if (cpu_ldq_data_ra(env, ptr + XO(header.reserved) + offset, ra)) {
            raise_exception_ra(env, EXCP0D_GPF, ra);
        }
    }

    if (rfbm & XSTATE_SSE_MASK) {
        /* Validate MXCSR before restoring any requested state component. */
        mxcsr = load_xrstor_mxcsr(env, ptr, ra);
    }

    if (rfbm & XSTATE_FP_MASK) {
        if (xstate_bv & XSTATE_FP_MASK) {
            do_xrstor_fpu(env, ptr, ra);
        } else {
            do_fninit(env);
            memset(env->fpregs, 0, sizeof(env->fpregs));
        }
    }
    if (rfbm & XSTATE_SSE_MASK) {
        /* Note that the standard form of XRSTOR loads MXCSR from memory
           whether or not the XSTATE_BV bit is set.  */
        cpu_set_mxcsr(env, mxcsr);
        if (xstate_bv & XSTATE_SSE_MASK) {
            do_xrstor_sse(env, ptr, ra);
        } else {
            do_clear_sse(env);
        }
    }
    if (rfbm & XSTATE_YMM_MASK) {
        if (xstate_bv & XSTATE_YMM_MASK) {
            do_xrstor_ymmh(env, ptr + XO(avx_state), ra);
        } else {
            do_clear_ymmh(env);
        }
    }
    if (rfbm & XSTATE_BNDREGS_MASK) {
        if (xstate_bv & XSTATE_BNDREGS_MASK) {
            do_xrstor_bndregs(env, ptr + XO(bndreg_state), ra);
            env->hflags |= HF_MPX_IU_MASK;
        } else {
            memset(env->bnd_regs, 0, sizeof(env->bnd_regs));
            env->hflags &= ~HF_MPX_IU_MASK;
        }
    }
    if (rfbm & XSTATE_BNDCSR_MASK) {
        if (xstate_bv & XSTATE_BNDCSR_MASK) {
            do_xrstor_bndcsr(env, ptr + XO(bndcsr_state), ra);
        } else {
            memset(&env->bndcs_regs, 0, sizeof(env->bndcs_regs));
        }
        cpu_sync_bndcs_hflags(env);
    }
    if (rfbm & XSTATE_OPMASK_MASK) {
        if (xstate_bv & XSTATE_OPMASK_MASK) {
            do_xrstor_opmask(env, ptr + XO(opmask_state), ra);
            env->xstate_bv |= XSTATE_OPMASK_MASK;
        } else {
            do_clear_opmask(env);
            env->xstate_bv &= ~XSTATE_OPMASK_MASK;
        }
    }
    if (rfbm & XSTATE_ZMM_Hi256_MASK) {
        if (xstate_bv & XSTATE_ZMM_Hi256_MASK) {
            do_xrstor_zmm_hi256(env, ptr + XO(zmm_hi256_state), ra);
            env->xstate_bv |= XSTATE_ZMM_Hi256_MASK;
        } else {
            do_clear_zmm_hi256(env);
            env->xstate_bv &= ~XSTATE_ZMM_Hi256_MASK;
        }
    }
    if (rfbm & XSTATE_Hi16_ZMM_MASK) {
        if (xstate_bv & XSTATE_Hi16_ZMM_MASK) {
            do_xrstor_hi16_zmm(env, ptr + XO(hi16_zmm_state), ra);
            env->xstate_bv |= XSTATE_Hi16_ZMM_MASK;
        } else {
            do_clear_hi16_zmm(env);
            env->xstate_bv &= ~XSTATE_Hi16_ZMM_MASK;
        }
    }
    if (rfbm & XSTATE_APX_MASK) {
        if (xstate_bv & XSTATE_APX_MASK) {
            do_xrstor_apx(env, ptr + XO(apx_state), ra);
            env->xstate_bv |= XSTATE_APX_MASK;
        } else {
            do_clear_apx(env);
            env->xstate_bv &= ~XSTATE_APX_MASK;
        }
    }
    if (rfbm & XSTATE_PKRU_MASK) {
        uint64_t old_pkru = env->pkru;
        if (xstate_bv & XSTATE_PKRU_MASK) {
            do_xrstor_pkru(env, ptr + XO(pkru_state), ra);
        } else {
            env->pkru = 0;
        }
        if (env->pkru != old_pkru) {
            CPUState *cs = env_cpu(env);
            tlb_flush(cs);
        }
    }
    if (rfbm & XSTATE_XTILE_CFG_MASK) {
        if (xstate_bv & XSTATE_XTILE_CFG_MASK) {
            do_xrstor_xtilecfg(env, ptr + XO(xtilecfg_state), ra);
            if (env->xtilecfg[0] == 0) {
                /* XRSTOR initializes an unsupported or palette-zero
                 * configuration instead of faulting.  Keep XINUSE in sync
                 * with that architectural init state. */
                env->xstate_bv &= ~XSTATE_XTILE_CFG_MASK;
            } else {
                env->xstate_bv |= XSTATE_XTILE_CFG_MASK;
            }
        } else {
            do_clear_xtilecfg(env);
            env->xstate_bv &= ~XSTATE_XTILE_CFG_MASK;
        }
    }
    if (rfbm & XSTATE_XTILE_DATA_MASK) {
        if (xstate_bv & XSTATE_XTILE_DATA_MASK) {
            do_xrstor_xtiledata(env, ptr + XO(xtiledata_state), ra);
            env->xstate_bv |= XSTATE_XTILE_DATA_MASK;
        } else {
            do_clear_xtiledata(env);
            env->xstate_bv &= ~XSTATE_XTILE_DATA_MASK;
        }
    }
}

#undef XO

uint64_t helper_xgetbv(CPUX86State *env, uint32_t ecx)
{
    /* The OS must have enabled XSAVE.  */
    if (!(env->cr[4] & CR4_OSXSAVE_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }

    switch (ecx) {
    case 0:
        return env->xcr0;
    case 1:
        if (env->features[FEAT_XSAVE] & CPUID_XSAVE_XGETBV1) {
            return env->xcr0 & get_xinuse(env);
        }
        break;
    }
    raise_exception_ra(env, EXCP0D_GPF, GETPC());
}

void helper_xsetbv(CPUX86State *env, uint32_t ecx, uint64_t mask)
{
    uint32_t dummy, ena_lo, ena_hi;
    uint64_t ena;
    const uint64_t avx512_state =
        XSTATE_OPMASK_MASK | XSTATE_ZMM_Hi256_MASK |
        XSTATE_Hi16_ZMM_MASK;
    const uint64_t tile_state =
        XSTATE_XTILE_CFG_MASK | XSTATE_XTILE_DATA_MASK;

    /* The OS must have enabled XSAVE.  */
    if (!(env->cr[4] & CR4_OSXSAVE_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }

    /* Only XCR0 is defined at present; the FPU may not be disabled.  */
    if (ecx != 0 || (mask & XSTATE_FP_MASK) == 0) {
        goto do_gpf;
    }

    /* YMM state depends on SSE state and cannot be enabled on its own. */
    if ((mask & (XSTATE_SSE_MASK | XSTATE_YMM_MASK)) == XSTATE_YMM_MASK) {
        goto do_gpf;
    }

    /* AVX-512 state is enabled as one group and depends on SSE and YMM. */
    if ((mask & avx512_state) &&
        ((mask & avx512_state) != avx512_state ||
         (mask & (XSTATE_SSE_MASK | XSTATE_YMM_MASK)) !=
             (XSTATE_SSE_MASK | XSTATE_YMM_MASK))) {
        goto do_gpf;
    }

    /* TILECFG and TILEDATA are enabled and disabled as one unit. */
    if ((mask & tile_state) && (mask & tile_state) != tile_state) {
        goto do_gpf;
    }

    /* Disallow enabling unimplemented features.  */
    cpu_x86_cpuid(env, 0x0d, 0, &ena_lo, &dummy, &dummy, &ena_hi);
    ena = ((uint64_t)ena_hi << 32) | ena_lo;
    if (mask & ~ena) {
        goto do_gpf;
    }

    /* Disallow enabling only half of MPX.  */
    if ((mask ^ (mask * (XSTATE_BNDCSR_MASK / XSTATE_BNDREGS_MASK)))
        & XSTATE_BNDCSR_MASK) {
        goto do_gpf;
    }

    env->xcr0 = mask;
    cpu_sync_bndcs_hflags(env);
    return;

 do_gpf:
    raise_exception_ra(env, EXCP0D_GPF, GETPC());
}

/* MMX/SSE */
/* XXX: optimize by storing fptt and fptags in the static cpu state */

#define SSE_DAZ             0x0040
#define SSE_RC_MASK         0x6000
#define SSE_RC_NEAR         0x0000
#define SSE_RC_DOWN         0x2000
#define SSE_RC_UP           0x4000
#define SSE_RC_CHOP         0x6000
#define SSE_FZ              0x8000

void update_mxcsr_status(CPUX86State *env)
{
    uint32_t mxcsr = env->mxcsr;
    int rnd_type;

    /* set rounding mode */
    switch (mxcsr & SSE_RC_MASK) {
    default:
    case SSE_RC_NEAR:
        rnd_type = float_round_nearest_even;
        break;
    case SSE_RC_DOWN:
        rnd_type = float_round_down;
        break;
    case SSE_RC_UP:
        rnd_type = float_round_up;
        break;
    case SSE_RC_CHOP:
        rnd_type = float_round_to_zero;
        break;
    }
    set_float_rounding_mode(rnd_type, &env->sse_status);

    set_float_exception_flags(
        ((mxcsr & FPUS_IE) ? float_flag_invalid : 0) |
        ((mxcsr & FPUS_DE) ? float_flag_input_denormal : 0) |
        ((mxcsr & FPUS_ZE) ? float_flag_divbyzero : 0) |
        ((mxcsr & FPUS_OE) ? float_flag_overflow : 0) |
        ((mxcsr & FPUS_UE) ? float_flag_underflow : 0) |
        ((mxcsr & FPUS_PE) ? float_flag_inexact : 0),
        &env->sse_status);

    /* set denormals are zero */
    set_flush_inputs_to_zero((mxcsr & SSE_DAZ) ? 1 : 0, &env->sse_status);

    /* set flush to zero */
    set_flush_to_zero((mxcsr & SSE_FZ) ? 1 : 0, &env->sse_status);
}

void update_mxcsr_from_sse_status(CPUX86State *env)
{
    int flags = get_float_exception_flags(&env->sse_status);

    env->mxcsr |= ((flags & float_flag_invalid) ? FPUS_IE : 0) |
                  ((flags & float_flag_input_denormal) &&
                           !(env->mxcsr & SSE_DAZ)
                       ? FPUS_DE
                       : 0) |
                  ((flags & float_flag_divbyzero) ? FPUS_ZE : 0) |
                  ((flags & float_flag_overflow) ? FPUS_OE : 0) |
                  ((flags & float_flag_underflow) ? FPUS_UE : 0) |
                  ((flags & float_flag_inexact) ? FPUS_PE : 0) |
                  ((flags & float_flag_output_denormal)
                       ? (FPUS_UE | FPUS_PE)
                       : 0);
}

void helper_update_mxcsr(CPUX86State *env)
{
    update_mxcsr_from_sse_status(env);
}

void helper_ldmxcsr(CPUX86State *env, uint32_t val)
{
    if (val & 0xffff0000U) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    cpu_set_mxcsr(env, val);
}

void helper_vtest(CPUX86State *env, void *dptr, void *sptr,
                  uint32_t element_bits)
{
    ZMMReg *d = dptr;
    ZMMReg *s = sptr;
    uint64_t zf = 0;
    uint64_t cf = 0;

    if (element_bits == 32) {
        for (int i = 0; i < 4; i++) {
            zf |= (s->ZMM_L(i) & d->ZMM_L(i)) & UINT32_C(0x80000000);
            cf |= (s->ZMM_L(i) & ~d->ZMM_L(i)) & UINT32_C(0x80000000);
        }
    } else {
        for (int i = 0; i < 2; i++) {
            zf |= (s->ZMM_Q(i) & d->ZMM_Q(i)) &
                  UINT64_C(0x8000000000000000);
            cf |= (s->ZMM_Q(i) & ~d->ZMM_Q(i)) &
                  UINT64_C(0x8000000000000000);
        }
    }

    CC_SRC = (zf ? 0 : CC_Z) | (cf ? 0 : CC_C);
}

void helper_enter_mmx(CPUX86State *env)
{
    env->fpstt = 0;
    *(uint32_t *)(env->fptags) = 0;
    *(uint32_t *)(env->fptags + 4) = 0;
}

void helper_emms(CPUX86State *env)
{
    /* set to empty state */
    *(uint32_t *)(env->fptags) = 0x01010101;
    *(uint32_t *)(env->fptags + 4) = 0x01010101;
}

/* XXX: suppress */
void helper_movq(CPUX86State *env, void *d, void *s)
{
    *(uint64_t *)d = *(uint64_t *)s;
}

#define SHIFT 0
#include "ops_sse.h"

#define SHIFT 1
#include "ops_sse.h"
