/*
 *  i386 translation
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

#include "qemu/host-utils.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg/tcg-op.h"
#include "exec/cpu_ldst.h"
#include "exec/translator.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "qemu/compiler.h"

#include "unicorn/platform.h"
#include "uc_priv.h"

/* NeverD modification, 2026-10-04: retain the register-form EVEX U bit.
 * APX reuses it as X4 only for memory operands; AVX10.2 is not modeled. */
enum {
#define X86_EVEX_ENCODING(Name, Value) X86Evex##Name = Value,
#include "evex-prefix.def"
#undef X86_EVEX_ENCODING
};

#define PREFIX_REPZ   0x01
#define PREFIX_REPNZ  0x02
#define PREFIX_LOCK   0x04
#define PREFIX_DATA   0x08
#define PREFIX_ADR    0x10
#define PREFIX_VEX    0x20

#ifdef TARGET_X86_64
#define CODE64(s) ((s)->code64)
#define REX_X(s) ((s)->rex_x)
#define REX_B(s) ((s)->rex_b)
#else
#define CODE64(s) 0
#define REX_X(s) 0
#define REX_B(s) 0
#endif

#ifdef TARGET_X86_64
# define ctztl  ctz64
# define clztl  clz64
#else
# define ctztl  ctz32
# define clztl  clz32
#endif

/* For a switch indexed by MODRM, match all memory operands for a given OP.  */
#define CASE_MODRM_MEM_OP(OP) \
    case (0 << 6) | (OP << 3) | 0: \
    case (0 << 6) | (OP << 3) | 1: \
    case (0 << 6) | (OP << 3) | 2: \
    case (0 << 6) | (OP << 3) | 3: \
    case (0 << 6) | (OP << 3) | 4: \
    case (0 << 6) | (OP << 3) | 5: \
    case (0 << 6) | (OP << 3) | 6: \
    case (0 << 6) | (OP << 3) | 7: \
    case (1 << 6) | (OP << 3) | 0: \
    case (1 << 6) | (OP << 3) | 1: \
    case (1 << 6) | (OP << 3) | 2: \
    case (1 << 6) | (OP << 3) | 3: \
    case (1 << 6) | (OP << 3) | 4: \
    case (1 << 6) | (OP << 3) | 5: \
    case (1 << 6) | (OP << 3) | 6: \
    case (1 << 6) | (OP << 3) | 7: \
    case (2 << 6) | (OP << 3) | 0: \
    case (2 << 6) | (OP << 3) | 1: \
    case (2 << 6) | (OP << 3) | 2: \
    case (2 << 6) | (OP << 3) | 3: \
    case (2 << 6) | (OP << 3) | 4: \
    case (2 << 6) | (OP << 3) | 5: \
    case (2 << 6) | (OP << 3) | 6: \
    case (2 << 6) | (OP << 3) | 7

#define CASE_MODRM_OP(OP) \
    case (0 << 6) | (OP << 3) | 0: \
    case (0 << 6) | (OP << 3) | 1: \
    case (0 << 6) | (OP << 3) | 2: \
    case (0 << 6) | (OP << 3) | 3: \
    case (0 << 6) | (OP << 3) | 4: \
    case (0 << 6) | (OP << 3) | 5: \
    case (0 << 6) | (OP << 3) | 6: \
    case (0 << 6) | (OP << 3) | 7: \
    case (1 << 6) | (OP << 3) | 0: \
    case (1 << 6) | (OP << 3) | 1: \
    case (1 << 6) | (OP << 3) | 2: \
    case (1 << 6) | (OP << 3) | 3: \
    case (1 << 6) | (OP << 3) | 4: \
    case (1 << 6) | (OP << 3) | 5: \
    case (1 << 6) | (OP << 3) | 6: \
    case (1 << 6) | (OP << 3) | 7: \
    case (2 << 6) | (OP << 3) | 0: \
    case (2 << 6) | (OP << 3) | 1: \
    case (2 << 6) | (OP << 3) | 2: \
    case (2 << 6) | (OP << 3) | 3: \
    case (2 << 6) | (OP << 3) | 4: \
    case (2 << 6) | (OP << 3) | 5: \
    case (2 << 6) | (OP << 3) | 6: \
    case (2 << 6) | (OP << 3) | 7: \
    case (3 << 6) | (OP << 3) | 0: \
    case (3 << 6) | (OP << 3) | 1: \
    case (3 << 6) | (OP << 3) | 2: \
    case (3 << 6) | (OP << 3) | 3: \
    case (3 << 6) | (OP << 3) | 4: \
    case (3 << 6) | (OP << 3) | 5: \
    case (3 << 6) | (OP << 3) | 6: \
    case (3 << 6) | (OP << 3) | 7

#include "exec/gen-icount.h"

typedef struct DisasContext {
    DisasContextBase base;

    /* current insn context */
    int override; /* -1 if no override */
    int prefix;
    MemOp aflag;
    MemOp dflag;
    target_ulong pc_start;
    target_ulong pc; /* pc = eip + cs_base */
    /* current block context */
    target_ulong cs_base; /* base of CS segment */
    int pe;     /* protected mode */
    int code32; /* 32 bit code segment */
#ifdef TARGET_X86_64
    int lma;    /* long mode active */
    int code64; /* 64 bit code segment */
    int rex_x, rex_b;
#endif
    int vex_l;  /* vex vector length */
    int vex_w;  /* VEX.W encoding bit (independent of operand size) */
    int vex_v;  /* vex vvvv register, without 1's complement.  */
    int ss32;   /* 32 bit stack segment */
    CCOp cc_op;  /* current CC operation */
    CCOp last_cc_op;  /* Unicorn: last CC operation. Save this to see if cc_op has changed */
    bool cc_op_dirty;
#ifdef TARGET_X86_64
    bool x86_64_hregs;
#endif
    int addseg; /* non zero if either DS/ES/SS have a non zero base */
    int f_st;   /* currently unused */
    int vm86;   /* vm86 mode */
    int cpl;
    int iopl;
    int tf;     /* TF cpu flag */
    int jmp_opt; /* use direct block chaining for direct jumps */
    int repz_opt; /* optimize jumps within repz instructions */
    int mem_index; /* select memory access functions */
    uint64_t flags; /* all execution flags */
    int popl_esp_hack; /* for correct popl with esp base handling */
    int rip_offset; /* only used in x86_64, but left for simplicity */
    int cpuid_features;
    int cpuid_ext_features;
    int cpuid_ext2_features;
    int cpuid_ext3_features;
    int cpuid_7_0_ebx_features;
    int cpuid_7_0_ecx_features;
    int cpuid_7_0_edx_features;
    int cpuid_7_1_eax_features;
    int cpuid_7_1_ecx_features;
    int cpuid_7_1_edx_features;
    int cpuid_29_0_ebx_features;
    int cpuid_xsave_features;

    /* TCG local temps */
    TCGv cc_srcT;
    TCGv A0;
    TCGv T0;
    TCGv T1;

    /* TCG local register indexes (only used inside old micro ops) */
    TCGv tmp0;
    TCGv tmp4;
    TCGv_ptr ptr0;
    TCGv_ptr ptr1;
    TCGv_i32 tmp2_i32;
    TCGv_i32 tmp3_i32;
    TCGv_i64 tmp1_i64;

    sigjmp_buf jmpbuf;

    // Unicorn
    struct uc_struct *uc;
    target_ulong prev_pc; /* save address of the previous instruction */
} DisasContext;

static void gen_eob(DisasContext *s);
static void gen_jr(DisasContext *s, TCGv dest);
static void gen_jmp(DisasContext *s, target_ulong eip);
static void gen_jmp_tb(DisasContext *s, target_ulong eip, int tb_num);
static void gen_op(DisasContext *s, int op, MemOp ot, int d);

/* i386 arith/logic operations */
enum {
    OP_ADDL,
    OP_ORL,
    OP_ADCL,
    OP_SBBL,
    OP_ANDL,
    OP_SUBL,
    OP_XORL,
    OP_CMPL,
};

/* i386 shift ops */
enum {
    OP_ROL,
    OP_ROR,
    OP_RCL,
    OP_RCR,
    OP_SHL,
    OP_SHR,
    OP_SHL1, /* undocumented */
    OP_SAR = 7,
};

enum {
    JCC_O,
    JCC_B,
    JCC_Z,
    JCC_BE,
    JCC_S,
    JCC_P,
    JCC_L,
    JCC_LE,
};

enum {
    /* I386 int registers */
    OR_EAX,   /* MUST be even numbered */
    OR_ECX,
    OR_EDX,
    OR_EBX,
    OR_ESP,
    OR_EBP,
    OR_ESI,
    OR_EDI,

    OR_TMP0 = 16,    /* temporary operand register */
    OR_TMP1,
    OR_A0, /* temporary register used when doing address evaluation */
};

enum {
    USES_CC_DST  = 1,
    USES_CC_SRC  = 2,
    USES_CC_SRC2 = 4,
    USES_CC_SRCT = 8,
};

/* Bit set if the global variable is live after setting CC_OP to X.  */
static const uint8_t cc_op_live[CC_OP_NB] = {
    [CC_OP_DYNAMIC] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_EFLAGS] = USES_CC_SRC,

    [CC_OP_MULB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_MULW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_MULL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_MULQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_ADDB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADDW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADDL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADDQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_ADCB] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_ADCW] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_ADCL] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_ADCQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,

    [CC_OP_SUBB] = USES_CC_DST | USES_CC_SRC | USES_CC_SRCT,
    [CC_OP_SUBW] = USES_CC_DST | USES_CC_SRC | USES_CC_SRCT,
    [CC_OP_SUBL] = USES_CC_DST | USES_CC_SRC | USES_CC_SRCT,
    [CC_OP_SUBQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRCT,

    [CC_OP_SBBB] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_SBBW] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_SBBL] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_SBBQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,

    [CC_OP_LOGICB] = USES_CC_DST,
    [CC_OP_LOGICW] = USES_CC_DST,
    [CC_OP_LOGICL] = USES_CC_DST,
    [CC_OP_LOGICQ] = USES_CC_DST,

    [CC_OP_INCB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_INCW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_INCL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_INCQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_DECB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_DECW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_DECL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_DECQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_SHLB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SHLW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SHLL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SHLQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_SARB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SARW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SARL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SARQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_BMILGB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_BMILGW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_BMILGL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_BMILGQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_ADCX] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADOX] = USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_ADCOX] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_CLR] = 0,
    [CC_OP_POPCNT] = USES_CC_SRC,
};

static inline void gen_jmp_im(DisasContext *s, target_ulong pc);

static void set_cc_op(DisasContext *s, CCOp op)
{
    int dead;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 cpu_cc_op = tcg_ctx->cpu_cc_op;
    TCGv cpu_cc_dst = tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src = tcg_ctx->cpu_cc_src;
    TCGv cpu_cc_src2 = tcg_ctx->cpu_cc_src2;

    if (s->cc_op == op) {
        return;
    }

    /* Discard CC computation that will no longer be used.  */
    dead = cc_op_live[s->cc_op] & ~cc_op_live[op];
    if (dead & USES_CC_DST) {
        tcg_gen_discard_tl(tcg_ctx, cpu_cc_dst);
    }
    if (dead & USES_CC_SRC) {
        tcg_gen_discard_tl(tcg_ctx, cpu_cc_src);
    }
    if (dead & USES_CC_SRC2) {
        tcg_gen_discard_tl(tcg_ctx, cpu_cc_src2);
    }
    if (dead & USES_CC_SRCT) {
        tcg_gen_discard_tl(tcg_ctx, s->cc_srcT);
    }

    if (op == CC_OP_DYNAMIC) {
        /* The DYNAMIC setting is translator only, and should never be
           stored.  Thus we always consider it clean.  */
        s->cc_op_dirty = false;
    } else {
        /* Discard any computed CC_OP value (see shifts).  */
        if (s->cc_op == CC_OP_DYNAMIC) {
            tcg_gen_discard_i32(tcg_ctx, cpu_cc_op);
        }
        s->cc_op_dirty = true;
    }
    s->cc_op = op;
}

static void gen_update_cc_op(DisasContext *s)
{
    if (s->cc_op_dirty) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        TCGv_i32 cpu_cc_op = tcg_ctx->cpu_cc_op;

        tcg_gen_movi_i32(tcg_ctx, cpu_cc_op, s->cc_op);
        s->cc_op_dirty = false;
    }
}

#ifdef TARGET_X86_64

#define NB_OP_SIZES 4

#else /* !TARGET_X86_64 */

#define NB_OP_SIZES 3

#endif /* !TARGET_X86_64 */

#if defined(HOST_WORDS_BIGENDIAN)
#define REG_B_OFFSET (sizeof(target_ulong) - 1)
#define REG_H_OFFSET (sizeof(target_ulong) - 2)
#define REG_W_OFFSET (sizeof(target_ulong) - 2)
#define REG_L_OFFSET (sizeof(target_ulong) - 4)
#define REG_LH_OFFSET (sizeof(target_ulong) - 8)
#else
#define REG_B_OFFSET 0
#define REG_H_OFFSET 1
#define REG_W_OFFSET 0
#define REG_L_OFFSET 0
#define REG_LH_OFFSET 4
#endif

/* In instruction encodings for byte register accesses the
 * register number usually indicates "low 8 bits of register N";
 * however there are some special cases where N 4..7 indicates
 * [AH, CH, DH, BH], ie "bits 15..8 of register N-4". Return
 * true for this special case, false otherwise.
 */
static inline bool byte_reg_is_xH(DisasContext *s, int reg)
{
    if (reg < 4) {
        return false;
    }
#ifdef TARGET_X86_64
    if (reg >= 8 || s->x86_64_hregs) {
        return false;
    }
#endif
    return true;
}

/* Select the size of a push/pop operation.  */
static inline MemOp mo_pushpop(DisasContext *s, MemOp ot)
{
    if (CODE64(s)) {
        return ot == MO_16 ? MO_16 : MO_64;
    } else {
        return ot;
    }
}

/* Select the size of the stack pointer.  */
static inline MemOp mo_stacksize(DisasContext *s)
{
    return CODE64(s) ? MO_64 : s->ss32 ? MO_32 : MO_16;
}

/* Select only size 64 else 32.  Used for SSE operand sizes.  */
static inline MemOp mo_64_32(MemOp ot)
{
#ifdef TARGET_X86_64
    return ot == MO_64 ? MO_64 : MO_32;
#else
    return MO_32;
#endif
}

/* Select size 8 if lsb of B is clear, else OT.  Used for decoding
   byte vs word opcodes.  */
static inline MemOp mo_b_d(int b, MemOp ot)
{
    return b & 1 ? ot : MO_8;
}

/* Select size 8 if lsb of B is clear, else OT capped at 32.
   Used for decoding operand size of port opcodes.  */
static inline MemOp mo_b_d32(int b, MemOp ot)
{
    return b & 1 ? (ot == MO_16 ? MO_16 : MO_32) : MO_8;
}

static TCGv gen_op_deposit_reg_v(DisasContext *s, MemOp ot, int reg,
                                 TCGv dest, TCGv t0)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    switch (ot) {
    case MO_8:
        if (byte_reg_is_xH(s, reg)) {
            dest = dest ? dest : tcg_ctx->cpu_regs[reg - 4];
            tcg_gen_deposit_tl(tcg_ctx, dest, tcg_ctx->cpu_regs[reg - 4],
                               t0, 8, 8);
            return tcg_ctx->cpu_regs[reg - 4];
        }
        dest = dest ? dest : tcg_ctx->cpu_regs[reg];
        tcg_gen_deposit_tl(tcg_ctx, dest, tcg_ctx->cpu_regs[reg], t0, 0, 8);
        break;
    case MO_16:
        dest = dest ? dest : tcg_ctx->cpu_regs[reg];
        tcg_gen_deposit_tl(tcg_ctx, dest, tcg_ctx->cpu_regs[reg], t0, 0, 16);
        break;
    case MO_32:
        /* For x86_64, this sets the higher half of register to zero.
           For i386, this is equivalent to a mov. */
        dest = dest ? dest : tcg_ctx->cpu_regs[reg];
        tcg_gen_ext32u_tl(tcg_ctx, dest, t0);
        break;
#ifdef TARGET_X86_64
    case MO_64:
        dest = dest ? dest : tcg_ctx->cpu_regs[reg];
        tcg_gen_mov_tl(tcg_ctx, dest, t0);
        break;
#endif
    default:
        tcg_abort();
    }
    return tcg_ctx->cpu_regs[reg];
}

static void gen_op_mov_reg_v(DisasContext *s, MemOp ot, int reg, TCGv t0)
{
    gen_op_deposit_reg_v(s, ot, reg, NULL, t0);
}

static inline
void gen_op_mov_v_reg(DisasContext *s, MemOp ot, TCGv t0, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (ot == MO_8 && byte_reg_is_xH(s, reg)) {
        tcg_gen_extract_tl(tcg_ctx, t0, tcg_ctx->cpu_regs[reg - 4], 8, 8);
    } else {
        tcg_gen_mov_tl(tcg_ctx, t0, tcg_ctx->cpu_regs[reg]);
    }
}

static void gen_add_A0_im(DisasContext *s, int val)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_addi_tl(tcg_ctx, s->A0, s->A0, val);
    if (!CODE64(s)) {
        tcg_gen_ext32u_tl(tcg_ctx, s->A0, s->A0);
    }
}

static inline void gen_op_jmp_v(TCGContext *tcg_ctx, TCGv dest)
{
    tcg_gen_st_tl(tcg_ctx, dest, tcg_ctx->cpu_env, offsetof(CPUX86State, eip));
}

static inline
void gen_op_add_reg_im(DisasContext *s, MemOp size, int reg, int32_t val)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_addi_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_regs[reg], val);
    gen_op_mov_reg_v(s, size, reg, s->tmp0);
}

static inline void gen_op_add_reg_T0(DisasContext *s, MemOp size, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_add_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_regs[reg], s->T0);
    gen_op_mov_reg_v(s, size, reg, s->tmp0);
}

static inline void gen_sync_pc(TCGContext *ctx, uint64_t pc) {
    TCGv v = tcg_temp_new(ctx);

    tcg_gen_movi_tl(ctx, v, pc);
    gen_op_jmp_v(ctx, v);

    tcg_temp_free(ctx, v);
}

static inline void gen_op_ld_v(DisasContext *s, int idx, TCGv t0, TCGv a0)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_qemu_ld_tl(tcg_ctx, t0, a0, s->mem_index, idx | MO_LE);
}

static inline void gen_op_st_v(DisasContext *s, int idx, TCGv t0, TCGv a0)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_qemu_st_tl(tcg_ctx, t0, a0, s->mem_index, idx | MO_LE);
}

static inline void gen_op_st_rm_T0_A0(DisasContext *s, int idx, int d)
{
    if (d == OR_TMP0) {
        gen_op_st_v(s, idx, s->T0, s->A0);
    } else {
        gen_op_mov_reg_v(s, idx, d, s->T0);
    }
}

static inline void gen_jmp_im(DisasContext *s, target_ulong pc)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_movi_tl(tcg_ctx, s->tmp0, pc);
    gen_op_jmp_v(tcg_ctx, s->tmp0);
}

/* Compute SEG:REG into A0.  SEG is selected from the override segment
   (OVR_SEG) and the default segment (DEF_SEG).  OVR_SEG may be -1 to
   indicate no override.  */
static void gen_lea_v_seg(DisasContext *s, MemOp aflag, TCGv a0,
                          int def_seg, int ovr_seg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    switch (aflag) {
#ifdef TARGET_X86_64
    case MO_64:
        if (ovr_seg < 0) {
            tcg_gen_mov_tl(tcg_ctx, s->A0, a0);
            return;
        }
        break;
#endif
    case MO_32:
        /* 32 bit address */
        if (ovr_seg < 0 && s->addseg) {
            ovr_seg = def_seg;
        }
        if (ovr_seg < 0) {
            tcg_gen_ext32u_tl(tcg_ctx, s->A0, a0);
            return;
        }
        break;
    case MO_16:
        /* 16 bit address */
        tcg_gen_ext16u_tl(tcg_ctx, s->A0, a0);
        a0 = s->A0;
        if (ovr_seg < 0) {
            if (s->addseg) {
                ovr_seg = def_seg;
            } else {
                return;
            }
        }
        break;
    default:
        tcg_abort();
    }

    if (ovr_seg >= 0) {
        TCGv seg = tcg_ctx->cpu_seg_base[ovr_seg];

        if (aflag == MO_64) {
            tcg_gen_add_tl(tcg_ctx, s->A0, a0, seg);
        } else if (CODE64(s)) {
            tcg_gen_ext32u_tl(tcg_ctx, s->A0, a0);
            tcg_gen_add_tl(tcg_ctx, s->A0, s->A0, seg);
        } else {
            tcg_gen_add_tl(tcg_ctx, s->A0, a0, seg);
            tcg_gen_ext32u_tl(tcg_ctx, s->A0, s->A0);
        }
    }
}

static inline void gen_string_movl_A0_ESI(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_lea_v_seg(s, s->aflag, tcg_ctx->cpu_regs[R_ESI], R_DS, s->override);
}

static inline void gen_string_movl_A0_EDI(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_lea_v_seg(s, s->aflag, tcg_ctx->cpu_regs[R_EDI], R_ES, -1);
}

static inline void gen_op_movl_T0_Dshift(DisasContext *s, MemOp ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_ld32s_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, df));
    tcg_gen_shli_tl(tcg_ctx, s->T0, s->T0, ot);
};

static TCGv gen_ext_tl(TCGContext *tcg_ctx, TCGv dst, TCGv src, MemOp size, bool sign)
{
    switch (size) {
    case MO_8:
        if (sign) {
            tcg_gen_ext8s_tl(tcg_ctx, dst, src);
        } else {
            tcg_gen_ext8u_tl(tcg_ctx, dst, src);
        }
        return dst;
    case MO_16:
        if (sign) {
            tcg_gen_ext16s_tl(tcg_ctx, dst, src);
        } else {
            tcg_gen_ext16u_tl(tcg_ctx, dst, src);
        }
        return dst;
#ifdef TARGET_X86_64
    case MO_32:
        if (sign) {
            tcg_gen_ext32s_tl(tcg_ctx, dst, src);
        } else {
            tcg_gen_ext32u_tl(tcg_ctx, dst, src);
        }
        return dst;
#endif
    default:
        return src;
    }
}

static void gen_extu(TCGContext *tcg_ctx, MemOp ot, TCGv reg)
{
    gen_ext_tl(tcg_ctx, reg, reg, ot, false);
}

static void gen_exts(TCGContext *tcg_ctx, MemOp ot, TCGv reg)
{
    gen_ext_tl(tcg_ctx, reg, reg, ot, true);
}

static inline
void gen_op_jnz_ecx(DisasContext *s, MemOp size, TCGLabel *label1)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_regs[R_ECX]);
    gen_extu(tcg_ctx, size, s->tmp0);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_NE, s->tmp0, 0, label1);
}

static inline
void gen_op_jz_ecx(DisasContext *s, MemOp size, TCGLabel *label1)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_regs[R_ECX]);
    gen_extu(tcg_ctx, size, s->tmp0);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, s->tmp0, 0, label1);
}

static void gen_helper_in_func(TCGContext *tcg_ctx, MemOp ot, TCGv v, TCGv_i32 n)
{
    switch (ot) {
    case MO_8:
        gen_helper_inb(tcg_ctx, v, tcg_ctx->cpu_env, n);
        break;
    case MO_16:
        gen_helper_inw(tcg_ctx, v, tcg_ctx->cpu_env, n);
        break;
    case MO_32:
        gen_helper_inl(tcg_ctx, v, tcg_ctx->cpu_env, n);
        break;
    default:
        tcg_abort();
    }
}

static void gen_helper_out_func(TCGContext *tcg_ctx, MemOp ot, TCGv_i32 v, TCGv_i32 n)
{
    switch (ot) {
    case MO_8:
        gen_helper_outb(tcg_ctx, tcg_ctx->cpu_env, v, n);
        break;
    case MO_16:
        gen_helper_outw(tcg_ctx, tcg_ctx->cpu_env, v, n);
        break;
    case MO_32:
        gen_helper_outl(tcg_ctx, tcg_ctx->cpu_env, v, n);
        break;
    default:
        tcg_abort();
    }
}

static void gen_check_io(DisasContext *s, MemOp ot, target_ulong cur_eip,
                         uint32_t svm_flags)
{
    // Unicorn: allow all I/O instructions
    return;

    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    target_ulong next_eip;

    if (s->pe && (s->cpl > s->iopl || s->vm86)) {
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        switch (ot) {
        case MO_8:
            gen_helper_check_iob(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
            break;
        case MO_16:
            gen_helper_check_iow(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
            break;
        case MO_32:
            gen_helper_check_iol(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
            break;
        default:
            tcg_abort();
        }
    }
    if(s->flags & HF_GUEST_MASK) {
        gen_update_cc_op(s);
        gen_jmp_im(s, cur_eip);
        svm_flags |= (1 << (4 + ot));
        next_eip = s->pc - s->cs_base;
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        gen_helper_svm_check_io(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32,
                                tcg_const_i32(tcg_ctx, svm_flags),
                                tcg_const_i32(tcg_ctx, next_eip - cur_eip));
    }
}

static inline void gen_movs(DisasContext *s, MemOp ot)
{
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, s->T0, s->A0);
    gen_string_movl_A0_EDI(s);
    gen_op_st_v(s, ot, s->T0, s->A0);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_ESI);
    gen_op_add_reg_T0(s, s->aflag, R_EDI);
}

static void gen_op_update1_cc(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
}

static void gen_op_update2_cc(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T1);
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
}

static void gen_op_update3_cc(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, reg);
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T1);
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
}

static inline void gen_op_testl_T0_T1_cc(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_and_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0, s->T1);
}

static void gen_op_update_neg_cc(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
    tcg_gen_neg_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0);
    tcg_gen_movi_tl(tcg_ctx, s->cc_srcT, 0);
}

/* compute all eflags to cc_src */
static void gen_compute_eflags(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv zero, dst, src1, src2;
    int live, dead;

    if (s->cc_op == CC_OP_EFLAGS) {
        return;
    }
    if (s->cc_op == CC_OP_CLR) {
        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_cc_src, CC_Z | CC_P);
        set_cc_op(s, CC_OP_EFLAGS);
        return;
    }

    zero = NULL;
    dst = tcg_ctx->cpu_cc_dst;
    src1 = tcg_ctx->cpu_cc_src;
    src2 = tcg_ctx->cpu_cc_src2;

    /* Take care to not read values that are not live.  */
    live = cc_op_live[s->cc_op] & ~USES_CC_SRCT;
    dead = live ^ (USES_CC_DST | USES_CC_SRC | USES_CC_SRC2);
    if (dead) {
        zero = tcg_const_tl(tcg_ctx, 0);
        if (dead & USES_CC_DST) {
            dst = zero;
        }
        if (dead & USES_CC_SRC) {
            src1 = zero;
        }
        if (dead & USES_CC_SRC2) {
            src2 = zero;
        }
    }

    gen_helper_cc_compute_all(tcg_ctx, tcg_ctx->cpu_cc_src, dst, src1, src2, tcg_ctx->cpu_cc_op);
    set_cc_op(s, CC_OP_EFLAGS);
    gen_update_cc_op(s);

    if (dead) {
        tcg_temp_free(tcg_ctx, zero);
    }
}

/* Compute all EFLAGS into REG without changing the lazy-flag state.  This is
   used for conditional evaluation, which may be followed by a faulting store
   and therefore must not commit the current instruction's flag state. */
static void gen_mov_eflags(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 cc_op;
    TCGv zero = NULL;
    TCGv dst = tcg_ctx->cpu_cc_dst;
    TCGv src1 = tcg_ctx->cpu_cc_src;
    TCGv src2 = tcg_ctx->cpu_cc_src2;
    bool free_cc_op = false;
    int live, dead;

    if (s->cc_op == CC_OP_EFLAGS) {
        tcg_gen_mov_tl(tcg_ctx, reg, tcg_ctx->cpu_cc_src);
        return;
    }
    if (s->cc_op == CC_OP_CLR) {
        tcg_gen_movi_tl(tcg_ctx, reg, CC_Z | CC_P);
        return;
    }

    live = cc_op_live[s->cc_op] & ~USES_CC_SRCT;
    dead = live ^ (USES_CC_DST | USES_CC_SRC | USES_CC_SRC2);
    if (dead) {
        zero = tcg_const_tl(tcg_ctx, 0);
        if (dead & USES_CC_DST) {
            dst = zero;
        }
        if (dead & USES_CC_SRC) {
            src1 = zero;
        }
        if (dead & USES_CC_SRC2) {
            src2 = zero;
        }
    }

    if (s->cc_op == CC_OP_DYNAMIC) {
        cc_op = tcg_ctx->cpu_cc_op;
    } else {
        cc_op = tcg_const_i32(tcg_ctx, s->cc_op);
        free_cc_op = true;
    }
    gen_helper_cc_compute_all(tcg_ctx, reg, dst, src1, src2, cc_op);
    if (free_cc_op) {
        tcg_temp_free_i32(tcg_ctx, cc_op);
    }
    if (zero != NULL) {
        tcg_temp_free(tcg_ctx, zero);
    }
}

typedef struct CCPrepare {
    TCGCond cond;
    TCGv reg;
    TCGv reg2;
    target_ulong imm;
    target_ulong mask;
    bool use_reg2;
    bool no_setcond;
} CCPrepare;

/* compute eflags.C to reg */
static CCPrepare gen_prepare_eflags_c(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv t0, t1;
    int size, shift;

    switch (s->cc_op) {
    case CC_OP_SUBB:
    case CC_OP_SUBW:
    case CC_OP_SUBL:
    case CC_OP_SUBQ:
        /* (DATA_TYPE)CC_SRCT < (DATA_TYPE)CC_SRC */
        size = s->cc_op - CC_OP_SUBB;
        t1 = gen_ext_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_cc_src, size, false);
        /* If no temporary was used, be careful not to alias t1 and t0.  */
        t0 = t1 == tcg_ctx->cpu_cc_src ? s->tmp0 : reg;
        tcg_gen_mov_tl(tcg_ctx, t0, s->cc_srcT);
        gen_extu(tcg_ctx, size, t0);
        goto add_sub;

    case CC_OP_ADDB:
    case CC_OP_ADDW:
    case CC_OP_ADDL:
    case CC_OP_ADDQ:
        /* (DATA_TYPE)CC_DST < (DATA_TYPE)CC_SRC */
        size = s->cc_op - CC_OP_ADDB;
        t1 = gen_ext_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_cc_src, size, false);
        t0 = gen_ext_tl(tcg_ctx, reg, tcg_ctx->cpu_cc_dst, size, false);
    add_sub:
        return (CCPrepare) { .cond = TCG_COND_LTU, .reg = t0,
                             .reg2 = t1, .mask = -1, .use_reg2 = true };

    case CC_OP_LOGICB:
    case CC_OP_LOGICW:
    case CC_OP_LOGICL:
    case CC_OP_LOGICQ:
    case CC_OP_CLR:
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_NEVER, .mask = -1 };

    case CC_OP_INCB:
    case CC_OP_INCW:
    case CC_OP_INCL:
    case CC_OP_INCQ:

    case CC_OP_DECB:
    case CC_OP_DECW:
    case CC_OP_DECL:
    case CC_OP_DECQ:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_src,
                             .mask = -1, .no_setcond = true };

    case CC_OP_SHLB:
    case CC_OP_SHLW:
    case CC_OP_SHLL:
    case CC_OP_SHLQ:
        /* (CC_SRC >> (DATA_BITS - 1)) & 1 */
        size = s->cc_op - CC_OP_SHLB;
        shift = (8 << size) - 1;
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_src,
                             .mask = (target_ulong)1 << shift };

    case CC_OP_MULB:
    case CC_OP_MULW:
    case CC_OP_MULL:
    case CC_OP_MULQ:
        return (CCPrepare) { .cond = TCG_COND_NE,
                             .reg = tcg_ctx->cpu_cc_src, .mask = -1 };

    case CC_OP_BMILGB:
    case CC_OP_BMILGW:
    case CC_OP_BMILGL:
    case CC_OP_BMILGQ:
        size = s->cc_op - CC_OP_BMILGB;
        t0 = gen_ext_tl(tcg_ctx, reg, tcg_ctx->cpu_cc_src, size, false);
        return (CCPrepare) { .cond = TCG_COND_EQ, .reg = t0, .mask = -1 };

    case CC_OP_ADCX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_dst,
                             .mask = -1, .no_setcond = true };

    case CC_OP_EFLAGS:
    case CC_OP_SARB:
    case CC_OP_SARW:
    case CC_OP_SARL:
    case CC_OP_SARQ:
        /* CC_SRC & 1 */
        return (CCPrepare) { .cond = TCG_COND_NE,
                             .reg = tcg_ctx->cpu_cc_src, .mask = CC_C };

    default:
       /* The need to compute only C from CC_OP_DYNAMIC is important
          in efficiently implementing e.g. INC at the start of a TB.  */
       gen_update_cc_op(s);
       gen_helper_cc_compute_c(tcg_ctx, reg, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_cc_src,
                               tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_op);
       return (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                            .mask = -1, .no_setcond = true };
    }
}

/* compute eflags.P to reg */
static CCPrepare gen_prepare_eflags_p(DisasContext *s, TCGv reg)
{
    gen_mov_eflags(s, reg);
    return (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                         .mask = CC_P };
}

/* compute eflags.S to reg */
static CCPrepare gen_prepare_eflags_s(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    switch (s->cc_op) {
    case CC_OP_DYNAMIC:
        gen_mov_eflags(s, reg);
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                             .mask = CC_S };
    case CC_OP_EFLAGS:
    case CC_OP_ADCX:
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_src,
                             .mask = CC_S };
    case CC_OP_CLR:
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_NEVER, .mask = -1 };
    default:
        {
            MemOp size = (s->cc_op - CC_OP_ADDB) & 3;
            TCGv t0 = gen_ext_tl(tcg_ctx, reg, tcg_ctx->cpu_cc_dst, size, true);
            return (CCPrepare) { .cond = TCG_COND_LT, .reg = t0, .mask = -1 };
        }
    }
}

/* compute eflags.O to reg */
static CCPrepare gen_prepare_eflags_o(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    switch (s->cc_op) {
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_src2,
                             .mask = -1, .no_setcond = true };
    case CC_OP_CLR:
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_NEVER, .mask = -1 };
    default:
        gen_mov_eflags(s, reg);
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                             .mask = CC_O };
    }
}

/* compute eflags.Z to reg */
static CCPrepare gen_prepare_eflags_z(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    switch (s->cc_op) {
    case CC_OP_DYNAMIC:
        gen_mov_eflags(s, reg);
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                             .mask = CC_Z };
    case CC_OP_EFLAGS:
    case CC_OP_ADCX:
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_src,
                             .mask = CC_Z };
    case CC_OP_CLR:
        return (CCPrepare) { .cond = TCG_COND_ALWAYS, .mask = -1 };
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_EQ, .reg = tcg_ctx->cpu_cc_src,
                             .mask = -1 };
    default:
        {
            MemOp size = (s->cc_op - CC_OP_ADDB) & 3;
            TCGv t0 = gen_ext_tl(tcg_ctx, reg, tcg_ctx->cpu_cc_dst, size, false);
            return (CCPrepare) { .cond = TCG_COND_EQ, .reg = t0, .mask = -1 };
        }
    }
}

/* perform a conditional store into register 'reg' according to jump opcode
   value 'b'. In the fast case, T0 is guaranted not to be used. */
static CCPrepare gen_prepare_cc(DisasContext *s, int b, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int inv, jcc_op, cond;
    MemOp size;
    CCPrepare cc;
    TCGv t0;

    inv = b & 1;
    jcc_op = (b >> 1) & 7;

    switch (s->cc_op) {
    case CC_OP_SUBB:
    case CC_OP_SUBW:
    case CC_OP_SUBL:
    case CC_OP_SUBQ:
        /* We optimize relational operators for the cmp/jcc case.  */
        size = s->cc_op - CC_OP_SUBB;
        switch (jcc_op) {
        case JCC_BE:
            tcg_gen_mov_tl(tcg_ctx, s->tmp4, s->cc_srcT);
            gen_extu(tcg_ctx, size, s->tmp4);
            t0 = gen_ext_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_cc_src, size, false);
            cc = (CCPrepare) { .cond = TCG_COND_LEU, .reg = s->tmp4,
                               .reg2 = t0, .mask = -1, .use_reg2 = true };
            break;

        case JCC_L:
            cond = TCG_COND_LT;
            goto fast_jcc_l;
        case JCC_LE:
            cond = TCG_COND_LE;
        fast_jcc_l:
            tcg_gen_mov_tl(tcg_ctx, s->tmp4, s->cc_srcT);
            gen_exts(tcg_ctx, size, s->tmp4);
            t0 = gen_ext_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_cc_src, size, true);
            cc = (CCPrepare) { .cond = cond, .reg = s->tmp4,
                               .reg2 = t0, .mask = -1, .use_reg2 = true };
            break;

        default:
            goto slow_jcc;
        }
        break;

    default:
    slow_jcc:
        /* This actually generates good code for JC, JZ and JS.  */
        switch (jcc_op) {
        case JCC_O:
            cc = gen_prepare_eflags_o(s, reg);
            break;
        case JCC_B:
            cc = gen_prepare_eflags_c(s, reg);
            break;
        case JCC_Z:
            cc = gen_prepare_eflags_z(s, reg);
            break;
        case JCC_BE:
            gen_mov_eflags(s, reg);
            cc = (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                               .mask = CC_Z | CC_C };
            break;
        case JCC_S:
            cc = gen_prepare_eflags_s(s, reg);
            break;
        case JCC_P:
            cc = gen_prepare_eflags_p(s, reg);
            break;
        case JCC_L:
            gen_mov_eflags(s, s->tmp4);
            tcg_gen_shri_tl(tcg_ctx, reg, s->tmp4, 4); /* CC_O -> CC_S */
            tcg_gen_xor_tl(tcg_ctx, reg, reg, s->tmp4);
            cc = (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                               .mask = CC_S };
            break;
        default:
        case JCC_LE:
            gen_mov_eflags(s, s->tmp4);
            tcg_gen_shri_tl(tcg_ctx, reg, s->tmp4, 4); /* CC_O -> CC_S */
            tcg_gen_xor_tl(tcg_ctx, reg, reg, s->tmp4);
            cc = (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                               .mask = CC_S | CC_Z };
            break;
        }
        break;
    }

    if (inv) {
        cc.cond = tcg_invert_cond(cc.cond);
    }
    return cc;
}

static void gen_setcc1(DisasContext *s, int b, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    CCPrepare cc = gen_prepare_cc(s, b, reg);

    if (cc.no_setcond) {
        if (cc.cond == TCG_COND_EQ) {
            tcg_gen_xori_tl(tcg_ctx, reg, cc.reg, 1);
        } else {
            tcg_gen_mov_tl(tcg_ctx, reg, cc.reg);
        }
        return;
    }

    if (cc.cond == TCG_COND_NE && !cc.use_reg2 && cc.imm == 0 &&
        cc.mask != 0 && (cc.mask & (cc.mask - 1)) == 0) {
        tcg_gen_shri_tl(tcg_ctx, reg, cc.reg, ctztl(cc.mask));
        tcg_gen_andi_tl(tcg_ctx, reg, reg, 1);
        return;
    }
    if (cc.mask != -1) {
        tcg_gen_andi_tl(tcg_ctx, reg, cc.reg, cc.mask);
        cc.reg = reg;
    }
    if (cc.use_reg2) {
        tcg_gen_setcond_tl(tcg_ctx, cc.cond, reg, cc.reg, cc.reg2);
    } else {
        tcg_gen_setcondi_tl(tcg_ctx, cc.cond, reg, cc.reg, cc.imm);
    }
}

static inline void gen_compute_eflags_c(DisasContext *s, TCGv reg)
{
    gen_setcc1(s, JCC_B << 1, reg);
}

/* generate a conditional jump to label 'l1' according to jump opcode
   value 'b'. In the fast case, T0 is guaranted not to be used. */
static inline void gen_jcc1_noeob(DisasContext *s, int b, TCGLabel *l1)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    CCPrepare cc = gen_prepare_cc(s, b, s->T0);

    if (cc.mask != -1) {
        tcg_gen_andi_tl(tcg_ctx, s->T0, cc.reg, cc.mask);
        cc.reg = s->T0;
    }
    if (cc.use_reg2) {
        tcg_gen_brcond_tl(tcg_ctx, cc.cond, cc.reg, cc.reg2, l1);
    } else {
        tcg_gen_brcondi_tl(tcg_ctx, cc.cond, cc.reg, cc.imm, l1);
    }
}

/* Generate a conditional jump to label 'l1' according to jump opcode
   value 'b'. In the fast case, T0 is guaranted not to be used.
   A translation block must end soon.  */
static inline void gen_jcc1(DisasContext *s, int b, TCGLabel *l1)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    CCPrepare cc;

    gen_update_cc_op(s);
    cc = gen_prepare_cc(s, b, s->T0);
    if (cc.mask != -1) {
        tcg_gen_andi_tl(tcg_ctx, s->T0, cc.reg, cc.mask);
        cc.reg = s->T0;
    }
    set_cc_op(s, CC_OP_DYNAMIC);
    if (cc.use_reg2) {
        tcg_gen_brcond_tl(tcg_ctx, cc.cond, cc.reg, cc.reg2, l1);
    } else {
        tcg_gen_brcondi_tl(tcg_ctx, cc.cond, cc.reg, cc.imm, l1);
    }
}

/* XXX: does not work with gdbstub "ice" single step - not a
   serious problem */
static TCGLabel *gen_jz_ecx_string(DisasContext *s, target_ulong next_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGLabel *l1 = gen_new_label(tcg_ctx);
    TCGLabel *l2 = gen_new_label(tcg_ctx);
    gen_op_jnz_ecx(s, s->aflag, l1);
    gen_set_label(tcg_ctx, l2);
    gen_jmp_tb(s, next_eip, 1);
    gen_set_label(tcg_ctx, l1);
    return l2;
}

static inline void gen_stos(DisasContext *s, MemOp ot)
{
    gen_op_mov_v_reg(s, MO_32, s->T0, R_EAX);
    gen_string_movl_A0_EDI(s);
    gen_op_st_v(s, ot, s->T0, s->A0);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_EDI);
}

static inline void gen_lods(DisasContext *s, MemOp ot)
{
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, s->T0, s->A0);
    gen_op_mov_reg_v(s, ot, R_EAX, s->T0);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_ESI);
}

static inline void gen_scas(DisasContext *s, MemOp ot)
{
    gen_string_movl_A0_EDI(s);
    gen_op_ld_v(s, ot, s->T1, s->A0);
    gen_op(s, OP_CMPL, ot, R_EAX);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_EDI);
}

static inline void gen_cmps(DisasContext *s, MemOp ot)
{
    gen_string_movl_A0_EDI(s);
    gen_op_ld_v(s, ot, s->T1, s->A0);
    gen_string_movl_A0_ESI(s);
    gen_op(s, OP_CMPL, ot, OR_TMP0);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_ESI);
    gen_op_add_reg_T0(s, s->aflag, R_EDI);
}

static void gen_bpt_io(DisasContext *s, TCGv_i32 t_port, int ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (s->flags & HF_IOBPT_MASK) {
        TCGv_i32 t_size = tcg_const_i32(tcg_ctx, 1 << ot);
        TCGv t_next = tcg_const_tl(tcg_ctx, s->pc - s->cs_base);

        gen_helper_bpt_io(tcg_ctx, tcg_ctx->cpu_env, t_port, t_size, t_next);
        tcg_temp_free_i32(tcg_ctx, t_size);
        tcg_temp_free(tcg_ctx, t_next);
    }
}


static inline void gen_ins(DisasContext *s, MemOp ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
        gen_io_start(tcg_ctx);
    }
    gen_string_movl_A0_EDI(s);
    /* Note: we must do this dummy write first to be restartable in
       case of page fault. */
    tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
    gen_op_st_v(s, ot, s->T0, s->A0);
    tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[R_EDX]);
    tcg_gen_andi_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, 0xffff);
    gen_helper_in_func(tcg_ctx, ot, s->T0, s->tmp2_i32);
    gen_op_st_v(s, ot, s->T0, s->A0);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_EDI);
    gen_bpt_io(s, s->tmp2_i32, ot);
    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
        gen_io_end(tcg_ctx);
    }
}

static inline void gen_outs(DisasContext *s, MemOp ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
        gen_io_start(tcg_ctx);
    }
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, s->T0, s->A0);

    tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[R_EDX]);
    tcg_gen_andi_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, 0xffff);
    tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, s->T0);
    gen_helper_out_func(tcg_ctx, ot, s->tmp2_i32, s->tmp3_i32);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_ESI);
    gen_bpt_io(s, s->tmp2_i32, ot);
    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
        gen_io_end(tcg_ctx);
    }
}

/* same method as Valgrind : we generate jumps to current or next
   instruction */
#define GEN_REPZ(op)                                                          \
static inline void gen_repz_ ## op(DisasContext *s, MemOp ot,              \
                                 target_ulong cur_eip, target_ulong next_eip) \
{                                                                             \
    TCGLabel *l2;                                                             \
    gen_update_cc_op(s);                                                      \
    l2 = gen_jz_ecx_string(s, next_eip);                                      \
    gen_ ## op(s, ot);                                                        \
    gen_op_add_reg_im(s, s->aflag, R_ECX, -1);                                \
    /* a loop would cause two single step exceptions if ECX = 1               \
       before rep string_insn */                                              \
    if (s->repz_opt)                                                          \
        gen_op_jz_ecx(s, s->aflag, l2);                                       \
    gen_jmp(s, cur_eip);                                                      \
}

#define GEN_REPZ2(op)                                                         \
static inline void gen_repz_ ## op(DisasContext *s, MemOp ot,              \
                                   target_ulong cur_eip,                      \
                                   target_ulong next_eip,                     \
                                   int nz)                                    \
{                                                                             \
    TCGLabel *l2;                                                             \
    gen_update_cc_op(s);                                                      \
    l2 = gen_jz_ecx_string(s, next_eip);                                      \
    gen_ ## op(s, ot);                                                        \
    gen_op_add_reg_im(s, s->aflag, R_ECX, -1);                                \
    gen_update_cc_op(s);                                                      \
    gen_jcc1(s, (JCC_Z << 1) | (nz ^ 1), l2);                                 \
    if (s->repz_opt)                                                          \
        gen_op_jz_ecx(s, s->aflag, l2);                                       \
    gen_jmp(s, cur_eip);                                                      \
}

GEN_REPZ(movs)
GEN_REPZ(stos)
GEN_REPZ(lods)
GEN_REPZ(ins)
GEN_REPZ(outs)
GEN_REPZ2(scas)
GEN_REPZ2(cmps)

static void gen_helper_fp_arith_ST0_FT0(TCGContext *tcg_ctx, int op)
{
    switch (op) {
    case 0:
        gen_helper_fadd_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 1:
        gen_helper_fmul_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 2:
        gen_helper_fcom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 3:
        gen_helper_fcom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 4:
        gen_helper_fsub_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 5:
        gen_helper_fsubr_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 6:
        gen_helper_fdiv_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 7:
        gen_helper_fdivr_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    }
}

/* NOTE the exception in "r" op ordering */
static void gen_helper_fp_arith_STN_ST0(TCGContext *tcg_ctx, int op, int opreg)
{
    TCGv_i32 tmp = tcg_const_i32(tcg_ctx, opreg);
    switch (op) {
    case 0:
        gen_helper_fadd_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tmp);
        break;
    case 1:
        gen_helper_fmul_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tmp);
        break;
    case 4:
        gen_helper_fsubr_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tmp);
        break;
    case 5:
        gen_helper_fsub_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tmp);
        break;
    case 6:
        gen_helper_fdivr_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tmp);
        break;
    case 7:
        gen_helper_fdiv_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tmp);
        break;
    }
}

static void gen_exception(DisasContext *s, int trapno, target_ulong cur_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_update_cc_op(s);
    gen_jmp_im(s, cur_eip);
    gen_helper_raise_exception(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, trapno));
    s->base.is_jmp = DISAS_NORETURN;
}

/* Generate #UD for the current instruction.  The assumption here is that
   the instruction is known, but it isn't allowed in the current cpu mode.  */
static void gen_illegal_opcode(DisasContext *s)
{
    gen_exception(s, EXCP06_ILLOP, s->pc_start - s->cs_base);
}

/* if d == OR_TMP0, it means memory operand (address in A0) */
static void gen_op(DisasContext *s1, int op, MemOp ot, int d)
{
    TCGContext *tcg_ctx = s1->uc->tcg_ctx;
    uc_engine *uc = s1->uc;

    /* Invalid lock prefix when destination is not memory or OP_CMPL. */
    if ((d != OR_TMP0 || op == OP_CMPL) && s1->prefix & PREFIX_LOCK){
        gen_illegal_opcode(s1);
        return;
    }

    if (d != OR_TMP0) {
        gen_op_mov_v_reg(s1, ot, s1->T0, d);
    } else if (!(s1->prefix & PREFIX_LOCK)) {
        gen_op_ld_v(s1, ot, s1->T0, s1->A0);
    }
    switch(op) {
    case OP_ADCL:
        gen_compute_eflags_c(s1, s1->tmp4);
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_add_tl(tcg_ctx, s1->T0, s1->tmp4, s1->T1);
            tcg_gen_atomic_add_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T0,
                                        s1->mem_index, ot | MO_LE);
        } else {
            tcg_gen_add_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            tcg_gen_add_tl(tcg_ctx, s1->T0, s1->T0, s1->tmp4);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update3_cc(s1, s1->tmp4);
        set_cc_op(s1, CC_OP_ADCB + ot);
        break;
    case OP_SBBL:
        gen_compute_eflags_c(s1, s1->tmp4);
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_add_tl(tcg_ctx, s1->T0, s1->T1, s1->tmp4);
            tcg_gen_neg_tl(tcg_ctx, s1->T0, s1->T0);
            tcg_gen_atomic_add_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T0,
                                        s1->mem_index, ot | MO_LE);
        } else {
            tcg_gen_sub_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            tcg_gen_sub_tl(tcg_ctx, s1->T0, s1->T0, s1->tmp4);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update3_cc(s1, s1->tmp4);
        set_cc_op(s1, CC_OP_SBBB + ot);
        break;
    case OP_ADDL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_atomic_add_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T1,
                                        s1->mem_index, ot | MO_LE);
        } else {
            tcg_gen_add_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update2_cc(s1);
        set_cc_op(s1, CC_OP_ADDB + ot);
        break;
    case OP_SUBL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_neg_tl(tcg_ctx, s1->T0, s1->T1);
            tcg_gen_atomic_fetch_add_tl(tcg_ctx, s1->cc_srcT, s1->A0, s1->T0,
                                        s1->mem_index, ot | MO_LE);
            tcg_gen_sub_tl(tcg_ctx, s1->T0, s1->cc_srcT, s1->T1);
        } else {
            tcg_gen_mov_tl(tcg_ctx, s1->cc_srcT, s1->T0);
            tcg_gen_sub_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        
        if (HOOK_EXISTS_BOUNDED(uc, UC_HOOK_TCG_OPCODE, s1->pc_start)) {
            struct hook *hook;
            HOOK_FOREACH_VAR_DECLARE;
            HOOK_FOREACH(uc, hook, UC_HOOK_TCG_OPCODE) {
                if (hook->to_delete)
                    continue;
                if (hook->op == UC_TCG_OP_SUB && (hook->op_flags & UC_TCG_OP_FLAG_DIRECT) ) {
                    // TCGv is just an offset to tcg_ctx so it's safe to do so.
                    gen_uc_traceopcode(tcg_ctx, hook, (TCGv_i64)s1->T0, (TCGv_i64)s1->T1, 1 << ((ot & MO_SIZE) + 3), uc, s1->pc_start);
                }
            }
        }

        gen_op_update2_cc(s1);
        set_cc_op(s1, CC_OP_SUBB + ot);
        break;
    default:
    case OP_ANDL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_atomic_and_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T1,
                                        s1->mem_index, ot | MO_LE);
        } else {
            tcg_gen_and_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update1_cc(s1);
        set_cc_op(s1, CC_OP_LOGICB + ot);
        break;
    case OP_ORL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_atomic_or_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T1,
                                       s1->mem_index, ot | MO_LE);
        } else {
            tcg_gen_or_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update1_cc(s1);
        set_cc_op(s1, CC_OP_LOGICB + ot);
        break;
    case OP_XORL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_atomic_xor_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T1,
                                        s1->mem_index, ot | MO_LE);
        } else {
            tcg_gen_xor_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update1_cc(s1);
        set_cc_op(s1, CC_OP_LOGICB + ot);
        break;
    case OP_CMPL:
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s1->T1);
        tcg_gen_mov_tl(tcg_ctx, s1->cc_srcT, s1->T0);
        tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s1->T0, s1->T1);

        if (HOOK_EXISTS_BOUNDED(uc, UC_HOOK_TCG_OPCODE, s1->pc_start)) {
            struct hook *hook;
            HOOK_FOREACH_VAR_DECLARE;
            HOOK_FOREACH(uc, hook, UC_HOOK_TCG_OPCODE) {
                if (hook->to_delete)
                    continue;
                if (hook->op == UC_TCG_OP_SUB && (hook->op_flags & UC_TCG_OP_FLAG_CMP) ) {
                    // TCGv is just an offset to tcg_ctx so it's safe to do so.
                    gen_uc_traceopcode(tcg_ctx, hook, (TCGv_i64)s1->T0, (TCGv_i64)s1->T1, 1 << ((ot & MO_SIZE) + 3), uc, s1->pc_start);
                }
            }
        }

        set_cc_op(s1, CC_OP_SUBB + ot);
        break;
    }
}

/* if d == OR_TMP0, it means memory operand (address in A0) */
static void gen_inc(DisasContext *s1, MemOp ot, int d, int c)
{
    TCGContext *tcg_ctx = s1->uc->tcg_ctx;

    if (s1->prefix & PREFIX_LOCK) {
        if (d != OR_TMP0) {
            /* Lock prefix when destination is not memory */
            gen_illegal_opcode(s1);
            return;
        }
        tcg_gen_movi_tl(tcg_ctx, s1->T0, c > 0 ? 1 : -1);
        tcg_gen_atomic_add_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T0,
                                    s1->mem_index, ot | MO_LE);
    } else {
        if (d != OR_TMP0) {
            gen_op_mov_v_reg(s1, ot, s1->T0, d);
        } else {
            gen_op_ld_v(s1, ot, s1->T0, s1->A0);
        }
        tcg_gen_addi_tl(tcg_ctx, s1->T0, s1->T0, (c > 0 ? 1 : -1));
        gen_op_st_rm_T0_A0(s1, ot, d);
    }

    gen_compute_eflags_c(s1, tcg_ctx->cpu_cc_src);
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s1->T0);
    set_cc_op(s1, (c > 0 ? CC_OP_INCB : CC_OP_DECB) + ot);
}

static void gen_shift_flags(DisasContext *s, MemOp ot, TCGv result,
                            TCGv shm1, TCGv count, bool is_right)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 z32, s32, oldop;
    TCGv z_tl;

    /* Store the results into the CC variables.  If we know that the
       variable must be dead, store unconditionally.  Otherwise we'll
       need to not disrupt the current contents.  */
    z_tl = tcg_const_tl(tcg_ctx, 0);
    if (cc_op_live[s->cc_op] & USES_CC_DST) {
        tcg_gen_movcond_tl(tcg_ctx, TCG_COND_NE, tcg_ctx->cpu_cc_dst, count, z_tl,
                           result, tcg_ctx->cpu_cc_dst);
    } else {
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, result);
    }
    if (cc_op_live[s->cc_op] & USES_CC_SRC) {
        tcg_gen_movcond_tl(tcg_ctx, TCG_COND_NE, tcg_ctx->cpu_cc_src, count, z_tl,
                           shm1, tcg_ctx->cpu_cc_src);
    } else {
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, shm1);
    }
    tcg_temp_free(tcg_ctx, z_tl);

    /* Get the two potential CC_OP values into temporaries.  */
    tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, (is_right ? CC_OP_SARB : CC_OP_SHLB) + ot);
    if (s->cc_op == CC_OP_DYNAMIC) {
        oldop = tcg_ctx->cpu_cc_op;
    } else {
        tcg_gen_movi_i32(tcg_ctx, s->tmp3_i32, s->cc_op);
        oldop = s->tmp3_i32;
    }

    /* Conditionally store the CC_OP value.  */
    z32 = tcg_const_i32(tcg_ctx, 0);
    s32 = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_trunc_tl_i32(tcg_ctx, s32, count);
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_NE, tcg_ctx->cpu_cc_op, s32, z32, s->tmp2_i32, oldop);
    tcg_temp_free_i32(tcg_ctx, z32);
    tcg_temp_free_i32(tcg_ctx, s32);

    /* The CC_OP value is no longer predictable.  */
    set_cc_op(s, CC_OP_DYNAMIC);
}

static void gen_shift_rm_T1(DisasContext *s, MemOp ot, int op1,
                            int is_right, int is_arith)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    target_ulong mask = (ot == MO_64 ? 0x3f : 0x1f);

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, s->T0, s->A0);
    } else {
        gen_op_mov_v_reg(s, ot, s->T0, op1);
    }

    tcg_gen_andi_tl(tcg_ctx, s->T1, s->T1, mask);
    tcg_gen_subi_tl(tcg_ctx, s->tmp0, s->T1, 1);

    if (is_right) {
        if (is_arith) {
            gen_exts(tcg_ctx, ot, s->T0);
            tcg_gen_sar_tl(tcg_ctx, s->tmp0, s->T0, s->tmp0);
            tcg_gen_sar_tl(tcg_ctx, s->T0, s->T0, s->T1);
        } else {
            gen_extu(tcg_ctx, ot, s->T0);
            tcg_gen_shr_tl(tcg_ctx, s->tmp0, s->T0, s->tmp0);
            tcg_gen_shr_tl(tcg_ctx, s->T0, s->T0, s->T1);
        }
    } else {
        tcg_gen_shl_tl(tcg_ctx, s->tmp0, s->T0, s->tmp0);
        tcg_gen_shl_tl(tcg_ctx, s->T0, s->T0, s->T1);
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    gen_shift_flags(s, ot, s->T0, s->tmp0, s->T1, is_right);
}

static void gen_shift_rm_im(DisasContext *s, MemOp ot, int op1, int op2,
                            int is_right, int is_arith)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mask = (ot == MO_64 ? 0x3f : 0x1f);

    /* load */
    if (op1 == OR_TMP0)
        gen_op_ld_v(s, ot, s->T0, s->A0);
    else
        gen_op_mov_v_reg(s, ot, s->T0, op1);

    op2 &= mask;
    if (op2 != 0) {
        if (is_right) {
            if (is_arith) {
                gen_exts(tcg_ctx, ot, s->T0);
                tcg_gen_sari_tl(tcg_ctx, s->tmp4, s->T0, op2 - 1);
                tcg_gen_sari_tl(tcg_ctx, s->T0, s->T0, op2);
            } else {
                gen_extu(tcg_ctx, ot, s->T0);
                tcg_gen_shri_tl(tcg_ctx, s->tmp4, s->T0, op2 - 1);
                tcg_gen_shri_tl(tcg_ctx, s->T0, s->T0, op2);
            }
        } else {
            tcg_gen_shli_tl(tcg_ctx, s->tmp4, s->T0, op2 - 1);
            tcg_gen_shli_tl(tcg_ctx, s->T0, s->T0, op2);
        }
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    /* update eflags if non zero shift */
    if (op2 != 0) {
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->tmp4);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
        set_cc_op(s, (is_right ? CC_OP_SARB : CC_OP_SHLB) + ot);
    }
}

static void gen_rot_rm_T1(DisasContext *s, MemOp ot, int op1, int is_right)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    target_ulong mask = (ot == MO_64 ? 0x3f : 0x1f);
    TCGv_i32 t0, t1;

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, s->T0, s->A0);
    } else {
        gen_op_mov_v_reg(s, ot, s->T0, op1);
    }

    tcg_gen_andi_tl(tcg_ctx, s->T1, s->T1, mask);

    switch (ot) {
    case MO_8:
        /* Replicate the 8-bit input so that a 32-bit rotate works.  */
        tcg_gen_ext8u_tl(tcg_ctx, s->T0, s->T0);
        tcg_gen_muli_tl(tcg_ctx, s->T0, s->T0, 0x01010101);
        goto do_long;
    case MO_16:
        /* Replicate the 16-bit input so that a 32-bit rotate works.  */
        tcg_gen_deposit_tl(tcg_ctx, s->T0, s->T0, s->T0, 16, 16);
        goto do_long;
    do_long:
#ifdef TARGET_X86_64
    case MO_32:
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, s->T1);
        if (is_right) {
            tcg_gen_rotr_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, s->tmp3_i32);
        } else {
            tcg_gen_rotl_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, s->tmp3_i32);
        }
        tcg_gen_extu_i32_tl(tcg_ctx, s->T0, s->tmp2_i32);
        break;
#endif
    default:
        if (is_right) {
            tcg_gen_rotr_tl(tcg_ctx, s->T0, s->T0, s->T1);
        } else {
            tcg_gen_rotl_tl(tcg_ctx, s->T0, s->T0, s->T1);
        }
        break;
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    /* We'll need the flags computed into CC_SRC.  */
    gen_compute_eflags(s);

    /* The value that was "rotated out" is now present at the other end
       of the word.  Compute C into CC_DST and O into CC_SRC2.  Note that
       since we've computed the flags into CC_SRC, these variables are
       currently dead.  */
    if (is_right) {
        tcg_gen_shri_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, s->T0, mask - 1);
        tcg_gen_shri_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0, mask);
        tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_cc_dst, 1);
    } else {
        tcg_gen_shri_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, s->T0, mask);
        tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0, 1);
    }
    tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_src2, 1);
    tcg_gen_xor_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_dst);

    /* Now conditionally store the new CC_OP value.  If the shift count
       is 0 we keep the CC_OP_EFLAGS setting so that only CC_SRC is live.
       Otherwise reuse CC_OP_ADCOX which have the C and O flags split out
       exactly as we computed above.  */
    t0 = tcg_const_i32(tcg_ctx, 0);
    t1 = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_trunc_tl_i32(tcg_ctx, t1, s->T1);
    tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, CC_OP_ADCOX);
    tcg_gen_movi_i32(tcg_ctx, s->tmp3_i32, CC_OP_EFLAGS);
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_NE, tcg_ctx->cpu_cc_op, t1, t0,
                        s->tmp2_i32, s->tmp3_i32);
    tcg_temp_free_i32(tcg_ctx, t0);
    tcg_temp_free_i32(tcg_ctx, t1);

    /* The CC_OP value is no longer predictable.  */ 
    set_cc_op(s, CC_OP_DYNAMIC);
}

static void gen_rot_rm_im(DisasContext *s, MemOp ot, int op1, int op2,
                          int is_right)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mask = (ot == MO_64 ? 0x3f : 0x1f);
    int shift;

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, s->T0, s->A0);
    } else {
        gen_op_mov_v_reg(s, ot, s->T0, op1);
    }

    op2 &= mask;
    if (op2 != 0) {
        switch (ot) {
#ifdef TARGET_X86_64
        case MO_32:
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
            if (is_right) {
                tcg_gen_rotri_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, op2);
            } else {
                tcg_gen_rotli_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, op2);
            }
            tcg_gen_extu_i32_tl(tcg_ctx, s->T0, s->tmp2_i32);
            break;
#endif
        default:
            if (is_right) {
                tcg_gen_rotri_tl(tcg_ctx, s->T0, s->T0, op2);
            } else {
                tcg_gen_rotli_tl(tcg_ctx, s->T0, s->T0, op2);
            }
            break;
        case MO_8:
            mask = 7;
            goto do_shifts;
        case MO_16:
            mask = 15;
        do_shifts:
            shift = op2 & mask;
            if (is_right) {
                shift = mask + 1 - shift;
            }
            gen_extu(tcg_ctx, ot, s->T0);
            tcg_gen_shli_tl(tcg_ctx, s->tmp0, s->T0, shift);
            tcg_gen_shri_tl(tcg_ctx, s->T0, s->T0, mask + 1 - shift);
            tcg_gen_or_tl(tcg_ctx, s->T0, s->T0, s->tmp0);
            break;
        }
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    if (op2 != 0) {
        /* Compute the flags into CC_SRC.  */
        gen_compute_eflags(s);

        /* The value that was "rotated out" is now present at the other end
           of the word.  Compute C into CC_DST and O into CC_SRC2.  Note that
           since we've computed the flags into CC_SRC, these variables are
           currently dead.  */
        if (is_right) {
            tcg_gen_shri_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, s->T0, mask - 1);
            tcg_gen_shri_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0, mask);
            tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_cc_dst, 1);
        } else {
            tcg_gen_shri_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, s->T0, mask);
            tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0, 1);
        }
        tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_src2, 1);
        tcg_gen_xor_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_dst);
        set_cc_op(s, CC_OP_ADCOX);
    }
}

/* XXX: add faster immediate = 1 case */
static void gen_rotc_rm_T1(DisasContext *s, MemOp ot, int op1,
                           int is_right)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_compute_eflags(s);
    // assert(s->cc_op == CC_OP_EFLAGS);

    /* load */
    if (op1 == OR_TMP0)
        gen_op_ld_v(s, ot, s->T0, s->A0);
    else
        gen_op_mov_v_reg(s, ot, s->T0, op1);
    
    if (is_right) {
        switch (ot) {
        case MO_8:
            gen_helper_rcrb(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
        case MO_16:
            gen_helper_rcrw(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
        case MO_32:
            gen_helper_rcrl(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
#ifdef TARGET_X86_64
        case MO_64:
            gen_helper_rcrq(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
#endif
        default:
            tcg_abort();
        }
    } else {
        switch (ot) {
        case MO_8:
            gen_helper_rclb(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
        case MO_16:
            gen_helper_rclw(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
        case MO_32:
            gen_helper_rcll(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
#ifdef TARGET_X86_64
        case MO_64:
            gen_helper_rclq(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
#endif
        default:
            tcg_abort();
        }
    }
    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);
}

/* XXX: add faster immediate case */
static void gen_shiftd_rm_T1(DisasContext *s, MemOp ot, int op1,
                             bool is_right, TCGv count_in)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    target_ulong mask = (ot == MO_64 ? 63 : 31);
    TCGv count;

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, s->T0, s->A0);
    } else {
        gen_op_mov_v_reg(s, ot, s->T0, op1);
    }

    count = tcg_temp_new(tcg_ctx);
    tcg_gen_andi_tl(tcg_ctx, count, count_in, mask);

    switch (ot) {
    case MO_16:
        /* Note: we implement the Intel behaviour for shift count > 16.
           This means "shrdw C, B, A" shifts A:B:A >> C.  Build the B:A
           portion by constructing it as a 32-bit value.  */
        if (is_right) {
            tcg_gen_deposit_tl(tcg_ctx, s->tmp0, s->T0, s->T1, 16, 16);
            tcg_gen_mov_tl(tcg_ctx, s->T1, s->T0);
            tcg_gen_mov_tl(tcg_ctx, s->T0, s->tmp0);
        } else {
            tcg_gen_deposit_tl(tcg_ctx, s->T1, s->T0, s->T1, 16, 16);
        }
        /* FALLTHRU */
#ifdef TARGET_X86_64
    case MO_32:
        /* Concatenate the two 32-bit values and use a 64-bit shift.  */
        tcg_gen_subi_tl(tcg_ctx, s->tmp0, count, 1);
        if (is_right) {
            tcg_gen_concat_tl_i64(tcg_ctx, s->T0, s->T0, s->T1);
            tcg_gen_shr_i64(tcg_ctx, s->tmp0, s->T0, s->tmp0);
            tcg_gen_shr_i64(tcg_ctx, s->T0, s->T0, count);
        } else {
            tcg_gen_concat_tl_i64(tcg_ctx, s->T0, s->T1, s->T0);
            tcg_gen_shl_i64(tcg_ctx, s->tmp0, s->T0, s->tmp0);
            tcg_gen_shl_i64(tcg_ctx, s->T0, s->T0, count);
            tcg_gen_shri_i64(tcg_ctx, s->tmp0, s->tmp0, 32);
            tcg_gen_shri_i64(tcg_ctx, s->T0, s->T0, 32);
        }
        break;
#endif
    default:
        tcg_gen_subi_tl(tcg_ctx, s->tmp0, count, 1);
        if (is_right) {
            tcg_gen_shr_tl(tcg_ctx, s->tmp0, s->T0, s->tmp0);

            tcg_gen_subfi_tl(tcg_ctx, s->tmp4, mask + 1, count);
            tcg_gen_shr_tl(tcg_ctx, s->T0, s->T0, count);
            tcg_gen_shl_tl(tcg_ctx, s->T1, s->T1, s->tmp4);
        } else {
            tcg_gen_shl_tl(tcg_ctx, s->tmp0, s->T0, s->tmp0);
            if (ot == MO_16) {
                /* Only needed if count > 16, for Intel behaviour.  */
                tcg_gen_subfi_tl(tcg_ctx, s->tmp4, 33, count);
                tcg_gen_shr_tl(tcg_ctx, s->tmp4, s->T1, s->tmp4);
                tcg_gen_or_tl(tcg_ctx, s->tmp0, s->tmp0, s->tmp4);
            }

            tcg_gen_subfi_tl(tcg_ctx, s->tmp4, mask + 1, count);
            tcg_gen_shl_tl(tcg_ctx, s->T0, s->T0, count);
            tcg_gen_shr_tl(tcg_ctx, s->T1, s->T1, s->tmp4);
        }
        tcg_gen_movi_tl(tcg_ctx, s->tmp4, 0);
        tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, s->T1, count, s->tmp4,
                           s->tmp4, s->T1);
        tcg_gen_or_tl(tcg_ctx, s->T0, s->T0, s->T1);
        break;
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    gen_shift_flags(s, ot, s->T0, s->tmp0, count, is_right);
    tcg_temp_free(tcg_ctx, count);
}

static void gen_shift(DisasContext *s1, int op, MemOp ot, int d, int s)
{
    if (s != OR_TMP1)
        gen_op_mov_v_reg(s1, ot, s1->T1, s);
    switch(op) {
    case OP_ROL:
        gen_rot_rm_T1(s1, ot, d, 0);
        break;
    case OP_ROR:
        gen_rot_rm_T1(s1, ot, d, 1);
        break;
    case OP_SHL:
    case OP_SHL1:
        gen_shift_rm_T1(s1, ot, d, 0, 0);
        break;
    case OP_SHR:
        gen_shift_rm_T1(s1, ot, d, 1, 0);
        break;
    case OP_SAR:
        gen_shift_rm_T1(s1, ot, d, 1, 1);
        break;
    case OP_RCL:
        gen_rotc_rm_T1(s1, ot, d, 0);
        break;
    case OP_RCR:
        gen_rotc_rm_T1(s1, ot, d, 1);
        break;
    }
}

static void gen_shifti(DisasContext *s1, int op, MemOp ot, int d, int c)
{
    TCGContext *tcg_ctx = s1->uc->tcg_ctx;

    switch(op) {
    case OP_ROL:
        gen_rot_rm_im(s1, ot, d, c, 0);
        break;
    case OP_ROR:
        gen_rot_rm_im(s1, ot, d, c, 1);
        break;
    case OP_SHL:
    case OP_SHL1:
        gen_shift_rm_im(s1, ot, d, c, 0, 0);
        break;
    case OP_SHR:
        gen_shift_rm_im(s1, ot, d, c, 1, 0);
        break;
    case OP_SAR:
        gen_shift_rm_im(s1, ot, d, c, 1, 1);
        break;
    default:
        /* currently not optimized */
        tcg_gen_movi_tl(tcg_ctx, s1->T1, c);
        gen_shift(s1, op, ot, d, OR_TMP1);
        break;
    }
}

#define X86_MAX_INSN_LENGTH 15

static uint64_t advance_pc(CPUX86State *env, DisasContext *s, int num_bytes)
{
    uint64_t pc = s->pc;

    s->pc += num_bytes;
    if (unlikely(s->pc - s->pc_start > X86_MAX_INSN_LENGTH)) {
        /* If the instruction's 16th byte is on a different page than the 1st, a
         * page fault on the second page wins over the general protection fault
         * caused by the instruction being too long.
         * This can happen even if the operand is only one byte long!
         */
        if (((s->pc - 1) ^ (pc - 1)) & TARGET_PAGE_MASK) {
            volatile uint8_t unused =
                cpu_ldub_code(env, (s->pc - 1) & TARGET_PAGE_MASK);
            (void) unused;
        }
        siglongjmp(s->jmpbuf, 1);
    }

    return pc;
}

static inline uint8_t x86_ldub_code(CPUX86State *env, DisasContext *s)
{
    return translator_ldub(env->uc->tcg_ctx, env, advance_pc(env, s, 1));
}

static inline uint16_t x86_lduw_code(CPUX86State *env, DisasContext *s)
{
    return translator_lduw(env->uc->tcg_ctx, env, advance_pc(env, s, 2));
}

static inline uint32_t x86_ldl_code(CPUX86State *env, DisasContext *s)
{
    return translator_ldl(env->uc->tcg_ctx, env, advance_pc(env, s, 4));
}

#ifdef TARGET_X86_64
static inline uint64_t x86_ldq_code(CPUX86State *env, DisasContext *s)
{
    return translator_ldq(env->uc->tcg_ctx, env, advance_pc(env, s, 8));
}
#endif

/* Decompose an address.  */

typedef struct AddressParts {
    int def_seg;
    int base;
    int index;
    int scale;
    target_long disp;
} AddressParts;

static AddressParts gen_lea_modrm_0_scaled(CPUX86State *env,
                                           DisasContext *s, int modrm,
                                           int disp8_scale)
{
    int def_seg, base, index, scale, mod, rm;
    target_long disp;
    bool havesib;

    def_seg = R_DS;
    index = -1;
    scale = 0;
    disp = 0;

    mod = (modrm >> 6) & 3;
    rm = modrm & 7;
    base = rm | REX_B(s);

    if (mod == 3) {
        /* Normally filtered out earlier, but including this path
           simplifies multi-byte nop, as well as bndcl, bndcu, bndcn.  */
        goto done;
    }

    switch (s->aflag) {
    case MO_64:
    case MO_32:
        havesib = 0;
        if (rm == 4) {
            int code = x86_ldub_code(env, s);
            scale = (code >> 6) & 3;
            index = ((code >> 3) & 7) | REX_X(s);
            if (index == 4) {
                index = -1;  /* no index */
            }
            base = (code & 7) | REX_B(s);
            havesib = 1;
        }

        switch (mod) {
        case 0:
            if ((base & 7) == 5) {
                base = -1;
                disp = (int32_t)x86_ldl_code(env, s);
                if (CODE64(s) && !havesib) {
                    base = -2;
                    disp += s->pc + s->rip_offset;
                }
            }
            break;
        case 1:
            disp = (int8_t)x86_ldub_code(env, s) * disp8_scale;
            break;
        default:
        case 2:
            disp = (int32_t)x86_ldl_code(env, s);
            break;
        }

        /* For correct popl handling with esp.  */
        if (base == R_ESP && s->popl_esp_hack) {
            disp += s->popl_esp_hack;
        }
        if (base == R_EBP || base == R_ESP) {
            def_seg = R_SS;
        }
        break;

    case MO_16:
        if (mod == 0) {
            if (rm == 6) {
                base = -1;
                disp = x86_lduw_code(env, s);
                break;
            }
        } else if (mod == 1) {
            disp = (int8_t)x86_ldub_code(env, s) * disp8_scale;
        } else {
            disp = (int16_t)x86_lduw_code(env, s);
        }

        switch (rm) {
        case 0:
            base = R_EBX;
            index = R_ESI;
            break;
        case 1:
            base = R_EBX;
            index = R_EDI;
            break;
        case 2:
            base = R_EBP;
            index = R_ESI;
            def_seg = R_SS;
            break;
        case 3:
            base = R_EBP;
            index = R_EDI;
            def_seg = R_SS;
            break;
        case 4:
            base = R_ESI;
            break;
        case 5:
            base = R_EDI;
            break;
        case 6:
            base = R_EBP;
            def_seg = R_SS;
            break;
        default:
        case 7:
            base = R_EBX;
            break;
        }
        break;

    default:
        tcg_abort();
    }

 done:
    return (AddressParts){ def_seg, base, index, scale, disp };
}

static AddressParts gen_lea_modrm_0(CPUX86State *env, DisasContext *s,
                                    int modrm)
{
    return gen_lea_modrm_0_scaled(env, s, modrm, 1);
}

/* Compute the address, with a minimum number of TCG ops.  */
static TCGv gen_lea_modrm_1(DisasContext *s, AddressParts a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv ea = NULL;

    if (a.index >= 0) {
        if (a.scale == 0) {
            ea = tcg_ctx->cpu_regs[a.index];
        } else {
            tcg_gen_shli_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[a.index], a.scale);
            ea = s->A0;
        }
        if (a.base >= 0) {
            tcg_gen_add_tl(tcg_ctx, s->A0, ea, tcg_ctx->cpu_regs[a.base]);
            ea = s->A0;
        }
    } else if (a.base >= 0) {
        ea = tcg_ctx->cpu_regs[a.base];
    }
    if (!ea) {
        tcg_gen_movi_tl(tcg_ctx, s->A0, a.disp);
        ea = s->A0;
    } else if (a.disp != 0) {
        tcg_gen_addi_tl(tcg_ctx, s->A0, ea, a.disp);
        ea = s->A0;
    }

    return ea;
}

static void gen_lea_modrm(CPUX86State *env, DisasContext *s, int modrm)
{
    AddressParts a = gen_lea_modrm_0(env, s, modrm);
    TCGv ea = gen_lea_modrm_1(s, a);
    gen_lea_v_seg(s, s->aflag, ea, a.def_seg, s->override);
}

static void gen_nop_modrm(CPUX86State *env, DisasContext *s, int modrm)
{
    (void)gen_lea_modrm_0(env, s, modrm);
}

/* Used for BNDCL, BNDCU, BNDCN.  */
static void gen_bndck(CPUX86State *env, DisasContext *s, int modrm,
                      TCGCond cond, TCGv_i64 bndv)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv ea = gen_lea_modrm_1(s, gen_lea_modrm_0(env, s, modrm));

    tcg_gen_extu_tl_i64(tcg_ctx, s->tmp1_i64, ea);
    if (!CODE64(s)) {
        tcg_gen_ext32u_i64(tcg_ctx, s->tmp1_i64, s->tmp1_i64);
    }
    tcg_gen_setcond_i64(tcg_ctx, cond, s->tmp1_i64, s->tmp1_i64, bndv);
    tcg_gen_extrl_i64_i32(tcg_ctx, s->tmp2_i32, s->tmp1_i64);
    gen_helper_bndck(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
}

/* used for LEA and MOV AX, mem */
static void gen_add_A0_ds_seg(DisasContext *s)
{
    gen_lea_v_seg(s, s->aflag, s->A0, R_DS, s->override);
}

/* generate modrm memory load or store of 'reg'. TMP0 is used if reg ==
   OR_TMP0 */
static void gen_ldst_modrm(CPUX86State *env, DisasContext *s, int modrm,
                           MemOp ot, int reg, int is_store)
{
    int mod, rm;

    mod = (modrm >> 6) & 3;
    rm = (modrm & 7) | REX_B(s);
    if (mod == 3) {
        if (is_store) {
            if (reg != OR_TMP0)
                gen_op_mov_v_reg(s, ot, s->T0, reg);
            gen_op_mov_reg_v(s, ot, rm, s->T0);
        } else {
            gen_op_mov_v_reg(s, ot, s->T0, rm);
            if (reg != OR_TMP0)
                gen_op_mov_reg_v(s, ot, reg, s->T0);
        }
    } else {
        gen_lea_modrm(env, s, modrm);
        if (is_store) {
            if (reg != OR_TMP0)
                gen_op_mov_v_reg(s, ot, s->T0, reg);
            gen_op_st_v(s, ot, s->T0, s->A0);
        } else {
            gen_op_ld_v(s, ot, s->T0, s->A0);
            if (reg != OR_TMP0)
                gen_op_mov_reg_v(s, ot, reg, s->T0);
        }
    }
}

static inline uint32_t insn_get(CPUX86State *env, DisasContext *s, MemOp ot)
{
    uint32_t ret;

    switch (ot) {
    case MO_8:
        ret = x86_ldub_code(env, s);
        break;
    case MO_16:
        ret = x86_lduw_code(env, s);
        break;
    case MO_32:
#ifdef TARGET_X86_64
    case MO_64:
#endif
        ret = x86_ldl_code(env, s);
        break;
    default:
        tcg_abort();
    }
    return ret;
}

static inline int insn_const_size(MemOp ot)
{
    if (ot <= MO_32) {
        return 1 << ot;
    } else {
        return 4;
    }
}

static inline bool use_goto_tb(DisasContext *s, target_ulong pc)
{
    return (pc & TARGET_PAGE_MASK) == (s->base.tb->pc & TARGET_PAGE_MASK) ||
           (pc & TARGET_PAGE_MASK) == (s->pc_start & TARGET_PAGE_MASK);
}

static inline void gen_goto_tb(DisasContext *s, int tb_num, target_ulong eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    target_ulong pc = s->cs_base + eip;

    if (use_goto_tb(s, pc))  {
        /* jump to same page: we can use a direct jump */
        tcg_gen_goto_tb(tcg_ctx, tb_num);
        gen_jmp_im(s, eip);
        tcg_gen_exit_tb(tcg_ctx, s->base.tb, tb_num);
        s->base.is_jmp = DISAS_NORETURN;
    } else {
        /* jump to another page */
        gen_jmp_im(s, eip);
        gen_jr(s, s->tmp0);
    }
}

static inline void gen_jcc(DisasContext *s, int b,
                           target_ulong val, target_ulong next_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGLabel *l1, *l2;

    if (s->jmp_opt) {
        l1 = gen_new_label(tcg_ctx);
        gen_jcc1(s, b, l1);

        gen_goto_tb(s, 0, next_eip);

        gen_set_label(tcg_ctx, l1);
        gen_goto_tb(s, 1, val);
    } else {
        l1 = gen_new_label(tcg_ctx);
        l2 = gen_new_label(tcg_ctx);
        gen_jcc1(s, b, l1);

        gen_jmp_im(s, next_eip);
        tcg_gen_br(tcg_ctx, l2);

        gen_set_label(tcg_ctx, l1);
        gen_jmp_im(s, val);
        gen_set_label(tcg_ctx, l2);
        gen_eob(s);
    }
}

static void gen_cmovcc1(CPUX86State *env, DisasContext *s, MemOp ot, int b,
                        int modrm, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    CCPrepare cc;

    gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);

    cc = gen_prepare_cc(s, b, s->T1);
    if (cc.mask != -1) {
        TCGv t0 = tcg_temp_new(tcg_ctx);
        tcg_gen_andi_tl(tcg_ctx, t0, cc.reg, cc.mask);
        cc.reg = t0;
    }
    if (!cc.use_reg2) {
        cc.reg2 = tcg_const_tl(tcg_ctx, cc.imm);
    }

    tcg_gen_movcond_tl(tcg_ctx, cc.cond, s->T0, cc.reg, cc.reg2,
                       s->T0, tcg_ctx->cpu_regs[reg]);
    gen_op_mov_reg_v(s, ot, reg, s->T0);

    if (cc.mask != -1) {
        tcg_temp_free(tcg_ctx, cc.reg);
    }
    if (!cc.use_reg2) {
        tcg_temp_free(tcg_ctx, cc.reg2);
    }
}

static inline void gen_op_movl_T0_seg(DisasContext *s, int seg_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                     offsetof(CPUX86State,segs[seg_reg].selector));
}

static inline void gen_op_movl_seg_T0_vm(DisasContext *s, int seg_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_ext16u_tl(tcg_ctx, s->T0, s->T0);
    tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                    offsetof(CPUX86State,segs[seg_reg].selector));
    tcg_gen_shli_tl(tcg_ctx, tcg_ctx->cpu_seg_base[seg_reg], s->T0, 4);
}

/* move T0 to seg_reg and compute if the CPU state may change. Never
   call this function with seg_reg == R_CS */
static void gen_movl_seg_T0(DisasContext *s, int seg_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (s->pe && !s->vm86) {
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        gen_helper_load_seg(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, seg_reg), s->tmp2_i32);
        /* abort translation because the addseg value may change or
           because ss32 may change. For R_SS, translation must always
           stop as a special handling must be done to disable hardware
           interrupts for the next instruction */
        if (seg_reg == R_SS || (s->code32 && seg_reg < R_FS)) {
            s->base.is_jmp = DISAS_TOO_MANY;
        }
    } else {
        gen_op_movl_seg_T0_vm(s, seg_reg);
        if (seg_reg == R_SS) {
            s->base.is_jmp = DISAS_TOO_MANY;
        }
    }
}

static inline int svm_is_rep(int prefixes)
{
    return ((prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) ? 8 : 0);
}

static inline void
gen_svm_check_intercept_param(DisasContext *s, target_ulong pc_start,
                              uint32_t type, uint64_t param)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    /* no SVM activated; fast case */
    if (likely(!(s->flags & HF_GUEST_MASK)))
        return;
    gen_update_cc_op(s);
    gen_jmp_im(s, pc_start - s->cs_base);
    gen_helper_svm_check_intercept_param(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, type),
                                         tcg_const_i64(tcg_ctx, param));
}

static inline void
gen_svm_check_intercept(DisasContext *s, target_ulong pc_start, uint64_t type)
{
    gen_svm_check_intercept_param(s, pc_start, type, 0);
}

static inline void gen_stack_update(DisasContext *s, int addend)
{
    gen_op_add_reg_im(s, mo_stacksize(s), R_ESP, addend);
}

/* Generate a push. It depends on ss32, addseg and dflag.  */
static void gen_push_v(DisasContext *s, TCGv val)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    MemOp d_ot = mo_pushpop(s, s->dflag);
    MemOp a_ot = mo_stacksize(s);
    int size = 1 << d_ot;
    TCGv new_esp = s->A0;

    tcg_gen_subi_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_ESP], size);

    if (!CODE64(s)) {
        if (s->addseg) {
            new_esp = s->tmp4;
            tcg_gen_mov_tl(tcg_ctx, new_esp, s->A0);
        }
        gen_lea_v_seg(s, a_ot, s->A0, R_SS, -1);
    }

    gen_op_st_v(s, d_ot, val, s->A0);
    gen_op_mov_reg_v(s, a_ot, R_ESP, new_esp);
}

/* two step pop is necessary for precise exceptions */
static MemOp gen_pop_T0(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    MemOp d_ot = mo_pushpop(s, s->dflag);

    gen_lea_v_seg(s, mo_stacksize(s), tcg_ctx->cpu_regs[R_ESP], R_SS, -1);
    gen_op_ld_v(s, d_ot, s->T0, s->A0);

    return d_ot;
}

static inline void gen_pop_update(DisasContext *s, MemOp ot)
{
    gen_stack_update(s, 1 << ot);
}

static inline void gen_stack_A0(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_lea_v_seg(s, s->ss32 ? MO_32 : MO_16, tcg_ctx->cpu_regs[R_ESP], R_SS, -1);
}

static void gen_pusha(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    MemOp s_ot = s->ss32 ? MO_32 : MO_16;
    MemOp d_ot = s->dflag;
    int size = 1 << d_ot;
    int i;

    for (i = 0; i < 8; i++) {
        tcg_gen_addi_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_ESP], (i - 8) * size);
        gen_lea_v_seg(s, s_ot, s->A0, R_SS, -1);
        gen_op_st_v(s, d_ot, tcg_ctx->cpu_regs[7 - i], s->A0);
    }

    gen_stack_update(s, -8 * size);
}

static void gen_popa(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    MemOp s_ot = s->ss32 ? MO_32 : MO_16;
    MemOp d_ot = s->dflag;
    int size = 1 << d_ot;
    int i;

    for (i = 0; i < 8; i++) {
        /* ESP is not reloaded */
        if (7 - i == R_ESP) {
            continue;
        }
        tcg_gen_addi_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_ESP], i * size);
        gen_lea_v_seg(s, s_ot, s->A0, R_SS, -1);
        gen_op_ld_v(s, d_ot, s->T0, s->A0);
        gen_op_mov_reg_v(s, d_ot, 7 - i, s->T0);
    }

    gen_stack_update(s, 8 * size);
}

static void gen_enter(DisasContext *s, int esp_addend, int level)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    MemOp d_ot = mo_pushpop(s, s->dflag);
    MemOp a_ot = CODE64(s) ? MO_64 : s->ss32 ? MO_32 : MO_16;
    int size = 1 << d_ot;

    /* Push BP; compute FrameTemp into T1.  */
    tcg_gen_subi_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[R_ESP], size);
    gen_lea_v_seg(s, a_ot, s->T1, R_SS, -1);
    gen_op_st_v(s, d_ot, tcg_ctx->cpu_regs[R_EBP], s->A0);

    level &= 31;
    if (level != 0) {
        int i;

        /* Copy level-1 pointers from the previous frame.  */
        for (i = 1; i < level; ++i) {
            tcg_gen_subi_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_EBP], size * i);
            gen_lea_v_seg(s, a_ot, s->A0, R_SS, -1);
            gen_op_ld_v(s, d_ot, s->tmp0, s->A0);

            tcg_gen_subi_tl(tcg_ctx, s->A0, s->T1, size * i);
            gen_lea_v_seg(s, a_ot, s->A0, R_SS, -1);
            gen_op_st_v(s, d_ot, s->tmp0, s->A0);
        }

        /* Push the current FrameTemp as the last level.  */
        tcg_gen_subi_tl(tcg_ctx, s->A0, s->T1, size * level);
        gen_lea_v_seg(s, a_ot, s->A0, R_SS, -1);
        gen_op_st_v(s, d_ot, s->T1, s->A0);
    }

    /* Copy the FrameTemp value to BP/EBP/RBP at operand size.  A 16-bit
     * ENTER in long mode writes BP only; using the stack-address size here
     * clobbered RBP's high half and disagreed with the host CPU.  */
    gen_op_mov_reg_v(s, d_ot, R_EBP, s->T1);

    /* Compute the final value of ESP.  */
    tcg_gen_subi_tl(tcg_ctx, s->T1, s->T1, esp_addend + size * level);
    gen_op_mov_reg_v(s, a_ot, R_ESP, s->T1);
}

static void gen_leave(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    MemOp d_ot = mo_pushpop(s, s->dflag);
    MemOp a_ot = mo_stacksize(s);

    gen_lea_v_seg(s, a_ot, tcg_ctx->cpu_regs[R_EBP], R_SS, -1);
    gen_op_ld_v(s, d_ot, s->T0, s->A0);

    tcg_gen_addi_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[R_EBP], 1ULL << d_ot);

    gen_op_mov_reg_v(s, d_ot, R_EBP, s->T0);
    gen_op_mov_reg_v(s, a_ot, R_ESP, s->T1);
}

/* Similarly, except that the assumption here is that we don't decode
   the instruction at all -- either a missing opcode, an unimplemented
   feature, or just a bogus instruction stream.  */
static void gen_unknown_opcode(CPUX86State *env, DisasContext *s)
{
    gen_illegal_opcode(s);
}

/* an interrupt is different from an exception because of the
   privilege checks */
static void gen_interrupt(DisasContext *s, int intno,
                          target_ulong cur_eip, target_ulong next_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_update_cc_op(s);
    gen_jmp_im(s, cur_eip);
    gen_helper_raise_interrupt(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, intno),
                               tcg_const_i32(tcg_ctx, next_eip - cur_eip));
    s->base.is_jmp = DISAS_NORETURN;
}

static void gen_debug(DisasContext *s, target_ulong cur_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_update_cc_op(s);
    gen_jmp_im(s, cur_eip);
    gen_helper_debug(tcg_ctx, tcg_ctx->cpu_env);
    s->base.is_jmp = DISAS_NORETURN;
}

static void gen_set_hflag(DisasContext *s, uint32_t mask)
{
    if ((s->flags & mask) == 0) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;

        TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_ld_i32(tcg_ctx, t, tcg_ctx->cpu_env, offsetof(CPUX86State, hflags));
        tcg_gen_ori_i32(tcg_ctx, t, t, mask);
        tcg_gen_st_i32(tcg_ctx, t, tcg_ctx->cpu_env, offsetof(CPUX86State, hflags));
        tcg_temp_free_i32(tcg_ctx, t);
        s->flags |= mask;
    }
}

static void gen_reset_hflag(DisasContext *s, uint32_t mask)
{
    if (s->flags & mask) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;

        TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_ld_i32(tcg_ctx, t, tcg_ctx->cpu_env, offsetof(CPUX86State, hflags));
        tcg_gen_andi_i32(tcg_ctx, t, t, ~mask);
        tcg_gen_st_i32(tcg_ctx, t, tcg_ctx->cpu_env, offsetof(CPUX86State, hflags));
        tcg_temp_free_i32(tcg_ctx, t);
        s->flags &= ~mask;
    }
}

/* Clear BND registers during legacy branches.  */
static void gen_bnd_jmp(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    /* Clear the registers only if BND prefix is missing, MPX is enabled,
       and if the BNDREGs are known to be in use (non-zero) already.
       The helper itself will check BNDPRESERVE at runtime.  */
    if ((s->prefix & PREFIX_REPNZ) == 0
        && (s->flags & HF_MPX_EN_MASK) != 0
        && (s->flags & HF_MPX_IU_MASK) != 0) {
        gen_helper_bnd_jmp(tcg_ctx, tcg_ctx->cpu_env);
    }
}

/* Generate an end of block. Trace exception is also generated if needed.
   If INHIBIT, set HF_INHIBIT_IRQ_MASK if it isn't already set.
   If RECHECK_TF, emit a rechecking helper for #DB, ignoring the state of
   S->TF.  This is used by the syscall/sysret insns.  */
static void
do_gen_eob_worker(DisasContext *s, bool inhibit, bool recheck_tf, bool jr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_update_cc_op(s);

    /* If several instructions disable interrupts, only the first does it.  */
    if (inhibit && !(s->flags & HF_INHIBIT_IRQ_MASK)) {
        gen_set_hflag(s, HF_INHIBIT_IRQ_MASK);
    } else {
        gen_reset_hflag(s, HF_INHIBIT_IRQ_MASK);
    }

    if (s->base.tb->flags & HF_RF_MASK) {
        gen_helper_reset_rf(tcg_ctx, tcg_ctx->cpu_env);
    }
    if (s->base.singlestep_enabled) {
        gen_helper_debug(tcg_ctx, tcg_ctx->cpu_env);
    } else if (recheck_tf) {
        gen_helper_rechecking_single_step(tcg_ctx, tcg_ctx->cpu_env);
        tcg_gen_exit_tb(tcg_ctx, NULL, 0);
    } else if (s->tf) {
        gen_helper_single_step(tcg_ctx, tcg_ctx->cpu_env);
    } else if (jr) {
        tcg_gen_lookup_and_goto_ptr(tcg_ctx);
    } else {
        tcg_gen_exit_tb(tcg_ctx, NULL, 0);
    }
    s->base.is_jmp = DISAS_NORETURN;
}

static inline void
gen_eob_worker(DisasContext *s, bool inhibit, bool recheck_tf)
{
    do_gen_eob_worker(s, inhibit, recheck_tf, false);
}

/* End of block.
   If INHIBIT, set HF_INHIBIT_IRQ_MASK if it isn't already set.  */
static void gen_eob_inhibit_irq(DisasContext *s, bool inhibit)
{
    gen_eob_worker(s, inhibit, false);
}

/* End of block, resetting the inhibit irq flag.  */
static void gen_eob(DisasContext *s)
{
    gen_eob_worker(s, false, false);
}

/* Jump to register */
static void gen_jr(DisasContext *s, TCGv dest)
{
    do_gen_eob_worker(s, false, false, true);
}

/* generate a jump to eip. No segment change must happen before as a
   direct call to the next block may occur */
static void gen_jmp_tb(DisasContext *s, target_ulong eip, int tb_num)
{
    gen_update_cc_op(s);
    set_cc_op(s, CC_OP_DYNAMIC);
    if (s->jmp_opt) {
        gen_goto_tb(s, tb_num, eip);
    } else {
        gen_jmp_im(s, eip);
        gen_eob(s);
    }
}

static void gen_jmp(DisasContext *s, target_ulong eip)
{
    gen_jmp_tb(s, eip, 0);
}

static inline void gen_ldq_env_A0(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0, s->mem_index, MO_LEQ);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset);
}

static inline void gen_stq_env_A0(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset);
    tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0, s->mem_index, MO_LEQ);
}

static inline void gen_ldo_env_A0(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mem_index = s->mem_index;

    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0, mem_index, MO_LEQ);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_addi_tl(tcg_ctx, s->tmp0, s->A0, 8);
    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->tmp0, mem_index, MO_LEQ);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(ZMMReg, ZMM_Q(1)));
}

static inline void gen_ldo_env_A0_aligned(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mem_index = s->mem_index;

    /* The first access performs the architectural 16-byte alignment check. */
    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0, mem_index,
                        MO_LEQ | MO_ALIGN_16);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                   offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_addi_tl(tcg_ctx, s->tmp0, s->A0, 8);
    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->tmp0, mem_index, MO_LEQ);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                   offset + offsetof(ZMMReg, ZMM_Q(1)));
}

static inline void gen_ldo_env_A0_legacy_sse(DisasContext *s, int offset)
{
    /* Legacy SSE full-width m128 operands require 16-byte alignment.  Their
     * VEX.128 equivalents generally permit unaligned memory operands unless
     * the individual instruction explicitly requires alignment. */
    if (s->prefix & PREFIX_VEX) {
        gen_ldo_env_A0(s, offset);
    } else {
        gen_ldo_env_A0_aligned(s, offset);
    }
}

static inline void gen_sto_env_A0(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mem_index = s->mem_index;

    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0, mem_index, MO_LEQ);
    tcg_gen_addi_tl(tcg_ctx, s->tmp0, s->A0, 8);
    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(ZMMReg, ZMM_Q(1)));
    tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->tmp0, mem_index, MO_LEQ);
}

static inline void gen_sto_env_A0_aligned(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mem_index = s->mem_index;

    /* Check alignment before the first architecturally visible store. */
    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                   offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0, mem_index,
                        MO_LEQ | MO_ALIGN_16);
    tcg_gen_addi_tl(tcg_ctx, s->tmp0, s->A0, 8);
    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                   offset + offsetof(ZMMReg, ZMM_Q(1)));
    tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->tmp0, mem_index, MO_LEQ);
}

static inline void gen_op_movo(DisasContext *s, int d_offset, int s_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, s_offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, d_offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, s_offset + offsetof(ZMMReg, ZMM_Q(1)));
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, d_offset + offsetof(ZMMReg, ZMM_Q(1)));
}

static inline void gen_op_movq(DisasContext *s, int d_offset, int s_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, s_offset);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, d_offset);
}

static inline void gen_mmx_set_x87_exp(DisasContext *s, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, UINT16_MAX);
    tcg_gen_st16_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                     offsetof(CPUX86State, fpregs[reg].d.high));
}

/*
 * 256-bit (YMM) helpers.  A YMM register lives in xmm_regs[N] (a 512-bit
 * ZMMReg): the low 128 bits are ZMM_Q(0)/ZMM_Q(1) and the high 128 bits
 * ZMM_Q(2)/ZMM_Q(3), so the high lane begins YMM_HI_LANE_OFF bytes into the
 * register.  These mirror gen_ldo/sto/movo for the full 256-bit width.
 */
#define YMM_HI_LANE_OFF 16

static inline void gen_ldy_env_A0(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mem_index = s->mem_index;

    gen_ldo_env_A0(s, offset);
    tcg_gen_addi_tl(tcg_ctx, s->tmp0, s->A0, 16);
    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->tmp0, mem_index, MO_LEQ);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(ZMMReg, ZMM_Q(2)));
    tcg_gen_addi_tl(tcg_ctx, s->tmp0, s->A0, 24);
    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->tmp0, mem_index, MO_LEQ);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(ZMMReg, ZMM_Q(3)));
}

static inline void gen_ldy_env_A0_aligned(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mem_index = s->mem_index;

    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0, mem_index,
                        MO_LEQ | MO_ALIGN_32);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                   offset + offsetof(ZMMReg, ZMM_Q(0)));
    for (int q = 1; q < 4; ++q) {
        tcg_gen_addi_tl(tcg_ctx, s->tmp0, s->A0, q * 8);
        tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->tmp0, mem_index,
                            MO_LEQ);
        tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                       offset + offsetof(ZMMReg, ZMM_Q(q)));
    }
}

static inline void gen_sty_env_A0(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mem_index = s->mem_index;

    gen_sto_env_A0(s, offset);
    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(ZMMReg, ZMM_Q(2)));
    tcg_gen_addi_tl(tcg_ctx, s->tmp0, s->A0, 16);
    tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->tmp0, mem_index, MO_LEQ);
    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(ZMMReg, ZMM_Q(3)));
    tcg_gen_addi_tl(tcg_ctx, s->tmp0, s->A0, 24);
    tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->tmp0, mem_index, MO_LEQ);
}

static inline void gen_sty_env_A0_aligned(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mem_index = s->mem_index;

    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                   offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0, mem_index,
                        MO_LEQ | MO_ALIGN_32);
    for (int q = 1; q < 4; ++q) {
        tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                       offset + offsetof(ZMMReg, ZMM_Q(q)));
        tcg_gen_addi_tl(tcg_ctx, s->tmp0, s->A0, q * 8);
        tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->tmp0, mem_index,
                            MO_LEQ);
    }
}

static inline void gen_op_movy(DisasContext *s, int d_offset, int s_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_op_movo(s, d_offset, s_offset);
    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, s_offset + offsetof(ZMMReg, ZMM_Q(2)));
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, d_offset + offsetof(ZMMReg, ZMM_Q(2)));
    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, s_offset + offsetof(ZMMReg, ZMM_Q(3)));
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, d_offset + offsetof(ZMMReg, ZMM_Q(3)));
}

/* Zero bits [255:128] of a YMM register (the AVX rule for any 128-bit write). */
static inline void gen_clear_ymmh(DisasContext *s, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int off = offsetof(CPUX86State, xmm_regs[reg]);

    tcg_gen_movi_i64(tcg_ctx, s->tmp1_i64, 0);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, off + offsetof(ZMMReg, ZMM_Q(2)));
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, off + offsetof(ZMMReg, ZMM_Q(3)));
}

static inline void gen_clear_ymm(DisasContext *s, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int off = offsetof(CPUX86State, xmm_regs[reg]);
    int q;

    tcg_gen_movi_i64(tcg_ctx, s->tmp1_i64, 0);
    for (q = 0; q < 4; q++) {
        tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                       off + offsetof(ZMMReg, ZMM_Q(q)));
    }
}

static inline void gen_op_movl(DisasContext *s, int d_offset, int s_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, s_offset);
    tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, d_offset);
}

static inline void gen_op_movq_env_0(DisasContext *s, int d_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_movi_i64(tcg_ctx, s->tmp1_i64, 0);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, d_offset);
}

typedef void (*SSEFunc_i_ep)(TCGContext *s, TCGv_i32 val, TCGv_ptr env, TCGv_ptr reg);
typedef void (*SSEFunc_l_ep)(TCGContext *s, TCGv_i64 val, TCGv_ptr env, TCGv_ptr reg);
typedef void (*SSEFunc_0_epi)(TCGContext *s, TCGv_ptr env, TCGv_ptr reg, TCGv_i32 val);
typedef void (*SSEFunc_0_epl)(TCGContext *s, TCGv_ptr env, TCGv_ptr reg, TCGv_i64 val);
typedef void (*SSEFunc_0_epp)(TCGContext *s, TCGv_ptr env, TCGv_ptr reg_a, TCGv_ptr reg_b);
typedef void (*SSEFunc_0_eppi)(TCGContext *s, TCGv_ptr env, TCGv_ptr reg_a, TCGv_ptr reg_b,
                               TCGv_i32 val);
typedef void (*SSEFunc_0_ppi)(TCGContext *s, TCGv_ptr reg_a, TCGv_ptr reg_b, TCGv_i32 val);
typedef void (*SSEFunc_0_eppt)(TCGContext *s, TCGv_ptr env, TCGv_ptr reg_a, TCGv_ptr reg_b,
                               TCGv val);

#define SSE_SPECIAL ((void *)1)
#define SSE_DUMMY ((void *)2)

#define MMX_OP2(x) { gen_helper_ ## x ## _mmx, gen_helper_ ## x ## _xmm }
#define SSE_FOP(x) { gen_helper_ ## x ## ps, gen_helper_ ## x ## pd, \
                     gen_helper_ ## x ## ss, gen_helper_ ## x ## sd, }

static const SSEFunc_0_epp sse_op_table1[256][4] = {
    /* 3DNow! extensions */
    [0x0e] = { SSE_DUMMY }, /* femms */
    [0x0f] = { SSE_DUMMY }, /* pf... */
    /* pure SSE operations */
    [0x10] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movups, movupd, movss, movsd */
    [0x11] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movups, movupd, movss, movsd */
    [0x12] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movlps, movlpd, movsldup, movddup */
    [0x13] = { SSE_SPECIAL, SSE_SPECIAL },  /* movlps, movlpd */
    [0x14] = { gen_helper_punpckldq_xmm, gen_helper_punpcklqdq_xmm },
    [0x15] = { gen_helper_punpckhdq_xmm, gen_helper_punpckhqdq_xmm },
    [0x16] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },  /* movhps, movhpd, movshdup */
    [0x17] = { SSE_SPECIAL, SSE_SPECIAL },  /* movhps, movhpd */

    [0x28] = { SSE_SPECIAL, SSE_SPECIAL },  /* movaps, movapd */
    [0x29] = { SSE_SPECIAL, SSE_SPECIAL },  /* movaps, movapd */
    [0x2a] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* cvtpi2ps, cvtpi2pd, cvtsi2ss, cvtsi2sd */
    [0x2b] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movntps, movntpd, movntss, movntsd */
    [0x2c] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* cvttps2pi, cvttpd2pi, cvttsd2si, cvttss2si */
    [0x2d] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* cvtps2pi, cvtpd2pi, cvtsd2si, cvtss2si */
    [0x2e] = { gen_helper_ucomiss, gen_helper_ucomisd },
    [0x2f] = { gen_helper_comiss, gen_helper_comisd },
    [0x50] = { SSE_SPECIAL, SSE_SPECIAL }, /* movmskps, movmskpd */
    [0x51] = SSE_FOP(sqrt),
    [0x52] = { gen_helper_rsqrtps, NULL, gen_helper_rsqrtss, NULL },
    [0x53] = { gen_helper_rcpps, NULL, gen_helper_rcpss, NULL },
    [0x54] = { gen_helper_pand_xmm, gen_helper_pand_xmm }, /* andps, andpd */
    [0x55] = { gen_helper_pandn_xmm, gen_helper_pandn_xmm }, /* andnps, andnpd */
    [0x56] = { gen_helper_por_xmm, gen_helper_por_xmm }, /* orps, orpd */
    [0x57] = { gen_helper_pxor_xmm, gen_helper_pxor_xmm }, /* xorps, xorpd */
    [0x58] = SSE_FOP(add),
    [0x59] = SSE_FOP(mul),
    [0x5a] = { gen_helper_cvtps2pd, gen_helper_cvtpd2ps,
               gen_helper_cvtss2sd, gen_helper_cvtsd2ss },
    [0x5b] = { gen_helper_cvtdq2ps, gen_helper_cvtps2dq, gen_helper_cvttps2dq },
    [0x5c] = SSE_FOP(sub),
    [0x5d] = SSE_FOP(min),
    [0x5e] = SSE_FOP(div),
    [0x5f] = SSE_FOP(max),

    [0xc2] = SSE_FOP(cmpeq),
    [0xc6] = { (SSEFunc_0_epp)gen_helper_shufps,
               (SSEFunc_0_epp)gen_helper_shufpd }, /* XXX: casts */

    /* SSSE3, SSE4, MOVBE, CRC32, BMI1, BMI2, ADX.  */
    [0x38] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },
    [0x3a] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },

    /* MMX ops and their SSE extensions */
    [0x60] = MMX_OP2(punpcklbw),
    [0x61] = MMX_OP2(punpcklwd),
    [0x62] = MMX_OP2(punpckldq),
    [0x63] = MMX_OP2(packsswb),
    [0x64] = MMX_OP2(pcmpgtb),
    [0x65] = MMX_OP2(pcmpgtw),
    [0x66] = MMX_OP2(pcmpgtl),
    [0x67] = MMX_OP2(packuswb),
    [0x68] = MMX_OP2(punpckhbw),
    [0x69] = MMX_OP2(punpckhwd),
    [0x6a] = MMX_OP2(punpckhdq),
    [0x6b] = MMX_OP2(packssdw),
    [0x6c] = { NULL, gen_helper_punpcklqdq_xmm },
    [0x6d] = { NULL, gen_helper_punpckhqdq_xmm },
    [0x6e] = { SSE_SPECIAL, SSE_SPECIAL }, /* movd mm, ea */
    [0x6f] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movq, movdqa, , movqdu */
    [0x70] = { (SSEFunc_0_epp)gen_helper_pshufw_mmx,
               (SSEFunc_0_epp)gen_helper_pshufd_xmm,
               (SSEFunc_0_epp)gen_helper_pshufhw_xmm,
               (SSEFunc_0_epp)gen_helper_pshuflw_xmm }, /* XXX: casts */
    [0x71] = { SSE_SPECIAL, SSE_SPECIAL }, /* shiftw */
    [0x72] = { SSE_SPECIAL, SSE_SPECIAL }, /* shiftd */
    [0x73] = { SSE_SPECIAL, SSE_SPECIAL }, /* shiftq */
    [0x74] = MMX_OP2(pcmpeqb),
    [0x75] = MMX_OP2(pcmpeqw),
    [0x76] = MMX_OP2(pcmpeql),
    [0x77] = { SSE_DUMMY }, /* emms */
    [0x78] = { NULL, SSE_SPECIAL, NULL, SSE_SPECIAL }, /* extrq_i, insertq_i */
    [0x79] = { NULL, gen_helper_extrq_r, NULL, gen_helper_insertq_r },
    [0x7c] = { NULL, gen_helper_haddpd, NULL, gen_helper_haddps },
    [0x7d] = { NULL, gen_helper_hsubpd, NULL, gen_helper_hsubps },
    [0x7e] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movd, movd, , movq */
    [0x7f] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movq, movdqa, movdqu */
    [0xc4] = { SSE_SPECIAL, SSE_SPECIAL }, /* pinsrw */
    [0xc5] = { SSE_SPECIAL, SSE_SPECIAL }, /* pextrw */
    [0xd0] = { NULL, gen_helper_addsubpd, NULL, gen_helper_addsubps },
    [0xd1] = MMX_OP2(psrlw),
    [0xd2] = MMX_OP2(psrld),
    [0xd3] = MMX_OP2(psrlq),
    [0xd4] = MMX_OP2(paddq),
    [0xd5] = MMX_OP2(pmullw),
    [0xd6] = { NULL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },
    [0xd7] = { SSE_SPECIAL, SSE_SPECIAL }, /* pmovmskb */
    [0xd8] = MMX_OP2(psubusb),
    [0xd9] = MMX_OP2(psubusw),
    [0xda] = MMX_OP2(pminub),
    [0xdb] = MMX_OP2(pand),
    [0xdc] = MMX_OP2(paddusb),
    [0xdd] = MMX_OP2(paddusw),
    [0xde] = MMX_OP2(pmaxub),
    [0xdf] = MMX_OP2(pandn),
    [0xe0] = MMX_OP2(pavgb),
    [0xe1] = MMX_OP2(psraw),
    [0xe2] = MMX_OP2(psrad),
    [0xe3] = MMX_OP2(pavgw),
    [0xe4] = MMX_OP2(pmulhuw),
    [0xe5] = MMX_OP2(pmulhw),
    [0xe6] = { NULL, gen_helper_cvttpd2dq, gen_helper_cvtdq2pd, gen_helper_cvtpd2dq },
    [0xe7] = { SSE_SPECIAL , SSE_SPECIAL },  /* movntq, movntq */
    [0xe8] = MMX_OP2(psubsb),
    [0xe9] = MMX_OP2(psubsw),
    [0xea] = MMX_OP2(pminsw),
    [0xeb] = MMX_OP2(por),
    [0xec] = MMX_OP2(paddsb),
    [0xed] = MMX_OP2(paddsw),
    [0xee] = MMX_OP2(pmaxsw),
    [0xef] = MMX_OP2(pxor),
    [0xf0] = { NULL, NULL, NULL, SSE_SPECIAL }, /* lddqu */
    [0xf1] = MMX_OP2(psllw),
    [0xf2] = MMX_OP2(pslld),
    [0xf3] = MMX_OP2(psllq),
    [0xf4] = MMX_OP2(pmuludq),
    [0xf5] = MMX_OP2(pmaddwd),
    [0xf6] = MMX_OP2(psadbw),
    [0xf7] = { (SSEFunc_0_epp)gen_helper_maskmov_mmx,
               (SSEFunc_0_epp)gen_helper_maskmov_xmm }, /* XXX: casts */
    [0xf8] = MMX_OP2(psubb),
    [0xf9] = MMX_OP2(psubw),
    [0xfa] = MMX_OP2(psubl),
    [0xfb] = MMX_OP2(psubq),
    [0xfc] = MMX_OP2(paddb),
    [0xfd] = MMX_OP2(paddw),
    [0xfe] = MMX_OP2(paddl),
};

static const SSEFunc_0_epp sse_op_table2[3 * 8][2] = {
    [0 + 2] = MMX_OP2(psrlw),
    [0 + 4] = MMX_OP2(psraw),
    [0 + 6] = MMX_OP2(psllw),
    [8 + 2] = MMX_OP2(psrld),
    [8 + 4] = MMX_OP2(psrad),
    [8 + 6] = MMX_OP2(pslld),
    [16 + 2] = MMX_OP2(psrlq),
    [16 + 3] = { NULL, gen_helper_psrldq_xmm },
    [16 + 6] = MMX_OP2(psllq),
    [16 + 7] = { NULL, gen_helper_pslldq_xmm },
};

static const SSEFunc_0_epi sse_op_table3ai[] = {
    gen_helper_cvtsi2ss,
    gen_helper_cvtsi2sd
};

#ifdef TARGET_X86_64
static const SSEFunc_0_epl sse_op_table3aq[] = {
    gen_helper_cvtsq2ss,
    gen_helper_cvtsq2sd
};
#endif

static const SSEFunc_i_ep sse_op_table3bi[] = {
    gen_helper_cvttss2si,
    gen_helper_cvtss2si,
    gen_helper_cvttsd2si,
    gen_helper_cvtsd2si
};

#ifdef TARGET_X86_64
static const SSEFunc_l_ep sse_op_table3bq[] = {
    gen_helper_cvttss2sq,
    gen_helper_cvtss2sq,
    gen_helper_cvttsd2sq,
    gen_helper_cvtsd2sq
};
#endif

static const SSEFunc_0_epp sse_op_table4[8][4] = {
    SSE_FOP(cmpeq),
    SSE_FOP(cmplt),
    SSE_FOP(cmple),
    SSE_FOP(cmpunord),
    SSE_FOP(cmpneq),
    SSE_FOP(cmpnlt),
    SSE_FOP(cmpnle),
    SSE_FOP(cmpord),
};

static const SSEFunc_0_epp sse_op_table5[256] = {
    [0x0c] = gen_helper_pi2fw,
    [0x0d] = gen_helper_pi2fd,
    [0x1c] = gen_helper_pf2iw,
    [0x1d] = gen_helper_pf2id,
    [0x8a] = gen_helper_pfnacc,
    [0x8e] = gen_helper_pfpnacc,
    [0x90] = gen_helper_pfcmpge,
    [0x94] = gen_helper_pfmin,
    [0x96] = gen_helper_pfrcp,
    [0x97] = gen_helper_pfrsqrt,
    [0x9a] = gen_helper_pfsub,
    [0x9e] = gen_helper_pfadd,
    [0xa0] = gen_helper_pfcmpgt,
    [0xa4] = gen_helper_pfmax,
    [0xa6] = gen_helper_movq, /* pfrcpit1; no need to actually increase precision */
    [0xa7] = gen_helper_movq, /* pfrsqit1 */
    [0xaa] = gen_helper_pfsubr,
    [0xae] = gen_helper_pfacc,
    [0xb0] = gen_helper_pfcmpeq,
    [0xb4] = gen_helper_pfmul,
    [0xb6] = gen_helper_movq, /* pfrcpit2 */
    [0xb7] = gen_helper_pmulhrw_mmx,
    [0xbb] = gen_helper_pswapd,
    [0xbf] = gen_helper_pavgb_mmx /* pavgusb */
};

struct SSEOpHelper_epp {
    SSEFunc_0_epp op[2];
    uint32_t ext_mask;
};

struct SSEOpHelper_eppi {
    SSEFunc_0_eppi op[2];
    uint32_t ext_mask;
};

#define SSSE3_OP(x) { MMX_OP2(x), CPUID_EXT_SSSE3 }
#define SSE41_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, CPUID_EXT_SSE41 }
#define SSE42_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, CPUID_EXT_SSE42 }
#define SSE41_SPECIAL { { NULL, SSE_SPECIAL }, CPUID_EXT_SSE41 }
#define PCLMULQDQ_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, \
        CPUID_EXT_PCLMULQDQ }
#define AESNI_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, CPUID_EXT_AES }

static const struct SSEOpHelper_epp sse_op_table6[256] = {
    [0x00] = SSSE3_OP(pshufb),
    [0x01] = SSSE3_OP(phaddw),
    [0x02] = SSSE3_OP(phaddd),
    [0x03] = SSSE3_OP(phaddsw),
    [0x04] = SSSE3_OP(pmaddubsw),
    [0x05] = SSSE3_OP(phsubw),
    [0x06] = SSSE3_OP(phsubd),
    [0x07] = SSSE3_OP(phsubsw),
    [0x08] = SSSE3_OP(psignb),
    [0x09] = SSSE3_OP(psignw),
    [0x0a] = SSSE3_OP(psignd),
    [0x0b] = SSSE3_OP(pmulhrsw),
    [0x10] = SSE41_OP(pblendvb),
    [0x13] = { { NULL, gen_helper_cvtph2ps }, CPUID_EXT_F16C }, /* vcvtph2ps */
    [0x14] = SSE41_OP(blendvps),
    [0x15] = SSE41_OP(blendvpd),
    [0x17] = SSE41_OP(ptest),
    [0x1c] = SSSE3_OP(pabsb),
    [0x1d] = SSSE3_OP(pabsw),
    [0x1e] = SSSE3_OP(pabsd),
    [0x20] = SSE41_OP(pmovsxbw),
    [0x21] = SSE41_OP(pmovsxbd),
    [0x22] = SSE41_OP(pmovsxbq),
    [0x23] = SSE41_OP(pmovsxwd),
    [0x24] = SSE41_OP(pmovsxwq),
    [0x25] = SSE41_OP(pmovsxdq),
    [0x28] = SSE41_OP(pmuldq),
    [0x29] = SSE41_OP(pcmpeqq),
    [0x2a] = SSE41_SPECIAL, /* movntqda */
    [0x2b] = SSE41_OP(packusdw),
    [0x30] = SSE41_OP(pmovzxbw),
    [0x31] = SSE41_OP(pmovzxbd),
    [0x32] = SSE41_OP(pmovzxbq),
    [0x33] = SSE41_OP(pmovzxwd),
    [0x34] = SSE41_OP(pmovzxwq),
    [0x35] = SSE41_OP(pmovzxdq),
    [0x37] = SSE42_OP(pcmpgtq),
    [0x38] = SSE41_OP(pminsb),
    [0x39] = SSE41_OP(pminsd),
    [0x3a] = SSE41_OP(pminuw),
    [0x3b] = SSE41_OP(pminud),
    [0x3c] = SSE41_OP(pmaxsb),
    [0x3d] = SSE41_OP(pmaxsd),
    [0x3e] = SSE41_OP(pmaxuw),
    [0x3f] = SSE41_OP(pmaxud),
    [0x40] = SSE41_OP(pmulld),
    [0x41] = SSE41_OP(phminposuw),
    [0xdb] = AESNI_OP(aesimc),
    [0xdc] = AESNI_OP(aesenc),
    [0xdd] = AESNI_OP(aesenclast),
    [0xde] = AESNI_OP(aesdec),
    [0xdf] = AESNI_OP(aesdeclast),
};

static const struct SSEOpHelper_eppi sse_op_table7[256] = {
    [0x08] = SSE41_OP(roundps),
    [0x09] = SSE41_OP(roundpd),
    [0x0a] = SSE41_OP(roundss),
    [0x0b] = SSE41_OP(roundsd),
    [0x0c] = SSE41_OP(blendps),
    [0x0d] = SSE41_OP(blendpd),
    [0x0e] = SSE41_OP(pblendw),
    [0x0f] = SSSE3_OP(palignr),
    [0x14] = SSE41_SPECIAL, /* pextrb */
    [0x15] = SSE41_SPECIAL, /* pextrw */
    [0x16] = SSE41_SPECIAL, /* pextrd/pextrq */
    [0x17] = SSE41_SPECIAL, /* extractps */
    [0x1d] = { { NULL, SSE_SPECIAL }, CPUID_EXT_F16C }, /* vcvtps2ph */
    [0x20] = SSE41_SPECIAL, /* pinsrb */
    [0x21] = SSE41_SPECIAL, /* insertps */
    [0x22] = SSE41_SPECIAL, /* pinsrd/pinsrq */
    [0x40] = SSE41_OP(dpps),
    [0x41] = SSE41_OP(dppd),
    [0x42] = SSE41_OP(mpsadbw),
    [0x44] = PCLMULQDQ_OP(pclmulqdq),
    [0x60] = SSE42_OP(pcmpestrm),
    [0x61] = SSE42_OP(pcmpestri),
    [0x62] = SSE42_OP(pcmpistrm),
    [0x63] = SSE42_OP(pcmpistri),
    [0xdf] = AESNI_OP(aeskeygenassist),
};

/*
 * VEX-encoded SSE arithmetic is non-destructive: dst = src1 OP src2, with
 * src1 = xmm[VEX.vvvv].  The legacy MMX/SSE decoder treats the destination as
 * the first source (dst = dst OP src2).  For VEX 3-operand forms, preload src1
 * into the dst slot so the in-place helper computes dst = src1 OP src2; route a
 * register src2 through xmm_t0 first so an aliased src2 (rm == reg) survives the
 * preload.  Scalar forms get the correct upper-lane carry-over from src1 for
 * free, since the whole 128-bit src1 is copied into dst.
 */
static void gen_sse_vex_merge_src1(DisasContext *s, int reg, int *op2_offset)
{
    int dst_offset = offsetof(CPUX86State, xmm_regs[reg]);
    int t0_offset = offsetof(CPUX86State, xmm_t0);

    if (*op2_offset != t0_offset) {
        gen_op_movo(s, t0_offset, *op2_offset);
        *op2_offset = t0_offset;
    }
    gen_op_movo(s, dst_offset, offsetof(CPUX86State, xmm_regs[s->vex_v]));
}

/* One-byte SSE opcodes (sse_op_table1) whose VEX form takes vvvv as src1.
 * comiss/ucomiss (2e/2f) read dst as a pure source and pshufd (70) is
 * 2-operand, so both are excluded; scalar forms (sqrt/cvt) carry src1 into the
 * upper lanes via the full preload. */
static bool sse_vex_3op_table1(int b)
{
    switch (b) {
    case 0x14: case 0x15:
    case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
    case 0x58: case 0x59: case 0x5a:
    case 0x5c: case 0x5d: case 0x5e: case 0x5f:
    case 0xc2: case 0xc6:
    case 0x60: case 0x61: case 0x62: case 0x63:
    case 0x64: case 0x65: case 0x66: case 0x67:
    case 0x68: case 0x69: case 0x6a: case 0x6b:
    case 0x6c: case 0x6d:
    case 0x74: case 0x75: case 0x76:
    case 0x7c: case 0x7d:
    case 0xd0:
    case 0xd1: case 0xd2: case 0xd3: case 0xd4: case 0xd5:
    case 0xd8: case 0xd9: case 0xda: case 0xdb:
    case 0xdc: case 0xdd: case 0xde: case 0xdf:
    case 0xe0: case 0xe1: case 0xe2: case 0xe3: case 0xe4: case 0xe5:
    case 0xe8: case 0xe9: case 0xea: case 0xeb:
    case 0xec: case 0xed: case 0xee: case 0xef:
    case 0xf1: case 0xf2: case 0xf3: case 0xf4: case 0xf5: case 0xf6:
    case 0xf8: case 0xf9: case 0xfa: case 0xfb:
    case 0xfc: case 0xfd: case 0xfe:
        return true;
    default:
        return false;
    }
}

/* 0f38 opcodes (sse_op_table6) whose VEX form takes vvvv as src1.  Unary ops
 * (pabs/pmovsx/zx/phminposuw/aesimc) ignore the dst input, ptest (17) reads it
 * as a source, and blendv (10/14/15) is a 4-operand VEX form decoded
 * elsewhere, so none of those merge. */
static bool sse_vex_3op_table6(int b)
{
    switch (b) {
    case 0x00:
    case 0x01: case 0x02: case 0x03: case 0x04:
    case 0x05: case 0x06: case 0x07:
    case 0x08: case 0x09: case 0x0a: case 0x0b:
    case 0x28: case 0x29: case 0x2b:
    case 0x37:
    case 0x38: case 0x39: case 0x3a: case 0x3b:
    case 0x3c: case 0x3d: case 0x3e: case 0x3f:
    case 0x40:
    case 0xdc: case 0xdd: case 0xde: case 0xdf:
        return true;
    default:
        return false;
    }
}

/* 0f3a opcodes (sse_op_table7) whose VEX form takes vvvv as src1.  roundps/pd
 * (08/09) are 2-operand and pcmp*str (60-63) read dst as a source; roundss/sd
 * (0a/0b) are scalar and carry src1 into the upper lanes. */
static bool sse_vex_3op_table7(int b)
{
    switch (b) {
    case 0x0a: case 0x0b:
    case 0x0c: case 0x0d: case 0x0e: case 0x0f:
    case 0x40: case 0x41: case 0x42: case 0x44:
        return true;
    default:
        return false;
    }
}

/* Run a 128-bit packed helper on both 128-bit lanes of a YMM operand. */
static void gen_sse_epp_ymm(DisasContext *s, SSEFunc_0_epp fn,
                            int op1_offset, int op2_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int lane;

    for (lane = 0; lane < 2; lane++) {
        int off = lane * YMM_HI_LANE_OFF;
        tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset + off);
        tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset + off);
        fn(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
    }
}

/* 256-bit analogue of gen_sse_vex_merge_src1: preload the full 256-bit src1
 * (VEX.vvvv) into the destination so the in-place helper computes
 * dst = src1 OP src2, routing a register src2 through xmm_t0 first so an
 * aliased src2 survives the preload. */
static void gen_sse_vex_merge_src1_ymm(DisasContext *s, int reg, int *op2_offset)
{
    int dst_offset = offsetof(CPUX86State, xmm_regs[reg]);
    int t0_offset = offsetof(CPUX86State, xmm_t0);

    if (*op2_offset != t0_offset) {
        gen_op_movy(s, t0_offset, *op2_offset);
        *op2_offset = t0_offset;
    }
    gen_op_movy(s, dst_offset, offsetof(CPUX86State, xmm_regs[s->vex_v]));
}

static bool x86_avx_enabled(const DisasContext *s)
{
    return (s->cpuid_ext_features & CPUID_EXT_AVX) &&
           (s->flags & HF_AVX_EN_MASK);
}

static bool x86_avx2_enabled(const DisasContext *s)
{
    return x86_avx_enabled(s) &&
           (s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_AVX2);
}

static bool x86_avx512_enabled(const DisasContext *s)
{
    return (s->flags & HF_AVX512_EN_MASK) != 0;
}

static bool x86_evex_require_features(DisasContext *s, uint32_t ebx,
                                      uint32_t ecx, uint32_t edx)
{
    if ((s->cpuid_7_0_ebx_features & ebx) != ebx ||
        (s->cpuid_7_0_ecx_features & ecx) != ecx ||
        (s->cpuid_7_0_edx_features & edx) != edx) {
        gen_illegal_opcode(s);
        return false;
    }
    return true;
}

/* These one-byte 0f opcodes acquire a 256-bit integer form only with AVX2.
 * Keep this separate from the global VEX gate: VEX-encoded scalar GPR
 * instructions (BMI/PDEP/RORX) do not require the AVX register state. */
static bool x86_avx2_0f_ymm_opcode(int b)
{
    return (b >= 0x60 && b <= 0x6d) ||
           (b >= 0x74 && b <= 0x76) ||
           (b >= 0xd1 && b <= 0xd5) ||
           (b >= 0xd8 && b <= 0xe5) ||
           (b >= 0xe8 && b <= 0xef) ||
           (b >= 0xf1 && b <= 0xf6) ||
           (b >= 0xf8 && b <= 0xfe);
}

/* Generic 0f38 YMM helpers below are all AVX2 integer instructions.  Other
 * 0f38 YMM families (AVX floating point, F16C, FMA, gather, broadcasts and
 * variable shifts) are decoded explicitly before the generic fallback. */
static bool x86_avx2_0f38_ymm_opcode(int b)
{
    return (b <= 0x0b) ||
           (b >= 0x1c && b <= 0x1e) ||
           b == 0x28 || b == 0x29 || b == 0x2a || b == 0x2b || b == 0x37 ||
           (b >= 0x38 && b <= 0x40);
}

/*
 * AVX2 VSIB gather (VPGATHER{DD,DQ,QD,QQ} 0f38 90/91, VGATHER{DPS,DPD,QPS,QPD}
 * 0f38 92/93).  Handles both VEX.128 and VEX.256.  The memory operand uses a
 * vector index register (SIB.index), VEX.vvvv is the element mask, and the
 * destination register doubles as the merge source for masked-off lanes.  QEMU
 * 5.0.1 has no gather decode at all, so this implements it from scratch:
 * decode the VSIB byte, then for each element form base + sext(index)*scale +
 * disp, conditionally load (mask sign bit), and clear the mask on completion.
 * `modrm` is already read; the SIB byte follows.  Returns false (→ #UD) on an
 * unexpected operand shape.
 *
 * A masked-off lane must not access memory.  Each completed active lane clears
 * its mask element immediately so a later fault leaves restartable partial
 * progress in the architectural destination and mask registers.
 */
static bool gen_vsib_gather(CPUX86State *env, DisasContext *s, int b, int modrm,
                            int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mod = (modrm >> 6) & 3;
    int rm = modrm & 7;

    if (!x86_avx2_enabled(s))
        return false;

    /* Gather requires a VSIB memory operand (SIB present, register form is an
     * invalid encoding) and a 32/64-bit address size. */
    if (mod == 3 || rm != 4 || s->aflag == MO_16)
        return false;

    int idx_sz = (b == 0x90 || b == 0x92) ? 4 : 8;
    int val_sz = s->vex_w ? 8 : 4;
    int vl = s->vex_l ? 32 : 16;
    int n = vl / (idx_sz > val_sz ? idx_sz : val_sz);

    int sib = x86_ldub_code(env, s);
    int scale_sh = (sib >> 6) & 3;
    int vindex = ((sib >> 3) & 7) | REX_X(s);
    int base_reg = (sib & 7) | REX_B(s);
    if (reg == s->vex_v || reg == vindex || s->vex_v == vindex)
        return false;
    target_long disp = 0;
    bool have_base = true;
    int def_seg = R_DS;
    if (mod == 0) {
        if ((base_reg & 7) == 5) { /* no base: disp32 only (VSIB has no RIP) */
            have_base = false;
            disp = (int32_t)x86_ldl_code(env, s);
        }
    } else if (mod == 1) {
        disp = (int8_t)x86_ldub_code(env, s);
    } else {
        disp = (int32_t)x86_ldl_code(env, s);
    }
    if (have_base && (base_reg == R_EBP || base_reg == R_ESP))
        def_seg = R_SS;

    int dst_off = offsetof(CPUX86State, xmm_regs[reg]);
    int idx_off = offsetof(CPUX86State, xmm_regs[vindex]);
    int mask_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);

    /* Architecturally, the complete mask is canonicalized before the first
     * memory access.  This matters when a later lane faults: unfinished active
     * lanes remain all-ones, rather than retaining their input bit pattern.
     * Parts with no corresponding gather element are zero from the outset. */
    tcg_gen_movi_i64(tcg_ctx, s->tmp1_i64, 0);
    for (int q = (n * val_sz) / 8; q < 4; q++)
        tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                       mask_off + offsetof(ZMMReg, ZMM_Q(q)));
    if (val_sz == 4) {
        TCGv_i32 msk = tcg_temp_new_i32(tcg_ctx);
        for (int i = 0; i < n; i++) {
            tcg_gen_ld_i32(tcg_ctx, msk, tcg_ctx->cpu_env,
                           mask_off + offsetof(ZMMReg, ZMM_L(i)));
            tcg_gen_sari_i32(tcg_ctx, msk, msk, 31);
            tcg_gen_st_i32(tcg_ctx, msk, tcg_ctx->cpu_env,
                           mask_off + offsetof(ZMMReg, ZMM_L(i)));
        }
        tcg_temp_free_i32(tcg_ctx, msk);
    } else {
        TCGv_i64 msk = tcg_temp_new_i64(tcg_ctx);
        for (int i = 0; i < n; i++) {
            tcg_gen_ld_i64(tcg_ctx, msk, tcg_ctx->cpu_env,
                           mask_off + offsetof(ZMMReg, ZMM_Q(i)));
            tcg_gen_sari_i64(tcg_ctx, msk, msk, 63);
            tcg_gen_st_i64(tcg_ctx, msk, tcg_ctx->cpu_env,
                           mask_off + offsetof(ZMMReg, ZMM_Q(i)));
        }
        tcg_temp_free_i64(tcg_ctx, msk);
    }

    TCGv base_disp = tcg_temp_local_new(tcg_ctx);
    if (have_base)
        tcg_gen_mov_tl(tcg_ctx, base_disp, tcg_ctx->cpu_regs[base_reg]);
    else
        tcg_gen_movi_tl(tcg_ctx, base_disp, 0);
    if (disp)
        tcg_gen_addi_tl(tcg_ctx, base_disp, base_disp, disp);

    TCGv off = tcg_temp_local_new(tcg_ctx);
    TCGv idxv = tcg_temp_local_new(tcg_ctx);
    for (int i = 0; i < n; i++) {
        if (idx_sz == 4)
            tcg_gen_ld32s_tl(tcg_ctx, idxv, tcg_ctx->cpu_env,
                             idx_off + offsetof(ZMMReg, ZMM_L(i)));
        else
            tcg_gen_ld_tl(tcg_ctx, idxv, tcg_ctx->cpu_env,
                          idx_off + offsetof(ZMMReg, ZMM_Q(i)));
        if (scale_sh)
            tcg_gen_shli_tl(tcg_ctx, idxv, idxv, scale_sh);
        tcg_gen_add_tl(tcg_ctx, off, base_disp, idxv);
        gen_lea_v_seg(s, s->aflag, off, def_seg, s->override);
        if (val_sz == 4) {
            TCGLabel *done = gen_new_label(tcg_ctx);
            TCGv lane_addr = tcg_temp_local_new(tcg_ctx);
            TCGv_i32 loaded = tcg_temp_new_i32(tcg_ctx);
            TCGv_i32 msk = tcg_temp_new_i32(tcg_ctx);
            tcg_gen_mov_tl(tcg_ctx, lane_addr, s->A0);
            tcg_gen_ld_i32(tcg_ctx, msk, tcg_ctx->cpu_env,
                           mask_off + offsetof(ZMMReg, ZMM_L(i)));
            tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_GE, msk, 0, done);
            tcg_gen_qemu_ld_i32(tcg_ctx, loaded, lane_addr, s->mem_index,
                                MO_LEUL);
            tcg_gen_st_i32(tcg_ctx, loaded, tcg_ctx->cpu_env,
                           dst_off + offsetof(ZMMReg, ZMM_L(i)));
            gen_set_label(tcg_ctx, done);
            tcg_gen_movi_i32(tcg_ctx, msk, 0);
            tcg_gen_st_i32(tcg_ctx, msk, tcg_ctx->cpu_env,
                           mask_off + offsetof(ZMMReg, ZMM_L(i)));
            tcg_temp_free(tcg_ctx, lane_addr);
            tcg_temp_free_i32(tcg_ctx, loaded);
            tcg_temp_free_i32(tcg_ctx, msk);
        } else {
            TCGLabel *done = gen_new_label(tcg_ctx);
            TCGv lane_addr = tcg_temp_local_new(tcg_ctx);
            TCGv_i64 loaded = tcg_temp_new_i64(tcg_ctx);
            TCGv_i64 msk = tcg_temp_new_i64(tcg_ctx);
            tcg_gen_mov_tl(tcg_ctx, lane_addr, s->A0);
            tcg_gen_ld_i64(tcg_ctx, msk, tcg_ctx->cpu_env,
                           mask_off + offsetof(ZMMReg, ZMM_Q(i)));
            tcg_gen_brcondi_i64(tcg_ctx, TCG_COND_GE, msk, 0, done);
            tcg_gen_qemu_ld_i64(tcg_ctx, loaded, lane_addr, s->mem_index,
                                MO_LEQ);
            tcg_gen_st_i64(tcg_ctx, loaded, tcg_ctx->cpu_env,
                           dst_off + offsetof(ZMMReg, ZMM_Q(i)));
            gen_set_label(tcg_ctx, done);
            tcg_gen_movi_i64(tcg_ctx, msk, 0);
            tcg_gen_st_i64(tcg_ctx, msk, tcg_ctx->cpu_env,
                           mask_off + offsetof(ZMMReg, ZMM_Q(i)));
            tcg_temp_free(tcg_ctx, lane_addr);
            tcg_temp_free_i64(tcg_ctx, loaded);
            tcg_temp_free_i64(tcg_ctx, msk);
        }
    }
    tcg_temp_free(tcg_ctx, base_disp);
    tcg_temp_free(tcg_ctx, off);
    tcg_temp_free(tcg_ctx, idxv);

    /* Zero the destination above the gathered elements: the unused low-lane
     * qwords of a narrowing (QD) gather and the YMM high lane for any sub-256
     * result. */
    tcg_gen_movi_i64(tcg_ctx, s->tmp1_i64, 0);
    for (int q = (n * val_sz) / 8; q < 4; q++)
        tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                       dst_off + offsetof(ZMMReg, ZMM_Q(q)));
    /* The whole mask register is cleared on completion. */
    for (int q = 0; q < 4; q++)
        tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                       mask_off + offsetof(ZMMReg, ZMM_Q(q)));
    return true;
}

/* VEX masked contiguous load/store, shared by the 128- and 256-bit forms. */
static bool gen_vmaskmov(CPUX86State *env, DisasContext *s, int sub,
                         int modrm, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mod = (modrm >> 6) & 3;
    bool is_fp = sub >= 0x2c && sub <= 0x2f;
    bool is_store;
    bool is_q;
    int reg_off;
    int value_off;
    int mask_off;
    int vl;
    int esz;
    int n;
    TCGv base_addr;

    if (sub != 0x8c && sub != 0x8e && sub != 0x2c && sub != 0x2d &&
        sub != 0x2e && sub != 0x2f) {
        return false;
    }
    if ((sub == 0x8c || sub == 0x8e) && !x86_avx2_enabled(s))
        return false;
    /* All forms require memory.  VEX.W is reserved for the floating-point
     * encodings; the integer encodings use it to select dword/qword lanes. */
    if (mod == 3 || (is_fp && s->vex_w)) {
        return false;
    }

    is_store = is_fp ? (sub == 0x2e || sub == 0x2f) : (sub == 0x8e);
    is_q = is_fp ? (sub == 0x2d || sub == 0x2f) : s->vex_w;
    reg_off = offsetof(CPUX86State, xmm_regs[reg]);
    value_off = is_store ? reg_off : offsetof(CPUX86State, xmm_t0);
    mask_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
    vl = s->vex_l ? 32 : 16;
    esz = is_q ? 8 : 4;
    n = vl / esz;

    gen_lea_modrm(env, s, modrm);
    base_addr = tcg_temp_local_new(tcg_ctx);
    tcg_gen_mov_tl(tcg_ctx, base_addr, s->A0);
    for (int i = 0; i < n; i++) {
        TCGv lane_addr = tcg_temp_local_new(tcg_ctx);
        if (i) {
            tcg_gen_addi_tl(tcg_ctx, lane_addr, base_addr, i * esz);
        } else {
            tcg_gen_mov_tl(tcg_ctx, lane_addr, base_addr);
        }
        if (is_q) {
            TCGLabel *done = gen_new_label(tcg_ctx);
            TCGv_i64 mask = tcg_temp_new_i64(tcg_ctx);
            TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);
            TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);
            tcg_gen_ld_i64(tcg_ctx, mask, tcg_ctx->cpu_env,
                           mask_off + offsetof(ZMMReg, ZMM_Q(i)));
            if (is_store) {
                tcg_gen_brcondi_i64(tcg_ctx, TCG_COND_GE, mask, 0, done);
                tcg_gen_ld_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                               value_off + offsetof(ZMMReg, ZMM_Q(i)));
                tcg_gen_qemu_st_i64(tcg_ctx, value, lane_addr, s->mem_index,
                                    MO_LEQ);
            } else {
                tcg_gen_st_i64(tcg_ctx, zero, tcg_ctx->cpu_env,
                               value_off + offsetof(ZMMReg, ZMM_Q(i)));
                tcg_gen_brcondi_i64(tcg_ctx, TCG_COND_GE, mask, 0, done);
                tcg_gen_qemu_ld_i64(tcg_ctx, value, lane_addr, s->mem_index,
                                    MO_LEQ);
                tcg_gen_st_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                               value_off + offsetof(ZMMReg, ZMM_Q(i)));
            }
            gen_set_label(tcg_ctx, done);
            tcg_temp_free_i64(tcg_ctx, mask);
            tcg_temp_free_i64(tcg_ctx, value);
            tcg_temp_free_i64(tcg_ctx, zero);
        } else {
            TCGLabel *done = gen_new_label(tcg_ctx);
            TCGv_i32 mask = tcg_temp_new_i32(tcg_ctx);
            TCGv_i32 value = tcg_temp_new_i32(tcg_ctx);
            TCGv_i32 zero = tcg_const_i32(tcg_ctx, 0);
            tcg_gen_ld_i32(tcg_ctx, mask, tcg_ctx->cpu_env,
                           mask_off + offsetof(ZMMReg, ZMM_L(i)));
            if (is_store) {
                tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_GE, mask, 0, done);
                tcg_gen_ld_i32(tcg_ctx, value, tcg_ctx->cpu_env,
                               value_off + offsetof(ZMMReg, ZMM_L(i)));
                tcg_gen_qemu_st_i32(tcg_ctx, value, lane_addr, s->mem_index,
                                    MO_LEUL);
            } else {
                tcg_gen_st_i32(tcg_ctx, zero, tcg_ctx->cpu_env,
                               value_off + offsetof(ZMMReg, ZMM_L(i)));
                tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_GE, mask, 0, done);
                tcg_gen_qemu_ld_i32(tcg_ctx, value, lane_addr, s->mem_index,
                                    MO_LEUL);
                tcg_gen_st_i32(tcg_ctx, value, tcg_ctx->cpu_env,
                               value_off + offsetof(ZMMReg, ZMM_L(i)));
            }
            gen_set_label(tcg_ctx, done);
            tcg_temp_free_i32(tcg_ctx, mask);
            tcg_temp_free_i32(tcg_ctx, value);
            tcg_temp_free_i32(tcg_ctx, zero);
        }
        tcg_temp_free(tcg_ctx, lane_addr);
    }
    tcg_temp_free(tcg_ctx, base_addr);

    if (!is_store) {
        if (s->vex_l) {
            gen_op_movy(s, reg_off, value_off);
        } else {
            gen_op_movo(s, reg_off, value_off);
            gen_clear_ymmh(s, reg);
        }
    }
    return true;
}

/* The 256-bit test instructions reduce both 128-bit lanes into one ZF/CF
 * result.  The existing XMM helper emits exactly those two flags, so ANDing
 * the per-lane flag words implements the full-width reduction. */
static void gen_vtest_ymm(CPUX86State *env, DisasContext *s, int modrm,
                          int reg, int element_bits)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mod = (modrm >> 6) & 3;
    int rm = (modrm & 7) | REX_B(s);
    int op1_offset = offsetof(CPUX86State, xmm_regs[reg]);
    int op2_offset;

    if (mod == 3) {
        op2_offset = offsetof(CPUX86State, xmm_regs[rm]);
    } else {
        op2_offset = offsetof(CPUX86State, xmm_t0);
        gen_lea_modrm(env, s, modrm);
        gen_ldy_env_A0(s, op2_offset);
    }
    tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
    tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
    if (element_bits) {
        gen_helper_vtest(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1,
                         tcg_const_i32(tcg_ctx, element_bits));
    } else {
        gen_helper_ptest_xmm(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
    }
    tcg_gen_mov_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_cc_src);
    tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                     op1_offset + YMM_HI_LANE_OFF);
    tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                     op2_offset + YMM_HI_LANE_OFF);
    if (element_bits) {
        gen_helper_vtest(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1,
                         tcg_const_i32(tcg_ctx, element_bits));
    } else {
        gen_helper_ptest_xmm(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
    }
    tcg_gen_and_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src,
                   s->tmp0);
    set_cc_op(s, CC_OP_EFLAGS);
}

/* FMA3 decoder (defined after gen_sse_256); the 256-bit path reuses it. */
static bool gen_x86_fma(CPUX86State *env, DisasContext *s, int b, int modrm,
                        int reg, int rm, int mod);

/*
 * 256-bit (VEX.L=1, YMM) AVX/AVX2 decode.  QEMU 5.0.1's SSE decoder rejects
 * every VEX.256 encoding outright; this handles the YMM forms by reusing the
 * existing 128-bit helpers once per 128-bit lane (almost all AVX2 packed ops
 * are in-lane), plus dedicated decoders for the widening (pmovsx/zx) and
 * cross-lane (vextract/vinsert128) shapes.  Returns true if the instruction was
 * fully handled; false leaves the caller to raise #UD.  Reached only when
 * s->vex_l != 0, so the 128-bit paths are untouched.
 *
 * For 0f38/0f3a, `modrm` carries the map's sub-opcode and the real ModRM byte
 * is read here; for one-byte 0f opcodes `modrm` is already the ModRM byte.
 */
static bool gen_sse_256(CPUX86State *env, DisasContext *s, int b, int b1,
                        int modrm, int reg, int rex_r)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mod, rm, op1_offset, op2_offset, sub = 0, val;
    SSEFunc_0_epp fn;

    if (!x86_avx_enabled(s))
        return false;

    /* Every VEX.256 instruction in the 0f3a map uses the mandatory 66
     * prefix.  Do not let a pp=none encoding select an MMX helper through
     * the legacy tables below. */
    if (b == 0x3a && b1 != 1)
        return false;

    if (b == 0x38 || b == 0x3a) {
        sub = modrm;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
    }
    mod = (modrm >> 6) & 3;
    rm = (modrm & 7) | REX_B(s);
    op1_offset = offsetof(CPUX86State, xmm_regs[reg]);

    if (b == 0x3a) {
        /* VEX.256 GF2P8AFFINE{,INV}QB (W1, per 128-bit lane). */
        if (b1 == 1 && (sub == 0xce || sub == 0xcf) &&
            s->vex_w) {
            TCGv_ptr matrix = tcg_temp_new_ptr(tcg_ctx);
            TCGv_i32 imm;
            int x_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
            int matrix_off;

            if (!(s->cpuid_7_0_ecx_features & CPUID_7_0_ECX_GFNI)) {
                tcg_temp_free_ptr(tcg_ctx, matrix);
                return false;
            }
            if (mod == 3) {
                matrix_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                matrix_off = offsetof(CPUX86State, xmm_t0);
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, matrix_off);
            }
            val = x86_ldub_code(env, s);
            imm = tcg_const_i32(tcg_ctx, val);
            for (int lane = 0; lane < 2; ++lane) {
                int off = lane * YMM_HI_LANE_OFF;
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 op1_offset + off);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                                 x_off + off);
                tcg_gen_addi_ptr(tcg_ctx, matrix, tcg_ctx->cpu_env,
                                 matrix_off + off);
                if (sub == 0xce) {
                    gen_helper_gf2p8affineqb_xmm(
                        tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1, matrix,
                        imm);
                } else {
                    gen_helper_gf2p8affineinvqb_xmm(
                        tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1, matrix,
                        imm);
                }
            }
            tcg_temp_free_i32(tcg_ctx, imm);
            tcg_temp_free_ptr(tcg_ctx, matrix);
            return true;
        }

        /* 0f3a: 128-bit-lane insert/extract (imm8 selects the lane). */
        switch (sub) {
        case 0x40: /* vdpps: independent dot product in each 128-bit lane */
        {
            SSEFunc_0_eppi ppi;
            TCGv_i32 imm;
            int s2_off, lane;

            if (sse_op_table7[0x40].op[b1] == SSE_SPECIAL ||
                !sse_op_table7[0x40].op[b1] ||
                !(s->cpuid_ext_features & sse_op_table7[0x40].ext_mask)) {
                return false;
            }
            ppi = (SSEFunc_0_eppi)sse_op_table7[0x40].op[b1];
            if (mod == 3) {
                s2_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                s2_off = offsetof(CPUX86State, xmm_t0);
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, s2_off);
            }
            val = x86_ldub_code(env, s);
            gen_sse_vex_merge_src1_ymm(s, reg, &s2_off);
            imm = tcg_const_i32(tcg_ctx, val);
            for (lane = 0; lane < 2; lane++) {
                int off = lane * YMM_HI_LANE_OFF;
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 op1_offset + off);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                                 s2_off + off);
                ppi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1, imm);
            }
            tcg_temp_free_i32(tcg_ctx, imm);
            return true;
        }
        case 0x44: /* vpclmulqdq: one carry-less multiply per 128-bit lane */
        {
            int s2_off;
            TCGv_i32 imm;

            if (!(s->cpuid_ext_features & CPUID_EXT_PCLMULQDQ) ||
                !(s->cpuid_7_0_ecx_features &
                  CPUID_7_0_ECX_VPCLMULQDQ))
                return false;
            if (mod == 3) {
                s2_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                s2_off = offsetof(CPUX86State, xmm_t0);
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, s2_off);
            }
            val = x86_ldub_code(env, s);
            gen_sse_vex_merge_src1_ymm(s, reg, &s2_off);
            imm = tcg_const_i32(tcg_ctx, val);
            for (int lane = 0; lane < 2; lane++) {
                int off = lane * YMM_HI_LANE_OFF;
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 op1_offset + off);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                                 s2_off + off);
                gen_helper_pclmulqdq_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                         s->ptr0, s->ptr1, imm);
            }
            tcg_temp_free_i32(tcg_ctx, imm);
            return true;
        }
        case 0x02: /* vpblendd */
        case 0x0c: /* vblendps (bit-identical to vpblendd: 8 dwords by imm8[i]) */
        {
            /* per-dword blend: dst.L[i] = imm8[i] ? src2.L[i] : src1.L[i].
             * src1=vvvv, src2=rm/mem.  Each output dword depends only on the
             * same input dword, so an in-place dst==src blend is safe.  vblendps
             * (0x0c) selects 8 packed f32 by the same imm8 bit-per-element rule,
             * so it shares this code exactly. */
            int s1_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
            int s2_off;
            int i;
            if (sub == 0x02 &&
                (s->vex_w || !x86_avx2_enabled(s)))
                return false;
            if (mod == 3) {
                s2_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                s2_off = offsetof(CPUX86State, xmm_t0);
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, s2_off);
            }
            val = x86_ldub_code(env, s);
            for (i = 0; i < 8; i++) {
                int from = ((val >> i) & 1) ? s2_off : s1_off;
                tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                               from + offsetof(ZMMReg, ZMM_L(i)));
                tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                               op1_offset + offsetof(ZMMReg, ZMM_L(i)));
            }
            return true;
        }
        case 0x0e: /* vpblendw: per-128-bit-lane word blend by imm8.  imm8[b]
                    * (b in 0..7) selects src2.word[b] (else src1.word[b]) within
                    * EACH 128-bit lane -- the same imm8 bit drives word b and
                    * word b+8 (one imm8 covers both lanes).  src1=vvvv,
                    * src2=rm/mem; each output word depends only on the same input
                    * word, so an in-place dst==src blend is safe. */
        {
            int s1_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
            int s2_off;
            int i;
            if (!x86_avx2_enabled(s))
                return false;
            if (mod == 3) {
                s2_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                s2_off = offsetof(CPUX86State, xmm_t0);
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, s2_off);
            }
            val = x86_ldub_code(env, s);
            for (i = 0; i < 16; i++) {
                int from = ((val >> (i & 7)) & 1) ? s2_off : s1_off;
                tcg_gen_ld16u_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_env,
                                 from + offsetof(ZMMReg, ZMM_W(i)));
                tcg_gen_st16_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_env,
                                op1_offset + offsetof(ZMMReg, ZMM_W(i)));
            }
            return true;
        }
        case 0x0d: /* vblendpd: per-qword blend, dst.Q[i] = imm8[i] ? src2 : src1
                    * (4 packed f64; imm8[0..3]).  src1=vvvv, src2=rm/mem; each
                    * output qword depends only on the same input qword so an
                    * in-place dst==src blend is safe. */
        {
            int s1_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
            int s2_off;
            int i;
            if (mod == 3) {
                s2_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                s2_off = offsetof(CPUX86State, xmm_t0);
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, s2_off);
            }
            val = x86_ldub_code(env, s);
            for (i = 0; i < 4; i++) {
                int from = ((val >> i) & 1) ? s2_off : s1_off;
                tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                               from + offsetof(ZMMReg, ZMM_Q(i)));
                tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                               op1_offset + offsetof(ZMMReg, ZMM_Q(i)));
            }
            return true;
        }
        case 0x00: /* vpermq */
        case 0x01: /* vpermpd */
        {
            /* CROSS-LANE qword permute by imm8 (each 2-bit field picks any of
             * the 4 source qwords).  Read all 4 source qwords first so an
             * in-place dst==src permute is correct. */
            int s_off;
            TCGv_i64 q[4];
            int i;
            if (!s->vex_w || !x86_avx2_enabled(s))
                return false;
            if (mod == 3) {
                s_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                s_off = offsetof(CPUX86State, xmm_t0);
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, s_off);
            }
            val = x86_ldub_code(env, s);
            for (i = 0; i < 4; i++) {
                q[i] = tcg_temp_new_i64(tcg_ctx);
                tcg_gen_ld_i64(tcg_ctx, q[i], tcg_ctx->cpu_env,
                               s_off + offsetof(ZMMReg, ZMM_Q(i)));
            }
            for (i = 0; i < 4; i++) {
                tcg_gen_st_i64(tcg_ctx, q[(val >> (2 * i)) & 3], tcg_ctx->cpu_env,
                               op1_offset + offsetof(ZMMReg, ZMM_Q(i)));
            }
            for (i = 0; i < 4; i++)
                tcg_temp_free_i64(tcg_ctx, q[i]);
            return true;
        }
        case 0x18: /* vinsertf128 */
        case 0x38: /* vinserti128 */
            /* Read the 128-bit src into xmm_t0 BEFORE overwriting dst with src1
             * (vvvv): a register src can alias dst (e.g. `vinserti128 $1,%xmm0,
             * %ymm1,%ymm0`, where xmm0 is the low half of dst ymm0), so the
             * src1 preload would otherwise clobber it. */
            if (s->vex_w ||
                (sub == 0x38 && !x86_avx2_enabled(s)))
                return false;
            if (mod == 3) {
                gen_op_movo(s, offsetof(CPUX86State, xmm_t0),
                            offsetof(CPUX86State, xmm_regs[rm]));
            } else {
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_t0));
            }
            gen_op_movy(s, op1_offset, offsetof(CPUX86State, xmm_regs[s->vex_v]));
            val = x86_ldub_code(env, s);
            gen_op_movo(s, op1_offset + (val & 1) * YMM_HI_LANE_OFF,
                        offsetof(CPUX86State, xmm_t0));
            return true;
        case 0x19: /* vextractf128 */
        case 0x39: /* vextracti128 */
            if (s->vex_w ||
                (sub == 0x39 && !x86_avx2_enabled(s)))
                return false;
            if (mod == 3) {
                val = x86_ldub_code(env, s);
                gen_op_movo(s, offsetof(CPUX86State, xmm_regs[rm]),
                            op1_offset + (val & 1) * YMM_HI_LANE_OFF);
                gen_clear_ymmh(s, rm);
            } else {
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                val = x86_ldub_code(env, s);
                gen_sto_env_A0(s, op1_offset + (val & 1) * YMM_HI_LANE_OFF);
            }
            return true;
        case 0x1d: { /* vcvtps2ph (256-bit): ymm reg -> xmm/m128 */
            /* 8 single-precision floats in the ymm reg source narrow to 8 packed
             * halves in the xmm/m128 dst.  Convert each 128-bit lane with the
             * existing cvtps2ph helper (low 4 floats -> low 4 halves, high 4
             * floats -> high 4 halves) into xmm_t0, then combine the two 64-bit
             * half-results into the 128-bit dst.  A register dst has its upper
             * 128 bits zeroed per the AVX rule. */
            int t0 = offsetof(CPUX86State, xmm_t0);
            TCGv_i64 lo = tcg_temp_new_i64(tcg_ctx);
            TCGv_i32 f16imm;
            if (b1 != 1 || s->vex_w || s->vex_v != 0 ||
                !(s->cpuid_ext_features & CPUID_EXT_F16C)) {
                tcg_temp_free_i64(tcg_ctx, lo);
                return false;
            }
            if (mod != 3) {
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
            }
            val = x86_ldub_code(env, s);
            f16imm = tcg_const_i32(tcg_ctx, val);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, t0);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op1_offset);
            gen_helper_cvtps2ph(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1,
                                f16imm);
            tcg_gen_ld_i64(tcg_ctx, lo, tcg_ctx->cpu_env,
                           t0 + offsetof(ZMMReg, ZMM_Q(0)));
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, t0);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                             op1_offset + YMM_HI_LANE_OFF);
            gen_helper_cvtps2ph(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1,
                                f16imm);
            tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                           t0 + offsetof(ZMMReg, ZMM_Q(0)));
            tcg_temp_free_i32(tcg_ctx, f16imm);
            if (mod == 3) {
                tcg_gen_st_i64(tcg_ctx, lo, tcg_ctx->cpu_env,
                               offsetof(CPUX86State, xmm_regs[rm]) +
                                   offsetof(ZMMReg, ZMM_Q(0)));
                tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                               offsetof(CPUX86State, xmm_regs[rm]) +
                                   offsetof(ZMMReg, ZMM_Q(1)));
                gen_clear_ymmh(s, rm);
            } else {
                tcg_gen_qemu_st_i64(tcg_ctx, lo, s->A0, s->mem_index, MO_LEQ);
                tcg_gen_addi_tl(tcg_ctx, s->A0, s->A0, 8);
                tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0, s->mem_index,
                                    MO_LEQ);
            }
            tcg_temp_free_i64(tcg_ctx, lo);
            return true;
        }
        case 0x06: /* vperm2f128 (FP domain) */
        case 0x46: { /* vperm2i128 (integer domain) -- bit-identical 128-bit lane
                      * block permute: pick each 128-bit dst lane from any of the
                      * four source lanes (src1=vvvv low/high, src2=rm/mem
                      * low/high) by imm8; imm bit (j*4+3) zeroes that lane. */
            int s1_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
            int s2_off;
            TCGv_i64 lane[8]; /* [0,1]=s1.lo [2,3]=s1.hi [4,5]=s2.lo [6,7]=s2.hi */
            int j;
            if (s->vex_w ||
                (sub == 0x46 && !x86_avx2_enabled(s)))
                return false;
            if (mod == 3) {
                s2_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                s2_off = offsetof(CPUX86State, xmm_t0);
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, s2_off);
            }
            val = x86_ldub_code(env, s);
            /* snapshot all four candidate lanes first (dst may alias a src). */
            for (j = 0; j < 4; j++) {
                lane[j] = tcg_temp_new_i64(tcg_ctx);
                tcg_gen_ld_i64(tcg_ctx, lane[j], tcg_ctx->cpu_env,
                               s1_off + offsetof(ZMMReg, ZMM_Q(j)));
            }
            for (j = 0; j < 4; j++) {
                lane[4 + j] = tcg_temp_new_i64(tcg_ctx);
                tcg_gen_ld_i64(tcg_ctx, lane[4 + j], tcg_ctx->cpu_env,
                               s2_off + offsetof(ZMMReg, ZMM_Q(j)));
            }
            for (j = 0; j < 2; j++) {
                int q0 = op1_offset + offsetof(ZMMReg, ZMM_Q(2 * j));
                int q1 = op1_offset + offsetof(ZMMReg, ZMM_Q(2 * j + 1));
                if ((val >> (j * 4 + 3)) & 1) {
                    TCGv_i64 z = tcg_const_i64(tcg_ctx, 0);
                    tcg_gen_st_i64(tcg_ctx, z, tcg_ctx->cpu_env, q0);
                    tcg_gen_st_i64(tcg_ctx, z, tcg_ctx->cpu_env, q1);
                    tcg_temp_free_i64(tcg_ctx, z);
                } else {
                    int sel = (val >> (j * 4)) & 3;
                    tcg_gen_st_i64(tcg_ctx, lane[sel * 2], tcg_ctx->cpu_env, q0);
                    tcg_gen_st_i64(tcg_ctx, lane[sel * 2 + 1], tcg_ctx->cpu_env,
                                   q1);
                }
            }
            for (j = 0; j < 8; j++)
                tcg_temp_free_i64(tcg_ctx, lane[j]);
            return true;
        }
        case 0x08: /* vroundps (256): round 8 packed f32 by imm8 mode */
        case 0x09: /* vroundpd (256): round 4 packed f64 by imm8 mode */
        {
            /* 2-operand: dst = round(src, imm8); src = rm/mem, no vvvv.  The
             * per-element round helper reads src[i] and writes dst[i] at the
             * same index, so an in-place dst==src (register src) is safe.
             * Apply the 128-bit helper to each of the two 128-bit lanes. */
            int src_off, lane;
            TCGv_i32 mode;
            if (mod == 3) {
                src_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                src_off = offsetof(CPUX86State, xmm_t0);
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, src_off);
            }
            val = x86_ldub_code(env, s);
            mode = tcg_const_i32(tcg_ctx, val);
            for (lane = 0; lane < 2; lane++) {
                int off = lane * YMM_HI_LANE_OFF;
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 op1_offset + off);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                                 src_off + off);
                if (sub == 0x08)
                    gen_helper_roundps_xmm(tcg_ctx, tcg_ctx->cpu_env, s->ptr0,
                                           s->ptr1, mode);
                else
                    gen_helper_roundpd_xmm(tcg_ctx, tcg_ctx->cpu_env, s->ptr0,
                                           s->ptr1, mode);
            }
            tcg_temp_free_i32(tcg_ctx, mode);
            return true;
        }
        case 0x4a: /* vblendvps (256) */
        case 0x4b: /* vblendvpd (256) */
        case 0x4c: /* vpblendvb (256) */
        {
            /* 4-operand variable blend over the full 256 bits: each element
             * takes src2 when its mask element's sign bit is set, else src1.
             * src1=vvvv, src2=rm/mem, mask=is4 imm high nibble. */
            int esz = (sub == 0x4a) ? 4 : (sub == 0x4b) ? 8 : 1;
            int s1off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
            int s2off, moff;
            if (s->vex_w ||
                (sub == 0x4c && !x86_avx2_enabled(s)))
                return false;
            if (mod == 3) {
                s2off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                s2off = offsetof(CPUX86State, xmm_t0);
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, s2off);
            }
            val = x86_ldub_code(env, s);
            moff = offsetof(CPUX86State, xmm_regs[(val >> 4) & 15]);
            if (esz == 8) {
                TCGv_i64 m = tcg_temp_new_i64(tcg_ctx);
                TCGv_i64 a = tcg_temp_new_i64(tcg_ctx);
                TCGv_i64 bv = tcg_temp_new_i64(tcg_ctx);
                TCGv_i64 z = tcg_const_i64(tcg_ctx, 0);
                for (int i = 0; i < 4; i++) {
                    tcg_gen_ld_i64(tcg_ctx, m, tcg_ctx->cpu_env,
                                   moff + offsetof(ZMMReg, ZMM_Q(i)));
                    tcg_gen_ld_i64(tcg_ctx, a, tcg_ctx->cpu_env,
                                   s1off + offsetof(ZMMReg, ZMM_Q(i)));
                    tcg_gen_ld_i64(tcg_ctx, bv, tcg_ctx->cpu_env,
                                   s2off + offsetof(ZMMReg, ZMM_Q(i)));
                    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LT, a, m, z, bv, a);
                    tcg_gen_st_i64(tcg_ctx, a, tcg_ctx->cpu_env,
                                   op1_offset + offsetof(ZMMReg, ZMM_Q(i)));
                }
                tcg_temp_free_i64(tcg_ctx, m);
                tcg_temp_free_i64(tcg_ctx, a);
                tcg_temp_free_i64(tcg_ctx, bv);
                tcg_temp_free_i64(tcg_ctx, z);
            } else if (esz == 4) {
                TCGv_i32 m = tcg_temp_new_i32(tcg_ctx);
                TCGv_i32 a = tcg_temp_new_i32(tcg_ctx);
                TCGv_i32 bv = tcg_temp_new_i32(tcg_ctx);
                TCGv_i32 z = tcg_const_i32(tcg_ctx, 0);
                for (int i = 0; i < 8; i++) {
                    tcg_gen_ld_i32(tcg_ctx, m, tcg_ctx->cpu_env,
                                   moff + offsetof(ZMMReg, ZMM_L(i)));
                    tcg_gen_ld_i32(tcg_ctx, a, tcg_ctx->cpu_env,
                                   s1off + offsetof(ZMMReg, ZMM_L(i)));
                    tcg_gen_ld_i32(tcg_ctx, bv, tcg_ctx->cpu_env,
                                   s2off + offsetof(ZMMReg, ZMM_L(i)));
                    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LT, a, m, z, bv, a);
                    tcg_gen_st_i32(tcg_ctx, a, tcg_ctx->cpu_env,
                                   op1_offset + offsetof(ZMMReg, ZMM_L(i)));
                }
                tcg_temp_free_i32(tcg_ctx, m);
                tcg_temp_free_i32(tcg_ctx, a);
                tcg_temp_free_i32(tcg_ctx, bv);
                tcg_temp_free_i32(tcg_ctx, z);
            } else {
                TCGv_i32 m = tcg_temp_new_i32(tcg_ctx);
                TCGv_i32 a = tcg_temp_new_i32(tcg_ctx);
                TCGv_i32 bv = tcg_temp_new_i32(tcg_ctx);
                TCGv_i32 z = tcg_const_i32(tcg_ctx, 0);
                for (int i = 0; i < 32; i++) {
                    tcg_gen_ld8u_i32(tcg_ctx, m, tcg_ctx->cpu_env,
                                     moff + offsetof(ZMMReg, ZMM_B(i)));
                    tcg_gen_andi_i32(tcg_ctx, m, m, 0x80);
                    tcg_gen_ld8u_i32(tcg_ctx, a, tcg_ctx->cpu_env,
                                     s1off + offsetof(ZMMReg, ZMM_B(i)));
                    tcg_gen_ld8u_i32(tcg_ctx, bv, tcg_ctx->cpu_env,
                                     s2off + offsetof(ZMMReg, ZMM_B(i)));
                    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_NE, a, m, z, bv, a);
                    tcg_gen_st8_i32(tcg_ctx, a, tcg_ctx->cpu_env,
                                    op1_offset + offsetof(ZMMReg, ZMM_B(i)));
                }
                tcg_temp_free_i32(tcg_ctx, m);
                tcg_temp_free_i32(tcg_ctx, a);
                tcg_temp_free_i32(tcg_ctx, bv);
                tcg_temp_free_i32(tcg_ctx, z);
            }
            return true;
        }
        case 0x04: /* vpermilps ymm, ymm/m256, imm8 */
        case 0x05: /* vpermilpd ymm, ymm/m256, imm8 */
        {
            int src_off;
            TCGv_i64 q[4];

            if (s->vex_w || s->vex_v != 0)
                return false;
            if (mod == 3) {
                src_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                src_off = offsetof(CPUX86State, xmm_t0);
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, src_off);
            }
            val = x86_ldub_code(env, s);
            for (int i = 0; i < 4; i++) {
                q[i] = tcg_temp_new_i64(tcg_ctx);
                tcg_gen_ld_i64(tcg_ctx, q[i], tcg_ctx->cpu_env,
                               src_off + offsetof(ZMMReg, ZMM_Q(i)));
            }
            if (sub == 0x05) {
                for (int i = 0; i < 4; i++) {
                    int base = i & ~1;
                    int sel = base + ((val >> i) & 1);
                    tcg_gen_st_i64(tcg_ctx, q[sel], tcg_ctx->cpu_env,
                                   op1_offset + offsetof(ZMMReg, ZMM_Q(i)));
                }
            } else {
                TCGv_i32 d[8];
                for (int i = 0; i < 8; i++) {
                    d[i] = tcg_temp_new_i32(tcg_ctx);
                    tcg_gen_ld_i32(tcg_ctx, d[i], tcg_ctx->cpu_env,
                                   src_off + offsetof(ZMMReg, ZMM_L(i)));
                }
                for (int i = 0; i < 8; i++) {
                    int lane = i & ~3;
                    int sel = lane + ((val >> (2 * (i & 3))) & 3);
                    tcg_gen_st_i32(tcg_ctx, d[sel], tcg_ctx->cpu_env,
                                   op1_offset + offsetof(ZMMReg, ZMM_L(i)));
                }
                for (int i = 0; i < 8; i++)
                    tcg_temp_free_i32(tcg_ctx, d[i]);
            }
            for (int i = 0; i < 4; i++)
                tcg_temp_free_i64(tcg_ctx, q[i]);
            return true;
        }
        case 0x0f: /* vpalignr: per-128-bit-lane byte align from concat(src1,src2). */
        {
            SSEFunc_0_eppi ppi;
            int s2_off, lane;
            if (!x86_avx2_enabled(s) ||
                sse_op_table7[0x0f].op[b1] == SSE_SPECIAL ||
                !sse_op_table7[0x0f].op[b1])
                return false;
            ppi = (SSEFunc_0_eppi)sse_op_table7[0x0f].op[b1];
            if (mod == 3) {
                s2_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                s2_off = offsetof(CPUX86State, xmm_t0);
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, s2_off);
            }
            val = x86_ldub_code(env, s);
            gen_sse_vex_merge_src1_ymm(s, reg, &s2_off);
            for (lane = 0; lane < 2; lane++) {
                int off = lane * YMM_HI_LANE_OFF;
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 op1_offset + off);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                                 s2_off + off);
                ppi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1,
                    tcg_const_i32(tcg_ctx, val));
            }
            return true;
        }
        case 0x42: /* vmpsadbw: per-128-bit-lane multiple sum-of-abs-differences.
                    * Eight overlapping 4-byte SADs per lane against a selectable
                    * block; unlike a plain per-lane op the two 128-bit lanes use
                    * DIFFERENT imm8 sub-fields -- the low lane imm8[2:0], the
                    * high lane imm8[5:3].  src1=vvvv, src2=rm/mem; the 128-bit
                    * helper snapshots its inputs so an in-place dst==src is
                    * safe. */
        {
            SSEFunc_0_eppi ppi;
            int s2_off, lane;
            if (!x86_avx2_enabled(s) ||
                sse_op_table7[0x42].op[b1] == SSE_SPECIAL ||
                !sse_op_table7[0x42].op[b1])
                return false;
            ppi = (SSEFunc_0_eppi)sse_op_table7[0x42].op[b1];
            if (mod == 3) {
                s2_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                s2_off = offsetof(CPUX86State, xmm_t0);
                s->rip_offset = 1;
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, s2_off);
            }
            val = x86_ldub_code(env, s);
            gen_sse_vex_merge_src1_ymm(s, reg, &s2_off);
            for (lane = 0; lane < 2; lane++) {
                int off = lane * YMM_HI_LANE_OFF;
                int limm = (lane == 0) ? (val & 7) : ((val >> 3) & 7);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 op1_offset + off);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                                 s2_off + off);
                ppi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1,
                    tcg_const_i32(tcg_ctx, limm));
            }
            return true;
        }
        default:
            return false;
        }
    }

    if (b == 0x38) {
        /* VTESTPS is the sole VEX.256 0f38 form with pp=none.  Every other
         * supported YMM form in this map has the mandatory 66 prefix. */
        if (b1 != 1 && !(b1 == 0 && sub == 0x0e))
            return false;

        /* VMOVNTDQA is a two-operand, memory-only aligned load.  Unlike the
         * generic 0f38 arithmetic helpers its table entry is SSE_SPECIAL. */
        if (sub == 0x2a) {
            if (!x86_avx2_enabled(s) || s->vex_v != 0 || mod == 3)
                return false;
            gen_lea_modrm(env, s, modrm);
            gen_ldy_env_A0_aligned(s, op1_offset);
            return true;
        }

        /* VEX.256 GF2P8MULB (W0, byte-wise GF(2^8) multiplication). */
        if (b1 == 1 && sub == 0xcf && !s->vex_w) {
            TCGv_ptr src2 = tcg_temp_new_ptr(tcg_ctx);
            int src1_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
            int src2_off;

            if (!(s->cpuid_7_0_ecx_features & CPUID_7_0_ECX_GFNI)) {
                tcg_temp_free_ptr(tcg_ctx, src2);
                return false;
            }
            if (mod == 3) {
                src2_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                src2_off = offsetof(CPUX86State, xmm_t0);
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, src2_off);
            }
            for (int lane = 0; lane < 2; ++lane) {
                int off = lane * YMM_HI_LANE_OFF;
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 op1_offset + off);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                                 src1_off + off);
                tcg_gen_addi_ptr(tcg_ctx, src2, tcg_ctx->cpu_env,
                                 src2_off + off);
                gen_helper_gf2p8mulb_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                          s->ptr0, s->ptr1, src2);
            }
            tcg_temp_free_ptr(tcg_ctx, src2);
            return true;
        }

        /* VPERMILPS/PD ymm, ymm, ymm/m256 (variable control, in-lane). */
        if (b1 == 1 && (sub == 0x0c || sub == 0x0d) &&
            !s->vex_w) {
            TCGv_ptr ctrl = tcg_temp_new_ptr(tcg_ctx);
            int data_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
            int ctrl_off;

            if (mod == 3) {
                ctrl_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                ctrl_off = offsetof(CPUX86State, xmm_t0);
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, ctrl_off);
            }
            for (int lane = 0; lane < 2; lane++) {
                int off = lane * YMM_HI_LANE_OFF;
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 op1_offset + off);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                                 data_off + off);
                tcg_gen_addi_ptr(tcg_ctx, ctrl, tcg_ctx->cpu_env,
                                 ctrl_off + off);
                if (sub == 0x0c) {
                    gen_helper_vpermilps_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                             s->ptr0, s->ptr1, ctrl);
                } else {
                    gen_helper_vpermilpd_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                             s->ptr0, s->ptr1, ctrl);
                }
            }
            tcg_temp_free_ptr(tcg_ctx, ctrl);
            return true;
        }
        /* AVX2 256-bit VSIB gather (0f38 90-93). */
        if (sub >= 0x90 && sub <= 0x93)
            return gen_vsib_gather(env, s, sub, modrm, reg);
        if (gen_vmaskmov(env, s, sub, modrm, reg))
            return true;
        /* AVX2 per-element variable shift (0f38 45/46/47): dst[i] = src1[i]
         * SHIFT src2[i].  No 128-bit helper exists, so shift each lane inline.
         * x86 does not mask the count -- an out-of-range count yields 0
         * (logical) or a sign fill (arithmetic).  VEX.W picks
         * the 64-bit (q) form; VPSRAVD (0x46) is dword-only in AVX2. */
        if (sub == 0x45 || sub == 0x46 || sub == 0x47) {
            int src_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
            int cnt_off;
            bool is_q = s->vex_w;
            bool arith = (sub == 0x46);
            bool left = (sub == 0x47);
            if (!x86_avx2_enabled(s) || (arith && is_q))
                return false;
            if (mod == 3) {
                cnt_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                cnt_off = offsetof(CPUX86State, xmm_t0);
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, cnt_off);
            }
            if (is_q) {
                TCGv_i64 v = tcg_temp_new_i64(tcg_ctx);
                TCGv_i64 c = tcg_temp_new_i64(tcg_ctx);
                TCGv_i64 r = tcg_temp_new_i64(tcg_ctx);
                TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);
                TCGv_i64 lim = tcg_const_i64(tcg_ctx, 64);
                for (int i = 0; i < 4; i++) {
                    tcg_gen_ld_i64(tcg_ctx, v, tcg_ctx->cpu_env,
                                   src_off + offsetof(ZMMReg, ZMM_Q(i)));
                    tcg_gen_ld_i64(tcg_ctx, c, tcg_ctx->cpu_env,
                                   cnt_off + offsetof(ZMMReg, ZMM_Q(i)));
                    if (left)
                        tcg_gen_shl_i64(tcg_ctx, r, v, c);
                    else
                        tcg_gen_shr_i64(tcg_ctx, r, v, c);
                    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, r, c, lim, r, zero);
                    tcg_gen_st_i64(tcg_ctx, r, tcg_ctx->cpu_env,
                                   op1_offset + offsetof(ZMMReg, ZMM_Q(i)));
                }
                tcg_temp_free_i64(tcg_ctx, v);
                tcg_temp_free_i64(tcg_ctx, c);
                tcg_temp_free_i64(tcg_ctx, r);
                tcg_temp_free_i64(tcg_ctx, zero);
                tcg_temp_free_i64(tcg_ctx, lim);
            } else {
                TCGv_i32 v = tcg_temp_new_i32(tcg_ctx);
                TCGv_i32 c = tcg_temp_new_i32(tcg_ctx);
                TCGv_i32 r = tcg_temp_new_i32(tcg_ctx);
                TCGv_i32 zero = tcg_const_i32(tcg_ctx, 0);
                TCGv_i32 lim = tcg_const_i32(tcg_ctx, 32);
                TCGv_i32 maxsh = tcg_const_i32(tcg_ctx, 31);
                for (int i = 0; i < 8; i++) {
                    tcg_gen_ld_i32(tcg_ctx, v, tcg_ctx->cpu_env,
                                   src_off + offsetof(ZMMReg, ZMM_L(i)));
                    tcg_gen_ld_i32(tcg_ctx, c, tcg_ctx->cpu_env,
                                   cnt_off + offsetof(ZMMReg, ZMM_L(i)));
                    if (arith) {
                        /* clamp count to 31 so an out-of-range count yields a
                         * full sign fill. */
                        tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LTU, c, c, lim,
                                            c, maxsh);
                        tcg_gen_sar_i32(tcg_ctx, r, v, c);
                    } else if (left) {
                        tcg_gen_shl_i32(tcg_ctx, r, v, c);
                        tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LTU, r, c, lim,
                                            r, zero);
                    } else {
                        tcg_gen_shr_i32(tcg_ctx, r, v, c);
                        tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LTU, r, c, lim,
                                            r, zero);
                    }
                    tcg_gen_st_i32(tcg_ctx, r, tcg_ctx->cpu_env,
                                   op1_offset + offsetof(ZMMReg, ZMM_L(i)));
                }
                tcg_temp_free_i32(tcg_ctx, v);
                tcg_temp_free_i32(tcg_ctx, c);
                tcg_temp_free_i32(tcg_ctx, r);
                tcg_temp_free_i32(tcg_ctx, zero);
                tcg_temp_free_i32(tcg_ctx, lim);
                tcg_temp_free_i32(tcg_ctx, maxsh);
            }
            return true;
        }
        /* AVX2 cross-lane dword gather (0f38 16/36): VPERMPS/VPERMD.
         * dst.L[i] = data.L[idx.L[i] & 7], where idx=vvvv (src1) and
         * data=rm/mem (src2) -- a full 256-bit gather, not lane-wise.  Read all
         * 8 data dwords up front so an in-place dst==data/idx gather is safe. */
        if (sub == 0x16 || sub == 0x36) {
            int idx_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
            int data_off;
            TCGv_i32 d[8], idx, res;
            int i, j;
            if (s->vex_w || !x86_avx2_enabled(s))
                return false;
            if (mod == 3) {
                data_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                data_off = offsetof(CPUX86State, xmm_t0);
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, data_off);
            }
            for (i = 0; i < 8; i++) {
                d[i] = tcg_temp_new_i32(tcg_ctx);
                tcg_gen_ld_i32(tcg_ctx, d[i], tcg_ctx->cpu_env,
                               data_off + offsetof(ZMMReg, ZMM_L(i)));
            }
            idx = tcg_temp_new_i32(tcg_ctx);
            res = tcg_temp_new_i32(tcg_ctx);
            for (i = 0; i < 8; i++) {
                tcg_gen_ld_i32(tcg_ctx, idx, tcg_ctx->cpu_env,
                               idx_off + offsetof(ZMMReg, ZMM_L(i)));
                tcg_gen_andi_i32(tcg_ctx, idx, idx, 7);
                tcg_gen_mov_i32(tcg_ctx, res, d[0]);
                for (j = 1; j < 8; j++) {
                    TCGv_i32 cst = tcg_const_i32(tcg_ctx, j);
                    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_EQ, res, idx, cst,
                                        d[j], res);
                    tcg_temp_free_i32(tcg_ctx, cst);
                }
                tcg_gen_st_i32(tcg_ctx, res, tcg_ctx->cpu_env,
                               op1_offset + offsetof(ZMMReg, ZMM_L(i)));
            }
            for (i = 0; i < 8; i++)
                tcg_temp_free_i32(tcg_ctx, d[i]);
            tcg_temp_free_i32(tcg_ctx, idx);
            tcg_temp_free_i32(tcg_ctx, res);
            return true;
        }
        /* AVX/AVX2 256-bit element broadcast (0f38 18/19/1a/58/59/5a/78/79): replicate
         * src element 0 across every dst lane.  No SSE helper exists. */
        if (sub == 0x18 || sub == 0x19 || sub == 0x1a || sub == 0x58 ||
            sub == 0x59 || sub == 0x5a || sub == 0x78 || sub == 0x79) {
            int doff = op1_offset;
            int soff = offsetof(CPUX86State, xmm_regs[rm]);
            int bsz;
            if (s->vex_w || s->vex_v != 0 ||
                (sub >= 0x58 && !x86_avx2_enabled(s)) ||
                ((sub == 0x18 || sub == 0x19) && mod == 3 &&
                 !x86_avx2_enabled(s)))
                return false;
            switch (sub) {
            case 0x1a: case 0x5a: bsz = 16; break; /* broadcastf/i128 */
            case 0x18: case 0x58: bsz = 4; break; /* vbroadcastss/vpbroadcastd */
            case 0x19: case 0x59: bsz = 8; break; /* vbroadcastsd/vpbroadcastq */
            case 0x78:            bsz = 1; break; /* vpbroadcastb */
            default:              bsz = 2; break; /* vpbroadcastw (0x79) */
            }
            if (bsz == 16 && mod == 3)
                return false;
            if (mod != 3)
                gen_lea_modrm(env, s, modrm);
            if (bsz == 16) {
                int t0 = offsetof(CPUX86State, xmm_t0);
                gen_ldo_env_A0(s, t0);
                gen_op_movo(s, doff, t0);
                gen_op_movo(s, doff + YMM_HI_LANE_OFF, t0);
            } else if (bsz == 8) {
                if (mod == 3)
                    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                                   soff + offsetof(ZMMReg, ZMM_Q(0)));
                else
                    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                        s->mem_index, MO_LEQ);
                for (int i = 0; i < 4; i++)
                    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                                   doff + offsetof(ZMMReg, ZMM_Q(i)));
            } else if (bsz == 4) {
                if (mod == 3)
                    tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                   soff + offsetof(ZMMReg, ZMM_L(0)));
                else
                    tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUL);
                /* pack {m,m} into a 64-bit value and splat via qword stores so
                 * the dst==src register form cannot read a half-overwritten
                 * lane mid-loop. */
                tcg_gen_extu_i32_i64(tcg_ctx, s->tmp1_i64, s->tmp2_i32);
                tcg_gen_deposit_i64(tcg_ctx, s->tmp1_i64, s->tmp1_i64,
                                    s->tmp1_i64, 32, 32);
                for (int i = 0; i < 4; i++)
                    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                                   doff + offsetof(ZMMReg, ZMM_Q(i)));
            } else if (bsz == 2) {
                if (mod == 3)
                    tcg_gen_ld16u_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_env,
                                     soff + offsetof(ZMMReg, ZMM_W(0)));
                else
                    tcg_gen_qemu_ld_tl(tcg_ctx, s->tmp0, s->A0,
                                       s->mem_index, MO_LEUW);
                for (int i = 0; i < 16; i++)
                    tcg_gen_st16_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_env,
                                    doff + offsetof(ZMMReg, ZMM_W(i)));
            } else {
                if (mod == 3)
                    tcg_gen_ld8u_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_env,
                                    soff + offsetof(ZMMReg, ZMM_B(0)));
                else
                    tcg_gen_qemu_ld_tl(tcg_ctx, s->tmp0, s->A0,
                                       s->mem_index, MO_UB);
                for (int i = 0; i < 32; i++)
                    tcg_gen_st8_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_env,
                                   doff + offsetof(ZMMReg, ZMM_B(i)));
            }
            return true;
        }
        /* Widening pmovsx/pmovzx + VCVTPH2PS: a narrow 128-bit src expands to a
         * 256-bit dst, so each output lane consumes 16/factor source bytes (not
         * lane-wise).  VCVTPH2PS (0f38 13) reads 8 halves (low 8 bytes per lane)
         * and writes 4 floats per 128-bit lane, i.e. the 2x-widen (step=8) shape
         * the cvtph2ps helper already implements for the 128-bit form. */
        if (sub == 0x13 || (sub >= 0x20 && sub <= 0x25) ||
            (sub >= 0x30 && sub <= 0x35)) {
            int t0 = offsetof(CPUX86State, xmm_t0);
            int step;

            if (sub == 0x13 &&
                (b1 != 1 || s->vex_w || s->vex_v != 0 ||
                 !(s->cpuid_ext_features & CPUID_EXT_F16C)))
                return false;
            if (sub != 0x13 && !x86_avx2_enabled(s))
                return false;

            fn = sse_op_table6[sub].op[b1];
            if (!fn || fn == SSE_SPECIAL)
                return false;
            switch (sub & 0x0f) {
            case 0x00: case 0x03: case 0x05: step = 8; break; /* 2x widen */
            case 0x01: case 0x04:            step = 4; break; /* 4x widen */
            case 0x02:                       step = 2; break; /* 8x widen */
            default: return false;
            }
            if (mod == 3) {
                gen_op_movo(s, t0, offsetof(CPUX86State, xmm_regs[rm]));
            } else {
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0(s, t0);
            }
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, t0);
            fn(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                             op1_offset + YMM_HI_LANE_OFF);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, t0 + step);
            fn(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            return true;
        }
        if (((sub == 0x17 && b1 == 1) || (sub == 0x0e && b1 == 0) ||
             (sub == 0x0f && b1 == 1)) && !s->vex_w && s->vex_v == 0) {
            if (sub == 0x17 && !x86_avx2_enabled(s))
                return false;
            gen_vtest_ymm(env, s, modrm, reg,
                          sub == 0x17 ? 0 : sub == 0x0f ? 64 : 32);
            return true;
        }
        /* FMA3 256-bit (0f38 98-9f/a8-af/b8-bf): no sse_op_table6 entry; reuse
         * the shared per-lane decoder, which handles the VEX.256 packed form. */
        if ((sub >= 0x96 && sub <= 0x9f) || (sub >= 0xa6 && sub <= 0xaf) ||
            (sub >= 0xb6 && sub <= 0xbf))
            return gen_x86_fma(env, s, sub, modrm, reg, rm, mod);
        fn = sse_op_table6[sub].op[b1];
        if (!fn || fn == SSE_SPECIAL ||
            !(s->cpuid_ext_features & sse_op_table6[sub].ext_mask))
            return false;
        if (sub >= 0xdc && sub <= 0xdf) {
            if (!(s->cpuid_7_0_ecx_features & CPUID_7_0_ECX_VAES))
                return false;
        } else if (!x86_avx2_0f38_ymm_opcode(sub) ||
                   !x86_avx2_enabled(s)) {
            /* Fail closed for 128-bit-only encodings such as AESIMC,
             * PHMINPOSUW and the legacy blendv opcode slots. */
            return false;
        }
        if (mod == 3) {
            op2_offset = offsetof(CPUX86State, xmm_regs[rm]);
        } else {
            op2_offset = offsetof(CPUX86State, xmm_t0);
            gen_lea_modrm(env, s, modrm);
            gen_ldy_env_A0(s, op2_offset);
        }
        if (sse_vex_3op_table6(sub))
            gen_sse_vex_merge_src1_ymm(s, reg, &op2_offset);
        gen_sse_epp_ymm(s, fn, op1_offset, op2_offset);
        return true;
    }

    /* One-byte 0f map. */
    switch ((b1 << 8) | b) {
    case 0x02b: case 0x12b: /* vmovntps / vmovntpd (store) */
        if (s->vex_v != 0 || mod == 3)
            return false;
        gen_lea_modrm(env, s, modrm);
        gen_sty_env_A0_aligned(s, op1_offset);
        return true;
    case 0x1e7:             /* vmovntdq (store) */
        if (!x86_avx2_enabled(s) || s->vex_v != 0 || mod == 3)
            return false;
        gen_lea_modrm(env, s, modrm);
        gen_sty_env_A0_aligned(s, op1_offset);
        return true;
    case 0x3f0: /* vlddqu (load) */
        if (s->vex_v != 0 || mod == 3)
            return false;
        gen_lea_modrm(env, s, modrm);
        gen_ldy_env_A0(s, op1_offset);
        return true;
    case 0x010: case 0x110: /* vmovups / vmovupd (load) */
    case 0x26f:             /* vmovdqu (load) */
        if (s->vex_v != 0)
            return false;
        if (mod == 3)
            gen_op_movy(s, op1_offset, offsetof(CPUX86State, xmm_regs[rm]));
        else { gen_lea_modrm(env, s, modrm); gen_ldy_env_A0(s, op1_offset); }
        return true;
    case 0x028: case 0x128: /* vmovaps / vmovapd (load) */
    case 0x16f:             /* vmovdqa (load) */
        if (s->vex_v != 0)
            return false;
        if (mod == 3)
            gen_op_movy(s, op1_offset, offsetof(CPUX86State, xmm_regs[rm]));
        else {
            gen_lea_modrm(env, s, modrm);
            gen_ldy_env_A0_aligned(s, op1_offset);
        }
        return true;
    case 0x011: case 0x111: /* vmovups / vmovupd (store) */
    case 0x27f:             /* vmovdqu (store) */
        if (s->vex_v != 0)
            return false;
        if (mod == 3)
            gen_op_movy(s, offsetof(CPUX86State, xmm_regs[rm]), op1_offset);
        else { gen_lea_modrm(env, s, modrm); gen_sty_env_A0(s, op1_offset); }
        return true;
    case 0x029: case 0x129: /* vmovaps / vmovapd (store) */
    case 0x17f:             /* vmovdqa (store) */
        if (s->vex_v != 0)
            return false;
        if (mod == 3)
            gen_op_movy(s, offsetof(CPUX86State, xmm_regs[rm]), op1_offset);
        else {
            gen_lea_modrm(env, s, modrm);
            gen_sty_env_A0_aligned(s, op1_offset);
        }
        return true;
    case 0x050: /* vmovmskps (ymm): 8 sign bits (4 per 128-bit lane) */
    case 0x150: /* vmovmskpd (ymm): 4 sign bits (2 per 128-bit lane) */
    {
        /* dst is a GPR (reg), source is the ymm rm; movmsk has no memory form.
         * Gather each 128-bit lane's sign mask with the 128-bit helper and
         * concatenate, the high lane's bits above the low lane's (4 apart for
         * ps, 2 for pd). */
        int src = offsetof(CPUX86State, xmm_regs[rm]);
        int shift = (b1 == 1) ? 2 : 4;
        TCGv_i32 lo = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 hi = tcg_temp_new_i32(tcg_ctx);
        if (s->vex_v != 0 || mod != 3) {
            tcg_temp_free_i32(tcg_ctx, lo);
            tcg_temp_free_i32(tcg_ctx, hi);
            return false;
        }
        tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, src);
        tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                         src + YMM_HI_LANE_OFF);
        if (b1 == 1) {
            gen_helper_movmskpd(tcg_ctx, lo, tcg_ctx->cpu_env, s->ptr0);
            gen_helper_movmskpd(tcg_ctx, hi, tcg_ctx->cpu_env, s->ptr1);
        } else {
            gen_helper_movmskps(tcg_ctx, lo, tcg_ctx->cpu_env, s->ptr0);
            gen_helper_movmskps(tcg_ctx, hi, tcg_ctx->cpu_env, s->ptr1);
        }
        tcg_gen_shli_i32(tcg_ctx, hi, hi, shift);
        tcg_gen_or_i32(tcg_ctx, lo, lo, hi);
        tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], lo);
        tcg_temp_free_i32(tcg_ctx, lo);
        tcg_temp_free_i32(tcg_ctx, hi);
        return true;
    }
    case 0x1d7: /* vpmovmskb (ymm): 32 sign bits (16 per 128-bit lane) */
    {
        /* dst is a GPR (reg), source is the ymm rm; pmovmskb has no memory
         * form.  Gather each 128-bit lane's 16-bit byte mask with the 128-bit
         * helper and concatenate, the high lane's 16 bits above the low's. */
        int src = offsetof(CPUX86State, xmm_regs[rm]);
        TCGv_i32 lo = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 hi = tcg_temp_new_i32(tcg_ctx);
        if (!x86_avx2_enabled(s) || s->vex_v != 0 || mod != 3) {
            tcg_temp_free_i32(tcg_ctx, lo);
            tcg_temp_free_i32(tcg_ctx, hi);
            return false;
        }
        tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, src);
        tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                         src + YMM_HI_LANE_OFF);
        gen_helper_pmovmskb_xmm(tcg_ctx, lo, tcg_ctx->cpu_env, s->ptr0);
        gen_helper_pmovmskb_xmm(tcg_ctx, hi, tcg_ctx->cpu_env, s->ptr1);
        tcg_gen_shli_i32(tcg_ctx, hi, hi, 16);
        tcg_gen_or_i32(tcg_ctx, lo, lo, hi);
        tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], lo);
        tcg_temp_free_i32(tcg_ctx, lo);
        tcg_temp_free_i32(tcg_ctx, hi);
        return true;
    }
    }

    if (b == 0x12 || b == 0x16) {
        /* VEX.256 duplicate moves (2-operand: dst, src=rm/m256; no vvvv):
         *   F2 0F 12  vmovddup  : dst.Q[2k]=dst.Q[2k+1]=src.Q[2k]   (k=0,1)
         *   F3 0F 12  vmovsldup : dst.L[i]=src.L[i & ~1]            (i=0..7)
         *   F3 0F 16  vmovshdup : dst.L[i]=src.L[i | 1]             (i=0..7)
         * Snapshot the source lanes first so an in-place dst==src register form
         * cannot read a half-overwritten lane.  Other prefixes for 0F 12/16
         * (movlps/movhps/movlpd/movhpd) are 128-bit-only and not valid here. */
        int src_off;
        if (s->vex_v != 0)
            return false;
        if (b == 0x12 && b1 == 3) {     /* vmovddup */
            TCGv_i64 q0 = tcg_temp_new_i64(tcg_ctx);
            TCGv_i64 q2 = tcg_temp_new_i64(tcg_ctx);
            if (mod == 3) {
                src_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                src_off = offsetof(CPUX86State, xmm_t0);
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, src_off);
            }
            tcg_gen_ld_i64(tcg_ctx, q0, tcg_ctx->cpu_env,
                           src_off + offsetof(ZMMReg, ZMM_Q(0)));
            tcg_gen_ld_i64(tcg_ctx, q2, tcg_ctx->cpu_env,
                           src_off + offsetof(ZMMReg, ZMM_Q(2)));
            tcg_gen_st_i64(tcg_ctx, q0, tcg_ctx->cpu_env,
                           op1_offset + offsetof(ZMMReg, ZMM_Q(0)));
            tcg_gen_st_i64(tcg_ctx, q0, tcg_ctx->cpu_env,
                           op1_offset + offsetof(ZMMReg, ZMM_Q(1)));
            tcg_gen_st_i64(tcg_ctx, q2, tcg_ctx->cpu_env,
                           op1_offset + offsetof(ZMMReg, ZMM_Q(2)));
            tcg_gen_st_i64(tcg_ctx, q2, tcg_ctx->cpu_env,
                           op1_offset + offsetof(ZMMReg, ZMM_Q(3)));
            tcg_temp_free_i64(tcg_ctx, q0);
            tcg_temp_free_i64(tcg_ctx, q2);
            return true;
        }
        if (b1 == 2) {                  /* vmovsldup (0x12) / vmovshdup (0x16) */
            int odd = (b == 0x16) ? 1 : 0;
            TCGv_i32 d[4];
            int i;
            if (mod == 3) {
                src_off = offsetof(CPUX86State, xmm_regs[rm]);
            } else {
                src_off = offsetof(CPUX86State, xmm_t0);
                gen_lea_modrm(env, s, modrm);
                gen_ldy_env_A0(s, src_off);
            }
            for (i = 0; i < 4; i++) {
                d[i] = tcg_temp_new_i32(tcg_ctx);
                tcg_gen_ld_i32(tcg_ctx, d[i], tcg_ctx->cpu_env,
                               src_off + offsetof(ZMMReg, ZMM_L(2 * i + odd)));
            }
            for (i = 0; i < 4; i++) {
                tcg_gen_st_i32(tcg_ctx, d[i], tcg_ctx->cpu_env,
                               op1_offset + offsetof(ZMMReg, ZMM_L(2 * i)));
                tcg_gen_st_i32(tcg_ctx, d[i], tcg_ctx->cpu_env,
                               op1_offset + offsetof(ZMMReg, ZMM_L(2 * i + 1)));
            }
            for (i = 0; i < 4; i++)
                tcg_temp_free_i32(tcg_ctx, d[i]);
            return true;
        }
        return false;
    }

    if (b == 0x70) {
        /* vpshufd / vpshuflw / vpshufhw: 2-operand, imm applied per 128 lane. */
        SSEFunc_0_ppi ppi;
        int lane;
        if (b1 == 0 || s->vex_v != 0 || !x86_avx2_enabled(s) ||
            sse_op_table1[b][b1] == SSE_SPECIAL || !sse_op_table1[b][b1])
            return false;
        ppi = (SSEFunc_0_ppi)sse_op_table1[b][b1];
        if (mod == 3) {
            op2_offset = offsetof(CPUX86State, xmm_regs[rm]);
        } else {
            op2_offset = offsetof(CPUX86State, xmm_t0);
            s->rip_offset = 1;
            gen_lea_modrm(env, s, modrm);
            gen_ldy_env_A0(s, op2_offset);
        }
        val = x86_ldub_code(env, s);
        for (lane = 0; lane < 2; lane++) {
            int off = lane * YMM_HI_LANE_OFF;
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset + off);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset + off);
            ppi(tcg_ctx, s->ptr0, s->ptr1, tcg_const_i32(tcg_ctx, val));
        }
        return true;
    }

    if (b == 0xc6) {
        /* vshufps / vshufpd: 3-operand, imm applied per 128 lane. */
        SSEFunc_0_ppi ppi;
        int lane;
        if (sse_op_table1[b][b1] == SSE_SPECIAL || !sse_op_table1[b][b1])
            return false;
        ppi = (SSEFunc_0_ppi)sse_op_table1[b][b1];
        if (mod == 3) {
            op2_offset = offsetof(CPUX86State, xmm_regs[rm]);
        } else {
            op2_offset = offsetof(CPUX86State, xmm_t0);
            s->rip_offset = 1;
            gen_lea_modrm(env, s, modrm);
            gen_ldy_env_A0(s, op2_offset);
        }
        val = x86_ldub_code(env, s);
        gen_sse_vex_merge_src1_ymm(s, reg, &op2_offset);
        for (lane = 0; lane < 2; lane++) {
            int off = lane * YMM_HI_LANE_OFF;
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset + off);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset + off);
            ppi(tcg_ctx, s->ptr0, s->ptr1, tcg_const_i32(tcg_ctx, val));
        }
        return true;
    }

    if (b == 0xc2) {
        /* vcmpps / vcmppd: 3-operand, imm predicate, per element.  Predicates
         * 0-7 are the SSE-compatible set and use the helper table directly.
         * AVX adds predicates 8-31; imm[4] is only the signaling bit (it does
         * not change the boolean result) so the result class is imm[3:0].
         * Classes 8-0xF have no helper, so synthesise each from one basic fact
         * OR'd with cmpunord, optionally bit-inverted:
         *   8 EQ_UQ  = eq | unord     c NEQ_OQ = ~(eq | unord)
         *   9 NGE_US = lt | unord     d GE_OS  = ~(lt | unord)
         *   a NGT_US = le | unord     e GT_OS  = ~(le | unord)
         *   b FALSE  = 0              f TRUE   = ~0
         * (NEQ_OQ is the one LLVM emits for an ordered fcmp one.) */
        if (mod == 3) {
            op2_offset = offsetof(CPUX86State, xmm_regs[rm]);
        } else {
            op2_offset = offsetof(CPUX86State, xmm_t0);
            s->rip_offset = 1;
            gen_lea_modrm(env, s, modrm);
            gen_ldy_env_A0(s, op2_offset);
        }
        val = x86_ldub_code(env, s);
        {
            int lc = val & 0x0f;          /* result class (imm[4] = signaling) */
            if (lc < 8) {
                fn = sse_op_table4[lc][b1];
                gen_sse_vex_merge_src1_ymm(s, reg, &op2_offset);
                gen_sse_epp_ymm(s, fn, op1_offset, op2_offset);
                return true;
            }
            /* Extended predicate.  Snapshot src1 into the unused upper half of
             * the 512-bit xmm_t0 scratch and src2 into the dst, so any dst/src
             * register aliasing is safe and dst is written only at the end. */
            {
                int s1_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
                int t0lo = offsetof(CPUX86State, xmm_t0);
                int t0hi = t0lo + 4 * 8; /* Q4..Q7: a second 256-bit scratch */
                int base = (lc >= 0xc) ? lc - 4 : lc; /* 8,9,a,b; >=c inverts */
                int i;
                if (base == 0x0b) { /* FALSE (TRUE after the ~ below) */
                    TCGv_i64 z = tcg_const_i64(tcg_ctx, 0);
                    for (i = 0; i < 4; i++)
                        tcg_gen_st_i64(tcg_ctx, z, tcg_ctx->cpu_env,
                                       op1_offset + offsetof(ZMMReg, ZMM_Q(i)));
                    tcg_temp_free_i64(tcg_ctx, z);
                } else {
                    int fi = (base == 0x08) ? 0 : (base == 0x09) ? 1 : 2;
                    TCGv_i64 a = tcg_temp_new_i64(tcg_ctx);
                    TCGv_i64 u = tcg_temp_new_i64(tcg_ctx);
                    gen_op_movy(s, t0hi, s1_off); /* t0hi = src1 */
                    if (op2_offset != op1_offset)
                        gen_op_movy(s, op1_offset, op2_offset); /* dst = src2 */
                    gen_op_movy(s, t0lo, t0hi);                 /* t0lo = src1 */
                    /* t0lo = fact(src1, src2); t0hi = unord(src1, src2). */
                    gen_sse_epp_ymm(s, sse_op_table4[fi][b1], t0lo, op1_offset);
                    gen_sse_epp_ymm(s, sse_op_table4[3][b1], t0hi, op1_offset);
                    for (i = 0; i < 4; i++) {
                        tcg_gen_ld_i64(tcg_ctx, a, tcg_ctx->cpu_env,
                                       t0lo + offsetof(ZMMReg, ZMM_Q(i)));
                        tcg_gen_ld_i64(tcg_ctx, u, tcg_ctx->cpu_env,
                                       t0hi + offsetof(ZMMReg, ZMM_Q(i)));
                        tcg_gen_or_i64(tcg_ctx, a, a, u);
                        tcg_gen_st_i64(tcg_ctx, a, tcg_ctx->cpu_env,
                                       op1_offset + offsetof(ZMMReg, ZMM_Q(i)));
                    }
                    tcg_temp_free_i64(tcg_ctx, a);
                    tcg_temp_free_i64(tcg_ctx, u);
                }
                if (lc >= 0x0c) { /* invert: c/d/e/f */
                    TCGv_i64 a = tcg_temp_new_i64(tcg_ctx);
                    for (i = 0; i < 4; i++) {
                        tcg_gen_ld_i64(tcg_ctx, a, tcg_ctx->cpu_env,
                                       op1_offset + offsetof(ZMMReg, ZMM_Q(i)));
                        tcg_gen_not_i64(tcg_ctx, a, a);
                        tcg_gen_st_i64(tcg_ctx, a, tcg_ctx->cpu_env,
                                       op1_offset + offsetof(ZMMReg, ZMM_Q(i)));
                    }
                    tcg_temp_free_i64(tcg_ctx, a);
                }
            }
            return true;
        }
    }

    if (b == 0x71 || b == 0x72 || b == 0x73) {
        /* Packed shift by immediate (group: /2 psrl, /4 psra, /6 psll,
         * /3 psrldq, /7 pslldq): 2-operand VEX (dst=vvvv, src=rm), imm applied
         * per 128-bit lane.  modrm.reg is the opcode extension, not a register;
         * the count goes in xmm_t0's low dword like the 128-bit path. */
        int t0 = offsetof(CPUX86State, xmm_t0);
        int dst_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
        int op_sel = (modrm >> 3) & 7;
        if (b1 != 1 || !x86_avx2_enabled(s))
            return false;
        fn = sse_op_table2[((b - 1) & 3) * 8 + op_sel][b1];
        if (!fn || fn == SSE_SPECIAL)
            return false;
        val = x86_ldub_code(env, s);
        tcg_gen_movi_tl(tcg_ctx, s->T0, val);
        tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                        t0 + offsetof(ZMMReg, ZMM_L(0)));
        tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
        tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                        t0 + offsetof(ZMMReg, ZMM_L(1)));
        gen_op_movy(s, dst_off, offsetof(CPUX86State, xmm_regs[rm]));
        for (int lane = 0; lane < 2; lane++) {
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                             dst_off + lane * YMM_HI_LANE_OFF);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, t0);
            fn(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
        }
        return true;
    }

    if (b == 0xd1 || b == 0xd2 || b == 0xd3 ||
        b == 0xe1 || b == 0xe2 ||
        b == 0xf1 || b == 0xf2 || b == 0xf3) {
        /* Packed shift by an XMM count: the 128-bit count applies to both
         * lanes, so the count operand must NOT advance with the lane. */
        int t0 = offsetof(CPUX86State, xmm_t0);
        if (b1 != 1 || !x86_avx2_enabled(s))
            return false;
        fn = sse_op_table1[b][b1];
        if (!fn || fn == SSE_SPECIAL)
            return false;
        if (mod == 3)
            gen_op_movo(s, t0, offsetof(CPUX86State, xmm_regs[rm]));
        else { gen_lea_modrm(env, s, modrm); gen_ldo_env_A0(s, t0); }
        gen_op_movy(s, op1_offset, offsetof(CPUX86State, xmm_regs[s->vex_v]));
        tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
        tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, t0);
        fn(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
        tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                         op1_offset + YMM_HI_LANE_OFF);
        tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, t0);
        fn(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
        return true;
    }

    if (b == 0xf7)               /* maskmovdqu: scalar store, not lane-wise */
        return false;

    if ((b == 0x5a && (b1 == 0 || b1 == 1)) ||
        (b == 0xe6 && (b1 == 1 || b1 == 2 || b1 == 3))) {
        /* Packed FP width-changing conversions.  Unlike the in-lane packed ops,
         * these gather/scatter ACROSS the two 128-bit lanes, so the generic
         * per-128 path mislays the results:
         *   narrow  cvtpd2ps (66 5a) / cvttpd2dq (66 e6) / cvtpd2dq (f2 e6):
         *           4 f64 in the 256-bit src -> 4 packed (f32/i32) in the dst
         *           LOW 128, dst[255:128] = 0.
         *   widen   cvtps2pd (5a) / cvtdq2pd (f3 e6):
         *           4 packed (f32/i32) in the src LOW 128 -> 4 f64 across both
         *           256-bit dst lanes.
         * The 128-bit helper converts the low TWO elements of its src lane and
         * writes the low 64 bits of its dst lane (zeroing the dst lane's high
         * 64), so we drive it twice with the right source/destination halves.
         * Snapshot src into xmm_t0 first so an in-place dst==src form is safe. */
        bool widen = (b == 0x5a) ? (b1 == 0) : (b1 == 2);
        int t0 = offsetof(CPUX86State, xmm_t0);
        SSEFunc_0_epp cfn = sse_op_table1[b][b1];
        if (!cfn || cfn == SSE_SPECIAL)
            return false;
        if (mod == 3) {
            gen_op_movy(s, t0, offsetof(CPUX86State, xmm_regs[rm]));
        } else {
            gen_lea_modrm(env, s, modrm);
            gen_ldy_env_A0(s, t0);
        }
        if (widen) {
            /* dst high lane <- src elements 2,3 (low128 bytes 8..15). */
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                             op1_offset + YMM_HI_LANE_OFF);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, t0 + 8);
            cfn(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            /* dst low lane <- src elements 0,1. */
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, t0);
            cfn(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
        } else {
            /* narrow: convert each input lane (2 elements) and pack the two
             * low-64 results into the dst low 128, then zero the dst high 128. */
            TCGv_i64 r1 = tcg_temp_new_i64(tcg_ctx);
            TCGv_i64 z = tcg_const_i64(tcg_ctx, 0);
            /* lane0 -> dst.Q0 (helper also zeroes dst.Q1). */
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, t0);
            cfn(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            /* lane1 -> scratch t0.Q4, then move its low 64 into dst.Q1. */
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, t0 + 4 * 8);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                             t0 + YMM_HI_LANE_OFF);
            cfn(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            tcg_gen_ld_i64(tcg_ctx, r1, tcg_ctx->cpu_env,
                           t0 + offsetof(ZMMReg, ZMM_Q(4)));
            tcg_gen_st_i64(tcg_ctx, r1, tcg_ctx->cpu_env,
                           op1_offset + offsetof(ZMMReg, ZMM_Q(1)));
            tcg_gen_st_i64(tcg_ctx, z, tcg_ctx->cpu_env,
                           op1_offset + offsetof(ZMMReg, ZMM_Q(2)));
            tcg_gen_st_i64(tcg_ctx, z, tcg_ctx->cpu_env,
                           op1_offset + offsetof(ZMMReg, ZMM_Q(3)));
            tcg_temp_free_i64(tcg_ctx, r1);
            tcg_temp_free_i64(tcg_ctx, z);
        }
        return true;
    }

    /* Generic in-lane packed arithmetic / logic via sse_op_table1. */
    fn = sse_op_table1[b][b1];
    if (!fn || fn == SSE_SPECIAL)
        return false;
    if (x86_avx2_0f_ymm_opcode(b)) {
        if (b1 != 1 || !x86_avx2_enabled(s))
            return false;
    } else if (b == 0x6e || b == 0x7e || b == 0xd6 || b == 0xe7) {
        /* These scalar/memory-only integer encodings have no YMM form. */
        return false;
    }
    if (mod == 3) {
        op2_offset = offsetof(CPUX86State, xmm_regs[rm]);
    } else {
        op2_offset = offsetof(CPUX86State, xmm_t0);
        gen_lea_modrm(env, s, modrm);
        gen_ldy_env_A0(s, op2_offset);
    }
    if (sse_vex_3op_table1(b))
        gen_sse_vex_merge_src1_ymm(s, reg, &op2_offset);
    gen_sse_epp_ymm(s, fn, op1_offset, op2_offset);
    return true;
}

/* x86 FMA3 (VEX.66.0F38 0x96-0x9F / 0xA6-0xAF / 0xB6-0xBF): fused multiply-add
 * with a SINGLE rounding via float{32,64}_muladd.  The three xmm sources are
 *   OP1 = xmm[reg]   (the dst, which is also a source)
 *   OP2 = xmm[vvvv]
 *   OP3 = xmm[rm] or m32/m64/m128
 * and the opcode high nibble selects the multiply/add permutation
 *   9x = 132 : dst = OP1*OP3 + OP2
 *   Ax = 213 : dst = OP2*OP1 + OP3
 *   Bx = 231 : dst = OP2*OP3 + OP1
 * The low nibble selects scalar(odd)/packed(even) and the sign variant
 * (6 maddsub, 7 msubadd, 8/9 madd, A/B msub, C/D nmadd, E/F nmsub); VEX.W
 * picks f64.
 * Handles VEX.128 and VEX.256: the packed form applies the 128-bit helper to
 * each 128-bit lane; scalar forms are VEX.LIG and stay 128-bit.  Returns true
 * when an FMA opcode was consumed. */
static bool gen_x86_fma(CPUX86State *env, DisasContext *s, int b, int modrm,
                        int reg, int rm, int mod)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int lo = b & 0x0f;
    int hi = b & 0xf0;
    bool alternating = lo == 0x6 || lo == 0x7;
    bool scalar = !alternating && (lo & 1);
    bool is_d = s->vex_w;               /* VEX.W -> f64 (pd/sd) */
    bool is256 = (s->vex_l != 0) && !scalar;    /* packed YMM: two 128-bit lanes */
    int variant;

    /* low nibble: 8/9 madd, a/b msub, c/d nmadd, e/f nmsub.  The helper turns
     * this variant code into softfloat muladd negate flags (bit0=negate addend,
     * bit1=negate product) so the float-status enum stays out of the decoder. */
    if (!(s->cpuid_ext_features & CPUID_EXT_FMA))
        return false;
    switch (lo) {
    case 0x6: variant = 4; break;                    /* maddsub */
    case 0x7: variant = 5; break;                    /* msubadd */
    case 0x8: case 0x9: variant = 0; break;     /* madd:  a*b + c */
    case 0xa: case 0xb: variant = 1; break;     /* msub:  a*b - c */
    case 0xc: case 0xd: variant = 2; break;     /* nmadd: -(a*b) + c */
    case 0xe: case 0xf: variant = 3; break;     /* nmsub: -(a*b) - c */
    default:
        return false;
    }

    int op1 = offsetof(CPUX86State, xmm_regs[reg]);        /* dst, also a src */
    int op2 = offsetof(CPUX86State, xmm_regs[s->vex_v]);   /* vvvv */
    int op3;                                               /* rm or memory */
    if (mod == 3) {
        op3 = offsetof(CPUX86State, xmm_regs[rm | REX_B(s)]);
    } else {
        op3 = offsetof(CPUX86State, xmm_t0);
        gen_lea_modrm(env, s, modrm);
        if (is256) {
            gen_ldy_env_A0(s, op3);
        } else if (!scalar) {
            gen_ldo_env_A0(s, op3);
        } else if (is_d) {
            gen_ldq_env_A0(s, op3 + offsetof(ZMMReg, ZMM_Q(0)));
        } else {
            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0, s->mem_index,
                                MO_LEUL);
            tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                           op3 + offsetof(ZMMReg, ZMM_L(0)));
        }
    }

    int sa, sb, sc;     /* permuted into multiply (sa*sb) + add (sc) order */
    switch (hi) {
    case 0x90: sa = op1; sb = op3; sc = op2; break;     /* 132 */
    case 0xa0: sa = op2; sb = op1; sc = op3; break;     /* 213 */
    case 0xb0: sa = op2; sb = op3; sc = op1; break;     /* 231 */
    default:
        return false;
    }

    TCGv_i32 fl = tcg_const_i32(tcg_ctx, variant);
    /* Apply the 128-bit fma helper to each 128-bit lane: two lanes for the
     * VEX.256 packed form (the high lane lives YMM_HI_LANE_OFF bytes in), one
     * otherwise. */
    for (int lane = 0; lane < (is256 ? 2 : 1); lane++) {
        int lo16 = lane * YMM_HI_LANE_OFF;
        TCGv_ptr pd = tcg_temp_new_ptr(tcg_ctx);
        TCGv_ptr pa = tcg_temp_new_ptr(tcg_ctx);
        TCGv_ptr pb = tcg_temp_new_ptr(tcg_ctx);
        TCGv_ptr pc = tcg_temp_new_ptr(tcg_ctx);
        tcg_gen_addi_ptr(tcg_ctx, pd, tcg_ctx->cpu_env, op1 + lo16);
        tcg_gen_addi_ptr(tcg_ctx, pa, tcg_ctx->cpu_env, sa + lo16);
        tcg_gen_addi_ptr(tcg_ctx, pb, tcg_ctx->cpu_env, sb + lo16);
        tcg_gen_addi_ptr(tcg_ctx, pc, tcg_ctx->cpu_env, sc + lo16);
        if (scalar && is_d) {
            gen_helper_fma_sd(tcg_ctx, tcg_ctx->cpu_env, pd, pa, pb, pc, fl);
        } else if (scalar) {
            gen_helper_fma_ss(tcg_ctx, tcg_ctx->cpu_env, pd, pa, pb, pc, fl);
        } else if (is_d) {
            gen_helper_fma_pd(tcg_ctx, tcg_ctx->cpu_env, pd, pa, pb, pc, fl);
        } else {
            gen_helper_fma_ps(tcg_ctx, tcg_ctx->cpu_env, pd, pa, pb, pc, fl);
        }
        tcg_temp_free_ptr(tcg_ctx, pd);
        tcg_temp_free_ptr(tcg_ctx, pa);
        tcg_temp_free_ptr(tcg_ctx, pb);
        tcg_temp_free_ptr(tcg_ctx, pc);
    }
    tcg_temp_free_i32(tcg_ctx, fl);

    if (!is256) {
        gen_clear_ymmh(s, reg);     /* VEX.128 zeroes dst[255:128] */
    }
    return true;
}

static void gen_sse(CPUX86State *env, DisasContext *s, int b,
                    target_ulong pc_start, int rex_r)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    int b1, op1_offset, op2_offset, is_xmm, val;
    int mmx_write_reg = -1;
    int modrm, mod, rm, reg;
    SSEFunc_0_epp sse_fn_epp;
    SSEFunc_0_eppi sse_fn_eppi;
    SSEFunc_0_ppi sse_fn_ppi;
    SSEFunc_0_eppt sse_fn_eppt;
    MemOp ot;

    b &= 0xff;
    if (s->prefix & PREFIX_DATA)
        b1 = 1;
    else if (s->prefix & PREFIX_REPZ)
        b1 = 2;
    else if (s->prefix & PREFIX_REPNZ)
        b1 = 3;
    else
        b1 = 0;
#ifdef TARGET_X86_64
    if (b == 0x38 && !(s->prefix & PREFIX_VEX)) {
        const int opcode =
            translator_ldub(env->uc->tcg_ctx, env, s->pc);

        if (opcode == 0x8a || opcode == 0x8b) {
            AddressParts address;
            TCGv ea;
            bool stack_segment;
            unsigned int width;

            (void)x86_ldub_code(env, s);
            if (!CODE64(s) ||
                !(s->cpuid_7_1_eax_features & CPUID_7_1_EAX_MOVRS) ||
                (s->prefix & (PREFIX_LOCK | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }

            ot = opcode == 0x8a ? MO_8 : s->dflag;
            width = 1U << ot;
            modrm = x86_ldub_code(env, s);
            if ((modrm >> 6) == 3) {
                goto illegal_op;
            }
            reg = ((modrm >> 3) & 7) | rex_r;
            address = gen_lea_modrm_0(env, s, modrm);
            stack_segment =
                s->override == R_SS ||
                (s->override < 0 && address.def_seg == R_SS);
            ea = gen_lea_modrm_1(s, address);
            gen_lea_v_seg(s, s->aflag, ea, address.def_seg, s->override);
            gen_helper_apx_evex_memory_check(
                tcg_ctx, tcg_ctx->cpu_env, s->A0,
                tcg_const_i32(tcg_ctx, 0), tcg_const_i32(tcg_ctx, 1),
                tcg_const_i32(tcg_ctx, width),
                tcg_const_i32(tcg_ctx,
                              (stack_segment ? APX_MEMORY_SS : 0) |
                                  APX_MEMORY_TUPLE));
            gen_op_ld_v(s, ot, s->T0, s->A0);
            /* MOVRS changes speculative behavior only; Unicorn's observable
             * result and fault model are the corresponding scalar load. */
            gen_op_mov_reg_v(s, ot, reg, s->T0);
            return;
        }
    }
    if (b == 0x38 && (b1 == 2 || b1 == 3) &&
        !(s->prefix & PREFIX_VEX) &&
        translator_ldub(env->uc->tcg_ctx, env, s->pc) == 0xf8) {
        AddressParts address;
        TCGv source;
        TCGv destination;
        bool stack_segment;
        const bool supervisor = b1 == 2;

        (void)x86_ldub_code(env, s);
        if ((s->prefix & PREFIX_LOCK) ||
            !(s->cpuid_7_0_ecx_features & CPUID_7_0_ECX_ENQCMD)) {
            goto illegal_op;
        }
        modrm = x86_ldub_code(env, s);
        if ((modrm & 0xc0) == 0xc0) {
            goto illegal_op;
        }
        reg = ((modrm >> 3) & 7) | rex_r;
        address = gen_lea_modrm_0(env, s, modrm);
        stack_segment =
            s->override == R_SS ||
            (s->override < 0 && address.def_seg == R_SS);
        destination = tcg_temp_new(tcg_ctx);
        source = tcg_temp_new(tcg_ctx);
        tcg_gen_mov_tl(tcg_ctx, source, gen_lea_modrm_1(s, address));
        gen_lea_v_seg(s, s->aflag, source, address.def_seg, s->override);
        tcg_gen_mov_tl(tcg_ctx, source, s->A0);

        if (supervisor && s->cpl != 0) {
            tcg_temp_free(tcg_ctx, source);
            tcg_temp_free(tcg_ctx, destination);
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            return;
        }

        tcg_gen_mov_tl(tcg_ctx, destination, tcg_ctx->cpu_regs[reg]);
        if (s->aflag == MO_32) {
            tcg_gen_ext32u_tl(tcg_ctx, destination, destination);
        } else if (s->aflag == MO_16) {
            tcg_gen_ext16u_tl(tcg_ctx, destination, destination);
        }
        gen_lea_v_seg(s, s->aflag, destination, R_ES, -1);
        tcg_gen_mov_tl(tcg_ctx, destination, s->A0);
        gen_helper_apx_enqueue(
            tcg_ctx, tcg_ctx->cpu_env, source, destination,
            tcg_const_i32(
                tcg_ctx,
                (stack_segment ? APX_ENQUEUE_SOURCE_SS : 0) |
                    (supervisor ? APX_ENQUEUE_SUPERVISOR : 0)));
        tcg_temp_free(tcg_ctx, source);
        tcg_temp_free(tcg_ctx, destination);
        set_cc_op(s, CC_OP_EFLAGS);
        return;
    }
    if (b == 0x38 && b1 == 1 && !(s->prefix & PREFIX_VEX) &&
        translator_ldub(env->uc->tcg_ctx, env, s->pc) == 0x82) {
        AddressParts address;
        TCGv ea;
        TCGv_i64 type;
        bool stack_segment;

        (void)x86_ldub_code(env, s);
        if ((s->prefix & PREFIX_LOCK) ||
            !(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_INVPCID)) {
            goto illegal_op;
        }
        modrm = x86_ldub_code(env, s);
        if ((modrm & 0xc0) == 0xc0) {
            goto illegal_op;
        }
        reg = ((modrm >> 3) & 7) | rex_r;
        address = gen_lea_modrm_0(env, s, modrm);
        stack_segment =
            s->override == R_SS ||
            (s->override < 0 && address.def_seg == R_SS);
        ea = gen_lea_modrm_1(s, address);
        gen_lea_v_seg(s, s->aflag, ea, address.def_seg, s->override);
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            return;
        }
        type = tcg_temp_new_i64(tcg_ctx);
        if (CODE64(s)) {
            tcg_gen_mov_i64(tcg_ctx, type, tcg_ctx->cpu_regs[reg]);
        } else {
            tcg_gen_ext32u_i64(tcg_ctx, type, tcg_ctx->cpu_regs[reg]);
        }
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_apx_invpcid(
            tcg_ctx, tcg_ctx->cpu_env, s->A0, type,
            tcg_const_i32(tcg_ctx,
                          stack_segment ? APX_MEMORY_SS : 0));
        tcg_temp_free_i64(tcg_ctx, type);
        gen_jmp_im(s, s->pc - s->cs_base);
        gen_eob(s);
        return;
    }
#endif
    sse_fn_epp = sse_op_table1[b][b1];
    if (!sse_fn_epp) {
        goto unknown_op;
    }
    if ((b <= 0x5f && b >= 0x10) || b == 0xc6 || b == 0xc2) {
        is_xmm = 1;
    } else {
        if (b1 == 0) {
            /* MMX case */
            is_xmm = 0;
        } else {
            is_xmm = 1;
        }
    }
    /* simple MMX/SSE operation */
    if (s->flags & HF_TS_MASK) {
        gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
        return;
    }
    if (s->flags & HF_EM_MASK) {
    illegal_op:
        gen_illegal_opcode(s);
        return;
    }
    if ((s->prefix & PREFIX_VEX) && b != 0x38 && b != 0x3a &&
        !x86_avx_enabled(s)) {
        goto illegal_op;
    }
    if (is_xmm
        && !(s->flags & HF_OSFXSR_MASK)
        && ((b != 0x38 && b != 0x3a) || (s->prefix & PREFIX_DATA))) {
        goto unknown_op;
    }
    if (b == 0x0e) {
        if (!(s->cpuid_ext2_features & CPUID_EXT2_3DNOW)) {
            /* If we were fully decoding this we might use illegal_op.  */
            goto unknown_op;
        }
        /* femms */
        gen_helper_emms(tcg_ctx, tcg_ctx->cpu_env);
        return;
    }
    if (b == 0x77) {
        if (s->prefix & PREFIX_VEX) {
            if (s->vex_v != 0) {
                goto illegal_op;
            }
            for (reg = 0; reg < CPU_NB_REGS; reg++) {
                if (s->vex_l) {
                    gen_clear_ymm(s, reg);
                } else {
                    gen_clear_ymmh(s, reg);
                }
            }
            return;
        }
        /* emms */
        gen_helper_emms(tcg_ctx, tcg_ctx->cpu_env);
        return;
    }
    /* VEX never selects an MMX operand table.  Packed integer VEX forms use
     * a mandatory prefix; accepting pp=none here would silently execute a
     * legacy MMX helper.  VZEROUPPER/VZEROALL returned above. */
    if ((s->prefix & PREFIX_VEX) && !is_xmm)
        goto illegal_op;
    /* prepare MMX state (XXX: optimize by storing fptt and fptags in
       the static cpu state) */
    if (!is_xmm) {
        gen_helper_enter_mmx(tcg_ctx, tcg_ctx->cpu_env);
    }

    modrm = x86_ldub_code(env, s);
    reg = ((modrm >> 3) & 7);
    if (is_xmm)
        reg |= rex_r;
    mod = (modrm >> 6) & 3;
    /* VEX.L=1 (256-bit, YMM): handled lane-wise by gen_sse_256; anything it
     * does not recognize falls through to #UD. */
    if (s->vex_l != 0) {
        if (gen_sse_256(env, s, b, b1, modrm, reg, rex_r)) {
            return;
        }
        goto illegal_op;
    }
    if (sse_fn_epp == SSE_SPECIAL) {
        b |= (b1 << 8);
        switch(b) {
        case 0x0e7: /* movntq */
            if (mod == 3) {
                goto illegal_op;
            }
            gen_lea_modrm(env, s, modrm);
            gen_stq_env_A0(s, offsetof(CPUX86State, fpregs[reg].mmx));
            break;
        case 0x1e7: /* movntdq */
        case 0x02b: /* movntps */
        case 0x12b: /* movntpd */
            if (mod == 3 ||
                ((s->prefix & PREFIX_VEX) && s->vex_v != 0))
                goto illegal_op;
            gen_lea_modrm(env, s, modrm);
            gen_sto_env_A0_aligned(s,
                                   offsetof(CPUX86State, xmm_regs[reg]));
            break;
        case 0x3f0: /* lddqu */
            if (mod == 3 ||
                ((s->prefix & PREFIX_VEX) && s->vex_v != 0))
                goto illegal_op;
            gen_lea_modrm(env, s, modrm);
            gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            if (s->prefix & PREFIX_VEX)
                gen_clear_ymmh(s, reg);
            break;
        case 0x22b: /* movntss */
        case 0x32b: /* movntsd */
            if (mod == 3)
                goto illegal_op;
            gen_lea_modrm(env, s, modrm);
            if (b1 & 1) {
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State,
                    xmm_regs[reg].ZMM_L(0)));
                gen_op_st_v(s, MO_32, s->T0, s->A0);
            }
            break;
        case 0x6e: /* movd mm, ea */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 0);
                tcg_gen_st_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                              offsetof(CPUX86State, fpregs[reg].mmx));
            } else
#endif
            {
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 0);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State,fpregs[reg].mmx));
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_movl_mm_T0_mmx(tcg_ctx, s->ptr0, s->tmp2_i32);
            }
            mmx_write_reg = reg;
            break;
        case 0x16e: /* movd xmm, ea */
            if ((s->prefix & PREFIX_VEX) &&
                (s->vex_v != 0 || s->vex_l != 0 ||
                 (s->vex_w && !CODE64(s))))
                goto illegal_op;
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 0);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State,xmm_regs[reg]));
                gen_helper_movq_mm_T0_xmm(tcg_ctx, s->ptr0, s->T0);
            } else
#endif
            {
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 0);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State,xmm_regs[reg]));
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_movl_mm_T0_xmm(tcg_ctx, s->ptr0, s->tmp2_i32);
            }
            if (s->prefix & PREFIX_VEX)
                gen_clear_ymmh(s, reg);
            break;
        case 0x6f: /* movq mm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State, fpregs[reg].mmx));
            } else {
                rm = (modrm & 7);
                tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                               offsetof(CPUX86State,fpregs[rm].mmx));
                tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                               offsetof(CPUX86State,fpregs[reg].mmx));
            }
            mmx_write_reg = reg;
            break;
        case 0x010: /* movups */
        case 0x110: /* movupd */
        case 0x26f: /* movdqu xmm, ea */
            if ((s->prefix & PREFIX_VEX) && s->vex_v != 0)
                goto illegal_op;
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movo(s, offsetof(CPUX86State, xmm_regs[reg]),
                            offsetof(CPUX86State,xmm_regs[rm]));
            }
            if (s->prefix & PREFIX_VEX)
                gen_clear_ymmh(s, reg);
            break;
        case 0x028: /* movaps */
        case 0x128: /* movapd */
        case 0x16f: /* movdqa xmm, ea */
            if ((s->prefix & PREFIX_VEX) && s->vex_v != 0)
                goto illegal_op;
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0_aligned(
                    s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movo(s, offsetof(CPUX86State, xmm_regs[reg]),
                            offsetof(CPUX86State,xmm_regs[rm]));
            }
            if (s->prefix & PREFIX_VEX)
                gen_clear_ymmh(s, reg);
            break;
        case 0x210: /* movss xmm, ea */
            if (s->prefix & PREFIX_VEX) {
                if (mod != 3) {
                    if (s->vex_v != 0)
                        goto illegal_op;
                    gen_lea_modrm(env, s, modrm);
                    gen_op_ld_v(s, MO_32, s->T0, s->A0);
                    tcg_gen_st32_tl(
                        tcg_ctx, s->T0, tcg_ctx->cpu_env,
                        offsetof(CPUX86State, xmm_regs[reg].ZMM_L(0)));
                    tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                    for (int i = 1; i < 4; ++i)
                        tcg_gen_st32_tl(
                            tcg_ctx, s->T0, tcg_ctx->cpu_env,
                            offsetof(CPUX86State, xmm_regs[reg].ZMM_L(i)));
                } else {
                    op2_offset = offsetof(
                        CPUX86State, xmm_regs[(modrm & 7) | REX_B(s)]);
                    gen_sse_vex_merge_src1(s, reg, &op2_offset);
                    gen_op_movl(
                        s,
                        offsetof(CPUX86State, xmm_regs[reg].ZMM_L(0)),
                        op2_offset + offsetof(ZMMReg, ZMM_L(0)));
                }
                gen_clear_ymmh(s, reg);
                break;
            }
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, MO_32, s->T0, s->A0);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_L(0)));
                tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_L(1)));
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_L(2)));
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_L(3)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(0)));
            }
            break;
        case 0x310: /* movsd xmm, ea */
            if (s->prefix & PREFIX_VEX) {
                if (mod != 3) {
                    if (s->vex_v != 0)
                        goto illegal_op;
                    gen_lea_modrm(env, s, modrm);
                    gen_ldq_env_A0(
                        s, offsetof(CPUX86State,
                                    xmm_regs[reg].ZMM_Q(0)));
                    gen_op_movq_env_0(
                        s, offsetof(CPUX86State,
                                    xmm_regs[reg].ZMM_Q(1)));
                } else {
                    op2_offset = offsetof(
                        CPUX86State, xmm_regs[(modrm & 7) | REX_B(s)]);
                    gen_sse_vex_merge_src1(s, reg, &op2_offset);
                    gen_op_movq(
                        s,
                        offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(0)),
                        op2_offset + offsetof(ZMMReg, ZMM_Q(0)));
                }
                gen_clear_ymmh(s, reg);
                break;
            }
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
                tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_L(2)));
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_L(3)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            }
            break;
        case 0x012: /* movlps */
        case 0x112: /* movlpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
                if (s->prefix & PREFIX_VEX) {
                    gen_op_movq(
                        s,
                        offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(1)),
                        offsetof(CPUX86State,
                                 xmm_regs[s->vex_v].ZMM_Q(1)));
                    gen_clear_ymmh(s, reg);
                }
            } else {
                /* movhlps / vmovhlps */
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(1)));
                if (s->prefix & PREFIX_VEX) {
                    /* VEX three-operand vmovhlps: dst[127:64] =
                     * src1(vvvv)[127:64], and the 128-bit VEX write zeroes
                     * dst[255:128].  The legacy two-operand movhlps leaves
                     * dst[127:64] untouched, so this VEX merge is required. */
                    gen_op_movq(s,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(1)),
                                offsetof(CPUX86State,
                                         xmm_regs[s->vex_v].ZMM_Q(1)));
                    gen_clear_ymmh(s, reg);
                }
            }
            break;
        case 0x212: /* movsldup */
            if ((s->prefix & PREFIX_VEX) && s->vex_v != 0)
                goto illegal_op;
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0_legacy_sse(
                    s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(0)));
                gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(2)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(2)));
            }
            gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(1)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)));
            gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(3)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_L(2)));
            break;
        case 0x312: /* movddup */
            if ((s->prefix & PREFIX_VEX) && s->vex_v != 0)
                goto illegal_op;
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            }
            gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(1)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)));
            break;
        case 0x016: /* movhps */
        case 0x116: /* movhpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(1)));
                if (s->prefix & PREFIX_VEX) {
                    gen_op_movq(
                        s,
                        offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(0)),
                        offsetof(CPUX86State,
                                 xmm_regs[s->vex_v].ZMM_Q(0)));
                    gen_clear_ymmh(s, reg);
                }
            } else {
                /* movlhps / vmovlhps */
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(1)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
                if (s->prefix & PREFIX_VEX) {
                    /* VEX three-operand vmovlhps: dst[63:0] = src1(vvvv)[63:0],
                     * and the 128-bit VEX write zeroes dst[255:128].  The legacy
                     * two-operand movlhps leaves dst[63:0] untouched, so this
                     * VEX merge is required (without it dst[63:0] keeps stale
                     * data — the bug that silently zeroed packed-vector lanes). */
                    gen_op_movq(s,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(0)),
                                offsetof(CPUX86State,
                                         xmm_regs[s->vex_v].ZMM_Q(0)));
                    gen_clear_ymmh(s, reg);
                }
            }
            break;
        case 0x216: /* movshdup */
            if ((s->prefix & PREFIX_VEX) && s->vex_v != 0)
                goto illegal_op;
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0_legacy_sse(
                    s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(1)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(1)));
                gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(3)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(3)));
            }
            gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(0)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_L(1)));
            gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(2)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_L(3)));
            break;
        case 0x178:
        case 0x378:
            {
                int bit_index, field_length;

                if (b1 == 1 && reg != 0)
                    goto illegal_op;
                field_length = x86_ldub_code(env, s) & 0x3F;
                bit_index = x86_ldub_code(env, s) & 0x3F;
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                    offsetof(CPUX86State,xmm_regs[reg]));
                if (b1 == 1)
                    gen_helper_extrq_i(tcg_ctx, tcg_ctx->cpu_env, s->ptr0,
                                       tcg_const_i32(tcg_ctx, bit_index),
                                       tcg_const_i32(tcg_ctx, field_length));
                else
                    gen_helper_insertq_i(tcg_ctx, tcg_ctx->cpu_env, s->ptr0,
                                         tcg_const_i32(tcg_ctx, bit_index),
                                         tcg_const_i32(tcg_ctx, field_length));
            }
            break;
        case 0x7e: /* movd ea, mm */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                tcg_gen_ld_i64(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                               offsetof(CPUX86State,fpregs[reg].mmx));
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 1);
            } else
#endif
            {
                tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State,fpregs[reg].mmx.MMX_L(0)));
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 1);
            }
            break;
        case 0x17e: /* movd ea, xmm */
            if ((s->prefix & PREFIX_VEX) &&
                (s->vex_v != 0 || s->vex_l != 0 ||
                 (s->vex_w && !CODE64(s))))
                goto illegal_op;
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                tcg_gen_ld_i64(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                               offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)));
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 1);
            } else
#endif
            {
                tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)));
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 1);
            }
            break;
        case 0x27e: /* movq xmm, ea */
            if ((s->prefix & PREFIX_VEX) &&
                (s->vex_v != 0 || s->vex_l != 0))
                goto illegal_op;
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            }
            gen_op_movq_env_0(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(1)));
            if (s->prefix & PREFIX_VEX)
                gen_clear_ymmh(s, reg);
            break;
        case 0x7f: /* movq ea, mm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State, fpregs[reg].mmx));
            } else {
                rm = (modrm & 7);
                gen_op_movq(s, offsetof(CPUX86State, fpregs[rm].mmx),
                            offsetof(CPUX86State,fpregs[reg].mmx));
                mmx_write_reg = rm;
            }
            break;
        case 0x011: /* movups */
        case 0x111: /* movupd */
        case 0x27f: /* movdqu ea, xmm */
            if ((s->prefix & PREFIX_VEX) && s->vex_v != 0)
                goto illegal_op;
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_sto_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movo(s, offsetof(CPUX86State, xmm_regs[rm]),
                            offsetof(CPUX86State,xmm_regs[reg]));
                if (s->prefix & PREFIX_VEX)
                    gen_clear_ymmh(s, rm);
            }
            break;
        case 0x029: /* movaps */
        case 0x129: /* movapd */
        case 0x17f: /* movdqa ea, xmm */
            if ((s->prefix & PREFIX_VEX) && s->vex_v != 0)
                goto illegal_op;
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_sto_env_A0_aligned(
                    s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movo(s, offsetof(CPUX86State, xmm_regs[rm]),
                            offsetof(CPUX86State,xmm_regs[reg]));
                if (s->prefix & PREFIX_VEX)
                    gen_clear_ymmh(s, rm);
            }
            break;
        case 0x211: /* movss ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State, xmm_regs[reg].ZMM_L(0)));
                gen_op_st_v(s, MO_32, s->T0, s->A0);
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(s, offsetof(CPUX86State, xmm_regs[rm].ZMM_L(0)),
                            offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)));
            }
            break;
        case 0x311: /* movsd ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[rm].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)));
            }
            break;
        case 0x013: /* movlps */
        case 0x113: /* movlpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                goto illegal_op;
            }
            break;
        case 0x017: /* movhps */
        case 0x117: /* movhpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(1)));
            } else {
                goto illegal_op;
            }
            break;
        case 0x71: /* shift mm, im */
        case 0x72:
        case 0x73:
        case 0x171: /* shift xmm, im */
        case 0x172:
        case 0x173:
            if (b1 >= 2) {
                goto unknown_op;
            }
            val = x86_ldub_code(env, s);
            if (is_xmm) {
                tcg_gen_movi_tl(tcg_ctx, s->T0, val);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_t0.ZMM_L(0)));
                tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_t0.ZMM_L(1)));
                op1_offset = offsetof(CPUX86State,xmm_t0);
            } else {
                tcg_gen_movi_tl(tcg_ctx, s->T0, val);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, mmx_t0.MMX_L(0)));
                tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, mmx_t0.MMX_L(1)));
                op1_offset = offsetof(CPUX86State,mmx_t0);
            }
            sse_fn_epp = sse_op_table2[((b - 1) & 3) * 8 +
                                       (((modrm >> 3)) & 7)][b1];
            if (!sse_fn_epp) {
                goto unknown_op;
            }
            if (is_xmm) {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
                /* VEX is 3-operand NDD: dst=vvvv, src=rm (the helper shifts in
                   place, so copy src into dst first).  Legacy SSE is 2-operand
                   in place on rm. */
                if (s->prefix & PREFIX_VEX) {
                    int dst_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
                    if (dst_off != op2_offset)
                        gen_op_movo(s, dst_off, op2_offset);
                    op2_offset = dst_off;
                }
            } else {
                rm = (modrm & 7);
                op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
            }
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op2_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op1_offset);
            sse_fn_epp(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            if (!is_xmm)
                mmx_write_reg = rm;
            if (is_xmm && (s->prefix & PREFIX_VEX))
                gen_clear_ymmh(s, s->vex_v); /* VEX.128 zeroes dst[255:128] */
            break;
        case 0x050: /* movmskps */
            if (mod != 3 ||
                ((s->prefix & PREFIX_VEX) && s->vex_v != 0))
                goto illegal_op;
            rm = (modrm & 7) | REX_B(s);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                             offsetof(CPUX86State,xmm_regs[rm]));
            gen_helper_movmskps(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, s->ptr0);
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], s->tmp2_i32);
            break;
        case 0x150: /* movmskpd */
            if (mod != 3 ||
                ((s->prefix & PREFIX_VEX) && s->vex_v != 0))
                goto illegal_op;
            rm = (modrm & 7) | REX_B(s);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                             offsetof(CPUX86State,xmm_regs[rm]));
            gen_helper_movmskpd(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, s->ptr0);
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], s->tmp2_i32);
            break;
        case 0x02a: /* cvtpi2ps */
        case 0x12a: /* cvtpi2pd */
            gen_helper_enter_mmx(tcg_ctx, tcg_ctx->cpu_env);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,mmx_t0);
                gen_ldq_env_A0(s, op2_offset);
            } else {
                rm = (modrm & 7);
                op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
            }
            op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            switch(b >> 8) {
            case 0x0:
                gen_helper_cvtpi2ps(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
                break;
            default:
            case 0x1:
                gen_helper_cvtpi2pd(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
                break;
            }
            break;
        case 0x22a: /* cvtsi2ss */
        case 0x32a: /* cvtsi2sd */
            ot = mo_64_32(s->dflag);
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
            op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            if (ot == MO_32) {
                SSEFunc_0_epi sse_fn_epi = sse_op_table3ai[(b >> 8) & 1];
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                sse_fn_epi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->tmp2_i32);
            } else {
#ifdef TARGET_X86_64
                SSEFunc_0_epl sse_fn_epl = sse_op_table3aq[(b >> 8) & 1];
                sse_fn_epl(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->T0);
#else
                goto illegal_op;
#endif
            }
            break;
        case 0x02c: /* cvttps2pi */
        case 0x12c: /* cvttpd2pi */
        case 0x02d: /* cvtps2pi */
        case 0x12d: /* cvtpd2pi */
            gen_helper_enter_mmx(tcg_ctx, tcg_ctx->cpu_env);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,xmm_t0);
                gen_ldo_env_A0_legacy_sse(s, op2_offset);
            } else {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            }
            op1_offset = offsetof(CPUX86State,fpregs[reg & 7].mmx);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            switch(b) {
            case 0x02c:
                gen_helper_cvttps2pi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
                break;
            case 0x12c:
                gen_helper_cvttpd2pi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
                break;
            case 0x02d:
                gen_helper_cvtps2pi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
                break;
            case 0x12d:
                gen_helper_cvtpd2pi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
                break;
            }
            mmx_write_reg = reg & 7;
            break;
        case 0x22c: /* cvttss2si */
        case 0x32c: /* cvttsd2si */
        case 0x22d: /* cvtss2si */
        case 0x32d: /* cvtsd2si */
            ot = mo_64_32(s->dflag);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                if ((b >> 8) & 1) {
                    gen_ldq_env_A0(s, offsetof(CPUX86State, xmm_t0.ZMM_Q(0)));
                } else {
                    gen_op_ld_v(s, MO_32, s->T0, s->A0);
                    tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                    offsetof(CPUX86State, xmm_t0.ZMM_L(0)));
                }
                op2_offset = offsetof(CPUX86State,xmm_t0);
            } else {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            }
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op2_offset);
            if (ot == MO_32) {
                SSEFunc_i_ep sse_fn_i_ep =
                    sse_op_table3bi[((b >> 7) & 2) | (b & 1)];
                sse_fn_i_ep(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, s->ptr0);
                tcg_gen_extu_i32_tl(tcg_ctx, s->T0, s->tmp2_i32);
            } else {
#ifdef TARGET_X86_64
                SSEFunc_l_ep sse_fn_l_ep =
                    sse_op_table3bq[((b >> 7) & 2) | (b & 1)];
                sse_fn_l_ep(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->ptr0);
#else
                goto illegal_op;
#endif
            }
            gen_op_mov_reg_v(s, ot, reg, s->T0);
            break;
        case 0xc4: /* pinsrw */
        case 0x1c4:
            s->rip_offset = 1;
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            val = x86_ldub_code(env, s);
            if (b1) {
                val &= 7;
                /* VEX vpinsrw is 3-operand: dst = src1(vvvv) with one word
                 * replaced, dst[255:128]=0.  The legacy form keeps the rest of
                 * dst, so only copy src1 (and zero the high lane) under VEX. */
                if (s->prefix & PREFIX_VEX)
                    gen_op_movo(s, offsetof(CPUX86State, xmm_regs[reg]),
                                offsetof(CPUX86State, xmm_regs[s->vex_v]));
                tcg_gen_st16_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State,xmm_regs[reg].ZMM_W(val)));
                if (s->prefix & PREFIX_VEX)
                    gen_clear_ymmh(s, reg);
            } else {
                val &= 3;
                tcg_gen_st16_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State,fpregs[reg].mmx.MMX_W(val)));
                mmx_write_reg = reg;
            }
            break;
        case 0xc5: /* pextrw */
        case 0x1c5:
            if (mod != 3)
                goto illegal_op;
            ot = mo_64_32(s->dflag);
            val = x86_ldub_code(env, s);
            if (b1) {
                val &= 7;
                rm = (modrm & 7) | REX_B(s);
                tcg_gen_ld16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State,xmm_regs[rm].ZMM_W(val)));
            } else {
                val &= 3;
                rm = (modrm & 7);
                tcg_gen_ld16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State,fpregs[rm].mmx.MMX_W(val)));
            }
            reg = ((modrm >> 3) & 7) | rex_r;
            gen_op_mov_reg_v(s, ot, reg, s->T0);
            break;
        case 0x1d6: /* movq ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[rm].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)));
                gen_op_movq_env_0(s,
                                  offsetof(CPUX86State, xmm_regs[rm].ZMM_Q(1)));
            }
            break;
        case 0x2d6: /* movq2dq */
            gen_helper_enter_mmx(tcg_ctx, tcg_ctx->cpu_env);
            rm = (modrm & 7);
            gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(0)),
                        offsetof(CPUX86State,fpregs[rm].mmx));
            gen_op_movq_env_0(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(1)));
            break;
        case 0x3d6: /* movdq2q */
            gen_helper_enter_mmx(tcg_ctx, tcg_ctx->cpu_env);
            rm = (modrm & 7) | REX_B(s);
            gen_op_movq(s, offsetof(CPUX86State, fpregs[reg & 7].mmx),
                        offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            mmx_write_reg = reg & 7;
            break;
        case 0xd7: /* pmovmskb */
        case 0x1d7:
            if (mod != 3)
                goto illegal_op;
            if ((s->prefix & PREFIX_VEX) && s->vex_v != 0)
                goto illegal_op;
            if (b1) {
                rm = (modrm & 7) | REX_B(s);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State, xmm_regs[rm]));
                gen_helper_pmovmskb_xmm(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, s->ptr0);
            } else {
                rm = (modrm & 7);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State, fpregs[rm].mmx));
                gen_helper_pmovmskb_mmx(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, s->ptr0);
            }
            reg = ((modrm >> 3) & 7) | rex_r;
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], s->tmp2_i32);
            break;

        case 0x138:
        case 0x038:
            b = modrm;
            if ((b & 0xf0) == 0xf0) {
                goto do_0f_38_fx;
            }
            /* VEX.128 0f38 uses pp=66 except VTESTPS (pp=none), matching
             * the VEX.256 decoder. */
            if ((s->prefix & PREFIX_VEX) && b1 != 1 && b != 0x0e) {
                goto illegal_op;
            }
            if ((s->prefix & PREFIX_VEX) && !x86_avx_enabled(s)) {
                goto illegal_op;
            }
            modrm = x86_ldub_code(env, s);
            rm = modrm & 7;
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            if (b1 >= 2) {
                goto unknown_op;
            }
            if ((s->prefix & PREFIX_VEX) && b1 == 1 && b == 0x13 &&
                (s->vex_w || s->vex_v != 0)) {
                goto illegal_op;
            }

            /* VTESTPS/PD xmm: the bitwise flag reduction is identical to
               PTEST, with VEX.vvvv reserved and VEX.W required to be zero. */
            if ((s->prefix & PREFIX_VEX) &&
                ((b == 0x0e && b1 == 0) || (b == 0x0f && b1 == 1))) {
                int op1 = offsetof(CPUX86State, xmm_regs[reg]);
                int op2;
                if (s->vex_w || s->vex_v != 0)
                    goto illegal_op;
                if (mod == 3) {
                    op2 = offsetof(CPUX86State, xmm_regs[rm | REX_B(s)]);
                } else {
                    op2 = offsetof(CPUX86State, xmm_t0);
                    gen_lea_modrm(env, s, modrm);
                    gen_ldo_env_A0(s, op2);
                }
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2);
                gen_helper_vtest(tcg_ctx, tcg_ctx->cpu_env, s->ptr0,
                                 s->ptr1,
                                 tcg_const_i32(tcg_ctx,
                                               b == 0x0f ? 64 : 32));
                set_cc_op(s, CC_OP_EFLAGS);
                break;
            }

            /* Legacy/VEX.128 GF2P8MULB.  VEX uses vvvv as src1 and W0. */
            if (b1 == 1 && b == 0xcf &&
                (!(s->prefix & PREFIX_VEX) || !s->vex_w)) {
                TCGv_ptr src2 = tcg_temp_new_ptr(tcg_ctx);
                int dst_off = offsetof(CPUX86State, xmm_regs[reg]);
                int src1_off = (s->prefix & PREFIX_VEX)
                                   ? offsetof(CPUX86State,
                                              xmm_regs[s->vex_v])
                                   : dst_off;
                int src2_off;

                if (!(s->cpuid_7_0_ecx_features & CPUID_7_0_ECX_GFNI)) {
                    tcg_temp_free_ptr(tcg_ctx, src2);
                    goto illegal_op;
                }
                if (mod == 3) {
                    src2_off = offsetof(CPUX86State,
                                        xmm_regs[rm | REX_B(s)]);
                } else {
                    src2_off = offsetof(CPUX86State, xmm_t0);
                    gen_lea_modrm(env, s, modrm);
                    gen_ldo_env_A0_legacy_sse(s, src2_off);
                }
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 dst_off);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                                 src1_off);
                tcg_gen_addi_ptr(tcg_ctx, src2, tcg_ctx->cpu_env,
                                 src2_off);
                gen_helper_gf2p8mulb_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                          s->ptr0, s->ptr1, src2);
                tcg_temp_free_ptr(tcg_ctx, src2);
                if (s->prefix & PREFIX_VEX)
                    gen_clear_ymmh(s, reg);
                break;
            }

            /* SHA-NI two-operand instructions (0f38 c8-cd). */
            if (!(s->prefix & PREFIX_VEX) && b1 == 0 &&
                b >= 0xc8 && b <= 0xcd) {
                int dst_off = offsetof(CPUX86State, xmm_regs[reg]);
                int src_off;

                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_SHA_NI))
                    goto illegal_op;
                if (mod == 3) {
                    src_off = offsetof(CPUX86State,
                                       xmm_regs[rm | REX_B(s)]);
                } else {
                    src_off = offsetof(CPUX86State, xmm_t0);
                    gen_lea_modrm(env, s, modrm);
                    gen_ldo_env_A0_aligned(s, src_off);
                }
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 dst_off);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                                 src_off);
                switch (b) {
                case 0xc8:
                    gen_helper_sha1nexte_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                             s->ptr0, s->ptr1);
                    break;
                case 0xc9:
                    gen_helper_sha1msg1_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                            s->ptr0, s->ptr1);
                    break;
                case 0xca:
                    gen_helper_sha1msg2_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                            s->ptr0, s->ptr1);
                    break;
                case 0xcb:
                    gen_helper_sha256rnds2_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                               s->ptr0, s->ptr1);
                    break;
                case 0xcc:
                    gen_helper_sha256msg1_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                              s->ptr0, s->ptr1);
                    break;
                default:
                    gen_helper_sha256msg2_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                              s->ptr0, s->ptr1);
                    break;
                }
                break;
            }

            /* VPERMILPS/PD xmm, xmm, xmm/m128 (variable control). */
            if ((s->prefix & PREFIX_VEX) && b1 == 1 &&
                (b == 0x0c || b == 0x0d) &&
                !s->vex_w) {
                TCGv_ptr ctrl;
                int data_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
                int ctrl_off;
                int dst_off = offsetof(CPUX86State, xmm_regs[reg]);

                if (mod == 3) {
                    ctrl_off = offsetof(CPUX86State,
                                        xmm_regs[rm | REX_B(s)]);
                } else {
                    ctrl_off = offsetof(CPUX86State, xmm_t0);
                    gen_lea_modrm(env, s, modrm);
                    gen_ldo_env_A0(s, ctrl_off);
                }
                ctrl = tcg_temp_new_ptr(tcg_ctx);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, dst_off);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, data_off);
                tcg_gen_addi_ptr(tcg_ctx, ctrl, tcg_ctx->cpu_env, ctrl_off);
                if (b == 0x0c) {
                    gen_helper_vpermilps_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                             s->ptr0, s->ptr1, ctrl);
                } else {
                    gen_helper_vpermilpd_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                             s->ptr0, s->ptr1, ctrl);
                }
                tcg_temp_free_ptr(tcg_ctx, ctrl);
                gen_clear_ymmh(s, reg);
                break;
            }

            /* AVX2 VSIB gather (0f38 90-93), VEX.128 form. */
            if ((s->prefix & PREFIX_VEX) && b1 == 1 && b >= 0x90 && b <= 0x93) {
                if (gen_vsib_gather(env, s, b, modrm, reg))
                    break;
                goto illegal_op;
            }

            /* VEX.128 masked contiguous load/store shares the 256-bit path so
               fault suppression, staged loads and reserved encodings agree. */
            if ((s->prefix & PREFIX_VEX) && b1 == 1 &&
                (b == 0x8c || b == 0x8e ||
                 (b >= 0x2c && b <= 0x2f))) {
                if (gen_vmaskmov(env, s, b, modrm, reg))
                    break;
                goto illegal_op;
            }

            /* AVX2 per-element variable shift (0f38 45/46/47), VEX.128 form:
               dst[i] = src1[i] SHIFT src2[i] (src1=vvvv, src2=rm/mem).  x86
               does not mask the count -- out-of-range yields 0 (logical) or a
               sign fill (arithmetic).  VEX.W picks the 64-bit (q) form. */
            if ((s->prefix & PREFIX_VEX) && b1 == 1 &&
                (b == 0x45 || b == 0x46 || b == 0x47)) {
                int src_off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
                int dst_off = offsetof(CPUX86State, xmm_regs[reg]);
                int cnt_off;
                bool is_q = s->vex_w;
                bool arith = (b == 0x46);
                bool left = (b == 0x47);
                if (!x86_avx2_enabled(s) || (arith && is_q))
                    goto illegal_op;
                if (mod == 3) {
                    cnt_off = offsetof(CPUX86State, xmm_regs[rm | REX_B(s)]);
                } else {
                    cnt_off = offsetof(CPUX86State, xmm_t0);
                    gen_lea_modrm(env, s, modrm);
                    gen_ldo_env_A0(s, cnt_off);
                }
                if (is_q) {
                    TCGv_i64 v = tcg_temp_new_i64(tcg_ctx);
                    TCGv_i64 c = tcg_temp_new_i64(tcg_ctx);
                    TCGv_i64 r = tcg_temp_new_i64(tcg_ctx);
                    TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);
                    TCGv_i64 lim = tcg_const_i64(tcg_ctx, 64);
                    for (int i = 0; i < 2; i++) {
                        tcg_gen_ld_i64(tcg_ctx, v, tcg_ctx->cpu_env,
                                       src_off + offsetof(ZMMReg, ZMM_Q(i)));
                        tcg_gen_ld_i64(tcg_ctx, c, tcg_ctx->cpu_env,
                                       cnt_off + offsetof(ZMMReg, ZMM_Q(i)));
                        if (left)
                            tcg_gen_shl_i64(tcg_ctx, r, v, c);
                        else
                            tcg_gen_shr_i64(tcg_ctx, r, v, c);
                        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, r, c, lim,
                                            r, zero);
                        tcg_gen_st_i64(tcg_ctx, r, tcg_ctx->cpu_env,
                                       dst_off + offsetof(ZMMReg, ZMM_Q(i)));
                    }
                    tcg_temp_free_i64(tcg_ctx, v);
                    tcg_temp_free_i64(tcg_ctx, c);
                    tcg_temp_free_i64(tcg_ctx, r);
                    tcg_temp_free_i64(tcg_ctx, zero);
                    tcg_temp_free_i64(tcg_ctx, lim);
                } else {
                    TCGv_i32 v = tcg_temp_new_i32(tcg_ctx);
                    TCGv_i32 c = tcg_temp_new_i32(tcg_ctx);
                    TCGv_i32 r = tcg_temp_new_i32(tcg_ctx);
                    TCGv_i32 zero = tcg_const_i32(tcg_ctx, 0);
                    TCGv_i32 lim = tcg_const_i32(tcg_ctx, 32);
                    TCGv_i32 maxsh = tcg_const_i32(tcg_ctx, 31);
                    for (int i = 0; i < 4; i++) {
                        tcg_gen_ld_i32(tcg_ctx, v, tcg_ctx->cpu_env,
                                       src_off + offsetof(ZMMReg, ZMM_L(i)));
                        tcg_gen_ld_i32(tcg_ctx, c, tcg_ctx->cpu_env,
                                       cnt_off + offsetof(ZMMReg, ZMM_L(i)));
                        if (arith) {
                            tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LTU, c, c, lim,
                                                c, maxsh);
                            tcg_gen_sar_i32(tcg_ctx, r, v, c);
                        } else if (left) {
                            tcg_gen_shl_i32(tcg_ctx, r, v, c);
                            tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LTU, r, c, lim,
                                                r, zero);
                        } else {
                            tcg_gen_shr_i32(tcg_ctx, r, v, c);
                            tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LTU, r, c, lim,
                                                r, zero);
                        }
                        tcg_gen_st_i32(tcg_ctx, r, tcg_ctx->cpu_env,
                                       dst_off + offsetof(ZMMReg, ZMM_L(i)));
                    }
                    tcg_temp_free_i32(tcg_ctx, v);
                    tcg_temp_free_i32(tcg_ctx, c);
                    tcg_temp_free_i32(tcg_ctx, r);
                    tcg_temp_free_i32(tcg_ctx, zero);
                    tcg_temp_free_i32(tcg_ctx, lim);
                    tcg_temp_free_i32(tcg_ctx, maxsh);
                }
                gen_clear_ymmh(s, reg); /* VEX.128 zeroes dst[255:128] */
                break;
            }

            /* VEX element broadcasts (no SSE equivalent, hence absent from the
               op table): replicate src element 0 across every dst lane. */
            if ((s->prefix & PREFIX_VEX) && b1 && !s->vex_w) {
                int bsz = 0;
                switch (b) {
                case 0x18: case 0x58: bsz = 4; break; /* vbroadcastss/vpbroadcastd */
                case 0x59:            bsz = 8; break; /* vpbroadcastq */
                case 0x78:            bsz = 1; break; /* vpbroadcastb */
                case 0x79:            bsz = 2; break; /* vpbroadcastw */
                }
                if (bsz) {
                    int doff = offsetof(CPUX86State, xmm_regs[reg]);
                    int soff = offsetof(CPUX86State, xmm_regs[rm | REX_B(s)]);
                    if (s->vex_v != 0 ||
                        (b >= 0x58 && !x86_avx2_enabled(s)) ||
                        (b == 0x18 && mod == 3 && !x86_avx2_enabled(s)))
                        goto illegal_op;
                    if (mod != 3)
                        gen_lea_modrm(env, s, modrm);
                    if (bsz == 8) {
                        if (mod == 3)
                            tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                                           soff + offsetof(ZMMReg, ZMM_Q(0)));
                        else
                            tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                        for (int i = 0; i < 2; i++)
                            tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                                           doff + offsetof(ZMMReg, ZMM_Q(i)));
                    } else if (bsz == 4) {
                        if (mod == 3)
                            tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                           soff + offsetof(ZMMReg, ZMM_L(0)));
                        else
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                        for (int i = 0; i < 4; i++)
                            tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                           doff + offsetof(ZMMReg, ZMM_L(i)));
                    } else if (bsz == 2) {
                        if (mod == 3)
                            tcg_gen_ld16u_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_env,
                                             soff + offsetof(ZMMReg, ZMM_W(0)));
                        else
                            tcg_gen_qemu_ld_tl(tcg_ctx, s->tmp0, s->A0,
                                               s->mem_index, MO_LEUW);
                        for (int i = 0; i < 8; i++)
                            tcg_gen_st16_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_env,
                                            doff + offsetof(ZMMReg, ZMM_W(i)));
                    } else {
                        if (mod == 3)
                            tcg_gen_ld8u_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_env,
                                            soff + offsetof(ZMMReg, ZMM_B(0)));
                        else
                            tcg_gen_qemu_ld_tl(tcg_ctx, s->tmp0, s->A0,
                                               s->mem_index, MO_UB);
                        for (int i = 0; i < 16; i++)
                            tcg_gen_st8_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_env,
                                           doff + offsetof(ZMMReg, ZMM_B(i)));
                    }
                    gen_clear_ymmh(s, reg);
                    break;
                }
            }

            /* FMA3 (VEX.66.0f38): 3-source fused multiply-add, single round.
             * These opcodes have no two-operand SSE table entry, so handle
             * them before the table lookup would reject them. */
            if ((s->prefix & PREFIX_VEX) && b1 == 1 &&
                ((b >= 0x96 && b <= 0x9f) || (b >= 0xa6 && b <= 0xaf) ||
                 (b >= 0xb6 && b <= 0xbf))) {
                if (gen_x86_fma(env, s, b, modrm, reg, rm, mod)) {
                    break;
                }
            }

            sse_fn_epp = sse_op_table6[b].op[b1];
            if (!sse_fn_epp) {
                goto unknown_op;
            }
            if (!(s->cpuid_ext_features & sse_op_table6[b].ext_mask))
                goto illegal_op;

            if (b1) {
                op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
                if (mod == 3) {
                    op2_offset = offsetof(CPUX86State,xmm_regs[rm | REX_B(s)]);
                } else {
                    op2_offset = offsetof(CPUX86State,xmm_t0);
                    gen_lea_modrm(env, s, modrm);
                    switch (b) {
                    case 0x13: /* vcvtph2ps: four packed halves in the low 64b */
                    case 0x20: case 0x30: /* pmovsxbw, pmovzxbw */
                    case 0x23: case 0x33: /* pmovsxwd, pmovzxwd */
                    case 0x25: case 0x35: /* pmovsxdq, pmovzxdq */
                        gen_ldq_env_A0(s, op2_offset +
                                        offsetof(ZMMReg, ZMM_Q(0)));
                        break;
                    case 0x21: case 0x31: /* pmovsxbd, pmovzxbd */
                    case 0x24: case 0x34: /* pmovsxwq, pmovzxwq */
                        tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                            s->mem_index, MO_LEUL);
                        tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, op2_offset +
                                        offsetof(ZMMReg, ZMM_L(0)));
                        break;
                    case 0x22: case 0x32: /* pmovsxbq, pmovzxbq */
                        tcg_gen_qemu_ld_tl(tcg_ctx, s->tmp0, s->A0,
                                           s->mem_index, MO_LEUW);
                        tcg_gen_st16_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_env, op2_offset +
                                        offsetof(ZMMReg, ZMM_W(0)));
                        break;
                    case 0x2a:            /* movntqda */
                        if ((s->prefix & PREFIX_VEX) &&
                            (s->vex_v != 0 || !x86_avx2_enabled(s)))
                            goto illegal_op;
                        gen_ldo_env_A0_aligned(s, op1_offset);
                        if (s->prefix & PREFIX_VEX) {
                            gen_clear_ymmh(s, reg);
                        }
                        return;
                    default:
                        gen_ldo_env_A0_legacy_sse(s, op2_offset);
                    }
                }
            } else {
                op1_offset = offsetof(CPUX86State,fpregs[reg].mmx);
                if (mod == 3) {
                    op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
                } else {
                    op2_offset = offsetof(CPUX86State,mmx_t0);
                    gen_lea_modrm(env, s, modrm);
                    gen_ldq_env_A0(s, op2_offset);
                }
            }
            if (sse_fn_epp == SSE_SPECIAL) {
                goto unknown_op;
            }

            if ((s->prefix & PREFIX_VEX) && b1 && sse_vex_3op_table6(b)) {
                gen_sse_vex_merge_src1(s, reg, &op2_offset);
            }
            if (!b1) {
                gen_helper_enter_mmx(tcg_ctx, tcg_ctx->cpu_env);
            }
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            sse_fn_epp(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            if (!b1)
                mmx_write_reg = reg;

            if (b == 0x17) {
                set_cc_op(s, CC_OP_EFLAGS);
            }
            if ((s->prefix & PREFIX_VEX) && b1 && b != 0x17) {
                gen_clear_ymmh(s, reg);
            }
            break;

        case 0x238:
        case 0x338:
        do_0f_38_fx:
            /* Various integer extensions at 0f 38 f[0-f].  */
            b = modrm | (b1 << 8);
            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;

            switch (b) {
            case 0x3f0: /* crc32 Gd,Eb */
            case 0x3f1: /* crc32 Gd,Ey */
            do_crc32:
                if (!(s->cpuid_ext_features & CPUID_EXT_SSE42)) {
                    goto illegal_op;
                }
                if ((b & 0xff) == 0xf0) {
                    ot = MO_8;
                } else {
                    ot = s->dflag;
                }

                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[reg]);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                gen_helper_crc32(tcg_ctx, s->T0, s->tmp2_i32,
                                 s->T0, tcg_const_i32(tcg_ctx, 8 << ot));

                ot = mo_64_32(s->dflag);
                gen_op_mov_reg_v(s, ot, reg, s->T0);
                break;

            case 0x1f0: /* crc32 or movbe */
            case 0x1f1:
                /* For these insns, the f3 prefix is supposed to have priority
                   over the 66 prefix, but that's not what we implement above
                   setting b1.  */
                if (s->prefix & PREFIX_REPNZ) {
                    goto do_crc32;
                }
                /* FALLTHRU */
            case 0x0f0: /* movbe Gy,My */
            case 0x0f1: /* movbe My,Gy */
                if (!(s->cpuid_ext_features & CPUID_EXT_MOVBE)) {
                    goto illegal_op;
                }
                if ((modrm & 0xc0) == 0xc0) {
                    goto illegal_op;
                }
                ot = s->dflag;

                gen_lea_modrm(env, s, modrm);
                if ((b & 1) == 0) {
                    tcg_gen_qemu_ld_tl(tcg_ctx, s->T0, s->A0,
                                       s->mem_index, ot | MO_BE);
                    gen_op_mov_reg_v(s, ot, reg, s->T0);
                } else {
                    tcg_gen_qemu_st_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], s->A0,
                                       s->mem_index, ot | MO_BE);
                }
                break;

            case 0x0f2: /* andn Gy, By, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI1)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                tcg_gen_andc_tl(tcg_ctx, s->T0, s->T0, tcg_ctx->cpu_regs[s->vex_v]);
                gen_op_mov_reg_v(s, ot, reg, s->T0);
                gen_op_update1_cc(s);
                set_cc_op(s, CC_OP_LOGICB + ot);
                break;

            case 0x0f7: /* bextr Gy, Ey, By */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI1)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                {
                    TCGv bound, zero;

                    gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                    /* Extract START, and shift the operand.
                       Shifts larger than operand size get zeros.  */
                    tcg_gen_ext8u_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[s->vex_v]);
                    tcg_gen_shr_tl(tcg_ctx, s->T0, s->T0, s->A0);

                    bound = tcg_const_tl(tcg_ctx, ot == MO_64 ? 63 : 31);
                    zero = tcg_const_tl(tcg_ctx, 0);
                    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_LEU, s->T0, s->A0, bound,
                                       s->T0, zero);

                    /* Extract the LEN into a mask.  Lengths >= the operand size
                       select all ones (extract everything from START upward).
                       Clamp LEN to keep the shift well-defined, then restore the
                       all-ones mask instead of wrongly dropping the top bit. */
                    tcg_gen_extract_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[s->vex_v], 8, 8);
                    {
                        TCGv lenover = tcg_temp_new(tcg_ctx);
                        TCGv allones = tcg_const_tl(tcg_ctx, -1);
                        tcg_gen_setcond_tl(tcg_ctx, TCG_COND_GTU, lenover, s->A0,
                                           bound);
                        tcg_gen_movcond_tl(tcg_ctx, TCG_COND_LEU, s->A0, s->A0,
                                           bound, s->A0, bound);
                        tcg_gen_movi_tl(tcg_ctx, s->T1, 1);
                        tcg_gen_shl_tl(tcg_ctx, s->T1, s->T1, s->A0);
                        tcg_gen_subi_tl(tcg_ctx, s->T1, s->T1, 1);
                        tcg_gen_movcond_tl(tcg_ctx, TCG_COND_NE, s->T1, lenover,
                                           zero, allones, s->T1);
                        tcg_temp_free(tcg_ctx, allones);
                        tcg_temp_free(tcg_ctx, lenover);
                    }
                    tcg_temp_free(tcg_ctx, bound);
                    tcg_temp_free(tcg_ctx, zero);
                    tcg_gen_and_tl(tcg_ctx, s->T0, s->T0, s->T1);

                    gen_op_mov_reg_v(s, ot, reg, s->T0);
                    gen_op_update1_cc(s);
                    set_cc_op(s, CC_OP_LOGICB + ot);
                }
                break;

            case 0x0f5: /* bzhi Gy, Ey, By */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                tcg_gen_ext8u_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v]);
                {
                    TCGv bound = tcg_const_tl(tcg_ctx, ot == MO_64 ? 63 : 31);
                    TCGv zero = tcg_const_tl(tcg_ctx, 0);
                    TCGv over = tcg_temp_new(tcg_ctx);
                    /* BZHI clears bits [OperandSize-1:N] only when N < OperandSize;
                       when N >= OperandSize it leaves the source unchanged and sets
                       CF.  Since we use BMILG (to get OF cleared) we store CF's
                       inverse (N <= bound, i.e. N < OperandSize) into cc_src. */
                    tcg_gen_setcond_tl(tcg_ctx, TCG_COND_LE, tcg_ctx->cpu_cc_src,
                                       s->T1, bound);
                    /* over = (N > bound): index reaches/exceeds the operand width. */
                    tcg_gen_setcond_tl(tcg_ctx, TCG_COND_GT, over, s->T1, bound);
                    /* Clamp the shift to keep it well-defined, build the high-bit
                       clear-mask -1<<N, then force it to 0 when N exceeds the width
                       (clearing nothing) instead of wrongly clearing the top bit. */
                    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_GT, s->T1, s->T1,
                                       bound, bound, s->T1);
                    tcg_gen_movi_tl(tcg_ctx, s->A0, -1);
                    tcg_gen_shl_tl(tcg_ctx, s->A0, s->A0, s->T1);
                    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_NE, s->A0, over, zero,
                                       zero, s->A0);
                    tcg_gen_andc_tl(tcg_ctx, s->T0, s->T0, s->A0);
                    tcg_temp_free(tcg_ctx, over);
                    tcg_temp_free(tcg_ctx, zero);
                    tcg_temp_free(tcg_ctx, bound);
                }
                gen_op_mov_reg_v(s, ot, reg, s->T0);
                gen_op_update1_cc(s);
                set_cc_op(s, CC_OP_BMILGB + ot);
                break;

            case 0x3f6: /* mulx By, Gy, rdx, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                switch (ot) {
                default:
                    tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                    tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, tcg_ctx->cpu_regs[R_EDX]);
                    tcg_gen_mulu2_i32(tcg_ctx, s->tmp2_i32, s->tmp3_i32,
                                      s->tmp2_i32, s->tmp3_i32);
                    tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[s->vex_v], s->tmp2_i32);
                    tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], s->tmp3_i32);
                    break;
#ifdef TARGET_X86_64
                case MO_64:
                    tcg_gen_mulu2_i64(tcg_ctx, s->T0, s->T1,
                                      s->T0, tcg_ctx->cpu_regs[R_EDX]);
                    tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_regs[s->vex_v], s->T0);
                    tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_regs[reg], s->T1);
                    break;
#endif
                }
                break;

            case 0x3f5: /* pdep Gy, By, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                if (ot == MO_64) {
                    tcg_gen_mov_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v]);
                } else {
                    /* Keep the helper within the 32-bit operand size. */
                    tcg_gen_ext32u_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v]);
                    tcg_gen_ext32u_tl(tcg_ctx, s->T0, s->T0);
                }
                gen_helper_pdep(tcg_ctx, tcg_ctx->cpu_regs[reg], s->T1, s->T0);
                break;

            case 0x2f5: /* pext Gy, By, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                /* Note that by zero-extending the source operand, we
                   automatically handle zero-extending the result.  */
                if (ot == MO_64) {
                    tcg_gen_mov_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v]);
                } else {
                    tcg_gen_ext32u_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v]);
                }
                gen_helper_pext(tcg_ctx, tcg_ctx->cpu_regs[reg], s->T1, s->T0);
                break;

            case 0x1f6: /* adcx Gy, Ey */
            case 0x2f6: /* adox Gy, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_ADX)) {
                    goto illegal_op;
                } else {
                    TCGv carry_in, carry_out, zero;
                    int end_op;

                    ot = mo_64_32(s->dflag);
                    gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);

                    /* Re-use the carry-out from a previous round.  */
                    carry_in = NULL;
                    carry_out = (b == 0x1f6 ? tcg_ctx->cpu_cc_dst : tcg_ctx->cpu_cc_src2);
                    switch (s->cc_op) {
                    case CC_OP_ADCX:
                        if (b == 0x1f6) {
                            carry_in = tcg_ctx->cpu_cc_dst;
                            end_op = CC_OP_ADCX;
                        } else {
                            end_op = CC_OP_ADCOX;
                        }
                        break;
                    case CC_OP_ADOX:
                        if (b == 0x1f6) {
                            end_op = CC_OP_ADCOX;
                        } else {
                            carry_in = tcg_ctx->cpu_cc_src2;
                            end_op = CC_OP_ADOX;
                        }
                        break;
                    case CC_OP_ADCOX:
                        end_op = CC_OP_ADCOX;
                        carry_in = carry_out;
                        break;
                    default:
                        end_op = (b == 0x1f6 ? CC_OP_ADCX : CC_OP_ADOX);
                        break;
                    }
                    /* If we can't reuse carry-out, get it out of EFLAGS.  */
                    if (!carry_in) {
                        if (s->cc_op != CC_OP_ADCX && s->cc_op != CC_OP_ADOX) {
                            gen_mov_eflags(s, tcg_ctx->cpu_cc_src);
                            set_cc_op(s, CC_OP_EFLAGS);
                        }
                        carry_in = s->tmp0;
                        tcg_gen_extract_tl(tcg_ctx, carry_in, tcg_ctx->cpu_cc_src,
                                           ctz32(b == 0x1f6 ? CC_C : CC_O), 1);
                    }

                    switch (ot) {
#ifdef TARGET_X86_64
                    case MO_32:
                        /* If we know TL is 64-bit, and we want a 32-bit
                           result, just do everything in 64-bit arithmetic.  */
                        tcg_gen_ext32u_i64(tcg_ctx, tcg_ctx->cpu_regs[reg], tcg_ctx->cpu_regs[reg]);
                        tcg_gen_ext32u_i64(tcg_ctx, s->T0, s->T0);
                        tcg_gen_add_i64(tcg_ctx, s->T0, s->T0, tcg_ctx->cpu_regs[reg]);
                        tcg_gen_add_i64(tcg_ctx, s->T0, s->T0, carry_in);
                        tcg_gen_ext32u_i64(tcg_ctx, tcg_ctx->cpu_regs[reg], s->T0);
                        tcg_gen_shri_i64(tcg_ctx, carry_out, s->T0, 32);
                        break;
#endif
                    default:
                        /* Otherwise compute the carry-out in two steps.  */
                        zero = tcg_const_tl(tcg_ctx, 0);
                        tcg_gen_add2_tl(tcg_ctx, s->T0, carry_out,
                                        s->T0, zero,
                                        carry_in, zero);
                        tcg_gen_add2_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], carry_out,
                                        tcg_ctx->cpu_regs[reg], carry_out,
                                        s->T0, zero);
                        tcg_temp_free(tcg_ctx, zero);
                        break;
                    }
                    set_cc_op(s, end_op);
                }
                break;

            case 0x1f7: /* shlx Gy, Ey, By */
            case 0x2f7: /* sarx Gy, Ey, By */
            case 0x3f7: /* shrx Gy, Ey, By */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                if (ot == MO_64) {
                    tcg_gen_andi_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v], 63);
                } else {
                    tcg_gen_andi_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v], 31);
                }
                if (b == 0x1f7) {
                    tcg_gen_shl_tl(tcg_ctx, s->T0, s->T0, s->T1);
                } else if (b == 0x2f7) {
                    if (ot != MO_64) {
                        tcg_gen_ext32s_tl(tcg_ctx, s->T0, s->T0);
                    }
                    tcg_gen_sar_tl(tcg_ctx, s->T0, s->T0, s->T1);
                } else {
                    if (ot != MO_64) {
                        tcg_gen_ext32u_tl(tcg_ctx, s->T0, s->T0);
                    }
                    tcg_gen_shr_tl(tcg_ctx, s->T0, s->T0, s->T1);
                }
                gen_op_mov_reg_v(s, ot, reg, s->T0);
                break;

            case 0x0f3:
            case 0x1f3:
            case 0x2f3:
            case 0x3f3: /* Group 17 */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI1)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);

                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0);
                switch (reg & 7) {
                case 1: /* blsr By,Ey */
                    tcg_gen_subi_tl(tcg_ctx, s->T1, s->T0, 1);
                    tcg_gen_and_tl(tcg_ctx, s->T0, s->T0, s->T1);
                    break;
                case 2: /* blsmsk By,Ey */
                    tcg_gen_subi_tl(tcg_ctx, s->T1, s->T0, 1);
                    tcg_gen_xor_tl(tcg_ctx, s->T0, s->T0, s->T1);
                    break;
                case 3: /* blsi By, Ey */
                    /* BLSI sets CF when the source is NON-zero, the OPPOSITE of
                       BLSR/BLSMSK.  BMILG yields CF = (cc_src == 0) over the
                       operand size, so overwrite cc_src (set to the raw source
                       above) with the inverse indicator (src == 0): then
                       CF = ((src==0) == 0) = (src != 0), per the Intel SDM. */
                    {
                        TCGv blsi_srcz =
                            gen_ext_tl(tcg_ctx, s->T1, s->T0, ot, false);
                        tcg_gen_setcondi_tl(tcg_ctx, TCG_COND_EQ,
                                            tcg_ctx->cpu_cc_src, blsi_srcz, 0);
                    }
                    tcg_gen_neg_tl(tcg_ctx, s->T1, s->T0);
                    tcg_gen_and_tl(tcg_ctx, s->T0, s->T0, s->T1);
                    break;
                default:
                    goto unknown_op;
                }
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                gen_op_mov_reg_v(s, ot, s->vex_v, s->T0);
                set_cc_op(s, CC_OP_BMILGB + ot);
                break;

            default:
                goto unknown_op;
            }
            break;

        case 0x03a:
        case 0x13a:
            b = modrm;
            /* All vector instructions in the 0f3a map use pp=66.  The F2
             * BMI2 RORX encoding is dispatched through case 0x33a below. */
            if ((s->prefix & PREFIX_VEX) && b1 != 1) {
                goto illegal_op;
            }
            if ((s->prefix & PREFIX_VEX) && !x86_avx_enabled(s)) {
                goto illegal_op;
            }
            modrm = x86_ldub_code(env, s);
            rm = modrm & 7;
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            if (b1 >= 2) {
                goto unknown_op;
            }
            if ((s->prefix & PREFIX_VEX) && b1 == 1 && b == 0x1d &&
                (s->vex_w || s->vex_v != 0)) {
                goto illegal_op;
            }

            if ((s->prefix & PREFIX_VEX) && b1 == 1 &&
                (b == 0x04 || b == 0x05)) {
                int dst = offsetof(CPUX86State, xmm_regs[reg]);
                int src;
                if (s->vex_w || s->vex_v != 0)
                    goto illegal_op;
                if (mod == 3) {
                    src = offsetof(CPUX86State, xmm_regs[rm | REX_B(s)]);
                } else {
                    src = offsetof(CPUX86State, xmm_t0);
                    s->rip_offset = 1;
                    gen_lea_modrm(env, s, modrm);
                    gen_ldo_env_A0(s, src);
                }
                val = x86_ldub_code(env, s);
                if (b == 0x04) {
                    TCGv_i32 d[4];
                    for (int i = 0; i < 4; i++) {
                        d[i] = tcg_temp_new_i32(tcg_ctx);
                        tcg_gen_ld_i32(tcg_ctx, d[i], tcg_ctx->cpu_env,
                                       src + offsetof(ZMMReg, ZMM_L(i)));
                    }
                    for (int i = 0; i < 4; i++) {
                        int sel = (val >> (2 * i)) & 3;
                        tcg_gen_st_i32(tcg_ctx, d[sel], tcg_ctx->cpu_env,
                                       dst + offsetof(ZMMReg, ZMM_L(i)));
                    }
                    for (int i = 0; i < 4; i++)
                        tcg_temp_free_i32(tcg_ctx, d[i]);
                } else {
                    TCGv_i64 q[2];
                    for (int i = 0; i < 2; i++) {
                        q[i] = tcg_temp_new_i64(tcg_ctx);
                        tcg_gen_ld_i64(tcg_ctx, q[i], tcg_ctx->cpu_env,
                                       src + offsetof(ZMMReg, ZMM_Q(i)));
                    }
                    for (int i = 0; i < 2; i++) {
                        int sel = (val >> i) & 1;
                        tcg_gen_st_i64(tcg_ctx, q[sel], tcg_ctx->cpu_env,
                                       dst + offsetof(ZMMReg, ZMM_Q(i)));
                    }
                    tcg_temp_free_i64(tcg_ctx, q[0]);
                    tcg_temp_free_i64(tcg_ctx, q[1]);
                }
                gen_clear_ymmh(s, reg);
                break;
            }

            /* Legacy/VEX.128 GF2P8AFFINE{,INV}QB.  VEX requires W1. */
            if (b1 == 1 && (b == 0xce || b == 0xcf) &&
                (!(s->prefix & PREFIX_VEX) || s->vex_w)) {
                TCGv_ptr matrix = tcg_temp_new_ptr(tcg_ctx);
                TCGv_i32 imm;
                int dst_off = offsetof(CPUX86State, xmm_regs[reg]);
                int x_off = (s->prefix & PREFIX_VEX)
                                ? offsetof(CPUX86State,
                                           xmm_regs[s->vex_v])
                                : dst_off;
                int matrix_off;

                if (!(s->cpuid_7_0_ecx_features & CPUID_7_0_ECX_GFNI)) {
                    tcg_temp_free_ptr(tcg_ctx, matrix);
                    goto illegal_op;
                }
                if (mod == 3) {
                    matrix_off = offsetof(CPUX86State,
                                          xmm_regs[rm | REX_B(s)]);
                } else {
                    matrix_off = offsetof(CPUX86State, xmm_t0);
                    s->rip_offset = 1;
                    gen_lea_modrm(env, s, modrm);
                    gen_ldo_env_A0_legacy_sse(s, matrix_off);
                }
                val = x86_ldub_code(env, s);
                imm = tcg_const_i32(tcg_ctx, val);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 dst_off);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                                 x_off);
                tcg_gen_addi_ptr(tcg_ctx, matrix, tcg_ctx->cpu_env,
                                 matrix_off);
                if (b == 0xce) {
                    gen_helper_gf2p8affineqb_xmm(
                        tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1, matrix,
                        imm);
                } else {
                    gen_helper_gf2p8affineinvqb_xmm(
                        tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1, matrix,
                        imm);
                }
                tcg_temp_free_i32(tcg_ctx, imm);
                tcg_temp_free_ptr(tcg_ctx, matrix);
                if (s->prefix & PREFIX_VEX)
                    gen_clear_ymmh(s, reg);
                break;
            }

            /* SHA1RNDS4 xmm, xmm/m128, imm8. */
            if (!(s->prefix & PREFIX_VEX) && b1 == 0 && b == 0xcc) {
                int dst_off = offsetof(CPUX86State, xmm_regs[reg]);
                int src_off;

                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_SHA_NI))
                    goto illegal_op;
                if (mod == 3) {
                    src_off = offsetof(CPUX86State,
                                       xmm_regs[rm | REX_B(s)]);
                } else {
                    src_off = offsetof(CPUX86State, xmm_t0);
                    s->rip_offset = 1;
                    gen_lea_modrm(env, s, modrm);
                    gen_ldo_env_A0_aligned(s, src_off);
                }
                val = x86_ldub_code(env, s);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 dst_off);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                                 src_off);
                switch (val & 3) {
                case 0:
                    gen_helper_sha1rnds4_f0_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                                 s->ptr0, s->ptr1);
                    break;
                case 1:
                    gen_helper_sha1rnds4_f1_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                                 s->ptr0, s->ptr1);
                    break;
                case 2:
                    gen_helper_sha1rnds4_f2_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                                 s->ptr0, s->ptr1);
                    break;
                default:
                    gen_helper_sha1rnds4_f3_xmm(tcg_ctx, tcg_ctx->cpu_env,
                                                 s->ptr0, s->ptr1);
                    break;
                }
                break;
            }

            /* VEX AVX2 vpblendd (no SSE equivalent): per-dword immediate blend,
               non-destructive (dst, src1=vvvv, src2, imm). */
            if ((s->prefix & PREFIX_VEX) && b1 && b == 0x02) {
                int doff = offsetof(CPUX86State, xmm_regs[reg]);
                int s1off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
                int s2off;
                if (s->vex_w || !x86_avx2_enabled(s))
                    goto illegal_op;
                if (mod == 3) {
                    s2off = offsetof(CPUX86State, xmm_regs[rm | REX_B(s)]);
                } else {
                    s->rip_offset = 1;
                    gen_lea_modrm(env, s, modrm);
                    gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_t0));
                    s2off = offsetof(CPUX86State, xmm_t0);
                }
                val = x86_ldub_code(env, s);
                for (int i = 0; i < 4; i++) {
                    int from = (val & (1 << i)) ? s2off : s1off;
                    tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                   from + offsetof(ZMMReg, ZMM_L(i)));
                    tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                   doff + offsetof(ZMMReg, ZMM_L(i)));
                }
                break;
            }

            /* VEX variable blend vblendvps/vblendvpd/vpblendvb (4-operand: the
               mask register is in the is4 immediate's high nibble; each lane
               takes src2 when its mask lane's sign bit is set, else src1). */
            if ((s->prefix & PREFIX_VEX) && b1 &&
                (b == 0x4a || b == 0x4b || b == 0x4c)) {
                int esz = (b == 0x4a) ? 4 : (b == 0x4b) ? 8 : 1;
                int doff = offsetof(CPUX86State, xmm_regs[reg]);
                int s1off = offsetof(CPUX86State, xmm_regs[s->vex_v]);
                int s2off;
                if (s->vex_w)
                    goto illegal_op;
                if (mod == 3) {
                    s2off = offsetof(CPUX86State, xmm_regs[rm | REX_B(s)]);
                } else {
                    s->rip_offset = 1;
                    gen_lea_modrm(env, s, modrm);
                    gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_t0));
                    s2off = offsetof(CPUX86State, xmm_t0);
                }
                val = x86_ldub_code(env, s);
                int moff = offsetof(CPUX86State, xmm_regs[(val >> 4) & 15]);
                if (esz == 8) {
                    TCGv_i64 m = tcg_temp_new_i64(tcg_ctx);
                    TCGv_i64 a = tcg_temp_new_i64(tcg_ctx);
                    TCGv_i64 bv = tcg_temp_new_i64(tcg_ctx);
                    TCGv_i64 z = tcg_const_i64(tcg_ctx, 0);
                    for (int i = 0; i < 2; i++) {
                        tcg_gen_ld_i64(tcg_ctx, m, tcg_ctx->cpu_env,
                                       moff + offsetof(ZMMReg, ZMM_Q(i)));
                        tcg_gen_ld_i64(tcg_ctx, a, tcg_ctx->cpu_env,
                                       s1off + offsetof(ZMMReg, ZMM_Q(i)));
                        tcg_gen_ld_i64(tcg_ctx, bv, tcg_ctx->cpu_env,
                                       s2off + offsetof(ZMMReg, ZMM_Q(i)));
                        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LT, a, m, z, bv, a);
                        tcg_gen_st_i64(tcg_ctx, a, tcg_ctx->cpu_env,
                                       doff + offsetof(ZMMReg, ZMM_Q(i)));
                    }
                    tcg_temp_free_i64(tcg_ctx, m);
                    tcg_temp_free_i64(tcg_ctx, a);
                    tcg_temp_free_i64(tcg_ctx, bv);
                    tcg_temp_free_i64(tcg_ctx, z);
                } else {
                    int nl = 16 / esz;
                    TCGv_i32 m = tcg_temp_new_i32(tcg_ctx);
                    TCGv_i32 a = tcg_temp_new_i32(tcg_ctx);
                    TCGv_i32 bv = tcg_temp_new_i32(tcg_ctx);
                    TCGv_i32 z = tcg_const_i32(tcg_ctx, 0);
                    for (int i = 0; i < nl; i++) {
                        if (esz == 4) {
                            tcg_gen_ld_i32(tcg_ctx, m, tcg_ctx->cpu_env,
                                           moff + offsetof(ZMMReg, ZMM_L(i)));
                            tcg_gen_ld_i32(tcg_ctx, a, tcg_ctx->cpu_env,
                                           s1off + offsetof(ZMMReg, ZMM_L(i)));
                            tcg_gen_ld_i32(tcg_ctx, bv, tcg_ctx->cpu_env,
                                           s2off + offsetof(ZMMReg, ZMM_L(i)));
                            tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LT, a, m, z, bv, a);
                            tcg_gen_st_i32(tcg_ctx, a, tcg_ctx->cpu_env,
                                           doff + offsetof(ZMMReg, ZMM_L(i)));
                        } else {
                            tcg_gen_ld8u_i32(tcg_ctx, m, tcg_ctx->cpu_env,
                                             moff + offsetof(ZMMReg, ZMM_B(i)));
                            tcg_gen_andi_i32(tcg_ctx, m, m, 0x80);
                            tcg_gen_ld8u_i32(tcg_ctx, a, tcg_ctx->cpu_env,
                                             s1off + offsetof(ZMMReg, ZMM_B(i)));
                            tcg_gen_ld8u_i32(tcg_ctx, bv, tcg_ctx->cpu_env,
                                             s2off + offsetof(ZMMReg, ZMM_B(i)));
                            tcg_gen_movcond_i32(tcg_ctx, TCG_COND_NE, a, m, z, bv, a);
                            tcg_gen_st8_i32(tcg_ctx, a, tcg_ctx->cpu_env,
                                            doff + offsetof(ZMMReg, ZMM_B(i)));
                        }
                    }
                    tcg_temp_free_i32(tcg_ctx, m);
                    tcg_temp_free_i32(tcg_ctx, a);
                    tcg_temp_free_i32(tcg_ctx, bv);
                    tcg_temp_free_i32(tcg_ctx, z);
                }
                break;
            }

            sse_fn_eppi = sse_op_table7[b].op[b1];
            if (!sse_fn_eppi) {
                goto unknown_op;
            }
            if (!(s->cpuid_ext_features & sse_op_table7[b].ext_mask))
                goto illegal_op;

            s->rip_offset = 1;

            if (sse_fn_eppi == SSE_SPECIAL) {
                ot = mo_64_32(s->dflag);
                rm = (modrm & 7) | REX_B(s);
                if (mod != 3)
                    gen_lea_modrm(env, s, modrm);
                reg = ((modrm >> 3) & 7) | rex_r;
                val = x86_ldub_code(env, s);
                switch (b) {
                case 0x14: /* pextrb */
                    tcg_gen_ld8u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].ZMM_B(val & 15)));
                    if (mod == 3) {
                        gen_op_mov_reg_v(s, ot, rm, s->T0);
                    } else {
                        tcg_gen_qemu_st_tl(tcg_ctx, s->T0, s->A0,
                                           s->mem_index, MO_UB);
                    }
                    break;
                case 0x15: /* pextrw */
                    tcg_gen_ld16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].ZMM_W(val & 7)));
                    if (mod == 3) {
                        gen_op_mov_reg_v(s, ot, rm, s->T0);
                    } else {
                        tcg_gen_qemu_st_tl(tcg_ctx, s->T0, s->A0,
                                           s->mem_index, MO_LEUW);
                    }
                    break;
                case 0x16:
                    if (ot == MO_32) { /* pextrd */
                        tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(val & 3)));
                        if (mod == 3) {
                            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[rm], s->tmp2_i32);
                        } else {
                            tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                        }
                    } else { /* pextrq */
#ifdef TARGET_X86_64
                        tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_Q(val & 1)));
                        if (mod == 3) {
                            tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_regs[rm], s->tmp1_i64);
                        } else {
                            tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                        }
#else
                        goto illegal_op;
#endif
                    }
                    break;
                case 0x17: /* extractps */
                    tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].ZMM_L(val & 3)));
                    if (mod == 3) {
                        gen_op_mov_reg_v(s, ot, rm, s->T0);
                    } else {
                        tcg_gen_qemu_st_tl(tcg_ctx, s->T0, s->A0,
                                           s->mem_index, MO_LEUL);
                    }
                    break;
                case 0x1d: /* vcvtps2ph: 4 floats (reg) -> 4 halves (rm) */
                    {
                        if (s->vex_w || s->vex_v != 0) {
                            goto illegal_op;
                        }
                        TCGv_i32 f16imm = tcg_const_i32(tcg_ctx, val);
                        tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                         offsetof(CPUX86State, xmm_t0));
                        tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env,
                                         offsetof(CPUX86State, xmm_regs[reg]));
                        gen_helper_cvtps2ph(tcg_ctx, tcg_ctx->cpu_env, s->ptr0,
                                            s->ptr1, f16imm);
                        tcg_temp_free_i32(tcg_ctx, f16imm);
                        tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                                       offsetof(CPUX86State, xmm_t0.ZMM_Q(0)));
                        if (mod == 3) {
                            tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                                           offsetof(CPUX86State,
                                                    xmm_regs[rm].ZMM_Q(0)));
                            tcg_gen_movi_i64(tcg_ctx, s->tmp1_i64, 0);
                            tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                                           offsetof(CPUX86State,
                                                    xmm_regs[rm].ZMM_Q(1)));
                            gen_clear_ymmh(s, rm);
                        } else {
                            tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                        }
                    }
                    break;
                case 0x20: /* pinsrb */
                    if (mod == 3) {
                        gen_op_mov_v_reg(s, MO_32, s->T0, rm);
                    } else {
                        tcg_gen_qemu_ld_tl(tcg_ctx, s->T0, s->A0,
                                           s->mem_index, MO_UB);
                    }
                    /* VEX vpinsrb is 3-operand: dst = src1(vvvv) with one byte
                     * replaced, dst[255:128]=0 (legacy keeps the rest of dst). */
                    if (s->prefix & PREFIX_VEX)
                        gen_op_movo(s, offsetof(CPUX86State, xmm_regs[reg]),
                                    offsetof(CPUX86State, xmm_regs[s->vex_v]));
                    tcg_gen_st8_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].ZMM_B(val & 15)));
                    if (s->prefix & PREFIX_VEX)
                        gen_clear_ymmh(s, reg);
                    break;
                case 0x21: /* insertps */
                    if (mod == 3) {
                        tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                        offsetof(CPUX86State,xmm_regs[rm]
                                                .ZMM_L((val >> 6) & 3)));
                    } else {
                        tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                            s->mem_index, MO_LEUL);
                    }
                    if (s->prefix & PREFIX_VEX) {
                        gen_op_movo(s, offsetof(CPUX86State, xmm_regs[reg]),
                                    offsetof(CPUX86State, xmm_regs[s->vex_v]));
                    }
                    tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                    offsetof(CPUX86State,xmm_regs[reg]
                                            .ZMM_L((val >> 4) & 3)));
                    if ((val >> 0) & 1)
                        tcg_gen_st_i32(tcg_ctx, tcg_const_i32(tcg_ctx, 0 /*float32_zero*/),
                                        tcg_ctx->cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(0)));
                    if ((val >> 1) & 1)
                        tcg_gen_st_i32(tcg_ctx, tcg_const_i32(tcg_ctx, 0 /*float32_zero*/),
                                        tcg_ctx->cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(1)));
                    if ((val >> 2) & 1)
                        tcg_gen_st_i32(tcg_ctx, tcg_const_i32(tcg_ctx, 0 /*float32_zero*/),
                                        tcg_ctx->cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(2)));
                    if ((val >> 3) & 1)
                        tcg_gen_st_i32(tcg_ctx, tcg_const_i32(tcg_ctx, 0 /*float32_zero*/),
                                        tcg_ctx->cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(3)));
                    if (s->prefix & PREFIX_VEX)
                        gen_clear_ymmh(s, reg);
                    break;
                case 0x22:
                    /* VEX vpinsrd/vpinsrq is 3-operand: dst = src1(vvvv) with one
                     * element replaced, dst[255:128]=0 (legacy keeps dst). */
                    if (s->prefix & PREFIX_VEX)
                        gen_op_movo(s, offsetof(CPUX86State, xmm_regs[reg]),
                                    offsetof(CPUX86State, xmm_regs[s->vex_v]));
                    if (ot == MO_32) { /* pinsrd */
                        if (mod == 3) {
                            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[rm]);
                        } else {
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                        }
                        tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(val & 3)));
                    } else { /* pinsrq */
#ifdef TARGET_X86_64
                        if (mod == 3) {
                            gen_op_mov_v_reg(s, ot, s->tmp1_i64, rm);
                        } else {
                            tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                        }
                        tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_Q(val & 1)));
#else
                        goto illegal_op;
#endif
                    }
                    if (s->prefix & PREFIX_VEX)
                        gen_clear_ymmh(s, reg);
                    break;
                }
                return;
            }

            if (b1) {
                op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
                if (mod == 3) {
                    op2_offset = offsetof(CPUX86State,xmm_regs[rm | REX_B(s)]);
                } else {
                    op2_offset = offsetof(CPUX86State,xmm_t0);
                    gen_lea_modrm(env, s, modrm);
                    if (b == 0x0a) { /* roundss: scalar m32 source */
                        gen_op_ld_v(s, MO_32, s->T0, s->A0);
                        tcg_gen_st32_tl(
                            tcg_ctx, s->T0, tcg_ctx->cpu_env,
                            offsetof(CPUX86State, xmm_t0.ZMM_L(0)));
                    } else if (b == 0x0b) { /* roundsd: scalar m64 source */
                        gen_ldq_env_A0(
                            s, offsetof(CPUX86State, xmm_t0.ZMM_D(0)));
                    } else {
                        gen_ldo_env_A0_legacy_sse(s, op2_offset);
                    }
                }
            } else {
                op1_offset = offsetof(CPUX86State,fpregs[reg].mmx);
                if (mod == 3) {
                    op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
                } else {
                    op2_offset = offsetof(CPUX86State,mmx_t0);
                    gen_lea_modrm(env, s, modrm);
                    gen_ldq_env_A0(s, op2_offset);
                }
            }
            val = x86_ldub_code(env, s);

            if ((b & 0xfc) == 0x60) { /* pcmpXstrX */
                set_cc_op(s, CC_OP_EFLAGS);

                if (s->dflag == MO_64) {
                    /* The helper must use entire 64-bit gp registers */
                    val |= 1 << 8;
                }
            }

            if ((s->prefix & PREFIX_VEX) && b1 && sse_vex_3op_table7(b)) {
                gen_sse_vex_merge_src1(s, reg, &op2_offset);
            }
            if (!b1) {
                gen_helper_enter_mmx(tcg_ctx, tcg_ctx->cpu_env);
            }
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            sse_fn_eppi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1, tcg_const_i32(tcg_ctx, val));
            if (!b1)
                mmx_write_reg = reg;
            if ((s->prefix & PREFIX_VEX) && b1 &&
                (b < 0x60 || b > 0x63)) {
                gen_clear_ymmh(s, reg);
            }
            break;

        case 0x33a:
            /* Various integer extensions at 0f 3a f[0-f].  */
            b = modrm | (b1 << 8);
            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;

            switch (b) {
            case 0x3f0: /* rorx Gy,Ey, Ib */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                s->rip_offset = 1;
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                b = x86_ldub_code(env, s);
                if (ot == MO_64) {
                    tcg_gen_rotri_tl(tcg_ctx, s->T0, s->T0, b & 63);
                } else {
                    tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                    tcg_gen_rotri_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, b & 31);
                    tcg_gen_extu_i32_tl(tcg_ctx, s->T0, s->tmp2_i32);
                }
                gen_op_mov_reg_v(s, ot, reg, s->T0);
                break;

            default:
                goto unknown_op;
            }
            break;

        default:
        unknown_op:
            gen_unknown_opcode(env, s);
            return;
        }
    } else {
        /* generic MMX or SSE operation */
        switch(b) {
        case 0x70: /* pshufx insn */
        case 0xc6: /* pshufx insn */
        case 0xc2: /* compare insns */
            s->rip_offset = 1;
            break;
        default:
            break;
        }
        if (is_xmm) {
            op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
            if (mod != 3) {
                int sz = 4;

                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,xmm_t0);

                switch (b) {
                case 0x50:
                case 0x51:
                case 0x52:
                case 0x53:
                case 0x54:
                case 0x55:
                case 0x56:
                case 0x57:
                case 0x58:
                case 0x59:
                case 0x5a:

                case 0x5c:
                case 0x5d:
                case 0x5e:
                case 0x5f:

                case 0xc2:
                    /* Most sse scalar operations.  */
                    if (b1 == 2) {
                        sz = 2;
                    } else if (b1 == 3 || sse_fn_epp == gen_helper_cvtps2pd) {
                        /* Packed widening consumes only two single values. */
                        sz = 3;
                    }
                    break;

                case 0x2e:  /* ucomis[sd] */
                case 0x2f:  /* comis[sd] */
                    if (b1 == 0) {
                        sz = 2;
                    } else {
                        sz = 3;
                    }
                    break;
                }

                switch (sz) {
                case 2:
                    /* 32 bit access */
                    gen_op_ld_v(s, MO_32, s->T0, s->A0);
                    tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                    offsetof(CPUX86State,xmm_t0.ZMM_L(0)));
                    break;
                case 3:
                    /* 64 bit access */
                    gen_ldq_env_A0(s, offsetof(CPUX86State, xmm_t0.ZMM_D(0)));
                    break;
                default:
                    /* 128 bit access */
                    gen_ldo_env_A0_legacy_sse(s, op2_offset);
                    break;
                }
            } else {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            }
        } else {
            op1_offset = offsetof(CPUX86State,fpregs[reg].mmx);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,mmx_t0);
                gen_ldq_env_A0(s, op2_offset);
            } else {
            rm = (modrm & 7);
            op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
        }
    }
    if ((s->prefix & PREFIX_VEX) && is_xmm && sse_vex_3op_table1(b)) {
        gen_sse_vex_merge_src1(s, reg, &op2_offset);
    }
    switch(b) {
    case 0x0f: /* 3DNow! data insns */
            val = x86_ldub_code(env, s);
            sse_fn_epp = sse_op_table5[val];
            if (!sse_fn_epp) {
                goto unknown_op;
            }
            if (!(s->cpuid_ext2_features & CPUID_EXT2_3DNOW)) {
                goto illegal_op;
            }
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            sse_fn_epp(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            break;
        case 0x70: /* pshufx insn */
        case 0xc6: /* pshufx insn */
            val = x86_ldub_code(env, s);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            /* XXX: introduce a new table? */
            sse_fn_ppi = (SSEFunc_0_ppi)sse_fn_epp;
            sse_fn_ppi(tcg_ctx, s->ptr0, s->ptr1, tcg_const_i32(tcg_ctx, val));
            break;
        case 0xc2:
            /* compare insns */
            val = x86_ldub_code(env, s);
            if (val >= 8)
                goto unknown_op;
            sse_fn_epp = sse_op_table4[val][b1];

            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            sse_fn_epp(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            break;
        case 0xf7:
            /* maskmov : we must prepare A0 */
            if (mod != 3)
                goto illegal_op;
            tcg_gen_mov_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_EDI]);
            gen_extu(tcg_ctx, s->aflag, s->A0);
            gen_add_A0_ds_seg(s);

            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            /* XXX: introduce a new table? */
            sse_fn_eppt = (SSEFunc_0_eppt)sse_fn_epp;
            sse_fn_eppt(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1, s->A0);
            break;
        default:
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            sse_fn_epp(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            break;
        }
        if (!is_xmm && b != 0xf7)
            mmx_write_reg = reg;
        if (b == 0x2e || b == 0x2f) {
            set_cc_op(s, CC_OP_EFLAGS);
        }
        if ((s->prefix & PREFIX_VEX) && is_xmm && b != 0x2e && b != 0x2f &&
            b != 0xf7) {
            gen_clear_ymmh(s, reg);
        }
    }
    if (mmx_write_reg >= 0)
        gen_mmx_set_x87_exp(s, mmx_write_reg);
}

// Unicorn: sync EFLAGS on demand
static void sync_eflags(DisasContext *s, TCGContext *tcg_ctx)
{
    gen_update_cc_op(s);
    gen_helper_read_eflags(tcg_ctx, s->T0, tcg_ctx->cpu_env);
    tcg_gen_st_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, eflags));
}

typedef enum VEXOpmaskDecodeResult {
    VEX_OPMASK_NOT_HANDLED,
    VEX_OPMASK_DECODED,
    VEX_OPMASK_INVALID,
} VEXOpmaskDecodeResult;

typedef enum VEXUserMSRDecodeResult {
    VEX_USER_MSR_NOT_HANDLED,
    VEX_USER_MSR_DECODED,
    VEX_USER_MSR_INVALID,
} VEXUserMSRDecodeResult;

typedef enum AMXVexDecodeResult {
    AMX_VEX_NOT_HANDLED,
    AMX_VEX_DECODED,
    AMX_VEX_INVALID,
} AMXVexDecodeResult;

static bool decode_vex_opmask_width(DisasContext *s, int required_l,
                                    uint64_t *width_mask)
{
    if (s->vex_l != required_l ||
        (s->prefix & (PREFIX_REPZ | PREFIX_REPNZ))) {
        return false;
    }

    if (s->vex_w) {
        *width_mask = (s->prefix & PREFIX_DATA) ? UINT32_MAX : UINT64_MAX;
    } else {
        *width_mask = (s->prefix & PREFIX_DATA) ? UINT8_MAX : UINT16_MAX;
    }
    return true;
}

static bool x86_opmask_width_feature_enabled(const DisasContext *s,
                                              uint64_t width_mask,
                                              bool word_requires_dq)
{
    uint32_t required = 0;

    if (width_mask == UINT8_MAX ||
        (word_requires_dq && width_mask == UINT16_MAX)) {
        required = CPUID_7_0_EBX_AVX512DQ;
    } else if (width_mask == UINT32_MAX || width_mask == UINT64_MAX) {
        required = CPUID_7_0_EBX_AVX512BW;
    }
    return (s->cpuid_7_0_ebx_features & required) == required;
}

static bool x86_opmask_state_ready(DisasContext *s)
{
    if (s->flags & HF_TS_MASK) {
        gen_exception(s, EXCP07_PREX, s->pc_start - s->cs_base);
        return false;
    }
    if (s->flags & HF_EM_MASK) {
        gen_illegal_opcode(s);
        return false;
    }
    return true;
}

static void gen_opmask_mark_inuse(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 inuse = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ld_i64(tcg_ctx, inuse, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, xstate_bv));
    tcg_gen_ori_i64(tcg_ctx, inuse, inuse, XSTATE_OPMASK_MASK);
    tcg_gen_st_i64(tcg_ctx, inuse, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, xstate_bv));
    tcg_temp_free_i64(tcg_ctx, inuse);
}

static VEXUserMSRDecodeResult gen_vex_user_msr(CPUX86State *env,
                                               DisasContext *s, int b)
{
    const int mandatory =
        s->prefix & (PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ);
    int opcode;
    int modrm;

    if (b != 0x700) {
        return VEX_USER_MSR_NOT_HANDLED;
    }
    opcode = translator_ldub(s->uc->tcg_ctx, env, s->pc);
    if (opcode != 0xf8) {
        return VEX_USER_MSR_NOT_HANDLED;
    }

    (void)x86_ldub_code(env, s);
    modrm = x86_ldub_code(env, s);
    if (!CODE64(s) || s->vex_w || s->vex_l != 0 || s->vex_v != 0 ||
        (mandatory != PREFIX_REPNZ && mandatory != PREFIX_REPZ) ||
        (modrm >> 6) != 3 || (modrm & 0x38) != 0) {
        return VEX_USER_MSR_INVALID;
    }
    (void)x86_ldl_code(env, s);

    if (!(s->cpuid_features & CPUID_MSR)) {
        gen_illegal_opcode(s);
        return VEX_USER_MSR_DECODED;
    }
    if (!(s->cpuid_7_1_edx_features & CPUID_7_1_EDX_USER_MSR)) {
        gen_illegal_opcode(s);
        return VEX_USER_MSR_DECODED;
    }
    /* IA32_USER_MSR_CTL and its permission bitmap are not modeled.  Its
     * architectural reset state has ENABLE clear, so a complete, otherwise
     * valid VEX USER_MSR instruction must #UD rather than reach an MSR. */
    gen_illegal_opcode(s);
    return VEX_USER_MSR_DECODED;
}

typedef enum OpmaskBinaryOp {
    OPMASK_BIN_AND,
    OPMASK_BIN_ANDN,
    OPMASK_BIN_OR,
    OPMASK_BIN_XOR,
    OPMASK_BIN_XNOR,
    OPMASK_BIN_ADD,
} OpmaskBinaryOp;

static void gen_opmask_binary(DisasContext *s, int dst, int src1, int src2,
                              uint64_t width_mask, OpmaskBinaryOp op)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 lhs = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 rhs = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ld_i64(tcg_ctx, lhs, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       src1 * sizeof(uint64_t));
    tcg_gen_ld_i64(tcg_ctx, rhs, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       src2 * sizeof(uint64_t));
    switch (op) {
    case OPMASK_BIN_AND:
        tcg_gen_and_i64(tcg_ctx, lhs, lhs, rhs);
        break;
    case OPMASK_BIN_ANDN:
        tcg_gen_not_i64(tcg_ctx, lhs, lhs);
        tcg_gen_and_i64(tcg_ctx, lhs, lhs, rhs);
        break;
    case OPMASK_BIN_OR:
        tcg_gen_or_i64(tcg_ctx, lhs, lhs, rhs);
        break;
    case OPMASK_BIN_XOR:
        tcg_gen_xor_i64(tcg_ctx, lhs, lhs, rhs);
        break;
    case OPMASK_BIN_XNOR:
        tcg_gen_xor_i64(tcg_ctx, lhs, lhs, rhs);
        tcg_gen_not_i64(tcg_ctx, lhs, lhs);
        break;
    case OPMASK_BIN_ADD:
        tcg_gen_add_i64(tcg_ctx, lhs, lhs, rhs);
        break;
    }
    if (width_mask != UINT64_MAX) {
        tcg_gen_andi_i64(tcg_ctx, lhs, lhs, width_mask);
    }
    tcg_gen_st_i64(tcg_ctx, lhs, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       dst * sizeof(uint64_t));
    gen_opmask_mark_inuse(s);

    tcg_temp_free_i64(tcg_ctx, lhs);
    tcg_temp_free_i64(tcg_ctx, rhs);
}

static void gen_opmask_knot(DisasContext *s, int dst, int src,
                            uint64_t width_mask)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ld_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       src * sizeof(uint64_t));
    tcg_gen_not_i64(tcg_ctx, value, value);
    if (width_mask != UINT64_MAX) {
        tcg_gen_andi_i64(tcg_ctx, value, value, width_mask);
    }
    tcg_gen_st_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       dst * sizeof(uint64_t));
    gen_opmask_mark_inuse(s);

    tcg_temp_free_i64(tcg_ctx, value);
}

static void gen_opmask_kunpack(DisasContext *s, int dst, int src1, int src2,
                               uint64_t element_mask, int element_bits)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 high = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 low = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ld_i64(tcg_ctx, high, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       src1 * sizeof(uint64_t));
    tcg_gen_ld_i64(tcg_ctx, low, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       src2 * sizeof(uint64_t));
    tcg_gen_andi_i64(tcg_ctx, high, high, element_mask);
    tcg_gen_andi_i64(tcg_ctx, low, low, element_mask);
    tcg_gen_shli_i64(tcg_ctx, high, high, element_bits);
    tcg_gen_or_i64(tcg_ctx, high, high, low);
    tcg_gen_st_i64(tcg_ctx, high, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       dst * sizeof(uint64_t));
    gen_opmask_mark_inuse(s);

    tcg_temp_free_i64(tcg_ctx, high);
    tcg_temp_free_i64(tcg_ctx, low);
}

static void gen_opmask_shift(DisasContext *s, int dst, int src,
                             uint64_t width_mask, int width_bits,
                             unsigned int count, bool shift_left)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ld_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       src * sizeof(uint64_t));
    if (width_mask != UINT64_MAX) {
        tcg_gen_andi_i64(tcg_ctx, value, value, width_mask);
    }
    if (count >= width_bits) {
        tcg_gen_movi_i64(tcg_ctx, value, 0);
    } else if (shift_left) {
        tcg_gen_shli_i64(tcg_ctx, value, value, count);
        if (width_mask != UINT64_MAX) {
            tcg_gen_andi_i64(tcg_ctx, value, value, width_mask);
        }
    } else {
        tcg_gen_shri_i64(tcg_ctx, value, value, count);
    }
    tcg_gen_st_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       dst * sizeof(uint64_t));
    gen_opmask_mark_inuse(s);

    tcg_temp_free_i64(tcg_ctx, value);
}

static bool decode_vex_kmov_width(DisasContext *s, bool gpr_form,
                                  uint64_t *width_mask, int *width_bits)
{
    bool data = s->prefix & PREFIX_DATA;
    bool repz = s->prefix & PREFIX_REPZ;
    bool repnz = s->prefix & PREFIX_REPNZ;

    if (s->vex_l != 0 || s->vex_v != 0 || repz) {
        return false;
    }

    if (!gpr_form) {
        if (repnz) {
            return false;
        }
        if (s->vex_w) {
            *width_bits = data ? 32 : 64;
        } else {
            *width_bits = data ? 8 : 16;
        }
    } else if (!s->vex_w && data && !repnz) {
        *width_bits = 8;
    } else if (!s->vex_w && !data && !repnz) {
        *width_bits = 16;
    } else if (!s->vex_w && !data && repnz) {
        *width_bits = 32;
    } else if (s->vex_w && !data && repnz) {
        *width_bits = 64;
    } else {
        return false;
    }

    switch (*width_bits) {
    case 8: *width_mask = UINT8_MAX; break;
    case 16: *width_mask = UINT16_MAX; break;
    case 32: *width_mask = UINT32_MAX; break;
    default: *width_mask = UINT64_MAX; break;
    }
    return true;
}

static MemOp opmask_width_memop(int width_bits)
{
    switch (width_bits) {
    case 8: return MO_UB;
    case 16: return MO_LEUW;
    case 32: return MO_LEUL;
    default: return MO_LEQ;
    }
}

static void gen_opmask_kmov_k_to_k(DisasContext *s, int dst, int src,
                                    uint64_t width_mask)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ld_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       src * sizeof(uint64_t));
    if (width_mask != UINT64_MAX) {
        tcg_gen_andi_i64(tcg_ctx, value, value, width_mask);
    }
    tcg_gen_st_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       dst * sizeof(uint64_t));
    gen_opmask_mark_inuse(s);
    tcg_temp_free_i64(tcg_ctx, value);
}

static void gen_opmask_kmov_mem_to_k(CPUX86State *env, DisasContext *s,
                                     int modrm, int dst, int width_bits)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

    gen_lea_modrm(env, s, modrm);
    tcg_gen_qemu_ld_i64(tcg_ctx, value, s->A0, s->mem_index,
                        opmask_width_memop(width_bits));
    tcg_gen_st_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       dst * sizeof(uint64_t));
    gen_opmask_mark_inuse(s);
    tcg_temp_free_i64(tcg_ctx, value);
}

static void gen_opmask_kmov_k_to_mem(CPUX86State *env, DisasContext *s,
                                     int modrm, int src, int width_bits)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

    gen_lea_modrm(env, s, modrm);
    tcg_gen_ld_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       src * sizeof(uint64_t));
    tcg_gen_qemu_st_i64(tcg_ctx, value, s->A0, s->mem_index,
                        opmask_width_memop(width_bits));
    tcg_temp_free_i64(tcg_ctx, value);
}

static void gen_opmask_kmov_gpr_to_k(DisasContext *s, int dst, int src,
                                     uint64_t width_mask)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_extu_tl_i64(tcg_ctx, value, tcg_ctx->cpu_regs[src]);
    if (width_mask != UINT64_MAX) {
        tcg_gen_andi_i64(tcg_ctx, value, value, width_mask);
    }
    tcg_gen_st_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       dst * sizeof(uint64_t));
    gen_opmask_mark_inuse(s);
    tcg_temp_free_i64(tcg_ctx, value);
}

static void gen_opmask_kmov_k_to_gpr(DisasContext *s, int dst, int src,
                                     uint64_t width_mask)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ld_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       src * sizeof(uint64_t));
    if (width_mask != UINT64_MAX) {
        tcg_gen_andi_i64(tcg_ctx, value, value, width_mask);
    }
    tcg_gen_trunc_i64_tl(tcg_ctx, tcg_ctx->cpu_regs[dst], value);
    tcg_temp_free_i64(tcg_ctx, value);
}

static void gen_opmask_ktest(DisasContext *s, int src1, int src2,
                             uint64_t width_mask)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 lhs = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 rhs = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 and_result = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ld_i64(tcg_ctx, lhs, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       src1 * sizeof(uint64_t));
    tcg_gen_ld_i64(tcg_ctx, rhs, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       src2 * sizeof(uint64_t));
    if (width_mask != UINT64_MAX) {
        tcg_gen_andi_i64(tcg_ctx, lhs, lhs, width_mask);
        tcg_gen_andi_i64(tcg_ctx, rhs, rhs, width_mask);
    }

    /* ZF := (src1 & src2) == 0; CF := ((~src1) & src2) == 0. */
    tcg_gen_and_i64(tcg_ctx, and_result, lhs, rhs);
    tcg_gen_not_i64(tcg_ctx, lhs, lhs);
    tcg_gen_and_i64(tcg_ctx, rhs, rhs, lhs);
    tcg_gen_setcondi_i64(tcg_ctx, TCG_COND_EQ, lhs, and_result, 0);
    tcg_gen_setcondi_i64(tcg_ctx, TCG_COND_EQ, rhs, rhs, 0);
    tcg_gen_shli_i64(tcg_ctx, lhs, lhs, 6);
    tcg_gen_or_i64(tcg_ctx, lhs, lhs, rhs);

    /* KTEST defines all arithmetic status flags: ZF/CF as above and
     * OF/SF/AF/PF cleared.  Non-status RFLAGS live outside cc_src and remain
     * untouched. */
    set_cc_op(s, CC_OP_EFLAGS);
    tcg_gen_trunc_i64_tl(tcg_ctx, tcg_ctx->cpu_cc_src, lhs);

    tcg_temp_free_i64(tcg_ctx, lhs);
    tcg_temp_free_i64(tcg_ctx, rhs);
    tcg_temp_free_i64(tcg_ctx, and_result);
}

static void gen_opmask_kortest(DisasContext *s, int src1, int src2,
                               uint64_t width_mask)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 lhs = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 rhs = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 flags = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ld_i64(tcg_ctx, lhs, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       src1 * sizeof(uint64_t));
    tcg_gen_ld_i64(tcg_ctx, rhs, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, opmask_regs) +
                       src2 * sizeof(uint64_t));
    if (width_mask != UINT64_MAX) {
        tcg_gen_andi_i64(tcg_ctx, lhs, lhs, width_mask);
        tcg_gen_andi_i64(tcg_ctx, rhs, rhs, width_mask);
    }

    tcg_gen_or_i64(tcg_ctx, lhs, lhs, rhs);
    tcg_gen_setcondi_i64(tcg_ctx, TCG_COND_EQ, rhs, lhs, 0);
    tcg_gen_setcondi_i64(tcg_ctx, TCG_COND_EQ, flags, lhs,
                         (int64_t)width_mask);
    tcg_gen_shli_i64(tcg_ctx, rhs, rhs, 6);
    tcg_gen_or_i64(tcg_ctx, flags, flags, rhs);

    /* Like KTEST, KORTEST defines ZF/CF and clears OF/SF/AF/PF. */
    set_cc_op(s, CC_OP_EFLAGS);
    tcg_gen_trunc_i64_tl(tcg_ctx, tcg_ctx->cpu_cc_src, flags);

    tcg_temp_free_i64(tcg_ctx, lhs);
    tcg_temp_free_i64(tcg_ctx, rhs);
    tcg_temp_free_i64(tcg_ctx, flags);
}

/* Decode VEX-encoded operations whose operands are the architectural K file.
 * Returning NOT_HANDLED leaves the caller's general VEX fail-closed rule in
 * charge, so adding one opcode cannot accidentally enable a neighboring form. */
static VEXOpmaskDecodeResult gen_vex_opmask(CPUX86State *env,
                                            DisasContext *s, int b,
                                            int rex_r)
{
    int modrm, subopcode;
    int width_bits;
    uint64_t width_mask;
    OpmaskBinaryOp binary_op;

    if (b == 0x13a) {
        unsigned int count;

        subopcode = x86_ldub_code(env, s);
        if (subopcode < 0x30 || subopcode > 0x33) {
            /* The shared vector decoder still owns other 0F3A opcodes. */
            s->pc--;
            return VEX_OPMASK_NOT_HANDLED;
        }
        if (!x86_avx512_enabled(s)) {
            return VEX_OPMASK_INVALID;
        }
        if (!x86_opmask_state_ready(s)) {
            return VEX_OPMASK_DECODED;
        }

        /* KSHIFTR/KSHIFTL B/W/D/Q have L=0, pp=66 and reserved vvvv. */
        if (s->vex_l != 0 || !(s->prefix & PREFIX_DATA) ||
            (s->prefix & (PREFIX_REPZ | PREFIX_REPNZ)) || s->vex_v != 0 ||
            rex_r || REX_X(s) || REX_B(s)) {
            return VEX_OPMASK_INVALID;
        }
        modrm = x86_ldub_code(env, s);
        if ((modrm >> 6) != 3) {
            return VEX_OPMASK_INVALID;
        }
        count = x86_ldub_code(env, s);

        if (subopcode & 1) {
            width_bits = s->vex_w ? 64 : 32;
        } else {
            width_bits = s->vex_w ? 16 : 8;
        }
        switch (width_bits) {
        case 8: width_mask = UINT8_MAX; break;
        case 16: width_mask = UINT16_MAX; break;
        case 32: width_mask = UINT32_MAX; break;
        default: width_mask = UINT64_MAX; break;
        }
        if (!x86_opmask_width_feature_enabled(s, width_mask, false)) {
            return VEX_OPMASK_INVALID;
        }
        gen_opmask_shift(s, (modrm >> 3) & 7, modrm & 7, width_mask,
                         width_bits, count, subopcode >= 0x32);
        return VEX_OPMASK_DECODED;
    }

    if (b != 0x141 && b != 0x142 && b != 0x144 && b != 0x145 &&
        b != 0x146 && b != 0x147 && b != 0x14a && b != 0x14b &&
        b != 0x190 && b != 0x191 && b != 0x192 && b != 0x193 &&
        b != 0x199) {
        if (b != 0x198) {
            return VEX_OPMASK_NOT_HANDLED;
        }
    }

    if (!x86_avx512_enabled(s)) {
        return VEX_OPMASK_INVALID;
    }
    if (!x86_opmask_state_ready(s)) {
        return VEX_OPMASK_DECODED;
    }

    if (b == 0x141 || b == 0x142 || b == 0x145 || b == 0x146 ||
        b == 0x147 || b == 0x14a) {
        /* KAND/KANDN/KOR/KXNOR/KXOR/KADD B/W/D/Q. */
        if (!decode_vex_opmask_width(s, 1, &width_mask) ||
            s->vex_v >= NB_OPMASK_REGS || rex_r || REX_X(s) || REX_B(s)) {
            return VEX_OPMASK_INVALID;
        }
        if (!x86_opmask_width_feature_enabled(s, width_mask, b == 0x14a)) {
            return VEX_OPMASK_INVALID;
        }

        modrm = x86_ldub_code(env, s);
        if ((modrm >> 6) != 3) {
            return VEX_OPMASK_INVALID;
        }

        switch (b) {
        case 0x141: binary_op = OPMASK_BIN_AND; break;
        case 0x142: binary_op = OPMASK_BIN_ANDN; break;
        case 0x145: binary_op = OPMASK_BIN_OR; break;
        case 0x146: binary_op = OPMASK_BIN_XNOR; break;
        case 0x147: binary_op = OPMASK_BIN_XOR; break;
        default: binary_op = OPMASK_BIN_ADD; break;
        }
        gen_opmask_binary(s, (modrm >> 3) & 7, s->vex_v, modrm & 7,
                          width_mask, binary_op);
    } else if (b >= 0x190 && b <= 0x193) {
        bool gpr_form = b == 0x192 || b == 0x193;

        if (!decode_vex_kmov_width(s, gpr_form, &width_mask, &width_bits) ||
            (width_bits == 64 && !CODE64(s))) {
            return VEX_OPMASK_INVALID;
        }
        if (!x86_opmask_width_feature_enabled(s, width_mask, false)) {
            return VEX_OPMASK_INVALID;
        }
        modrm = x86_ldub_code(env, s);

        if (b == 0x190) {
            if (rex_r) {
                return VEX_OPMASK_INVALID;
            }
            if ((modrm >> 6) == 3) {
                if (REX_X(s) || REX_B(s)) {
                    return VEX_OPMASK_INVALID;
                }
                gen_opmask_kmov_k_to_k(s, (modrm >> 3) & 7, modrm & 7,
                                        width_mask);
            } else {
                gen_opmask_kmov_mem_to_k(env, s, modrm,
                                         (modrm >> 3) & 7, width_bits);
            }
        } else if (b == 0x191) {
            if (rex_r || (modrm >> 6) == 3) {
                return VEX_OPMASK_INVALID;
            }
            gen_opmask_kmov_k_to_mem(env, s, modrm, (modrm >> 3) & 7,
                                     width_bits);
        } else if (b == 0x192) {
            if (rex_r || REX_X(s) || (modrm >> 6) != 3) {
                return VEX_OPMASK_INVALID;
            }
            gen_opmask_kmov_gpr_to_k(s, (modrm >> 3) & 7,
                                     (modrm & 7) | REX_B(s), width_mask);
        } else {
            if (REX_X(s) || REX_B(s) || (modrm >> 6) != 3) {
                return VEX_OPMASK_INVALID;
            }
            gen_opmask_kmov_k_to_gpr(s, ((modrm >> 3) & 7) | rex_r,
                                     modrm & 7, width_mask);
        }
    } else if (b == 0x144) {
        /* KNOT B/W/D/Q: VEX.L0[.66].0F.W{0,1} 44 /r, vvvv reserved. */
        if (!decode_vex_opmask_width(s, 0, &width_mask) || s->vex_v != 0 ||
            rex_r || REX_X(s) || REX_B(s)) {
            return VEX_OPMASK_INVALID;
        }
        if (!x86_opmask_width_feature_enabled(s, width_mask, false)) {
            return VEX_OPMASK_INVALID;
        }

        modrm = x86_ldub_code(env, s);
        if ((modrm >> 6) != 3) {
            return VEX_OPMASK_INVALID;
        }

        gen_opmask_knot(s, (modrm >> 3) & 7, modrm & 7, width_mask);
    } else if (b == 0x14b) {
        uint64_t element_mask;
        int element_bits;

        /* KUNPCKBW/WD/DQ use the low 8/16/32 bits of each source. */
        if (s->vex_l != 1 ||
            (s->prefix & (PREFIX_REPZ | PREFIX_REPNZ)) ||
            s->vex_v >= NB_OPMASK_REGS || rex_r || REX_X(s) || REX_B(s)) {
            return VEX_OPMASK_INVALID;
        }
        if (!s->vex_w && (s->prefix & PREFIX_DATA)) {
            element_mask = UINT8_MAX;
            element_bits = 8;
        } else if (!s->vex_w && !(s->prefix & PREFIX_DATA)) {
            element_mask = UINT16_MAX;
            element_bits = 16;
        } else if (s->vex_w && !(s->prefix & PREFIX_DATA)) {
            element_mask = UINT32_MAX;
            element_bits = 32;
        } else {
            return VEX_OPMASK_INVALID;
        }
        if (element_bits != 8 &&
            !(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_AVX512BW)) {
            return VEX_OPMASK_INVALID;
        }

        modrm = x86_ldub_code(env, s);
        if ((modrm >> 6) != 3) {
            return VEX_OPMASK_INVALID;
        }
        gen_opmask_kunpack(s, (modrm >> 3) & 7, s->vex_v, modrm & 7,
                           element_mask, element_bits);
    } else {
        /* KORTEST/KTEST B/W/D/Q: VEX.L0[.66].0F.W{0,1} 98/99 /r. */
        if (!decode_vex_opmask_width(s, 0, &width_mask) || s->vex_v != 0 ||
            rex_r || REX_X(s) || REX_B(s)) {
            return VEX_OPMASK_INVALID;
        }
        if (!x86_opmask_width_feature_enabled(s, width_mask, b == 0x199)) {
            return VEX_OPMASK_INVALID;
        }

        modrm = x86_ldub_code(env, s);
        if ((modrm >> 6) != 3) {
            return VEX_OPMASK_INVALID;
        }

        if (b == 0x198) {
            gen_opmask_kortest(s, (modrm >> 3) & 7, modrm & 7,
                               width_mask);
        } else {
            gen_opmask_ktest(s, (modrm >> 3) & 7, modrm & 7, width_mask);
        }
    }
    return VEX_OPMASK_DECODED;
}

/*
 * Once the independent opmask decoder has had first refusal, remaining VEX
 * instructions are implemented only by gen_sse().  Do not let an unimplemented
 * VEX opcode fall through to a legacy handler that happens to share its final
 * opcode byte: opmask operations otherwise decode as CMOVcc/SETcc and silently
 * modify general-purpose registers.
 *
 * The ranges below mirror the opcode families dispatched to gen_sse() at the
 * end of disas_insn().  gen_sse() performs the remaining per-form legality and
 * feature checks, so anything outside these VEX-aware families must #UD.
 */
static bool vex_opcode_uses_vector_decoder(int b)
{
    return (b >= 0x110 && b <= 0x117) ||
           (b >= 0x128 && b <= 0x12f) ||
           (b >= 0x138 && b <= 0x13a) ||
           (b >= 0x150 && b <= 0x179) ||
           (b >= 0x17c && b <= 0x17f) || b == 0x1c2 || b == 0x1c4 ||
           b == 0x1c5 || b == 0x1c6 ||
           (b >= 0x1d0 && b <= 0x1fe);
}

#ifdef TARGET_X86_64
static bool x86_amx_enabled(const DisasContext *s)
{
    return (s->cpuid_7_0_edx_features & CPUID_7_0_EDX_AMX_TILE) &&
           (s->flags & HF_AMX_EN_MASK);
}

static bool x86_amx_extended_feature(const CPUX86State *env,
                                     uint32_t feature)
{
    return (env->features[FEAT_1E_1_EAX] & feature) != 0;
}

static bool x86_vex_amx_owner_enabled(const CPUX86State *env,
                                      const DisasContext *s, int opcode,
                                      int mandatory)
{
    if (!x86_amx_enabled(s)) {
        return false;
    }

    switch (opcode) {
    case 0x49:
    case 0x4b:
        return true;
    case 0x4a:
        return x86_amx_extended_feature(
            env, CPUID_1E_1_EAX_AMX_MOVRS);
    case 0x5c:
        if (mandatory == PREFIX_REPZ) {
            return (s->cpuid_7_0_edx_features &
                    CPUID_7_0_EDX_AMX_BF16) != 0;
        }
        return mandatory == PREFIX_REPNZ &&
               (s->cpuid_7_1_eax_features &
                CPUID_7_1_EAX_AMX_FP16) != 0;
    case 0x5e:
        return (s->cpuid_7_0_edx_features &
                CPUID_7_0_EDX_AMX_INT8) != 0;
    case 0x6c:
        return (s->cpuid_7_1_edx_features &
                CPUID_7_1_EDX_AMX_COMPLEX) != 0;
    case 0xfd:
        return x86_amx_extended_feature(env,
                                        CPUID_1E_1_EAX_AMX_FP8);
    default:
        return false;
    }
}

static int amx_default_segment(AddressParts address)
{
    if (address.base >= 0 &&
        (address.base == R_ESP || address.base == R_EBP)) {
        return R_SS;
    }
    return address.def_seg;
}

static uint32_t amx_memory_desc(DisasContext *s, AddressParts address,
                                unsigned int tile, bool store)
{
    const int default_segment = amx_default_segment(address);
    const int segment = s->override >= 0 ? s->override : default_segment;
    uint32_t desc = tile & AMX_MEM_TILE_MASK;

    if (store) {
        desc |= AMX_MEM_STORE;
    }
    if (s->aflag == MO_32) {
        desc |= AMX_MEM_ADDR32;
    }
    if (s->override >= 0) {
        desc |= AMX_MEM_ADD_SEG |
                ((uint32_t)segment << AMX_MEM_SEG_SHIFT);
    }
    if (segment == R_SS) {
        desc |= AMX_MEM_SS;
    }
    return desc;
}

static void gen_amx_config_memory(CPUX86State *env, DisasContext *s,
                                  int modrm, bool store)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    AddressParts address = gen_lea_modrm_0(env, s, modrm);
    TCGv ea = gen_lea_modrm_1(s, address);
    const uint32_t desc = amx_memory_desc(s, address, 0, store);

    gen_lea_v_seg(s, s->aflag, ea, amx_default_segment(address),
                  s->override);
    if (store) {
        gen_helper_amx_sttilecfg(tcg_ctx, tcg_ctx->cpu_env, s->A0,
                                 tcg_const_i32(tcg_ctx, desc),
                                 tcg_const_tl(tcg_ctx,
                                              s->pc_start - s->cs_base));
    } else {
        gen_helper_amx_ldtilecfg(tcg_ctx, tcg_ctx->cpu_env, s->A0,
                                 tcg_const_i32(tcg_ctx, desc));
    }
}

static void gen_amx_tile_memory(CPUX86State *env, DisasContext *s,
                                int modrm, unsigned int tile, bool store)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    AddressParts address = gen_lea_modrm_0(env, s, modrm);
    AddressParts base_address = address;
    TCGv base;
    uint32_t desc;

    base_address.index = -1;
    base_address.scale = 0;
    base = gen_lea_modrm_1(s, base_address);
    if (base != s->A0) {
        tcg_gen_mov_tl(tcg_ctx, s->A0, base);
    }
    if (s->aflag == MO_32) {
        tcg_gen_ext32u_tl(tcg_ctx, s->A0, s->A0);
    }

    if (address.index < 0) {
        tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
    } else {
        tcg_gen_mov_tl(tcg_ctx, s->T0,
                       tcg_ctx->cpu_regs[address.index]);
        if (s->aflag == MO_32) {
            tcg_gen_ext32u_tl(tcg_ctx, s->T0, s->T0);
        }
        if (address.scale) {
            tcg_gen_shli_tl(tcg_ctx, s->T0, s->T0, address.scale);
            if (s->aflag == MO_32) {
                tcg_gen_ext32u_tl(tcg_ctx, s->T0, s->T0);
            }
        }
    }

    desc = amx_memory_desc(s, address, tile, store);
    gen_helper_amx_tileloadstore(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->T0,
                                 tcg_const_i32(tcg_ctx, desc),
                                 tcg_const_tl(tcg_ctx,
                                              s->pc_start - s->cs_base));
}

static AMXVexDecodeResult gen_vex_amx(CPUX86State *env, DisasContext *s,
                                      int b, int rex_r)
{
    const int mandatory =
        s->prefix & (PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ);
    int opcode;
    int modrm;

    if (b != 0x138 && b != 0x500) {
        return AMX_VEX_NOT_HANDLED;
    }
    opcode = translator_ldub(env->uc->tcg_ctx, env, s->pc);
    /* Keep ownership of the retired map-2 opcode 48 byte sequence so it
     * cannot alias another VEX decoder, but always reject it. */
    if (b == 0x138 && opcode == 0x48) {
        return AMX_VEX_INVALID;
    }
    if (b == 0x138 && opcode != 0x49 && opcode != 0x4a &&
        opcode != 0x4b && opcode != 0x5c && opcode != 0x5e &&
        opcode != 0x6c) {
        return AMX_VEX_NOT_HANDLED;
    }
    if (b == 0x500 && opcode != 0xfd) {
        return AMX_VEX_NOT_HANDLED;
    }

    (void)x86_ldub_code(env, s);
    if (!CODE64(s) || s->vex_l != 0 || s->vex_w) {
        return AMX_VEX_INVALID;
    }
    modrm = x86_ldub_code(env, s);
    if (!x86_vex_amx_owner_enabled(env, s, opcode, mandatory)) {
        return AMX_VEX_INVALID;
    }

    if (opcode == 0x49) {
        if (s->vex_v != 0) {
            return AMX_VEX_INVALID;
        }
        if (mandatory == 0) {
            if (modrm == 0xc0) {
                gen_helper_amx_tilerelease(s->uc->tcg_ctx,
                                           s->uc->tcg_ctx->cpu_env);
                return AMX_VEX_DECODED;
            }
            if ((modrm >> 6) == 3 || (modrm & 0x38) != 0) {
                return AMX_VEX_INVALID;
            }
            gen_amx_config_memory(env, s, modrm, false);
            return AMX_VEX_DECODED;
        }
        if (mandatory == PREFIX_DATA) {
            if ((modrm >> 6) == 3 || (modrm & 0x38) != 0) {
                return AMX_VEX_INVALID;
            }
            gen_amx_config_memory(env, s, modrm, true);
            return AMX_VEX_DECODED;
        }
        if (mandatory == PREFIX_REPNZ) {
            if ((modrm >> 6) != 3 || (modrm & 7) != 0 || rex_r) {
                return AMX_VEX_INVALID;
            }
            gen_helper_amx_tilezero(
                s->uc->tcg_ctx, s->uc->tcg_ctx->cpu_env,
                tcg_const_i32(s->uc->tcg_ctx, (modrm >> 3) & 7));
            return AMX_VEX_DECODED;
        }
        return AMX_VEX_INVALID;
    }

    if (opcode == 0x4a) {
        if (s->vex_v != 0 ||
            (mandatory != PREFIX_REPNZ && mandatory != PREFIX_DATA) ||
            (modrm >> 6) == 3 || (modrm & 7) != 4 || rex_r) {
            return AMX_VEX_INVALID;
        }
        gen_amx_tile_memory(env, s, modrm, (modrm >> 3) & 7, false);
        return AMX_VEX_DECODED;
    }

    if (opcode != 0x4b) {
        AMXComputeOp operation;
        const unsigned int dst = (modrm >> 3) & 7;
        const unsigned int src1 = modrm & 7;
        const unsigned int src2 = s->vex_v;
        uint32_t desc;

        if ((modrm >> 6) != 3 || src2 >= 8 || rex_r || REX_B(s) ||
            dst == src1 || dst == src2 || src1 == src2) {
            return AMX_VEX_INVALID;
        }

        switch (opcode) {
        case 0x5c:
            if (mandatory == PREFIX_REPZ) {
                operation = AMX_COMPUTE_TDPBF16PS;
            } else if (mandatory == PREFIX_REPNZ) {
                operation = AMX_COMPUTE_TDPFP16PS;
            } else {
                return AMX_VEX_INVALID;
            }
            break;
        case 0x5e:
            switch (mandatory) {
            case PREFIX_REPNZ:
                operation = AMX_COMPUTE_TDPBSSD;
                break;
            case PREFIX_REPZ:
                operation = AMX_COMPUTE_TDPBSUD;
                break;
            case PREFIX_DATA:
                operation = AMX_COMPUTE_TDPBUSD;
                break;
            case 0:
                operation = AMX_COMPUTE_TDPBUUD;
                break;
            default:
                return AMX_VEX_INVALID;
            }
            break;
        case 0x6c:
            if (mandatory == PREFIX_DATA) {
                operation = AMX_COMPUTE_TCMMIMFP16PS;
            } else if (mandatory == 0) {
                operation = AMX_COMPUTE_TCMMRLFP16PS;
            } else {
                return AMX_VEX_INVALID;
            }
            break;
        case 0xfd:
            switch (mandatory) {
            case 0:
                operation = AMX_COMPUTE_TDPBF8PS;
                break;
            case PREFIX_REPNZ:
                operation = AMX_COMPUTE_TDPBHF8PS;
                break;
            case PREFIX_REPZ:
                operation = AMX_COMPUTE_TDPHBF8PS;
                break;
            case PREFIX_DATA:
                operation = AMX_COMPUTE_TDPHF8PS;
                break;
            default:
                return AMX_VEX_INVALID;
            }
            break;
        default:
            g_assert_not_reached();
        }

        desc = (dst << AMX_COMPUTE_DST_SHIFT) |
               (src1 << AMX_COMPUTE_SRC1_SHIFT) |
               (src2 << AMX_COMPUTE_SRC2_SHIFT) |
               ((uint32_t)operation << AMX_COMPUTE_OP_SHIFT);
        gen_helper_amx_compute(s->uc->tcg_ctx, s->uc->tcg_ctx->cpu_env,
                               tcg_const_i32(s->uc->tcg_ctx, desc));
        return AMX_VEX_DECODED;
    }

    if (s->vex_v != 0 ||
        (mandatory != PREFIX_REPNZ && mandatory != PREFIX_DATA &&
         mandatory != PREFIX_REPZ)) {
        return AMX_VEX_INVALID;
    }
    if ((modrm >> 6) == 3 || (modrm & 7) != 4 || rex_r) {
        return AMX_VEX_INVALID;
    }
    gen_amx_tile_memory(env, s, modrm, (modrm >> 3) & 7,
                        mandatory == PREFIX_REPZ);
    return AMX_VEX_DECODED;
}
#endif

#ifdef TARGET_X86_64
static bool apx_f_enabled(const DisasContext *s)
{
    return (s->cpuid_7_1_edx_features & CPUID_7_1_EDX_APX_F) &&
           (s->flags & HF_APX_EN_MASK);
}

static bool apx_nci_enabled(const DisasContext *s)
{
    return apx_f_enabled(s) &&
           (s->cpuid_29_0_ebx_features & CPUID_29_0_EBX_NCI_NDD_NF);
}

typedef enum APXEVEXDecodeResult {
    APX_EVEX_NOT_HANDLED,
    APX_EVEX_DECODED,
    APX_EVEX_INVALID,
} APXEVEXDecodeResult;

static bool gen_apx_evex_register(CPUX86State *env, DisasContext *s,
                                  int rex_byte, int p0, int p1, int p2,
                                  int opcode);
static APXEVEXDecodeResult gen_apx_evex_bmi_register(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode);
static APXEVEXDecodeResult gen_apx_evex_kmov(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode);
static APXEVEXDecodeResult gen_apx_evex_direct_move(
    CPUX86State *env, DisasContext *s, int rex_byte, int p0, int p1, int p2,
    int opcode);
static APXEVEXDecodeResult gen_apx_evex_conditional(
    CPUX86State *env, DisasContext *s, int rex_byte, int p0, int p1, int p2,
    int opcode);
static APXEVEXDecodeResult gen_apx_evex_atomic(
    CPUX86State *env, DisasContext *s, int rex_byte, int p0, int p1, int p2,
    int opcode);
static APXEVEXDecodeResult gen_apx_evex_msr(
    CPUX86State *env, DisasContext *s, int rex_byte, int p0, int p1, int p2,
    int opcode);
static APXEVEXDecodeResult gen_apx_evex_system(
    CPUX86State *env, DisasContext *s, int rex_byte, int p0, int p1, int p2,
    int opcode);
static APXEVEXDecodeResult gen_evex_scalar_lane(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode);
static APXEVEXDecodeResult gen_evex_broadcast_lane(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode);
static APXEVEXDecodeResult gen_evex_gpr_vector_move(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode);
static APXEVEXDecodeResult gen_evex_half_move(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode);
static APXEVEXDecodeResult gen_evex_scalar_move(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode);
static APXEVEXDecodeResult gen_evex_non_temporal_move(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode);
static bool gen_evex_crypto(CPUX86State *env, DisasContext *s,
                            int p0, int p1, int p2, int opcode);
static bool gen_evex_dbpsadbw(CPUX86State *env, DisasContext *s,
                              int p0, int p1, int p2, int opcode);
static bool gen_evex_four_memory_ops(CPUX86State *env, DisasContext *s,
                                     int p0, int p1, int p2, int opcode);
static bool gen_evex_fpclass(CPUX86State *env, DisasContext *s,
                             int p0, int p1, int p2, int opcode);
static bool gen_evex_comi(CPUX86State *env, DisasContext *s,
                          int p0, int p1, int p2, int opcode);
static bool gen_evex_fcmp(CPUX86State *env, DisasContext *s,
                          int p0, int p1, int p2, int opcode);
static bool gen_apx_push2_pop2(CPUX86State *env, DisasContext *s,
                               int rex_byte, int p0, int p1, int p2,
                               int opcode);
static bool gen_apx_evex_setcc(CPUX86State *env, DisasContext *s,
                               int rex_byte, int p0, int p1, int p2,
                               int opcode);
static bool gen_apx_evex_cmovcc(CPUX86State *env, DisasContext *s,
                                int rex_byte, int p0, int p1, int p2,
                                int opcode);
static int apx_evex_reg_field(int p0, int modrm);
static int apx_evex_rm_field(int p0, int modrm);
static int evex_vector_rm_field(int p0, int modrm);
static bool gen_evex_memory_address_details(
    CPUX86State *env, DisasContext *s, int p0, int p1, int modrm,
    int disp8_scale, bool *uses_egpr);
static bool gen_evex_memory_address(CPUX86State *env, DisasContext *s,
                                    int p0, int p1, int modrm,
                                    int disp8_scale, int mask_reg,
                                    int active_elements, int access_bytes,
                                    bool tuple_access);
static void gen_evex_extended_memory_address(CPUX86State *env,
                                             DisasContext *s, int p0,
                                             int p1, int modrm,
                                             int disp8_scale,
                                             int access_bytes);
#endif

static uint32_t evex_vmovdqu_desc(int reg, int src, int element_shift,
                                  int vector_length, int mask_reg, bool zero)
{
    return (reg << EVEX_VMOV_REG_SHIFT) |
           (src << EVEX_VMOV_SRC_SHIFT) |
           (element_shift << EVEX_VMOV_ELEM_SHIFT) |
           (vector_length << EVEX_VMOV_VL_SHIFT) |
           (mask_reg << EVEX_VMOV_MASK_SHIFT) |
           (zero ? EVEX_VMOV_ZERO : 0);
}

static uint32_t evex_packed_int_desc(int dst, int src1, int src2,
                                     int element_shift, int vector_length,
                                     int mask_reg, bool zero,
                                     EVEXPackedIntOp operation)
{
    return (dst << EVEX_PINT_DST_SHIFT) |
           (src1 << EVEX_PINT_SRC1_SHIFT) |
           (src2 << EVEX_PINT_SRC2_SHIFT) |
           (element_shift << EVEX_PINT_ELEM_SHIFT) |
           (vector_length << EVEX_PINT_VL_SHIFT) |
           (mask_reg << EVEX_PINT_MASK_SHIFT) |
           (zero ? EVEX_PINT_ZERO : 0) |
           ((uint32_t)operation << EVEX_PINT_OP_SHIFT);
}

static uint32_t evex_packed_shift_desc(int dst, int src1, int src2,
                                       int element_shift, int vector_length,
                                       int mask_reg, bool zero,
                                       EVEXPackedShiftOp operation,
                                       bool variable)
{
    return (dst << EVEX_SHIFT_DST_SHIFT) |
           (src1 << EVEX_SHIFT_SRC1_SHIFT) |
           (src2 << EVEX_SHIFT_SRC2_SHIFT) |
           (element_shift << EVEX_SHIFT_ELEM_SHIFT) |
           (vector_length << EVEX_SHIFT_VL_SHIFT) |
           (mask_reg << EVEX_SHIFT_MASK_SHIFT) |
           (zero ? EVEX_SHIFT_ZERO : 0) |
           ((uint32_t)operation << EVEX_SHIFT_OP_SHIFT) |
           (variable ? EVEX_SHIFT_VARIABLE : 0);
}

static uint32_t evex_bit_shuffle_desc(int dst, int src1, int src2,
                                      int vector_length, int mask_reg)
{
    return (dst << EVEX_BITSHUF_DST_SHIFT) |
           (src1 << EVEX_BITSHUF_SRC1_SHIFT) |
           (src2 << EVEX_BITSHUF_SRC2_SHIFT) |
           (vector_length << EVEX_BITSHUF_VL_SHIFT) |
           (mask_reg << EVEX_BITSHUF_MASK_SHIFT);
}

static uint32_t evex_mask_test_desc(int dst, int src1, int src2,
                                    int element_shift, int vector_length,
                                    int mask_reg, bool negated)
{
    return (dst << EVEX_MTEST_DST_SHIFT) |
           (src1 << EVEX_MTEST_SRC1_SHIFT) |
           (src2 << EVEX_MTEST_SRC2_SHIFT) |
           (element_shift << EVEX_MTEST_ELEM_SHIFT) |
           (vector_length << EVEX_MTEST_VL_SHIFT) |
           (mask_reg << EVEX_MTEST_MASK_SHIFT) |
           (negated ? EVEX_MTEST_NEGATED : 0);
}

static uint32_t evex_ternlog_desc(int dst, int src1, int src2,
                                  int element_shift, int vector_length,
                                  int mask_reg, bool zero)
{
    return (dst << EVEX_TLOG_DST_SHIFT) |
           (src1 << EVEX_TLOG_SRC1_SHIFT) |
           (src2 << EVEX_TLOG_SRC2_SHIFT) |
           (element_shift << EVEX_TLOG_ELEM_SHIFT) |
           (vector_length << EVEX_TLOG_VL_SHIFT) |
           (mask_reg << EVEX_TLOG_MASK_SHIFT) |
           (zero ? EVEX_TLOG_ZERO : 0);
}

static uint32_t evex_shuffle_imm_desc(int dst, int src, int vector_length,
                                      int mask_reg, bool zero,
                                      unsigned int mandatory)
{
    return (dst << EVEX_SHUF_DST_SHIFT) | (src << EVEX_SHUF_SRC_SHIFT) |
           (vector_length << EVEX_SHUF_VL_SHIFT) |
           (mask_reg << EVEX_SHUF_MASK_SHIFT) |
           (zero ? EVEX_SHUF_ZERO : 0) |
           (mandatory == 2 ? EVEX_SHUF_HIGH_WORDS : 0) |
           (mandatory == 1 ? EVEX_SHUF_DWORDS : 0);
}

static uint32_t evex_lane_int_desc(int dst, int src1, int src2,
                                   int vector_length, int mask_reg, bool zero,
                                   EVEXLaneIntOp operation)
{
    return (dst << EVEX_LANE_DST_SHIFT) |
           (src1 << EVEX_LANE_SRC1_SHIFT) |
           (src2 << EVEX_LANE_SRC2_SHIFT) |
           (vector_length << EVEX_LANE_VL_SHIFT) |
           (mask_reg << EVEX_LANE_MASK_SHIFT) |
           (zero ? EVEX_LANE_ZERO : 0) |
           ((uint32_t)operation << EVEX_LANE_OP_SHIFT);
}

static uint32_t evex_crypto_desc(int dst, int src1, int src2,
                                 int vector_length, int mask_reg, bool zero,
                                 bool broadcast, EVEXCryptoOp operation)
{
    return (dst << EVEX_CRYPTO_DST_SHIFT) |
           (src1 << EVEX_CRYPTO_SRC1_SHIFT) |
           (src2 << EVEX_CRYPTO_SRC2_SHIFT) |
           (vector_length << EVEX_CRYPTO_VL_SHIFT) |
           (mask_reg << EVEX_CRYPTO_MASK_SHIFT) |
           (zero ? EVEX_CRYPTO_ZERO : 0) |
           (broadcast ? EVEX_CRYPTO_BROADCAST : 0) |
           ((uint32_t)operation << EVEX_CRYPTO_OP_SHIFT);
}

static uint32_t evex_four_desc(int dst, int source, int mask_reg, bool zero,
                               bool scalar, bool negative, bool saturating)
{
    return (dst << EVEX_FOUR_DST_SHIFT) |
           (source << EVEX_FOUR_SRC_SHIFT) |
           (mask_reg << EVEX_FOUR_MASK_SHIFT) |
           (zero ? EVEX_FOUR_ZERO : 0) |
           (scalar ? EVEX_FOUR_SCALAR : 0) |
           (negative ? EVEX_FOUR_NEGATIVE : 0) |
           (saturating ? EVEX_FOUR_SATURATING : 0);
}

static uint32_t evex_fpclass_desc(int dst, int src, int vector_length,
                                  int mask_reg, bool is_double, bool scalar,
                                  bool broadcast)
{
    return (dst << EVEX_FPCLASS_DST_SHIFT) |
           (src << EVEX_FPCLASS_SRC_SHIFT) |
           (vector_length << EVEX_FPCLASS_VL_SHIFT) |
           (mask_reg << EVEX_FPCLASS_MASK_SHIFT) |
           (is_double ? EVEX_FPCLASS_DOUBLE : 0) |
           (scalar ? EVEX_FPCLASS_SCALAR : 0) |
           (broadcast ? EVEX_FPCLASS_BROADCAST : 0);
}

static uint32_t evex_comi_desc(int left, int right, bool is_double,
                               bool quiet, bool sae)
{
    return (left << EVEX_COMI_LEFT_SHIFT) |
           (right << EVEX_COMI_RIGHT_SHIFT) |
           (is_double ? EVEX_COMI_DOUBLE : 0) |
           (quiet ? EVEX_COMI_QUIET : 0) |
           (sae ? EVEX_COMI_SAE : 0);
}

static uint32_t evex_fcmp_desc(int dst, int src1, int src2,
                               int vector_length, int mask_reg,
                               bool is_double, bool scalar, bool sae,
                               bool broadcast)
{
    return (dst << EVEX_FCMP_DST_SHIFT) |
           (src1 << EVEX_FCMP_SRC1_SHIFT) |
           (src2 << EVEX_FCMP_SRC2_SHIFT) |
           (vector_length << EVEX_FCMP_VL_SHIFT) |
           (mask_reg << EVEX_FCMP_MASK_SHIFT) |
           (is_double ? EVEX_FCMP_DOUBLE : 0) |
           (scalar ? EVEX_FCMP_SCALAR : 0) |
           (sae ? EVEX_FCMP_SAE : 0) |
           (broadcast ? EVEX_FCMP_BROADCAST : 0);
}

static uint32_t evex_mask_convert_desc(int dst, int src, int element_shift,
                                       int vector_length,
                                       EVEXMaskConvertOp operation)
{
    return (dst << EVEX_MCONV_DST_SHIFT) | (src << EVEX_MCONV_SRC_SHIFT) |
           (element_shift << EVEX_MCONV_ELEM_SHIFT) |
           (vector_length << EVEX_MCONV_VL_SHIFT) |
           ((uint32_t)operation << EVEX_MCONV_OP_SHIFT);
}

static uint32_t evex_widen_desc(int dst, int src, int input_shift,
                                int output_shift, int vector_length,
                                int mask_reg, bool zero, bool sign_extend)
{
    return (dst << EVEX_WIDEN_DST_SHIFT) | (src << EVEX_WIDEN_SRC_SHIFT) |
           (input_shift << EVEX_WIDEN_INPUT_SHIFT) |
           (output_shift << EVEX_WIDEN_OUTPUT_SHIFT) |
           (vector_length << EVEX_WIDEN_VL_SHIFT) |
           (mask_reg << EVEX_WIDEN_MASK_SHIFT) |
           (zero ? EVEX_WIDEN_ZERO : 0) |
           (sign_extend ? EVEX_WIDEN_SIGNED : 0);
}

static uint32_t evex_narrow_desc(int dst, int src, int input_shift,
                                 int output_shift, int vector_length,
                                 int mask_reg, bool zero,
                                 EVEXNarrowMode mode)
{
    return (dst << EVEX_NARROW_DST_SHIFT) | (src << EVEX_NARROW_SRC_SHIFT) |
           (input_shift << EVEX_NARROW_INPUT_SHIFT) |
           (output_shift << EVEX_NARROW_OUTPUT_SHIFT) |
           (vector_length << EVEX_NARROW_VL_SHIFT) |
           (mask_reg << EVEX_NARROW_MASK_SHIFT) |
           (zero ? EVEX_NARROW_ZERO : 0) |
           ((uint32_t)mode << EVEX_NARROW_MODE_SHIFT);
}

static uint32_t evex_packed_compare_desc(int dst, int src1, int src2,
                                         int element_shift, int vector_length,
                                         int mask_reg, int predicate,
                                         bool unsigned_compare)
{
    return (dst << EVEX_PCMP_DST_SHIFT) | (src1 << EVEX_PCMP_SRC1_SHIFT) |
           (src2 << EVEX_PCMP_SRC2_SHIFT) |
           (element_shift << EVEX_PCMP_ELEM_SHIFT) |
           (vector_length << EVEX_PCMP_VL_SHIFT) |
           (mask_reg << EVEX_PCMP_MASK_SHIFT) |
           (predicate << EVEX_PCMP_PRED_SHIFT) |
           (unsigned_compare ? EVEX_PCMP_UNSIGNED : 0);
}

static uint32_t evex_compress_expand_desc(int dst, int src,
                                           int element_shift,
                                           int vector_length, int mask_reg,
                                           bool zero, bool expand)
{
    return (dst << EVEX_CE_DST_SHIFT) | (src << EVEX_CE_SRC_SHIFT) |
           (element_shift << EVEX_CE_ELEM_SHIFT) |
           (vector_length << EVEX_CE_VL_SHIFT) |
           (mask_reg << EVEX_CE_MASK_SHIFT) |
           (zero ? EVEX_CE_ZERO : 0) |
           (expand ? EVEX_CE_EXPAND : 0);
}

static uint32_t evex_approx14_desc(int dst, int src1, int src2,
                                   int vector_length, int mask_reg,
                                   bool is_double, bool rsqrt, bool scalar,
                                   bool zero, bool broadcast)
{
    return (dst << EVEX_APPROX14_DST_SHIFT) |
           (src1 << EVEX_APPROX14_SRC1_SHIFT) |
           (src2 << EVEX_APPROX14_SRC2_SHIFT) |
           (vector_length << EVEX_APPROX14_VL_SHIFT) |
           (mask_reg << EVEX_APPROX14_MASK_SHIFT) |
           (is_double ? EVEX_APPROX14_DOUBLE : 0) |
           (rsqrt ? EVEX_APPROX14_RSQRT : 0) |
           (scalar ? EVEX_APPROX14_SCALAR : 0) |
           (zero ? EVEX_APPROX14_ZERO : 0) |
           (broadcast ? EVEX_APPROX14_BROADCAST : 0);
}

static uint32_t evex_fp_arith_desc(int dst, int src1, int src2,
                                   int vector_length, int mask_reg,
                                   EVEXFPArithOp operation, bool is_double,
                                   bool scalar, bool zero, bool sae,
                                   unsigned int rounding_mode,
                                   bool broadcast)
{
    return (dst << EVEX_FP_ARITH_DST_SHIFT) |
           (src1 << EVEX_FP_ARITH_SRC1_SHIFT) |
           (src2 << EVEX_FP_ARITH_SRC2_SHIFT) |
           (vector_length << EVEX_FP_ARITH_VL_SHIFT) |
           (mask_reg << EVEX_FP_ARITH_MASK_SHIFT) |
           ((uint32_t)operation << EVEX_FP_ARITH_OP_SHIFT) |
           (is_double ? EVEX_FP_ARITH_DOUBLE : 0) |
           (scalar ? EVEX_FP_ARITH_SCALAR : 0) |
           (zero ? EVEX_FP_ARITH_ZERO : 0) |
           (sae ? EVEX_FP_ARITH_SAE : 0) |
           ((rounding_mode & EVEX_FP_ARITH_RC_MASK)
            << EVEX_FP_ARITH_RC_SHIFT) |
           (broadcast ? EVEX_FP_ARITH_BROADCAST : 0);
}

static uint32_t evex_fma_desc(int dst, int src1, int src2, int vector_length,
                              int mask_reg, unsigned int permutation,
                              unsigned int variant, bool is_double,
                              bool scalar, bool zero, bool sae,
                              unsigned int rounding_mode, bool broadcast)
{
    return (dst << EVEX_FMA_DST_SHIFT) | (src1 << EVEX_FMA_SRC1_SHIFT) |
           (src2 << EVEX_FMA_SRC2_SHIFT) |
           (vector_length << EVEX_FMA_VL_SHIFT) |
           (mask_reg << EVEX_FMA_MASK_SHIFT) |
           ((permutation & 3) << EVEX_FMA_PERM_SHIFT) |
           ((variant & EVEX_FMA_VARIANT_MASK) << EVEX_FMA_VARIANT_SHIFT) |
           (is_double ? EVEX_FMA_DOUBLE : 0) |
           (scalar ? EVEX_FMA_SCALAR : 0) |
           (zero ? EVEX_FMA_ZERO : 0) | (sae ? EVEX_FMA_SAE : 0) |
           ((rounding_mode & EVEX_FMA_RC_MASK) << EVEX_FMA_RC_SHIFT) |
           (broadcast ? EVEX_FMA_BROADCAST : 0);
}

static uint32_t evex_convert_desc(int dst, int src, int vector_length,
                                  int mask_reg, EVEXConvertType src_type,
                                  EVEXConvertType dst_type, bool zero,
                                  bool truncate, bool sae,
                                  bool embedded_rounding,
                                  unsigned int rounding_mode, bool broadcast)
{
    return (dst << EVEX_CVT_DST_SHIFT) | (src << EVEX_CVT_SRC_SHIFT) |
           (vector_length << EVEX_CVT_VL_SHIFT) |
           (mask_reg << EVEX_CVT_MASK_SHIFT) |
           ((uint32_t)src_type << EVEX_CVT_SRC_TYPE_SHIFT) |
           ((uint32_t)dst_type << EVEX_CVT_DST_TYPE_SHIFT) |
           (zero ? EVEX_CVT_ZERO : 0) |
           (truncate ? EVEX_CVT_TRUNCATE : 0) |
           (sae ? EVEX_CVT_SAE : 0) |
           (embedded_rounding ? EVEX_CVT_EMBEDDED_RC : 0) |
           ((rounding_mode & EVEX_CVT_RC_MASK) << EVEX_CVT_RC_SHIFT) |
           (broadcast ? EVEX_CVT_BROADCAST : 0);
}

static uint32_t evex_scalar_convert_desc(
    int dst, int src1, int src2, int mask_reg, EVEXConvertType src_type,
    EVEXConvertType dst_type, bool zero, bool truncate, bool sae,
    bool embedded_rounding, unsigned int rounding_mode, bool gpr_source,
    bool gpr_destination)
{
    return (dst << EVEX_SCVT_DST_SHIFT) |
           (src1 << EVEX_SCVT_SRC1_SHIFT) |
           (src2 << EVEX_SCVT_SRC2_SHIFT) |
           (mask_reg << EVEX_SCVT_MASK_SHIFT) |
           ((uint32_t)src_type << EVEX_SCVT_SRC_TYPE_SHIFT) |
           ((uint32_t)dst_type << EVEX_SCVT_DST_TYPE_SHIFT) |
           (zero ? EVEX_SCVT_ZERO : 0) |
           (truncate ? EVEX_SCVT_TRUNCATE : 0) |
           (sae ? EVEX_SCVT_SAE : 0) |
           (embedded_rounding ? EVEX_SCVT_EMBEDDED_RC : 0) |
           ((rounding_mode & EVEX_SCVT_RC_MASK) << EVEX_SCVT_RC_SHIFT) |
           (gpr_source ? EVEX_SCVT_GPR_SOURCE : 0) |
           (gpr_destination ? EVEX_SCVT_GPR_DESTINATION : 0);
}

static uint32_t evex_range_desc(int dst, int src1, int src2, int vector_length,
                                int mask_reg, unsigned int immediate,
                                bool is_double, bool scalar, bool zero,
                                bool sae, bool broadcast)
{
    return (dst << EVEX_RANGE_DST_SHIFT) | (src1 << EVEX_RANGE_SRC1_SHIFT) |
           (src2 << EVEX_RANGE_SRC2_SHIFT) |
           (vector_length << EVEX_RANGE_VL_SHIFT) |
           (mask_reg << EVEX_RANGE_MASK_SHIFT) |
           (immediate << EVEX_RANGE_IMM_SHIFT) |
           (is_double ? EVEX_RANGE_DOUBLE : 0) |
           (scalar ? EVEX_RANGE_SCALAR : 0) | (zero ? EVEX_RANGE_ZERO : 0) |
           (sae ? EVEX_RANGE_SAE : 0) | (broadcast ? EVEX_RANGE_BROADCAST : 0);
}

static uint32_t evex_fp_transform_desc(
    int dst, int src1, int src2, int vector_length, int mask_reg,
    EVEXFPTransformKind kind, bool is_double, bool scalar, bool zero,
    bool sae, bool broadcast)
{
    return (dst << EVEX_FP_TRANSFORM_DST_SHIFT) |
           (src1 << EVEX_FP_TRANSFORM_SRC1_SHIFT) |
           (src2 << EVEX_FP_TRANSFORM_SRC2_SHIFT) |
           (vector_length << EVEX_FP_TRANSFORM_VL_SHIFT) |
           (mask_reg << EVEX_FP_TRANSFORM_MASK_SHIFT) |
           ((uint32_t)kind << EVEX_FP_TRANSFORM_KIND_SHIFT) |
           (is_double ? EVEX_FP_TRANSFORM_DOUBLE : 0) |
           (scalar ? EVEX_FP_TRANSFORM_SCALAR : 0) |
           (zero ? EVEX_FP_TRANSFORM_ZERO : 0) |
           (sae ? EVEX_FP_TRANSFORM_SAE : 0) |
           (broadcast ? EVEX_FP_TRANSFORM_BROADCAST : 0);
}

static uint32_t evex_get_fp_desc(int dst, int src1, int src2,
                                 int vector_length, int mask_reg,
                                 unsigned int immediate, bool is_double,
                                 bool scalar, bool zero, bool sae,
                                 bool broadcast, bool mantissa)
{
    return (dst << EVEX_GET_FP_DST_SHIFT) |
           (src1 << EVEX_GET_FP_SRC1_SHIFT) |
           (src2 << EVEX_GET_FP_SRC2_SHIFT) |
           (vector_length << EVEX_GET_FP_VL_SHIFT) |
           (mask_reg << EVEX_GET_FP_MASK_SHIFT) |
           ((immediate & 15) << EVEX_GET_FP_IMM_SHIFT) |
           (is_double ? EVEX_GET_FP_DOUBLE : 0) |
           (scalar ? EVEX_GET_FP_SCALAR : 0) |
           (zero ? EVEX_GET_FP_ZERO : 0) |
           (sae ? EVEX_GET_FP_SAE : 0) |
           (broadcast ? EVEX_GET_FP_BROADCAST : 0) |
           (mantissa ? EVEX_GET_FP_MANTISSA : 0);
}

static uint32_t evex_scalef_desc(int dst, int src1, int src2, int vector_length,
                                 int mask_reg, unsigned int rounding_mode,
                                 bool is_double, bool scalar, bool zero,
                                 bool sae, bool broadcast)
{
    return (dst << EVEX_SCALEF_DST_SHIFT) | (src1 << EVEX_SCALEF_SRC1_SHIFT) |
           (src2 << EVEX_SCALEF_SRC2_SHIFT) |
           (vector_length << EVEX_SCALEF_VL_SHIFT) |
           (mask_reg << EVEX_SCALEF_MASK_SHIFT) |
           (is_double ? EVEX_SCALEF_DOUBLE : 0) |
           (scalar ? EVEX_SCALEF_SCALAR : 0) | (zero ? EVEX_SCALEF_ZERO : 0) |
           (sae ? EVEX_SCALEF_SAE : 0) |
           (broadcast ? EVEX_SCALEF_BROADCAST : 0) |
           (rounding_mode << EVEX_SCALEF_RC_SHIFT);
}

static uint32_t evex_approx28_desc(int dst, int src1, int src2, int mask_reg,
                                   bool is_double, bool rsqrt, bool exp2,
                                   bool scalar, bool zero, bool sae,
                                   bool broadcast)
{
    return (dst << EVEX_APPROX28_DST_SHIFT) |
           (src1 << EVEX_APPROX28_SRC1_SHIFT) |
           (src2 << EVEX_APPROX28_SRC2_SHIFT) |
           (mask_reg << EVEX_APPROX28_MASK_SHIFT) |
           (is_double ? EVEX_APPROX28_DOUBLE : 0) |
           (rsqrt ? EVEX_APPROX28_RSQRT : 0) |
           (exp2 ? EVEX_APPROX28_EXP2 : 0) |
           (scalar ? EVEX_APPROX28_SCALAR : 0) |
           (zero ? EVEX_APPROX28_ZERO : 0) |
           (sae ? EVEX_APPROX28_SAE : 0) |
           (broadcast ? EVEX_APPROX28_BROADCAST : 0);
}

static bool gen_evex_packed_compare_reg(CPUX86State *env, DisasContext *s,
                                        int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool w = (p1 & 0x80) != 0;
    int element_shift;
    bool unsigned_compare;
    int vector_length;
    int mask_reg;
    int modrm;
    int dst, src1, src2;
    int predicate;

    if ((p0 & 3) != 3 || (p1 & 3) != 1) {
        return false;
    }

    switch (opcode) {
    case 0x3f: /* VPCMPB/VPCMPW */
        element_shift = w ? 1 : 0;
        unsigned_compare = false;
        break;
    case 0x1f: /* VPCMPD/VPCMPQ */
        element_shift = w ? 3 : 2;
        unsigned_compare = false;
        break;
    case 0x3e: /* VPCMPUB/VPCMPUW */
        element_shift = w ? 1 : 0;
        unsigned_compare = true;
        break;
    case 0x1e: /* VPCMPUD/VPCMPUQ */
        element_shift = w ? 3 : 2;
        unsigned_compare = true;
        break;
    default:
        return false;
    }

    vector_length = (p2 >> 5) & 3;
    mask_reg = p2 & 7;
    /* K destinations are never extended and use zeroing writemasking only.
     * EVEX.b is reserved for this register-only slice. */
    if ((p0 & 0x90) != 0x90 || vector_length == 3 || (p2 & 0x90)) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return false;
    }
    predicate = x86_ldub_code(env, s);
    if (predicate & ~7) {
        return false;
    }
    if (!x86_evex_require_features(
            s,
            (element_shift < 2 ? CPUID_7_0_EBX_AVX512BW : 0) |
                (vector_length != 2 ? CPUID_7_0_EBX_AVX512VL : 0),
            0, 0)) {
        return true;
    }

    dst = (modrm >> 3) & 7;
    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }
    src1 = (~p1 >> 3) & 15;
    if (!(p2 & 0x08)) {
        src1 |= 16;
    }

    gen_helper_evex_packed_compare_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_packed_compare_desc(dst, src1, src2, element_shift,
                                               vector_length, mask_reg,
                                               predicate, unsigned_compare)));
    return true;
}

static bool gen_evex_legacy_compare_reg(CPUX86State *env, DisasContext *s,
                                        int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int map = p0 & 3;
    const bool w = (p1 & 0x80) != 0;
    int element_shift;
    int predicate;
    int vector_length;
    int modrm;
    int dst, src1, src2;

    if ((p1 & 3) != 1 || (p0 & 0x90) != 0x90 || (p2 & 0x90) ||
        ((p2 >> 5) & 3) == 3) {
        return false;
    }

    if (map == 1) {
        switch (opcode) {
        case 0x74:
        case 0x64:
            element_shift = 0;
            break;
        case 0x75:
        case 0x65:
            element_shift = 1;
            break;
        case 0x76:
        case 0x66:
            if (w) {
                return false;
            }
            element_shift = 2;
            break;
        default:
            return false;
        }
        predicate = opcode >= 0x74 ? 0 : 6;
    } else if (map == 2 && w && (opcode == 0x29 || opcode == 0x37)) {
        element_shift = 3;
        predicate = opcode == 0x29 ? 0 : 6;
    } else {
        return false;
    }

    vector_length = (p2 >> 5) & 3;
    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return false;
    }
    if (!x86_evex_require_features(
            s,
            (element_shift < 2 ? CPUID_7_0_EBX_AVX512BW : 0) |
                (vector_length != 2 ? CPUID_7_0_EBX_AVX512VL : 0),
            0, 0)) {
        return true;
    }
    dst = (modrm >> 3) & 7;
    src1 = (~p1 >> 3) & 15;
    if (!(p2 & 0x08)) {
        src1 |= 16;
    }
    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }

    gen_helper_evex_packed_compare_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_packed_compare_desc(dst, src1, src2, element_shift,
                                               vector_length, p2 & 7,
                                               predicate, false)));
    return true;
}

static bool gen_evex_packed_int_reg(CPUX86State *env, DisasContext *s,
                                    int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int map = p0 & 3;
    const unsigned int mandatory = p1 & 3;
    const bool w = (p1 & 0x80) != 0;
    const bool float_logic =
        map == 1 && opcode >= 0x54 && opcode <= 0x57 &&
        ((w && mandatory == 1) || (!w && mandatory == 0));
    int element_shift;
    EVEXPackedIntOp operation;
    bool unary = false;
    bool no_xmm = false;
    int modrm;
    int dst, src1, src2;
    int vector_length;
    int mask_reg;
    bool zero;
    uint32_t required_ebx = 0;
    uint32_t required_ecx = 0;

    /* These operations require 66.0F or 66.0F38.  EVEX.b has only
     * memory-broadcast meaning for the forms that define it; this
     * register-only slice rejects it before emitting any state change. */
    if ((!float_logic && mandatory != 1) || (p2 & 0x10)) {
        return false;
    }

    if (map == 1) {
        switch (opcode) {
        case 0x54: /* VANDPS/VANDPD */
            if (!float_logic) {
                return false;
            }
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_AND;
            break;
        case 0x55: /* VANDNPS/VANDNPD */
            if (!float_logic) {
                return false;
            }
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_AND_NOT;
            break;
        case 0x56: /* VORPS/VORPD */
            if (!float_logic) {
                return false;
            }
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_OR;
            break;
        case 0x57: /* VXORPS/VXORPD */
            if (!float_logic) {
                return false;
            }
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_XOR;
            break;
        case 0xfc: /* VPADDB (WIG) */
            element_shift = 0;
            operation = EVEX_PINT_ADD;
            break;
        case 0xfd: /* VPADDW (WIG) */
            element_shift = 1;
            operation = EVEX_PINT_ADD;
            break;
        case 0xfe: /* VPADDD */
            if (w) {
                return false;
            }
            element_shift = 2;
            operation = EVEX_PINT_ADD;
            break;
        case 0xd4: /* VPADDQ */
            if (!w) {
                return false;
            }
            element_shift = 3;
            operation = EVEX_PINT_ADD;
            break;
        case 0xf8: /* VPSUBB (WIG) */
            element_shift = 0;
            operation = EVEX_PINT_SUB;
            break;
        case 0xf9: /* VPSUBW (WIG) */
            element_shift = 1;
            operation = EVEX_PINT_SUB;
            break;
        case 0xfa: /* VPSUBD */
            if (w) {
                return false;
            }
            element_shift = 2;
            operation = EVEX_PINT_SUB;
            break;
        case 0xfb: /* VPSUBQ */
            if (!w) {
                return false;
            }
            element_shift = 3;
            operation = EVEX_PINT_SUB;
            break;
        case 0xec: /* VPADDSB (WIG) */
            element_shift = 0;
            operation = EVEX_PINT_SAT_ADD_SIGNED;
            break;
        case 0xed: /* VPADDSW (WIG) */
            element_shift = 1;
            operation = EVEX_PINT_SAT_ADD_SIGNED;
            break;
        case 0xdc: /* VPADDUSB (WIG) */
            element_shift = 0;
            operation = EVEX_PINT_SAT_ADD_UNSIGNED;
            break;
        case 0xdd: /* VPADDUSW (WIG) */
            element_shift = 1;
            operation = EVEX_PINT_SAT_ADD_UNSIGNED;
            break;
        case 0xe8: /* VPSUBSB (WIG) */
            element_shift = 0;
            operation = EVEX_PINT_SAT_SUB_SIGNED;
            break;
        case 0xe9: /* VPSUBSW (WIG) */
            element_shift = 1;
            operation = EVEX_PINT_SAT_SUB_SIGNED;
            break;
        case 0xd8: /* VPSUBUSB (WIG) */
            element_shift = 0;
            operation = EVEX_PINT_SAT_SUB_UNSIGNED;
            break;
        case 0xd9: /* VPSUBUSW (WIG) */
            element_shift = 1;
            operation = EVEX_PINT_SAT_SUB_UNSIGNED;
            break;
        case 0xe0: /* VPAVGB (WIG) */
            element_shift = 0;
            operation = EVEX_PINT_AVG_UNSIGNED;
            break;
        case 0xe3: /* VPAVGW (WIG) */
            element_shift = 1;
            operation = EVEX_PINT_AVG_UNSIGNED;
            break;
        case 0xdb: /* VPANDD/VPANDQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_AND;
            break;
        case 0xdf: /* VPANDND/VPANDNQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_AND_NOT;
            break;
        case 0xeb: /* VPORD/VPORQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_OR;
            break;
        case 0xef: /* VPXORD/VPXORQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_XOR;
            break;
        case 0xea: /* VPMINSW (WIG) */
            element_shift = 1;
            operation = EVEX_PINT_MIN_SIGNED;
            break;
        case 0xda: /* VPMINUB (WIG) */
            element_shift = 0;
            operation = EVEX_PINT_MIN_UNSIGNED;
            break;
        case 0xee: /* VPMAXSW (WIG) */
            element_shift = 1;
            operation = EVEX_PINT_MAX_SIGNED;
            break;
        case 0xde: /* VPMAXUB (WIG) */
            element_shift = 0;
            operation = EVEX_PINT_MAX_UNSIGNED;
            break;
        case 0xd5: /* VPMULLW (WIG) */
            element_shift = 1;
            operation = EVEX_PINT_MUL_LOW;
            break;
        case 0xe4: /* VPMULHUW (WIG) */
            element_shift = 1;
            operation = EVEX_PINT_MUL_HIGH_UNSIGNED;
            break;
        case 0xe5: /* VPMULHW (WIG) */
            element_shift = 1;
            operation = EVEX_PINT_MUL_HIGH_SIGNED;
            break;
        case 0xf4: /* VPMULUDQ */
            if (!w) {
                return false;
            }
            element_shift = 3;
            operation = EVEX_PINT_MUL_DQ_UNSIGNED;
            break;
        default:
            return false;
        }
    } else if (map == 2) {
        switch (opcode) {
        case 0x18: /* VBROADCASTSS */
            if (w) {
                return false;
            }
            element_shift = 2;
            operation = EVEX_PINT_BROADCAST;
            unary = true;
            break;
        case 0x19: /* VBROADCASTSD (register source) */
            if (!w) {
                return false;
            }
            element_shift = 3;
            operation = EVEX_PINT_BROADCAST;
            unary = true;
            no_xmm = true;
            break;
        case 0x1c: /* VPABSB */
            if (w) {
                return false;
            }
            element_shift = 0;
            operation = EVEX_PINT_ABS;
            unary = true;
            break;
        case 0x1d: /* VPABSW */
            if (w) {
                return false;
            }
            element_shift = 1;
            operation = EVEX_PINT_ABS;
            unary = true;
            break;
        case 0x1e: /* VPABSD */
            if (w) {
                return false;
            }
            element_shift = 2;
            operation = EVEX_PINT_ABS;
            unary = true;
            break;
        case 0x1f: /* VPABSQ */
            if (!w) {
                return false;
            }
            element_shift = 3;
            operation = EVEX_PINT_ABS;
            unary = true;
            break;
        case 0x38: /* VPMINSB */
            if (w) {
                return false;
            }
            element_shift = 0;
            operation = EVEX_PINT_MIN_SIGNED;
            break;
        case 0x39: /* VPMINSD/VPMINSQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_MIN_SIGNED;
            break;
        case 0x3a: /* VPMINUW */
            if (w) {
                return false;
            }
            element_shift = 1;
            operation = EVEX_PINT_MIN_UNSIGNED;
            break;
        case 0x3b: /* VPMINUD/VPMINUQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_MIN_UNSIGNED;
            break;
        case 0x3c: /* VPMAXSB */
            if (w) {
                return false;
            }
            element_shift = 0;
            operation = EVEX_PINT_MAX_SIGNED;
            break;
        case 0x3d: /* VPMAXSD/VPMAXSQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_MAX_SIGNED;
            break;
        case 0x3e: /* VPMAXUW */
            if (w) {
                return false;
            }
            element_shift = 1;
            operation = EVEX_PINT_MAX_UNSIGNED;
            break;
        case 0x3f: /* VPMAXUD/VPMAXUQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_MAX_UNSIGNED;
            break;
        case 0x44: /* VPLZCNTD/VPLZCNTQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_LZCNT;
            unary = true;
            break;
        case 0x54: /* VPOPCNTB/VPOPCNTW */
            element_shift = w ? 1 : 0;
            operation = EVEX_PINT_POPCNT;
            unary = true;
            break;
        case 0x55: /* VPOPCNTD/VPOPCNTQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_POPCNT;
            unary = true;
            break;
        case 0x58: /* VPBROADCASTD */
            if (w) {
                return false;
            }
            element_shift = 2;
            operation = EVEX_PINT_BROADCAST;
            unary = true;
            break;
        case 0x59: /* VPBROADCASTQ */
            if (!w) {
                return false;
            }
            element_shift = 3;
            operation = EVEX_PINT_BROADCAST;
            unary = true;
            break;
        case 0x64: /* VPBLENDMD/VPBLENDMQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_BLEND;
            break;
        case 0x65: /* VBLENDMPS/VBLENDMPD */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_BLEND;
            break;
        case 0x66: /* VPBLENDMB/VPBLENDMW */
            element_shift = w ? 1 : 0;
            operation = EVEX_PINT_BLEND;
            break;
        case 0x78: /* VPBROADCASTB */
            if (w) {
                return false;
            }
            element_shift = 0;
            operation = EVEX_PINT_BROADCAST;
            unary = true;
            break;
        case 0x79: /* VPBROADCASTW */
            if (w) {
                return false;
            }
            element_shift = 1;
            operation = EVEX_PINT_BROADCAST;
            unary = true;
            break;
        case 0x0b: /* VPMULHRSW */
            if (w) {
                return false;
            }
            element_shift = 1;
            operation = EVEX_PINT_MUL_HRSW;
            break;
        case 0x28: /* VPMULDQ */
            if (!w) {
                return false;
            }
            element_shift = 3;
            operation = EVEX_PINT_MUL_DQ_SIGNED;
            break;
        case 0x40: /* VPMULLD/VPMULLQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_MUL_LOW;
            break;
        case 0x50: /* VPDPBUSD */
        case 0x51: /* VPDPBUSDS */
        case 0x52: /* VPDPWSSD */
        case 0x53: /* VPDPWSSDS */
            if (w) {
                return false;
            }
            element_shift = 2;
            operation = opcode == 0x50 ? EVEX_PINT_DOT_BYTE
                        : opcode == 0x51
                            ? EVEX_PINT_DOT_BYTE_SATURATE
                        : opcode == 0x52 ? EVEX_PINT_DOT_WORD
                                         : EVEX_PINT_DOT_WORD_SATURATE;
            break;
        case 0x83: /* VPMULTISHIFTQB */
            if (!w) {
                return false;
            }
            element_shift = 0;
            operation = EVEX_PINT_MULTISHIFT;
            break;
        case 0x0c: /* VPERMILPS (variable control) */
            if (w) {
                return false;
            }
            element_shift = 2;
            operation = EVEX_PINT_PERMUTE_IN_LANE;
            break;
        case 0x0d: /* VPERMILPD (variable control) */
            if (!w) {
                return false;
            }
            element_shift = 3;
            operation = EVEX_PINT_PERMUTE_IN_LANE;
            break;
        case 0x16: /* VPERMPS/VPERMPD */
        case 0x36: /* VPERMD/VPERMQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_PERMUTE;
            no_xmm = true;
            break;
        case 0x75: /* VPERMI2B/VPERMI2W */
            element_shift = w ? 1 : 0;
            operation = EVEX_PINT_PERMUTE_TWO_INDEX;
            break;
        case 0x76: /* VPERMI2D/VPERMI2Q */
        case 0x77: /* VPERMI2PS/VPERMI2PD */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_PERMUTE_TWO_INDEX;
            break;
        case 0x7d: /* VPERMT2B/VPERMT2W */
            element_shift = w ? 1 : 0;
            operation = EVEX_PINT_PERMUTE_TWO_TABLE;
            break;
        case 0x7e: /* VPERMT2D/VPERMT2Q */
        case 0x7f: /* VPERMT2PS/VPERMT2PD */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_PERMUTE_TWO_TABLE;
            break;
        case 0x8d: /* VPERMB/VPERMW */
            element_shift = w ? 1 : 0;
            operation = EVEX_PINT_PERMUTE;
            break;
        case 0xb4: /* VPMADD52LUQ */
        case 0xb5: /* VPMADD52HUQ */
            if (!w) {
                return false;
            }
            element_shift = 3;
            operation = opcode == 0xb4 ? EVEX_PINT_MADD52_LOW
                                       : EVEX_PINT_MADD52_HIGH;
            break;
        case 0xc4: /* VPCONFLICTD/VPCONFLICTQ */
            element_shift = w ? 3 : 2;
            operation = EVEX_PINT_CONFLICT;
            unary = true;
            break;
        default:
            return false;
        }
    } else {
        return false;
    }

    if (float_logic) {
        required_ebx |= CPUID_7_0_EBX_AVX512DQ;
    }
    if (map == 2) {
        switch (opcode) {
        case 0x44: /* VPLZCNTD/VPLZCNTQ */
        case 0xc4: /* VPCONFLICTD/VPCONFLICTQ */
            required_ebx |= CPUID_7_0_EBX_AVX512CD;
            break;
        case 0x54: /* VPOPCNTB/VPOPCNTW */
            required_ecx |= CPUID_7_0_ECX_AVX512BITALG;
            break;
        case 0x55: /* VPOPCNTD/VPOPCNTQ */
            required_ecx |= CPUID_7_0_ECX_AVX512_VPOPCNTDQ;
            break;
        case 0x40: /* VPMULLD/VPMULLQ */
            if (w) {
                required_ebx |= CPUID_7_0_EBX_AVX512DQ;
            }
            break;
        case 0x50: /* VPDPBUSD */
        case 0x51: /* VPDPBUSDS */
        case 0x52: /* VPDPWSSD */
        case 0x53: /* VPDPWSSDS */
            required_ecx |= CPUID_7_0_ECX_AVX512VNNI;
            break;
        case 0x83: /* VPMULTISHIFTQB */
            required_ecx |= CPUID_7_0_ECX_AVX512_VBMI;
            break;
        case 0x75: /* VPERMI2B/VPERMI2W */
        case 0x7d: /* VPERMT2B/VPERMT2W */
        case 0x8d: /* VPERMB/VPERMW */
            if (!w) {
                required_ecx |= CPUID_7_0_ECX_AVX512_VBMI;
            }
            break;
        case 0xb4: /* VPMADD52LUQ */
        case 0xb5: /* VPMADD52HUQ */
            required_ebx |= CPUID_7_0_EBX_AVX512IFMA;
            break;
        default:
            break;
        }
    }
    if (element_shift < 2 && !required_ecx) {
        required_ebx |= CPUID_7_0_EBX_AVX512BW;
    }

    if (unary && ((p1 & 0x78) != 0x78 || !(p2 & 0x08))) {
        return false;
    }

    vector_length = (p2 >> 5) & 3;
    mask_reg = p2 & 7;
    zero = (p2 & 0x80) != 0;
    if (vector_length == 3 || (zero && !mask_reg) ||
        (no_xmm && vector_length == 0)) {
        return false;
    }
    if (vector_length != 2) {
        required_ebx |= CPUID_7_0_EBX_AVX512VL;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return false;
    }
    if ((s->cpuid_7_0_ebx_features & required_ebx) != required_ebx ||
        (s->cpuid_7_0_ecx_features & required_ecx) != required_ecx) {
        gen_illegal_opcode(s);
        return true;
    }

    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }
    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }
    src1 = src2;
    if (!unary) {
        src1 = (~p1 >> 3) & 15;
        if (!(p2 & 0x08)) {
            src1 |= 16;
        }
    }

    gen_helper_evex_packed_int_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_packed_int_desc(dst, src1, src2, element_shift,
                                           vector_length, mask_reg, zero,
                                           operation)));
    return true;
}

static bool gen_evex_packed_shift_reg(CPUX86State *env, DisasContext *s,
                                      int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int map = p0 & 3;
    const bool w = (p1 & 0x80) != 0;
    bool immediate;
    bool variable;
    bool immediate_group;
    bool align_elements;
    EVEXPackedShiftOp operation;
    int element_shift;
    int modrm;
    int extension;
    int dst, src1, src2;
    int vector_length;
    int mask_reg;
    bool zero;
    unsigned int count = 0;

    if ((p1 & 3) != 1 || (p2 & 0x10)) {
        return false;
    }

    align_elements = map == 3 && opcode == 0x03;
    immediate_group = map == 1 &&
                      (opcode == 0x71 || opcode == 0x72 || opcode == 0x73);
    immediate = align_elements || immediate_group ||
                (map == 3 && opcode >= 0x70 && opcode <= 0x73);
    variable = map == 2 &&
               ((opcode >= 0x10 && opcode <= 0x15) ||
                (opcode >= 0x45 && opcode <= 0x47) ||
                (opcode >= 0x70 && opcode <= 0x73));
    if (!immediate && !variable) {
        return false;
    }

    vector_length = (p2 >> 5) & 3;
    mask_reg = p2 & 7;
    zero = (p2 & 0x80) != 0;
    if (vector_length == 3 || (zero && !mask_reg)) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return false;
    }
    extension = (modrm >> 3) & 7;

    if (align_elements) {
        element_shift = w ? 3 : 2;
        operation = EVEX_SHIFT_ALIGN_ELEMENTS;
    } else if (immediate_group) {
        /* ModRM.reg is an opcode extension, so EVEX.R/R' are reserved. */
        if ((p0 & 0x90) != 0x90) {
            return false;
        }
        if (opcode == 0x71) {
            element_shift = 1;
            switch (extension) {
            case 2:
                operation = EVEX_SHIFT_RIGHT_LOGICAL;
                break;
            case 4:
                operation = EVEX_SHIFT_RIGHT_ARITHMETIC;
                break;
            case 6:
                operation = EVEX_SHIFT_LEFT;
                break;
            default:
                return false;
            }
        } else if (opcode == 0x72) {
            if (extension == 0 || extension == 1) {
                element_shift = w ? 3 : 2;
                operation = extension == 0 ? EVEX_ROTATE_RIGHT
                                           : EVEX_ROTATE_LEFT;
            } else if (extension == 4) {
                element_shift = w ? 3 : 2;
                operation = EVEX_SHIFT_RIGHT_ARITHMETIC;
            } else {
                if (w) {
                    return false;
                }
                element_shift = 2;
                switch (extension) {
                case 2:
                    operation = EVEX_SHIFT_RIGHT_LOGICAL;
                    break;
                case 6:
                    operation = EVEX_SHIFT_LEFT;
                    break;
                default:
                    return false;
                }
            }
        } else {
            if (!w) {
                if ((extension != 3 && extension != 7) || mask_reg || zero) {
                    return false;
                }
                element_shift = 0;
                operation = extension == 3 ? EVEX_SHIFT_BYTES_RIGHT
                                           : EVEX_SHIFT_BYTES_LEFT;
            } else {
                element_shift = 3;
                switch (extension) {
                case 2:
                    operation = EVEX_SHIFT_RIGHT_LOGICAL;
                    break;
                case 4:
                    operation = EVEX_SHIFT_RIGHT_ARITHMETIC;
                    break;
                case 6:
                    operation = EVEX_SHIFT_LEFT;
                    break;
                default:
                    return false;
                }
            }
        }
    } else if (map == 2 && opcode >= 0x10 && opcode <= 0x15) {
        if (opcode <= 0x12) {
            if (!w) {
                return false;
            }
            element_shift = 1;
            operation = opcode == 0x10 ? EVEX_SHIFT_RIGHT_LOGICAL
                        : opcode == 0x11
                            ? EVEX_SHIFT_RIGHT_ARITHMETIC
                            : EVEX_SHIFT_LEFT;
        } else if (opcode == 0x14 || opcode == 0x15) {
            element_shift = w ? 3 : 2;
            operation = opcode == 0x14 ? EVEX_ROTATE_RIGHT
                                       : EVEX_ROTATE_LEFT;
        } else {
            return false;
        }
    } else if (map == 2 && opcode >= 0x45 && opcode <= 0x47) {
        element_shift = w ? 3 : 2;
        operation = opcode == 0x45 ? EVEX_SHIFT_RIGHT_LOGICAL
                    : opcode == 0x46 ? EVEX_SHIFT_RIGHT_ARITHMETIC
                                     : EVEX_SHIFT_LEFT;
    } else {
        /* Map 2 selects per-element counts; map 3 carries an imm8. */
        if (opcode == 0x70 || opcode == 0x72) {
            if (!w) {
                return false;
            }
            element_shift = 1;
        } else {
            element_shift = w ? 3 : 2;
        }
        operation = opcode <= 0x71 ? EVEX_DOUBLE_SHIFT_LEFT
                                   : EVEX_DOUBLE_SHIFT_RIGHT;
    }

    if (!x86_evex_require_features(
            s,
            ((operation != EVEX_DOUBLE_SHIFT_LEFT &&
              operation != EVEX_DOUBLE_SHIFT_RIGHT && element_shift < 2)
                 ? CPUID_7_0_EBX_AVX512BW
                 : 0) |
                (vector_length != 2 ? CPUID_7_0_EBX_AVX512VL : 0),
            (operation == EVEX_DOUBLE_SHIFT_LEFT ||
             operation == EVEX_DOUBLE_SHIFT_RIGHT)
                ? CPUID_7_0_ECX_AVX512_VBMI2
                : 0,
            0)) {
        return true;
    }

    if (immediate_group) {
        dst = (~p1 >> 3) & 15;
        if (!(p2 & 0x08)) {
            dst |= 16;
        }
    } else {
        dst = (modrm >> 3) & 7;
        if (!(p0 & 0x80)) {
            dst |= 8;
        }
        if (!(p0 & 0x10)) {
            dst |= 16;
        }
    }

    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }
    if (immediate_group) {
        src1 = src2;
        src2 = 0;
    } else {
        src1 = (~p1 >> 3) & 15;
        if (!(p2 & 0x08)) {
            src1 |= 16;
        }
    }
    if (immediate) {
        count = x86_ldub_code(env, s);
    }

    gen_helper_evex_packed_shift_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_packed_shift_desc(dst, src1, src2, element_shift,
                                             vector_length, mask_reg, zero,
                                             operation, variable)),
        tcg_const_i32(tcg_ctx, count));
    return true;
}

static bool gen_evex_bit_shuffle_reg(CPUX86State *env, DisasContext *s,
                                     int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int vector_length;
    int modrm;
    int dst, src1, src2;

    if ((p0 & 3) != 2 || (p0 & 0x90) != 0x90 ||
        (p1 & 0x83) != 1 || opcode != 0x8f ||
        (p2 & 0x90) != 0 || ((p2 >> 5) & 3) == 3) {
        return false;
    }

    vector_length = (p2 >> 5) & 3;
    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return false;
    }
    if (!x86_evex_require_features(
            s, vector_length != 2 ? CPUID_7_0_EBX_AVX512VL : 0,
            CPUID_7_0_ECX_AVX512BITALG, 0)) {
        return true;
    }
    dst = (modrm >> 3) & 7;
    src1 = (~p1 >> 3) & 15;
    if (!(p2 & 0x08)) {
        src1 |= 16;
    }
    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }

    gen_helper_evex_bit_shuffle_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_bit_shuffle_desc(dst, src1, src2, vector_length,
                                            p2 & 7)));
    return true;
}

static bool gen_evex_mask_test_reg(CPUX86State *env, DisasContext *s,
                                   int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int mandatory = p1 & 3;
    const bool w = (p1 & 0x80) != 0;
    int element_shift;
    int vector_length;
    int modrm;
    int dst, src1, src2;

    if ((p0 & 3) != 2 || (p0 & 0x90) != 0x90 ||
        (mandatory != 1 && mandatory != 2) ||
        (opcode != 0x26 && opcode != 0x27) ||
        (p2 & 0x80) || ((p2 >> 5) & 3) == 3) {
        return false;
    }

    element_shift = opcode == 0x26 ? (w ? 1 : 0) : (w ? 3 : 2);
    vector_length = (p2 >> 5) & 3;
    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3 || (p2 & 0x10)) {
        return false;
    }
    if (!x86_evex_require_features(
            s,
            (element_shift < 2 ? CPUID_7_0_EBX_AVX512BW : 0) |
                (vector_length != 2 ? CPUID_7_0_EBX_AVX512VL : 0),
            0, 0)) {
        return true;
    }
    dst = (modrm >> 3) & 7;
    src1 = (~p1 >> 3) & 15;
    if (!(p2 & 0x08)) {
        src1 |= 16;
    }
    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }

    gen_helper_evex_mask_test_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_mask_test_desc(dst, src1, src2, element_shift,
                                          vector_length, p2 & 7,
                                          mandatory == 2)));
    return true;
}

static bool gen_evex_ternlog_reg(CPUX86State *env, DisasContext *s,
                                 int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool w = (p1 & 0x80) != 0;
    const int vector_length = (p2 >> 5) & 3;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    int modrm;
    int dst, src1, src2;
    unsigned int immediate;

    if ((p0 & 3) != 3 || (p1 & 3) != 1 || opcode != 0x25 ||
        (p2 & 0x10) || vector_length == 3 || (zero && !mask_reg)) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return false;
    }
    if (!x86_evex_require_features(
            s, vector_length != 2 ? CPUID_7_0_EBX_AVX512VL : 0,
            0, 0)) {
        return true;
    }
    immediate = x86_ldub_code(env, s);
    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }
    src1 = (~p1 >> 3) & 15;
    if (!(p2 & 0x08)) {
        src1 |= 16;
    }
    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }

    gen_helper_evex_ternlog_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_ternlog_desc(dst, src1, src2, w ? 3 : 2,
                                        vector_length, mask_reg, zero)),
        tcg_const_i32(tcg_ctx, immediate));
    return true;
}

static bool gen_evex_shuffle_imm_reg(CPUX86State *env, DisasContext *s,
                                     int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int mandatory = p1 & 3;
    const int vector_length = (p2 >> 5) & 3;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    int modrm;
    int dst, src;
    unsigned int immediate;

    if ((p0 & 3) != 1 || mandatory == 0 || opcode != 0x70 ||
        (p1 & 0x78) != 0x78 || (mandatory == 1 && (p1 & 0x80)) ||
        !(p2 & 0x08) || (p2 & 0x10) || vector_length == 3 ||
        (zero && !mask_reg)) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return false;
    }
    if (!x86_evex_require_features(
            s,
            (mandatory == 1 ? 0 : CPUID_7_0_EBX_AVX512BW) |
                (vector_length != 2 ? CPUID_7_0_EBX_AVX512VL : 0),
            0, 0)) {
        return true;
    }
    immediate = x86_ldub_code(env, s);
    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }
    src = modrm & 7;
    if (!(p0 & 0x20)) {
        src |= 8;
    }
    if (!(p0 & 0x40)) {
        src |= 16;
    }

    gen_helper_evex_shuffle_imm_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_shuffle_imm_desc(dst, src, vector_length, mask_reg,
                                            zero, mandatory)),
        tcg_const_i32(tcg_ctx, immediate));
    return true;
}

static bool gen_evex_lane_int_reg(CPUX86State *env, DisasContext *s,
                                  int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int map = p0 & 3;
    const unsigned int mandatory = p1 & 3;
    const bool w = (p1 & 0x80) != 0;
    const int vector_length = (p2 >> 5) & 3;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    EVEXLaneIntOp operation;
    int modrm;
    int dst, src1, src2;
    unsigned int immediate = 0;
    uint32_t required_ebx =
        vector_length != 2 ? CPUID_7_0_EBX_AVX512VL : 0;
    const bool float_unpack =
        map == 1 && (opcode == 0x14 || opcode == 0x15) &&
        ((!w && mandatory == 0) || (w && mandatory == 1));
    const bool float_shuffle =
        map == 1 && opcode == 0xc6 &&
        ((!w && mandatory == 0) || (w && mandatory == 1));
    const bool duplicate =
        map == 1 &&
        ((!w && mandatory == 2 && (opcode == 0x12 || opcode == 0x16)) ||
         (w && mandatory == 3 && opcode == 0x12));
    const bool lane_shuffle_128 =
        map == 3 && (opcode == 0x23 || opcode == 0x43) && mandatory == 1;
    const bool lane_insert_128 =
        map == 3 && (opcode == 0x18 || opcode == 0x38) && mandatory == 1;
    const bool lane_insert_256 =
        map == 3 && (opcode == 0x1a || opcode == 0x3a) && mandatory == 1;
    const bool lane_extract_128 =
        map == 3 && (opcode == 0x19 || opcode == 0x39) && mandatory == 1;
    const bool lane_extract_256 =
        map == 3 && (opcode == 0x1b || opcode == 0x3b) && mandatory == 1;
    const bool lane_extract = lane_extract_128 || lane_extract_256;
    const bool lane_subvector = lane_insert_128 || lane_insert_256 ||
                                lane_extract;

    if ((!float_unpack && !float_shuffle && !duplicate && mandatory != 1) ||
        (p2 & 0x10) || vector_length == 3 ||
        (zero && !mask_reg) ||
        ((lane_shuffle_128 || lane_insert_128 || lane_extract_128) &&
         vector_length == 0) ||
        ((lane_insert_256 || lane_extract_256) && vector_length != 2) ||
        ((lane_extract || duplicate) &&
         ((p1 & 0x78) != 0x78 || !(p2 & 0x08)))) {
        return false;
    }

    if (map == 1) {
        switch (opcode) {
        case 0x12: /* VMOVSLDUP/VMOVDDUP */
            if (!duplicate) {
                return false;
            }
            operation = w ? EVEX_LANE_DUP_LOW_Q : EVEX_LANE_DUP_LOW_D;
            break;
        case 0x16: /* VMOVSHDUP */
            if (!duplicate || w) {
                return false;
            }
            operation = EVEX_LANE_DUP_HIGH_D;
            break;
        case 0x14: /* VUNPCKLPS/VUNPCKLPD */
            if (!float_unpack) {
                return false;
            }
            operation = w ? EVEX_LANE_UNPACK_LOW_Q
                          : EVEX_LANE_UNPACK_LOW_D;
            break;
        case 0x15: /* VUNPCKHPS/VUNPCKHPD */
            if (!float_unpack) {
                return false;
            }
            operation = w ? EVEX_LANE_UNPACK_HIGH_Q
                          : EVEX_LANE_UNPACK_HIGH_D;
            break;
        case 0xc6: /* VSHUFPS/VSHUFPD */
            if (!float_shuffle) {
                return false;
            }
            operation = w ? EVEX_LANE_SHUFFLE_PD
                          : EVEX_LANE_SHUFFLE_PS;
            break;
        case 0x63:
            operation = EVEX_LANE_PACKSSWB;
            break;
        case 0x6b:
            if (w) {
                return false;
            }
            operation = EVEX_LANE_PACKSSDW;
            break;
        case 0x67:
            operation = EVEX_LANE_PACKUSWB;
            break;
        case 0x60:
            operation = EVEX_LANE_UNPACK_LOW_B;
            break;
        case 0x61:
            operation = EVEX_LANE_UNPACK_LOW_W;
            break;
        case 0x62:
            if (w) {
                return false;
            }
            operation = EVEX_LANE_UNPACK_LOW_D;
            break;
        case 0x6c:
            if (!w) {
                return false;
            }
            operation = EVEX_LANE_UNPACK_LOW_Q;
            break;
        case 0x68:
            operation = EVEX_LANE_UNPACK_HIGH_B;
            break;
        case 0x69:
            operation = EVEX_LANE_UNPACK_HIGH_W;
            break;
        case 0x6a:
            if (w) {
                return false;
            }
            operation = EVEX_LANE_UNPACK_HIGH_D;
            break;
        case 0x6d:
            if (!w) {
                return false;
            }
            operation = EVEX_LANE_UNPACK_HIGH_Q;
            break;
        case 0xf5:
            operation = EVEX_LANE_MADDWD;
            break;
        case 0xf6:
            operation = EVEX_LANE_SADBW;
            break;
        default:
            return false;
        }
    } else if (map == 2) {
        switch (opcode) {
        case 0x00:
            operation = EVEX_LANE_SHUFFLE_BYTES;
            break;
        case 0x04:
            operation = EVEX_LANE_MADDUBSW;
            break;
        case 0x2b:
            if (w) {
                return false;
            }
            operation = EVEX_LANE_PACKUSDW;
            break;
        default:
            return false;
        }
    } else if (lane_shuffle_128) {
        operation = w ? EVEX_LANE_SHUFFLE_128_Q
                      : EVEX_LANE_SHUFFLE_128_D;
    } else if (lane_insert_128) {
        operation = w ? EVEX_LANE_INSERT_128_Q
                      : EVEX_LANE_INSERT_128_D;
    } else if (lane_insert_256) {
        operation = w ? EVEX_LANE_INSERT_256_Q
                      : EVEX_LANE_INSERT_256_D;
    } else if (lane_extract_128) {
        operation = w ? EVEX_LANE_EXTRACT_128_Q
                      : EVEX_LANE_EXTRACT_128_D;
    } else if (lane_extract_256) {
        operation = w ? EVEX_LANE_EXTRACT_256_Q
                      : EVEX_LANE_EXTRACT_256_D;
    } else if (map == 3 && opcode == 0x0f) {
        if (w) {
            return false;
        }
        operation = EVEX_LANE_ALIGN_RIGHT;
    } else {
        return false;
    }

    if ((map == 1 &&
         (opcode == 0x60 || opcode == 0x61 || opcode == 0x63 ||
          opcode == 0x67 || opcode == 0x68 || opcode == 0x69 ||
          opcode == 0x6b || opcode == 0xf5 || opcode == 0xf6)) ||
        map == 2 || (map == 3 && opcode == 0x0f)) {
        required_ebx |= CPUID_7_0_EBX_AVX512BW;
    }
    if (((lane_insert_128 || lane_extract_128) && w) ||
        ((lane_insert_256 || lane_extract_256) && !w)) {
        required_ebx |= CPUID_7_0_EBX_AVX512DQ;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return false;
    }
    if (!x86_evex_require_features(s, required_ebx, 0, 0)) {
        return true;
    }
    if (operation == EVEX_LANE_ALIGN_RIGHT ||
        operation == EVEX_LANE_SHUFFLE_PS ||
        operation == EVEX_LANE_SHUFFLE_PD ||
        operation == EVEX_LANE_SHUFFLE_128_D ||
        operation == EVEX_LANE_SHUFFLE_128_Q || lane_subvector) {
        immediate = x86_ldub_code(env, s);
    }
    if (lane_extract) {
        src1 = (modrm >> 3) & 7;
        if (!(p0 & 0x80)) {
            src1 |= 8;
        }
        if (!(p0 & 0x10)) {
            src1 |= 16;
        }
        dst = modrm & 7;
        if (!(p0 & 0x20)) {
            dst |= 8;
        }
        if (!(p0 & 0x40)) {
            dst |= 16;
        }
        src2 = 0;
    } else {
        dst = (modrm >> 3) & 7;
        if (!(p0 & 0x80)) {
            dst |= 8;
        }
        if (!(p0 & 0x10)) {
            dst |= 16;
        }
        src1 = (~p1 >> 3) & 15;
        if (!(p2 & 0x08)) {
            src1 |= 16;
        }
        src2 = modrm & 7;
        if (!(p0 & 0x20)) {
            src2 |= 8;
        }
        if (!(p0 & 0x40)) {
            src2 |= 16;
        }
        if (duplicate) {
            src1 = src2;
        }
    }

    gen_helper_evex_lane_int_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_lane_int_desc(dst, src1, src2, vector_length,
                                         mask_reg, zero, operation)),
        tcg_const_i32(tcg_ctx, immediate));
    return true;
}

static bool gen_evex_mask_convert_reg(CPUX86State *env, DisasContext *s,
                                      int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool w = (p1 & 0x80) != 0;
    const int vector_length = (p2 >> 5) & 3;
    EVEXMaskConvertOp operation;
    int element_shift;
    int modrm;
    int dst, src;
    uint32_t required_ebx;

    if ((p0 & 3) != 2 || (p1 & 3) != 2 ||
        (p1 & 0x78) != 0x78 || (p2 & 0x9f) != 0x08 ||
        vector_length == 3) {
        return false;
    }

    switch (opcode) {
    case 0x28:
        operation = EVEX_MCONV_MASK_TO_VECTOR;
        element_shift = w ? 1 : 0;
        break;
    case 0x38:
        operation = EVEX_MCONV_MASK_TO_VECTOR;
        element_shift = w ? 3 : 2;
        break;
    case 0x29:
        operation = EVEX_MCONV_VECTOR_TO_MASK;
        element_shift = w ? 1 : 0;
        break;
    case 0x39:
        operation = EVEX_MCONV_VECTOR_TO_MASK;
        element_shift = w ? 3 : 2;
        break;
    case 0x2a:
        if (!w) {
            return false;
        }
        operation = EVEX_MCONV_BROADCAST_MASK;
        element_shift = 3;
        break;
    case 0x3a:
        if (w) {
            return false;
        }
        operation = EVEX_MCONV_BROADCAST_MASK;
        element_shift = 2;
        break;
    default:
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return false;
    }
    if (opcode == 0x28 || opcode == 0x29) {
        required_ebx = CPUID_7_0_EBX_AVX512BW;
    } else if (opcode == 0x38 || opcode == 0x39) {
        required_ebx = CPUID_7_0_EBX_AVX512DQ;
    } else {
        required_ebx = CPUID_7_0_EBX_AVX512CD;
    }
    if (vector_length != 2) {
        required_ebx |= CPUID_7_0_EBX_AVX512VL;
    }
    if (!x86_evex_require_features(s, required_ebx, 0, 0)) {
        return true;
    }
    if (operation == EVEX_MCONV_VECTOR_TO_MASK) {
        if ((p0 & 0x90) != 0x90) {
            return false;
        }
        dst = (modrm >> 3) & 7;
        src = modrm & 7;
        if (!(p0 & 0x20)) {
            src |= 8;
        }
        if (!(p0 & 0x40)) {
            src |= 16;
        }
    } else {
        if ((p0 & 0x60) != 0x60) {
            return false;
        }
        dst = (modrm >> 3) & 7;
        if (!(p0 & 0x80)) {
            dst |= 8;
        }
        if (!(p0 & 0x10)) {
            dst |= 16;
        }
        src = modrm & 7;
    }

    gen_helper_evex_mask_convert_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_mask_convert_desc(dst, src, element_shift,
                                             vector_length, operation)));
    return true;
}

static bool gen_evex_widen_reg(CPUX86State *env, DisasContext *s, int p0,
                               int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int vector_length = (p2 >> 5) & 3;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    const bool sign_extend = opcode >= 0x20 && opcode <= 0x25;
    const int form = opcode & 15;
    int input_shift;
    int output_shift;
    int modrm;
    int dst, src;

    if ((p0 & 3) != 2 || (p1 & 0x83) != 1 ||
        (p1 & 0x78) != 0x78 || !(p2 & 0x08) || (p2 & 0x10) ||
        vector_length == 3 || (zero && !mask_reg) ||
        (!sign_extend && (opcode < 0x30 || opcode > 0x35))) {
        return false;
    }

    switch (form) {
    case 0:
        input_shift = 0;
        output_shift = 1;
        break;
    case 1:
        input_shift = 0;
        output_shift = 2;
        break;
    case 2:
        input_shift = 0;
        output_shift = 3;
        break;
    case 3:
        input_shift = 1;
        output_shift = 2;
        break;
    case 4:
        input_shift = 1;
        output_shift = 3;
        break;
    case 5:
        input_shift = 2;
        output_shift = 3;
        break;
    default:
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return false;
    }
    if (!x86_evex_require_features(
            s,
            (input_shift == 0 && output_shift == 1
                 ? CPUID_7_0_EBX_AVX512BW
                 : 0) |
                (vector_length != 2 ? CPUID_7_0_EBX_AVX512VL : 0),
            0, 0)) {
        return true;
    }
    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }
    src = modrm & 7;
    if (!(p0 & 0x20)) {
        src |= 8;
    }
    if (!(p0 & 0x40)) {
        src |= 16;
    }

    gen_helper_evex_widen_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_widen_desc(dst, src, input_shift, output_shift,
                                      vector_length, mask_reg, zero,
                                      sign_extend)));
    return true;
}

static bool gen_evex_narrow_reg(CPUX86State *env, DisasContext *s, int p0,
                                int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int vector_length = (p2 >> 5) & 3;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    const int family = opcode >> 4;
    const int form = opcode & 15;
    EVEXNarrowMode mode;
    int input_shift;
    int output_shift;
    int modrm;
    int dst, src;

    if ((p0 & 3) != 2 || (p1 & 0x83) != 2 ||
        (p1 & 0x78) != 0x78 || !(p2 & 0x08) || (p2 & 0x10) ||
        vector_length == 3 || (zero && !mask_reg) || family < 1 ||
        family > 3 || form > 5) {
        return false;
    }

    mode = family == 1 ? EVEX_NARROW_SATURATE_UNSIGNED
           : family == 2 ? EVEX_NARROW_SATURATE_SIGNED
                         : EVEX_NARROW_TRUNCATE;
    switch (form) {
    case 0:
        input_shift = 1;
        output_shift = 0;
        break;
    case 1:
        input_shift = 2;
        output_shift = 0;
        break;
    case 2:
        input_shift = 3;
        output_shift = 0;
        break;
    case 3:
        input_shift = 2;
        output_shift = 1;
        break;
    case 4:
        input_shift = 3;
        output_shift = 1;
        break;
    case 5:
        input_shift = 3;
        output_shift = 2;
        break;
    default:
        g_assert_not_reached();
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return false;
    }
    if (!x86_evex_require_features(
            s,
            (form == 0 ? CPUID_7_0_EBX_AVX512BW : 0) |
                (vector_length != 2 ? CPUID_7_0_EBX_AVX512VL : 0),
            0, 0)) {
        return true;
    }
    src = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        src |= 8;
    }
    if (!(p0 & 0x10)) {
        src |= 16;
    }
    dst = modrm & 7;
    if (!(p0 & 0x20)) {
        dst |= 8;
    }
    if (!(p0 & 0x40)) {
        dst |= 16;
    }

    gen_helper_evex_narrow_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_narrow_desc(dst, src, input_shift, output_shift,
                                       vector_length, mask_reg, zero, mode)));
    return true;
}

static bool gen_evex_vector_move_reg(CPUX86State *env, DisasContext *s,
                                     int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int mandatory = p1 & 3;
    const bool w = (p1 & 0x80) != 0;
    const int vector_length = (p2 >> 5) & 3;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    bool store;
    int element_shift;
    int modrm;
    int reg, rm;

    if ((p0 & 3) != 1 || (p1 & 0x78) != 0x78 || !(p2 & 0x08) ||
        (p2 & 0x10) || vector_length == 3 || (zero && !mask_reg)) {
        return false;
    }

    switch (opcode) {
    case 0x10:
    case 0x11: /* VMOVUPS/VMOVUPD */
    case 0x28:
    case 0x29: /* VMOVAPS/VMOVAPD */
        if ((!w && mandatory != 0) || (w && mandatory != 1)) {
            return false;
        }
        element_shift = w ? 3 : 2;
        store = opcode & 1;
        break;
    case 0x6f:
    case 0x7f:
        if (mandatory == 1) { /* VMOVDQA32/VMOVDQA64 */
            element_shift = w ? 3 : 2;
        } else {
            return false;
        }
        store = opcode == 0x7f;
        break;
    default:
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return false;
    }
    if (!x86_evex_require_features(
            s, vector_length != 2 ? CPUID_7_0_EBX_AVX512VL : 0,
            0, 0)) {
        return true;
    }
    reg = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        reg |= 8;
    }
    if (!(p0 & 0x10)) {
        reg |= 16;
    }
    rm = modrm & 7;
    if (!(p0 & 0x20)) {
        rm |= 8;
    }
    if (!(p0 & 0x40)) {
        rm |= 16;
    }
    if (store) {
        const int tmp = reg;
        reg = rm;
        rm = tmp;
    }

    gen_helper_evex_vmovdqu_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_vmovdqu_desc(reg, rm, element_shift, vector_length,
                                        mask_reg, zero)));
    return true;
}

static bool gen_evex_compress_expand_reg(CPUX86State *env, DisasContext *s,
                                          int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool w = (p1 & 0x80) != 0;
    int element_shift;
    bool expand;
    int vector_length;
    int mask_reg;
    bool zero;
    int modrm;
    int reg, rm;
    int dst, src;
    uint32_t required_ebx = 0;
    uint32_t required_ecx = 0;

    if ((p0 & 3) != 2 || (p1 & 3) != 1) {
        return false;
    }

    switch (opcode) {
    case 0x62: /* VPEXPANDB/VPEXPANDW */
        element_shift = w ? 1 : 0;
        expand = true;
        required_ecx = CPUID_7_0_ECX_AVX512_VBMI2;
        break;
    case 0x63: /* VPCOMPRESSB/VPCOMPRESSW */
        element_shift = w ? 1 : 0;
        expand = false;
        required_ecx = CPUID_7_0_ECX_AVX512_VBMI2;
        break;
    case 0x88: /* VEXPANDPS/VEXPANDPD */
    case 0x89: /* VPEXPANDD/VPEXPANDQ */
        element_shift = w ? 3 : 2;
        expand = true;
        break;
    case 0x8a: /* VCOMPRESSPS/VCOMPRESSPD */
    case 0x8b: /* VPCOMPRESSD/VPCOMPRESSQ */
        element_shift = w ? 3 : 2;
        expand = false;
        break;
    default:
        return false;
    }

    vector_length = (p2 >> 5) & 3;
    mask_reg = p2 & 7;
    zero = (p2 & 0x80) != 0;
    if ((p1 & 0x78) != 0x78 || !(p2 & 0x08) || (p2 & 0x10) ||
        vector_length == 3 || (zero && !mask_reg)) {
        return false;
    }
    if (vector_length != 2) {
        required_ebx = CPUID_7_0_EBX_AVX512VL;
    }
    modrm = x86_ldub_code(env, s);
    /* Complete VBMI2 is not advertised to TCG guests, so keep its memory
     * forms fail-closed. */
    if ((modrm >> 6) != 3 && (opcode == 0x62 || opcode == 0x63)) {
        return false;
    }
    if ((s->cpuid_7_0_ebx_features & required_ebx) != required_ebx ||
        (s->cpuid_7_0_ecx_features & required_ecx) != required_ecx) {
        gen_illegal_opcode(s);
        return true;
    }

    reg = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        reg |= 8;
    }
    if (!(p0 & 0x10)) {
        reg |= 16;
    }

    if ((modrm >> 6) != 3) {
        bool stack_segment;
        bool uses_egpr;
        uint32_t desc;

        /* EVEX.z is reserved when compress writes memory. */
        if (!expand && zero) {
            return false;
        }
        stack_segment = gen_evex_memory_address_details(
            env, s, p0, p1, modrm, 1 << element_shift, &uses_egpr);
        if (uses_egpr && (!CODE64(s) || !apx_f_enabled(s))) {
            gen_illegal_opcode(s);
            return true;
        }
        desc = evex_compress_expand_desc(
            expand ? reg : 0, expand ? 0 : reg, element_shift,
            vector_length, mask_reg, zero, expand);
        if (stack_segment) {
            desc |= EVEX_CE_STACK;
        }
        gen_helper_evex_compress_expand_mem(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc),
            tcg_const_tl(tcg_ctx, s->pc_start - s->cs_base));
        return true;
    }

    rm = modrm & 7;
    if (!(p0 & 0x20)) {
        rm |= 8;
    }
    if (!(p0 & 0x40)) {
        rm |= 16;
    }

    /* Expand is the usual reg <- r/m direction.  Compress encodes the source
     * in ModRM.reg and the register destination in ModRM.r/m. */
    dst = expand ? reg : rm;
    src = expand ? rm : reg;
    gen_helper_evex_compress_expand_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_compress_expand_desc(
                          dst, src, element_shift, vector_length, mask_reg,
                          zero, expand)));
    return true;
}

static bool gen_evex_fp_arith(CPUX86State *env, DisasContext *s, int p0,
                              int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int mandatory = p1 & 3;
    const bool scalar = mandatory >= 2;
    const bool is_double = mandatory == 1 || mandatory == 3;
    const bool evex_b = (p2 & 0x10) != 0;
    const bool zero = (p2 & 0x80) != 0;
    const int mask_reg = p2 & 7;
    const unsigned int encoded_ll = (p2 >> 5) & 3;
    EVEXFPArithOp operation;
    int vector_length = encoded_ll;
    int modrm;
    int dst, src1, src2;

    if ((p0 & 3) != 1 || ((p1 & 0x80) != 0) != is_double ||
        (zero && !mask_reg)) {
        return false;
    }

    switch (opcode) {
    case 0x51:
        operation = EVEX_FP_ARITH_SQRT;
        break;
    case 0x58:
        operation = EVEX_FP_ARITH_ADD;
        break;
    case 0x59:
        operation = EVEX_FP_ARITH_MUL;
        break;
    case 0x5c:
        operation = EVEX_FP_ARITH_SUB;
        break;
    case 0x5d:
        operation = EVEX_FP_ARITH_MIN;
        break;
    case 0x5e:
        operation = EVEX_FP_ARITH_DIV;
        break;
    case 0x5f:
        operation = EVEX_FP_ARITH_MAX;
        break;
    default:
        return false;
    }

    /* Packed square-root has no first source.  All five encoded vvvv bits
     * are reserved, while the scalar form uses that source for bits 127:E.
     */
    if (!scalar && operation == EVEX_FP_ARITH_SQRT &&
        ((p1 & 0x78) != 0x78 || !(p2 & 0x08))) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if (scalar) {
        /* LL is ignored without EVEX.b and contains RC with register ER. */
        vector_length = 0;
    } else if ((modrm >> 6) == 3 && evex_b) {
        /* Register ER/SAE is defined only at an effective 512-bit VL. */
        vector_length = 2;
    } else if (vector_length == 3) {
        return false;
    }
    if (!scalar && vector_length != 2 &&
        !(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_AVX512VL)) {
        gen_illegal_opcode(s);
        return true;
    }

    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }

    src1 = 0;
    if (operation != EVEX_FP_ARITH_SQRT || scalar) {
        src1 = (~p1 >> 3) & 15;
        if (!(p2 & 0x08)) {
            src1 |= 16;
        }
    }

    if ((modrm >> 6) != 3) {
        uint32_t desc;

        /* Scalar tuple-one memory forms do not define EVEX.b broadcast. */
        if (scalar && evex_b) {
            return false;
        }
        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm,
                scalar || evex_b ? (is_double ? 8 : 4)
                                 : 16 << vector_length,
                mask_reg,
                scalar ? 1
                       : (16 << vector_length) / (is_double ? 8 : 4),
                is_double ? 8 : 4, evex_b)) {
            return true;
        }
        desc = evex_fp_arith_desc(
            dst, src1, 0, vector_length, mask_reg, operation, is_double,
            scalar, zero, false, 0, evex_b && !scalar);
        gen_helper_evex_fp_arith_load(tcg_ctx, tcg_ctx->cpu_env, s->A0,
                                      tcg_const_i32(tcg_ctx, desc));
        return true;
    }

    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }
    gen_helper_evex_fp_arith_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(
            tcg_ctx,
            evex_fp_arith_desc(dst, src1, src2, vector_length, mask_reg,
                               operation, is_double, scalar, zero, evex_b,
                               evex_b ? encoded_ll : 0, false)));
    return true;
}

static bool gen_evex_fma(CPUX86State *env, DisasContext *s, int p0, int p1,
                         int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int high = opcode & 0xf0;
    const unsigned int low = opcode & 0x0f;
    const bool alternating = low == 6 || low == 7;
    const bool scalar = !alternating && (low & 1);
    const bool is_double = (p1 & 0x80) != 0;
    const bool evex_b = (p2 & 0x10) != 0;
    const bool zero = (p2 & 0x80) != 0;
    const int mask_reg = p2 & 7;
    const unsigned int encoded_ll = (p2 >> 5) & 3;
    unsigned int permutation;
    unsigned int variant;
    int vector_length = encoded_ll;
    int modrm;
    int dst, src1, src2;

    if ((p0 & 3) != 2 || (p1 & 3) != 1 ||
        (high != 0x90 && high != 0xa0 && high != 0xb0) ||
        (zero && !mask_reg)) {
        return false;
    }
    permutation = (high >> 4) - 9;
    switch (low) {
    case 0x6:
        variant = 4; /* MADD/SUB: even subtract, odd add. */
        break;
    case 0x7:
        variant = 5; /* MSUB/ADD: even add, odd subtract. */
        break;
    case 0x8:
    case 0x9:
        variant = 0;
        break;
    case 0xa:
    case 0xb:
        variant = 1;
        break;
    case 0xc:
    case 0xd:
        variant = 2;
        break;
    case 0xe:
    case 0xf:
        variant = 3;
        break;
    default:
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if (scalar) {
        /* LL is ignored without EVEX.b and contains RC with register ER. */
        vector_length = 0;
    } else if ((modrm >> 6) == 3 && evex_b) {
        vector_length = 2;
    } else if (vector_length == 3) {
        return false;
    }
    if (!scalar && vector_length != 2 &&
        !x86_evex_require_features(s, CPUID_7_0_EBX_AVX512VL, 0, 0)) {
        return true;
    }

    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }
    src1 = (~p1 >> 3) & 15;
    if (!(p2 & 0x08)) {
        src1 |= 16;
    }

    if ((modrm >> 6) != 3) {
        uint32_t desc;

        if (scalar && evex_b) {
            return false;
        }
        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm,
                scalar || evex_b ? (is_double ? 8 : 4)
                                 : 16 << vector_length,
                mask_reg,
                scalar ? 1
                       : (16 << vector_length) / (is_double ? 8 : 4),
                is_double ? 8 : 4, evex_b)) {
            return true;
        }
        desc = evex_fma_desc(dst, src1, 0, vector_length, mask_reg,
                             permutation, variant, is_double, scalar, zero,
                             false, 0, evex_b && !scalar);
        gen_helper_evex_fma_load(tcg_ctx, tcg_ctx->cpu_env, s->A0,
                                 tcg_const_i32(tcg_ctx, desc));
        return true;
    }

    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }
    gen_helper_evex_fma_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_fma_desc(dst, src1, src2, vector_length, mask_reg,
                                    permutation, variant, is_double, scalar,
                                    zero, evex_b,
                                    evex_b ? encoded_ll : 0, false)));
    return true;
}

static int evex_convert_type_bytes(EVEXConvertType type)
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

static bool gen_evex_convert(CPUX86State *env, DisasContext *s, int p0,
                             int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int map = p0 & 3;
    const unsigned int mandatory = p1 & 3;
    const bool w = (p1 & 0x80) != 0;
    const bool evex_b = (p2 & 0x10) != 0;
    const bool zero = (p2 & 0x80) != 0;
    const int mask_reg = p2 & 7;
    const unsigned int encoded_ll = (p2 >> 5) & 3;
    EVEXConvertType src_type;
    EVEXConvertType dst_type;
    bool truncate = false;
    bool allow_er = false;
    bool allow_sae = false;
    int vector_length = encoded_ll;
    int modrm;
    int dst, src;

    if ((p1 & 0x78) != 0x78 || !(p2 & 0x08) ||
        (zero && !mask_reg)) {
        return false;
    }

    if (map == 3 && opcode == 0x1d && mandatory == 1 && !w) {
        unsigned int immediate;
        uint32_t desc;

        if (evex_b || vector_length == 3) {
            return false;
        }
        if (vector_length != 2 &&
            !x86_evex_require_features(s, CPUID_7_0_EBX_AVX512VL, 0, 0)) {
            return true;
        }
        modrm = x86_ldub_code(env, s);
        src = (modrm >> 3) & 7;
        if (!(p0 & 0x80)) {
            src |= 8;
        }
        if (!(p0 & 0x10)) {
            src |= 16;
        }

        if ((modrm >> 6) != 3) {
            const int destination_bytes = (16 << vector_length) / 2;

            if (zero) {
                return false;
            }
            s->rip_offset = 1;
            if (!gen_evex_memory_address(
                    env, s, p0, p1, modrm, destination_bytes, mask_reg,
                    destination_bytes / 2, 2, false)) {
                return true;
            }
            immediate = x86_ldub_code(env, s);
            desc = evex_convert_desc(
                0, src, vector_length, mask_reg, EVEX_CVT_F32, EVEX_CVT_F16,
                false, false, (immediate & 8) != 0, (immediate & 4) == 0,
                immediate & 3, false);
            gen_helper_evex_convert_store(
                tcg_ctx, tcg_ctx->cpu_env, s->A0,
                tcg_const_i32(tcg_ctx, desc),
                tcg_const_tl(tcg_ctx, s->pc_start - s->cs_base));
            return true;
        }

        dst = modrm & 7;
        if (!(p0 & 0x20)) {
            dst |= 8;
        }
        if (!(p0 & 0x40)) {
            dst |= 16;
        }
        immediate = x86_ldub_code(env, s);
        desc = evex_convert_desc(
            dst, src, vector_length, mask_reg, EVEX_CVT_F32, EVEX_CVT_F16,
            zero, false, (immediate & 8) != 0, (immediate & 4) == 0,
            immediate & 3, false);
        gen_helper_evex_convert_reg(tcg_ctx, tcg_ctx->cpu_env,
                                    tcg_const_i32(tcg_ctx, desc));
        return true;
    }

    if (map == 1) {
        switch (opcode) {
        case 0xe6:
            if (!w && mandatory == 2) {
                src_type = EVEX_CVT_I32;
                dst_type = EVEX_CVT_F64;
            } else if (w && mandatory == 2) {
                src_type = EVEX_CVT_I64;
                dst_type = EVEX_CVT_F64;
                allow_er = true;
            } else if (w && mandatory == 3) {
                src_type = EVEX_CVT_F64;
                dst_type = EVEX_CVT_I32;
                allow_er = true;
            } else if (w && mandatory == 1) {
                src_type = EVEX_CVT_F64;
                dst_type = EVEX_CVT_I32;
                truncate = true;
                allow_sae = true;
            } else {
                return false;
            }
            break;
        case 0x5b:
            if (!w && mandatory == 0) {
                src_type = EVEX_CVT_I32;
                dst_type = EVEX_CVT_F32;
                allow_er = true;
            } else if (!w && mandatory == 1) {
                src_type = EVEX_CVT_F32;
                dst_type = EVEX_CVT_I32;
                allow_er = true;
            } else if (!w && mandatory == 2) {
                src_type = EVEX_CVT_F32;
                dst_type = EVEX_CVT_I32;
                truncate = true;
                allow_sae = true;
            } else if (w && mandatory == 0) {
                src_type = EVEX_CVT_I64;
                dst_type = EVEX_CVT_F32;
                allow_er = true;
            } else {
                return false;
            }
            break;
        case 0x5a:
            if (!w && mandatory == 0) {
                src_type = EVEX_CVT_F32;
                dst_type = EVEX_CVT_F64;
                allow_sae = true;
            } else if (w && mandatory == 1) {
                src_type = EVEX_CVT_F64;
                dst_type = EVEX_CVT_F32;
                allow_er = true;
            } else {
                return false;
            }
            break;
        case 0x7b:
            if (mandatory != 1) {
                return false;
            }
            src_type = w ? EVEX_CVT_F64 : EVEX_CVT_F32;
            dst_type = EVEX_CVT_I64;
            allow_er = true;
            break;
        case 0x7a:
            if (mandatory == 1) {
                src_type = w ? EVEX_CVT_F64 : EVEX_CVT_F32;
                dst_type = EVEX_CVT_I64;
                truncate = true;
                allow_sae = true;
            } else if (mandatory == 2) {
                src_type = w ? EVEX_CVT_U64 : EVEX_CVT_U32;
                dst_type = EVEX_CVT_F64;
                allow_er = w;
            } else if (mandatory == 3) {
                src_type = w ? EVEX_CVT_U64 : EVEX_CVT_U32;
                dst_type = EVEX_CVT_F32;
                allow_er = true;
            } else {
                return false;
            }
            break;
        case 0x79:
        case 0x78:
            if (mandatory > 1) {
                return false;
            }
            src_type = w ? EVEX_CVT_F64 : EVEX_CVT_F32;
            dst_type = mandatory == 1 ? EVEX_CVT_U64 : EVEX_CVT_U32;
            truncate = opcode == 0x78;
            allow_er = !truncate;
            allow_sae = truncate;
            break;
        default:
            return false;
        }
    } else if (map == 2 && opcode == 0x13 && mandatory == 1 && !w) {
        src_type = EVEX_CVT_F16;
        dst_type = EVEX_CVT_F32;
        allow_sae = true;
    } else {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) == 3 && evex_b) {
        if (!allow_er && !allow_sae) {
            return false;
        }
        vector_length = 2;
    } else if (vector_length == 3) {
        return false;
    }
    {
        uint32_t required_ebx =
            vector_length != 2 ? CPUID_7_0_EBX_AVX512VL : 0;

        if (src_type == EVEX_CVT_I64 || src_type == EVEX_CVT_U64 ||
            dst_type == EVEX_CVT_I64 || dst_type == EVEX_CVT_U64) {
            required_ebx |= CPUID_7_0_EBX_AVX512DQ;
        }
        if (!x86_evex_require_features(s, required_ebx, 0, 0)) {
            return true;
        }
    }

    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }

    if ((modrm >> 6) != 3) {
        const int src_bytes = evex_convert_type_bytes(src_type);
        const int dst_bytes = evex_convert_type_bytes(dst_type);
        const int element_bytes = MAX(src_bytes, dst_bytes);
        const int elements = (16 << vector_length) / element_bytes;
        const int memory_bytes = elements * src_bytes;
        const uint32_t desc = evex_convert_desc(
            dst, 0, vector_length, mask_reg, src_type, dst_type, zero,
            truncate, false, false, 0, evex_b);

        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm,
                evex_b ? src_bytes : memory_bytes, mask_reg, elements,
                src_bytes, evex_b)) {
            return true;
        }
        gen_helper_evex_convert_load(tcg_ctx, tcg_ctx->cpu_env, s->A0,
                                     tcg_const_i32(tcg_ctx, desc));
        return true;
    }

    src = modrm & 7;
    if (!(p0 & 0x20)) {
        src |= 8;
    }
    if (!(p0 & 0x40)) {
        src |= 16;
    }
    gen_helper_evex_convert_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(
            tcg_ctx,
            evex_convert_desc(dst, src, vector_length, mask_reg, src_type,
                              dst_type, zero, truncate, evex_b,
                              evex_b && allow_er,
                              evex_b && allow_er ? encoded_ll : 0, false)));
    return true;
}

static bool gen_evex_scalar_convert(CPUX86State *env, DisasContext *s,
                                    int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int mandatory = p1 & 3;
    const bool w = (p1 & 0x80) != 0;
    const bool evex_b = (p2 & 0x10) != 0;
    const bool zero = (p2 & 0x80) != 0;
    const int mask_reg = p2 & 7;
    const unsigned int encoded_ll = (p2 >> 5) & 3;
    EVEXConvertType src_type;
    EVEXConvertType dst_type;
    bool gpr_source = false;
    bool gpr_destination = false;
    bool truncate = false;
    bool allow_er = false;
    bool allow_sae = false;
    int modrm;
    int dst, src1 = 0, src2;

    if ((p0 & 3) != 1 || mandatory < 2) {
        return false;
    }

    if (opcode == 0x5a &&
        ((!w && mandatory == 2) || (w && mandatory == 3))) {
        src_type = w ? EVEX_CVT_F64 : EVEX_CVT_F32;
        dst_type = w ? EVEX_CVT_F32 : EVEX_CVT_F64;
        allow_er = w;
        allow_sae = !w;
    } else if (opcode == 0x2a || opcode == 0x7b) {
        gpr_source = true;
        src_type = opcode == 0x2a
                       ? (w ? EVEX_CVT_I64 : EVEX_CVT_I32)
                       : (w ? EVEX_CVT_U64 : EVEX_CVT_U32);
        dst_type = mandatory == 3 ? EVEX_CVT_F64 : EVEX_CVT_F32;
        allow_er = w || dst_type == EVEX_CVT_F32;
    } else if (opcode == 0x2d || opcode == 0x2c || opcode == 0x79 ||
               opcode == 0x78) {
        gpr_destination = true;
        src_type = mandatory == 3 ? EVEX_CVT_F64 : EVEX_CVT_F32;
        dst_type = (opcode == 0x79 || opcode == 0x78)
                       ? (w ? EVEX_CVT_U64 : EVEX_CVT_U32)
                       : (w ? EVEX_CVT_I64 : EVEX_CVT_I32);
        truncate = opcode == 0x2c || opcode == 0x78;
        allow_er = !truncate;
        allow_sae = truncate;
    } else {
        return false;
    }

    if (gpr_source && (mask_reg || zero)) {
        return false;
    }
    if (gpr_destination) {
        if ((p1 & 0x78) != 0x78 || !(p2 & 0x08) || mask_reg || zero) {
            return false;
        }
    } else if (zero && !mask_reg) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3 && evex_b) {
        return false;
    }
    if ((modrm >> 6) == 3 && evex_b && !allow_er && !allow_sae) {
        return false;
    }

    dst = apx_evex_reg_field(p0, modrm);
    if (gpr_destination && dst >= 16 &&
        (!CODE64(s) || !apx_f_enabled(s))) {
        gen_illegal_opcode(s);
        return true;
    }
    if (!gpr_destination) {
        src1 = (~p1 >> 3) & 15;
        if (!(p2 & 0x08)) {
            src1 |= 16;
        }
    }

    if ((modrm >> 6) != 3) {
        const uint32_t desc = evex_scalar_convert_desc(
            dst, src1, 0, mask_reg, src_type, dst_type, zero, truncate,
            false, false, 0, false, gpr_destination);

        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm,
                evex_convert_type_bytes(src_type), mask_reg, 1,
                evex_convert_type_bytes(src_type), false)) {
            return true;
        }
        gen_helper_evex_scalar_convert_load(tcg_ctx, tcg_ctx->cpu_env, s->A0,
                                            tcg_const_i32(tcg_ctx, desc));
        return true;
    }

    if (gpr_source) {
        src2 = apx_evex_rm_field(p0, modrm);
        if (src2 >= 16 && (!CODE64(s) || !apx_f_enabled(s))) {
            gen_illegal_opcode(s);
            return true;
        }
    } else {
        src2 = evex_vector_rm_field(p0, modrm);
    }
    gen_helper_evex_scalar_convert_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(
            tcg_ctx,
            evex_scalar_convert_desc(
                dst, src1, src2, mask_reg, src_type, dst_type, zero, truncate,
                evex_b, evex_b && allow_er,
                evex_b && allow_er ? encoded_ll : 0, gpr_source,
                gpr_destination)));
    return true;
}

static bool gen_evex_approx14_reg(CPUX86State *env, DisasContext *s,
                                   int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool scalar = (opcode & 1) != 0;
    const bool rsqrt = (opcode & 2) != 0;
    const bool is_double = (p1 & 0x80) != 0;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    const bool evex_b = (p2 & 0x10) != 0;
    int vector_length;
    int modrm;
    int dst, src1, src2;

    if ((p0 & 3) != 2 || (p1 & 3) != 1 || opcode < 0x4c ||
        opcode > 0x4f || (zero && !mask_reg)) {
        return false;
    }

    if (scalar) {
        /* EVEX.L'L is ignored for scalar forms. */
        vector_length = 0;
    } else {
        vector_length = (p2 >> 5) & 3;
        if ((p1 & 0x78) != 0x78 || !(p2 & 0x08) ||
            vector_length == 3) {
            return false;
        }
    }

    modrm = x86_ldub_code(env, s);
    if (!scalar && vector_length != 2 &&
        !x86_evex_require_features(s, CPUID_7_0_EBX_AVX512VL, 0, 0)) {
        return true;
    }
    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }
    src1 = 0;
    if (scalar) {
        src1 = (~p1 >> 3) & 15;
        if (!(p2 & 0x08)) {
            src1 |= 16;
        }
    }

    if ((modrm >> 6) != 3) {
        uint32_t desc;

        /* Scalar forms have neither broadcast nor SAE. */
        if (scalar && evex_b) {
            return false;
        }
        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm,
                scalar || evex_b ? (is_double ? 8 : 4)
                                 : 16 << vector_length,
                mask_reg,
                scalar ? 1
                       : (16 << vector_length) / (is_double ? 8 : 4),
                is_double ? 8 : 4, evex_b)) {
            return true;
        }
        desc = evex_approx14_desc(dst, src1, 0, vector_length, mask_reg,
                                 is_double, rsqrt, scalar, zero,
                                 evex_b && !scalar);
        gen_helper_evex_approx14_load(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc));
        return true;
    }

    if (evex_b) {
        return false;
    }
    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }
    gen_helper_evex_approx14_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx, evex_approx14_desc(
                                   dst, src1, src2, vector_length, mask_reg,
                                   is_double, rsqrt, scalar, zero, false)));
    return true;
}

static bool gen_evex_range(CPUX86State *env, DisasContext *s, int p0, int p1,
                           int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool scalar = opcode == 0x51;
    const bool is_double = (p1 & 0x80) != 0;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    const bool evex_b = (p2 & 0x10) != 0;
    int vector_length = (p2 >> 5) & 3;
    int modrm;
    int dst, src1, src2;
    unsigned int immediate;

    if ((p0 & 3) != 3 || (p1 & 3) != 1 || (opcode != 0x50 && opcode != 0x51) ||
        (zero && !mask_reg)) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if (scalar) {
        /* Scalar L'L is ignored.  EVEX.b selects SAE for register sources
         * and is reserved for memory sources. */
        vector_length = 0;
    } else if ((modrm >> 6) == 3 && evex_b) {
        /* The packed SAE form has a fixed effective length of 512 bits;
         * L'L is ignored rather than selecting a shorter vector. */
        vector_length = 2;
    } else if (vector_length == 3) {
        return false;
    }
    if (!x86_evex_require_features(
            s,
            CPUID_7_0_EBX_AVX512DQ |
                (!scalar && vector_length != 2
                     ? CPUID_7_0_EBX_AVX512VL
                     : 0),
            0, 0)) {
        return true;
    }
    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }
    src1 = (~p1 >> 3) & 15;
    if (!(p2 & 0x08)) {
        src1 |= 16;
    }

    if ((modrm >> 6) != 3) {
        uint32_t desc;

        if (scalar && evex_b) {
            return false;
        }
        /* The immediate follows the complete ModRM/SIB/displacement field,
         * so include it when resolving RIP-relative addressing. */
        s->rip_offset = 1;
        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm,
                scalar || evex_b ? (is_double ? 8 : 4)
                                 : 16 << vector_length,
                mask_reg,
                scalar ? 1
                       : (16 << vector_length) / (is_double ? 8 : 4),
                is_double ? 8 : 4, evex_b)) {
            return true;
        }
        immediate = x86_ldub_code(env, s);
        if (immediate & 0xf0) {
            return false;
        }
        desc =
            evex_range_desc(dst, src1, 0, vector_length, mask_reg, immediate,
                            is_double, scalar, zero, false, evex_b && !scalar);
        gen_helper_evex_range_load(tcg_ctx, tcg_ctx->cpu_env, s->A0,
                                   tcg_const_i32(tcg_ctx, desc));
        return true;
    }

    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }
    immediate = x86_ldub_code(env, s);
    if (immediate & 0xf0) {
        return false;
    }
    gen_helper_evex_range_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx, evex_range_desc(dst, src1, src2, vector_length,
                                               mask_reg, immediate, is_double,
                                               scalar, zero, evex_b, false)));
    return true;
}

static bool gen_evex_fp_transform(CPUX86State *env, DisasContext *s, int p0,
                                  int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    EVEXFPTransformKind kind;
    const bool scalar = opcode == 0x55 || opcode == 0x57 || opcode == 0x0a ||
                        opcode == 0x0b;
    const bool is_double = (p1 & 0x80) != 0;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    const bool evex_b = (p2 & 0x10) != 0;
    const unsigned int encoded_ll = (p2 >> 5) & 3;
    int vector_length = encoded_ll;
    int modrm;
    int dst, src1, src2;
    unsigned int immediate;

    switch (opcode) {
    case 0x54:
    case 0x55:
        kind = EVEX_FP_TRANSFORM_FIXUP;
        break;
    case 0x56:
    case 0x57:
        kind = EVEX_FP_TRANSFORM_REDUCE;
        break;
    case 0x08:
    case 0x09:
    case 0x0a:
    case 0x0b:
        kind = EVEX_FP_TRANSFORM_ROUNDSCALE;
        break;
    default:
        return false;
    }
    /* The two VRNDSCALE opcode pairs encode precision in the opcode as well
     * as EVEX.W.  Accepting the opposite W value aliases a reserved encoding
     * to the other precision instead of raising #UD. */
    if (kind == EVEX_FP_TRANSFORM_ROUNDSCALE &&
        ((opcode == 0x08 && is_double) ||
         (opcode == 0x09 && !is_double) ||
         (opcode == 0x0a && is_double) ||
         (opcode == 0x0b && !is_double))) {
        return false;
    }
    if ((p0 & 3) != 3 || (p1 & 3) != 1 || (zero && !mask_reg)) {
        return false;
    }
    if (kind != EVEX_FP_TRANSFORM_FIXUP && !scalar &&
        ((p1 & 0x78) != 0x78 || !(p2 & 0x08))) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if (scalar) {
        vector_length = 0; /* LLIG */
    } else if ((modrm >> 6) == 3 && evex_b) {
        /* B=1 selects SAE and makes LL ignored for packed register forms;
         * the architectural operation is always 512 bits. */
        vector_length = 2;
    } else if (vector_length == 3) {
        return false;
    }
    if (!x86_evex_require_features(
            s,
            (kind == EVEX_FP_TRANSFORM_REDUCE
                 ? CPUID_7_0_EBX_AVX512DQ
                 : 0) |
                (!scalar && vector_length != 2
                     ? CPUID_7_0_EBX_AVX512VL
                     : 0),
            0, 0)) {
        return true;
    }

    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }
    src1 = (~p1 >> 3) & 15;
    if (!(p2 & 0x08)) {
        src1 |= 16;
    }
    if (kind != EVEX_FP_TRANSFORM_FIXUP && !scalar) {
        src1 = 0;
    }

    if ((modrm >> 6) != 3) {
        uint32_t desc;

        if (scalar && evex_b) {
            return false; /* EVEX.b is reserved for scalar memory forms. */
        }
        s->rip_offset = 1;
        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm,
                scalar || evex_b ? (is_double ? 8 : 4)
                                 : 16 << vector_length,
                mask_reg,
                scalar ? 1
                       : (16 << vector_length) / (is_double ? 8 : 4),
                is_double ? 8 : 4, evex_b)) {
            return true;
        }
        immediate = x86_ldub_code(env, s);
        desc = evex_fp_transform_desc(
            dst, src1, 0, vector_length, mask_reg, kind, is_double, scalar,
            zero, false, evex_b && !scalar);
        gen_helper_evex_fp_transform_load(
            tcg_ctx, tcg_ctx->cpu_env, s->A0, tcg_const_i32(tcg_ctx, desc),
            tcg_const_i32(tcg_ctx, immediate));
        return true;
    }

    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }
    immediate = x86_ldub_code(env, s);
    gen_helper_evex_fp_transform_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx, evex_fp_transform_desc(
                                   dst, src1, src2, vector_length, mask_reg,
                                   kind, is_double, scalar, zero, evex_b,
                                   false)),
        tcg_const_i32(tcg_ctx, immediate));
    return true;
}

static bool gen_evex_get_fp(CPUX86State *env, DisasContext *s, int p0, int p1,
                            int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int map = p0 & 3;
    const bool mantissa = map == 3;
    const bool scalar = opcode == (mantissa ? 0x27 : 0x43);
    const bool is_double = (p1 & 0x80) != 0;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    const bool evex_b = (p2 & 0x10) != 0;
    int vector_length = (p2 >> 5) & 3;
    int modrm;
    int dst, src1, src2;
    unsigned int immediate = 0;

    if ((p1 & 3) != 1 || (zero && !mask_reg) ||
        (!mantissa && (map != 2 || (opcode != 0x42 && opcode != 0x43))) ||
        (mantissa && (opcode != 0x26 && opcode != 0x27))) {
        return false;
    }

    if (!scalar && ((p1 & 0x78) != 0x78 || !(p2 & 0x08))) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if (scalar) {
        /* Scalar forms are LLIG.  EVEX.b is SAE for register sources and is
         * reserved for memory sources. */
        vector_length = 0;
    } else if ((modrm >> 6) == 3 && evex_b) {
        /* Packed SAE fixes the effective vector length at 512 bits and the
         * encoded L'L bits are ignored. */
        vector_length = 2;
    } else if (vector_length == 3) {
        return false;
    }
    if (!scalar && vector_length != 2 &&
        !x86_evex_require_features(s, CPUID_7_0_EBX_AVX512VL, 0, 0)) {
        return true;
    }

    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }
    src1 = 0;
    if (scalar) {
        src1 = (~p1 >> 3) & 15;
        if (!(p2 & 0x08)) {
            src1 |= 16;
        }
    }

    if ((modrm >> 6) != 3) {
        uint32_t desc;

        if (scalar && evex_b) {
            return false;
        }
        if (mantissa) {
            /* Account for the trailing immediate in RIP-relative addresses. */
            s->rip_offset = 1;
        }
        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm,
                scalar || evex_b ? (is_double ? 8 : 4)
                                 : 16 << vector_length,
                mask_reg,
                scalar ? 1
                       : (16 << vector_length) / (is_double ? 8 : 4),
                is_double ? 8 : 4, evex_b && !scalar)) {
            return true;
        }
        if (mantissa) {
            immediate = x86_ldub_code(env, s);
        }
        desc = evex_get_fp_desc(dst, src1, 0, vector_length, mask_reg,
                                immediate, is_double, scalar, zero, false,
                                evex_b && !scalar, mantissa);
        gen_helper_evex_get_fp_load(tcg_ctx, tcg_ctx->cpu_env, s->A0,
                                    tcg_const_i32(tcg_ctx, desc));
        return true;
    }

    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }
    if (mantissa) {
        immediate = x86_ldub_code(env, s);
    }
    gen_helper_evex_get_fp_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_get_fp_desc(dst, src1, src2, vector_length,
                                       mask_reg, immediate, is_double, scalar,
                                       zero, evex_b, false, mantissa)));
    return true;
}

static bool gen_evex_scalef(CPUX86State *env, DisasContext *s, int p0, int p1,
                            int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool scalar = opcode == 0x2d;
    const bool is_double = (p1 & 0x80) != 0;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    const bool evex_b = (p2 & 0x10) != 0;
    const unsigned int encoded_ll = (p2 >> 5) & 3;
    int vector_length = encoded_ll;
    unsigned int rounding_mode = 0;
    int modrm;
    int dst, src1, src2;

    if ((p0 & 3) != 2 || (p1 & 3) != 1 || (opcode != 0x2c && opcode != 0x2d) ||
        (zero && !mask_reg)) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if (scalar) {
        /* LL is ignored without EVEX.b and encodes rounding with EVEX.b. */
        vector_length = 0;
    } else if ((modrm >> 6) == 3 && evex_b) {
        /* Packed embedded rounding is available only at effective VL=512. */
        vector_length = 2;
    } else if (vector_length == 3) {
        return false;
    }
    if (!scalar && vector_length != 2 &&
        !x86_evex_require_features(s, CPUID_7_0_EBX_AVX512VL, 0, 0)) {
        return true;
    }
    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }
    src1 = (~p1 >> 3) & 15;
    if (!(p2 & 0x08)) {
        src1 |= 16;
    }

    if ((modrm >> 6) != 3) {
        uint32_t desc;

        if (scalar && evex_b) {
            return false;
        }
        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm,
                scalar || evex_b ? (is_double ? 8 : 4)
                                 : 16 << vector_length,
                mask_reg,
                scalar ? 1
                       : (16 << vector_length) / (is_double ? 8 : 4),
                is_double ? 8 : 4, evex_b)) {
            return true;
        }
        desc = evex_scalef_desc(dst, src1, 0, vector_length, mask_reg,
                                rounding_mode, is_double, scalar, zero, false,
                                evex_b && !scalar);
        gen_helper_evex_scalef_load(tcg_ctx, tcg_ctx->cpu_env, s->A0,
                                    tcg_const_i32(tcg_ctx, desc));
        return true;
    }

    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }
    rounding_mode = evex_b ? encoded_ll : 0;
    gen_helper_evex_scalef_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_scalef_desc(dst, src1, src2, vector_length, mask_reg,
                                       rounding_mode, is_double, scalar, zero,
                                       evex_b, false)));
    return true;
}

static bool gen_evex_approx28_reg(CPUX86State *env, DisasContext *s,
                                  int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool is_double = (p1 & 0x80) != 0;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    const bool evex_b = (p2 & 0x10) != 0;
    bool scalar;
    bool rsqrt;
    bool exp2;
    int modrm;
    int dst, src1, src2;

    if ((p0 & 3) != 2 || (p1 & 3) != 1 || (zero && !mask_reg)) {
        return false;
    }

    switch (opcode) {
    case 0xc8: /* VEXP2PS/VEXP2PD */
        scalar = false;
        rsqrt = false;
        exp2 = true;
        break;
    case 0xca: /* VRCP28PS/VRCP28PD */
        scalar = false;
        rsqrt = false;
        exp2 = false;
        break;
    case 0xcb: /* VRCP28SS/VRCP28SD */
        scalar = true;
        rsqrt = false;
        exp2 = false;
        break;
    case 0xcc: /* VRSQRT28PS/VRSQRT28PD */
        scalar = false;
        rsqrt = true;
        exp2 = false;
        break;
    case 0xcd: /* VRSQRT28SS/VRSQRT28SD */
        scalar = true;
        rsqrt = true;
        exp2 = false;
        break;
    default:
        return false;
    }

    if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_AVX512ER)) {
        gen_illegal_opcode(s);
        return true;
    }

    if (scalar) {
        /* EVEX.L'L is ignored for scalar forms. */
        src1 = (~p1 >> 3) & 15;
        if (!(p2 & 0x08)) {
            src1 |= 16;
        }
    } else {
        /* AVX-512ER packed forms are 512-bit only; vvvv and V' are reserved. */
        if ((p1 & 0x78) != 0x78 || !(p2 & 0x08) ||
            ((p2 >> 5) & 3) != 2) {
            return false;
        }
        src1 = 0;
    }

    modrm = x86_ldub_code(env, s);
    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }

    if ((modrm >> 6) != 3) {
        uint32_t desc;

        /* SAE is register-only.  For packed memory EVEX.b selects broadcast;
         * scalar memory has neither broadcast nor SAE encoding. */
        if (scalar && evex_b) {
            return false;
        }
        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm,
                scalar || evex_b ? (is_double ? 8 : 4) : 64, mask_reg,
                scalar ? 1 : 64 / (is_double ? 8 : 4),
                is_double ? 8 : 4, evex_b)) {
            return true;
        }
        desc = evex_approx28_desc(dst, src1, 0, mask_reg, is_double,
                                 rsqrt, exp2, scalar, zero, false, evex_b);
        gen_helper_evex_approx28_load(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc));
        return true;
    }

    src2 = modrm & 7;
    if (!(p0 & 0x20)) {
        src2 |= 8;
    }
    if (!(p0 & 0x40)) {
        src2 |= 16;
    }

    gen_helper_evex_approx28_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_approx28_desc(dst, src1, src2, mask_reg,
                                         is_double, rsqrt, exp2, scalar,
                                         zero, evex_b, false)));
    return true;
}

typedef enum EVEXAMXRowDecodeResult {
    EVEX_AMX_ROW_NOT_HANDLED,
    EVEX_AMX_ROW_DECODED,
    EVEX_AMX_ROW_INVALID,
} EVEXAMXRowDecodeResult;

static AddressParts decode_rex2_memory_address_scaled(
    CPUX86State *env, DisasContext *s, int modrm, int rex2,
    int disp8_scale);
static void gen_rex2_memory_address(DisasContext *s, AddressParts address);
static void gen_rex2_load_gpr(DisasContext *s, TCGv_i64 value, int reg,
                              int width);

static void gen_evex_amx_tile_memory(CPUX86State *env, DisasContext *s,
                                     int p0, int p1, int modrm,
                                     unsigned int tile, bool store)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int rex2 = (!(p0 & 0x20) ? 0x01 : 0) |
                     (!(p0 & 0x40) ? 0x02 : 0) |
                     ((p0 & 0x08) ? 0x10 : 0) |
                     (!(p1 & 0x04) ? 0x20 : 0);
    const AddressParts address =
        decode_rex2_memory_address_scaled(env, s, modrm, rex2, 1);
    TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);
    uint32_t desc;

    /* AMX tile memory operands use the SIB base as the row-zero address and
     * the SIB index as the row stride.  Do not feed the index through the
     * ordinary effective-address adder: doing so would count it once before
     * the helper and again for every row. */
    tcg_gen_movi_i64(tcg_ctx, s->A0, address.disp);
    if (address.base >= 0) {
        gen_rex2_load_gpr(s, value, address.base, 8);
        tcg_gen_add_i64(tcg_ctx, s->A0, s->A0, value);
    }
    if (s->aflag == MO_32) {
        tcg_gen_ext32u_i64(tcg_ctx, s->A0, s->A0);
    }

    if (address.index < 0) {
        tcg_gen_movi_i64(tcg_ctx, s->T0, 0);
    } else {
        gen_rex2_load_gpr(s, s->T0, address.index, 8);
        if (s->aflag == MO_32) {
            tcg_gen_ext32u_i64(tcg_ctx, s->T0, s->T0);
        }
        if (address.scale) {
            tcg_gen_shli_i64(tcg_ctx, s->T0, s->T0, address.scale);
            if (s->aflag == MO_32) {
                tcg_gen_ext32u_i64(tcg_ctx, s->T0, s->T0);
            }
        }
    }

    desc = amx_memory_desc(s, address, tile, store);
    gen_helper_amx_tileloadstore(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->T0,
                                 tcg_const_i32(tcg_ctx, desc),
                                 tcg_const_tl(tcg_ctx,
                                              s->pc_start - s->cs_base));
    tcg_temp_free_i64(tcg_ctx, value);
}

static EVEXAMXRowDecodeResult gen_evex_amx_config(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int mandatory = p1 & 3;
    const bool store = mandatory == 1;
    int modrm;
    int rex2;
    AddressParts address;
    uint32_t desc;

    if ((p0 & 7) != 2 || opcode != 0x49) {
        return EVEX_AMX_ROW_NOT_HANDLED;
    }
    /* EVEX-promoted TILECFG access keeps R/R' ignored for ModRM /0, while
     * B4 and X4 extend the address base/index into the APX register bank. */
    if ((p1 & 0xf8) != 0x78 || p2 != 0x08 || mandatory > 1 ||
        !x86_amx_enabled(s) || !apx_f_enabled(s)) {
        return EVEX_AMX_ROW_INVALID;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) == 3 || (modrm & 0x38) != 0) {
        return EVEX_AMX_ROW_INVALID;
    }
    rex2 = (!(p0 & 0x20) ? 0x01 : 0) |
           (!(p0 & 0x40) ? 0x02 : 0) |
           ((p0 & 0x08) ? 0x10 : 0) |
           (!(p1 & 0x04) ? 0x20 : 0);
    address = decode_rex2_memory_address_scaled(env, s, modrm, rex2, 1);
    desc = amx_memory_desc(s, address, 0, store);
    gen_rex2_memory_address(s, address);
    if (store) {
        gen_helper_amx_sttilecfg(tcg_ctx, tcg_ctx->cpu_env, s->A0,
                                 tcg_const_i32(tcg_ctx, desc),
                                 tcg_const_tl(tcg_ctx,
                                              s->pc_start - s->cs_base));
    } else {
        gen_helper_amx_ldtilecfg(tcg_ctx, tcg_ctx->cpu_env, s->A0,
                                 tcg_const_i32(tcg_ctx, desc));
    }
    return EVEX_AMX_ROW_DECODED;
}

static EVEXAMXRowDecodeResult gen_evex_amx_tile_memory_decode(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode)
{
    const unsigned int mandatory = p1 & 3;
    bool store;
    int modrm;

    if ((p0 & 7) != 2 || (opcode != 0x4a && opcode != 0x4b)) {
        return EVEX_AMX_ROW_NOT_HANDLED;
    }
    /* Map-2 opcode 4A also owns the LL=2 AMX-AVX512 row forms. */
    if (opcode == 0x4a && (p2 & 0x7f) != 0x08) {
        return EVEX_AMX_ROW_NOT_HANDLED;
    }
    if ((p1 & 0xf8) != 0x78 ||
        (opcode == 0x4a ? (p2 & 0x7f) != 0x08 : p2 != 0x08) ||
        (opcode == 0x4a
             ? (mandatory != 1 && mandatory != 3)
             : (mandatory != 1 && mandatory != 2 && mandatory != 3)) ||
        !x86_amx_enabled(s) || !apx_f_enabled(s) ||
        (opcode == 0x4a &&
         !x86_amx_extended_feature(
             env, CPUID_1E_1_EAX_AMX_MOVRS))) {
        return EVEX_AMX_ROW_INVALID;
    }

    modrm = x86_ldub_code(env, s);
    /* The SIB index is the architectural stride operand. */
    if ((p0 & 0x90) != 0x90 || (modrm >> 6) == 3 || (modrm & 7) != 4) {
        return EVEX_AMX_ROW_INVALID;
    }
    store = opcode == 0x4b && mandatory == 2;
    gen_evex_amx_tile_memory(env, s, p0, p1, modrm,
                             (modrm >> 3) & 7, store);
    return EVEX_AMX_ROW_DECODED;
}

static EVEXAMXRowDecodeResult gen_evex_amx_tile_row(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const unsigned int map = p0 & 7;
    const unsigned int mandatory = p1 & 3;
    AMXTileRowOp operation;
    bool immediate;
    int modrm;
    unsigned int dst;
    unsigned int src;
    unsigned int selector;
    uint32_t desc;

    if (map == 2 && opcode == 0x4a) {
        immediate = false;
        if (mandatory == 1) {
            operation = AMX_ROW_MOVE;
        } else if (mandatory == 2) {
            operation = AMX_ROW_D2PS;
        } else {
            return EVEX_AMX_ROW_NOT_HANDLED;
        }
    } else if (map == 2 && opcode == 0x6d) {
        immediate = false;
        switch (mandatory) {
        case 0:
            operation = AMX_ROW_PS2PHH;
            break;
        case 1:
            operation = AMX_ROW_PS2PHL;
            break;
        case 2:
            operation = AMX_ROW_PS2BF16L;
            break;
        case 3:
            operation = AMX_ROW_PS2BF16H;
            break;
        default:
            g_assert_not_reached();
        }
    } else if (map == 3 && opcode == 0x07) {
        immediate = true;
        switch (mandatory) {
        case 0:
            operation = AMX_ROW_PS2PHH;
            break;
        case 1:
            operation = AMX_ROW_MOVE;
            break;
        case 2:
            operation = AMX_ROW_D2PS;
            break;
        case 3:
            operation = AMX_ROW_PS2BF16H;
            break;
        default:
            g_assert_not_reached();
        }
    } else if (map == 3 && opcode == 0x77) {
        immediate = true;
        if (mandatory == 2) {
            operation = AMX_ROW_PS2BF16L;
        } else if (mandatory == 3) {
            operation = AMX_ROW_PS2PHL;
        } else {
            return EVEX_AMX_ROW_NOT_HANDLED;
        }
    } else {
        return EVEX_AMX_ROW_NOT_HANDLED;
    }

    if ((p1 & 0x80) || !(p1 & 0x04) || (p0 & 0x60) != 0x60 ||
        (p2 & 0x80) ||
        (p2 & 0x10) || (p2 & 7) || ((p2 >> 5) & 3) != 2) {
        return EVEX_AMX_ROW_INVALID;
    }
    if (immediate && ((p1 & 0x78) != 0x78 || !(p2 & 0x08))) {
        return EVEX_AMX_ROW_INVALID;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return EVEX_AMX_ROW_INVALID;
    }

    dst = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        dst |= 8;
    }
    if (!(p0 & 0x10)) {
        dst |= 16;
    }
    src = modrm & 7;

    if (immediate) {
        selector = x86_ldub_code(env, s);
    } else {
        selector = (~p1 >> 3) & 15;
        if (!(p2 & 0x08)) {
            selector |= 16;
        }
    }

    if (!x86_amx_enabled(s) ||
        !x86_amx_extended_feature(
            env, CPUID_1E_1_EAX_AMX_AVX512) ||
        !x86_avx512_enabled(s) ||
        (!immediate && selector >= 16 && !apx_f_enabled(s))) {
        return EVEX_AMX_ROW_INVALID;
    }
    /* AMX-AVX512 row operations use SIMD state and therefore retain the
     * architectural TS -> #NM behavior, but AMX does not consult CR0.EM. */
    if (s->flags & HF_TS_MASK) {
        gen_exception(s, EXCP07_PREX, s->pc_start - s->cs_base);
        return EVEX_AMX_ROW_DECODED;
    }

    desc = (dst << AMX_ROW_DST_SHIFT) | (src << AMX_ROW_SRC_SHIFT) |
           ((uint32_t)operation << AMX_ROW_OP_SHIFT) |
           (immediate ? AMX_ROW_IMMEDIATE : 0) |
           (selector << AMX_ROW_SELECTOR_SHIFT);
    gen_helper_amx_tile_row(tcg_ctx, tcg_ctx->cpu_env,
                            tcg_const_i32(tcg_ctx, desc));
    return EVEX_AMX_ROW_DECODED;
}

/* Strict EVEX slices for selected packed integer register and move forms. */
static bool gen_evex_instruction(CPUX86State *env, DisasContext *s,
                                 int rex_byte, bool approx14_only)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int p0 = x86_ldub_code(env, s);
    int p1 = x86_ldub_code(env, s);
    int p2 = x86_ldub_code(env, s);
    int opcode = x86_ldub_code(env, s);
    target_ulong operand_pc = s->pc;
    int modrm;
    int reg, rm;
    int vector_length;
    int element_shift;
    int mask_reg;
    bool zero;

#ifdef TARGET_X86_64
    {
        const APXEVEXDecodeResult atomic =
            gen_apx_evex_atomic(env, s, rex_byte, p0, p1, p2, opcode);

        if (atomic != APX_EVEX_NOT_HANDLED) {
            return atomic == APX_EVEX_DECODED;
        }
    }
    {
        const APXEVEXDecodeResult msr =
            gen_apx_evex_msr(env, s, rex_byte, p0, p1, p2, opcode);

        if (msr != APX_EVEX_NOT_HANDLED) {
            return msr == APX_EVEX_DECODED;
        }
    }
    /* Promoted APX scalar instructions own EVEX map 4.  Do not let malformed
     * map-4 encodings fall through to legacy EVEX vector slices. */
    if (CODE64(s) && (p0 & 7) == 4) {
        const APXEVEXDecodeResult system =
            gen_apx_evex_system(env, s, rex_byte, p0, p1, p2, opcode);

        if (system != APX_EVEX_NOT_HANDLED) {
            return system == APX_EVEX_DECODED;
        }
        const APXEVEXDecodeResult direct_move =
            gen_apx_evex_direct_move(env, s, rex_byte, p0, p1, p2, opcode);

        if (direct_move != APX_EVEX_NOT_HANDLED) {
            return direct_move == APX_EVEX_DECODED;
        }
        const APXEVEXDecodeResult conditional =
            gen_apx_evex_conditional(env, s, rex_byte, p0, p1, p2,
                                     opcode);

        if (conditional != APX_EVEX_NOT_HANDLED) {
            return conditional == APX_EVEX_DECODED;
        }
        if (!apx_nci_enabled(s)) {
            return false;
        }
        if ((opcode == 0xff || opcode == 0x8f) &&
            (translator_ldub(env->uc->tcg_ctx, env, s->pc) & 0x38) ==
                (opcode == 0xff ? 0x30 : 0)) {
            return gen_apx_push2_pop2(env, s, rex_byte, p0, p1, p2,
                                      opcode);
        }
        if (opcode >= 0x40 && opcode <= 0x4f) {
            if ((p1 & 3) == 3) {
                return gen_apx_evex_setcc(env, s, rex_byte, p0, p1, p2,
                                          opcode);
            }
            return gen_apx_evex_cmovcc(env, s, rex_byte, p0, p1, p2,
                                       opcode);
        }
        return gen_apx_evex_register(env, s, rex_byte, p0, p1, p2, opcode);
    }
#endif

    /* EVEX map 5 opcode 6F is VMOVRS and additionally requires AVX10.
     * AVX10 state is not modeled, so fail closed instead of aliasing the
     * map-1 VMOVDQU decoder below. */
    if ((p0 & 7) == 5 && opcode == 0x6f) {
        return false;
    }

#ifdef TARGET_X86_64
    if (CODE64(s) && !rex_byte &&
        !(s->prefix &
          (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ)) &&
        apx_nci_enabled(s)) {
        const APXEVEXDecodeResult apx_bmi =
            gen_apx_evex_bmi_register(env, s, p0, p1, p2, opcode);

        if (apx_bmi != APX_EVEX_NOT_HANDLED) {
            return apx_bmi == APX_EVEX_DECODED;
        }
    }

#endif

    if (CODE64(s) && !rex_byte &&
        !(s->prefix &
          (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ))) {
        EVEXAMXRowDecodeResult amx;

        s->pc = operand_pc;
        amx = gen_evex_amx_config(env, s, p0, p1, p2, opcode);
        if (amx != EVEX_AMX_ROW_NOT_HANDLED) {
            return amx == EVEX_AMX_ROW_DECODED;
        }

        s->pc = operand_pc;
        amx = gen_evex_amx_tile_memory_decode(env, s, p0, p1, p2,
                                              opcode);
        if (amx != EVEX_AMX_ROW_NOT_HANDLED) {
            return amx == EVEX_AMX_ROW_DECODED;
        }

        s->pc = operand_pc;
        amx = gen_evex_amx_tile_row(env, s, p0, p1, p2, opcode);
        if (amx != EVEX_AMX_ROW_NOT_HANDLED) {
            return amx == EVEX_AMX_ROW_DECODED;
        }
    }

    /* APX scalar owners above do not use the SIMD state.  All remaining
     * EVEX owners do, and therefore preserve the architectural CR0 fault
     * ordering used by the legacy SSE/VEX decoder. */
    if (s->flags & HF_TS_MASK) {
        gen_exception(s, EXCP07_PREX, s->pc_start - s->cs_base);
        return true;
    }
    if (s->flags & HF_EM_MASK) {
        gen_illegal_opcode(s);
        return true;
    }

    /* APX and AMX have already had the opportunity to claim their EVEX
     * maps.  Every remaining EVEX family requires AVX-512F plus the complete
     * architectural opmask/ZMM state cached in the translation flags. */
    if (!x86_avx512_enabled(s)) {
        gen_illegal_opcode(s);
        return true;
    }

    /* U is not an ignored X4 for ModRM.Mod = 3.  Reject that reserved
     * encoding before any SIMD owner can publish register effects. */
    if (!(p1 & X86EvexUMask) &&
        (translator_ldub(tcg_ctx, env, operand_pc) & X86EvexModMask) ==
            X86EvexRegisterMod) {
        return false;
    }

#ifdef TARGET_X86_64
    if (CODE64(s) && !rex_byte &&
        !(s->prefix &
          (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ)) &&
        apx_f_enabled(s)) {
        const APXEVEXDecodeResult apx_kmov =
            gen_apx_evex_kmov(env, s, p0, p1, p2, opcode);

        if (apx_kmov != APX_EVEX_NOT_HANDLED) {
            return apx_kmov == APX_EVEX_DECODED;
        }
    }

    if (CODE64(s) && !rex_byte &&
        !(s->prefix &
          (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ))) {
        const APXEVEXDecodeResult scalar_lane =
            gen_evex_scalar_lane(env, s, p0, p1, p2, opcode);

        if (scalar_lane != APX_EVEX_NOT_HANDLED) {
            return scalar_lane == APX_EVEX_DECODED;
        }

        const APXEVEXDecodeResult broadcast_lane =
            gen_evex_broadcast_lane(env, s, p0, p1, p2, opcode);

        if (broadcast_lane != APX_EVEX_NOT_HANDLED) {
            return broadcast_lane == APX_EVEX_DECODED;
        }

        const APXEVEXDecodeResult gpr_vector_move =
            gen_evex_gpr_vector_move(env, s, p0, p1, p2, opcode);

        if (gpr_vector_move != APX_EVEX_NOT_HANDLED) {
            return gpr_vector_move == APX_EVEX_DECODED;
        }

        const APXEVEXDecodeResult half_move =
            gen_evex_half_move(env, s, p0, p1, p2, opcode);

        if (half_move != APX_EVEX_NOT_HANDLED) {
            return half_move == APX_EVEX_DECODED;
        }

        const APXEVEXDecodeResult scalar_move =
            gen_evex_scalar_move(env, s, p0, p1, p2, opcode);

        if (scalar_move != APX_EVEX_NOT_HANDLED) {
            return scalar_move == APX_EVEX_DECODED;
        }

        const APXEVEXDecodeResult non_temporal_move =
            gen_evex_non_temporal_move(env, s, p0, p1, p2, opcode);

        if (non_temporal_move != APX_EVEX_NOT_HANDLED) {
            return non_temporal_move == APX_EVEX_DECODED;
        }

        /* Scalar conversions can use APX B4/X4 for an EGPR source or an
         * extended memory address.  Give those encodings an owner before
         * the legacy EVEX fixed-bit check rejects the promoted fields. */
        if (apx_f_enabled(s) && ((p0 & 0x08) || !(p1 & 0x04))) {
            s->pc = operand_pc;
            if (gen_evex_scalar_convert(env, s, p0, p1, p2, opcode)) {
                return true;
            }
        }
    }
#endif

    /* EVEX cannot be combined with REX, LOCK, operand-size or REP prefixes.
     * P0[2] remains fixed.  APX promotes P0.B4 and P1.X4 only when an
     * existing EVEX form actually consumes the corresponding GPR address or
     * scalar field; unused B4 and memory-form X4 are ignored. */
    if (rex_byte ||
        (s->prefix &
         (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ)) ||
        (p0 & 0x04) != 0) {
        return false;
    }

    /* Non-64-bit mode has only XMM0-XMM7 and EAX-EDI.  The EVEX extension
     * bits must therefore remain encoded as one, including the high vvvv
     * extension. */
    if (!CODE64(s) && ((p0 & 0xf0) != 0xf0 || !(p1 & 0x40) || !(p2 & 0x08))) {
        return false;
    }

    /* The 32-bit entry point is deliberately limited to strict families
     * whose non-extended register and addressing contracts are tested. */
    if (approx14_only) {
        s->pc = operand_pc;
        if (gen_evex_fp_transform(env, s, p0, p1, p2, opcode)) {
            return true;
        }
        s->pc = operand_pc;
        if (gen_evex_approx14_reg(env, s, p0, p1, p2, opcode)) {
            return true;
        }
        s->pc = operand_pc;
        if (gen_evex_range(env, s, p0, p1, p2, opcode)) {
            return true;
        }
        s->pc = operand_pc;
        if (gen_evex_get_fp(env, s, p0, p1, p2, opcode)) {
            return true;
        }
        s->pc = operand_pc;
        return gen_evex_scalef(env, s, p0, p1, p2, opcode);
    }

    /* Candidate decoders are transactional.  A rejected candidate may have
     * inspected ModRM or an immediate, but the next candidate must always
     * start at the architectural operand byte. */
    s->pc = operand_pc;
    if (gen_evex_fp_arith(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_fma(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_convert(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_scalar_convert(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_packed_compare_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_legacy_compare_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_crypto(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_dbpsadbw(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_four_memory_ops(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_fpclass(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_comi(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_fcmp(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_packed_int_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_packed_shift_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_bit_shuffle_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_mask_test_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_ternlog_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_shuffle_imm_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_lane_int_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_mask_convert_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_widen_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_narrow_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_vector_move_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_compress_expand_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_approx14_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_fp_transform(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_range(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_get_fp(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_scalef(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    if (gen_evex_approx28_reg(env, s, p0, p1, p2, opcode)) {
        return true;
    }

    s->pc = operand_pc;
    /* vvvv/V' are reserved, EVEX.b is unavailable, and LL=3 is reserved. */
    if ((p0 & 3) != 1 || (p1 & 0x78) != 0x78 ||
        ((p1 & 3) != 2 && (p1 & 3) != 3) || !(p2 & 0x08) || (p2 & 0x10) ||
        ((p2 >> 5) & 3) == 3 || (opcode != 0x6f && opcode != 0x7f)) {
        return false;
    }
    vector_length = (p2 >> 5) & 3;
    if (vector_length != 2 &&
        !(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_AVX512VL)) {
        gen_illegal_opcode(s);
        return true;
    }
    mask_reg = p2 & 7;
    zero = (p2 & 0x80) != 0;
    if (zero && !mask_reg) {
        return false;
    }

    /* F2 selects byte/word and F3 selects dword/qword; W picks the pair. */
    if ((p1 & 3) == 3) {
        element_shift = (p1 & 0x80) ? 1 : 0;
    } else {
        element_shift = (p1 & 0x80) ? 3 : 2;
    }
    if (element_shift < 2 &&
        !(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_AVX512BW)) {
        gen_illegal_opcode(s);
        return true;
    }

    modrm = x86_ldub_code(env, s);
    reg = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        reg |= 8;
    }
    if (!(p0 & 0x10)) {
        reg |= 16;
    }

    if ((modrm >> 6) != 3) {
        uint32_t desc;

        if (opcode == 0x7f && zero) {
            return false;
        }
        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm, 16 << vector_length, mask_reg,
                (16 << vector_length) >> element_shift,
                1 << element_shift, false)) {
            return true;
        }
        desc = evex_vmovdqu_desc(reg, 0, element_shift, vector_length, mask_reg,
                                 zero);
        if (opcode == 0x6f) {
            gen_helper_evex_vmovdqu_load(tcg_ctx, tcg_ctx->cpu_env, s->A0,
                                         tcg_const_i32(tcg_ctx, desc));
        } else {
            gen_helper_evex_vmovdqu_store(
                tcg_ctx, tcg_ctx->cpu_env, s->A0, tcg_const_i32(tcg_ctx, desc),
                tcg_const_tl(tcg_ctx, s->pc_start - s->cs_base));
        }
        return true;
    }

    rm = modrm & 7;
    if (!(p0 & 0x20)) {
        rm |= 8;
    }
    if (!(p0 & 0x40)) {
        rm |= 16;
    }

    if (opcode == 0x7f) {
        int tmp = reg;
        reg = rm;
        rm = tmp;
    }
    gen_helper_evex_vmovdqu_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      evex_vmovdqu_desc(reg, rm, element_shift, vector_length,
                                        mask_reg, zero)));
    return true;
}

#ifdef TARGET_X86_64
static bool gen_apx_push2_pop2(CPUX86State *env, DisasContext *s,
                               int rex_byte, int p0, int p1, int p2,
                               int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool push = opcode == 0xff;
    int modrm;
    int v, b;
    uint32_t desc;

    if ((p0 & 7) != 4 || rex_byte ||
        (s->prefix &
         (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ)) ||
        !(p1 & 0x04) || (p1 & 3) != 0 || (p2 & 0xe7) != 0 ||
        !(p2 & 0x10)) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3 ||
        (push ? (modrm & 0x38) != 0x30 : (modrm & 0x38) != 0)) {
        return false;
    }

    v = ((~p2 & 0x08) << 1) | ((~p1 & 0x78) >> 3);
    b = ((~p0 & 0x20) >> 2) | ((p0 & 0x08) << 1) | (modrm & 7);
    if (v == R_ESP || b == R_ESP || (!push && v == b)) {
        return false;
    }

    desc = (v << APX_PAIR_V_SHIFT) | (b << APX_PAIR_B_SHIFT) |
           (push ? APX_PAIR_PUSH : 0);
    gen_helper_apx_push2_pop2(
        tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, desc),
        tcg_const_tl(tcg_ctx, s->pc_start - s->cs_base));
    return true;
}

static int apx_gpr_offset(int reg)
{
    if (reg < 16) {
        return offsetof(CPUX86State, regs[reg]);
    }
    return offsetof(CPUX86State, apx_regs[reg - 16]);
}

static void gen_apx_mark_inuse(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 inuse = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ld_i64(tcg_ctx, inuse, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, xstate_bv));
    tcg_gen_ori_i64(tcg_ctx, inuse, inuse, XSTATE_APX_MASK);
    tcg_gen_st_i64(tcg_ctx, inuse, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, xstate_bv));
    tcg_temp_free_i64(tcg_ctx, inuse);
}

static void gen_rex2_load_gpr(DisasContext *s, TCGv_i64 value, int reg,
                              int width)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (reg < 16) {
        tcg_gen_mov_i64(tcg_ctx, value, tcg_ctx->cpu_regs[reg]);
    } else {
        tcg_gen_ld_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                       apx_gpr_offset(reg));
    }
    switch (width) {
    case 1:
        tcg_gen_ext8u_i64(tcg_ctx, value, value);
        break;
    case 2:
        tcg_gen_ext16u_i64(tcg_ctx, value, value);
        break;
    case 4:
        tcg_gen_ext32u_i64(tcg_ctx, value, value);
        break;
    }
}

static void gen_rex2_store_gpr(DisasContext *s, int reg, TCGv_i64 value,
                               int width)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (reg < 16) {
        switch (width) {
        case 1:
        case 2:
            tcg_gen_deposit_i64(tcg_ctx, tcg_ctx->cpu_regs[reg],
                                tcg_ctx->cpu_regs[reg], value, 0,
                                width * 8);
            return;
        case 4:
            tcg_gen_ext32u_i64(tcg_ctx, tcg_ctx->cpu_regs[reg], value);
            return;
        default:
            tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_regs[reg], value);
            return;
        }
    }
    gen_apx_mark_inuse(s);
    if (width == 1 || width == 2) {
        TCGv_i64 merged = tcg_temp_new_i64(tcg_ctx);

        tcg_gen_ld_i64(tcg_ctx, merged, tcg_ctx->cpu_env, apx_gpr_offset(reg));
        tcg_gen_deposit_i64(tcg_ctx, merged, merged, value, 0, width * 8);
        tcg_gen_st_i64(tcg_ctx, merged, tcg_ctx->cpu_env, apx_gpr_offset(reg));
        tcg_temp_free_i64(tcg_ctx, merged);
        return;
    }
    if (width == 4) {
        tcg_gen_ext32u_i64(tcg_ctx, value, value);
    }
    tcg_gen_st_i64(tcg_ctx, value, tcg_ctx->cpu_env, apx_gpr_offset(reg));
}

static AddressParts decode_rex2_memory_address(CPUX86State *env,
                                               DisasContext *s, int modrm,
                                               int rex2);
static AddressParts decode_rex2_memory_address_scaled(
    CPUX86State *env, DisasContext *s, int modrm, int rex2,
    int disp8_scale);
static void gen_rex2_memory_address(DisasContext *s, AddressParts address);
static void gen_rex2_load_memory(DisasContext *s, TCGv_i64 value, int width);
static void gen_rex2_store_memory(DisasContext *s, TCGv_i64 value, int width);
static void gen_rex2_memory_range_check(DisasContext *s,
                                        bool stack_segment, int width);
static int apx_evex_v_field(int p1, int p2);

static bool gen_apx_evex_setcc(CPUX86State *env, DisasContext *s,
                               int rex_byte, int p0, int p1, int p2,
                               int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int modrm, mod, rm;
    const bool nd = (p2 & 0x10) != 0;

    if ((p0 & 7) != 4 || rex_byte || opcode < 0x40 || opcode > 0x4f ||
        (s->prefix &
         (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ)) ||
        (p1 & 0x78) != 0x78 || (p1 & 3) != 3 || !(p2 & 0x08) ||
        (p2 & 0xe7)) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    if (mod == 3) {
        if (!(p1 & 0x04)) {
            return false;
        }
        rm = modrm & 7;
        if (!(p0 & 0x20)) {
            rm |= 8;
        }
        if (p0 & 0x08) {
            rm |= 16;
        }

        gen_setcc1(s, opcode & 15, s->T0);
        gen_rex2_store_gpr(s, rm, s->T0, nd ? 8 : 1);
    } else {
        const int rex2 = (!(p0 & 0x20) ? 0x01 : 0) |
                         (!(p0 & 0x40) ? 0x02 : 0) |
                         ((p0 & 0x08) ? 0x10 : 0) |
                         (!(p1 & 0x04) ? 0x20 : 0);
        AddressParts address =
            decode_rex2_memory_address(env, s, modrm, rex2);
        const bool stack_segment =
            s->override == R_SS ||
            (s->override < 0 && address.def_seg == R_SS);

        gen_rex2_memory_address(s, address);
        gen_helper_apx_memory_check(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, stack_segment ? APX_MEMORY_SS : 0));
        gen_setcc1(s, opcode & 15, s->T0);
        gen_rex2_store_memory(s, s->T0, 1);
    }
    return true;
}

static void gen_apx_evex_cmov_memory_check(DisasContext *s,
                                           bool stack_segment, int width)
{
    gen_rex2_memory_range_check(s, stack_segment, width);
}

static bool gen_apx_evex_cmovcc(CPUX86State *env, DisasContext *s,
                                int rex_byte, int p0, int p1, int p2,
                                int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool nd = (p2 & 0x10) != 0;
    const bool nf = (p2 & 0x04) != 0;
    int modrm, mod;
    int reg, rm = -1, ndd = -1;
    int width;

    /* LL/z/aaa and payload bit 1 are reserved.  VVVVV is reserved at
     * decoded zero for the two-operand forms and names NDD otherwise. */
    if ((p0 & 7) != 4 || rex_byte || opcode < 0x40 || opcode > 0x4f ||
        (s->prefix &
         (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ)) ||
        (p1 & 3) > 1 || (p2 & 0xe3) ||
        (!nd && ((p1 & 0x78) != 0x78 || !(p2 & 0x08)))) {
        return false;
    }

    width = (p1 & 0x80) ? 8 : (p1 & 1) ? 2 : 4;
    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    if (mod == 3 && !(p1 & 0x04)) {
        return false;
    }

    reg = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        reg |= 8;
    }
    if (!(p0 & 0x10)) {
        reg |= 16;
    }
    if (nd) {
        ndd = (~p1 >> 3) & 15;
        if (!(p2 & 0x08)) {
            ndd |= 16;
        }
    }

    if (mod == 3) {
        TCGv_i64 reg_value = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 rm_value = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 condition = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 result = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);
        int destination;

        rm = modrm & 7;
        if (!(p0 & 0x20)) {
            rm |= 8;
        }
        if (p0 & 0x08) {
            rm |= 16;
        }
        destination = nd ? ndd : nf ? rm : reg;

        /* Both old source values precede the full-register destination
         * update so every legal source/destination alias is well-defined. */
        gen_rex2_load_gpr(s, reg_value, reg, width);
        gen_rex2_load_gpr(s, rm_value, rm, width);
        gen_setcc1(s, opcode & 15, condition);
        tcg_gen_movcond_i64(
            tcg_ctx, TCG_COND_NE, result, condition, zero,
            !nd && nf ? reg_value : rm_value, nd ? reg_value : zero);
        gen_rex2_store_gpr(s, destination, result, 8);

        tcg_temp_free_i64(tcg_ctx, reg_value);
        tcg_temp_free_i64(tcg_ctx, rm_value);
        tcg_temp_free_i64(tcg_ctx, condition);
        tcg_temp_free_i64(tcg_ctx, result);
        tcg_temp_free_i64(tcg_ctx, zero);
        return true;
    }

    {
        const int rex2 = (!(p0 & 0x20) ? 0x01 : 0) |
                         (!(p0 & 0x40) ? 0x02 : 0) |
                         ((p0 & 0x08) ? 0x10 : 0) |
                         (!(p1 & 0x04) ? 0x20 : 0);
        AddressParts address =
            decode_rex2_memory_address(env, s, modrm, rex2);
        const bool stack_segment =
            s->override == R_SS ||
            (s->override < 0 && address.def_seg == R_SS);
        TCGv_i64 reg_value = tcg_temp_local_new_i64(tcg_ctx);
        TCGv_i64 address_value = tcg_temp_local_new_i64(tcg_ctx);

        /* Effective-address arithmetic is non-faulting and must observe all
         * old address-register values before a possibly aliased destination
         * is committed.  The canonical check and actual access remain in
         * the conditionally executed region where required. */
        gen_rex2_load_gpr(s, reg_value, reg, width);
        gen_rex2_memory_address(s, address);
        tcg_gen_mov_i64(tcg_ctx, address_value, s->A0);

        if (nd && !nf) {
            TCGv_i64 memory_value = tcg_temp_new_i64(tcg_ctx);
            TCGv_i64 condition = tcg_temp_new_i64(tcg_ctx);
            TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);

            /* The ordinary NDD CMOV form always fetches r/m, even when the
             * condition is false, and therefore never suppresses faults. */
            gen_apx_evex_cmov_memory_check(s, stack_segment, width);
            gen_rex2_load_memory(s, memory_value, width);
            gen_setcc1(s, opcode & 15, condition);
            tcg_gen_movcond_i64(tcg_ctx, TCG_COND_NE, memory_value,
                                condition, zero, memory_value, reg_value);
            gen_rex2_store_gpr(s, ndd, memory_value, 8);

            tcg_temp_free_i64(tcg_ctx, memory_value);
            tcg_temp_free_i64(tcg_ctx, condition);
            tcg_temp_free_i64(tcg_ctx, zero);
        } else if (!nd && nf) {
            TCGLabel *taken = gen_new_label(tcg_ctx);
            TCGLabel *done = gen_new_label(tcg_ctx);

            /* The reversed two-operand form stores only when selected; the
             * entire memory operation, including address faults, is absent
             * from the false path. */
            gen_jcc1_noeob(s, opcode & 15, taken);
            tcg_gen_br(tcg_ctx, done);
            gen_set_label(tcg_ctx, taken);
            tcg_gen_mov_i64(tcg_ctx, s->A0, address_value);
            gen_apx_evex_cmov_memory_check(s, stack_segment, width);
            gen_rex2_store_memory(s, reg_value, width);
            gen_set_label(tcg_ctx, done);
        } else {
            TCGv_i64 result = tcg_temp_local_new_i64(tcg_ctx);
            TCGLabel *taken = gen_new_label(tcg_ctx);
            TCGLabel *done = gen_new_label(tcg_ctx);
            const int destination = nd ? ndd : reg;

            if (nd) {
                tcg_gen_mov_i64(tcg_ctx, result, reg_value);
            } else {
                tcg_gen_movi_i64(tcg_ctx, result, 0);
            }
            gen_jcc1_noeob(s, opcode & 15, taken);
            tcg_gen_br(tcg_ctx, done);
            gen_set_label(tcg_ctx, taken);
            tcg_gen_mov_i64(tcg_ctx, s->A0, address_value);
            gen_apx_evex_cmov_memory_check(s, stack_segment, width);
            gen_rex2_load_memory(s, result, width);
            gen_set_label(tcg_ctx, done);
            gen_rex2_store_gpr(s, destination, result, 8);
            tcg_temp_free_i64(tcg_ctx, result);
        }

        tcg_temp_free_i64(tcg_ctx, reg_value);
        tcg_temp_free_i64(tcg_ctx, address_value);
    }
    return true;
}

static void gen_rex2_push_pop(DisasContext *s, int reg, bool push, int width)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const MemOp ot = width == 2 ? MO_16 : MO_64;
    const MemOp saved_dflag = s->dflag;

    /* gen_push_v/gen_pop_T0 derive their access width from dflag.  REX2.W is
     * decoded locally, so temporarily expose its effective operand size. */
    s->dflag = ot;
    gen_helper_apx_push_pop_check(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx, (push ? APX_PUSH_POP_PUSH : 0) |
                                   (width == 2 ? APX_PUSH_POP_16 : 0)));
    if (push) {
        TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

        if (reg < 16) {
            gen_op_mov_v_reg(s, ot, value, reg);
        } else {
            gen_rex2_load_gpr(s, value, reg, width);
        }
        gen_push_v(s, value);
        tcg_temp_free_i64(tcg_ctx, value);
    } else {
        MemOp pop_ot = gen_pop_T0(s);

        /* The implicit update precedes the explicit destination write.  This
         * ordering is architecturally visible for POP RSP/POP SP. */
        gen_pop_update(s, pop_ot);
        if (reg < 16) {
            gen_op_mov_reg_v(s, pop_ot, reg, s->T0);
        } else {
            gen_rex2_store_gpr(s, reg, s->T0, width);
        }
    }
    s->dflag = saved_dflag;
}

static void gen_rex2_mov(DisasContext *s, int dst, int src, int width)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

    gen_rex2_load_gpr(s, value, src, width);
    gen_rex2_store_gpr(s, dst, value, width);
    tcg_temp_free_i64(tcg_ctx, value);
}

static AddressParts decode_rex2_memory_address(CPUX86State *env,
                                               DisasContext *s, int modrm,
                                               int rex2)
{
    int mod = (modrm >> 6) & 3;
    int raw_rm = modrm & 7;
    int base = raw_rm | ((rex2 & 0x01) << 3) | (rex2 & 0x10);
    int index = -1;
    int scale = 0;
    int def_seg = R_DS;
    target_long disp = 0;
    bool have_sib = false;

    if (raw_rm == 4) {
        int sib = x86_ldub_code(env, s);
        int raw_index = (sib >> 3) & 7;

        have_sib = true;
        scale = (sib >> 6) & 3;
        if (raw_index != 4 || (rex2 & 0x22)) {
            index = raw_index | ((rex2 & 0x02) << 2) | ((rex2 & 0x20) >> 1);
        }
        base = (sib & 7) | ((rex2 & 0x01) << 3) | (rex2 & 0x10);
    }

    switch (mod) {
    case 0:
        if ((base & 7) == 5) {
            base = -1;
            disp = (int32_t)x86_ldl_code(env, s);
            if (CODE64(s) && !have_sib) {
                disp += s->pc + s->rip_offset;
            }
        }
        break;
    case 1:
        disp = (int8_t)x86_ldub_code(env, s);
        break;
    case 2:
        disp = (int32_t)x86_ldl_code(env, s);
        break;
    default:
        tcg_abort();
    }

    if (base == R_ESP || base == R_EBP) {
        def_seg = R_SS;
    }
    return (AddressParts){def_seg, base, index, scale, disp};
}

static AddressParts decode_rex2_memory_address_scaled(
    CPUX86State *env, DisasContext *s, int modrm, int rex2,
    int disp8_scale)
{
    AddressParts address =
        decode_rex2_memory_address(env, s, modrm, rex2);

    if ((modrm >> 6) == 1) {
        address.disp *= disp8_scale;
    }
    return address;
}

static void gen_rex2_memory_address(DisasContext *s, AddressParts address)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv value = tcg_temp_new(tcg_ctx);

    tcg_gen_movi_tl(tcg_ctx, s->A0, address.disp);
    if (address.base >= 0) {
        if (address.base < 16) {
            tcg_gen_mov_tl(tcg_ctx, value,
                           tcg_ctx->cpu_regs[address.base]);
        } else {
            tcg_gen_ld_tl(tcg_ctx, value, tcg_ctx->cpu_env,
                          apx_gpr_offset(address.base));
        }
        tcg_gen_add_tl(tcg_ctx, s->A0, s->A0, value);
    }
    if (address.index >= 0) {
        if (address.index < 16) {
            tcg_gen_mov_tl(tcg_ctx, value,
                           tcg_ctx->cpu_regs[address.index]);
        } else {
            tcg_gen_ld_tl(tcg_ctx, value, tcg_ctx->cpu_env,
                          apx_gpr_offset(address.index));
        }
        if (address.scale) {
            tcg_gen_shli_tl(tcg_ctx, value, value, address.scale);
        }
        tcg_gen_add_tl(tcg_ctx, s->A0, s->A0, value);
    }
    tcg_temp_free(tcg_ctx, value);
    gen_lea_v_seg(s, s->aflag, s->A0, address.def_seg, s->override);
}

typedef enum REX2BinaryOp {
    REX2_BIN_ADD,
    REX2_BIN_ADC,
    REX2_BIN_OR,
    REX2_BIN_AND,
    REX2_BIN_SUB,
    REX2_BIN_SBB,
    REX2_BIN_XOR,
    REX2_BIN_CMP,
    REX2_BIN_TEST,
} REX2BinaryOp;

static MemOp rex2_width_memop(int width)
{
    switch (width) {
    case 1:
        return MO_8;
    case 2:
        return MO_16;
    case 4:
        return MO_32;
    default:
        return MO_64;
    }
}

static void gen_rex2_load_memory(DisasContext *s, TCGv_i64 value, int width)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_qemu_ld_i64(tcg_ctx, value, s->A0, s->mem_index,
                        rex2_width_memop(width) | MO_LE);
}

static void gen_rex2_store_memory(DisasContext *s, TCGv_i64 value, int width)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_qemu_st_i64(tcg_ctx, value, s->A0, s->mem_index,
                        rex2_width_memop(width) | MO_LE);
}

static void gen_rex2_memory_range_check(DisasContext *s,
                                        bool stack_segment, int width)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_helper_apx_evex_memory_check(
        tcg_ctx, tcg_ctx->cpu_env, s->A0,
        tcg_const_i32(tcg_ctx, 0), tcg_const_i32(tcg_ctx, 1),
        tcg_const_i32(tcg_ctx, width),
        tcg_const_i32(tcg_ctx,
                      (stack_segment ? APX_MEMORY_SS : 0) |
                          APX_MEMORY_TUPLE));
}

static void gen_apx_bswap(DisasContext *s, TCGv_i64 value, int width)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    switch (width) {
    case 2:
        tcg_gen_bswap16_i64(tcg_ctx, value, value);
        break;
    case 4:
        tcg_gen_bswap32_i64(tcg_ctx, value, value);
        break;
    case 8:
        tcg_gen_bswap64_i64(tcg_ctx, value, value);
        break;
    default:
        g_assert_not_reached();
    }
}

static APXEVEXDecodeResult gen_apx_evex_atomic(
    CPUX86State *env, DisasContext *s, int rex_byte, int p0, int p1, int p2,
    int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int map = p0 & 7;
    const bool rao = map == 4 && opcode == 0xfc;
    const bool cmpccxadd = map == 2 && opcode >= 0xe0 && opcode <= 0xef;
    const bool qword = (p1 & 0x80) != 0;
    const int width = qword ? 8 : 4;
    int modrm, mod;

    if (!rao && !cmpccxadd) {
        return APX_EVEX_NOT_HANDLED;
    }
    if (!CODE64(s) || !apx_f_enabled(s) || rex_byte ||
        (s->prefix & (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ |
                      PREFIX_REPNZ))) {
        return APX_EVEX_INVALID;
    }
    if (rao) {
        if (!(s->cpuid_7_1_eax_features & CPUID_7_1_EAX_RAO_INT) ||
            (p1 & 0x78) != 0x78 || p2 != 0x08) {
            return APX_EVEX_INVALID;
        }
    } else if (!(s->cpuid_7_1_eax_features &
                 CPUID_7_1_EAX_CMPCCXADD) ||
               (p1 & 3) != 1 || (p2 & 0xf7) != 0) {
        return APX_EVEX_INVALID;
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    if (mod == 3) {
        return APX_EVEX_INVALID;
    }
    gen_evex_extended_memory_address(env, s, p0, p1, modrm, 1, width);

    if (rao) {
        const int source = apx_evex_reg_field(p0, modrm);
        const int operation = p1 & 3;
        const MemOp memop = rex2_width_memop(width) | MO_LE | MO_ALIGN;
        TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 old_value = tcg_temp_new_i64(tcg_ctx);

        gen_rex2_load_gpr(s, value, source, width);
        /* Unicorn's ordinary mapped RAM represents the WB memory type that
         * RAO-INT requires.  The TCG atomic enforces the architectural
         * natural-alignment #GP and indivisible read-modify-write. */
        switch (operation) {
        case 0:
            tcg_gen_atomic_fetch_add_i64(tcg_ctx, old_value, s->A0, value,
                                         s->mem_index, memop);
            break;
        case 1:
            tcg_gen_atomic_fetch_and_i64(tcg_ctx, old_value, s->A0, value,
                                         s->mem_index, memop);
            break;
        case 2:
            tcg_gen_atomic_fetch_xor_i64(tcg_ctx, old_value, s->A0, value,
                                         s->mem_index, memop);
            break;
        case 3:
            tcg_gen_atomic_fetch_or_i64(tcg_ctx, old_value, s->A0, value,
                                        s->mem_index, memop);
            break;
        default:
            g_assert_not_reached();
        }
        tcg_temp_free_i64(tcg_ctx, old_value);
        tcg_temp_free_i64(tcg_ctx, value);
        return APX_EVEX_DECODED;
    }

    gen_helper_apx_cmpccxadd(
        tcg_ctx, tcg_ctx->cpu_env, s->A0,
        tcg_const_i32(
            tcg_ctx,
            ((opcode - 0xe0) << APX_CMPCC_CONDITION_SHIFT) |
                (apx_evex_reg_field(p0, modrm)
                 << APX_CMPCC_COMPARE_SHIFT) |
                (apx_evex_v_field(p1, p2) << APX_CMPCC_ADD_SHIFT) |
                (qword ? APX_CMPCC_64 : 0) |
                ((tb_cflags(s->base.tb) & CF_PARALLEL)
                     ? APX_CMPCC_PARALLEL
                     : 0)));
    set_cc_op(s, CC_OP_EFLAGS);
    return APX_EVEX_DECODED;
}

static APXEVEXDecodeResult gen_apx_evex_direct_move(
    CPUX86State *env, DisasContext *s, int rex_byte, int p0, int p1, int p2,
    int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int mandatory = p1 & 3;
    const bool w = (p1 & 0x80) != 0;
    const bool movrs = opcode == 0x8a || opcode == 0x8b;
    int modrm, mod;
    int reg, rm;

    if ((p0 & 7) != 4) {
        return APX_EVEX_NOT_HANDLED;
    }
    if (opcode != 0x60 && opcode != 0x61 && opcode != 0xf8 &&
        opcode != 0xf9 && !movrs) {
        return APX_EVEX_NOT_HANDLED;
    }
    /* F8 with F2/F3 belongs to ENQCMD/ENQCMDS, not this decoder. */
    if (opcode == 0xf8 && mandatory != 1) {
        return APX_EVEX_NOT_HANDLED;
    }
    if (!apx_f_enabled(s) || rex_byte ||
        (s->prefix & (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ |
                      PREFIX_REPNZ)) ||
        (p1 & 0x78) != 0x78 || p2 != 0x08) {
        return APX_EVEX_INVALID;
    }

    if (movrs) {
        TCGv_i64 value;
        int width;

        if (!(s->cpuid_7_1_eax_features & CPUID_7_1_EAX_MOVRS) ||
            (opcode == 0x8a && (mandatory != 0 || w)) ||
            (opcode == 0x8b &&
             (mandatory > 1 || (mandatory == 1 && w)))) {
            return APX_EVEX_INVALID;
        }
        width = opcode == 0x8a ? 1 : mandatory == 1 ? 2 : w ? 8 : 4;
        modrm = x86_ldub_code(env, s);
        if ((modrm >> 6) == 3) {
            return APX_EVEX_INVALID;
        }
        reg = apx_evex_reg_field(p0, modrm);
        gen_evex_extended_memory_address(env, s, p0, p1, modrm, 1,
                                         width);
        value = tcg_temp_new_i64(tcg_ctx);
        gen_rex2_load_memory(s, value, width);
        /* MOVRS changes speculation behavior, not the architectural value or
         * fault model.  Unicorn has no speculative cache state, so an exact
         * architectural load is the observable implementation. */
        gen_rex2_store_gpr(s, reg, value, width);
        tcg_temp_free_i64(tcg_ctx, value);
        return APX_EVEX_DECODED;
    }

    if (!(p1 & 0x04)) {
        return APX_EVEX_INVALID;
    }

    if (opcode == 0x60 || opcode == 0x61) {
        int width;
        TCGv_i64 value;

        if (!(s->cpuid_ext_features & CPUID_EXT_MOVBE) ||
            (mandatory != 0 && mandatory != 1) ||
            (mandatory == 1 && w)) {
            return APX_EVEX_INVALID;
        }
        width = mandatory == 1 ? 2 : w ? 8 : 4;
        modrm = x86_ldub_code(env, s);
        mod = modrm >> 6;
        reg = apx_evex_reg_field(p0, modrm);
        rm = apx_evex_rm_field(p0, modrm);
        value = tcg_temp_new_i64(tcg_ctx);

        if (mod == 3) {
            const int source = opcode == 0x60 ? rm : reg;
            const int destination = opcode == 0x60 ? reg : rm;

            gen_rex2_load_gpr(s, value, source, width);
            gen_apx_bswap(s, value, width);
            gen_rex2_store_gpr(s, destination, value, width);
        } else {
            gen_evex_extended_memory_address(env, s, p0, p1, modrm, 1,
                                             width);
            if (opcode == 0x60) {
                gen_rex2_load_memory(s, value, width);
                gen_apx_bswap(s, value, width);
                gen_rex2_store_gpr(s, reg, value, width);
            } else {
                gen_rex2_load_gpr(s, value, reg, width);
                gen_apx_bswap(s, value, width);
                gen_rex2_store_memory(s, value, width);
            }
        }
        tcg_temp_free_i64(tcg_ctx, value);
        return APX_EVEX_DECODED;
    }

    if (opcode == 0xf9) {
        if (mandatory != 0 ||
            !(s->cpuid_7_0_ecx_features & CPUID_7_0_ECX_MOVDIRI)) {
            return APX_EVEX_INVALID;
        }
    } else if (w ||
               !(s->cpuid_7_0_ecx_features & CPUID_7_0_ECX_MOVDIR64B)) {
        return APX_EVEX_INVALID;
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    if (mod == 3) {
        return APX_EVEX_INVALID;
    }
    reg = apx_evex_reg_field(p0, modrm);
    gen_evex_extended_memory_address(env, s, p0, p1, modrm, 1,
                                     opcode == 0xf9 ? (w ? 8 : 4) : 64);

    if (opcode == 0xf9) {
        TCGv_i64 value;
        const int width = w ? 8 : 4;

        value = tcg_temp_new_i64(tcg_ctx);
        gen_rex2_load_gpr(s, value, reg, width);
        gen_rex2_store_memory(s, value, width);
        tcg_temp_free_i64(tcg_ctx, value);
        return APX_EVEX_DECODED;
    }

    gen_helper_apx_movdir64b(
        tcg_ctx, tcg_ctx->cpu_env, s->A0,
        tcg_const_i32(
            tcg_ctx,
            (reg << APX_MOVDIR64B_DST_SHIFT) |
                (s->aflag == MO_32 ? APX_MOVDIR64B_ADDRESS32 : 0)),
        tcg_const_tl(tcg_ctx, s->pc_start - s->cs_base));
    return APX_EVEX_DECODED;
}

static void gen_apx_conditional_flags(DisasContext *s, TCGv_i64 left,
                                      TCGv_i64 right, int width, int scc,
                                      int dfv, bool test)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const MemOp ot = rex2_width_memop(width);
    const target_ulong default_flags =
        ((dfv & 1) ? CC_C | CC_P : 0) |
        ((dfv & 2) ? CC_Z : 0) |
        ((dfv & 4) ? CC_S : 0) |
        ((dfv & 8) ? CC_O : 0);
    TCGv_i64 condition = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 result = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 true_flags = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 false_flags = tcg_const_i64(tcg_ctx, default_flags);
    TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);

    /* SCC consumes the incoming flags.  Codes 10 and 11 replace the parity
     * conditions with architectural always-true and always-false forms. */
    if (scc == 10) {
        tcg_gen_movi_i64(tcg_ctx, condition, 1);
    } else if (scc == 11) {
        tcg_gen_movi_i64(tcg_ctx, condition, 0);
    } else {
        gen_setcc1(s, scc, condition);
    }

    if (test) {
        tcg_gen_and_i64(tcg_ctx, result, left, right);
    } else {
        tcg_gen_sub_i64(tcg_ctx, result, left, right);
    }
    gen_helper_cc_compute_all(
        tcg_ctx, true_flags, result, test ? zero : right, zero,
        tcg_const_i32(tcg_ctx,
                      (test ? CC_OP_LOGICB : CC_OP_SUBB) + ot));
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_NE, tcg_ctx->cpu_cc_src,
                        condition, zero, true_flags, false_flags);
    set_cc_op(s, CC_OP_EFLAGS);

    tcg_temp_free_i64(tcg_ctx, condition);
    tcg_temp_free_i64(tcg_ctx, result);
    tcg_temp_free_i64(tcg_ctx, true_flags);
    tcg_temp_free_i64(tcg_ctx, false_flags);
    tcg_temp_free_i64(tcg_ctx, zero);
}

static APXEVEXDecodeResult gen_apx_evex_conditional(
    CPUX86State *env, DisasContext *s, int rex_byte, int p0, int p1, int p2,
    int opcode)
{
    const bool compare = opcode == 0x38 || opcode == 0x39 ||
                         opcode == 0x3a || opcode == 0x3b ||
                         opcode == 0x80 || opcode == 0x81 ||
                         opcode == 0x83;
    const bool test = opcode == 0x84 || opcode == 0x85 ||
                      opcode == 0xf6 || opcode == 0xf7;
    const bool immediate = opcode >= 0x80 && opcode != 0x84 &&
                           opcode != 0x85;
    const bool byte_form = opcode == 0x38 || opcode == 0x3a ||
                           opcode == 0x80 || opcode == 0x84 ||
                           opcode == 0xf6;
    int modrm, mod, group;
    int width;
    TCGv_i64 left;
    TCGv_i64 right;

    if (!compare && !test) {
        return APX_EVEX_NOT_HANDLED;
    }
    if (immediate) {
        const int candidate_group =
            (translator_ldub(env->uc->tcg_ctx, env, s->pc) >> 3) & 7;

        /* The remaining group extensions are ordinary APX F6/F7 and
         * 80/81/83 scalar operations, not malformed CCMP/CTEST forms. */
        if ((compare && candidate_group != 7) ||
            (test && candidate_group > 1)) {
            return APX_EVEX_NOT_HANDLED;
        }
    }
    if ((p0 & 7) != 4 || !apx_nci_enabled(s) || rex_byte ||
        (s->prefix & (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ |
                      PREFIX_REPNZ)) ||
        (p2 & 0xf0)) {
        return APX_EVEX_INVALID;
    }
    if (byte_form) {
        if (p1 & 0x83) {
            return APX_EVEX_INVALID;
        }
        width = 1;
    } else {
        const int mandatory = p1 & 3;

        if (mandatory > 1 || (mandatory == 1 && (p1 & 0x80))) {
            return APX_EVEX_INVALID;
        }
        width = mandatory == 1 ? 2 : (p1 & 0x80) ? 8 : 4;
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    group = (modrm >> 3) & 7;
    if (mod == 3 && !(p1 & 0x04)) {
        return APX_EVEX_INVALID;
    }
    g_assert(!immediate || (compare ? group == 7 : group <= 1));

    left = tcg_temp_new_i64(s->uc->tcg_ctx);
    right = tcg_temp_new_i64(s->uc->tcg_ctx);
    if (mod == 3) {
        gen_rex2_load_gpr(s, left, apx_evex_rm_field(p0, modrm), width);
    } else {
        int immediate_size = 0;

        if (immediate) {
            immediate_size = (opcode == 0x81 || opcode == 0xf7)
                                 ? (width == 2 ? 2 : 4)
                                 : 1;
        }
        s->rip_offset = immediate_size;
        gen_evex_extended_memory_address(env, s, p0, p1, modrm, 1,
                                         width);
        gen_rex2_load_memory(s, left, width);
    }

    if (immediate) {
        int64_t value;

        if (opcode == 0x81 || opcode == 0xf7) {
            if (width == 2) {
                value = (int16_t)x86_lduw_code(env, s);
            } else {
                value = (int32_t)x86_ldl_code(env, s);
            }
        } else {
            value = (int8_t)x86_ldub_code(env, s);
        }
        tcg_gen_movi_i64(s->uc->tcg_ctx, right, value);
    } else {
        gen_rex2_load_gpr(s, right, apx_evex_reg_field(p0, modrm), width);
    }

    if (compare && (opcode == 0x3a || opcode == 0x3b)) {
        TCGv_i64 swap = left;

        left = right;
        right = swap;
    }
    gen_apx_conditional_flags(s, left, right, width, p2 & 15,
                              (p1 >> 3) & 15, test);
    tcg_temp_free_i64(s->uc->tcg_ctx, left);
    tcg_temp_free_i64(s->uc->tcg_ctx, right);
    return APX_EVEX_DECODED;
}

static void gen_rex2_mov_memory(DisasContext *s, int reg, int width, bool load)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

    if (load) {
        gen_rex2_load_memory(s, value, width);
        gen_rex2_store_gpr(s, reg, value, width);
    } else {
        gen_rex2_load_gpr(s, value, reg, width);
        gen_rex2_store_memory(s, value, width);
    }
    tcg_temp_free_i64(tcg_ctx, value);
}

static void gen_rex2_binary(DisasContext *s, REX2BinaryOp op, int dst, int src,
                            int width)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 lhs = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 rhs = tcg_temp_new_i64(tcg_ctx);
    MemOp ot = rex2_width_memop(width);

    gen_rex2_load_gpr(s, lhs, dst, width);
    gen_rex2_load_gpr(s, rhs, src, width);

    switch (op) {
    case REX2_BIN_ADD:
        tcg_gen_add_i64(tcg_ctx, lhs, lhs, rhs);
        gen_rex2_store_gpr(s, dst, lhs, width);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, rhs);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, lhs);
        set_cc_op(s, CC_OP_ADDB + ot);
        break;
    case REX2_BIN_ADC:
    case REX2_BIN_SBB: {
        TCGv_i64 carry = tcg_temp_new_i64(tcg_ctx);

        gen_compute_eflags_c(s, carry);
        if (op == REX2_BIN_ADC) {
            tcg_gen_add_i64(tcg_ctx, lhs, lhs, rhs);
            tcg_gen_add_i64(tcg_ctx, lhs, lhs, carry);
        } else {
            tcg_gen_sub_i64(tcg_ctx, lhs, lhs, rhs);
            tcg_gen_sub_i64(tcg_ctx, lhs, lhs, carry);
        }
        gen_rex2_store_gpr(s, dst, lhs, width);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, carry);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, rhs);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, lhs);
        set_cc_op(s, (op == REX2_BIN_ADC ? CC_OP_ADCB : CC_OP_SBBB) + ot);
        tcg_temp_free_i64(tcg_ctx, carry);
        break;
    }
    case REX2_BIN_SUB:
    case REX2_BIN_CMP:
        tcg_gen_mov_tl(tcg_ctx, s->cc_srcT, lhs);
        tcg_gen_sub_i64(tcg_ctx, lhs, lhs, rhs);
        if (op == REX2_BIN_SUB) {
            gen_rex2_store_gpr(s, dst, lhs, width);
        }
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, rhs);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, lhs);
        set_cc_op(s, CC_OP_SUBB + ot);
        break;
    case REX2_BIN_OR:
        tcg_gen_or_i64(tcg_ctx, lhs, lhs, rhs);
        goto logical_result;
    case REX2_BIN_AND:
    case REX2_BIN_TEST:
        tcg_gen_and_i64(tcg_ctx, lhs, lhs, rhs);
        goto logical_result;
    case REX2_BIN_XOR:
        tcg_gen_xor_i64(tcg_ctx, lhs, lhs, rhs);
    logical_result:
        if (op != REX2_BIN_TEST) {
            gen_rex2_store_gpr(s, dst, lhs, width);
        }
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, lhs);
        set_cc_op(s, CC_OP_LOGICB + ot);
        break;
    }

    tcg_temp_free_i64(tcg_ctx, lhs);
    tcg_temp_free_i64(tcg_ctx, rhs);
}

static void gen_apx_evex_binary(DisasContext *s, REX2BinaryOp op, int dst,
                                int src1, int src2, int width, bool nf)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 lhs = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 rhs = tcg_temp_new_i64(tcg_ctx);
    MemOp ot = rex2_width_memop(width);

    /* Load both inputs before committing the destination so every legal
     * source/destination alias observes the architectural old values. */
    gen_rex2_load_gpr(s, lhs, src1, width);
    gen_rex2_load_gpr(s, rhs, src2, width);

    switch (op) {
    case REX2_BIN_ADD:
        tcg_gen_add_i64(tcg_ctx, lhs, lhs, rhs);
        gen_rex2_store_gpr(s, dst, lhs, width);
        if (!nf) {
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, rhs);
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, lhs);
            set_cc_op(s, CC_OP_ADDB + ot);
        }
        break;
    case REX2_BIN_ADC:
    case REX2_BIN_SBB: {
        TCGv_i64 carry = tcg_temp_new_i64(tcg_ctx);

        gen_compute_eflags_c(s, carry);
        if (op == REX2_BIN_ADC) {
            tcg_gen_add_i64(tcg_ctx, lhs, lhs, rhs);
            tcg_gen_add_i64(tcg_ctx, lhs, lhs, carry);
        } else {
            tcg_gen_sub_i64(tcg_ctx, lhs, lhs, rhs);
            tcg_gen_sub_i64(tcg_ctx, lhs, lhs, carry);
        }
        gen_rex2_store_gpr(s, dst, lhs, width);
        if (!nf) {
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, carry);
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, rhs);
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, lhs);
            set_cc_op(s, (op == REX2_BIN_ADC ? CC_OP_ADCB : CC_OP_SBBB) +
                             ot);
        }
        tcg_temp_free_i64(tcg_ctx, carry);
        break;
    }
    case REX2_BIN_SUB:
        if (!nf) {
            tcg_gen_mov_tl(tcg_ctx, s->cc_srcT, lhs);
        }
        tcg_gen_sub_i64(tcg_ctx, lhs, lhs, rhs);
        gen_rex2_store_gpr(s, dst, lhs, width);
        if (!nf) {
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, rhs);
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, lhs);
            set_cc_op(s, CC_OP_SUBB + ot);
        }
        break;
    case REX2_BIN_OR:
        tcg_gen_or_i64(tcg_ctx, lhs, lhs, rhs);
        goto logical_result;
    case REX2_BIN_AND:
        tcg_gen_and_i64(tcg_ctx, lhs, lhs, rhs);
        goto logical_result;
    case REX2_BIN_XOR:
        tcg_gen_xor_i64(tcg_ctx, lhs, lhs, rhs);
    logical_result:
        gen_rex2_store_gpr(s, dst, lhs, width);
        if (!nf) {
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, lhs);
            set_cc_op(s, CC_OP_LOGICB + ot);
        }
        break;
    default:
        g_assert_not_reached();
    }

    tcg_temp_free_i64(tcg_ctx, lhs);
    tcg_temp_free_i64(tcg_ctx, rhs);
}

static int apx_evex_reg_field(int p0, int modrm)
{
    int reg = (modrm >> 3) & 7;

    if (!(p0 & 0x80)) {
        reg |= 8;
    }
    if (!(p0 & 0x10)) {
        reg |= 16;
    }
    return reg;
}

static int apx_evex_rm_field(int p0, int modrm)
{
    int reg = modrm & 7;

    if (!(p0 & 0x20)) {
        reg |= 8;
    }
    if (p0 & 0x08) {
        reg |= 16;
    }
    return reg;
}

static int apx_evex_v_field(int p1, int p2)
{
    int reg = (~p1 >> 3) & 15;

    if (!(p2 & 0x08)) {
        reg |= 16;
    }
    return reg;
}

static bool apx_evex_width(int p1, bool byte_form, int *width)
{
    if (byte_form) {
        if ((p1 & 3) != 0) {
            return false;
        }
        *width = 1;
        return true;
    }
    if ((p1 & 3) > 1) {
        return false;
    }
    *width = (p1 & 0x80) ? 8 : (p1 & 1) ? 2 : 4;
    return true;
}

static APXEVEXDecodeResult gen_apx_evex_kmov(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int map = p0 & 7;
    const int mandatory = p1 & 3;
    const bool w = (p1 & 0x80) != 0;
    int width;
    uint64_t width_mask;
    int modrm, mod;
    int reg, rm;

    if (map != 1 || opcode < 0x90 || opcode > 0x93) {
        return APX_EVEX_NOT_HANDLED;
    }
    if ((p1 & 0x78) != 0x78 || p2 != 0x08) {
        return APX_EVEX_INVALID;
    }

    if (opcode <= 0x91) {
        if (!w && mandatory == 1) {
            width = 1;
        } else if (!w && mandatory == 0) {
            width = 2;
        } else if (w && mandatory == 1) {
            width = 4;
        } else if (w && mandatory == 0) {
            width = 8;
        } else {
            return APX_EVEX_INVALID;
        }
    } else {
        if (!w && mandatory == 1) {
            width = 1;
        } else if (!w && mandatory == 0) {
            width = 2;
        } else if (!w && mandatory == 3) {
            width = 4;
        } else if (w && mandatory == 3) {
            width = 8;
        } else {
            return APX_EVEX_INVALID;
        }
    }
    width_mask = width == 1   ? UINT8_MAX
                 : width == 2 ? UINT16_MAX
                 : width == 4 ? UINT32_MAX
                              : UINT64_MAX;
    if (!x86_opmask_width_feature_enabled(s, width_mask, false)) {
        return APX_EVEX_INVALID;
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    if ((mod == 3 && !(p1 & 0x04)) ||
        (opcode == 0x91 && mod == 3) ||
        (opcode >= 0x92 && mod != 3)) {
        return APX_EVEX_INVALID;
    }

    reg = apx_evex_reg_field(p0, modrm);
    if (opcode != 0x93 && reg >= NB_OPMASK_REGS) {
        return APX_EVEX_INVALID;
    }

    if (mod != 3) {
        const int rex2 = (!(p0 & 0x20) ? 0x01 : 0) |
                         (!(p0 & 0x40) ? 0x02 : 0) |
                         ((p0 & 0x08) ? 0x10 : 0) |
                         (!(p1 & 0x04) ? 0x20 : 0);
        AddressParts address =
            decode_rex2_memory_address(env, s, modrm, rex2);
        const bool stack_segment =
            s->override == R_SS ||
            (s->override < 0 && address.def_seg == R_SS);
        TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

        gen_rex2_memory_address(s, address);
        gen_rex2_memory_range_check(s, stack_segment, width);
        if (opcode == 0x90) {
            gen_rex2_load_memory(s, value, width);
            tcg_gen_st_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                           offsetof(CPUX86State, opmask_regs) +
                               reg * sizeof(uint64_t));
            gen_opmask_mark_inuse(s);
        } else {
            tcg_gen_ld_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                           offsetof(CPUX86State, opmask_regs) +
                               reg * sizeof(uint64_t));
            gen_rex2_store_memory(s, value, width);
        }
        tcg_temp_free_i64(tcg_ctx, value);
        return APX_EVEX_DECODED;
    }

    rm = apx_evex_rm_field(p0, modrm);
    if (opcode == 0x90) {
        if (rm >= NB_OPMASK_REGS) {
            return APX_EVEX_INVALID;
        }
        gen_opmask_kmov_k_to_k(s, reg, rm, width_mask);
    } else if (opcode == 0x92) {
        TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

        gen_rex2_load_gpr(s, value, rm, width == 8 ? 8 : 4);
        if (width_mask != UINT64_MAX) {
            tcg_gen_andi_i64(tcg_ctx, value, value, width_mask);
        }
        tcg_gen_st_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                       offsetof(CPUX86State, opmask_regs) +
                           reg * sizeof(uint64_t));
        gen_opmask_mark_inuse(s);
        tcg_temp_free_i64(tcg_ctx, value);
    } else {
        TCGv_i64 value;

        if (rm >= NB_OPMASK_REGS) {
            return APX_EVEX_INVALID;
        }
        value = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_ld_i64(tcg_ctx, value, tcg_ctx->cpu_env,
                       offsetof(CPUX86State, opmask_regs) +
                           rm * sizeof(uint64_t));
        if (width_mask != UINT64_MAX) {
            tcg_gen_andi_i64(tcg_ctx, value, value, width_mask);
        }
        gen_rex2_store_gpr(s, reg, value, width == 8 ? 8 : 4);
        tcg_temp_free_i64(tcg_ctx, value);
    }
    return APX_EVEX_DECODED;
}

static uint32_t evex_scalar_lane_desc(int dst, int src, int element_shift,
                                      unsigned int index,
                                      unsigned int zero_mask)
{
    return (dst << EVEX_SCALAR_LANE_DST_SHIFT) |
           (src << EVEX_SCALAR_LANE_SRC_SHIFT) |
           (element_shift << EVEX_SCALAR_LANE_ELEM_SHIFT) |
           ((index & EVEX_SCALAR_LANE_INDEX_MASK)
            << EVEX_SCALAR_LANE_INDEX_SHIFT) |
           ((zero_mask & EVEX_SCALAR_LANE_ZERO_MASK)
            << EVEX_SCALAR_LANE_ZERO_MASK_SHIFT);
}

static uint32_t evex_scalar_move_desc(int dst, int src1, int src2,
                                      int mask_reg, bool zero,
                                      bool qword)
{
    return (dst << EVEX_SCALAR_MOVE_DST_SHIFT) |
           (src1 << EVEX_SCALAR_MOVE_SRC1_SHIFT) |
           (src2 << EVEX_SCALAR_MOVE_SRC2_SHIFT) |
           (mask_reg << EVEX_SCALAR_MOVE_MASK_SHIFT) |
           (zero ? EVEX_SCALAR_MOVE_ZERO : 0) |
           (qword ? EVEX_SCALAR_MOVE_QWORD : 0);
}

static bool gen_evex_memory_address_details(
    CPUX86State *env, DisasContext *s, int p0, int p1, int modrm,
    int disp8_scale, bool *uses_egpr)
{
    const int rex2 = (!(p0 & 0x20) ? 0x01 : 0) |
                     (!(p0 & 0x40) ? 0x02 : 0) |
                     ((p0 & 0x08) ? 0x10 : 0) |
                     (!(p1 & 0x04) ? 0x20 : 0);
    AddressParts address = decode_rex2_memory_address_scaled(
        env, s, modrm, rex2, disp8_scale);
    const bool stack_segment =
        s->override == R_SS ||
        (s->override < 0 && address.def_seg == R_SS);

    if (uses_egpr) {
        *uses_egpr = address.base >= 16 || address.index >= 16;
    }
    gen_rex2_memory_address(s, address);
    return stack_segment;
}

static bool gen_evex_extended_memory_address_unchecked(
    CPUX86State *env, DisasContext *s, int p0, int p1, int modrm,
    int disp8_scale)
{
    return gen_evex_memory_address_details(env, s, p0, p1, modrm,
                                           disp8_scale, NULL);
}

static void gen_evex_extended_memory_address(CPUX86State *env,
                                             DisasContext *s, int p0,
                                             int p1, int modrm,
                                             int disp8_scale,
                                             int access_bytes)
{
    const bool stack_segment = gen_evex_extended_memory_address_unchecked(
        env, s, p0, p1, modrm, disp8_scale);

    gen_rex2_memory_range_check(s, stack_segment, access_bytes);
}

static void gen_evex_masked_memory_check(DisasContext *s,
                                         bool stack_segment, int mask_reg,
                                         int active_elements,
                                         int access_bytes,
                                         bool tuple_access)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_helper_apx_evex_memory_check(
        tcg_ctx, tcg_ctx->cpu_env, s->A0,
        tcg_const_i32(tcg_ctx, mask_reg),
        tcg_const_i32(tcg_ctx, active_elements),
        tcg_const_i32(tcg_ctx, access_bytes),
        tcg_const_i32(tcg_ctx,
                      (stack_segment ? APX_MEMORY_SS : 0) |
                          (tuple_access ? APX_MEMORY_TUPLE : 0)));
}

/* Existing EVEX instructions use the ordinary X/B extensions unless APX
 * promotes the address to X4/B4.  Keep the ordinary path unchanged.  For an
 * APX address, canonicality is checked only when the architectural writemask
 * selects at least one lane, preserving EVEX fault suppression. */
static bool gen_evex_memory_address(CPUX86State *env, DisasContext *s,
                                    int p0, int p1, int modrm,
                                    int disp8_scale, int mask_reg,
                                    int active_elements, int access_bytes,
                                    bool tuple_access)
{
    bool uses_egpr;
    const bool stack_segment = gen_evex_memory_address_details(
        env, s, p0, p1, modrm, disp8_scale, &uses_egpr);

    if (uses_egpr && (!CODE64(s) || !apx_f_enabled(s))) {
        gen_illegal_opcode(s);
        return false;
    }
    gen_evex_masked_memory_check(s, stack_segment, mask_reg,
                                 active_elements, access_bytes,
                                 tuple_access);
    return true;
}

static APXEVEXDecodeResult gen_apx_evex_msr(
    CPUX86State *env, DisasContext *s, int rex_byte, int p0, int p1, int p2,
    int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int map = p0 & 7;
    const int mandatory = p1 & 3;
    const bool read = mandatory == 3;  /* EVEX.F2 */
    const bool write = mandatory == 2; /* EVEX.F3 */
    const bool msr_imm = map == 7 && opcode == 0xf6 && (read || write);
    const bool user_msr = (map == 7 || map == 4) && opcode == 0xf8 &&
                          (read || write);
    const bool immediate = map == 7;
    uint32_t index = 0;
    int modrm;
    int operand;

    if (!msr_imm && !user_msr) {
        return APX_EVEX_NOT_HANDLED;
    }

    /* MAP4.F8 F2/F3 memory encodings are ENQCMD/ENQCMDS.  Only the
     * register form belongs to USER_MSR, so preserve that inherited path. */
    if (map == 4 &&
        (translator_ldub(tcg_ctx, env, s->pc) >> 6) != 3) {
        return APX_EVEX_NOT_HANDLED;
    }

    if (!CODE64(s) || rex_byte ||
        (s->prefix & (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ |
                      PREFIX_REPNZ)) ||
        (p1 & 0x7c) != 0x7c || p2 != 0x08 ||
        (user_msr && (p1 & 0x80))) {
        return APX_EVEX_INVALID;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3 ||
        (immediate && (modrm & 0x38) != 0)) {
        return APX_EVEX_INVALID;
    }
    if (immediate) {
        index = x86_ldl_code(env, s);
    }

    if (!apx_f_enabled(s) ||
        !(s->cpuid_features & CPUID_MSR)) {
        gen_illegal_opcode(s);
        return APX_EVEX_DECODED;
    }

    if (user_msr) {
        if (!(s->cpuid_7_1_edx_features & CPUID_7_1_EDX_USER_MSR)) {
            gen_illegal_opcode(s);
            return APX_EVEX_DECODED;
        }
        /* Unicorn has no architectural IA32_USER_MSR_CTL bitmap backing.
         * Model ENABLE as clear, which requires #UD, rather than allowing an
         * unauthenticated MSR access or fabricating a successful result. */
        gen_illegal_opcode(s);
        return APX_EVEX_DECODED;
    }

    if (!(s->cpuid_7_1_ecx_features & CPUID_7_1_ECX_MSR_IMM)) {
        gen_illegal_opcode(s);
        return APX_EVEX_DECODED;
    }
    if (s->cpl != 0) {
        gen_exception(s, EXCP0D_GPF, s->pc_start - s->cs_base);
        return APX_EVEX_DECODED;
    }

    operand = apx_evex_rm_field(p0, modrm);
    gen_update_cc_op(s);
    gen_jmp_im(s, s->pc_start - s->cs_base);
    if (read) {
        TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

        gen_helper_apx_rdmsr_imm(tcg_ctx, value, tcg_ctx->cpu_env,
                                 tcg_const_i32(tcg_ctx, index));
        gen_rex2_store_gpr(s, operand, value, 8);
        tcg_temp_free_i64(tcg_ctx, value);
    } else {
        TCGv_i64 value = tcg_temp_new_i64(tcg_ctx);

        gen_rex2_load_gpr(s, value, operand, 8);
        gen_helper_apx_wrmsr_imm(tcg_ctx, tcg_ctx->cpu_env,
                                 tcg_const_i32(tcg_ctx, index), value);
        tcg_temp_free_i64(tcg_ctx, value);
        /* MSRs can alter state consulted while translating later guest
         * instructions.  WRMSRNS is not architecturally serializing, but a
         * local TB boundary keeps that newly written state observable. */
        gen_jmp_im(s, s->pc - s->cs_base);
        gen_eob(s);
    }
    return APX_EVEX_DECODED;
}

static APXEVEXDecodeResult gen_apx_evex_system(
    CPUX86State *env, DisasContext *s, int rex_byte, int p0, int p1, int p2,
    int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int mandatory = p1 & 3;
    const bool invept = opcode == 0xf0 && mandatory == 2;
    const bool invvpid = opcode == 0xf1 && mandatory == 2;
    const bool invpcid = opcode == 0xf2 && mandatory == 2;
    const bool enqcmd = opcode == 0xf8 && mandatory == 3;
    const bool enqcmds = opcode == 0xf8 && mandatory == 2;
    const bool wrss = opcode == 0x66 && mandatory == 0;
    const bool wruss = opcode == 0x65 && mandatory == 1;
    int modrm;
    bool stack_segment;

    /* Opcode alone is not ownership: these values deliberately overlap
     * CRC32, ADCX/ADOX, and MOVDIR64B under other mandatory prefixes. */
    if (!invept && !invvpid && !invpcid && !enqcmd && !enqcmds &&
        !wrss && !wruss) {
        return APX_EVEX_NOT_HANDLED;
    }
    if (!apx_f_enabled(s) || rex_byte ||
        (s->prefix & (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ |
                      PREFIX_REPNZ)) ||
        (p1 & 0x78) != 0x78 || p2 != 0x08) {
        return APX_EVEX_INVALID;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) == 3) {
        return APX_EVEX_INVALID;
    }

    /* Decode the complete addressing form even when an inherited feature or
     * machine state makes the instruction #UD.  Address generation itself
     * has no architectural memory access or canonicality fault here. */
    stack_segment = gen_evex_extended_memory_address_unchecked(
        env, s, p0, p1, modrm, 1);

    if (invpcid) {
        TCGv_i64 type;

        if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_INVPCID)) {
            gen_illegal_opcode(s);
            return APX_EVEX_DECODED;
        }
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, s->pc_start - s->cs_base);
            return APX_EVEX_DECODED;
        }

        type = tcg_temp_new_i64(tcg_ctx);
        gen_rex2_load_gpr(s, type, apx_evex_reg_field(p0, modrm), 8);
        gen_update_cc_op(s);
        gen_jmp_im(s, s->pc_start - s->cs_base);
        gen_helper_apx_invpcid(
            tcg_ctx, tcg_ctx->cpu_env, s->A0, type,
            tcg_const_i32(tcg_ctx,
                          stack_segment ? APX_MEMORY_SS : 0));
        tcg_temp_free_i64(tcg_ctx, type);
        gen_jmp_im(s, s->pc - s->cs_base);
        gen_eob(s);
        return APX_EVEX_DECODED;
    }

    if (enqcmd || enqcmds) {
        const bool supervisor = enqcmds;
        const int destination_reg = apx_evex_reg_field(p0, modrm);
        const int destination_width = s->aflag == MO_32 ? 4 : 8;
        TCGv source;
        TCGv destination;

        if (!(s->cpuid_7_0_ecx_features & CPUID_7_0_ECX_ENQCMD)) {
            gen_illegal_opcode(s);
            return APX_EVEX_DECODED;
        }
        if (supervisor && s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, s->pc_start - s->cs_base);
            return APX_EVEX_DECODED;
        }

        source = tcg_temp_new(tcg_ctx);
        destination = tcg_temp_new(tcg_ctx);
        tcg_gen_mov_tl(tcg_ctx, source, s->A0);
        gen_rex2_load_gpr(s, destination, destination_reg,
                          destination_width);
        gen_lea_v_seg(s, s->aflag, destination, R_ES, -1);
        tcg_gen_mov_tl(tcg_ctx, destination, s->A0);
        gen_helper_apx_enqueue(
            tcg_ctx, tcg_ctx->cpu_env, source, destination,
            tcg_const_i32(
                tcg_ctx,
                (stack_segment ? APX_ENQUEUE_SOURCE_SS : 0) |
                    (supervisor ? APX_ENQUEUE_SUPERVISOR : 0)));
        tcg_temp_free(tcg_ctx, source);
        tcg_temp_free(tcg_ctx, destination);
        set_cc_op(s, CC_OP_EFLAGS);
        return APX_EVEX_DECODED;
    }

    /* The remaining promoted encodings depend on VMX operation or CET
     * shadow-stack page state.  No current CPU model advertises those
     * inherited features; fail as real hardware does instead of fabricating
     * a TLB operation or ordinary-RAM shadow-stack store. */
    gen_illegal_opcode(s);
    return APX_EVEX_DECODED;
}

static int evex_vector_rm_field(int p0, int modrm)
{
    int reg = modrm & 7;

    if (!(p0 & 0x20)) {
        reg |= 8;
    }
    if (!(p0 & 0x40)) {
        reg |= 16;
    }
    return reg;
}

static APXEVEXDecodeResult gen_evex_scalar_lane(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int map = p0 & 7;
    const int mandatory = p1 & 3;
    const bool w = (p1 & 0x80) != 0;
    bool extract = false;
    bool reversed_extract = false;
    bool insert_ps = false;
    int element_shift = -1;
    int modrm, mod;
    int dst, src, base;
    uint32_t immediate;
    TCGv_i64 value;

    if (map == 3) {
        switch (opcode) {
        case 0x14: /* VPEXTRB */
            extract = true;
            element_shift = 0;
            break;
        case 0x15: /* VPEXTRW (memory-capable encoding) */
            extract = true;
            element_shift = 1;
            break;
        case 0x16: /* VPEXTRD/VPEXTRQ */
            extract = true;
            element_shift = w ? 3 : 2;
            break;
        case 0x17: /* VEXTRACTPS */
            extract = true;
            element_shift = 2;
            break;
        case 0x20: /* VPINSRB */
            element_shift = 0;
            break;
        case 0x21: /* VINSERTPS */
            if (w) {
                return APX_EVEX_INVALID;
            }
            element_shift = 2;
            insert_ps = true;
            break;
        case 0x22: /* VPINSRD/VPINSRQ */
            element_shift = w ? 3 : 2;
            break;
        default:
            return APX_EVEX_NOT_HANDLED;
        }
    } else if (map == 1 && (opcode == 0xc4 || opcode == 0xc5)) {
        element_shift = 1;
        extract = opcode == 0xc5;
        reversed_extract = extract;
    } else {
        return APX_EVEX_NOT_HANDLED;
    }

    if (mandatory != 1 || (p2 & 0xf7) ||
        (extract && ((p1 & 0x78) != 0x78 || !(p2 & 0x08)))) {
        return APX_EVEX_INVALID;
    }
    if ((opcode == 0x16 || opcode == 0x22) && map == 3) {
        /* W selects the dword/qword form. */
    } else if (opcode != 0x21) {
        /* W is architecturally ignored for the remaining scalar lanes. */
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    if (reversed_extract && mod != 3) {
        return APX_EVEX_INVALID;
    }
    if (!x86_evex_require_features(
            s,
            element_shift < 2
                ? CPUID_7_0_EBX_AVX512BW
                : ((map == 3 &&
                    (opcode == 0x16 || opcode == 0x22))
                       ? CPUID_7_0_EBX_AVX512DQ
                       : 0),
            0, 0)) {
        return APX_EVEX_DECODED;
    }

    if (extract) {
        int gpr_width = element_shift == 3 ? 8 : 4;
        bool memory_destination = mod != 3;

        if (reversed_extract) {
            dst = apx_evex_reg_field(p0, modrm);
            src = evex_vector_rm_field(p0, modrm);
        } else {
            src = apx_evex_reg_field(p0, modrm);
            if (memory_destination) {
                s->rip_offset = 1;
                if (!gen_evex_memory_address(
                        env, s, p0, p1, modrm, 1 << element_shift, 0, 1,
                        1 << element_shift, false)) {
                    return APX_EVEX_DECODED;
                }
            } else {
                dst = apx_evex_rm_field(p0, modrm);
            }
        }
        if (!memory_destination && dst >= 16 && !apx_f_enabled(s)) {
            return APX_EVEX_INVALID;
        }

        immediate = x86_ldub_code(env, s);
        value = tcg_temp_new_i64(tcg_ctx);
        gen_helper_evex_extract_scalar_lane(
            tcg_ctx, value, tcg_ctx->cpu_env,
            tcg_const_i32(tcg_ctx,
                          evex_scalar_lane_desc(0, src, element_shift,
                                                immediate, 0)));
        if (memory_destination) {
            gen_rex2_store_memory(s, value, 1 << element_shift);
        } else {
            gen_rex2_store_gpr(s, dst, value, gpr_width);
        }
        tcg_temp_free_i64(tcg_ctx, value);
        return APX_EVEX_DECODED;
    }

    dst = apx_evex_reg_field(p0, modrm);
    base = apx_evex_v_field(p1, p2);
    value = tcg_temp_new_i64(tcg_ctx);
    if (mod != 3) {
        s->rip_offset = 1;
        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm, 1 << element_shift, 0, 1,
                1 << element_shift, false)) {
            tcg_temp_free_i64(tcg_ctx, value);
            return APX_EVEX_DECODED;
        }
        immediate = x86_ldub_code(env, s);
        gen_rex2_load_memory(s, value, 1 << element_shift);
    } else {
        immediate = x86_ldub_code(env, s);
        if (insert_ps) {
            const int vector_source = evex_vector_rm_field(p0, modrm);

            gen_helper_evex_extract_scalar_lane(
                tcg_ctx, value, tcg_ctx->cpu_env,
                tcg_const_i32(
                    tcg_ctx,
                    evex_scalar_lane_desc(0, vector_source, 2,
                                          immediate >> 6, 0)));
        } else {
            src = apx_evex_rm_field(p0, modrm);
            if (src >= 16 && !apx_f_enabled(s)) {
                tcg_temp_free_i64(tcg_ctx, value);
                return APX_EVEX_INVALID;
            }
            gen_rex2_load_gpr(s, value, src,
                              element_shift == 3 ? 8 : 4);
        }
    }

    gen_helper_evex_insert_scalar_lane(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(
            tcg_ctx,
            evex_scalar_lane_desc(dst, base, element_shift,
                                  insert_ps ? immediate >> 4 : immediate,
                                  insert_ps ? immediate & 15 : 0)),
        value);
    tcg_temp_free_i64(tcg_ctx, value);
    return APX_EVEX_DECODED;
}

static uint32_t evex_broadcast_lane_desc(int dst, int src,
                                         int vector_length, int mask_reg,
                                         bool zero, int element_shift,
                                         int tuple_shift)
{
    return (dst << EVEX_BCAST_DST_SHIFT) |
           (src << EVEX_BCAST_SRC_SHIFT) |
           (vector_length << EVEX_BCAST_VL_SHIFT) |
           (mask_reg << EVEX_BCAST_MASK_SHIFT) |
           (zero ? EVEX_BCAST_ZERO : 0) |
           (element_shift << EVEX_BCAST_ELEM_SHIFT) |
           (tuple_shift << EVEX_BCAST_TUPLE_SHIFT);
}

static APXEVEXDecodeResult gen_evex_broadcast_lane(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int map = p0 & 7;
    const int mandatory = p1 & 3;
    const bool w = (p1 & 0x80) != 0;
    int element_shift;
    int tuple_shift;
    int minimum_vector_length = 0;
    bool register_allowed = true;
    int vector_length;
    int mask_reg;
    bool zero;
    int modrm, mod;
    int dst, src = 0;
    uint32_t desc;

    if (map != 2 ||
        !((opcode >= 0x18 && opcode <= 0x1b) ||
          (opcode >= 0x58 && opcode <= 0x5b) || opcode == 0x78 ||
          opcode == 0x79)) {
        return APX_EVEX_NOT_HANDLED;
    }
    if (mandatory != 1 || (p1 & 0x78) != 0x78 || !(p2 & 0x08) ||
        (p2 & 0x10)) {
        return APX_EVEX_INVALID;
    }

    switch (opcode) {
    case 0x18: /* VBROADCASTSS */
        if (w) {
            return APX_EVEX_INVALID;
        }
        element_shift = 2;
        tuple_shift = 2;
        break;
    case 0x19:
        element_shift = w ? 3 : 2;
        tuple_shift = 3;
        minimum_vector_length = 1;
        break;
    case 0x1a: /* VBROADCASTF32X4/VBROADCASTF64X2 */
        element_shift = w ? 3 : 2;
        tuple_shift = 4;
        minimum_vector_length = 1;
        register_allowed = false;
        break;
    case 0x1b: /* VBROADCASTF32X8/VBROADCASTF64X4 */
        element_shift = w ? 3 : 2;
        tuple_shift = 5;
        minimum_vector_length = 2;
        register_allowed = false;
        break;
    case 0x58: /* VPBROADCASTD */
        if (w) {
            return APX_EVEX_INVALID;
        }
        element_shift = 2;
        tuple_shift = 2;
        break;
    case 0x59:
        element_shift = w ? 3 : 2;
        tuple_shift = 3;
        break;
    case 0x5a: /* VBROADCASTI32X4/VBROADCASTI64X2 */
        element_shift = w ? 3 : 2;
        tuple_shift = 4;
        minimum_vector_length = 1;
        register_allowed = false;
        break;
    case 0x5b: /* VBROADCASTI32X8/VBROADCASTI64X4 */
        element_shift = w ? 3 : 2;
        tuple_shift = 5;
        minimum_vector_length = 2;
        register_allowed = false;
        break;
    case 0x78: /* VPBROADCASTB */
        if (w) {
            return APX_EVEX_INVALID;
        }
        element_shift = 0;
        tuple_shift = 0;
        break;
    default: /* VPBROADCASTW */
        if (w) {
            return APX_EVEX_INVALID;
        }
        element_shift = 1;
        tuple_shift = 1;
        break;
    }

    vector_length = (p2 >> 5) & 3;
    mask_reg = p2 & 7;
    zero = (p2 & 0x80) != 0;
    if (vector_length == 3 || vector_length < minimum_vector_length ||
        (zero && !mask_reg)) {
        return APX_EVEX_INVALID;
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    if (mod == 3 && !register_allowed) {
        return APX_EVEX_INVALID;
    }
    {
        uint32_t required_ebx =
            vector_length != 2 ? CPUID_7_0_EBX_AVX512VL : 0;

        if (opcode == 0x78 || opcode == 0x79) {
            required_ebx |= CPUID_7_0_EBX_AVX512BW;
        } else if ((opcode == 0x19 && !w) ||
                   (opcode == 0x59 && !w) ||
                   ((opcode == 0x1a || opcode == 0x5a) && w) ||
                   ((opcode == 0x1b || opcode == 0x5b) && !w)) {
            required_ebx |= CPUID_7_0_EBX_AVX512DQ;
        }
        if (!x86_evex_require_features(s, required_ebx, 0, 0)) {
            return APX_EVEX_DECODED;
        }
    }

    dst = apx_evex_reg_field(p0, modrm);
    if (mod == 3) {
        src = evex_vector_rm_field(p0, modrm);
    }
    desc = evex_broadcast_lane_desc(dst, src, vector_length, mask_reg, zero,
                                    element_shift, tuple_shift);
    if (mod == 3) {
        gen_helper_evex_broadcast_lane_reg(
            tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, desc));
    } else {
        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm, 1 << tuple_shift, mask_reg,
                (16 << vector_length) >> element_shift,
                (1 << element_shift) |
                    (((1 << tuple_shift) >> element_shift)
                     << APX_MEMORY_MODULO_ELEMENTS_SHIFT),
                false)) {
            return APX_EVEX_DECODED;
        }
        gen_helper_evex_broadcast_lane_load(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc));
    }
    return APX_EVEX_DECODED;
}

static APXEVEXDecodeResult gen_evex_gpr_vector_move(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool to_vector = opcode == 0x6e;
    const bool from_vector = opcode == 0x7e;
    const int width = (p1 & 0x80) ? 8 : 4;
    const int element_shift = width == 8 ? 3 : 2;
    int modrm, mod;
    int vector_reg;
    int gpr = -1;
    TCGv_i64 value;

    if ((p0 & 7) != 1 || (!to_vector && !from_vector)) {
        return APX_EVEX_NOT_HANDLED;
    }
    if ((p1 & 3) != 1 || (p1 & 0x78) != 0x78 || p2 != 0x08) {
        return APX_EVEX_INVALID;
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    vector_reg = apx_evex_reg_field(p0, modrm);
    value = tcg_temp_new_i64(tcg_ctx);
    if (mod == 3) {
        gpr = apx_evex_rm_field(p0, modrm);
        if (gpr >= 16 && !apx_f_enabled(s)) {
            tcg_temp_free_i64(tcg_ctx, value);
            return APX_EVEX_INVALID;
        }
        if (to_vector) {
            gen_rex2_load_gpr(s, value, gpr, width);
        } else {
            gen_helper_evex_extract_scalar_lane(
                tcg_ctx, value, tcg_ctx->cpu_env,
                tcg_const_i32(
                    tcg_ctx,
                    evex_scalar_lane_desc(0, vector_reg, element_shift, 0,
                                          0)));
            gen_rex2_store_gpr(s, gpr, value, width);
        }
    } else {
        if (!gen_evex_memory_address(env, s, p0, p1, modrm, width, 0,
                                     1, width, false)) {
            tcg_temp_free_i64(tcg_ctx, value);
            return APX_EVEX_DECODED;
        }
        if (to_vector) {
            gen_rex2_load_memory(s, value, width);
        } else {
            gen_helper_evex_extract_scalar_lane(
                tcg_ctx, value, tcg_ctx->cpu_env,
                tcg_const_i32(
                    tcg_ctx,
                    evex_scalar_lane_desc(0, vector_reg, element_shift, 0,
                                          0)));
            gen_rex2_store_memory(s, value, width);
        }
    }

    if (to_vector) {
        gen_helper_evex_set_vector_scalar(
            tcg_ctx, tcg_ctx->cpu_env,
            tcg_const_i32(
                tcg_ctx,
                evex_scalar_lane_desc(vector_reg, 0, element_shift, 0, 0)),
            value);
    }
    tcg_temp_free_i64(tcg_ctx, value);
    return APX_EVEX_DECODED;
}

static APXEVEXDecodeResult gen_evex_half_move(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int mandatory = p1 & 3;
    const bool w = (p1 & 0x80) != 0;
    const bool store = opcode == 0x13 || opcode == 0x17;
    int modrm, mod;
    int dst, base, src;
    int source_index, destination_index;
    TCGv_i64 value;

    if ((p0 & 7) != 1 ||
        (opcode != 0x12 && opcode != 0x13 &&
         opcode != 0x16 && opcode != 0x17) ||
        (mandatory != 0 && mandatory != 1)) {
        return APX_EVEX_NOT_HANDLED;
    }
    if ((mandatory == 0 && w) || (mandatory == 1 && !w) ||
        (p2 & 0xf7)) {
        return APX_EVEX_INVALID;
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    if (store) {
        if (mod == 3 || (p1 & 0x78) != 0x78 || !(p2 & 0x08)) {
            return APX_EVEX_INVALID;
        }
        src = apx_evex_reg_field(p0, modrm);
        value = tcg_temp_new_i64(tcg_ctx);
        gen_helper_evex_extract_scalar_lane(
            tcg_ctx, value, tcg_ctx->cpu_env,
            tcg_const_i32(
                tcg_ctx,
                evex_scalar_lane_desc(0, src, 3,
                                      opcode == 0x17 ? 1 : 0, 0)));
        if (!gen_evex_memory_address(env, s, p0, p1, modrm, 8, 0, 1, 8,
                                     false)) {
            tcg_temp_free_i64(tcg_ctx, value);
            return APX_EVEX_DECODED;
        }
        gen_rex2_store_memory(s, value, 8);
        tcg_temp_free_i64(tcg_ctx, value);
        return APX_EVEX_DECODED;
    }

    dst = apx_evex_reg_field(p0, modrm);
    base = apx_evex_v_field(p1, p2);
    value = tcg_temp_new_i64(tcg_ctx);
    if (mod == 3) {
        /* Only the no-prefix W0 forms have register sources: opcode 12 is
         * VMOVHLPS and opcode 16 is VMOVLHPS. */
        if (mandatory != 0 || w) {
            tcg_temp_free_i64(tcg_ctx, value);
            return APX_EVEX_INVALID;
        }
        src = evex_vector_rm_field(p0, modrm);
        source_index = opcode == 0x12 ? 1 : 0;
    } else {
        if (!gen_evex_memory_address(env, s, p0, p1, modrm, 8, 0, 1, 8,
                                     false)) {
            tcg_temp_free_i64(tcg_ctx, value);
            return APX_EVEX_DECODED;
        }
        gen_rex2_load_memory(s, value, 8);
        source_index = -1;
    }
    destination_index = opcode == 0x12 ? 0 : 1;
    if (source_index >= 0) {
        gen_helper_evex_extract_scalar_lane(
            tcg_ctx, value, tcg_ctx->cpu_env,
            tcg_const_i32(
                tcg_ctx,
                evex_scalar_lane_desc(0, src, 3, source_index, 0)));
    }
    gen_helper_evex_insert_scalar_lane(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(
            tcg_ctx,
            evex_scalar_lane_desc(dst, base, 3, destination_index, 0)),
        value);
    tcg_temp_free_i64(tcg_ctx, value);
    return APX_EVEX_DECODED;
}

static APXEVEXDecodeResult gen_evex_scalar_move(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int mandatory = p1 & 3;
    const bool qword = mandatory == 3;
    const bool w = (p1 & 0x80) != 0;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    int modrm, mod;
    int reg, src1, src2;
    uint32_t desc;

    if ((p0 & 7) != 1 || (opcode != 0x10 && opcode != 0x11) ||
        (mandatory != 2 && mandatory != 3)) {
        return APX_EVEX_NOT_HANDLED;
    }
    if ((qword != w) || (p2 & 0x10) || (zero && !mask_reg)) {
        return APX_EVEX_INVALID;
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    reg = apx_evex_reg_field(p0, modrm);
    if (mod == 3) {
        src1 = apx_evex_v_field(p1, p2);
        src2 = evex_vector_rm_field(p0, modrm);
        desc = evex_scalar_move_desc(reg, src1, src2, mask_reg, zero,
                                     qword);
        gen_helper_evex_scalar_move_reg(
            tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, desc));
        return APX_EVEX_DECODED;
    }

    if ((p1 & 0x78) != 0x78 || !(p2 & 0x08) ||
        (opcode == 0x11 && zero)) {
        return APX_EVEX_INVALID;
    }
    desc = evex_scalar_move_desc(reg, 0, 0, mask_reg, zero, qword);
    if (!gen_evex_memory_address(env, s, p0, p1, modrm,
                                 qword ? 8 : 4, mask_reg, 1,
                                 qword ? 8 : 4, false)) {
        return APX_EVEX_DECODED;
    }
    if (opcode == 0x10) {
        gen_helper_evex_scalar_move_load(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc));
    } else {
        gen_helper_evex_scalar_move_store(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc));
    }
    return APX_EVEX_DECODED;
}

static APXEVEXDecodeResult gen_evex_non_temporal_move(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int map = p0 & 7;
    const int mandatory = p1 & 3;
    const bool w = (p1 & 0x80) != 0;
    bool load;
    int vector_length;
    int vector_bytes;
    int modrm;
    int reg;
    uint32_t desc;

    if (map == 2 && opcode == 0x2a && mandatory == 1) {
        if (w) {
            return APX_EVEX_INVALID;
        }
        load = true;
    } else if (map == 1 && opcode == 0xe7 && mandatory == 1) {
        if (w) {
            return APX_EVEX_INVALID;
        }
        load = false;
    } else if (map == 1 && opcode == 0x2b && mandatory <= 1) {
        if ((mandatory == 0) != !w) {
            return APX_EVEX_INVALID;
        }
        load = false;
    } else {
        return APX_EVEX_NOT_HANDLED;
    }

    vector_length = (p2 >> 5) & 3;
    if ((p1 & 0x78) != 0x78 || (p2 & 0x9f) != 0x08 ||
        vector_length == 3) {
        return APX_EVEX_INVALID;
    }
    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) == 3) {
        return APX_EVEX_INVALID;
    }
    if (vector_length != 2 &&
        !x86_evex_require_features(s, CPUID_7_0_EBX_AVX512VL, 0, 0)) {
        return APX_EVEX_DECODED;
    }

    reg = apx_evex_reg_field(p0, modrm);
    vector_bytes = 16 << vector_length;
    if (!gen_evex_memory_address(env, s, p0, p1, modrm, vector_bytes, 0,
                                 1, vector_bytes, true)) {
        return APX_EVEX_DECODED;
    }
    desc = evex_vmovdqu_desc(reg, 0, 3, vector_length, 0, false) |
           EVEX_VMOV_ALIGNED;
    if (load) {
        gen_helper_evex_vmovdqu_load(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc));
    } else {
        gen_helper_evex_vmovdqu_store(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc),
            tcg_const_tl(tcg_ctx, s->pc_start - s->cs_base));
    }
    return APX_EVEX_DECODED;
}

static bool gen_evex_crypto(CPUX86State *env, DisasContext *s,
                            int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int map = p0 & 7;
    const int mandatory = p1 & 3;
    const bool w = (p1 & 0x80) != 0;
    const bool evex_b = (p2 & 0x10) != 0;
    int vector_length;
    int vector_bytes;
    int mask_reg;
    bool zero;
    bool masking = false;
    bool immediate_form = false;
    EVEXCryptoOp operation;
    uint32_t required_feature;
    int modrm, mod;
    int dst, src1, src2 = 0;
    uint32_t immediate = 0;
    uint32_t desc;

    if (mandatory != 1) {
        return false;
    }
    if (map == 2 && opcode >= 0xdc && opcode <= 0xdf) {
        operation = opcode == 0xdc   ? EVEX_CRYPTO_AES_ENC
                    : opcode == 0xdd ? EVEX_CRYPTO_AES_ENC_LAST
                    : opcode == 0xde ? EVEX_CRYPTO_AES_DEC
                                     : EVEX_CRYPTO_AES_DEC_LAST;
    } else if (map == 2 && opcode == 0xcf && !w) {
        operation = EVEX_CRYPTO_GF_MUL;
        masking = true;
    } else if (map == 3 && (opcode == 0xce || opcode == 0xcf) && w) {
        operation = opcode == 0xce ? EVEX_CRYPTO_GF_AFFINE
                                   : EVEX_CRYPTO_GF_AFFINE_INV;
        masking = true;
        immediate_form = true;
    } else if (map == 3 && opcode == 0x44) {
        operation = EVEX_CRYPTO_PCLMUL;
        immediate_form = true;
    } else {
        return false;
    }

    if (operation == EVEX_CRYPTO_AES_ENC ||
        operation == EVEX_CRYPTO_AES_ENC_LAST ||
        operation == EVEX_CRYPTO_AES_DEC ||
        operation == EVEX_CRYPTO_AES_DEC_LAST) {
        required_feature = CPUID_7_0_ECX_VAES;
    } else if (operation == EVEX_CRYPTO_PCLMUL) {
        required_feature = CPUID_7_0_ECX_VPCLMULQDQ;
    } else {
        required_feature = CPUID_7_0_ECX_GFNI;
    }
    if (!(s->cpuid_7_0_ecx_features & required_feature)) {
        gen_illegal_opcode(s);
        return true;
    }

    vector_length = (p2 >> 5) & 3;
    mask_reg = p2 & 7;
    zero = (p2 & 0x80) != 0;
    if (vector_length == 3 || (zero && !mask_reg) ||
        (!masking && (mask_reg || zero)) ||
        (evex_b && operation != EVEX_CRYPTO_GF_AFFINE &&
         operation != EVEX_CRYPTO_GF_AFFINE_INV)) {
        return false;
    }
    if (vector_length != 2 &&
        !(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_AVX512VL)) {
        gen_illegal_opcode(s);
        return true;
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    if (mod == 3 && evex_b) {
        return false;
    }

    dst = apx_evex_reg_field(p0, modrm);
    src1 = apx_evex_v_field(p1, p2);
    vector_bytes = 16 << vector_length;
    if (mod == 3) {
        src2 = evex_vector_rm_field(p0, modrm);
        if (immediate_form) {
            immediate = x86_ldub_code(env, s);
        }
    } else {
        if (immediate_form) {
            s->rip_offset = 1;
        }
        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm, evex_b ? 8 : vector_bytes,
                operation == EVEX_CRYPTO_GF_MUL ? mask_reg : 0,
                vector_bytes,
                operation == EVEX_CRYPTO_GF_MUL
                    ? 1
                    : (evex_b ? 8 : vector_bytes),
                operation != EVEX_CRYPTO_GF_MUL)) {
            return true;
        }
        if (immediate_form) {
            immediate = x86_ldub_code(env, s);
        }
    }

    desc = evex_crypto_desc(dst, src1, src2, vector_length, mask_reg, zero,
                            evex_b, operation);
    if (mod == 3) {
        gen_helper_evex_crypto_reg(
            tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, desc),
            tcg_const_i32(tcg_ctx, immediate));
    } else {
        gen_helper_evex_crypto_load(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc),
            tcg_const_i32(tcg_ctx, immediate));
    }
    return true;
}

static bool gen_evex_dbpsadbw(CPUX86State *env, DisasContext *s,
                              int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int vector_length = (p2 >> 5) & 3;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    int modrm, mod;
    int dst, src1, src2 = 0;
    uint32_t immediate;
    uint32_t desc;

    if ((p0 & 7) != 3 || (p1 & 3) != 1 || (p1 & 0x80) ||
        opcode != 0x42) {
        return false;
    }
    /* EVEX.b is reserved, L'L=11 is reserved, and {z} requires a mask. */
    if ((p2 & 0x10) || vector_length == 3 || (zero && !mask_reg)) {
        return false;
    }
    if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_AVX512BW) ||
        (vector_length != 2 &&
         !(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_AVX512VL))) {
        gen_illegal_opcode(s);
        return true;
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;

    dst = apx_evex_reg_field(p0, modrm);
    src1 = apx_evex_v_field(p1, p2);
    if (mod == 3) {
        src2 = evex_vector_rm_field(p0, modrm);
        immediate = x86_ldub_code(env, s);
    } else {
        /* Account for the trailing imm8 in RIP-relative addressing. */
        s->rip_offset = 1;
        if (!gen_evex_memory_address(env, s, p0, p1, modrm,
                                     16 << vector_length, 0, 1,
                                     16 << vector_length, true)) {
            return true;
        }
        immediate = x86_ldub_code(env, s);
    }

    desc = evex_lane_int_desc(dst, src1, src2, vector_length, mask_reg,
                              zero, EVEX_LANE_SADBW);
    if (mod == 3) {
        gen_helper_evex_dbpsadbw_reg(
            tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, desc),
            tcg_const_i32(tcg_ctx, immediate));
    } else {
        gen_helper_evex_dbpsadbw_load(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc),
            tcg_const_i32(tcg_ctx, immediate));
    }
    return true;
}

static bool gen_evex_four_memory_ops(CPUX86State *env, DisasContext *s,
                                     int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int vector_length = (p2 >> 5) & 3;
    const int mask_reg = p2 & 7;
    const bool zero = (p2 & 0x80) != 0;
    bool four_fma = false;
    bool scalar = false;
    bool negative = false;
    bool saturating = false;
    uint32_t required_feature;
    int modrm;
    int dst, source;
    uint32_t desc;

    if ((p0 & 7) != 2 || (p1 & 3) != 3 || (p1 & 0x80)) {
        return false;
    }
    switch (opcode) {
    case 0x9a:
    case 0xaa:
        four_fma = true;
        negative = opcode == 0xaa;
        if (vector_length != 2) {
            return false;
        }
        break;
    case 0x9b:
    case 0xab:
        four_fma = true;
        scalar = true;
        negative = opcode == 0xab;
        break;
    case 0x52:
    case 0x53:
        saturating = opcode == 0x53;
        if (vector_length != 2) {
            return false;
        }
        break;
    default:
        return false;
    }
    required_feature = four_fma ? CPUID_7_0_EDX_AVX512_4FMAPS
                                : CPUID_7_0_EDX_AVX512_4VNNIW;
    if (!(s->cpuid_7_0_edx_features & required_feature)) {
        gen_illegal_opcode(s);
        return true;
    }
    if ((p2 & 0x10) || (zero && !mask_reg)) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) == 3) {
        return false;
    }
    dst = apx_evex_reg_field(p0, modrm);
    source = apx_evex_v_field(p1, p2);
    if (!gen_evex_memory_address(env, s, p0, p1, modrm, 16, mask_reg,
                                 scalar ? 1 : 16, 16, true)) {
        return true;
    }
    desc = evex_four_desc(dst, source, mask_reg, zero, scalar, negative,
                          saturating);
    if (four_fma) {
        gen_helper_evex_four_fma_load(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc));
    } else {
        gen_helper_evex_four_vnni_load(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc));
    }
    return true;
}

static bool gen_evex_fpclass(CPUX86State *env, DisasContext *s,
                             int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool scalar = opcode == 0x67;
    const bool is_double = (p1 & 0x80) != 0;
    const bool broadcast = (p2 & 0x10) != 0;
    const int mask_reg = p2 & 7;
    int vector_length = (p2 >> 5) & 3;
    int modrm, mod;
    int dst, src = 0;
    uint32_t immediate;
    uint32_t desc;

    if ((p0 & 7) != 3 || (p1 & 3) != 1 ||
        (opcode != 0x66 && opcode != 0x67) ||
        (p1 & 0x78) != 0x78 || !(p2 & 0x08) || (p2 & 0x80)) {
        return false;
    }
    if (scalar) {
        vector_length = 0;
        if (broadcast) {
            return false;
        }
    } else if (vector_length == 3) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    /* A mask-register destination has no EVEX R/R' extension. */
    if ((p0 & 0x90) != 0x90 ||
        (mod == 3 && broadcast)) {
        return false;
    }
    if (!x86_evex_require_features(
            s,
            CPUID_7_0_EBX_AVX512DQ |
                (!scalar && vector_length != 2
                     ? CPUID_7_0_EBX_AVX512VL
                     : 0),
            0, 0)) {
        return true;
    }
    dst = (modrm >> 3) & 7;
    if (mod == 3) {
        src = evex_vector_rm_field(p0, modrm);
        immediate = x86_ldub_code(env, s);
    } else {
        const int element_bytes = is_double ? 8 : 4;

        s->rip_offset = 1;
        if (!gen_evex_memory_address(
                env, s, p0, p1, modrm,
                scalar || broadcast ? element_bytes : 16 << vector_length,
                mask_reg,
                scalar ? 1 : (16 << vector_length) / element_bytes,
                element_bytes, broadcast)) {
            return true;
        }
        immediate = x86_ldub_code(env, s);
    }
    desc = evex_fpclass_desc(dst, src, vector_length, mask_reg,
                             is_double, scalar, broadcast);
    if (mod == 3) {
        gen_helper_evex_fpclass_reg(
            tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, desc),
            tcg_const_i32(tcg_ctx, immediate));
    } else {
        gen_helper_evex_fpclass_load(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc),
            tcg_const_i32(tcg_ctx, immediate));
    }
    return true;
}

static bool gen_evex_comi(CPUX86State *env, DisasContext *s,
                          int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool is_double = (p1 & 0x80) != 0;
    const bool quiet = opcode == 0x2e;
    const bool sae = (p2 & 0x10) != 0;
    int modrm, mod;
    int left, right = 0;
    uint32_t desc;

    if ((p0 & 7) != 1 || (opcode != 0x2e && opcode != 0x2f) ||
        (p1 & 3) != (is_double ? 1 : 0) ||
        (p1 & 0x78) != 0x78 || !(p2 & 0x08) ||
        (p2 & 0x87)) {
        return false;
    }
    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    if (mod != 3 && sae) {
        return false;
    }
    left = apx_evex_reg_field(p0, modrm);
    if (mod == 3) {
        right = evex_vector_rm_field(p0, modrm);
    } else {
        if (!gen_evex_memory_address(env, s, p0, p1, modrm,
                                     is_double ? 8 : 4, 0, 1,
                                     is_double ? 8 : 4, false)) {
            return true;
        }
    }
    desc = evex_comi_desc(left, right, is_double, quiet, sae);
    if (mod == 3) {
        gen_helper_evex_comi_reg(
            tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, desc));
    } else {
        gen_helper_evex_comi_load(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc));
    }
    set_cc_op(s, CC_OP_EFLAGS);
    return true;
}

static bool gen_evex_fcmp(CPUX86State *env, DisasContext *s,
                          int p0, int p1, int p2, int opcode)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int mandatory = p1 & 3;
    const bool scalar = mandatory == 2 || mandatory == 3;
    const bool is_double = mandatory == 1 || mandatory == 3;
    const bool b = (p2 & 0x10) != 0;
    const int mask_reg = p2 & 7;
    int vector_length = (p2 >> 5) & 3;
    bool sae = false;
    bool broadcast = false;
    bool stack_segment = false;
    int modrm, mod;
    int dst, src1, src2 = 0;
    uint32_t immediate;
    uint32_t desc;

    if ((p0 & 7) != 1 || opcode != 0xc2 ||
        (p1 & 0x80) != (is_double ? 0x80 : 0) ||
        (p2 & 0x80)) {
        return false;
    }
    if (scalar) {
        vector_length = 0;
    }

    modrm = x86_ldub_code(env, s);
    mod = modrm >> 6;
    /* A mask-register destination has no EVEX R/R' extension. */
    if ((p0 & 0x90) != 0x90) {
        return false;
    }
    if (mod == 3) {
        if (b) {
            if (!scalar) {
                /* Packed register SAE has fixed 512-bit semantics and LLIG. */
                vector_length = 2;
            }
            sae = true;
        } else if (!scalar && vector_length == 3) {
            return false;
        }
    } else {
        if (scalar && b) {
            return false;
        }
        if (!scalar && vector_length == 3) {
            return false;
        }
        broadcast = b;
    }
    if (!scalar && vector_length != 2 &&
        !x86_evex_require_features(s, CPUID_7_0_EBX_AVX512VL, 0, 0)) {
        return true;
    }

    dst = (modrm >> 3) & 7;
    src1 = apx_evex_v_field(p1, p2);
    if (mod == 3) {
        src2 = evex_vector_rm_field(p0, modrm);
        immediate = x86_ldub_code(env, s);
    } else {
        const int element_bytes = is_double ? 8 : 4;
        bool uses_egpr;

        s->rip_offset = 1;
        stack_segment = gen_evex_memory_address_details(
            env, s, p0, p1, modrm,
            scalar || broadcast ? element_bytes : 16 << vector_length,
            &uses_egpr);
        if (uses_egpr && (!CODE64(s) || !apx_f_enabled(s))) {
            gen_illegal_opcode(s);
            return true;
        }
        immediate = x86_ldub_code(env, s);
    }

    desc = evex_fcmp_desc(dst, src1, src2, vector_length, mask_reg,
                          is_double, scalar, sae, broadcast);
    if (stack_segment) {
        desc |= EVEX_FCMP_STACK;
    }
    if (mod == 3) {
        gen_helper_evex_fcmp_reg(
            tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, desc),
            tcg_const_i32(tcg_ctx, immediate));
    } else {
        gen_helper_evex_fcmp_load(
            tcg_ctx, tcg_ctx->cpu_env, s->A0,
            tcg_const_i32(tcg_ctx, desc),
            tcg_const_i32(tcg_ctx, immediate));
    }
    return true;
}

static uint32_t apx_scalar_desc(int dst, int src1, int src2, int width,
                                APXScalarOp operation, bool no_flags,
                                bool count_cl)
{
    const int width_shift = width == 1 ? 0 : width == 2 ? 1 : width == 4 ? 2 : 3;

    return (dst << APX_SCALAR_DST_SHIFT) |
           (src1 << APX_SCALAR_SRC1_SHIFT) |
           (src2 << APX_SCALAR_SRC2_SHIFT) |
           (width_shift << APX_SCALAR_WIDTH_SHIFT) |
           ((uint32_t)operation << APX_SCALAR_OP_SHIFT) |
           (no_flags ? APX_SCALAR_NO_FLAGS : 0) |
           (count_cl ? APX_SCALAR_COUNT_CL : 0);
}

static bool apx_scalar_operation_writes_flags(APXScalarOp operation,
                                              bool no_flags)
{
    if (no_flags) {
        return false;
    }
    switch (operation) {
    case APX_SCALAR_NOT:
    case APX_SCALAR_PDEP:
    case APX_SCALAR_PEXT:
    case APX_SCALAR_SARX:
    case APX_SCALAR_SHLX:
    case APX_SCALAR_SHRX:
    case APX_SCALAR_RORX:
    case APX_SCALAR_MULX:
        return false;
    default:
        return true;
    }
}

static void gen_apx_scalar_reg(DisasContext *s, int dst, int src1, int src2,
                               int width, APXScalarOp operation,
                               bool no_flags, bool count_cl,
                               uint64_t immediate)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    /* The helper reads the lazy flag state even for flag-suppressed forms so
     * carry-chain operands and preserved flags observe the preceding insn. */
    gen_update_cc_op(s);
    gen_helper_apx_scalar_reg(
        tcg_ctx, tcg_ctx->cpu_env,
        tcg_const_i32(tcg_ctx,
                      apx_scalar_desc(dst, src1, src2, width, operation,
                                      no_flags, count_cl)),
        tcg_const_i64(tcg_ctx, immediate));
    if (apx_scalar_operation_writes_flags(operation, no_flags)) {
        set_cc_op(s, CC_OP_EFLAGS);
    }
}

static void gen_apx_implicit_mul_div(DisasContext *s, int extension,
                                     int width, bool no_flags)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (extension == 4) {
        switch (width) {
        case 1:
            gen_op_mov_v_reg(s, MO_8, s->T1, R_EAX);
            tcg_gen_ext8u_tl(tcg_ctx, s->T0, s->T0);
            tcg_gen_ext8u_tl(tcg_ctx, s->T1, s->T1);
            tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
            gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
            if (!no_flags) {
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0,
                                0xff00);
                set_cc_op(s, CC_OP_MULB);
            }
            break;
        case 2:
            gen_op_mov_v_reg(s, MO_16, s->T1, R_EAX);
            tcg_gen_ext16u_tl(tcg_ctx, s->T0, s->T0);
            tcg_gen_ext16u_tl(tcg_ctx, s->T1, s->T1);
            tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
            gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
            if (!no_flags) {
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                tcg_gen_shri_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0, 16);
            }
            tcg_gen_shri_tl(tcg_ctx, s->T0, s->T0, 16);
            gen_op_mov_reg_v(s, MO_16, R_EDX, s->T0);
            if (!no_flags) {
                set_cc_op(s, CC_OP_MULW);
            }
            break;
        case 4:
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32,
                                 tcg_ctx->cpu_regs[R_EAX]);
            tcg_gen_mulu2_i32(tcg_ctx, s->tmp2_i32, s->tmp3_i32,
                              s->tmp2_i32, s->tmp3_i32);
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EAX],
                                s->tmp2_i32);
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EDX],
                                s->tmp3_i32);
            if (!no_flags) {
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst,
                               tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src,
                               tcg_ctx->cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULL);
            }
            break;
        default:
            tcg_gen_mulu2_i64(tcg_ctx, tcg_ctx->cpu_regs[R_EAX],
                              tcg_ctx->cpu_regs[R_EDX], s->T0,
                              tcg_ctx->cpu_regs[R_EAX]);
            if (!no_flags) {
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst,
                               tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src,
                               tcg_ctx->cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULQ);
            }
            break;
        }
        return;
    }

    if (extension == 5) {
        switch (width) {
        case 1:
            gen_op_mov_v_reg(s, MO_8, s->T1, R_EAX);
            tcg_gen_ext8s_tl(tcg_ctx, s->T0, s->T0);
            tcg_gen_ext8s_tl(tcg_ctx, s->T1, s->T1);
            tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
            gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
            if (!no_flags) {
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                tcg_gen_ext8s_tl(tcg_ctx, s->tmp0, s->T0);
                tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0,
                               s->tmp0);
                set_cc_op(s, CC_OP_MULB);
            }
            break;
        case 2:
            gen_op_mov_v_reg(s, MO_16, s->T1, R_EAX);
            tcg_gen_ext16s_tl(tcg_ctx, s->T0, s->T0);
            tcg_gen_ext16s_tl(tcg_ctx, s->T1, s->T1);
            tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
            gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
            if (!no_flags) {
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                tcg_gen_ext16s_tl(tcg_ctx, s->tmp0, s->T0);
                tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0,
                               s->tmp0);
            }
            tcg_gen_shri_tl(tcg_ctx, s->T0, s->T0, 16);
            gen_op_mov_reg_v(s, MO_16, R_EDX, s->T0);
            if (!no_flags) {
                set_cc_op(s, CC_OP_MULW);
            }
            break;
        case 4:
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32,
                                 tcg_ctx->cpu_regs[R_EAX]);
            tcg_gen_muls2_i32(tcg_ctx, s->tmp2_i32, s->tmp3_i32,
                              s->tmp2_i32, s->tmp3_i32);
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EAX],
                                s->tmp2_i32);
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EDX],
                                s->tmp3_i32);
            if (!no_flags) {
                tcg_gen_sari_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, 31);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst,
                               tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_sub_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32,
                                s->tmp3_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_cc_src,
                                    s->tmp2_i32);
                set_cc_op(s, CC_OP_MULL);
            }
            break;
        default:
            tcg_gen_muls2_i64(tcg_ctx, tcg_ctx->cpu_regs[R_EAX],
                              tcg_ctx->cpu_regs[R_EDX], s->T0,
                              tcg_ctx->cpu_regs[R_EAX]);
            if (!no_flags) {
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst,
                               tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_sari_tl(tcg_ctx, tcg_ctx->cpu_cc_src,
                                tcg_ctx->cpu_regs[R_EAX], 63);
                tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_src,
                               tcg_ctx->cpu_cc_src,
                               tcg_ctx->cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULQ);
            }
            break;
        }
        return;
    }

    if (extension == 6) {
        switch (width) {
        case 1:
            gen_helper_divb_AL(tcg_ctx, tcg_ctx->cpu_env, s->T0);
            break;
        case 2:
            gen_helper_divw_AX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
            break;
        case 4:
            gen_helper_divl_EAX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
            break;
        default:
            gen_helper_divq_EAX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
            break;
        }
        return;
    }

    switch (width) {
    case 1:
        gen_helper_idivb_AL(tcg_ctx, tcg_ctx->cpu_env, s->T0);
        break;
    case 2:
        gen_helper_idivw_AX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
        break;
    case 4:
        gen_helper_idivl_EAX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
        break;
    default:
        gen_helper_idivq_EAX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
        break;
    }
}

static bool gen_apx_evex_scalar_other(CPUX86State *env, DisasContext *s,
                                      int p0, int p1, int p2, int opcode)
{
    const bool nd = (p2 & 0x10) != 0;
    const bool nf = (p2 & 0x04) != 0;
    int modrm;
    int reg, rm, v;
    int dst, src2;
    int width;
    APXScalarOp operation;
    bool count_cl = false;
    uint64_t immediate = 0;

    if ((p0 & 7) != 4 || (p2 & 0xe3)) {
        return false;
    }

    /* Promoted one-operand MUL/IMUL/DIV/IDIV retain the architectural
     * accumulator pair and do not define NDD.  Load the explicit source
     * before changing RAX/RDX so every register and address alias observes
     * the old state. */
    if (opcode == 0xf6 || opcode == 0xf7) {
        const bool byte_form = opcode == 0xf6;
        const target_ulong modrm_pc = s->pc;
        int extension;

        if (!apx_evex_width(p1, byte_form, &width)) {
            return false;
        }
        modrm = x86_ldub_code(env, s);
        extension = (modrm >> 3) & 7;
        if (extension >= 4) {
            const int mod = modrm >> 6;

            if (nd || (p1 & 0x78) != 0x78 || !(p2 & 0x08) ||
                (mod == 3 && !(p1 & 0x04))) {
                return false;
            }
            if (mod == 3) {
                rm = apx_evex_rm_field(p0, modrm);
                gen_rex2_load_gpr(s, s->T0, rm, width);
            } else {
                const int rex2 = (!(p0 & 0x20) ? 0x01 : 0) |
                                 (!(p0 & 0x40) ? 0x02 : 0) |
                                 ((p0 & 0x08) ? 0x10 : 0) |
                                 (!(p1 & 0x04) ? 0x20 : 0);
                AddressParts address =
                    decode_rex2_memory_address(env, s, modrm, rex2);
                const bool stack_segment =
                    s->override == R_SS ||
                    (s->override < 0 && address.def_seg == R_SS);

                gen_rex2_memory_address(s, address);
                gen_rex2_memory_range_check(s, stack_segment, width);
                gen_rex2_load_memory(s, s->T0, width);
            }
            gen_apx_implicit_mul_div(s, extension, width, nf);
            return true;
        }
        s->pc = modrm_pc;
    }

    if (!(p1 & 0x04)) {
        return false;
    }

    /* Count instructions have an ordinary ModRM destination and use NF but
     * not NDD.  Their EVEX.vvvvv field remains architectural zero. */
    if (opcode == 0xf4 || opcode == 0xf5 || opcode == 0x88) {
        if (nd || (p1 & 0x78) != 0x78 || !(p2 & 0x08) ||
            !apx_evex_width(p1, false, &width)) {
            return false;
        }
        modrm = x86_ldub_code(env, s);
        if ((modrm >> 6) != 3) {
            return false;
        }
        operation = opcode == 0xf4 ? APX_SCALAR_TZCNT
                    : opcode == 0xf5 ? APX_SCALAR_LZCNT
                                     : APX_SCALAR_POPCNT;
        dst = apx_evex_reg_field(p0, modrm);
        src2 = apx_evex_rm_field(p0, modrm);
        gen_apx_scalar_reg(s, dst, 0, src2, width, operation, nf, false, 0);
        return true;
    }

    if (!nd && ((p1 & 0x78) != 0x78 || !(p2 & 0x08))) {
        return false;
    }

    if (opcode == 0xaf) {
        if (!apx_evex_width(p1, false, &width)) {
            return false;
        }
        modrm = x86_ldub_code(env, s);
        if ((modrm >> 6) != 3) {
            return false;
        }
        reg = apx_evex_reg_field(p0, modrm);
        rm = apx_evex_rm_field(p0, modrm);
        v = apx_evex_v_field(p1, p2);
        dst = nd ? v : reg;
        gen_apx_scalar_reg(s, dst, reg, rm, width, APX_SCALAR_IMUL, nf,
                           false, 0);
        return true;
    }

    if (opcode == 0x66) {
        if (nf || (p1 & 3) < 1 || (p1 & 3) > 2) {
            return false;
        }
        width = (p1 & 0x80) ? 8 : 4;
        modrm = x86_ldub_code(env, s);
        if ((modrm >> 6) != 3) {
            return false;
        }
        reg = apx_evex_reg_field(p0, modrm);
        rm = apx_evex_rm_field(p0, modrm);
        v = apx_evex_v_field(p1, p2);
        dst = nd ? v : reg;
        operation = (p1 & 3) == 1 ? APX_SCALAR_ADCX : APX_SCALAR_ADOX;
        gen_apx_scalar_reg(s, dst, reg, rm, width, operation, false, false,
                           0);
        return true;
    }

    if (opcode == 0xa4 || opcode == 0xa5 || opcode == 0xac || opcode == 0xad ||
        opcode == 0x24 || opcode == 0x25 || opcode == 0x2c || opcode == 0x2d) {
        const int normalized = opcode | 0x80;

        if (!apx_evex_width(p1, false, &width)) {
            return false;
        }
        modrm = x86_ldub_code(env, s);
        if ((modrm >> 6) != 3) {
            return false;
        }
        reg = apx_evex_reg_field(p0, modrm);
        rm = apx_evex_rm_field(p0, modrm);
        v = apx_evex_v_field(p1, p2);
        dst = nd ? v : rm;
        operation = normalized == 0xa4 || normalized == 0xa5
                        ? APX_SCALAR_SHLD
                        : APX_SCALAR_SHRD;
        count_cl = normalized & 1;
        if (!count_cl) {
            immediate = x86_ldub_code(env, s);
        }
        gen_apx_scalar_reg(s, dst, rm, reg, width, operation, nf, count_cl,
                           immediate);
        return true;
    }

    if (opcode == 0xfe || opcode == 0xff || opcode == 0xf6 || opcode == 0xf7) {
        const bool byte_form = !(opcode & 1);
        int extension;

        if (!apx_evex_width(p1, byte_form, &width)) {
            return false;
        }
        modrm = x86_ldub_code(env, s);
        if ((modrm >> 6) != 3) {
            return false;
        }
        extension = (modrm >> 3) & 7;
        if ((opcode == 0xfe || opcode == 0xff) && extension <= 1) {
            operation = extension == 0 ? APX_SCALAR_INC : APX_SCALAR_DEC;
        } else if ((opcode == 0xf6 || opcode == 0xf7) &&
                   (extension == 2 || extension == 3)) {
            operation = extension == 2 ? APX_SCALAR_NOT : APX_SCALAR_NEG;
        } else {
            return false;
        }
        if (operation == APX_SCALAR_NOT && nf) {
            return false;
        }
        rm = apx_evex_rm_field(p0, modrm);
        v = apx_evex_v_field(p1, p2);
        dst = nd ? v : rm;
        gen_apx_scalar_reg(s, dst, rm, 0, width, operation, nf, false, 0);
        return true;
    }

    if (opcode == 0xc0 || opcode == 0xc1 || opcode == 0xd0 || opcode == 0xd1 ||
        opcode == 0xd2 || opcode == 0xd3) {
        const bool byte_form = !(opcode & 1);
        const int count_kind = opcode & 0xfe;
        int extension;

        if (!apx_evex_width(p1, byte_form, &width) ||
            (p0 & 0x90) != 0x90) {
            return false;
        }
        modrm = x86_ldub_code(env, s);
        if ((modrm >> 6) != 3) {
            return false;
        }
        extension = (modrm >> 3) & 7;
        switch (extension) {
        case 0:
            operation = APX_SCALAR_ROL;
            break;
        case 1:
            operation = APX_SCALAR_ROR;
            break;
        case 2:
            operation = APX_SCALAR_RCL;
            break;
        case 3:
            operation = APX_SCALAR_RCR;
            break;
        case 4:
            operation = APX_SCALAR_SHL;
            break;
        case 5:
            operation = APX_SCALAR_SHR;
            break;
        case 7:
            operation = APX_SCALAR_SAR;
            break;
        default:
            return false;
        }
        if ((operation == APX_SCALAR_RCL || operation == APX_SCALAR_RCR) &&
            nf) {
            return false;
        }
        rm = apx_evex_rm_field(p0, modrm);
        v = apx_evex_v_field(p1, p2);
        dst = nd ? v : rm;
        if (count_kind == 0xc0) {
            immediate = x86_ldub_code(env, s);
        } else if (count_kind == 0xd0) {
            immediate = 1;
        } else {
            count_cl = true;
        }
        gen_apx_scalar_reg(s, dst, rm, 0, width, operation, nf, count_cl,
                           immediate);
        return true;
    }

    return false;
}

static APXEVEXDecodeResult gen_apx_evex_bmi_register(
    CPUX86State *env, DisasContext *s, int p0, int p1, int p2, int opcode)
{
    const int map = p0 & 7;
    const int mandatory = p1 & 3;
    const bool nf = (p2 & 0x04) != 0;
    APXScalarOp operation;
    int modrm;
    int dst, src1, src2;
    int width;
    uint64_t immediate = 0;

    if (!((map == 2 && (opcode == 0xf2 || opcode == 0xf3 ||
                       opcode == 0xf5 || opcode == 0xf6 || opcode == 0xf7)) ||
          (map == 3 && opcode == 0xf0 && mandatory == 3))) {
        return APX_EVEX_NOT_HANDLED;
    }
    if (!(p1 & 0x04) || (p2 & 0xf3)) {
        return APX_EVEX_INVALID;
    }
    width = (p1 & 0x80) ? 8 : 4;

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return APX_EVEX_INVALID;
    }
    dst = apx_evex_reg_field(p0, modrm);
    src1 = apx_evex_v_field(p1, p2);
    src2 = apx_evex_rm_field(p0, modrm);

    if (map == 3) {
        if (nf || (p1 & 0x78) != 0x78 || !(p2 & 0x08)) {
            return APX_EVEX_INVALID;
        }
        immediate = x86_ldub_code(env, s);
        gen_apx_scalar_reg(s, dst, 0, src2, width, APX_SCALAR_RORX, false,
                           false, immediate);
        return APX_EVEX_DECODED;
    }

    if (opcode == 0xf2 && mandatory == 0) {
        operation = APX_SCALAR_ANDN;
    } else if (opcode == 0xf3 && mandatory == 0) {
        const int extension = (modrm >> 3) & 7;

        if ((p0 & 0x90) != 0x90 || extension < 1 || extension > 3) {
            return APX_EVEX_INVALID;
        }
        operation = extension == 1 ? APX_SCALAR_BLSR
                    : extension == 2 ? APX_SCALAR_BLSMSK
                                     : APX_SCALAR_BLSI;
        dst = src1;
        src1 = 0;
    } else if (opcode == 0xf5 && mandatory == 0) {
        operation = APX_SCALAR_BZHI;
    } else if (opcode == 0xf7 && mandatory == 0) {
        operation = APX_SCALAR_BEXTR;
    } else if (opcode == 0xf5 && mandatory == 3) {
        if (nf) {
            return APX_EVEX_INVALID;
        }
        operation = APX_SCALAR_PDEP;
    } else if (opcode == 0xf5 && mandatory == 2) {
        if (nf) {
            return APX_EVEX_INVALID;
        }
        operation = APX_SCALAR_PEXT;
    } else if (opcode == 0xf6 && mandatory == 3) {
        if (nf) {
            return APX_EVEX_INVALID;
        }
        operation = APX_SCALAR_MULX;
    } else if (opcode == 0xf7 && mandatory >= 1) {
        if (nf) {
            return APX_EVEX_INVALID;
        }
        operation = mandatory == 1 ? APX_SCALAR_SHLX
                    : mandatory == 2 ? APX_SCALAR_SARX
                                     : APX_SCALAR_SHRX;
    } else {
        return APX_EVEX_INVALID;
    }

    if (operation == APX_SCALAR_MULX) {
        gen_apx_scalar_reg(s, dst, src1, src2, width, operation, false, false,
                           0);
    } else {
        gen_apx_scalar_reg(s, dst, src1, src2, width, operation, nf, false,
                           0);
    }
    return APX_EVEX_DECODED;
}

static bool gen_apx_evex_register(CPUX86State *env, DisasContext *s,
                                  int rex_byte, int p0, int p1, int p2,
                                  int opcode)
{
    REX2BinaryOp operation;
    bool nd, nf, reverse;
    int modrm;
    int reg, rm;
    int dst, src1, src2;
    int width;

    if ((p0 & 7) != 4 || rex_byte ||
        (s->prefix &
         (PREFIX_LOCK | PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ)) ||
        !(p1 & 0x04) || (p2 & 0xe3)) {
        return false;
    }

    switch (opcode) {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
        operation = REX2_BIN_ADD;
        break;
    case 0x08:
    case 0x09:
    case 0x0a:
    case 0x0b:
        operation = REX2_BIN_OR;
        break;
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
        operation = REX2_BIN_ADC;
        break;
    case 0x20:
    case 0x21:
    case 0x22:
    case 0x23:
        operation = REX2_BIN_AND;
        break;
    case 0x28:
    case 0x29:
    case 0x2a:
    case 0x2b:
        operation = REX2_BIN_SUB;
        break;
    case 0x18:
    case 0x19:
    case 0x1a:
    case 0x1b:
        operation = REX2_BIN_SBB;
        break;
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
        operation = REX2_BIN_XOR;
        break;
    default:
        return gen_apx_evex_scalar_other(env, s, p0, p1, p2, opcode);
    }

    if (!(opcode & 1)) {
        if ((p1 & 3) != 0) {
            return false;
        }
        width = 1;
    } else {
        if ((p1 & 3) > 1) {
            return false;
        }
        width = (p1 & 0x80) ? 8 : (p1 & 1) ? 2 : 4;
    }

    nd = (p2 & 0x10) != 0;
    nf = (p2 & 0x04) != 0;
    if (operation == REX2_BIN_SBB && nf) {
        return false;
    }
    if (!nd && ((p1 & 0x78) != 0x78 || !(p2 & 0x08))) {
        return false;
    }

    modrm = x86_ldub_code(env, s);
    if ((modrm >> 6) != 3) {
        return false;
    }

    reg = (modrm >> 3) & 7;
    if (!(p0 & 0x80)) {
        reg |= 8;
    }
    if (!(p0 & 0x10)) {
        reg |= 16;
    }
    rm = modrm & 7;
    if (!(p0 & 0x20)) {
        rm |= 8;
    }
    if (p0 & 0x08) {
        rm |= 16;
    }

    reverse = (opcode & 2) != 0;
    src1 = reverse ? reg : rm;
    src2 = reverse ? rm : reg;
    dst = src1;
    if (nd) {
        dst = (~p1 >> 3) & 15;
        if (!(p2 & 0x08)) {
            dst |= 16;
        }
    }

    gen_apx_evex_binary(s, operation, dst, src1, src2, width, nf);
    return true;
}

static void gen_rex2_binary_memory(DisasContext *s, REX2BinaryOp op, int reg,
                                   int width, bool memory_is_destination)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 lhs = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 rhs = tcg_temp_new_i64(tcg_ctx);
    MemOp ot = rex2_width_memop(width);

    if (memory_is_destination) {
        gen_rex2_load_memory(s, lhs, width);
        gen_rex2_load_gpr(s, rhs, reg, width);
    } else {
        gen_rex2_load_gpr(s, lhs, reg, width);
        gen_rex2_load_memory(s, rhs, width);
    }

    switch (op) {
    case REX2_BIN_ADD:
        tcg_gen_add_i64(tcg_ctx, lhs, lhs, rhs);
        if (memory_is_destination) {
            gen_rex2_store_memory(s, lhs, width);
        } else {
            gen_rex2_store_gpr(s, reg, lhs, width);
        }
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, rhs);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, lhs);
        set_cc_op(s, CC_OP_ADDB + ot);
        break;
    case REX2_BIN_ADC:
    case REX2_BIN_SBB: {
        TCGv_i64 carry = tcg_temp_new_i64(tcg_ctx);

        gen_compute_eflags_c(s, carry);
        if (op == REX2_BIN_ADC) {
            tcg_gen_add_i64(tcg_ctx, lhs, lhs, rhs);
            tcg_gen_add_i64(tcg_ctx, lhs, lhs, carry);
        } else {
            tcg_gen_sub_i64(tcg_ctx, lhs, lhs, rhs);
            tcg_gen_sub_i64(tcg_ctx, lhs, lhs, carry);
        }
        if (memory_is_destination) {
            gen_rex2_store_memory(s, lhs, width);
        } else {
            gen_rex2_store_gpr(s, reg, lhs, width);
        }
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, carry);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, rhs);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, lhs);
        set_cc_op(s, (op == REX2_BIN_ADC ? CC_OP_ADCB : CC_OP_SBBB) + ot);
        tcg_temp_free_i64(tcg_ctx, carry);
        break;
    }
    case REX2_BIN_SUB:
    case REX2_BIN_CMP:
        tcg_gen_mov_tl(tcg_ctx, s->cc_srcT, lhs);
        tcg_gen_sub_i64(tcg_ctx, lhs, lhs, rhs);
        if (op == REX2_BIN_SUB) {
            if (memory_is_destination) {
                gen_rex2_store_memory(s, lhs, width);
            } else {
                gen_rex2_store_gpr(s, reg, lhs, width);
            }
        }
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, rhs);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, lhs);
        set_cc_op(s, CC_OP_SUBB + ot);
        break;
    case REX2_BIN_OR:
        tcg_gen_or_i64(tcg_ctx, lhs, lhs, rhs);
        goto logical_result;
    case REX2_BIN_AND:
    case REX2_BIN_TEST:
        tcg_gen_and_i64(tcg_ctx, lhs, lhs, rhs);
        goto logical_result;
    case REX2_BIN_XOR:
        tcg_gen_xor_i64(tcg_ctx, lhs, lhs, rhs);
    logical_result:
        if (op != REX2_BIN_TEST) {
            if (memory_is_destination) {
                gen_rex2_store_memory(s, lhs, width);
            } else {
                gen_rex2_store_gpr(s, reg, lhs, width);
            }
        }
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, lhs);
        set_cc_op(s, CC_OP_LOGICB + ot);
        break;
    }

    tcg_temp_free_i64(tcg_ctx, lhs);
    tcg_temp_free_i64(tcg_ctx, rhs);
}

static void gen_rex2_imul(DisasContext *s, int dst, int src, int width,
                          bool memory_source)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 lhs = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 rhs = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 result = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 overflow = tcg_temp_new_i64(tcg_ctx);

    gen_rex2_load_gpr(s, lhs, dst, width);
    if (memory_source) {
        gen_rex2_load_memory(s, rhs, width);
    } else {
        gen_rex2_load_gpr(s, rhs, src, width);
    }

    if (width == 8) {
        TCGv_i64 high = tcg_temp_new_i64(tcg_ctx);

        tcg_gen_muls2_i64(tcg_ctx, result, high, lhs, rhs);
        tcg_gen_sari_i64(tcg_ctx, overflow, result, 63);
        tcg_gen_sub_i64(tcg_ctx, overflow, overflow, high);
        tcg_temp_free_i64(tcg_ctx, high);
    } else {
        if (width == 2) {
            tcg_gen_ext16s_i64(tcg_ctx, lhs, lhs);
            tcg_gen_ext16s_i64(tcg_ctx, rhs, rhs);
        } else {
            tcg_gen_ext32s_i64(tcg_ctx, lhs, lhs);
            tcg_gen_ext32s_i64(tcg_ctx, rhs, rhs);
        }
        tcg_gen_mul_i64(tcg_ctx, result, lhs, rhs);
        if (width == 2) {
            tcg_gen_ext16s_i64(tcg_ctx, overflow, result);
        } else {
            tcg_gen_ext32s_i64(tcg_ctx, overflow, result);
        }
        tcg_gen_sub_i64(tcg_ctx, overflow, result, overflow);
    }

    gen_rex2_store_gpr(s, dst, result, width);
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, result);
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, overflow);
    set_cc_op(s, CC_OP_MULB + rex2_width_memop(width));

    tcg_temp_free_i64(tcg_ctx, overflow);
    tcg_temp_free_i64(tcg_ctx, result);
    tcg_temp_free_i64(tcg_ctx, rhs);
    tcg_temp_free_i64(tcg_ctx, lhs);
}

/* Fail-closed REX2 scalar slice. It owns D5 in 64-bit mode and accepts the
 * explicitly implemented map-0 and map-1 register/memory forms below. */
static bool gen_rex2_register(CPUX86State *env, DisasContext *s, int rex_byte)
{
    int rex2 = x86_ldub_code(env, s);
    int opcode = x86_ldub_code(env, s);
    int modrm;
    int mod, reg, rm, dst, src, width;
    bool destination_is_reg;
    REX2BinaryOp binary_op;

    if (opcode == 0xa1) {
        uint64_t target;

        if (rex_byte || (rex2 & 0x88) ||
            (s->prefix & (PREFIX_LOCK | PREFIX_DATA | PREFIX_ADR |
                          PREFIX_REPZ | PREFIX_REPNZ))) {
            return false;
        }
        target = x86_ldq_code(env, s);
        gen_update_cc_op(s);
        set_cc_op(s, CC_OP_DYNAMIC);
        gen_jmp_im(s, s->pc_start - s->cs_base);
        gen_helper_apx_jmpabs(s->uc->tcg_ctx,
                              s->uc->tcg_ctx->cpu_env,
                              tcg_const_i64(s->uc->tcg_ctx, target));
        gen_eob(s);
        return true;
    }

    /* REX2 must be the final prefix and cannot immediately follow an
     * effective REX. Legacy prefixes retain their normal meanings and
     * restrictions; 66 selects 16-bit operands when W is clear. */
    if (rex_byte || (s->prefix & PREFIX_LOCK)) {
        return false;
    }

    /* M0=1 selects legacy map 1 without an encoded 0F byte.  Keep this
     * allowlist narrow until each inherited opcode has its own semantics and
     * legality coverage. */
    if (rex2 & 0x80) {
        if (opcode != 0xaf) {
            return false;
        }

        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | ((rex2 & 0x04) << 1) |
              ((rex2 & 0x40) >> 2);
        width = (rex2 & 0x08)               ? 8
                : (s->prefix & PREFIX_DATA) ? 2
                                            : 4;
        if (mod != 3) {
            AddressParts address =
                decode_rex2_memory_address(env, s, modrm, rex2);
            const bool stack_segment =
                s->override == R_SS ||
                (s->override < 0 && address.def_seg == R_SS);

            gen_rex2_memory_address(s, address);
            gen_rex2_memory_range_check(s, stack_segment, width);
            gen_rex2_imul(s, reg, 0, width, true);
            return true;
        }

        rm = (modrm & 7) | ((rex2 & 0x01) << 3) | (rex2 & 0x10);
        gen_rex2_imul(s, reg, rm, width, false);
        return true;
    }

    if ((opcode & 0xf8) == 0x50 || (opcode & 0xf8) == 0x58) {
        const bool push = (opcode & 0xf8) == 0x50;

        rm = (opcode & 7) | ((rex2 & 0x01) << 3) | (rex2 & 0x10);
        width = (rex2 & 0x08) || !(s->prefix & PREFIX_DATA) ? 8 : 2;
        gen_rex2_push_pop(s, rm, push, width);
        return true;
    }

    switch (opcode) {
    case 0x88:
    case 0x89:
    case 0x8a:
    case 0x8b:
        break;
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
        binary_op = REX2_BIN_ADD;
        break;
    case 0x08:
    case 0x09:
    case 0x0a:
    case 0x0b:
        binary_op = REX2_BIN_OR;
        break;
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
        binary_op = REX2_BIN_ADC;
        break;
    case 0x18:
    case 0x19:
    case 0x1a:
    case 0x1b:
        binary_op = REX2_BIN_SBB;
        break;
    case 0x20:
    case 0x21:
    case 0x22:
    case 0x23:
        binary_op = REX2_BIN_AND;
        break;
    case 0x28:
    case 0x29:
    case 0x2a:
    case 0x2b:
        binary_op = REX2_BIN_SUB;
        break;
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
        binary_op = REX2_BIN_XOR;
        break;
    case 0x38:
    case 0x39:
    case 0x3a:
    case 0x3b:
        binary_op = REX2_BIN_CMP;
        break;
    case 0x84:
    case 0x85:
        binary_op = REX2_BIN_TEST;
        break;
    default:
        return false;
    }

    modrm = x86_ldub_code(env, s);
    mod = (modrm >> 6) & 3;

    reg = (modrm >> 3) & 7;
    if (rex2 & 0x04) {
        reg |= 8;
    }
    if (rex2 & 0x40) {
        reg |= 16;
    }

    width = !(opcode & 1)               ? 1
            : (rex2 & 0x08)             ? 8
            : (s->prefix & PREFIX_DATA) ? 2
                                        : 4;
    destination_is_reg = opcode != 0x84 && opcode != 0x85 && (opcode & 2) != 0;

    if (mod != 3) {
        AddressParts address = decode_rex2_memory_address(env, s, modrm, rex2);
        const bool stack_segment =
            s->override == R_SS ||
            (s->override < 0 && address.def_seg == R_SS);

        gen_rex2_memory_address(s, address);
        gen_rex2_memory_range_check(s, stack_segment, width);
        if (opcode >= 0x88) {
            gen_rex2_mov_memory(s, reg, width, destination_is_reg);
        } else {
            gen_rex2_binary_memory(s, binary_op, reg, width,
                                   !destination_is_reg);
        }
        return true;
    }

    rm = modrm & 7;
    if (rex2 & 0x01) {
        rm |= 8;
    }
    if (rex2 & 0x10) {
        rm |= 16;
    }
    dst = destination_is_reg ? reg : rm;
    src = destination_is_reg ? rm : reg;

    if (opcode >= 0x88) {
        gen_rex2_mov(s, dst, src, width);
    } else {
        gen_rex2_binary(s, binary_op, dst, src, width);
    }
    return true;
}
#endif

/* convert one instruction. s->base.is_jmp is set if the translation must
   be stopped. Return the next pc value */
static target_ulong disas_insn(DisasContext *s, CPUState *cpu)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    CPUX86State *env = cpu->env_ptr;
    int b, prefixes, prefix_count;
    int shift;
    MemOp ot, aflag, dflag;
    int modrm, reg, rm, mod, op, opreg, val;
    target_ulong next_eip, tval;
    int rex_w, rex_r, rex_byte, rex_index, effective_rex_byte;
    target_ulong pc_start = s->base.pc_next;
    TCGOp *tcg_op, *prev_op = NULL;
    bool insn_hook = false;

    s->pc_start = tcg_ctx->pc_start = s->pc = pc_start;
    s->prefix = 0;

    s->uc = env->uc;

    // Unicorn: end address tells us to stop emulation
    if (uc_addr_is_exit(env->uc, s->pc)) {
        // imitate the HLT instruction
        gen_update_cc_op(s);
        gen_sync_pc(tcg_ctx, pc_start - s->cs_base);
        gen_helper_hlt(tcg_ctx, tcg_ctx->cpu_env,
                       tcg_const_i32(tcg_ctx, s->pc - pc_start));
        s->base.is_jmp = DISAS_NORETURN;
        return s->pc;
    }

    // Unicorn: callback might need to access to EFLAGS,
    // or want to stop emulation immediately
    if (HOOK_EXISTS_BOUNDED(env->uc, UC_HOOK_CODE, pc_start)) {
        if (s->last_cc_op != s->cc_op || s->cc_op_dirty) {
            sync_eflags(s, tcg_ctx);
            s->last_cc_op = s->cc_op;
        }

        // Sync PC in advance
        gen_sync_pc(tcg_ctx, pc_start - s->cs_base);

        // save the last operand
        prev_op = tcg_last_op(tcg_ctx);
        insn_hook = true;
        gen_uc_tracecode(tcg_ctx, 0xf1f1f1f1, UC_HOOK_CODE_IDX, env->uc, pc_start);

        check_exit_request(tcg_ctx);

        // Unicorn: Previous hook might change eflags to any state, let's sync it
        gen_compute_eflags(s);
    }

    s->override = -1;

#ifdef TARGET_X86_64
    s->rex_x = 0;
    s->rex_b = 0;
    s->x86_64_hregs = false;
#endif
    s->rip_offset = 0; /* for relative ip address */
    s->vex_l = 0;
    s->vex_w = 0;
    s->vex_v = 0;
    if (sigsetjmp(s->jmpbuf, 0) != 0) {
        gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        return s->pc;
    }

    prefixes = 0;
    rex_w = -1;
    rex_r = 0;
    rex_byte = 0;
    rex_index = -1;
    effective_rex_byte = 0;
    prefix_count = 0;

 next_byte:
    b = x86_ldub_code(env, s);
    /* Collect prefixes.  */
    switch (b) {
    case 0xf3:
        prefixes |= PREFIX_REPZ;
        prefix_count++;
        goto next_byte;
    case 0xf2:
        prefixes |= PREFIX_REPNZ;
        prefix_count++;
        goto next_byte;
    case 0xf0:
        prefixes |= PREFIX_LOCK;
        prefix_count++;
        goto next_byte;
    case 0x2e:
        if (!CODE64(s)) {
            s->override = R_CS;
        }
        prefix_count++;
        goto next_byte;
    case 0x36:
        if (!CODE64(s)) {
            s->override = R_SS;
        }
        prefix_count++;
        goto next_byte;
    case 0x3e:
        if (!CODE64(s)) {
            s->override = R_DS;
        }
        prefix_count++;
        goto next_byte;
    case 0x26:
        if (!CODE64(s)) {
            s->override = R_ES;
        }
        prefix_count++;
        goto next_byte;
    case 0x64:
        s->override = R_FS;
        prefix_count++;
        goto next_byte;
    case 0x65:
        s->override = R_GS;
        prefix_count++;
        goto next_byte;
    case 0x66:
        prefixes |= PREFIX_DATA;
        prefix_count++;
        goto next_byte;
    case 0x67:
        prefixes |= PREFIX_ADR;
        prefix_count++;
        goto next_byte;
#ifdef TARGET_X86_64
    case 0x40:
    case 0x41:
    case 0x42:
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x48:
    case 0x49:
    case 0x4a:
    case 0x4b:
    case 0x4c:
    case 0x4d:
    case 0x4e:
    case 0x4f:
        if (CODE64(s)) {
            rex_byte = b;
            rex_index = prefix_count;
            prefix_count++;
            goto next_byte;
        }
        break;
#endif
    case 0xc5: /* 2-byte VEX */
    case 0xc4: /* 3-byte VEX */
        /* VEX prefixes cannot be used except in 32-bit mode.
           Otherwise the instruction is LES or LDS.  */
        if (s->code32 && !s->vm86) {
            static const int pp_prefix[4] = {
                0, PREFIX_DATA, PREFIX_REPZ, PREFIX_REPNZ
            };
            int vex3, vex2 = x86_ldub_code(env, s);

            if (!CODE64(s) && (vex2 & 0xc0) != 0xc0) {
                /* 4.1.4.6: In 32-bit mode, bits [7:6] must be 11b,
                   otherwise the instruction is LES or LDS.  */
                s->pc--; /* rewind the advance_pc() x86_ldub_code() did */
                break;
            }

            /* 4.1.1-4.1.3: No preceding lock, 66, f2, f3, or rex prefixes. */
            if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ
                            | PREFIX_LOCK | PREFIX_DATA)) {
                goto illegal_op;
            }
#ifdef TARGET_X86_64
            if (rex_byte != 0 && rex_index + 1 == prefix_count) {
                goto illegal_op;
            }
#endif
            rex_r = (~vex2 >> 4) & 8;
            if (b == 0xc5) {
                /* 2-byte VEX prefix: RVVVVlpp, implied 0f leading opcode byte */
                vex3 = vex2;
                b = x86_ldub_code(env, s) | 0x100;
            } else {
                /* 3-byte VEX prefix: RXBmmmmm wVVVVlpp */
#ifdef TARGET_X86_64
                s->rex_x = (~vex2 >> 3) & 8;
                s->rex_b = (~vex2 >> 2) & 8;
#endif
                vex3 = x86_ldub_code(env, s);
                rex_w = (vex3 >> 7) & 1;
                switch (vex2 & 0x1f) {
                case 0x01: /* Implied 0f leading opcode bytes.  */
                    b = x86_ldub_code(env, s) | 0x100;
                    break;
                case 0x02: /* Implied 0f 38 leading opcode bytes.  */
                    b = 0x138;
                    break;
                case 0x03: /* Implied 0f 3a leading opcode bytes.  */
                    b = 0x13a;
                    break;
                case 0x05: /* Intel AMX map 5. */
                    b = 0x500;
                    break;
                case 0x07: /* Intel USER_MSR map 7. */
                    b = 0x700;
                    break;
                default:   /* Reserved for future use.  */
                    goto unknown_op;
                }
            }
            s->vex_v = (~vex3 >> 3) & 0xf;
            s->vex_l = (vex3 >> 2) & 1;
            s->vex_w = rex_w > 0;
#ifdef TARGET_X86_64
            /* Like REX, VEX selects SPL/BPL/SIL/DIL rather than the legacy
             * AH/CH/DH/BH byte-register aliases. */
            s->x86_64_hregs = true;
#endif
            prefixes |= pp_prefix[vex3 & 3] | PREFIX_VEX;
        }
        prefix_count++;
        break;
    }

    /* Post-process prefixes.  */
    if (CODE64(s)) {
        /* 2.2.1: A REX prefix is ignored when it does not immediately precede the opcode byte */
        if (rex_byte != 0 && rex_index + 1 == prefix_count) {
            /* REX prefix */
            effective_rex_byte = rex_byte;
            rex_w = (rex_byte >> 3) & 1;
            rex_r = (rex_byte & 0x4) << 1;
            s->rex_x = (rex_byte & 0x2) << 2;
            REX_B(s) = (rex_byte & 0x1) << 3;
            /* select uniform byte register addressing */
            s->x86_64_hregs = true;
        }

        /* In 64-bit mode, the default data size is 32-bit.  Select 64-bit
           data with rex_w, and 16-bit data with 0x66; rex_w takes precedence
           over 0x66 if both are present.  */
        dflag = (rex_w > 0 ? MO_64 : prefixes & PREFIX_DATA ? MO_16 : MO_32);
        /* In 64-bit mode, 0x67 selects 32-bit addressing.  */
        aflag = (prefixes & PREFIX_ADR ? MO_32 : MO_64);
    } else {
        /* In 16/32-bit mode, 0x66 selects the opposite data size.  */
        if (s->code32 ^ ((prefixes & PREFIX_DATA) != 0)) {
            dflag = MO_32;
        } else {
            dflag = MO_16;
        }
        /* In 16/32-bit mode, 0x67 selects the opposite addressing.  */
        if (s->code32 ^ ((prefixes & PREFIX_ADR) != 0)) {
            aflag = MO_32;
        }  else {
            aflag = MO_16;
        }
    }

    s->prefix = prefixes;
    s->aflag = aflag;
    s->dflag = dflag;

    if (prefixes & PREFIX_VEX) {
        VEXUserMSRDecodeResult user_msr =
            gen_vex_user_msr(env, s, b);
        VEXOpmaskDecodeResult opmask;

        if (user_msr == VEX_USER_MSR_DECODED) {
            goto decoded;
        }
        if (user_msr == VEX_USER_MSR_INVALID) {
            goto illegal_op;
        }
        opmask = gen_vex_opmask(env, s, b, rex_r);
        if (opmask == VEX_OPMASK_DECODED) {
            goto decoded;
        }
#ifdef TARGET_X86_64
        {
            AMXVexDecodeResult amx = gen_vex_amx(env, s, b, rex_r);

            if (amx == AMX_VEX_DECODED) {
                goto decoded;
            }
            if (amx == AMX_VEX_INVALID) {
                goto illegal_op;
            }
        }
#endif
        if (opmask == VEX_OPMASK_INVALID ||
            !vex_opcode_uses_vector_decoder(b)) {
            goto illegal_op;
        }
    }

    /* now check op code */
 reswitch:
    switch(b) {
    case 0x0f:
        /**************************/
        /* extended op code */
        b = x86_ldub_code(env, s) | 0x100;
        goto reswitch;

        /**************************/
        /* arith & logic */
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:

    case 0x08:
    case 0x09:
    case 0x0a:
    case 0x0b:
    case 0x0c:
    case 0x0d:

    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15:

    case 0x18:
    case 0x19:
    case 0x1a:
    case 0x1b:
    case 0x1c:
    case 0x1d:

    case 0x20:
    case 0x21:
    case 0x22:
    case 0x23:
    case 0x24:
    case 0x25:

    case 0x28:
    case 0x29:
    case 0x2a:
    case 0x2b:
    case 0x2c:
    case 0x2d:

    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:

    case 0x38:
    case 0x39:
    case 0x3a:
    case 0x3b:
    case 0x3c:
    case 0x3d:
        {
            int op, f, val;
            op = (b >> 3) & 7;
            f = (b >> 1) & 3;

            ot = mo_b_d(b, dflag);

            switch(f) {
            case 0: /* OP Ev, Gv */
                modrm = x86_ldub_code(env, s);
                reg = ((modrm >> 3) & 7) | rex_r;
                mod = (modrm >> 6) & 3;
                rm = (modrm & 7) | REX_B(s);
                if (mod != 3) {
                    gen_lea_modrm(env, s, modrm);
                    opreg = OR_TMP0;
                } else if (op == OP_XORL && rm == reg) {
                xor_zero:
                    /* xor reg, reg optimisation */
                    set_cc_op(s, CC_OP_CLR);
                    tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                    gen_op_mov_reg_v(s, ot, reg, s->T0);
                    break;
                } else {
                    opreg = rm;
                }
                gen_op_mov_v_reg(s, ot, s->T1, reg);
                gen_op(s, op, ot, opreg);
                break;
            case 1: /* OP Gv, Ev */
                modrm = x86_ldub_code(env, s);
                mod = (modrm >> 6) & 3;
                reg = ((modrm >> 3) & 7) | rex_r;
                rm = (modrm & 7) | REX_B(s);
                if (mod != 3) {
                    gen_lea_modrm(env, s, modrm);
                    gen_op_ld_v(s, ot, s->T1, s->A0);
                } else if (op == OP_XORL && rm == reg) {
                    goto xor_zero;
                } else {
                    gen_op_mov_v_reg(s, ot, s->T1, rm);
                }
                gen_op(s, op, ot, reg);
                break;
            case 2: /* OP A, Iv */
                val = insn_get(env, s, ot);
                tcg_gen_movi_tl(tcg_ctx, s->T1, val);
                gen_op(s, op, ot, OR_EAX);
                break;
            }
        }
        break;

    case 0x82:
        if (CODE64(s))
            goto illegal_op;
        /* fall through */
    case 0x80: /* GRP1 */
    case 0x81:
    case 0x83:
        {
            int val;

            ot = mo_b_d(b, dflag);

            modrm = x86_ldub_code(env, s);
            mod = (modrm >> 6) & 3;
            rm = (modrm & 7) | REX_B(s);
            op = (modrm >> 3) & 7;

            if (mod != 3) {
                if (b == 0x83)
                    s->rip_offset = 1;
                else
                    s->rip_offset = insn_const_size(ot);
                gen_lea_modrm(env, s, modrm);
                opreg = OR_TMP0;
            } else {
                opreg = rm;
            }

            switch(b) {
            default:
            case 0x80:
            case 0x81:
            case 0x82:
                val = insn_get(env, s, ot);
                break;
            case 0x83:
                val = (int8_t)insn_get(env, s, MO_8);
                break;
            }
            tcg_gen_movi_tl(tcg_ctx, s->T1, val);
            gen_op(s, op, ot, opreg);
        }
        break;

        /**************************/
        /* inc, dec, and other misc arith */
    case 0x40: /* inc Gv */
    case 0x41: /* inc Gv */
    case 0x42: /* inc Gv */
    case 0x43: /* inc Gv */
    case 0x44: /* inc Gv */
    case 0x45: /* inc Gv */
    case 0x46: /* inc Gv */
    case 0x47: /* inc Gv */
        ot = dflag;
        gen_inc(s, ot, OR_EAX + (b & 7), 1);
        break;
    case 0x48: /* dec Gv */
    case 0x49: /* dec Gv */
    case 0x4a: /* dec Gv */
    case 0x4b: /* dec Gv */
    case 0x4c: /* dec Gv */
    case 0x4d: /* dec Gv */
    case 0x4e: /* dec Gv */
    case 0x4f: /* dec Gv */
        ot = dflag;
        gen_inc(s, ot, OR_EAX + (b & 7), -1);
        break;
    case 0xf6: /* GRP3 */
    case 0xf7:
        ot = mo_b_d(b, dflag);

        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        op = (modrm >> 3) & 7;
        if (mod != 3) {
            if (op == 0) {
                s->rip_offset = insn_const_size(ot);
            }
            gen_lea_modrm(env, s, modrm);
            /* For those below that handle locked memory, don't load here.  */
            if (!(s->prefix & PREFIX_LOCK)
                || op != 2) {
                gen_op_ld_v(s, ot, s->T0, s->A0);
            }
        } else {
            gen_op_mov_v_reg(s, ot, s->T0, rm);
        }

        switch(op) {
        case 0: /* test */
        case 1:
            val = insn_get(env, s, ot);
            tcg_gen_movi_tl(tcg_ctx, s->T1, val);
            gen_op_testl_T0_T1_cc(s);
            set_cc_op(s, CC_OP_LOGICB + ot);
            break;
        case 2: /* not */
            if (s->prefix & PREFIX_LOCK) {
                if (mod == 3) {
                    goto illegal_op;
                }
                tcg_gen_movi_tl(tcg_ctx, s->T0, ~0);
                tcg_gen_atomic_xor_fetch_tl(tcg_ctx, s->T0, s->A0, s->T0,
                                            s->mem_index, ot | MO_LE);
            } else {
                tcg_gen_not_tl(tcg_ctx, s->T0, s->T0);
                if (mod != 3) {
                    gen_op_st_v(s, ot, s->T0, s->A0);
                } else {
                    gen_op_mov_reg_v(s, ot, rm, s->T0);
                }
            }
            break;
        case 3: /* neg */
            if (s->prefix & PREFIX_LOCK) {
                TCGLabel *label1;
                TCGv a0, t0, t1, t2;

                if (mod == 3) {
                    goto illegal_op;
                }
                a0 = tcg_temp_local_new(tcg_ctx);
                t0 = tcg_temp_local_new(tcg_ctx);
                label1 = gen_new_label(tcg_ctx);

                tcg_gen_mov_tl(tcg_ctx, a0, s->A0);
                tcg_gen_mov_tl(tcg_ctx, t0, s->T0);

                gen_set_label(tcg_ctx, label1);
                t1 = tcg_temp_new(tcg_ctx);
                t2 = tcg_temp_new(tcg_ctx);
                tcg_gen_mov_tl(tcg_ctx, t2, t0);
                tcg_gen_neg_tl(tcg_ctx, t1, t0);
                tcg_gen_atomic_cmpxchg_tl(tcg_ctx, t0, a0, t0, t1,
                                          s->mem_index, ot | MO_LE);
                tcg_temp_free(tcg_ctx, t1);
                tcg_gen_brcond_tl(tcg_ctx, TCG_COND_NE, t0, t2, label1);

                tcg_temp_free(tcg_ctx, t2);
                tcg_temp_free(tcg_ctx, a0);
                tcg_gen_mov_tl(tcg_ctx, s->T0, t0);
                tcg_temp_free(tcg_ctx, t0);
            } else {
                tcg_gen_neg_tl(tcg_ctx, s->T0, s->T0);
                if (mod != 3) {
                    gen_op_st_v(s, ot, s->T0, s->A0);
                } else {
                    gen_op_mov_reg_v(s, ot, rm, s->T0);
                }
            }
            gen_op_update_neg_cc(s);
            set_cc_op(s, CC_OP_SUBB + ot);
            break;
        case 4: /* mul */
            switch(ot) {
            case MO_8:
                gen_op_mov_v_reg(s, MO_8, s->T1, R_EAX);
                tcg_gen_ext8u_tl(tcg_ctx, s->T0, s->T0);
                tcg_gen_ext8u_tl(tcg_ctx, s->T1, s->T1);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
                gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0, 0xff00);
                set_cc_op(s, CC_OP_MULB);
                break;
            case MO_16:
                gen_op_mov_v_reg(s, MO_16, s->T1, R_EAX);
                tcg_gen_ext16u_tl(tcg_ctx, s->T0, s->T0);
                tcg_gen_ext16u_tl(tcg_ctx, s->T1, s->T1);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
                gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                tcg_gen_shri_tl(tcg_ctx, s->T0, s->T0, 16);
                gen_op_mov_reg_v(s, MO_16, R_EDX, s->T0);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0);
                set_cc_op(s, CC_OP_MULW);
                break;
            default:
            case MO_32:
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_mulu2_i32(tcg_ctx, s->tmp2_i32, s->tmp3_i32,
                                  s->tmp2_i32, s->tmp3_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EAX], s->tmp2_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EDX], s->tmp3_i32);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULL);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                tcg_gen_mulu2_i64(tcg_ctx, tcg_ctx->cpu_regs[R_EAX], tcg_ctx->cpu_regs[R_EDX],
                                  s->T0, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULQ);
                break;
#endif
            }
            break;
        case 5: /* imul */
            switch(ot) {
            case MO_8:
                gen_op_mov_v_reg(s, MO_8, s->T1, R_EAX);
                tcg_gen_ext8s_tl(tcg_ctx, s->T0, s->T0);
                tcg_gen_ext8s_tl(tcg_ctx, s->T1, s->T1);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
                gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                tcg_gen_ext8s_tl(tcg_ctx, s->tmp0, s->T0);
                tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0, s->tmp0);
                set_cc_op(s, CC_OP_MULB);
                break;
            case MO_16:
                gen_op_mov_v_reg(s, MO_16, s->T1, R_EAX);
                tcg_gen_ext16s_tl(tcg_ctx, s->T0, s->T0);
                tcg_gen_ext16s_tl(tcg_ctx, s->T1, s->T1);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
                gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                tcg_gen_ext16s_tl(tcg_ctx, s->tmp0, s->T0);
                tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0, s->tmp0);
                tcg_gen_shri_tl(tcg_ctx, s->T0, s->T0, 16);
                gen_op_mov_reg_v(s, MO_16, R_EDX, s->T0);
                set_cc_op(s, CC_OP_MULW);
                break;
            default:
            case MO_32:
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_muls2_i32(tcg_ctx, s->tmp2_i32, s->tmp3_i32,
                                  s->tmp2_i32, s->tmp3_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EAX], s->tmp2_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EDX], s->tmp3_i32);
                tcg_gen_sari_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, 31);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_sub_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, s->tmp3_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->tmp2_i32);
                set_cc_op(s, CC_OP_MULL);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                tcg_gen_muls2_i64(tcg_ctx, tcg_ctx->cpu_regs[R_EAX], tcg_ctx->cpu_regs[R_EDX],
                                  s->T0, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_sari_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_regs[R_EAX], 63);
                tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULQ);
                break;
#endif
            }
            break;
        case 6: /* div */
            switch(ot) {
            case MO_8:
                gen_helper_divb_AL(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
            case MO_16:
                gen_helper_divw_AX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
            default:
            case MO_32:
                gen_helper_divl_EAX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                gen_helper_divq_EAX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
#endif
            }
            break;
        case 7: /* idiv */
            switch(ot) {
            case MO_8:
                gen_helper_idivb_AL(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
            case MO_16:
                gen_helper_idivw_AX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
            default:
            case MO_32:
                gen_helper_idivl_EAX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                gen_helper_idivq_EAX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
#endif
            }
            break;
        default:
            goto unknown_op;
        }
        break;

    case 0xfe: /* GRP4 */
    case 0xff: /* GRP5 */
        ot = mo_b_d(b, dflag);

        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        op = (modrm >> 3) & 7;
        if (op == 7 || (op >= 2 && b == 0xfe)) {
            goto unknown_op;
        }
        if (CODE64(s)) {
            if (op == 2 || op == 4) {
                /* operand size for jumps is 64 bit */
                ot = MO_64;
            } else if (op == 3 || op == 5) {
                ot = dflag != MO_16 ? MO_32 + (rex_w == 1) : MO_16;
            } else if (op == 6) {
                /* default push size is 64 bit */
                ot = mo_pushpop(s, dflag);
            }
        }
        if (mod != 3) {
            gen_lea_modrm(env, s, modrm);
            if (op >= 2 && op != 3 && op != 5)
                gen_op_ld_v(s, ot, s->T0, s->A0);
        } else {
            gen_op_mov_v_reg(s, ot, s->T0, rm);
        }

        switch(op) {
        case 0: /* inc Ev */
            if (mod != 3)
                opreg = OR_TMP0;
            else
                opreg = rm;
            gen_inc(s, ot, opreg, 1);
            break;
        case 1: /* dec Ev */
            if (mod != 3)
                opreg = OR_TMP0;
            else
                opreg = rm;
            gen_inc(s, ot, opreg, -1);
            break;
        case 2: /* call Ev */
            /* XXX: optimize if memory (no 'and' is necessary) */
            if (dflag == MO_16) {
                tcg_gen_ext16u_tl(tcg_ctx, s->T0, s->T0);
            }
            next_eip = s->pc - s->cs_base;
            tcg_gen_movi_tl(tcg_ctx, s->T1, next_eip);
            gen_push_v(s, s->T1);
            gen_op_jmp_v(tcg_ctx, s->T0);
            gen_bnd_jmp(s);
            gen_jr(s, s->T0);
            break;
        case 3: /* lcall Ev */
            if (mod == 3) {
                goto illegal_op;
            }
            gen_op_ld_v(s, ot, s->T1, s->A0);
            gen_add_A0_im(s, 1 << ot);
            gen_op_ld_v(s, MO_16, s->T0, s->A0);
        do_lcall:
            if (s->pe && !s->vm86) {
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_lcall_protected(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32, s->T1,
                                           tcg_const_i32(tcg_ctx, dflag - 1),
                                           tcg_const_tl(tcg_ctx, s->pc - s->cs_base));
            } else {
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_lcall_real(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32, s->T1,
                                      tcg_const_i32(tcg_ctx, dflag - 1),
                                      tcg_const_i32(tcg_ctx, s->pc - s->cs_base));
            }
            tcg_gen_ld_tl(tcg_ctx, s->tmp4, tcg_ctx->cpu_env, offsetof(CPUX86State, eip));
            gen_jr(s, s->tmp4);
            break;
        case 4: /* jmp Ev */
            if (dflag == MO_16) {
                tcg_gen_ext16u_tl(tcg_ctx, s->T0, s->T0);
            }
            gen_op_jmp_v(tcg_ctx, s->T0);
            gen_bnd_jmp(s);
            gen_jr(s, s->T0);
            break;
        case 5: /* ljmp Ev */
            if (mod == 3) {
                goto illegal_op;
            }
            gen_op_ld_v(s, ot, s->T1, s->A0);
            gen_add_A0_im(s, 1 << ot);
            gen_op_ld_v(s, MO_16, s->T0, s->A0);
        do_ljmp:
            if (s->pe && !s->vm86) {
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_ljmp_protected(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32, s->T1,
                                          tcg_const_tl(tcg_ctx, s->pc - s->cs_base));
            } else {
                gen_op_movl_seg_T0_vm(s, R_CS);
                gen_op_jmp_v(tcg_ctx, s->T1);
            }
            tcg_gen_ld_tl(tcg_ctx, s->tmp4, tcg_ctx->cpu_env, offsetof(CPUX86State, eip));
            gen_jr(s, s->tmp4);
            break;
        case 6: /* push Ev */
            gen_push_v(s, s->T0);
            break;
        default:
            goto unknown_op;
        }
        break;

    case 0x84: /* test Ev, Gv */
    case 0x85:
        ot = mo_b_d(b, dflag);

        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;

        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_op_mov_v_reg(s, ot, s->T1, reg);
        gen_op_testl_T0_T1_cc(s);
        set_cc_op(s, CC_OP_LOGICB + ot);
        break;

    case 0xa8: /* test eAX, Iv */
    case 0xa9:
        ot = mo_b_d(b, dflag);
        val = insn_get(env, s, ot);

        gen_op_mov_v_reg(s, ot, s->T0, OR_EAX);
        tcg_gen_movi_tl(tcg_ctx, s->T1, val);
        gen_op_testl_T0_T1_cc(s);
        set_cc_op(s, CC_OP_LOGICB + ot);
        break;

    case 0x98: /* CWDE/CBW */
        switch (dflag) {
#ifdef TARGET_X86_64
        case MO_64:
            gen_op_mov_v_reg(s, MO_32, s->T0, R_EAX);
            tcg_gen_ext32s_tl(tcg_ctx, s->T0, s->T0);
            gen_op_mov_reg_v(s, MO_64, R_EAX, s->T0);
            break;
#endif
        case MO_32:
            gen_op_mov_v_reg(s, MO_16, s->T0, R_EAX);
            tcg_gen_ext16s_tl(tcg_ctx, s->T0, s->T0);
            gen_op_mov_reg_v(s, MO_32, R_EAX, s->T0);
            break;
        case MO_16:
            gen_op_mov_v_reg(s, MO_8, s->T0, R_EAX);
            tcg_gen_ext8s_tl(tcg_ctx, s->T0, s->T0);
            gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
            break;
        default:
            tcg_abort();
        }
        break;
    case 0x99: /* CDQ/CWD */
        switch (dflag) {
#ifdef TARGET_X86_64
        case MO_64:
            gen_op_mov_v_reg(s, MO_64, s->T0, R_EAX);
            tcg_gen_sari_tl(tcg_ctx, s->T0, s->T0, 63);
            gen_op_mov_reg_v(s, MO_64, R_EDX, s->T0);
            break;
#endif
        case MO_32:
            gen_op_mov_v_reg(s, MO_32, s->T0, R_EAX);
            tcg_gen_ext32s_tl(tcg_ctx, s->T0, s->T0);
            tcg_gen_sari_tl(tcg_ctx, s->T0, s->T0, 31);
            gen_op_mov_reg_v(s, MO_32, R_EDX, s->T0);
            break;
        case MO_16:
            gen_op_mov_v_reg(s, MO_16, s->T0, R_EAX);
            tcg_gen_ext16s_tl(tcg_ctx, s->T0, s->T0);
            tcg_gen_sari_tl(tcg_ctx, s->T0, s->T0, 15);
            gen_op_mov_reg_v(s, MO_16, R_EDX, s->T0);
            break;
        default:
            tcg_abort();
        }
        break;
    case 0x1af: /* imul Gv, Ev */
    case 0x69: /* imul Gv, Ev, I */
    case 0x6b:
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        if (b == 0x69)
            s->rip_offset = insn_const_size(ot);
        else if (b == 0x6b)
            s->rip_offset = 1;
        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        if (b == 0x69) {
            val = insn_get(env, s, ot);
            tcg_gen_movi_tl(tcg_ctx, s->T1, val);
        } else if (b == 0x6b) {
            val = (int8_t)insn_get(env, s, MO_8);
            tcg_gen_movi_tl(tcg_ctx, s->T1, val);
        } else {
            gen_op_mov_v_reg(s, ot, s->T1, reg);
        }
        switch (ot) {
#ifdef TARGET_X86_64
        case MO_64:
            tcg_gen_muls2_i64(tcg_ctx, tcg_ctx->cpu_regs[reg], s->T1, s->T0, s->T1);
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_regs[reg]);
            tcg_gen_sari_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_dst, 63);
            tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, s->T1);
            break;
#endif
        case MO_32:
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, s->T1);
            tcg_gen_muls2_i32(tcg_ctx, s->tmp2_i32, s->tmp3_i32,
                              s->tmp2_i32, s->tmp3_i32);
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], s->tmp2_i32);
            tcg_gen_sari_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, 31);
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_regs[reg]);
            tcg_gen_sub_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, s->tmp3_i32);
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->tmp2_i32);
            break;
        default:
            tcg_gen_ext16s_tl(tcg_ctx, s->T0, s->T0);
            tcg_gen_ext16s_tl(tcg_ctx, s->T1, s->T1);
            /* XXX: use 32 bit mul which could be faster */
            tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
            tcg_gen_ext16s_tl(tcg_ctx, s->tmp0, s->T0);
            tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0, s->tmp0);
            gen_op_mov_reg_v(s, ot, reg, s->T0);
            break;
        }
        set_cc_op(s, CC_OP_MULB + ot);
        break;
    case 0x1c0:
    case 0x1c1: /* xadd Ev, Gv */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        gen_op_mov_v_reg(s, ot, s->T0, reg);
        if (mod == 3) {
            rm = (modrm & 7) | REX_B(s);
            gen_op_mov_v_reg(s, ot, s->T1, rm);
            tcg_gen_add_tl(tcg_ctx, s->T0, s->T0, s->T1);
            gen_op_mov_reg_v(s, ot, reg, s->T1);
            gen_op_mov_reg_v(s, ot, rm, s->T0);
        } else {
            gen_lea_modrm(env, s, modrm);
            if (s->prefix & PREFIX_LOCK) {
                tcg_gen_atomic_fetch_add_tl(tcg_ctx, s->T1, s->A0, s->T0,
                                            s->mem_index, ot | MO_LE);
                tcg_gen_add_tl(tcg_ctx, s->T0, s->T0, s->T1);
            } else {
                gen_op_ld_v(s, ot, s->T1, s->A0);
                tcg_gen_add_tl(tcg_ctx, s->T0, s->T0, s->T1);
                gen_op_st_v(s, ot, s->T0, s->A0);
            }
            gen_op_mov_reg_v(s, ot, reg, s->T1);
        }
        gen_op_update2_cc(s);
        set_cc_op(s, CC_OP_ADDB + ot);
        break;
    case 0x1b0:
    case 0x1b1: /* cmpxchg Ev, Gv */
        {
            TCGv oldv, newv, cmpv, dest;

            ot = mo_b_d(b, dflag);
            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            oldv = tcg_temp_new(tcg_ctx);
            newv = tcg_temp_new(tcg_ctx);
            cmpv = tcg_temp_new(tcg_ctx);
            gen_op_mov_v_reg(s, ot, newv, reg);
            tcg_gen_mov_tl(tcg_ctx, cmpv, tcg_ctx->cpu_regs[R_EAX]);
            gen_extu(tcg_ctx, ot, cmpv);

            if (s->prefix & PREFIX_LOCK) {
                if (mod == 3) {
                    goto illegal_op;
                }
                gen_lea_modrm(env, s, modrm);
                tcg_gen_atomic_cmpxchg_tl(tcg_ctx, oldv, s->A0, cmpv, newv,
                                          s->mem_index, ot | MO_LE);
            } else {
                if (mod == 3) {
                    rm = (modrm & 7) | REX_B(s);
                    gen_op_mov_v_reg(s, ot, oldv, rm);
                    gen_extu(tcg_ctx, ot, oldv);
                    dest = gen_op_deposit_reg_v(s, ot, rm, newv, newv);
                    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, dest, oldv,
                                       cmpv, newv, dest);
                } else {
                    gen_lea_modrm(env, s, modrm);
                    gen_op_ld_v(s, ot, oldv, s->A0);
                    /* Perform an unconditional store cycle like physical cpu;
                       must be before changing accumulator to ensure
                       idempotency if the store faults and the instruction
                       is restarted */
                    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, newv, oldv,
                                       cmpv, newv, oldv);
                    gen_op_st_v(s, ot, newv, s->A0);
                }
            }
            dest = gen_op_deposit_reg_v(s, ot, R_EAX, newv, oldv);
            tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, dest, oldv, cmpv,
                               dest, newv);
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, oldv);
            tcg_gen_mov_tl(tcg_ctx, s->cc_srcT, cmpv);
            tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, cmpv, oldv);
            set_cc_op(s, CC_OP_SUBB + ot);
            tcg_temp_free(tcg_ctx, oldv);
            tcg_temp_free(tcg_ctx, newv);
            tcg_temp_free(tcg_ctx, cmpv);
        }
        break;
    case 0x1c7: /* cmpxchg8b */
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        switch ((modrm >> 3) & 7) {
        case 1: /* CMPXCHG8, CMPXCHG16 */
            if (mod == 3) {
                goto illegal_op;
            }
#ifdef TARGET_X86_64
            if (dflag == MO_64) {
                if (!(s->cpuid_ext_features & CPUID_EXT_CX16)) {
                    goto illegal_op;
                }
                gen_lea_modrm(env, s, modrm);
                if ((s->prefix & PREFIX_LOCK) &&
                    (tb_cflags(s->base.tb) & CF_PARALLEL)) {
                    gen_helper_cmpxchg16b(tcg_ctx, tcg_ctx->cpu_env, s->A0);
                } else {
                    gen_helper_cmpxchg16b_unlocked(tcg_ctx, tcg_ctx->cpu_env, s->A0);
                }
                set_cc_op(s, CC_OP_EFLAGS);
                break;
            }
#endif        
            if (!(s->cpuid_features & CPUID_CX8)) {
                goto illegal_op;
            }
            gen_lea_modrm(env, s, modrm);
            if ((s->prefix & PREFIX_LOCK) &&
                (tb_cflags(s->base.tb) & CF_PARALLEL)) {
                gen_helper_cmpxchg8b(tcg_ctx, tcg_ctx->cpu_env, s->A0);
            } else {
                gen_helper_cmpxchg8b_unlocked(tcg_ctx, tcg_ctx->cpu_env, s->A0);
            }
            set_cc_op(s, CC_OP_EFLAGS);
            break;

        case 7: /* RDSEED or RDPID */
            if (s->prefix & PREFIX_REPZ) {
                if (mod != 3 ||
                    (s->prefix & (PREFIX_LOCK | PREFIX_REPNZ)) ||
                    !(s->cpuid_7_0_ecx_features & CPUID_7_0_ECX_RDPID)) {
                    goto illegal_op;
                }
                rm = (modrm & 7) | REX_B(s);
                tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                  offsetof(CPUX86State, tsc_aux));
                gen_op_mov_reg_v(s, MO_32, rm, s->T0);
                break;
            }
            if (mod != 3 ||
                (s->prefix & (PREFIX_LOCK | PREFIX_REPNZ)) ||
                !(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_RDSEED)) {
                goto illegal_op;
            }
            goto do_random;

        case 6: /* RDRAND */
            if (mod != 3 ||
                (s->prefix & (PREFIX_LOCK | PREFIX_REPZ | PREFIX_REPNZ)) ||
                !(s->cpuid_ext_features & CPUID_EXT_RDRAND)) {
                goto illegal_op;
            }
        do_random:
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_io_start(tcg_ctx);
            }
            gen_helper_rdrand(tcg_ctx, s->T0, tcg_ctx->cpu_env);
            rm = (modrm & 7) | REX_B(s);
            gen_op_mov_reg_v(s, dflag, rm, s->T0);
            set_cc_op(s, CC_OP_EFLAGS);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_jmp(s, s->pc - s->cs_base);
            }
            break;

        default:
            goto illegal_op;
        }
        break;

        /**************************/
        /* push/pop */
    case 0x50: /* push */
    case 0x51: /* push */
    case 0x52: /* push */
    case 0x53: /* push */
    case 0x54: /* push */
    case 0x55: /* push */
    case 0x56: /* push */
    case 0x57: /* push */
        gen_op_mov_v_reg(s, MO_32, s->T0, (b & 7) | REX_B(s));
        gen_push_v(s, s->T0);
        break;
    case 0x58: /* pop */
    case 0x59: /* pop */
    case 0x5a: /* pop */
    case 0x5b: /* pop */
    case 0x5c: /* pop */
    case 0x5d: /* pop */
    case 0x5e: /* pop */
    case 0x5f: /* pop */
        ot = gen_pop_T0(s);
        /* NOTE: order is important for pop %sp */
        gen_pop_update(s, ot);
        gen_op_mov_reg_v(s, ot, (b & 7) | REX_B(s), s->T0);
        break;
    case 0x60: /* pusha */
        if (CODE64(s))
            goto illegal_op;
        gen_pusha(s);
        break;
    case 0x61: /* popa */
        if (CODE64(s))
            goto illegal_op;
        gen_popa(s);
        break;
    case 0x68: /* push Iv */
    case 0x6a:
        ot = mo_pushpop(s, dflag);
        if (b == 0x68)
            val = insn_get(env, s, ot);
        else
            val = (int8_t)insn_get(env, s, MO_8);
        tcg_gen_movi_tl(tcg_ctx, s->T0, val);
        gen_push_v(s, s->T0);
        break;
    case 0x8f: /* GRP1a */
        modrm = x86_ldub_code(env, s);
        if ((modrm >> 3) & 7) {
            goto unknown_op;
        }
        mod = (modrm >> 6) & 3;
        ot = gen_pop_T0(s);
        if (mod == 3) {
            /* NOTE: order is important for pop %sp */
            gen_pop_update(s, ot);
            rm = (modrm & 7) | REX_B(s);
            gen_op_mov_reg_v(s, ot, rm, s->T0);
        } else {
            /* NOTE: order is important too for MMU exceptions */
            s->popl_esp_hack = 1 << ot;
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
            s->popl_esp_hack = 0;
            gen_pop_update(s, ot);
        }
        break;
    case 0xc8: /* enter */
        {
            int level;
            val = x86_lduw_code(env, s);
            level = x86_ldub_code(env, s);
            gen_enter(s, val, level);
        }
        break;
    case 0xc9: /* leave */
        gen_leave(s);
        break;
    case 0x06: /* push es */
    case 0x0e: /* push cs */
    case 0x16: /* push ss */
    case 0x1e: /* push ds */
        if (CODE64(s))
            goto illegal_op;
        gen_op_movl_T0_seg(s, b >> 3);
        gen_push_v(s, s->T0);
        break;
    case 0x1a0: /* push fs */
    case 0x1a8: /* push gs */
        gen_op_movl_T0_seg(s, (b >> 3) & 7);
        gen_push_v(s, s->T0);
        break;
    case 0x07: /* pop es */
    case 0x17: /* pop ss */
    case 0x1f: /* pop ds */
        if (CODE64(s))
            goto illegal_op;
        reg = b >> 3;
        ot = gen_pop_T0(s);
        gen_movl_seg_T0(s, reg);
        gen_pop_update(s, ot);
        /* Note that reg == R_SS in gen_movl_seg_T0 always sets is_jmp.  */
        if (s->base.is_jmp) {
            gen_jmp_im(s, s->pc - s->cs_base);
            if (reg == R_SS) {
                s->tf = 0;
                gen_eob_inhibit_irq(s, true);
            } else {
                gen_eob(s);
            }
        }
        break;
    case 0x1a1: /* pop fs */
    case 0x1a9: /* pop gs */
        ot = gen_pop_T0(s);
        gen_movl_seg_T0(s, (b >> 3) & 7);
        gen_pop_update(s, ot);
        if (s->base.is_jmp) {
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
        }
        break;

        /**************************/
        /* mov */
    case 0x88:
    case 0x89: /* mov Gv, Ev */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;

        /* generate a generic store */
        gen_ldst_modrm(env, s, modrm, ot, reg, 1);
        break;
    case 0xc6:
    case 0xc7: /* mov Ev, Iv */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        reg = (modrm >> 3) & 7;
        if (reg != 0) {
            goto illegal_op;
        }
        if (mod != 3) {
            s->rip_offset = insn_const_size(ot);
            gen_lea_modrm(env, s, modrm);
        }
        val = insn_get(env, s, ot);
        tcg_gen_movi_tl(tcg_ctx, s->T0, val);
        if (mod != 3) {
            gen_op_st_v(s, ot, s->T0, s->A0);
        } else {
            gen_op_mov_reg_v(s, ot, (modrm & 7) | REX_B(s), s->T0);
        }
        break;
    case 0x8a:
    case 0x8b: /* mov Ev, Gv */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;

        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_op_mov_reg_v(s, ot, reg, s->T0);
        break;
    case 0x8e: /* mov seg, Gv */
        modrm = x86_ldub_code(env, s);
        reg = (modrm >> 3) & 7;
        if (reg >= 6 || reg == R_CS)
            goto illegal_op;
        gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
        gen_movl_seg_T0(s, reg);
        /* Note that reg == R_SS in gen_movl_seg_T0 always sets is_jmp.  */
        if (s->base.is_jmp) {
            gen_jmp_im(s, s->pc - s->cs_base);
            if (reg == R_SS) {
                s->tf = 0;
                gen_eob_inhibit_irq(s, true);
            } else {
                gen_eob(s);
            }
        }
        break;
    case 0x8c: /* mov Gv, seg */
        modrm = x86_ldub_code(env, s);
        reg = (modrm >> 3) & 7;
        mod = (modrm >> 6) & 3;
        if (reg >= 6)
            goto illegal_op;
        gen_op_movl_T0_seg(s, reg);
        ot = mod == 3 ? dflag : MO_16;
        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
        break;

    case 0x1b6: /* movzbS Gv, Eb */
    case 0x1b7: /* movzwS Gv, Eb */
    case 0x1be: /* movsbS Gv, Eb */
    case 0x1bf: /* movswS Gv, Eb */
        {
            MemOp d_ot;
            MemOp s_ot;

            /* d_ot is the size of destination */
            d_ot = dflag;
            /* ot is the size of source */
            ot = (b & 1) + MO_8;
            /* s_ot is the sign+size of source */
            s_ot = b & 8 ? MO_SIGN | ot : ot;

            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            rm = (modrm & 7) | REX_B(s);

            if (mod == 3) {
                if (s_ot == MO_SB && byte_reg_is_xH(s, rm)) {
                    tcg_gen_sextract_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[rm - 4], 8, 8);
                } else {
                    gen_op_mov_v_reg(s, ot, s->T0, rm);
                    switch (s_ot) {
                    case MO_UB:
                        tcg_gen_ext8u_tl(tcg_ctx, s->T0, s->T0);
                        break;
                    case MO_SB:
                        tcg_gen_ext8s_tl(tcg_ctx, s->T0, s->T0);
                        break;
                    case MO_UW:
                        tcg_gen_ext16u_tl(tcg_ctx, s->T0, s->T0);
                        break;
                    default:
                    case MO_SW:
                        tcg_gen_ext16s_tl(tcg_ctx, s->T0, s->T0);
                        break;
                    }
                }
                gen_op_mov_reg_v(s, d_ot, reg, s->T0);
            } else {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, s_ot, s->T0, s->A0);
                gen_op_mov_reg_v(s, d_ot, reg, s->T0);
            }
        }
        break;

    case 0x8d: /* lea */
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        reg = ((modrm >> 3) & 7) | rex_r;
        {
            AddressParts a = gen_lea_modrm_0(env, s, modrm);
            TCGv ea = gen_lea_modrm_1(s, a);
            gen_lea_v_seg(s, s->aflag, ea, -1, -1);
            gen_op_mov_reg_v(s, dflag, reg, s->A0);
        }
        break;

    case 0xa0: /* mov EAX, Ov */
    case 0xa1:
    case 0xa2: /* mov Ov, EAX */
    case 0xa3:
        {
            target_ulong offset_addr;

            ot = mo_b_d(b, dflag);
            switch (s->aflag) {
#ifdef TARGET_X86_64
            case MO_64:
                offset_addr = x86_ldq_code(env, s);
                break;
#endif
            default:
                offset_addr = insn_get(env, s, s->aflag);
                break;
            }
            tcg_gen_movi_tl(tcg_ctx, s->A0, offset_addr);
            gen_add_A0_ds_seg(s);
            if ((b & 2) == 0) {
                gen_op_ld_v(s, ot, s->T0, s->A0);
                gen_op_mov_reg_v(s, ot, R_EAX, s->T0);
            } else {
                gen_op_mov_v_reg(s, ot, s->T0, R_EAX);
                gen_op_st_v(s, ot, s->T0, s->A0);
            }
        }
        break;
    case 0xd7: /* xlat */
        tcg_gen_mov_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_EBX]);
        tcg_gen_ext8u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[R_EAX]);
        tcg_gen_add_tl(tcg_ctx, s->A0, s->A0, s->T0);
        gen_extu(tcg_ctx, s->aflag, s->A0);
        gen_add_A0_ds_seg(s);
        gen_op_ld_v(s, MO_8, s->T0, s->A0);
        gen_op_mov_reg_v(s, MO_8, R_EAX, s->T0);
        break;
    case 0xb0: /* mov R, Ib */
    case 0xb1: /* mov R, Ib */
    case 0xb2: /* mov R, Ib */
    case 0xb3: /* mov R, Ib */
    case 0xb4: /* mov R, Ib */
    case 0xb5: /* mov R, Ib */
    case 0xb6: /* mov R, Ib */
    case 0xb7: /* mov R, Ib */
        val = insn_get(env, s, MO_8);
        tcg_gen_movi_tl(tcg_ctx, s->T0, val);
        gen_op_mov_reg_v(s, MO_8, (b & 7) | REX_B(s), s->T0);
        break;
    case 0xb8: /* mov R, Iv */
    case 0xb9: /* mov R, Iv */
    case 0xba: /* mov R, Iv */
    case 0xbb: /* mov R, Iv */
    case 0xbc: /* mov R, Iv */
    case 0xbd: /* mov R, Iv */
    case 0xbe: /* mov R, Iv */
    case 0xbf: /* mov R, Iv */
#ifdef TARGET_X86_64
        if (dflag == MO_64) {
            uint64_t tmp;
            /* 64 bit case */
            tmp = x86_ldq_code(env, s);
            reg = (b & 7) | REX_B(s);
            tcg_gen_movi_tl(tcg_ctx, s->T0, tmp);
            gen_op_mov_reg_v(s, MO_64, reg, s->T0);
        } else
#endif
        {
            ot = dflag;
            val = insn_get(env, s, ot);
            reg = (b & 7) | REX_B(s);
            tcg_gen_movi_tl(tcg_ctx, s->T0, val);
            gen_op_mov_reg_v(s, ot, reg, s->T0);
        }
        break;

    case 0x91: /* xchg R, EAX */
    case 0x92: /* xchg R, EAX */
    case 0x93: /* xchg R, EAX */
    case 0x94: /* xchg R, EAX */
    case 0x95: /* xchg R, EAX */
    case 0x96: /* xchg R, EAX */
    case 0x97: /* xchg R, EAX */
    do_xchg_reg_eax:
        ot = dflag;
        reg = (b & 7) | REX_B(s);
        rm = R_EAX;
        goto do_xchg_reg;
    case 0x86:
    case 0x87: /* xchg Ev, Gv */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        if (mod == 3) {
            rm = (modrm & 7) | REX_B(s);
        do_xchg_reg:
            gen_op_mov_v_reg(s, ot, s->T0, reg);
            gen_op_mov_v_reg(s, ot, s->T1, rm);
            gen_op_mov_reg_v(s, ot, rm, s->T0);
            gen_op_mov_reg_v(s, ot, reg, s->T1);
        } else {
            gen_lea_modrm(env, s, modrm);
            gen_op_mov_v_reg(s, ot, s->T0, reg);
            /* for xchg, lock is implicit */
            tcg_gen_atomic_xchg_tl(tcg_ctx, s->T1, s->A0, s->T0,
                                   s->mem_index, ot | MO_LE);
            gen_op_mov_reg_v(s, ot, reg, s->T1);
        }
        break;
    case 0xc4: /* les Gv */
        /* In CODE64 this is VEX3; see above.  */
        op = R_ES;
        goto do_lxx;
    case 0xc5: /* lds Gv */
        /* In CODE64 this is VEX2; see above.  */
        op = R_DS;
        goto do_lxx;
    case 0x1b2: /* lss Gv */
        op = R_SS;
        goto do_lxx;
    case 0x1b4: /* lfs Gv */
        op = R_FS;
        goto do_lxx;
    case 0x1b5: /* lgs Gv */
        op = R_GS;
    do_lxx:
        ot = dflag != MO_16 ? MO_32 : MO_16;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        gen_lea_modrm(env, s, modrm);
        gen_op_ld_v(s, ot, s->T1, s->A0);
        gen_add_A0_im(s, 1 << ot);
        /* load the segment first to handle exceptions properly */
        gen_op_ld_v(s, MO_16, s->T0, s->A0);
        gen_movl_seg_T0(s, op);
        /* then put the data */
        gen_op_mov_reg_v(s, ot, reg, s->T1);
        if (s->base.is_jmp) {
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
        }
        break;

        /************************/
        /* shifts */
    case 0xc0:
    case 0xc1:
        /* shift Ev,Ib */
        shift = 2;
    grp2_label:
        {
            ot = mo_b_d(b, dflag);
            modrm = x86_ldub_code(env, s);
            mod = (modrm >> 6) & 3;
            op = (modrm >> 3) & 7;

            if (mod != 3) {
                if (shift == 2) {
                    s->rip_offset = 1;
                }
                gen_lea_modrm(env, s, modrm);
                opreg = OR_TMP0;
            } else {
                opreg = (modrm & 7) | REX_B(s);
            }

            /* simpler op */
            if (shift == 0) {
                gen_shift(s, op, ot, opreg, OR_ECX);
            } else {
                if (shift == 2) {
                    shift = x86_ldub_code(env, s);
                }
                gen_shifti(s, op, ot, opreg, shift);
            }
        }
        break;
    case 0xd0:
    case 0xd1:
        /* shift Ev,1 */
        shift = 1;
        goto grp2_label;
    case 0xd2:
    case 0xd3:
        /* shift Ev,cl */
        shift = 0;
        goto grp2_label;

    case 0x1a4: /* shld imm */
        op = 0;
        shift = 1;
        goto do_shiftd;
    case 0x1a5: /* shld cl */
        op = 0;
        shift = 0;
        goto do_shiftd;
    case 0x1ac: /* shrd imm */
        op = 1;
        shift = 1;
        goto do_shiftd;
    case 0x1ad: /* shrd cl */
        op = 1;
        shift = 0;
    do_shiftd:
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        reg = ((modrm >> 3) & 7) | rex_r;
        if (mod != 3) {
            if (shift) {
                s->rip_offset = 1;
            }
            gen_lea_modrm(env, s, modrm);
            opreg = OR_TMP0;
        } else {
            opreg = rm;
        }
        gen_op_mov_v_reg(s, ot, s->T1, reg);

        if (shift) {
            TCGv imm = tcg_const_tl(tcg_ctx, x86_ldub_code(env, s));
            gen_shiftd_rm_T1(s, ot, opreg, op, imm);
            tcg_temp_free(tcg_ctx, imm);
        } else {
            gen_shiftd_rm_T1(s, ot, opreg, op, tcg_ctx->cpu_regs[R_ECX]);
        }
        break;

        /************************/
        /* floats */
    case 0xd8:
    case 0xd9:
    case 0xda:
    case 0xdb:
    case 0xdc:
    case 0xdd:
    case 0xde:
    case 0xdf:
        {
            bool update_fip = true;

            if (s->flags & (HF_EM_MASK | HF_TS_MASK)) {
                /* if CR0.EM or CR0.TS are set, generate an FPU exception */
                /* XXX: what to do if illegal op ? */
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            modrm = x86_ldub_code(env, s);
            mod = (modrm >> 6) & 3;
            rm = modrm & 7;
            op = ((b & 7) << 3) | ((modrm >> 3) & 7);
            if (mod != 3) {
                /* memory op */
                AddressParts a = gen_lea_modrm_0(env, s, modrm);
                TCGv ea = gen_lea_modrm_1(s, a);
                TCGv last_addr = tcg_temp_new(tcg_ctx);
                bool update_fdp = true;

                tcg_gen_mov_tl(tcg_ctx, last_addr, ea);
                gen_lea_v_seg(s, s->aflag, ea, a.def_seg, s->override);
                switch(op) {
                case 0x00: /* fxxxs */
                case 0x01: /* fxxxs */
                case 0x02: /* fxxxs */
                case 0x03: /* fxxxs */
                case 0x04: /* fxxxs */
                case 0x05: /* fxxxs */
                case 0x06: /* fxxxs */
                case 0x07: /* fxxxs */

                case 0x10: /* fixxxl */
                case 0x11: /* fixxxl */
                case 0x12: /* fixxxl */
                case 0x13: /* fixxxl */
                case 0x14: /* fixxxl */
                case 0x15: /* fixxxl */
                case 0x16: /* fixxxl */
                case 0x17: /* fixxxl */

                case 0x20: /* fxxxl */
                case 0x21: /* fxxxl */
                case 0x22: /* fxxxl */
                case 0x23: /* fxxxl */
                case 0x24: /* fxxxl */
                case 0x25: /* fxxxl */
                case 0x26: /* fxxxl */
                case 0x27: /* fxxxl */

                case 0x30: /* fixxx */
                case 0x31: /* fixxx */
                case 0x32: /* fixxx */
                case 0x33: /* fixxx */
                case 0x34: /* fixxx */
                case 0x35: /* fixxx */
                case 0x36: /* fixxx */
                case 0x37: /* fixxx */
                    {
                        int op1;
                        op1 = op & 7;

                        switch(op >> 4) {
                        case 0:
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            gen_helper_flds_FT0(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                            break;
                        case 1:
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            gen_helper_fildl_FT0(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                            break;
                        case 2:
                            tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                            gen_helper_fldl_FT0(tcg_ctx, tcg_ctx->cpu_env, s->tmp1_i64);
                            break;
                        case 3:
                        default:
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LESW);
                            gen_helper_fildl_FT0(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                            break;
                        }

                        gen_helper_fp_arith_ST0_FT0(tcg_ctx, op1);
                        if (op1 == 3) {
                            /* fcomp needs pop */
                            gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        }
                    }
                    break;
                case 0x08: /* flds */
                case 0x0a: /* fsts */
                case 0x0b: /* fstps */

                case 0x18: /* fildl, fisttpl, fistl, fistpl */
                case 0x19: /* fildl, fisttpl, fistl, fistpl */
                case 0x1a: /* fildl, fisttpl, fistl, fistpl */
                case 0x1b: /* fildl, fisttpl, fistl, fistpl */

                case 0x28: /* fldl, fisttpll, fstl, fstpl */
                case 0x29: /* fldl, fisttpll, fstl, fstpl */
                case 0x2a: /* fldl, fisttpll, fstl, fstpl */
                case 0x2b: /* fldl, fisttpll, fstl, fstpl */

                case 0x38: /* filds, fisttps, fists, fistps */
                case 0x39: /* filds, fisttps, fists, fistps */
                case 0x3a: /* filds, fisttps, fists, fistps */
                case 0x3b: /* filds, fisttps, fists, fistps */
                    switch(op & 7) {
                    case 0:
                        switch(op >> 4) {
                        case 0:
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            gen_helper_flds_ST0(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                            break;
                        case 1:
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            gen_helper_fildl_ST0(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                            break;
                        case 2:
                            tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                            gen_helper_fldl_ST0(tcg_ctx, tcg_ctx->cpu_env, s->tmp1_i64);
                            break;
                        case 3:
                        default:
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LESW);
                            gen_helper_fildl_ST0(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                            break;
                        }
                        break;
                    case 1:
                        /* XXX: the corresponding CPUID bit must be tested ! */
                        switch(op >> 4) {
                        case 1:
                            gen_helper_fisttl_ST0(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            break;
                        case 2:
                            gen_helper_fisttll_ST0(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                            break;
                        case 3:
                        default:
                            gen_helper_fistt_ST0(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUW);
                            break;
                        }
                        gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    default:
                        switch(op >> 4) {
                        case 0:
                            gen_helper_fsts_ST0(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            break;
                        case 1:
                            gen_helper_fistl_ST0(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            break;
                        case 2:
                            gen_helper_fstl_ST0(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                            break;
                        case 3:
                        default:
                            gen_helper_fist_ST0(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUW);
                            break;
                        }
                        if ((op & 7) == 3)
                            gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    }
                    break;
                case 0x0c: /* fldenv mem */
                    gen_helper_fldenv(tcg_ctx, tcg_ctx->cpu_env, s->A0, tcg_const_i32(tcg_ctx, dflag - 1));
                    update_fip = update_fdp = false;
                    break;
                case 0x0d: /* fldcw mem */
                    tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUW);
                    gen_helper_fldcw(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                    update_fip = update_fdp = false;
                    break;
                case 0x0e: /* fnstenv mem */
                    gen_helper_fstenv(tcg_ctx, tcg_ctx->cpu_env, s->A0, tcg_const_i32(tcg_ctx, dflag - 1));
                    update_fip = update_fdp = false;
                    break;
                case 0x0f: /* fnstcw mem */
                    gen_helper_fnstcw(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                    tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUW);
                    update_fip = update_fdp = false;
                    break;
                case 0x1d: /* fldt mem */
                    gen_helper_fldt_ST0(tcg_ctx, tcg_ctx->cpu_env, s->A0);
                    break;
                case 0x1f: /* fstpt mem */
                    gen_helper_fstt_ST0(tcg_ctx, tcg_ctx->cpu_env, s->A0);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x2c: /* frstor mem */
                    gen_helper_frstor(tcg_ctx, tcg_ctx->cpu_env, s->A0, tcg_const_i32(tcg_ctx, dflag - 1));
                    update_fip = update_fdp = false;
                    break;
                case 0x2e: /* fnsave mem */
                    gen_helper_fsave(tcg_ctx, tcg_ctx->cpu_env, s->A0, tcg_const_i32(tcg_ctx, dflag - 1));
                    update_fip = update_fdp = false;
                    break;
                case 0x2f: /* fnstsw mem */
                    gen_helper_fnstsw(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                    tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUW);
                    update_fip = update_fdp = false;
                    break;
                case 0x3c: /* fbld */
                    gen_helper_fbld_ST0(tcg_ctx, tcg_ctx->cpu_env, s->A0);
                    break;
                case 0x3e: /* fbstp */
                    gen_helper_fbst_ST0(tcg_ctx, tcg_ctx->cpu_env, s->A0);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x3d: /* fildll */
                    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0, s->mem_index, MO_LEQ);
                    gen_helper_fildll_ST0(tcg_ctx, tcg_ctx->cpu_env, s->tmp1_i64);
                    break;
                case 0x3f: /* fistpll */
                    gen_helper_fistll_ST0(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env);
                    tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0, s->mem_index, MO_LEQ);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                default:
                    goto unknown_op;
                }

                if (update_fdp) {
                    int last_seg = s->override >= 0 ? s->override : a.def_seg;

                    tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                    offsetof(CPUX86State,
                                            segs[last_seg].selector));
                    tcg_gen_st16_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                        offsetof(CPUX86State, fpds));
                    tcg_gen_st_tl(tcg_ctx, last_addr, tcg_ctx->cpu_env,
                                    offsetof(CPUX86State, fpdp));
                }
                tcg_temp_free(tcg_ctx, last_addr);
            } else {
                /* register float ops */
                opreg = rm;

                switch(op) {
                case 0x08: /* fld sti */
                    gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                    gen_helper_fmov_ST0_STN(tcg_ctx, tcg_ctx->cpu_env,
                                            tcg_const_i32(tcg_ctx, (opreg + 1) & 7));
                    break;
                case 0x09: /* fxchg sti */
                case 0x29: /* fxchg4 sti, undocumented op */
                case 0x39: /* fxchg7 sti, undocumented op */
                    gen_helper_fxchg_ST0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    break;
                case 0x0a: /* grp d9/2 */
                    switch(rm) {
                    case 0: /* fnop */
                        /* check exceptions (FreeBSD FPU probe) */
                        gen_helper_fwait(tcg_ctx, tcg_ctx->cpu_env);
                        update_fip = false;
                        break;
                    default:
                        goto unknown_op;
                    }
                    break;
                case 0x0c: /* grp d9/4 */
                    switch(rm) {
                    case 0: /* fchs */
                        gen_helper_fchs_ST0(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 1: /* fabs */
                        gen_helper_fabs_ST0(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 4: /* ftst */
                        gen_helper_fldz_FT0(tcg_ctx, tcg_ctx->cpu_env);
                        gen_helper_fcom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 5: /* fxam */
                        gen_helper_fxam_ST0(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    default:
                        goto unknown_op;
                    }
                    break;
                case 0x0d: /* grp d9/5 */
                    {
                        switch(rm) {
                        case 0:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fld1_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        case 1:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fldl2t_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        case 2:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fldl2e_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        case 3:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fldpi_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        case 4:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fldlg2_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        case 5:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fldln2_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        case 6:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fldz_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        default:
                            goto unknown_op;
                        }
                    }
                    break;
                case 0x0e: /* grp d9/6 */
                    switch(rm) {
                    case 0: /* f2xm1 */
                        gen_helper_f2xm1(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 1: /* fyl2x */
                        gen_helper_fyl2x(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 2: /* fptan */
                        gen_helper_fptan(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 3: /* fpatan */
                        gen_helper_fpatan(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 4: /* fxtract */
                        gen_helper_fxtract(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 5: /* fprem1 */
                        gen_helper_fprem1(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 6: /* fdecstp */
                        gen_helper_fdecstp(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    default:
                    case 7: /* fincstp */
                        gen_helper_fincstp(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    }
                    break;
                case 0x0f: /* grp d9/7 */
                    switch(rm) {
                    case 0: /* fprem */
                        gen_helper_fprem(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 1: /* fyl2xp1 */
                        gen_helper_fyl2xp1(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 2: /* fsqrt */
                        gen_helper_fsqrt(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 3: /* fsincos */
                        gen_helper_fsincos(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 5: /* fscale */
                        gen_helper_fscale(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 4: /* frndint */
                        gen_helper_frndint(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 6: /* fsin */
                        gen_helper_fsin(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    default:
                    case 7: /* fcos */
                        gen_helper_fcos(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    }
                    break;
                case 0x00: case 0x01:
                case 0x04: /* fxxx st, sti */
                case 0x05: /* fxxx st, sti */
                case 0x06: /* fxxx st, sti */
                case 0x07: /* fxxx st, sti */

                case 0x20: case 0x21:
                case 0x24: /* fxxx sti, st */
                case 0x25: /* fxxx sti, st */
                case 0x26: /* fxxx sti, st */
                case 0x27: /* fxxx sti, st */

                case 0x30: case 0x31:
                case 0x34: /* fxxxp sti, st */
                case 0x35: /* fxxxp sti, st */
                case 0x36: /* fxxxp sti, st */
                case 0x37: /* fxxxp sti, st */
                    {
                        int op1;

                        op1 = op & 7;
                        if (op >= 0x20) {
                            gen_helper_fp_arith_STN_ST0(tcg_ctx, op1, opreg);
                            if (op >= 0x30)
                                gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        } else {
                            gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                            gen_helper_fp_arith_ST0_FT0(tcg_ctx, op1);
                        }
                    }
                    break;
                case 0x02: /* fcom */
                case 0x22: /* fcom2, undocumented op */
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fcom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x03: /* fcomp */
                case 0x23: /* fcomp3, undocumented op */
                case 0x32: /* fcomp5, undocumented op */
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fcom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x15: /* da/5 */
                    switch(rm) {
                    case 1: /* fucompp */
                        gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, 1));
                        gen_helper_fucom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                        gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    default:
                        goto unknown_op;
                    }
                    break;
                case 0x1c:
                    switch(rm) {
                    case 0: /* feni (287 only, just do nop here) */
                        break;
                    case 1: /* fdisi (287 only, just do nop here) */
                        break;
                    case 2: /* fclex */
                        gen_helper_fclex(tcg_ctx, tcg_ctx->cpu_env);
                        update_fip = false;
                        break;
                    case 3: /* fninit */
                        gen_helper_fninit(tcg_ctx, tcg_ctx->cpu_env);
                        update_fip = false;
                        break;
                    case 4: /* fsetpm (287 only, just do nop here) */
                        break;
                    default:
                        goto unknown_op;
                    }
                    break;
                case 0x1d: /* fucomi */
                    if (!(s->cpuid_features & CPUID_CMOV)) {
                        goto illegal_op;
                    }
                    gen_update_cc_op(s);
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fucomi_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    set_cc_op(s, CC_OP_EFLAGS);
                    break;
                case 0x1e: /* fcomi */
                    if (!(s->cpuid_features & CPUID_CMOV)) {
                        goto illegal_op;
                    }
                    gen_update_cc_op(s);
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fcomi_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    set_cc_op(s, CC_OP_EFLAGS);
                    break;
                case 0x28: /* ffree sti */
                    gen_helper_ffree_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    break;
                case 0x2a: /* fst sti */
                    gen_helper_fmov_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    break;
                case 0x2b: /* fstp sti */
                case 0x0b: /* fstp1 sti, undocumented op */
                case 0x3a: /* fstp8 sti, undocumented op */
                case 0x3b: /* fstp9 sti, undocumented op */
                    gen_helper_fmov_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x2c: /* fucom st(i) */
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fucom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x2d: /* fucomp st(i) */
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fucom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x33: /* de/3 */
                    switch(rm) {
                    case 1: /* fcompp */
                        gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, 1));
                        gen_helper_fcom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                        gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    default:
                        goto unknown_op;
                    }
                    break;
                case 0x38: /* ffreep sti, undocumented op */
                    gen_helper_ffree_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x3c: /* df/4 */
                    switch(rm) {
                    case 0:
                        gen_helper_fnstsw(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                        tcg_gen_extu_i32_tl(tcg_ctx, s->T0, s->tmp2_i32);
                        gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
                        break;
                    default:
                        goto unknown_op;
                    }
                    break;
                case 0x3d: /* fucomip */
                    if (!(s->cpuid_features & CPUID_CMOV)) {
                        goto illegal_op;
                    }
                    gen_update_cc_op(s);
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fucomi_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    set_cc_op(s, CC_OP_EFLAGS);
                    break;
                case 0x3e: /* fcomip */
                    if (!(s->cpuid_features & CPUID_CMOV)) {
                        goto illegal_op;
                    }
                    gen_update_cc_op(s);
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fcomi_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    set_cc_op(s, CC_OP_EFLAGS);
                    break;
                case 0x10: /* fcmovxx */
                case 0x11: /* fcmovxx */
                case 0x12: /* fcmovxx */
                case 0x13: /* fcmovxx */

                case 0x18:
                case 0x19:
                case 0x1a:
                case 0x1b:
                    {
                        int op1;
                        TCGLabel *l1;
                        static const uint8_t fcmov_cc[8] = {
                            (JCC_B << 1),
                            (JCC_Z << 1),
                            (JCC_BE << 1),
                            (JCC_P << 1),
                        };

                        if (!(s->cpuid_features & CPUID_CMOV)) {
                            goto illegal_op;
                        }
                        op1 = fcmov_cc[op & 3] | (((op >> 3) & 1) ^ 1);
                        l1 = gen_new_label(tcg_ctx);
                        gen_jcc1_noeob(s, op1, l1);
                        gen_helper_fmov_ST0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                        gen_set_label(tcg_ctx, l1);
                    }
                    break;
                default:
                    goto unknown_op;
                }
            }

            if (update_fip) {
                tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, segs[R_CS].selector));
                tcg_gen_st16_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                    offsetof(CPUX86State, fpcs));
                tcg_gen_st_tl(tcg_ctx, tcg_const_tl(tcg_ctx, pc_start - s->cs_base),
                                tcg_ctx->cpu_env, offsetof(CPUX86State, fpip));
            }
        }
        break;
        /************************/
        /* string ops */

    case 0xa4: /* movsS */
    case 0xa5:
        ot = mo_b_d(b, dflag);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_movs(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_movs(s, ot);
        }
        break;

    case 0xaa: /* stosS */
    case 0xab:
        ot = mo_b_d(b, dflag);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_stos(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_stos(s, ot);
        }
        break;
    case 0xac: /* lodsS */
    case 0xad:
        ot = mo_b_d(b, dflag);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_lods(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_lods(s, ot);
        }
        break;
    case 0xae: /* scasS */
    case 0xaf:
        ot = mo_b_d(b, dflag);
        if (prefixes & PREFIX_REPNZ) {
            gen_repz_scas(s, ot, pc_start - s->cs_base, s->pc - s->cs_base, 1);
        } else if (prefixes & PREFIX_REPZ) {
            gen_repz_scas(s, ot, pc_start - s->cs_base, s->pc - s->cs_base, 0);
        } else {
            gen_scas(s, ot);
        }
        break;

    case 0xa6: /* cmpsS */
    case 0xa7:
        ot = mo_b_d(b, dflag);
        if (prefixes & PREFIX_REPNZ) {
            gen_repz_cmps(s, ot, pc_start - s->cs_base, s->pc - s->cs_base, 1);
        } else if (prefixes & PREFIX_REPZ) {
            gen_repz_cmps(s, ot, pc_start - s->cs_base, s->pc - s->cs_base, 0);
        } else {
            gen_cmps(s, ot);
        }
        break;
    case 0x6c: /* insS */
    case 0x6d:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base, 
                     SVM_IOIO_TYPE_MASK | svm_is_rep(prefixes) | 4);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_ins(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_ins(s, ot);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_jmp(s, s->pc - s->cs_base);
            }
        }
        break;
    case 0x6e: /* outsS */
    case 0x6f:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     svm_is_rep(prefixes) | 4);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_outs(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_outs(s, ot);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_jmp(s, s->pc - s->cs_base);
            }
        }
        break;

        /************************/
        /* port I/O */

    case 0xe4:
    case 0xe5:
        ot = mo_b_d32(b, dflag);
        val = x86_ldub_code(env, s);
        tcg_gen_movi_tl(tcg_ctx, s->T0, val);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     SVM_IOIO_TYPE_MASK | svm_is_rep(prefixes));
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start(tcg_ctx);
        }
        tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, val);
        gen_helper_in_func(tcg_ctx, ot, s->T1, s->tmp2_i32);
        gen_op_mov_reg_v(s, ot, R_EAX, s->T1);
        gen_bpt_io(s, s->tmp2_i32, ot);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;
    case 0xe6:
    case 0xe7:
        ot = mo_b_d32(b, dflag);
        val = x86_ldub_code(env, s);
        tcg_gen_movi_tl(tcg_ctx, s->T0, val);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     svm_is_rep(prefixes));
        gen_op_mov_v_reg(s, ot, s->T1, R_EAX);

        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start(tcg_ctx);
        }
        tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, val);
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, s->T1);
        gen_helper_out_func(tcg_ctx, ot, s->tmp2_i32, s->tmp3_i32);
        gen_bpt_io(s, s->tmp2_i32, ot);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;
    case 0xec:
    case 0xed:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     SVM_IOIO_TYPE_MASK | svm_is_rep(prefixes));
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start(tcg_ctx);
        }
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        gen_helper_in_func(tcg_ctx, ot, s->T1, s->tmp2_i32);
        gen_op_mov_reg_v(s, ot, R_EAX, s->T1);
        gen_bpt_io(s, s->tmp2_i32, ot);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;
    case 0xee:
    case 0xef:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     svm_is_rep(prefixes));
        gen_op_mov_v_reg(s, ot, s->T1, R_EAX);

        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start(tcg_ctx);
        }
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, s->T1);
        gen_helper_out_func(tcg_ctx, ot, s->tmp2_i32, s->tmp3_i32);
        gen_bpt_io(s, s->tmp2_i32, ot);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;

        /************************/
        /* control */
    case 0xc2: /* ret im */
        val = x86_lduw_code(env, s);
        ot = gen_pop_T0(s);
        gen_stack_update(s, val + (1 << ot));
        /* Note that gen_pop_T0 uses a zero-extending load.  */
        gen_op_jmp_v(tcg_ctx, s->T0);
        gen_bnd_jmp(s);
        gen_jr(s, s->T0);
        break;
    case 0xc3: /* ret */
        ot = gen_pop_T0(s);
        gen_pop_update(s, ot);
        /* Note that gen_pop_T0 uses a zero-extending load.  */
        gen_op_jmp_v(tcg_ctx, s->T0);
        gen_bnd_jmp(s);
        gen_jr(s, s->T0);
        break;
    case 0xca: /* lret im */
        val = x86_lduw_code(env, s);
    do_lret:
        if (s->pe && !s->vm86) {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_lret_protected(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, dflag - 1),
                                      tcg_const_i32(tcg_ctx, val));
        } else {
            gen_stack_A0(s);
            /* pop offset */
            gen_op_ld_v(s, dflag, s->T0, s->A0);
            /* NOTE: keeping EIP updated is not a problem in case of
               exception */
            gen_op_jmp_v(tcg_ctx, s->T0);
            /* pop selector */
            gen_add_A0_im(s, 1 << dflag);
            gen_op_ld_v(s, dflag, s->T0, s->A0);
            gen_op_movl_seg_T0_vm(s, R_CS);
            /* add stack offset */
            gen_stack_update(s, val + (2 << dflag));
        }
        gen_eob(s);
        break;
    case 0xcb: /* lret */
        val = 0;
        goto do_lret;
    case 0xcf: /* iret */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_IRET);
        if (!s->pe) {
            /* real mode */
            gen_helper_iret_real(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, dflag - 1));
            set_cc_op(s, CC_OP_EFLAGS);
        } else if (s->vm86) {
            if (s->iopl != 3) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            } else {
                gen_helper_iret_real(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, dflag - 1));
                set_cc_op(s, CC_OP_EFLAGS);
            }
        } else {
            gen_helper_iret_protected(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, dflag - 1),
                                      tcg_const_i32(tcg_ctx, s->pc - s->cs_base));
            set_cc_op(s, CC_OP_EFLAGS);
        }
        gen_eob(s);
        break;
    case 0xe8: /* call im */
        {
            if (dflag != MO_16) {
                tval = (int32_t)insn_get(env, s, MO_32);
            } else {
                tval = (int16_t)insn_get(env, s, MO_16);
            }
            next_eip = s->pc - s->cs_base;
            tval += next_eip;
            if (dflag == MO_16) {
                tval &= 0xffff;
            } else if (!CODE64(s)) {
                tval &= 0xffffffff;
            }
            tcg_gen_movi_tl(tcg_ctx, s->T0, next_eip);
            gen_push_v(s, s->T0);
            gen_bnd_jmp(s);
            gen_jmp(s, tval);
        }
        break;
    case 0x9a: /* lcall im */
        {
            unsigned int selector, offset;

            if (CODE64(s))
                goto illegal_op;
            ot = dflag;
            offset = insn_get(env, s, ot);
            selector = insn_get(env, s, MO_16);

            tcg_gen_movi_tl(tcg_ctx, s->T0, selector);
            tcg_gen_movi_tl(tcg_ctx, s->T1, offset);
        }
        goto do_lcall;
    case 0xe9: /* jmp im */
        if (dflag != MO_16) {
            tval = (int32_t)insn_get(env, s, MO_32);
        } else {
            tval = (int16_t)insn_get(env, s, MO_16);
        }
        tval += s->pc - s->cs_base;
        if (dflag == MO_16) {
            tval &= 0xffff;
        } else if (!CODE64(s)) {
            tval &= 0xffffffff;
        }
        gen_bnd_jmp(s);
        gen_jmp(s, tval);
        break;
    case 0xea: /* ljmp im */
        {
            unsigned int selector, offset;

            if (CODE64(s))
                goto illegal_op;
            ot = dflag;
            offset = insn_get(env, s, ot);
            selector = insn_get(env, s, MO_16);

            tcg_gen_movi_tl(tcg_ctx, s->T0, selector);
            tcg_gen_movi_tl(tcg_ctx, s->T1, offset);
        }
        goto do_ljmp;
    case 0xeb: /* jmp Jb */
        tval = (int8_t)insn_get(env, s, MO_8);
        tval += s->pc - s->cs_base;
        if (dflag == MO_16) {
            tval &= 0xffff;
        }
        gen_jmp(s, tval);
        break;
    case 0x70: /* jcc Jb */
    case 0x71: /* jcc Jb */
    case 0x72: /* jcc Jb */
    case 0x73: /* jcc Jb */
    case 0x74: /* jcc Jb */
    case 0x75: /* jcc Jb */
    case 0x76: /* jcc Jb */
    case 0x77: /* jcc Jb */
    case 0x78: /* jcc Jb */
    case 0x79: /* jcc Jb */
    case 0x7a: /* jcc Jb */
    case 0x7b: /* jcc Jb */
    case 0x7c: /* jcc Jb */
    case 0x7d: /* jcc Jb */
    case 0x7e: /* jcc Jb */
    case 0x7f: /* jcc Jb */
        tval = (int8_t)insn_get(env, s, MO_8);
        goto do_jcc;
    case 0x180: /* jcc Jv */
    case 0x181: /* jcc Jv */
    case 0x182: /* jcc Jv */
    case 0x183: /* jcc Jv */
    case 0x184: /* jcc Jv */
    case 0x185: /* jcc Jv */
    case 0x186: /* jcc Jv */
    case 0x187: /* jcc Jv */
    case 0x188: /* jcc Jv */
    case 0x189: /* jcc Jv */
    case 0x18a: /* jcc Jv */
    case 0x18b: /* jcc Jv */
    case 0x18c: /* jcc Jv */
    case 0x18d: /* jcc Jv */
    case 0x18e: /* jcc Jv */
    case 0x18f: /* jcc Jv */
        if (dflag != MO_16) {
            tval = (int32_t)insn_get(env, s, MO_32);
        } else {
            tval = (int16_t)insn_get(env, s, MO_16);
        }
    do_jcc:
        next_eip = s->pc - s->cs_base;
        tval += next_eip;
        if (dflag == MO_16) {
            tval &= 0xffff;
        }
        gen_bnd_jmp(s);
        gen_jcc(s, b, tval, next_eip);
        break;

    case 0x190: /* setcc Gv */
    case 0x191: /* setcc Gv */
    case 0x192: /* setcc Gv */
    case 0x193: /* setcc Gv */
    case 0x194: /* setcc Gv */
    case 0x195: /* setcc Gv */
    case 0x196: /* setcc Gv */
    case 0x197: /* setcc Gv */
    case 0x198: /* setcc Gv */
    case 0x199: /* setcc Gv */
    case 0x19a: /* setcc Gv */
    case 0x19b: /* setcc Gv */
    case 0x19c: /* setcc Gv */
    case 0x19d: /* setcc Gv */
    case 0x19e: /* setcc Gv */
    case 0x19f: /* setcc Gv */
        modrm = x86_ldub_code(env, s);
        gen_setcc1(s, b, s->T0);
        gen_ldst_modrm(env, s, modrm, MO_8, OR_TMP0, 1);
        break;
    case 0x140: /* cmov Gv, Ev */
    case 0x141: /* cmov Gv, Ev */
    case 0x142: /* cmov Gv, Ev */
    case 0x143: /* cmov Gv, Ev */
    case 0x144: /* cmov Gv, Ev */
    case 0x145: /* cmov Gv, Ev */
    case 0x146: /* cmov Gv, Ev */
    case 0x147: /* cmov Gv, Ev */
    case 0x148: /* cmov Gv, Ev */
    case 0x149: /* cmov Gv, Ev */
    case 0x14a: /* cmov Gv, Ev */
    case 0x14b: /* cmov Gv, Ev */
    case 0x14c: /* cmov Gv, Ev */
    case 0x14d: /* cmov Gv, Ev */
    case 0x14e: /* cmov Gv, Ev */
    case 0x14f: /* cmov Gv, Ev */
        if (!(s->cpuid_features & CPUID_CMOV)) {
            goto illegal_op;
        }
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        gen_cmovcc1(env, s, ot, b, modrm, reg);
        break;

        /************************/
        /* flags */
    case 0x9c: /* pushf */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_PUSHF);
        if (s->vm86 && s->iopl != 3) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_helper_read_eflags(tcg_ctx, s->T0, tcg_ctx->cpu_env);
            gen_push_v(s, s->T0);
        }
        break;
    case 0x9d: /* popf */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_POPF);
        if (s->vm86 && s->iopl != 3) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            ot = gen_pop_T0(s);
            if (s->cpl == 0) {
                if (dflag != MO_16) {
                    gen_helper_write_eflags(tcg_ctx, tcg_ctx->cpu_env, s->T0,
                                            tcg_const_i32(tcg_ctx, (TF_MASK | AC_MASK |
                                                           ID_MASK | NT_MASK |
                                                           IF_MASK |
                                                           IOPL_MASK)));
                } else {
                    gen_helper_write_eflags(tcg_ctx, tcg_ctx->cpu_env, s->T0,
                                            tcg_const_i32(tcg_ctx, (TF_MASK | AC_MASK |
                                                           ID_MASK | NT_MASK |
                                                           IF_MASK | IOPL_MASK)
                                                          & 0xffff));
                }
            } else {
                if (s->cpl <= s->iopl) {
                    if (dflag != MO_16) {
                        gen_helper_write_eflags(tcg_ctx, tcg_ctx->cpu_env, s->T0,
                                                tcg_const_i32(tcg_ctx, (TF_MASK |
                                                               AC_MASK |
                                                               ID_MASK |
                                                               NT_MASK |
                                                               IF_MASK)));
                    } else {
                        gen_helper_write_eflags(tcg_ctx, tcg_ctx->cpu_env, s->T0,
                                                tcg_const_i32(tcg_ctx, (TF_MASK |
                                                               AC_MASK |
                                                               ID_MASK |
                                                               NT_MASK |
                                                               IF_MASK)
                                                              & 0xffff));
                    }
                } else {
                    if (dflag != MO_16) {
                        gen_helper_write_eflags(tcg_ctx, tcg_ctx->cpu_env, s->T0,
                                           tcg_const_i32(tcg_ctx, (TF_MASK | AC_MASK |
                                                          ID_MASK | NT_MASK)));
                    } else {
                        gen_helper_write_eflags(tcg_ctx, tcg_ctx->cpu_env, s->T0,
                                           tcg_const_i32(tcg_ctx, (TF_MASK | AC_MASK |
                                                          ID_MASK | NT_MASK)
                                                         & 0xffff));
                    }
                }
            }
            gen_pop_update(s, ot);
            set_cc_op(s, CC_OP_EFLAGS);
            /* abort translation because TF/AC flag may change */
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
        }
        break;
    case 0x9e: /* sahf */
        if (CODE64(s) && !(s->cpuid_ext3_features & CPUID_EXT3_LAHF_LM))
            goto illegal_op;
        gen_op_mov_v_reg(s, MO_8, s->T0, R_AH);
        gen_compute_eflags(s);
        tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, CC_O);
        tcg_gen_andi_tl(tcg_ctx, s->T0, s->T0, CC_S | CC_Z | CC_A | CC_P | CC_C);
        tcg_gen_or_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, s->T0);
        break;
    case 0x9f: /* lahf */
        if (CODE64(s) && !(s->cpuid_ext3_features & CPUID_EXT3_LAHF_LM))
            goto illegal_op;
        gen_mov_eflags(s, s->T0);
        /* Note: gen_mov_eflags() only gives the condition codes */
        tcg_gen_ori_tl(tcg_ctx, s->T0, s->T0, 0x02);
        gen_op_mov_reg_v(s, MO_8, R_AH, s->T0);
        break;
    case 0xf5: /* cmc */
        gen_compute_eflags(s);
        tcg_gen_xori_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, CC_C);
        break;
    case 0xf8: /* clc */
        gen_compute_eflags(s);
        tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, ~CC_C);
        break;
    case 0xf9: /* stc */
        gen_compute_eflags(s);
        tcg_gen_ori_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, CC_C);
        break;
    case 0xfc: /* cld */
        tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, 1);
        tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, offsetof(CPUX86State, df));
        break;
    case 0xfd: /* std */
        tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, -1);
        tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, offsetof(CPUX86State, df));
        break;

        /************************/
        /* bit operations */
    case 0x1ba: /* bt/bts/btr/btc Gv, im */
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        op = (modrm >> 3) & 7;
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        if (mod != 3) {
            s->rip_offset = 1;
            gen_lea_modrm(env, s, modrm);
            if (!(s->prefix & PREFIX_LOCK)) {
                gen_op_ld_v(s, ot, s->T0, s->A0);
            }
        } else {
            gen_op_mov_v_reg(s, ot, s->T0, rm);
        }
        /* load shift */
        val = x86_ldub_code(env, s);
        tcg_gen_movi_tl(tcg_ctx, s->T1, val);
        if (op < 4)
            goto unknown_op;
        op -= 4;
        goto bt_op;
    case 0x1a3: /* bt Gv, Ev */
        op = 0;
        goto do_btx;
    case 0x1ab: /* bts */
        op = 1;
        goto do_btx;
    case 0x1b3: /* btr */
        op = 2;
        goto do_btx;
    case 0x1bb: /* btc */
        op = 3;
    do_btx:
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        gen_op_mov_v_reg(s, MO_32, s->T1, reg);
        if (mod != 3) {
            AddressParts a = gen_lea_modrm_0(env, s, modrm);
            /* specific case: we need to add a displacement */
            gen_exts(tcg_ctx, ot, s->T1);
            tcg_gen_sari_tl(tcg_ctx, s->tmp0, s->T1, 3 + ot);
            tcg_gen_shli_tl(tcg_ctx, s->tmp0, s->tmp0, ot);
            tcg_gen_add_tl(tcg_ctx, s->A0, gen_lea_modrm_1(s, a), s->tmp0);
            gen_lea_v_seg(s, s->aflag, s->A0, a.def_seg, s->override);
            if (!(s->prefix & PREFIX_LOCK)) {
                gen_op_ld_v(s, ot, s->T0, s->A0);
            }
        } else {
            gen_op_mov_v_reg(s, ot, s->T0, rm);
        }
    bt_op:
        tcg_gen_andi_tl(tcg_ctx, s->T1, s->T1, (1 << (3 + ot)) - 1);
        tcg_gen_movi_tl(tcg_ctx, s->tmp0, 1);
        tcg_gen_shl_tl(tcg_ctx, s->tmp0, s->tmp0, s->T1);
        if (s->prefix & PREFIX_LOCK) {
            switch (op) {
            case 0: /* bt */
                /* Needs no atomic ops; we surpressed the normal
                   memory load for LOCK above so do it now.  */
                gen_op_ld_v(s, ot, s->T0, s->A0);
                break;
            case 1: /* bts */
                tcg_gen_atomic_fetch_or_tl(tcg_ctx, s->T0, s->A0, s->tmp0,
                                           s->mem_index, ot | MO_LE);
                break;
            case 2: /* btr */
                tcg_gen_not_tl(tcg_ctx, s->tmp0, s->tmp0);
                tcg_gen_atomic_fetch_and_tl(tcg_ctx, s->T0, s->A0, s->tmp0,
                                            s->mem_index, ot | MO_LE);
                break;
            default:
            case 3: /* btc */
                tcg_gen_atomic_fetch_xor_tl(tcg_ctx, s->T0, s->A0, s->tmp0,
                                            s->mem_index, ot | MO_LE);
                break;
            }
            tcg_gen_shr_tl(tcg_ctx, s->tmp4, s->T0, s->T1);
        } else {
            tcg_gen_shr_tl(tcg_ctx, s->tmp4, s->T0, s->T1);
            switch (op) {
            case 0: /* bt */
                /* Data already loaded; nothing to do.  */
                break;
            case 1: /* bts */
                tcg_gen_or_tl(tcg_ctx, s->T0, s->T0, s->tmp0);
                break;
            case 2: /* btr */
                tcg_gen_andc_tl(tcg_ctx, s->T0, s->T0, s->tmp0);
                break;
            default:
            case 3: /* btc */
                tcg_gen_xor_tl(tcg_ctx, s->T0, s->T0, s->tmp0);
                break;
            }
            if (op != 0) {
                if (mod != 3) {
                    gen_op_st_v(s, ot, s->T0, s->A0);
                } else {
                    gen_op_mov_reg_v(s, ot, rm, s->T0);
                }
            }
        }

        /* Delay all CC updates until after the store above.  Note that
           C is the result of the test, Z is unchanged, and the others
           are all undefined.  */
        switch (s->cc_op) {
        case CC_OP_MULB:
        case CC_OP_MULW:
        case CC_OP_MULL:
        case CC_OP_MULQ:

        case CC_OP_ADDB:
        case CC_OP_ADDW:
        case CC_OP_ADDL:
        case CC_OP_ADDQ:

        case CC_OP_ADCB:
        case CC_OP_ADCW:
        case CC_OP_ADCL:
        case CC_OP_ADCQ:

        case CC_OP_SUBB:
        case CC_OP_SUBW:
        case CC_OP_SUBL:
        case CC_OP_SUBQ:

        case CC_OP_SBBB:
        case CC_OP_SBBW:
        case CC_OP_SBBL:
        case CC_OP_SBBQ:

        case CC_OP_LOGICB:
        case CC_OP_LOGICW:
        case CC_OP_LOGICL:
        case CC_OP_LOGICQ:

        case CC_OP_INCB:
        case CC_OP_INCW:
        case CC_OP_INCL:
        case CC_OP_INCQ:

        case CC_OP_DECB:
        case CC_OP_DECW:
        case CC_OP_DECL:
        case CC_OP_DECQ:

        case CC_OP_SHLB:
        case CC_OP_SHLW:
        case CC_OP_SHLL:
        case CC_OP_SHLQ:

        case CC_OP_SARB:
        case CC_OP_SARW:
        case CC_OP_SARL:
        case CC_OP_SARQ:

        case CC_OP_BMILGB:
        case CC_OP_BMILGW:
        case CC_OP_BMILGL:
        case CC_OP_BMILGQ:
            /* Z was going to be computed from the non-zero status of CC_DST.
               We can get that same Z value (and the new C value) by leaving
               CC_DST alone, setting CC_SRC, and using a CC_OP_SAR of the
               same width.  */
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->tmp4);
            set_cc_op(s, ((s->cc_op - CC_OP_MULB) & 3) + CC_OP_SARB);
            break;
        default:
            /* Otherwise, generate EFLAGS and replace the C bit.  */
            gen_compute_eflags(s);
            tcg_gen_deposit_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, s->tmp4,
                               ctz32(CC_C), 1);
            break;
        }
        break;
    case 0x1bc: /* bsf / tzcnt */
    case 0x1bd: /* bsr / lzcnt */
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_extu(tcg_ctx, ot, s->T0);

        /* Note that lzcnt and tzcnt are in different extensions.  */
        if ((prefixes & PREFIX_REPZ)
            && (b & 1
                ? s->cpuid_ext3_features & CPUID_EXT3_ABM
                : s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI1)) {
            int size = 8 << ot;
            /* For lzcnt/tzcnt, C bit is defined related to the input. */
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0);
            if (b & 1) {
                /* For lzcnt, reduce the target_ulong result by the
                   number of zeros that we expect to find at the top.  */
                tcg_gen_clzi_tl(tcg_ctx, s->T0, s->T0, TARGET_LONG_BITS);
                tcg_gen_subi_tl(tcg_ctx, s->T0, s->T0, TARGET_LONG_BITS - size);
            } else {
                /* For tzcnt, a zero input must return the operand size.  */
                tcg_gen_ctzi_tl(tcg_ctx, s->T0, s->T0, size);
            }
            /* For lzcnt/tzcnt, Z bit is defined related to the result.  */
            gen_op_update1_cc(s);
            set_cc_op(s, CC_OP_BMILGB + ot);
            gen_op_mov_reg_v(s, ot, reg, s->T0);
        } else {
            TCGv source = tcg_temp_new(tcg_ctx);
            TCGv new_dest = tcg_temp_new(tcg_ctx);
            TCGv zero = tcg_const_tl(tcg_ctx, 0);

            /* For bsr/bsf, only the Z bit is defined and it is related
               to the input and not the result.  */
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
            set_cc_op(s, CC_OP_LOGICB + ot);

            /* ??? The manual says that the output is undefined when the
               input is zero, but real hardware leaves it unchanged, and
               real programs appear to depend on that.  Accomplish this
               with a data-flow select so a zero input suppresses the entire
               architectural register write, including the high-half clearing
               side effect of a 32-bit write in 64-bit mode.  */
            tcg_gen_mov_tl(tcg_ctx, source, s->T0);
            if (b & 1) {
                /* For bsr, return the bit index of the first 1 bit,
                   not the count of leading zeros.  */
                tcg_gen_clz_tl(tcg_ctx, s->T0, s->T0, zero);
                tcg_gen_xori_tl(tcg_ctx, s->T0, s->T0, TARGET_LONG_BITS - 1);
            } else {
                tcg_gen_ctz_tl(tcg_ctx, s->T0, s->T0, zero);
            }
            gen_op_deposit_reg_v(s, ot, reg, new_dest, s->T0);
            tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ,
                               tcg_ctx->cpu_regs[reg], source, zero,
                               tcg_ctx->cpu_regs[reg], new_dest);
            tcg_temp_free(tcg_ctx, zero);
            tcg_temp_free(tcg_ctx, new_dest);
            tcg_temp_free(tcg_ctx, source);
        }
        break;
        /************************/
        /* bcd */
    case 0x27: /* daa */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_daa(tcg_ctx, tcg_ctx->cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0x2f: /* das */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_das(tcg_ctx, tcg_ctx->cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0x37: /* aaa */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_aaa(tcg_ctx, tcg_ctx->cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0x3f: /* aas */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_aas(tcg_ctx, tcg_ctx->cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0xd4: /* aam */
        if (CODE64(s))
            goto illegal_op;
        val = x86_ldub_code(env, s);
        if (val == 0) {
            gen_exception(s, EXCP00_DIVZ, pc_start - s->cs_base);
        } else {
            gen_helper_aam(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, val));
            set_cc_op(s, CC_OP_LOGICB);
        }
        break;
    case 0xd5: /* aad */
#ifdef TARGET_X86_64
        if (CODE64(s)) {
            if (!apx_f_enabled(s) ||
                !gen_rex2_register(env, s, effective_rex_byte)) {
                goto illegal_op;
            }
            break;
        }
#endif
        val = x86_ldub_code(env, s);
        gen_helper_aad(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, val));
        set_cc_op(s, CC_OP_LOGICB);
        break;
        /************************/
        /* misc */
    case 0x90: /* nop */
        /* XXX: correct lock test for all insn */
        if (prefixes & PREFIX_LOCK) {
            goto illegal_op;
        }
        /* If REX_B is set, then this is xchg eax, r8d, not a nop.  */
        if (REX_B(s)) {
            goto do_xchg_reg_eax;
        }
        if (prefixes & PREFIX_REPZ) {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_pause(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
            s->base.is_jmp = DISAS_NORETURN;
        }
        break;
    case 0x9b: /* fwait */
        if ((s->flags & (HF_MP_MASK | HF_TS_MASK)) ==
            (HF_MP_MASK | HF_TS_MASK)) {
            gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
        } else {
            gen_helper_fwait(tcg_ctx, tcg_ctx->cpu_env);
        }
        break;
    case 0xcc: /* int3 */
        gen_interrupt(s, EXCP03_INT3, pc_start - s->cs_base, s->pc - s->cs_base);
        break;
    case 0xcd: /* int N */
        val = x86_ldub_code(env, s);
        if (s->vm86 && s->iopl != 3) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_interrupt(s, val, pc_start - s->cs_base, s->pc - s->cs_base);
        }
        break;
    case 0xce: /* into */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_into(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
        break;
    case 0xf1: /* icebp: #DB is a trap and reports the next instruction */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_ICEBP);
        gen_update_cc_op(s);
        gen_sync_pc(tcg_ctx, s->pc - s->cs_base);
        gen_helper_icebp(tcg_ctx, tcg_ctx->cpu_env);
        s->base.is_jmp = DISAS_NORETURN;
        break;
    case 0xfa: /* cli */
        if (!s->vm86) {
            if (s->cpl <= s->iopl) {
                gen_helper_cli(tcg_ctx, tcg_ctx->cpu_env);
            } else {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            }
        } else {
            if (s->iopl == 3) {
                gen_helper_cli(tcg_ctx, tcg_ctx->cpu_env);
            } else {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            }
        }
        break;
    case 0xfb: /* sti */
        if (s->vm86 ? s->iopl == 3 : s->cpl <= s->iopl) {
            gen_helper_sti(tcg_ctx, tcg_ctx->cpu_env);
            /* interruptions are enabled only the first insn after sti */
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob_inhibit_irq(s, true);
        } else {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        }
        break;
    case 0x62: /* bound */
        if (CODE64(s)) {
            if (!gen_evex_instruction(env, s, effective_rex_byte, false)) {
                goto illegal_op;
            }
            break;
        }
        if (s->code32 && !s->vm86) {
            /* Like VEX, EVEX is distinguished from BOUND in 32-bit mode by
             * the following byte's ModRM.mod-shaped top bits. */
            val = x86_ldub_code(env, s);
            s->pc--;
            if ((val & 0xc0) == 0xc0) {
                if (!gen_evex_instruction(env, s, effective_rex_byte, true)) {
                    goto illegal_op;
                }
                break;
            }
        }
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = (modrm >> 3) & 7;
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        gen_op_mov_v_reg(s, ot, s->T0, reg);
        gen_lea_modrm(env, s, modrm);
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        if (ot == MO_16) {
            gen_helper_boundw(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->tmp2_i32);
        } else {
            gen_helper_boundl(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->tmp2_i32);
        }
        break;
    case 0x1c8: /* bswap reg */
    case 0x1c9: /* bswap reg */
    case 0x1ca: /* bswap reg */
    case 0x1cb: /* bswap reg */
    case 0x1cc: /* bswap reg */
    case 0x1cd: /* bswap reg */
    case 0x1ce: /* bswap reg */
    case 0x1cf: /* bswap reg */
        reg = (b & 7) | REX_B(s);
#ifdef TARGET_X86_64
        if (dflag == MO_64) {
            gen_op_mov_v_reg(s, MO_64, s->T0, reg);
            tcg_gen_bswap64_i64(tcg_ctx, s->T0, s->T0);
            gen_op_mov_reg_v(s, MO_64, reg, s->T0);
        } else
#endif
        if (dflag == MO_32) {
            gen_op_mov_v_reg(s, MO_32, s->T0, reg);
            tcg_gen_ext32u_tl(tcg_ctx, s->T0, s->T0);
            tcg_gen_bswap32_tl(tcg_ctx, s->T0, s->T0);
            gen_op_mov_reg_v(s, MO_32, reg, s->T0);
        }
        else {
            tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
            gen_op_mov_reg_v(s, MO_16, reg, s->T0);
        }
        break;
    case 0xd6: /* salc */
        if (CODE64(s))
            goto illegal_op;
        gen_compute_eflags_c(s, s->T0);
        tcg_gen_neg_tl(tcg_ctx, s->T0, s->T0);
        gen_op_mov_reg_v(s, MO_8, R_EAX, s->T0);
        break;
    case 0xe0: /* loopnz */
    case 0xe1: /* loopz */
    case 0xe2: /* loop */
    case 0xe3: /* jecxz */
        {
            TCGLabel *l1, *l2, *l3;

            tval = (int8_t)insn_get(env, s, MO_8);
            next_eip = s->pc - s->cs_base;
            tval += next_eip;
            if (dflag == MO_16) {
                tval &= 0xffff;
            }

            l1 = gen_new_label(tcg_ctx);
            l2 = gen_new_label(tcg_ctx);
            l3 = gen_new_label(tcg_ctx);
            b &= 3;
            switch(b) {
            case 0: /* loopnz */
            case 1: /* loopz */
                gen_op_add_reg_im(s, s->aflag, R_ECX, -1);
                gen_op_jz_ecx(s, s->aflag, l3);
                gen_jcc1(s, (JCC_Z << 1) | (b ^ 1), l1);
                break;
            case 2: /* loop */
                gen_op_add_reg_im(s, s->aflag, R_ECX, -1);
                gen_op_jnz_ecx(s, s->aflag, l1);
                break;
            default:
            case 3: /* jcxz */
                gen_op_jz_ecx(s, s->aflag, l1);
                break;
            }

            gen_set_label(tcg_ctx, l3);
            gen_jmp_im(s, next_eip);
            tcg_gen_br(tcg_ctx, l2);

            gen_set_label(tcg_ctx, l1);
            gen_jmp_im(s, tval);
            gen_set_label(tcg_ctx, l2);
            gen_eob(s);
        }
        break;
    case 0x130: /* wrmsr */
    case 0x132: /* rdmsr */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            if (b & 2) {
                gen_helper_rdmsr(tcg_ctx, tcg_ctx->cpu_env);
            } else {
                gen_helper_wrmsr(tcg_ctx, tcg_ctx->cpu_env);
            }
        }
        break;
    case 0x131: /* rdtsc */
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start(tcg_ctx);
        }
        gen_helper_rdtsc(tcg_ctx, tcg_ctx->cpu_env);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;
    case 0x133: /* rdpmc */
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_rdpmc(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 0x134: /* sysenter */
        /* For Intel SYSENTER is valid on 64-bit */
        if (CODE64(s) && env->cpuid_vendor1 != CPUID_VENDOR_INTEL_1)
            goto illegal_op;
        if (!s->pe) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            TCGv_i32 addend = tcg_const_i32(tcg_ctx, s->pc - pc_start);
            gen_helper_sysenter(tcg_ctx, tcg_ctx->cpu_env, addend);
            gen_eob(s);
            tcg_temp_free_i32(tcg_ctx, addend);
        }
        break;
    case 0x135: /* sysexit */
        /* For Intel SYSEXIT is valid on 64-bit */
        if (CODE64(s) && env->cpuid_vendor1 != CPUID_VENDOR_INTEL_1)
            goto illegal_op;
        if (!s->pe) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_helper_sysexit(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, dflag - 1));
            gen_eob(s);
        }
        break;
#ifdef TARGET_X86_64
    case 0x105: /* syscall */
        /* XXX: is it usable in real mode ? */
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_syscall(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
        /* TF handling for the syscall insn is different. The TF bit is  checked
           after the syscall insn completes. This allows #DB to not be
           generated after one has entered CPL0 if TF is set in FMASK.  */
        gen_eob_worker(s, false, true);
        break;
    case 0x107: /* sysret */
        if (!s->pe) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_helper_sysret(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, dflag - 1));
            /* condition codes are modified only in long mode */
            if (s->lma) {
                set_cc_op(s, CC_OP_EFLAGS);
            }
            /* TF handling for the sysret insn is different. The TF bit is
               checked after the sysret insn completes. This allows #DB to be
               generated "as if" the syscall insn in userspace has just
               completed.  */
            gen_eob_worker(s, false, true);
        }
        break;
#endif
    case 0x1a2: /* cpuid */
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_cpuid(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 0xf4: /* hlt */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_hlt(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
            s->base.is_jmp = DISAS_NORETURN;
        }
        break;
    case 0x100:
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        op = (modrm >> 3) & 7;
        switch(op) {
        case 0: /* sldt */
            if (!s->pe || s->vm86)
                goto illegal_op;
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_LDTR_READ);
            tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                             offsetof(CPUX86State, ldt.selector));
            ot = mod == 3 ? dflag : MO_16;
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
            break;
        case 2: /* lldt */
            if (!s->pe || s->vm86)
                goto illegal_op;
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            } else {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_LDTR_WRITE);
                gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_lldt(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
            }
            break;
        case 1: /* str */
            if (!s->pe || s->vm86)
                goto illegal_op;
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_TR_READ);
            tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                             offsetof(CPUX86State, tr.selector));
            ot = mod == 3 ? dflag : MO_16;
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
            break;
        case 3: /* ltr */
            if (!s->pe || s->vm86)
                goto illegal_op;
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            } else {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_TR_WRITE);
                gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_ltr(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
            }
            break;
        case 4: /* verr */
        case 5: /* verw */
            if (!s->pe || s->vm86)
                goto illegal_op;
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            gen_update_cc_op(s);
            if (op == 4) {
                gen_helper_verr(tcg_ctx, tcg_ctx->cpu_env, s->T0);
            } else {
                gen_helper_verw(tcg_ctx, tcg_ctx->cpu_env, s->T0);
            }
            set_cc_op(s, CC_OP_EFLAGS);
            break;
        default:
            goto unknown_op;
        }
        break;

    case 0x101:
        modrm = x86_ldub_code(env, s);
        switch (modrm) {
        CASE_MODRM_MEM_OP(0): /* sgdt */
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_GDTR_READ);
            gen_lea_modrm(env, s, modrm);
            tcg_gen_ld32u_tl(tcg_ctx, s->T0,
                             tcg_ctx->cpu_env, offsetof(CPUX86State, gdt.limit));
            gen_op_st_v(s, MO_16, s->T0, s->A0);
            gen_add_A0_im(s, 2);
            tcg_gen_ld_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, gdt.base));
            if (dflag == MO_16) {
                tcg_gen_andi_tl(tcg_ctx, s->T0, s->T0, 0xffffff);
            }
            gen_op_st_v(s, CODE64(s) + MO_32, s->T0, s->A0);
            break;

        case 0xc8: /* monitor */
            if (!(s->cpuid_ext_features & CPUID_EXT_MONITOR) || s->cpl != 0) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            tcg_gen_mov_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_EAX]);
            gen_extu(tcg_ctx, s->aflag, s->A0);
            gen_add_A0_ds_seg(s);
            gen_helper_monitor(tcg_ctx, tcg_ctx->cpu_env, s->A0);
            break;

        case 0xc9: /* mwait */
            if (!(s->cpuid_ext_features & CPUID_EXT_MONITOR) || s->cpl != 0) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_mwait(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
            gen_eob(s);
            break;

        case 0xca: /* clac */
            if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_SMAP)
                || s->cpl != 0) {
                goto illegal_op;
            }
            gen_helper_clac(tcg_ctx, tcg_ctx->cpu_env);
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        case 0xcb: /* stac */
            if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_SMAP)
                || s->cpl != 0) {
                goto illegal_op;
            }
            gen_helper_stac(tcg_ctx, tcg_ctx->cpu_env);
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        CASE_MODRM_MEM_OP(1): /* sidt */
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_IDTR_READ);
            gen_lea_modrm(env, s, modrm);
            tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, idt.limit));
            gen_op_st_v(s, MO_16, s->T0, s->A0);
            gen_add_A0_im(s, 2);
            tcg_gen_ld_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, idt.base));
            if (dflag == MO_16) {
                tcg_gen_andi_tl(tcg_ctx, s->T0, s->T0, 0xffffff);
            }
            gen_op_st_v(s, CODE64(s) + MO_32, s->T0, s->A0);
            break;

        case 0xd0: /* xgetbv */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (s->prefix & (PREFIX_LOCK | PREFIX_DATA
                                 | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[R_ECX]);
            gen_helper_xgetbv(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, s->tmp2_i32);
            tcg_gen_extr_i64_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EAX], tcg_ctx->cpu_regs[R_EDX], s->tmp1_i64);
            break;

        case 0xd1: /* xsetbv */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (s->prefix & (PREFIX_LOCK | PREFIX_DATA
                                 | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            tcg_gen_concat_tl_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_regs[R_EAX],
                                  tcg_ctx->cpu_regs[R_EDX]);
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[R_ECX]);
            gen_helper_xsetbv(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32, s->tmp1_i64);
            /* End TB because translation flags may change.  */
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        case 0xd8: /* VMRUN */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_vmrun(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->aflag - 1),
                             tcg_const_i32(tcg_ctx, s->pc - pc_start));
            tcg_gen_exit_tb(tcg_ctx, NULL, 0);
            s->base.is_jmp = DISAS_NORETURN;
            break;

        case 0xd9: /* VMMCALL */
            if (!(s->flags & HF_SVME_MASK)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_vmmcall(tcg_ctx, tcg_ctx->cpu_env);
            break;

        case 0xda: /* VMLOAD */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_vmload(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->aflag - 1));
            break;

        case 0xdb: /* VMSAVE */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_vmsave(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->aflag - 1));
            break;

        case 0xdc: /* STGI */
            if ((!(s->flags & HF_SVME_MASK)
                   && !(s->cpuid_ext3_features & CPUID_EXT3_SKINIT))
                || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_helper_stgi(tcg_ctx, tcg_ctx->cpu_env);
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        case 0xdd: /* CLGI */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_clgi(tcg_ctx, tcg_ctx->cpu_env);
            break;

        case 0xde: /* SKINIT */
            if ((!(s->flags & HF_SVME_MASK)
                 && !(s->cpuid_ext3_features & CPUID_EXT3_SKINIT))
                || !s->pe) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_skinit(tcg_ctx, tcg_ctx->cpu_env);
            break;

        case 0xdf: /* INVLPGA */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_invlpga(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->aflag - 1));
            break;

        CASE_MODRM_MEM_OP(2): /* lgdt */
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_GDTR_WRITE);
            gen_lea_modrm(env, s, modrm);
            gen_op_ld_v(s, MO_16, s->T1, s->A0);
            gen_add_A0_im(s, 2);
            gen_op_ld_v(s, CODE64(s) + MO_32, s->T0, s->A0);
            if (dflag == MO_16) {
                tcg_gen_andi_tl(tcg_ctx, s->T0, s->T0, 0xffffff);
            }
            tcg_gen_st_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, gdt.base));
            tcg_gen_st32_tl(tcg_ctx, s->T1, tcg_ctx->cpu_env, offsetof(CPUX86State, gdt.limit));
            break;

        CASE_MODRM_MEM_OP(3): /* lidt */
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_IDTR_WRITE);
            gen_lea_modrm(env, s, modrm);
            gen_op_ld_v(s, MO_16, s->T1, s->A0);
            gen_add_A0_im(s, 2);
            gen_op_ld_v(s, CODE64(s) + MO_32, s->T0, s->A0);
            if (dflag == MO_16) {
                tcg_gen_andi_tl(tcg_ctx, s->T0, s->T0, 0xffffff);
            }
            tcg_gen_st_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, idt.base));
            tcg_gen_st32_tl(tcg_ctx, s->T1, tcg_ctx->cpu_env, offsetof(CPUX86State, idt.limit));
            break;

        CASE_MODRM_OP(4): /* smsw */
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_READ_CR0);
            tcg_gen_ld_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, cr[0]));
            if (CODE64(s)) {
                mod = (modrm >> 6) & 3;
                ot = (mod != 3 ? MO_16 : s->dflag);
            } else {
                ot = MO_16;
            }
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
            break;
        case 0xee: /* rdpkru */
            if (prefixes & PREFIX_LOCK) {
                goto illegal_op;
            }
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[R_ECX]);
            gen_helper_rdpkru(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, s->tmp2_i32);
            tcg_gen_extr_i64_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EAX], tcg_ctx->cpu_regs[R_EDX], s->tmp1_i64);
            break;
        case 0xef: /* wrpkru */
            if (prefixes & PREFIX_LOCK) {
                goto illegal_op;
            }
            tcg_gen_concat_tl_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_regs[R_EAX],
                                  tcg_ctx->cpu_regs[R_EDX]);
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[R_ECX]);
            gen_helper_wrpkru(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32, s->tmp1_i64);
            break;
        CASE_MODRM_OP(6): /* lmsw */
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_WRITE_CR0);
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            gen_helper_lmsw(tcg_ctx, tcg_ctx->cpu_env, s->T0);
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        CASE_MODRM_MEM_OP(7): /* invlpg */
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_lea_modrm(env, s, modrm);
            gen_helper_invlpg(tcg_ctx, tcg_ctx->cpu_env, s->A0);
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        case 0xf8: /* swapgs */
#ifdef TARGET_X86_64
            if (CODE64(s)) {
                if (s->cpl != 0) {
                    gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                } else {
                    tcg_gen_mov_tl(tcg_ctx, s->T0, tcg_ctx->cpu_seg_base[R_GS]);
                    tcg_gen_ld_tl(tcg_ctx, tcg_ctx->cpu_seg_base[R_GS], tcg_ctx->cpu_env,
                                  offsetof(CPUX86State, kernelgsbase));
                    tcg_gen_st_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                  offsetof(CPUX86State, kernelgsbase));
                }
                break;
            }
#endif
            goto illegal_op;

        case 0xf9: /* rdtscp */
            if (!(s->cpuid_ext2_features & CPUID_EXT2_RDTSCP)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_io_start(tcg_ctx);
            }
            gen_helper_rdtscp(tcg_ctx, tcg_ctx->cpu_env);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_jmp(s, s->pc - s->cs_base);
            }
            break;

        default:
            goto unknown_op;
        }
        break;

    case 0x108: /* invd */
    case 0x109: /* wbinvd */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_svm_check_intercept(s, pc_start, (b & 2) ? SVM_EXIT_INVD : SVM_EXIT_WBINVD);
            /* nothing to do */
        }
        break;
    case 0x63: /* arpl or movslS (x86_64) */
#ifdef TARGET_X86_64
        if (CODE64(s)) {
            int d_ot;
            /* d_ot is the size of destination */
            d_ot = dflag;

            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            rm = (modrm & 7) | REX_B(s);

            if (mod == 3) {
                gen_op_mov_v_reg(s, MO_32, s->T0, rm);
                /* sign extend */
                if (d_ot == MO_64) {
                    tcg_gen_ext32s_tl(tcg_ctx, s->T0, s->T0);
                }
                gen_op_mov_reg_v(s, d_ot, reg, s->T0);
            } else {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, MO_32 | MO_SIGN, s->T0, s->A0);
                gen_op_mov_reg_v(s, d_ot, reg, s->T0);
            }
        } else
#endif
        {
            TCGLabel *label1;
            TCGv t0, t1, t2, a0;

            if (!s->pe || s->vm86)
                goto illegal_op;
            t0 = tcg_temp_local_new(tcg_ctx);
            t1 = tcg_temp_local_new(tcg_ctx);
            t2 = tcg_temp_local_new(tcg_ctx);
            ot = MO_16;
            modrm = x86_ldub_code(env, s);
            reg = (modrm >> 3) & 7;
            mod = (modrm >> 6) & 3;
            rm = modrm & 7;
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, ot, t0, s->A0);
                a0 = tcg_temp_local_new(tcg_ctx);
                tcg_gen_mov_tl(tcg_ctx, a0, s->A0);
            } else {
                gen_op_mov_v_reg(s, ot, t0, rm);
                a0 = NULL;
            }
            gen_op_mov_v_reg(s, ot, t1, reg);
            tcg_gen_andi_tl(tcg_ctx, s->tmp0, t0, 3);
            tcg_gen_andi_tl(tcg_ctx, t1, t1, 3);
            tcg_gen_movi_tl(tcg_ctx, t2, 0);
            label1 = gen_new_label(tcg_ctx);
            tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GE, s->tmp0, t1, label1);
            tcg_gen_andi_tl(tcg_ctx, t0, t0, ~3);
            tcg_gen_or_tl(tcg_ctx, t0, t0, t1);
            tcg_gen_movi_tl(tcg_ctx, t2, CC_Z);
            gen_set_label(tcg_ctx, label1);
            if (mod != 3) {
                gen_op_st_v(s, ot, t0, a0);
                tcg_temp_free(tcg_ctx, a0);
           } else {
                gen_op_mov_reg_v(s, ot, rm, t0);
            }
            gen_compute_eflags(s);
            tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, ~CC_Z);
            tcg_gen_or_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, t2);
            tcg_temp_free(tcg_ctx, t0);
            tcg_temp_free(tcg_ctx, t1);
            tcg_temp_free(tcg_ctx, t2);
        }
        break;
    case 0x102: /* lar */
    case 0x103: /* lsl */
        {
            TCGLabel *label1;
            TCGv t0;
            if (!s->pe || s->vm86)
                goto illegal_op;
            ot = dflag != MO_16 ? MO_32 : MO_16;
            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            t0 = tcg_temp_local_new(tcg_ctx);
            gen_update_cc_op(s);
            if (b == 0x102) {
                gen_helper_lar(tcg_ctx, t0, tcg_ctx->cpu_env, s->T0);
            } else {
                gen_helper_lsl(tcg_ctx, t0, tcg_ctx->cpu_env, s->T0);
            }
            tcg_gen_andi_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_cc_src, CC_Z);
            label1 = gen_new_label(tcg_ctx);
            tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, s->tmp0, 0, label1);
            gen_op_mov_reg_v(s, ot, reg, t0);
            gen_set_label(tcg_ctx, label1);
            set_cc_op(s, CC_OP_EFLAGS);
            tcg_temp_free(tcg_ctx, t0);
        }
        break;
    case 0x118:
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        op = (modrm >> 3) & 7;
        switch(op) {
        case 0: /* prefetchnta */
        case 1: /* prefetchnt0 */
        case 2: /* prefetchnt0 */
        case 3: /* prefetchnt0 */
            if (mod == 3)
                goto illegal_op;
            gen_nop_modrm(env, s, modrm);
            /* nothing more to do */
            break;
        case 4: /* prefetchrst2 */
            if (mod == 3 || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            /* With PREFETCHRST this is PREFETCHRST2; without it the same
             * memory form is NOP0F18r4.  Both consume the complete address
             * encoding without performing an architectural access. */
            gen_nop_modrm(env, s, modrm);
            break;
        default: /* nop (multi byte) */
            gen_nop_modrm(env, s, modrm);
            break;
        }
        break;
    case 0x11a:
        modrm = x86_ldub_code(env, s);
        if (s->flags & HF_MPX_EN_MASK) {
            mod = (modrm >> 6) & 3;
            reg = ((modrm >> 3) & 7) | rex_r;
            if (prefixes & PREFIX_REPZ) {
                /* bndcl */
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                gen_bndck(env, s, modrm, TCG_COND_LTU, tcg_ctx->cpu_bndl[reg]);
            } else if (prefixes & PREFIX_REPNZ) {
                /* bndcu */
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                TCGv_i64 notu = tcg_temp_new_i64(tcg_ctx);
                tcg_gen_not_i64(tcg_ctx, notu, tcg_ctx->cpu_bndu[reg]);
                gen_bndck(env, s, modrm, TCG_COND_GTU, notu);
                tcg_temp_free_i64(tcg_ctx, notu);
            } else if (prefixes & PREFIX_DATA) {
                /* bndmov -- from reg/mem */
                if (reg >= 4 || s->aflag == MO_16) {
                    goto illegal_op;
                }
                if (mod == 3) {
                    int reg2 = (modrm & 7) | REX_B(s);
                    if (reg2 >= 4 || (prefixes & PREFIX_LOCK)) {
                        goto illegal_op;
                    }
                    if (s->flags & HF_MPX_IU_MASK) {
                        tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_bndl[reg2]);
                        tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], tcg_ctx->cpu_bndu[reg2]);
                    }
                } else {
                    gen_lea_modrm(env, s, modrm);
                    if (CODE64(s)) {
                        tcg_gen_qemu_ld_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], s->A0,
                                            s->mem_index, MO_LEQ);
                        tcg_gen_addi_tl(tcg_ctx, s->A0, s->A0, 8);
                        tcg_gen_qemu_ld_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], s->A0,
                                            s->mem_index, MO_LEQ);
                    } else {
                        tcg_gen_qemu_ld_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], s->A0,
                                            s->mem_index, MO_LEUL);
                        tcg_gen_addi_tl(tcg_ctx, s->A0, s->A0, 4);
                        tcg_gen_qemu_ld_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], s->A0,
                                            s->mem_index, MO_LEUL);
                    }
                    /* bnd registers are now in-use */
                    gen_set_hflag(s, HF_MPX_IU_MASK);
                }
            } else if (mod != 3) {
                /* bndldx */
                AddressParts a = gen_lea_modrm_0(env, s, modrm);
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16
                    || a.base < -1) {
                    goto illegal_op;
                }
                if (a.base >= 0) {
                    tcg_gen_addi_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[a.base], a.disp);
                } else {
                    tcg_gen_movi_tl(tcg_ctx, s->A0, 0);
                }
                gen_lea_v_seg(s, s->aflag, s->A0, a.def_seg, s->override);
                if (a.index >= 0) {
                    tcg_gen_mov_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[a.index]);
                } else {
                    tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                }
                if (CODE64(s)) {
                    gen_helper_bndldx64(tcg_ctx, tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_env, s->A0, s->T0);
                    tcg_gen_ld_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], tcg_ctx->cpu_env,
                                   offsetof(CPUX86State, mmx_t0.MMX_Q(0)));
                } else {
                    gen_helper_bndldx32(tcg_ctx, tcg_ctx->cpu_bndu[reg], tcg_ctx->cpu_env, s->A0, s->T0);
                    tcg_gen_ext32u_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_bndu[reg]);
                    tcg_gen_shri_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], tcg_ctx->cpu_bndu[reg], 32);
                }
                gen_set_hflag(s, HF_MPX_IU_MASK);
            }
        }
        gen_nop_modrm(env, s, modrm);
        break;
    case 0x11b:
        modrm = x86_ldub_code(env, s);
        if (s->flags & HF_MPX_EN_MASK) {
            mod = (modrm >> 6) & 3;
            reg = ((modrm >> 3) & 7) | rex_r;
            if (mod != 3 && (prefixes & PREFIX_REPZ)) {
                /* bndmk */
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                AddressParts a = gen_lea_modrm_0(env, s, modrm);
                if (a.base >= 0) {
                    tcg_gen_extu_tl_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_regs[a.base]);
                    if (!CODE64(s)) {
                        tcg_gen_ext32u_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_bndl[reg]);
                    }
                } else if (a.base == -1) {
                    /* no base register has lower bound of 0 */
                    tcg_gen_movi_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], 0);
                } else {
                    /* rip-relative generates #ud */
                    goto illegal_op;
                }
                tcg_gen_not_tl(tcg_ctx, s->A0, gen_lea_modrm_1(s, a));
                if (!CODE64(s)) {
                    tcg_gen_ext32u_tl(tcg_ctx, s->A0, s->A0);
                }
                tcg_gen_extu_tl_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], s->A0);
                /* bnd registers are now in-use */
                gen_set_hflag(s, HF_MPX_IU_MASK);
                break;
            } else if (prefixes & PREFIX_REPNZ) {
                /* bndcn */
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                gen_bndck(env, s, modrm, TCG_COND_GTU, tcg_ctx->cpu_bndu[reg]);
            } else if (prefixes & PREFIX_DATA) {
                /* bndmov -- to reg/mem */
                if (reg >= 4 || s->aflag == MO_16) {
                    goto illegal_op;
                }
                if (mod == 3) {
                    int reg2 = (modrm & 7) | REX_B(s);
                    if (reg2 >= 4 || (prefixes & PREFIX_LOCK)) {
                        goto illegal_op;
                    }
                    if (s->flags & HF_MPX_IU_MASK) {
                        tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg2], tcg_ctx->cpu_bndl[reg]);
                        tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg2], tcg_ctx->cpu_bndu[reg]);
                    }
                } else {
                    gen_lea_modrm(env, s, modrm);
                    if (CODE64(s)) {
                        tcg_gen_qemu_st_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], s->A0,
                                            s->mem_index, MO_LEQ);
                        tcg_gen_addi_tl(tcg_ctx, s->A0, s->A0, 8);
                        tcg_gen_qemu_st_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], s->A0,
                                            s->mem_index, MO_LEQ);
                    } else {
                        tcg_gen_qemu_st_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], s->A0,
                                            s->mem_index, MO_LEUL);
                        tcg_gen_addi_tl(tcg_ctx, s->A0, s->A0, 4);
                        tcg_gen_qemu_st_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], s->A0,
                                            s->mem_index, MO_LEUL);
                    }
                }
            } else if (mod != 3) {
                /* bndstx */
                AddressParts a = gen_lea_modrm_0(env, s, modrm);
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16
                    || a.base < -1) {
                    goto illegal_op;
                }
                if (a.base >= 0) {
                    tcg_gen_addi_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[a.base], a.disp);
                } else {
                    tcg_gen_movi_tl(tcg_ctx, s->A0, 0);
                }
                gen_lea_v_seg(s, s->aflag, s->A0, a.def_seg, s->override);
                if (a.index >= 0) {
                    tcg_gen_mov_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[a.index]);
                } else {
                    tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                }
                if (CODE64(s)) {
                    gen_helper_bndstx64(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->T0,
                                        tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_bndu[reg]);
                } else {
                    gen_helper_bndstx32(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->T0,
                                        tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_bndu[reg]);
                }
            }
        }
        gen_nop_modrm(env, s, modrm);
        break;
    case 0x119:
    case 0x11c: /* nop (multi byte) */
    case 0x11d: /* nop (multi byte) */
    case 0x11e: /* nop (multi byte) */
    case 0x11f: /* nop (multi byte) */
        modrm = x86_ldub_code(env, s);
        gen_nop_modrm(env, s, modrm);
        break;
    case 0x120: /* mov reg, crN */
    case 0x122: /* mov crN, reg */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            modrm = x86_ldub_code(env, s);
            /* Ignore the mod bits (assume (modrm&0xc0)==0xc0).
             * AMD documentation (24594.pdf) and testing of
             * intel 386 and 486 processors all show that the mod bits
             * are assumed to be 1's, regardless of actual values.
             */
            rm = (modrm & 7) | REX_B(s);
            reg = ((modrm >> 3) & 7) | rex_r;
            if (CODE64(s))
                ot = MO_64;
            else
                ot = MO_32;
            if ((prefixes & PREFIX_LOCK) && (reg == 0) &&
                (s->cpuid_ext3_features & CPUID_EXT3_CR8LEG)) {
                reg = 8;
            }
            switch(reg) {
            case 0:
            case 2:
            case 3:
            case 4:
            case 8:
                gen_update_cc_op(s);
                gen_jmp_im(s, pc_start - s->cs_base);
                if (b & 2) {
                    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                        gen_io_start(tcg_ctx);
                    }
                    gen_op_mov_v_reg(s, ot, s->T0, rm);
                    gen_helper_write_crN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, reg),
                                         s->T0);
                    gen_jmp_im(s, s->pc - s->cs_base);
                    gen_eob(s);
                } else {
                    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                        gen_io_start(tcg_ctx);
                    }
                    gen_helper_read_crN(tcg_ctx, s->T0, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, reg));
                    gen_op_mov_reg_v(s, ot, rm, s->T0);
                    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                        gen_io_end(tcg_ctx);
                    }
                }
                break;
            default:
                goto unknown_op;
            }
        }
        break;
    case 0x121: /* mov reg, drN */
    case 0x123: /* mov drN, reg */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            modrm = x86_ldub_code(env, s);
            /* Ignore the mod bits (assume (modrm&0xc0)==0xc0).
             * AMD documentation (24594.pdf) and testing of
             * intel 386 and 486 processors all show that the mod bits
             * are assumed to be 1's, regardless of actual values.
             */
            rm = (modrm & 7) | REX_B(s);
            reg = ((modrm >> 3) & 7) | rex_r;
            if (CODE64(s))
                ot = MO_64;
            else
                ot = MO_32;
            if (reg >= 8) {
                goto illegal_op;
            }
            if (b & 2) {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_WRITE_DR0 + reg);
                gen_op_mov_v_reg(s, ot, s->T0, rm);
                tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, reg);
                gen_helper_set_dr(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32, s->T0);
                gen_jmp_im(s, s->pc - s->cs_base);
                gen_eob(s);
            } else {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_READ_DR0 + reg);
                tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, reg);
                gen_helper_get_dr(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->tmp2_i32);
                gen_op_mov_reg_v(s, ot, rm, s->T0);
            }
        }
        break;
    case 0x106: /* clts */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_WRITE_CR0);
            gen_helper_clts(tcg_ctx, tcg_ctx->cpu_env);
            /* abort block because static cpu state changed */
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
        }
        break;
    /* MMX/3DNow!/SSE/SSE2/SSE3/SSSE3/SSE4 support */
    case 0x1c3: /* MOVNTI reg, mem */
        if (!(s->cpuid_features & CPUID_SSE2))
            goto illegal_op;
        ot = mo_64_32(dflag);
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        reg = ((modrm >> 3) & 7) | rex_r;
        /* generate a generic store */
        gen_ldst_modrm(env, s, modrm, ot, reg, 1);
        break;
    case 0x1ae:
        modrm = x86_ldub_code(env, s);
        switch (modrm) {
        CASE_MODRM_MEM_OP(0): /* fxsave */
            if (!(s->cpuid_features & CPUID_FXSR)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            if ((s->flags & HF_EM_MASK) || (s->flags & HF_TS_MASK)) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            gen_helper_fxsave(tcg_ctx, tcg_ctx->cpu_env, s->A0);
            break;

        CASE_MODRM_MEM_OP(1): /* fxrstor */
            if (!(s->cpuid_features & CPUID_FXSR)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            if ((s->flags & HF_EM_MASK) || (s->flags & HF_TS_MASK)) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            gen_helper_fxrstor(tcg_ctx, tcg_ctx->cpu_env, s->A0);
            break;

        CASE_MODRM_MEM_OP(2): /* ldmxcsr */
            if ((s->flags & HF_EM_MASK) || !(s->flags & HF_OSFXSR_MASK)) {
                goto illegal_op;
            }
            if (s->flags & HF_TS_MASK) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0, s->mem_index, MO_LEUL);
            gen_helper_ldmxcsr(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
            break;

        CASE_MODRM_MEM_OP(3): /* stmxcsr */
            if ((s->flags & HF_EM_MASK) || !(s->flags & HF_OSFXSR_MASK)) {
                goto illegal_op;
            }
            if (s->flags & HF_TS_MASK) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            gen_helper_update_mxcsr(tcg_ctx, tcg_ctx->cpu_env);
            tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, mxcsr));
            gen_op_st_v(s, MO_32, s->T0, s->A0);
            break;

        CASE_MODRM_MEM_OP(4): /* xsave */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (prefixes & (PREFIX_LOCK | PREFIX_DATA
                                | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            gen_lea_modrm(env, s, modrm);
            tcg_gen_concat_tl_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_regs[R_EAX],
                                  tcg_ctx->cpu_regs[R_EDX]);
            gen_helper_xsave(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->tmp1_i64);
            break;

        CASE_MODRM_MEM_OP(5): /* xrstor */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (prefixes & (PREFIX_LOCK | PREFIX_DATA
                                | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            gen_lea_modrm(env, s, modrm);
            tcg_gen_concat_tl_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_regs[R_EAX],
                                  tcg_ctx->cpu_regs[R_EDX]);
            gen_helper_xrstor(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->tmp1_i64);
            /* XRSTOR is how MPX is enabled, which changes how
               we translate.  Thus we need to end the TB.  */
            gen_update_cc_op(s);
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        CASE_MODRM_MEM_OP(6): /* xsaveopt / clwb */
            if (prefixes & PREFIX_LOCK) {
                goto illegal_op;
            }
            if (prefixes & PREFIX_DATA) {
                /* clwb */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_CLWB)) {
                    goto illegal_op;
                }
                gen_nop_modrm(env, s, modrm);
            } else {
                /* xsaveopt */
                if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                    || (s->cpuid_xsave_features & CPUID_XSAVE_XSAVEOPT) == 0
                    || (prefixes & (PREFIX_REPZ | PREFIX_REPNZ))) {
                    goto illegal_op;
                }
                gen_lea_modrm(env, s, modrm);
                tcg_gen_concat_tl_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_regs[R_EAX],
                                      tcg_ctx->cpu_regs[R_EDX]);
                gen_helper_xsaveopt(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->tmp1_i64);
            }
            break;

        CASE_MODRM_MEM_OP(7): /* clflush / clflushopt */
            if (prefixes & PREFIX_LOCK) {
                goto illegal_op;
            }
            if (prefixes & PREFIX_DATA) {
                /* clflushopt */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_CLFLUSHOPT)) {
                    goto illegal_op;
                }
            } else {
                /* clflush */
                if ((s->prefix & (PREFIX_REPZ | PREFIX_REPNZ))
                    || !(s->cpuid_features & CPUID_CLFLUSH)) {
                    goto illegal_op;
                }
            }
            gen_nop_modrm(env, s, modrm);
            break;

        case 0xc0: /* rdfsbase (f3 0f ae /0) */
        case 0xc1: /* rdfsbase (f3 0f ae /0) */
        case 0xc2: /* rdfsbase (f3 0f ae /0) */
        case 0xc3: /* rdfsbase (f3 0f ae /0) */
        case 0xc4: /* rdfsbase (f3 0f ae /0) */
        case 0xc5: /* rdfsbase (f3 0f ae /0) */
        case 0xc6: /* rdfsbase (f3 0f ae /0) */
        case 0xc7: /* rdfsbase (f3 0f ae /0) */

        case 0xc8: /* rdgsbase (f3 0f ae /1) */
        case 0xc9: /* rdgsbase (f3 0f ae /1) */
        case 0xca: /* rdgsbase (f3 0f ae /1) */
        case 0xcb: /* rdgsbase (f3 0f ae /1) */
        case 0xcc: /* rdgsbase (f3 0f ae /1) */
        case 0xcd: /* rdgsbase (f3 0f ae /1) */
        case 0xce: /* rdgsbase (f3 0f ae /1) */
        case 0xcf: /* rdgsbase (f3 0f ae /1) */

        case 0xd0: /* wrfsbase (f3 0f ae /2) */
        case 0xd1: /* wrfsbase (f3 0f ae /2) */
        case 0xd2: /* wrfsbase (f3 0f ae /2) */
        case 0xd3: /* wrfsbase (f3 0f ae /2) */
        case 0xd4: /* wrfsbase (f3 0f ae /2) */
        case 0xd5: /* wrfsbase (f3 0f ae /2) */
        case 0xd6: /* wrfsbase (f3 0f ae /2) */
        case 0xd7: /* wrfsbase (f3 0f ae /2) */

        case 0xd8: /* wrgsbase (f3 0f ae /3) */
        case 0xd9: /* wrgsbase (f3 0f ae /3) */
        case 0xda: /* wrgsbase (f3 0f ae /3) */
        case 0xdb: /* wrgsbase (f3 0f ae /3) */
        case 0xdc: /* wrgsbase (f3 0f ae /3) */
        case 0xdd: /* wrgsbase (f3 0f ae /3) */
        case 0xde: /* wrgsbase (f3 0f ae /3) */
        case 0xdf: /* wrgsbase (f3 0f ae /3) */
            if (CODE64(s)
                && (prefixes & PREFIX_REPZ)
                && !(prefixes & PREFIX_LOCK)
                && (s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_FSGSBASE)) {
                TCGv base, treg, src, dst;

                /* Preserve hflags bits by testing CR4 at runtime.  */
                tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, CR4_FSGSBASE_MASK);
                gen_helper_cr4_testbit(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);

                base = tcg_ctx->cpu_seg_base[modrm & 8 ? R_GS : R_FS];
                treg = tcg_ctx->cpu_regs[(modrm & 7) | REX_B(s)];

                if (modrm & 0x10) {
                    /* wr*base */
                    dst = base, src = treg;
                } else {
                    /* rd*base */
                    dst = treg, src = base;
                }

                if (s->dflag == MO_32) {
                    tcg_gen_ext32u_tl(tcg_ctx, dst, src);
                } else {
                    tcg_gen_mov_tl(tcg_ctx, dst, src);
                }
                break;
            }
            goto unknown_op;

        case 0xf8: /* sfence / pcommit */
            if (prefixes & PREFIX_DATA) {
                /* pcommit */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_PCOMMIT)
                    || (prefixes & PREFIX_LOCK)) {
                    goto illegal_op;
                }
                break;
            }
            /* fallthru */
        case 0xf9: /* sfence */
        case 0xfa: /* sfence */
        case 0xfb: /* sfence */
        case 0xfc: /* sfence */
        case 0xfd: /* sfence */
        case 0xfe: /* sfence */
        case 0xff: /* sfence */
            if (!(s->cpuid_features & CPUID_SSE)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            tcg_gen_mb(tcg_ctx, TCG_MO_ST_ST | TCG_BAR_SC);
            break;
        case 0xe8: /* lfence */
        case 0xe9: /* lfence */
        case 0xea: /* lfence */
        case 0xeb: /* lfence */
        case 0xec: /* lfence */
        case 0xed: /* lfence */
        case 0xee: /* lfence */
        case 0xef: /* lfence */
            if (!(s->cpuid_features & CPUID_SSE)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            tcg_gen_mb(tcg_ctx, TCG_MO_LD_LD | TCG_BAR_SC);
            break;
        case 0xf0: /* mfence */
        case 0xf1: /* mfence */
        case 0xf2: /* mfence */
        case 0xf3: /* mfence */
        case 0xf4: /* mfence */
        case 0xf5: /* mfence */
        case 0xf6: /* mfence */
        case 0xf7: /* mfence */
            if (!(s->cpuid_features & CPUID_SSE2)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            tcg_gen_mb(tcg_ctx, TCG_MO_ALL | TCG_BAR_SC);
            break;

        default:
            goto unknown_op;
        }
        break;

    case 0x10d: /* 3DNow! prefetch(w) */
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        gen_nop_modrm(env, s, modrm);
        break;
    case 0x1aa: /* rsm */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_RSM);
        if (!(s->flags & HF_SMM_MASK))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_jmp_im(s, s->pc - s->cs_base);
        gen_helper_rsm(tcg_ctx, tcg_ctx->cpu_env);
        gen_eob(s);
        break;
    case 0x1b8: /* SSE4.2 popcnt */
        if ((prefixes & (PREFIX_REPZ | PREFIX_LOCK | PREFIX_REPNZ)) !=
             PREFIX_REPZ)
            goto illegal_op;
        if (!(s->cpuid_ext_features & CPUID_EXT_POPCNT))
            goto illegal_op;

        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;

        /* dflag already applies the architectural REX.W-over-66 priority. */
        ot = dflag;

        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_extu(tcg_ctx, ot, s->T0);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0);
        tcg_gen_ctpop_tl(tcg_ctx, s->T0, s->T0);
        gen_op_mov_reg_v(s, ot, reg, s->T0);

        set_cc_op(s, CC_OP_POPCNT);
        break;
    case 0x10e:
    case 0x10f:
        /* 3DNow! instructions, ignore prefixes */
        s->prefix &= ~(PREFIX_REPZ | PREFIX_REPNZ | PREFIX_DATA);
        /* fall through */
    case 0x110:
    case 0x111:
    case 0x112:
    case 0x113:
    case 0x114:
    case 0x115:
    case 0x116:
    case 0x117:

    case 0x128:
    case 0x129:
    case 0x12a:
    case 0x12b:
    case 0x12c:
    case 0x12d:
    case 0x12e:
    case 0x12f:

    case 0x138:
        if (b == 0x138 && !(prefixes & PREFIX_VEX) &&
            (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) &&
            translator_ldub(tcg_ctx, env, s->pc) == 0xf8 &&
            (translator_ldub(tcg_ctx, env, s->pc + 1) >> 6) == 3) {
            /* Legacy F2/F3 0F 38 F8 /r is USER_MSR.  Decode its complete
             * ModRM form before failing closed: without IA32_USER_MSR_CTL
             * bitmap state, ENABLE is architecturally clear and execution
             * must #UD even if USER_MSR were explicitly enumerated. */
            (void)x86_ldub_code(env, s);
            (void)x86_ldub_code(env, s);
            if (!(s->cpuid_features & CPUID_MSR) ||
                !(s->cpuid_7_1_edx_features & CPUID_7_1_EDX_USER_MSR)) {
                goto illegal_op;
            }
            goto illegal_op;
        }
        /* fall through */
    case 0x139:
    case 0x13a:

    // case 0x150 ... 0x179:

    case 0x17c:
    case 0x17d:
    case 0x17e:
    case 0x17f:
    case 0x1c2:
    case 0x1c4:
    case 0x1c5:
    case 0x1c6:
    // case 0x1d0 ... 0x1fe:
        gen_sse(env, s, b, pc_start, rex_r);
        break;
    default:
        if (b >= 0x150 && b <= 0x179) {
            gen_sse(env, s, b, pc_start, rex_r);
            break;
        }

        if (b >= 0x1d0 && b <= 0x1fe) {
            gen_sse(env, s, b, pc_start, rex_r);
            break;
        }

        goto unknown_op;
    }

 decoded:
    if (insn_hook) {
        // Unicorn: patch the callback to have the proper instruction size.
        if (prev_op) {
            // As explained further up in the function where prev_op is
            // assigned, we move forward in the tail queue, so we're modifying the
            // move instruction generated by gen_uc_tracecode() that contains
            // the instruction size to assign the proper size (replacing 0xF1F1F1F1).
            tcg_op = QTAILQ_NEXT(prev_op, link);
        } else {
            // this instruction is the first emulated code ever,
            // so the operand is the first operand
            tcg_op = QTAILQ_FIRST(&tcg_ctx->ops);
        }
        tcg_op->args[1] = s->pc - pc_start;
    }

    return s->pc;

 illegal_op:
    gen_illegal_opcode(s);
    return s->pc;

 unknown_op:
    gen_unknown_opcode(env, s);
    return s->pc;
 }

void tcg_x86_init(struct uc_struct *uc)
{
    static const char reg_names[CPU_NB_REGS][4] = {
#ifdef TARGET_X86_64
        [R_EAX] = "rax",
        [R_EBX] = "rbx",
        [R_ECX] = "rcx",
        [R_EDX] = "rdx",
        [R_ESI] = "rsi",
        [R_EDI] = "rdi",
        [R_EBP] = "rbp",
        [R_ESP] = "rsp",
        [8]  = "r8",
        [9]  = "r9",
        [10] = "r10",
        [11] = "r11",
        [12] = "r12",
        [13] = "r13",
        [14] = "r14",
        [15] = "r15",
#else
        [R_EAX] = "eax",
        [R_EBX] = "ebx",
        [R_ECX] = "ecx",
        [R_EDX] = "edx",
        [R_ESI] = "esi",
        [R_EDI] = "edi",
        [R_EBP] = "ebp",
        [R_ESP] = "esp",
#endif
    };
    static const char seg_base_names[6][8] = {
        [R_CS] = "cs_base",
        [R_DS] = "ds_base",
        [R_ES] = "es_base",
        [R_FS] = "fs_base",
        [R_GS] = "gs_base",
        [R_SS] = "ss_base",
    };
    static const char bnd_regl_names[4][8] = {
        "bnd0_lb", "bnd1_lb", "bnd2_lb", "bnd3_lb"
    };
    static const char bnd_regu_names[4][8] = {
        "bnd0_ub", "bnd1_ub", "bnd2_ub", "bnd3_ub"
    };
    int i;
    TCGContext *tcg_ctx = uc->tcg_ctx;

    tcg_ctx->cpu_cc_op = tcg_global_mem_new_i32(tcg_ctx, tcg_ctx->cpu_env,
                                       offsetof(CPUX86State, cc_op), "cc_op");
    tcg_ctx->cpu_cc_dst = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env, offsetof(CPUX86State, cc_dst),
                                    "cc_dst");
    tcg_ctx->cpu_cc_src = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env, offsetof(CPUX86State, cc_src),
                                    "cc_src");
    tcg_ctx->cpu_cc_src2 = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env, offsetof(CPUX86State, cc_src2),
                                     "cc_src2");

    for (i = 0; i < CPU_NB_REGS; ++i) {
        tcg_ctx->cpu_regs[i] = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env,
                                         offsetof(CPUX86State, regs[i]),
                                         reg_names[i]);
    }

    for (i = 0; i < 6; ++i) {
        tcg_ctx->cpu_seg_base[i]
            = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State, segs[i].base),
                                 seg_base_names[i]);
    }

    for (i = 0; i < 4; ++i) {
        tcg_ctx->cpu_bndl[i]
            = tcg_global_mem_new_i64(tcg_ctx, tcg_ctx->cpu_env,
                                     offsetof(CPUX86State, bnd_regs[i].lb),
                                     bnd_regl_names[i]);
        tcg_ctx->cpu_bndu[i]
            = tcg_global_mem_new_i64(tcg_ctx, tcg_ctx->cpu_env,
                                     offsetof(CPUX86State, bnd_regs[i].ub),
                                     bnd_regu_names[i]);
    }
}

static void i386_tr_init_disas_context(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    TCGContext *tcg_ctx = cpu->uc->tcg_ctx;
    CPUX86State *env = cpu->env_ptr;
    uint32_t flags = dc->base.tb->flags;
    target_ulong cs_base = dc->base.tb->cs_base;

    // unicorn setup
    dc->uc = cpu->uc;
    dc->pe = (flags >> HF_PE_SHIFT) & 1;
    dc->code32 = (flags >> HF_CS32_SHIFT) & 1;
    dc->ss32 = (flags >> HF_SS32_SHIFT) & 1;
    dc->addseg = (flags >> HF_ADDSEG_SHIFT) & 1;
    dc->f_st = 0;
    dc->vm86 = (flags >> VM_SHIFT) & 1;
    dc->cpl = (flags >> HF_CPL_SHIFT) & 3;
    dc->iopl = (flags >> IOPL_SHIFT) & 3;
    dc->tf = (flags >> TF_SHIFT) & 1;
    dc->cc_op = CC_OP_DYNAMIC;
    dc->cc_op_dirty = false;
    dc->cs_base = cs_base;
    dc->popl_esp_hack = 0;
    /* select memory access functions */
    dc->mem_index = 0;
    dc->mem_index = cpu_mmu_index(env, false);
    dc->cpuid_features = env->features[FEAT_1_EDX];
    dc->cpuid_ext_features = env->features[FEAT_1_ECX];
    dc->cpuid_ext2_features = env->features[FEAT_8000_0001_EDX];
    dc->cpuid_ext3_features = env->features[FEAT_8000_0001_ECX];
    dc->cpuid_7_0_ebx_features = env->features[FEAT_7_0_EBX];
    dc->cpuid_7_0_ecx_features = env->features[FEAT_7_0_ECX];
    dc->cpuid_7_0_edx_features = env->features[FEAT_7_0_EDX];
    dc->cpuid_7_1_eax_features = env->features[FEAT_7_1_EAX];
    dc->cpuid_7_1_ecx_features = env->features[FEAT_7_1_ECX];
    dc->cpuid_7_1_edx_features = env->features[FEAT_7_1_EDX];
    dc->cpuid_29_0_ebx_features = env->features[FEAT_29_0_EBX];
    dc->cpuid_xsave_features = env->features[FEAT_XSAVE];
#ifdef TARGET_X86_64
    dc->lma = (flags >> HF_LMA_SHIFT) & 1;
    dc->code64 = (flags >> HF_CS64_SHIFT) & 1;
#endif
    dc->flags = flags;
    dc->jmp_opt = !(dc->tf || dc->base.singlestep_enabled ||
                    (flags & HF_INHIBIT_IRQ_MASK));
    /* Do not optimize repz jumps at all in icount mode, because
       rep movsS instructions are execured with different paths
       in !repz_opt and repz_opt modes. The first one was used
       always except single step mode. And this setting
       disables jumps optimization and control paths become
       equivalent in run and single step modes.
       Now there will be no jump optimization for repz in
       record/replay modes and there will always be an
       additional step for ecx=0 when icount is enabled.
     */
    dc->repz_opt = !dc->jmp_opt && !(tb_cflags(dc->base.tb) & CF_USE_ICOUNT);
#if 0
    /* check addseg logic */
    if (!dc->addseg && (dc->vm86 || !dc->pe || !dc->code32))
        printf("ERROR addseg\n");
#endif

    dc->T0 = tcg_temp_new(tcg_ctx);
    dc->T1 = tcg_temp_new(tcg_ctx);
    dc->A0 = tcg_temp_new(tcg_ctx);

    dc->tmp0 = tcg_temp_new(tcg_ctx);
    dc->tmp1_i64 = tcg_temp_new_i64(tcg_ctx);
    dc->tmp2_i32 = tcg_temp_new_i32(tcg_ctx);
    dc->tmp3_i32 = tcg_temp_new_i32(tcg_ctx);
    dc->tmp4 = tcg_temp_new(tcg_ctx);
    dc->ptr0 = tcg_temp_new_ptr(tcg_ctx);
    dc->ptr1 = tcg_temp_new_ptr(tcg_ctx);
    dc->cc_srcT = tcg_temp_local_new(tcg_ctx);
}

static void i386_tr_tb_start(DisasContextBase *db, CPUState *cpu)
{
}

static void i386_tr_insn_start(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    TCGContext *tcg_ctx = dc->uc->tcg_ctx;

    dc->prev_pc = dc->base.pc_next - dc->cs_base;
    tcg_gen_insn_start(tcg_ctx, dc->base.pc_next, dc->cc_op);
}

static bool i386_tr_breakpoint_check(DisasContextBase *dcbase, CPUState *cpu,
                                     const CPUBreakpoint *bp)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);

    /* If RF is set, suppress an internally generated breakpoint.  */
    int flags = dc->base.tb->flags & HF_RF_MASK ? BP_GDB : BP_ANY;
    if (bp->flags & flags) {
        gen_debug(dc, dc->base.pc_next - dc->cs_base);
        dc->base.is_jmp = DISAS_NORETURN;
        /* The address covered by the breakpoint must be included in
           [tb->pc, tb->pc + tb->size) in order to for it to be
           properly cleared -- thus we increment the PC here so that
           the generic logic setting tb->size later does the right thing.  */
        dc->base.pc_next += 1;
        return true;
    } else {
        return false;
    }
}

static void i386_tr_translate_insn(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    target_ulong pc_next;

    pc_next = disas_insn(dc, cpu);

    if (dc->tf || (dc->base.tb->flags & HF_INHIBIT_IRQ_MASK)) {
        /* if single step mode, we generate only one instruction and
           generate an exception */
        /* if irq were inhibited with HF_INHIBIT_IRQ_MASK, we clear
           the flag and abort the translation to give the irqs a
           chance to happen */
        dc->base.is_jmp = DISAS_TOO_MANY;
    } else if (dc->base.is_jmp == DISAS_NEXT
               && ((pc_next & TARGET_PAGE_MASK)
                   != ((pc_next + TARGET_MAX_INSN_SIZE - 1)
                       & TARGET_PAGE_MASK)
                   || (pc_next & ~TARGET_PAGE_MASK) == 0)
               && !uc_addr_is_exit(dc->uc, pc_next)) {
        /* Start a new TB before speculative decoding can cross a page.
           Otherwise a translation-time fetch exception would discard all
           instructions already translated into the current TB. Keep an exit
           address in this TB so it can stop without fetching an unmapped page.
         */
        dc->base.is_jmp = DISAS_TOO_MANY;
    } else if ((pc_next - dc->base.pc_first) >= (TARGET_PAGE_SIZE - 32)) {
        dc->base.is_jmp = DISAS_TOO_MANY;
    }

    dc->base.pc_next = pc_next;
}

static void i386_tr_tb_stop(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);

    if (dc->base.is_jmp == DISAS_TOO_MANY) {
        gen_jmp_im(dc, dc->base.pc_next - dc->cs_base);
        gen_eob(dc);
    }
}

static void i386_sync_pc(DisasContextBase *db, CPUState *cpu)
{
    DisasContext *dc = container_of(db, DisasContext, base);

    gen_jmp_im(dc, dc->base.pc_next - dc->cs_base);
}

static const TranslatorOps i386_tr_ops = {
    .init_disas_context = i386_tr_init_disas_context,
    .tb_start           = i386_tr_tb_start,
    .insn_start         = i386_tr_insn_start,
    .breakpoint_check   = i386_tr_breakpoint_check,
    .translate_insn     = i386_tr_translate_insn,
    .tb_stop            = i386_tr_tb_stop,
    .pc_sync            = i386_sync_pc,
};

/* generate intermediate code for basic block 'tb'.  */
void gen_intermediate_code(CPUState *cpu, TranslationBlock *tb, int max_insns)
{
    DisasContext dc;

    memset(&dc, 0, sizeof(dc));
    translator_loop(&i386_tr_ops, &dc.base, cpu, tb, max_insns);
}

void restore_state_to_opc(CPUX86State *env, TranslationBlock *tb,
                          target_ulong *data)
{
    int cc_op = data[1];
    env->eip = data[0] - tb->cs_base;
    if (cc_op != CC_OP_DYNAMIC) {
        env->cc_op = cc_op;
    }
}
