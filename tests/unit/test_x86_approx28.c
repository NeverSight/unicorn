#include "unicorn_test.h"

static const uint64_t code_start = UINT64_C(0x1000);
static const uint64_t code_size = UINT64_C(0x2000);

typedef enum Approx28Kind {
    APPROX28_RCP,
    APPROX28_RSQRT,
    APPROX28_EXP2,
} Approx28Kind;

typedef struct TestApprox28Op {
    const char *name;
    Approx28Kind kind;
    bool scalar;
    bool is_double;
} TestApprox28Op;

typedef struct InterruptRecord {
    uint32_t vector;
    uint32_t count;
} InterruptRecord;

static const uint32_t source32[16] = {
    0x40400000, 0x40000000, 0x00000000, 0x80000000,
    0x7f800000, 0xff800000, 0x7fc12345, 0x7f812345,
    0xc0000000, 0x00400001, 0x80400001, 0x7f7fffff,
    0x3f800001, 0x3fc00000, 0x40800000, 0xc0400000,
};

static const uint32_t reference32[3][16] = {
    {
        0x3eaaaaab, 0x3f000000, 0x7f800000, 0xff800000,
        0x00000000, 0x80000000, 0x7fc12345, 0x7fc12345,
        0xbf000000, 0x7f800000, 0xff800000, 0x00000000,
        0x3f7ffffe, 0x3f2aaaab, 0x3e800000, 0xbeaaaaab,
    },
    {
        0x3f13cd3a, 0x3f3504f3, 0x7f800000, 0xff800000,
        0x00000000, 0xffc00000, 0x7fc12345, 0x7fc12345,
        0xffc00000, 0x7f800000, 0xff800000, 0x1f800000,
        0x3f7fffff, 0x3f5105ec, 0x3f000000, 0xffc00000,
    },
    {
        0x41000000, 0x40800000, 0x3f800000, 0x3f800000,
        0x7f800000, 0x00000000, 0x7fc12345, 0x7fc12345,
        0x3e800000, 0x3f800000, 0x3f800000, 0x7f800000,
        0x40000001, 0x403504f3, 0x41800000, 0x3e000000,
    },
};

static const uint8_t flags32[3][16] = {
    {0, 0, 4, 4, 0, 0, 0, 1, 0, 4, 4, 0, 0, 0, 0, 0},
    {0, 0, 4, 4, 0, 1, 0, 1, 1, 4, 4, 0, 0, 0, 0, 1},
    {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 0},
};

static const uint64_t source64[8] = {
    UINT64_C(0x4008000000000000), UINT64_C(0x4000000000000000),
    UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
    UINT64_C(0x7ff0000000000000), UINT64_C(0x7ff0123456789abc),
    UINT64_C(0xc000000000000000), UINT64_C(0x0008000000000001),
};

static const uint64_t reference64[3][8] = {
    {
        UINT64_C(0x3fd5555555100000), UINT64_C(0x3fe0000000000000),
        UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
        UINT64_C(0x0000000000000000), UINT64_C(0x7ff8123456789abc),
        UINT64_C(0xbfe0000000000000), UINT64_C(0x7ff0000000000000),
    },
    {
        UINT64_C(0x3fe279a745800000), UINT64_C(0x3fe6a09e66500000),
        UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
        UINT64_C(0x0000000000000000), UINT64_C(0x7ff8123456789abc),
        UINT64_C(0xfff8000000000000), UINT64_C(0x7ff0000000000000),
    },
    {
        UINT64_C(0x4020000000000000), UINT64_C(0x4010000000000000),
        UINT64_C(0x3ff0000000000000), UINT64_C(0x3ff0000000000000),
        UINT64_C(0x7ff0000000000000), UINT64_C(0x7ff8123456789abc),
        UINT64_C(0x3fd0000000000000), UINT64_C(0x3ff0000000000000),
    },
};

static const uint8_t flags64[3][8] = {
    {0, 0, 4, 4, 0, 1, 0, 4},
    {0, 0, 4, 4, 0, 1, 1, 4},
    {0, 0, 0, 0, 0, 1, 0, 0},
};

static void setup_x86(uc_engine **uc, const uint8_t *code, size_t size)
{
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, uc));
    OK(uc_ctl_set_cpu_model(*uc, UC_CPU_X86_KNIGHTSMILL));
    OK(uc_mem_map(*uc, code_start, code_size, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void record_interrupt(uc_engine *uc, uint32_t intno, void *user_data)
{
    InterruptRecord *record = user_data;

    record->vector = intno;
    record->count++;
    OK(uc_emu_stop(uc));
}

static void encode_approx28(uint8_t code[6], const TestApprox28Op *op,
                            unsigned int dst, unsigned int src1,
                            unsigned int src2, unsigned int mask,
                            bool zeroing, bool sae, unsigned int ll)
{
    uint8_t p0 = 0xf2;
    uint8_t p1 = (op->is_double ? 0x80 : 0) | 0x05;
    uint8_t p2;
    uint8_t opcode;

    TEST_CHECK(dst < 32 && src1 < 32 && src2 < 32 && mask < 8 && ll < 4);
    if (dst & 8) {
        p0 &= (uint8_t)~0x80;
    }
    if (dst & 16) {
        p0 &= (uint8_t)~0x10;
    }
    if (src2 & 8) {
        p0 &= (uint8_t)~0x20;
    }
    if (src2 & 16) {
        p0 &= (uint8_t)~0x40;
    }

    if (op->scalar) {
        p1 |= ((~src1) & 15) << 3;
        p2 = (src1 & 16) ? 0 : 0x08;
        opcode = op->kind == APPROX28_RCP ? 0xcb : 0xcd;
    } else {
        p1 |= 0x78;
        p2 = 0x08;
        opcode = op->kind == APPROX28_RCP
                     ? 0xca
                     : op->kind == APPROX28_RSQRT ? 0xcc : 0xc8;
    }

    code[0] = 0x62;
    code[1] = p0;
    code[2] = p1;
    code[3] = (uint8_t)(p2 | (ll << 5) | mask |
                        (zeroing ? 0x80 : 0) | (sae ? 0x10 : 0));
    code[4] = opcode;
    code[5] = (uint8_t)(0xc0 | ((dst & 7) << 3) | (src2 & 7));
}

static bool run_packed(const TestApprox28Op *op, unsigned int mask_reg,
                       uint64_t mask_value, bool zeroing, bool sae)
{
    const size_t element_bytes = op->is_double ? 8 : 4;
    const size_t elements = 64 / element_bytes;
    const uint64_t effective_mask = mask_reg ? mask_value : UINT64_MAX;
    const void *source = op->is_double ? (const void *)source64
                                       : (const void *)source32;
    const void *reference = op->is_double
                                ? (const void *)reference64[op->kind]
                                : (const void *)reference32[op->kind];
    const uint8_t *lane_flags = op->is_double ? flags64[op->kind]
                                              : flags32[op->kind];
    uint8_t initial[64];
    uint8_t expected[64];
    uint8_t observed[64];
    uint8_t source_after[64];
    uint8_t code[6];
    uint32_t mxcsr = UINT32_C(0x1fa0);
    uint32_t expected_flags = 0;
    uint64_t observed_mask = mask_value;
    uint64_t rflags = UINT64_C(0xcd7);
    uc_engine *uc;

    for (size_t byte = 0; byte < sizeof(initial); ++byte) {
        initial[byte] = (uint8_t)(0x71 + byte * 17);
    }
    memcpy(expected, initial, sizeof(expected));
    for (size_t element = 0; element < elements; ++element) {
        if ((effective_mask >> element) & 1) {
            memcpy(expected + element * element_bytes,
                   (const uint8_t *)reference + element * element_bytes,
                   element_bytes);
            expected_flags |= lane_flags[element];
        } else if (zeroing) {
            memset(expected + element * element_bytes, 0, element_bytes);
        }
    }
    if (sae) {
        expected_flags = 0;
    }
    encode_approx28(code, op, 31, 0, 30, mask_reg, zeroing, sae, 2);

    setup_x86(&uc, code, sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source));
    if (mask_reg) {
        OK(uc_reg_write(uc, UC_X86_REG_K0 + mask_reg, &observed_mask));
    }
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM30, source_after));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    if (mask_reg) {
        OK(uc_reg_read(uc, UC_X86_REG_K0 + mask_reg, &observed_mask));
    }

    TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                "%s packed result mismatch", op->name);
    TEST_CHECK_(memcmp(source_after, source, sizeof(source_after)) == 0,
                "%s changed source", op->name);
    TEST_CHECK_(mxcsr == (UINT32_C(0x1fa0) | expected_flags),
                "%s MXCSR mismatch: 0x%x", op->name, mxcsr);
    TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS", op->name);
    TEST_CHECK_(!mask_reg || observed_mask == mask_value,
                "%s changed writemask", op->name);
    OK(uc_close(uc));
    return true;
}

static bool run_scalar(const TestApprox28Op *op, unsigned int mask_reg,
                       uint64_t mask_value, bool zeroing, bool sae,
                       unsigned int ll)
{
    const size_t element_bytes = op->is_double ? 8 : 4;
    uint8_t initial[64];
    uint8_t source1[64];
    uint8_t source2[64];
    uint8_t expected[64];
    uint8_t observed[64];
    uint8_t code[6];
    uint32_t mxcsr = UINT32_C(0x1fa0);
    uc_engine *uc;

    for (size_t byte = 0; byte < 64; ++byte) {
        initial[byte] = (uint8_t)(0xc3 - byte * 5);
        source1[byte] = (uint8_t)(0x23 + byte * 11);
        source2[byte] = (uint8_t)(0xe1 - byte * 7);
    }
    memcpy(expected, initial, sizeof(expected));
    if (op->is_double) {
        const uint64_t input = source64[0];
        const uint64_t output = reference64[op->kind][0];

        memcpy(source2, &input, sizeof(input));
        if (!mask_reg || (mask_value & 1)) {
            memcpy(expected, &output, sizeof(output));
        } else if (zeroing) {
            memset(expected, 0, sizeof(output));
        }
    } else {
        const uint32_t input = source32[0];
        const uint32_t output = reference32[op->kind][0];

        memcpy(source2, &input, sizeof(input));
        if (!mask_reg || (mask_value & 1)) {
            memcpy(expected, &output, sizeof(output));
        } else if (zeroing) {
            memset(expected, 0, sizeof(output));
        }
    }
    memcpy(expected + element_bytes, source1 + element_bytes,
           16 - element_bytes);
    memset(expected + 16, 0, 48);
    encode_approx28(code, op, 31, 29, 30, mask_reg, zeroing, sae, ll);

    setup_x86(&uc, code, sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source2));
    if (mask_reg) {
        OK(uc_reg_write(uc, UC_X86_REG_K0 + mask_reg, &mask_value));
    }
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                "%s scalar LL=%u result mismatch", op->name, ll);
    TEST_CHECK_(mxcsr == UINT32_C(0x1fa0), "%s changed MXCSR", op->name);
    OK(uc_close(uc));
    return true;
}

static void run_exception_cases(void)
{
    static const TestApprox28Op rcp = {
        "VRCP28SS", APPROX28_RCP, true, false,
    };
    for (unsigned int osxmmexcpt = 0; osxmmexcpt < 2; ++osxmmexcpt) {
        uint8_t code[6];
        uint8_t initial[64];
        uint8_t observed[64];
        uint8_t source[64] = {0};
        uint32_t mxcsr = UINT32_C(0x1d80); /* divide-by-zero unmasked */
        uint64_t cr4;
        uint64_t rip = 0;
        InterruptRecord record = {0};
        uc_engine *uc;
        uc_hook hook;
        uc_err err;

        memset(initial, 0xa5, sizeof(initial));
        encode_approx28(code, &rcp, 31, 29, 30, 0, false, false, 3);
        setup_x86(&uc, code, sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
        if (osxmmexcpt) {
            cr4 |= UINT64_C(1) << 10;
        } else {
            cr4 &= ~(UINT64_C(1) << 10);
        }
        OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));
        OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, record_interrupt, &record,
                       1, 0));
        err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        if (osxmmexcpt) {
            TEST_CHECK(err == UC_ERR_OK);
            TEST_CHECK(record.count == 1);
            TEST_CHECK_(record.vector == 19,
                        "wrong SIMD exception vector %u", record.vector);
        } else {
            /* Unicorn reports a delivered #UD as invalid instruction rather
             * than invoking the interrupt hook. */
            TEST_CHECK(err == UC_ERR_INSN_INVALID);
            TEST_CHECK(record.count == 0);
        }
        TEST_CHECK(memcmp(observed, initial, sizeof(initial)) == 0);
        TEST_CHECK(mxcsr == UINT32_C(0x1d84));
        TEST_CHECK(rip == code_start);
        OK(uc_hook_del(uc, hook));
        OK(uc_close(uc));
    }

    /* SAE suppresses both the sticky flag and an otherwise unmasked trap. */
    {
        uint8_t code[6];
        uint8_t observed[64] = {0};
        uint8_t source[64] = {0};
        const uint32_t infinity = UINT32_C(0x7f800000);
        uint32_t mxcsr = UINT32_C(0x1d80);
        uint64_t cr4;
        uc_engine *uc;

        encode_approx28(code, &rcp, 31, 29, 30, 0, false, true, 0);
        setup_x86(&uc, code, sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
        cr4 |= UINT64_C(1) << 10;
        OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK(memcmp(observed, &infinity, sizeof(infinity)) == 0);
        TEST_CHECK(mxcsr == UINT32_C(0x1d80));
        OK(uc_close(uc));
    }

    /* A masked-off exceptional lane contributes no MXCSR status. */
    {
        uint8_t code[6];
        uint8_t initial[64];
        uint8_t observed[64];
        uint8_t source[64] = {0};
        uint64_t mask = 0;
        uint32_t mxcsr = UINT32_C(0x1fa0);
        uc_engine *uc;

        memset(initial, 0x5a, sizeof(initial));
        encode_approx28(code, &rcp, 31, 29, 30, 7, false, false, 1);
        setup_x86(&uc, code, sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK(memcmp(observed, initial, 4) == 0);
        TEST_CHECK(mxcsr == UINT32_C(0x1fa0));
        OK(uc_close(uc));
    }
}

static void run_daz_ftz_cases(void)
{
    static const TestApprox28Op ops[] = {
        {"VRCP28SS", APPROX28_RCP, true, false},
        {"VRSQRT28SS", APPROX28_RSQRT, true, false},
    };
    const uint32_t denormal = UINT32_C(0x00400000);
    const uint32_t infinity = UINT32_C(0x7f800000);

    for (size_t op = 0; op < sizeof(ops) / sizeof(ops[0]); ++op) {
        for (unsigned int mode = 0; mode < 2; ++mode) {
            uint8_t code[6];
            uint8_t observed[64] = {0};
            uint8_t source[64] = {0};
            uint32_t mxcsr = mode ? UINT32_C(0x9fc0) : UINT32_C(0x1f80);
            uc_engine *uc;

            encode_approx28(code, &ops[op], 31, 29, 30, 0, false, false,
                            mode);
            setup_x86(&uc, code, sizeof(code));
            memcpy(source, &denormal, sizeof(denormal));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source));
            OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
            OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0,
                            0));
            OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
            OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
            TEST_CHECK(memcmp(observed, &infinity, sizeof(infinity)) == 0);
            TEST_CHECK_(mxcsr == (mode ? UINT32_C(0x9fc4)
                                       : UINT32_C(0x1f84)),
                        "%s DAZ/FTZ MXCSR mismatch", ops[op].name);
            OK(uc_close(uc));
        }
    }
}

static void run_invalid_cases(void)
{
    static const struct {
        uint8_t code[7];
        size_t size;
        const char *name;
    } cases[] = {
        {{0x62, 0xf2, 0x7d, 0x08, 0xca, 0xca}, 6, "packed VL128"},
        {{0x62, 0xf2, 0x7d, 0x28, 0xca, 0xca}, 6, "packed VL256"},
        {{0x62, 0xf2, 0x7d, 0x68, 0xca, 0xca}, 6, "packed LL=3"},
        {{0x62, 0xf2, 0x75, 0x48, 0xca, 0xca}, 6, "packed vvvv"},
        {{0x62, 0xf2, 0x7d, 0x40, 0xca, 0xca}, 6, "packed V-prime"},
        {{0x62, 0xf2, 0x7d, 0xc8, 0xca, 0xca}, 6, "zeroing K0"},
        {{0x62, 0xf2, 0x7c, 0x48, 0xca, 0xca}, 6, "wrong pp"},
        {{0x62, 0xf1, 0x7d, 0x48, 0xca, 0xca}, 6, "wrong map"},
        {{0x62, 0xf2, 0x15, 0x18, 0xcb, 0x08}, 6,
         "scalar memory EVEX.b"},
        {{0xf0, 0x62, 0xf2, 0x7d, 0x48, 0xca, 0xca}, 7, "LOCK prefix"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t initial[64];
        uint8_t observed[64];
        uint64_t rax = code_start + UINT64_C(0x800);
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        memset(initial, 0xa5, sizeof(initial));
        setup_x86(&uc, cases[i].code, cases[i].size);
        OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        err = uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM1, observed));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not fail closed",
                    cases[i].name);
        TEST_CHECK_(memcmp(observed, initial, sizeof(initial)) == 0,
                    "%s changed destination", cases[i].name);
        TEST_CHECK_(rip == code_start, "%s advanced RIP", cases[i].name);
        OK(uc_close(uc));
    }
}

static void test_x86_evex_approx28_semantics(void)
{
    static const TestApprox28Op packed[] = {
        {"VRCP28PS", APPROX28_RCP, false, false},
        {"VRCP28PD", APPROX28_RCP, false, true},
        {"VRSQRT28PS", APPROX28_RSQRT, false, false},
        {"VRSQRT28PD", APPROX28_RSQRT, false, true},
        {"VEXP2PS", APPROX28_EXP2, false, false},
        {"VEXP2PD", APPROX28_EXP2, false, true},
    };
    static const TestApprox28Op scalar[] = {
        {"VRCP28SS", APPROX28_RCP, true, false},
        {"VRCP28SD", APPROX28_RCP, true, true},
        {"VRSQRT28SS", APPROX28_RSQRT, true, false},
        {"VRSQRT28SD", APPROX28_RSQRT, true, true},
    };

    for (size_t op = 0; op < sizeof(packed) / sizeof(packed[0]); ++op) {
        TEST_CHECK(run_packed(&packed[op], 0, 0, false, false));
        TEST_CHECK(run_packed(&packed[op], 7, UINT64_C(0xa55a), false,
                              false));
        TEST_CHECK(run_packed(&packed[op], 7, UINT64_C(0xa55a), true,
                              false));
        TEST_CHECK(run_packed(&packed[op], 0, 0, false, true));
    }
    for (size_t op = 0; op < sizeof(scalar) / sizeof(scalar[0]); ++op) {
        TEST_CHECK(run_scalar(&scalar[op], 0, 0, false, false, 0));
        TEST_CHECK(run_scalar(&scalar[op], 7, 0, false, false, 1));
        TEST_CHECK(run_scalar(&scalar[op], 7, 0, true, false, 2));
        TEST_CHECK(run_scalar(&scalar[op], 7, 1, false, true, 3));
    }
    run_exception_cases();
    run_daz_ftz_cases();
    run_invalid_cases();
}

TEST_LIST = {
    {"test_x86_evex_approx28_semantics", test_x86_evex_approx28_semantics},
    {NULL, NULL},
};
