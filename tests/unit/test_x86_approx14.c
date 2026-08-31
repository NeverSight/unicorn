#include "unicorn_test.h"

static const uint64_t test_code_start = UINT64_C(0x1000);
static const uint64_t test_code_size = UINT64_C(0x2000);

typedef struct TestApprox14Op {
    const char *name;
    bool rsqrt;
    bool scalar;
    bool is_double;
} TestApprox14Op;

static void setup_x86(uc_engine **uc, const uint8_t *code, size_t size)
{
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, uc));
    OK(uc_ctl_set_cpu_model(*uc, UC_CPU_X86_ICELAKE_SERVER));
    OK(uc_mem_map(*uc, test_code_start, test_code_size, UC_PROT_ALL));
    OK(uc_mem_write(*uc, test_code_start, code, size));
}

static void encode_approx14(uint8_t code[6], const TestApprox14Op *op,
                            size_t vector_bytes, unsigned int dst,
                            unsigned int src1, unsigned int src2,
                            unsigned int mask, bool zeroing, int scalar_ll)
{
    uint8_t p0 = 0xf2;
    uint8_t p1 = (op->is_double ? 0x80 : 0) | 0x05;
    uint8_t p2;
    unsigned int ll;

    TEST_CHECK(dst < 32 && src1 < 32 && src2 < 32 && mask < 8);
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
        ll = (unsigned int)scalar_ll & 3;
    } else {
        p1 |= 0x78;
        p2 = 0x08;
        ll = vector_bytes == 16 ? 0 : vector_bytes == 32 ? 1 : 2;
    }

    code[0] = 0x62;
    code[1] = p0;
    code[2] = p1;
    code[3] = (uint8_t)(p2 | (ll << 5) | mask | (zeroing ? 0x80 : 0));
    code[4] = (uint8_t)(0x4c + (op->scalar ? 1 : 0) +
                        (op->rsqrt ? 2 : 0));
    code[5] = (uint8_t)(0xc0 | ((dst & 7) << 3) | (src2 & 7));
}

static const uint32_t source32[16] = {
    UINT32_C(0x40400000), UINT32_C(0x40000000),
    UINT32_C(0x00000000), UINT32_C(0x80000000),
    UINT32_C(0x7f800000), UINT32_C(0xff800000),
    UINT32_C(0x7fc12345), UINT32_C(0x7f812345),
    UINT32_C(0xc0000000), UINT32_C(0x00400001),
    UINT32_C(0x00000001), UINT32_C(0x7f000000),
    UINT32_C(0xff000000), UINT32_C(0x3f800001),
    UINT32_C(0x3fc00000), UINT32_C(0x40800000),
};

static const uint32_t rcp32[16] = {
    UINT32_C(0x3eaaaa80), UINT32_C(0x3f000000),
    UINT32_C(0x7f800000), UINT32_C(0xff800000),
    UINT32_C(0x00000000), UINT32_C(0x80000000),
    UINT32_C(0x7fc12345), UINT32_C(0x7fc12345),
    UINT32_C(0xbf000000), UINT32_C(0x7efffe00),
    UINT32_C(0x7f800000), UINT32_C(0x00400000),
    UINT32_C(0x80400000), UINT32_C(0x3f7ffe00),
    UINT32_C(0x3f2aaa80), UINT32_C(0x3e800000),
};

static const uint32_t rsqrt32[16] = {
    UINT32_C(0x3f13cc80), UINT32_C(0x3f350280),
    UINT32_C(0x7f800000), UINT32_C(0xff800000),
    UINT32_C(0x00000000), UINT32_C(0xffc00000),
    UINT32_C(0x7fc12345), UINT32_C(0x7fc12345),
    UINT32_C(0xffc00000), UINT32_C(0x5f350280),
    UINT32_C(0x64b50280), UINT32_C(0x1fb50280),
    UINT32_C(0xffc00000), UINT32_C(0x3f7ffd00),
    UINT32_C(0x3f510480), UINT32_C(0x3f000000),
};

static const uint64_t source64[8] = {
    UINT64_C(0x4008000000000000), UINT64_C(0x4000000000000000),
    UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
    UINT64_C(0x7ff0000000000000), UINT64_C(0x7ff0123456789abc),
    UINT64_C(0xc000000000000000), UINT64_C(0x0008000000000001),
};

static const uint64_t rcp64[8] = {
    UINT64_C(0x3fd5555000000000), UINT64_C(0x3fe0000000000000),
    UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
    UINT64_C(0x0000000000000000), UINT64_C(0x7ff8123456789abc),
    UINT64_C(0xbfe0000000000000), UINT64_C(0x7fdfffc000000000),
};

static const uint64_t rsqrt64[8] = {
    UINT64_C(0x3fe2799000000000), UINT64_C(0x3fe6a05000000000),
    UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
    UINT64_C(0x0000000000000000), UINT64_C(0x7ff8123456789abc),
    UINT64_C(0xfff8000000000000), UINT64_C(0x5fe6a05000000000),
};

static bool run_packed(const TestApprox14Op *op, size_t vector_bytes,
                       unsigned int mask_reg, bool zeroing)
{
    const size_t element_bytes = op->is_double ? 8 : 4;
    const size_t elements = vector_bytes / element_bytes;
    const void *source = op->is_double ? (const void *)source64
                                       : (const void *)source32;
    const void *reference = op->is_double
                                ? op->rsqrt ? (const void *)rsqrt64
                                             : (const void *)rcp64
                                : op->rsqrt ? (const void *)rsqrt32
                                             : (const void *)rcp32;
    const uint64_t mask_value = UINT64_C(0xa55a);
    const uint64_t effective_mask = mask_reg ? mask_value : UINT64_MAX;
    uint8_t initial[64];
    uint8_t expected[64];
    uint8_t observed[64];
    uint8_t source_after[64];
    uint8_t code[6];
    uint64_t observed_mask = mask_value;
    uint64_t rflags = UINT64_C(0xcd7);
    uint64_t rip = 0;
    uint32_t mxcsr = UINT32_C(0x1fbf);
    uc_engine *uc;
    uc_err err;

    for (size_t byte = 0; byte < sizeof(initial); ++byte) {
        initial[byte] = (uint8_t)(0x71 + byte * 17);
    }
    memcpy(expected, initial, sizeof(expected));
    for (size_t element = 0; element < elements; ++element) {
        if ((effective_mask >> element) & 1) {
            memcpy(expected + element * element_bytes,
                   (const uint8_t *)reference + element * element_bytes,
                   element_bytes);
        } else if (zeroing) {
            memset(expected + element * element_bytes, 0, element_bytes);
        }
    }
    memset(expected + vector_bytes, 0, sizeof(expected) - vector_bytes);
    encode_approx14(code, op, vector_bytes, 31, 0, 30, mask_reg, zeroing, 0);

    setup_x86(&uc, code, sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source));
    if (mask_reg) {
        OK(uc_reg_write(uc, UC_X86_REG_K0 + mask_reg, &observed_mask));
    }
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
    err = uc_emu_start(uc, test_code_start, test_code_start + sizeof(code),
                       0, 0);
    if (!TEST_CHECK_(err == UC_ERR_OK, "%s VL%zu failed: %s", op->name,
                     vector_bytes * 8, uc_strerror(err))) {
        OK(uc_close(uc));
        return false;
    }
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM30, source_after));
    if (mask_reg) {
        OK(uc_reg_read(uc, UC_X86_REG_K0 + mask_reg, &observed_mask));
    }
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                "%s VL%zu mask result mismatch", op->name,
                vector_bytes * 8);
    TEST_CHECK_(memcmp(source_after, source, sizeof(source_after)) == 0,
                "%s changed source", op->name);
    TEST_CHECK_(!mask_reg || observed_mask == mask_value,
                "%s changed writemask", op->name);
    TEST_CHECK_(mxcsr == UINT32_C(0x1fbf), "%s changed MXCSR", op->name);
    TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS", op->name);
    TEST_CHECK_(rip == test_code_start + sizeof(code), "%s RIP mismatch",
                op->name);
    OK(uc_close(uc));
    return true;
}

static bool run_scalar(const TestApprox14Op *op, unsigned int mask_reg,
                       uint64_t mask_value, bool zeroing, int ll)
{
    const size_t element_bytes = op->is_double ? 8 : 4;
    uint8_t initial[64];
    uint8_t source1[64];
    uint8_t source2[64];
    uint8_t expected[64];
    uint8_t observed[64];
    uint8_t code[6];
    uint32_t mxcsr = UINT32_C(0x1fbf);
    uint64_t rip = 0;
    uc_engine *uc;
    uc_err err;

    for (size_t byte = 0; byte < 64; ++byte) {
        initial[byte] = (uint8_t)(0xc3 - byte * 5);
        source1[byte] = (uint8_t)(0x23 + byte * 11);
        source2[byte] = (uint8_t)(0xe1 - byte * 7);
    }
    memcpy(expected, initial, sizeof(expected));
    if (op->is_double) {
        const uint64_t input = UINT64_C(0x4008000000000000);
        const uint64_t result = op->rsqrt ? UINT64_C(0x3fe2799000000000)
                                          : UINT64_C(0x3fd5555000000000);

        memcpy(source2, &input, sizeof(input));
        if (!mask_reg || (mask_value & 1)) {
            memcpy(expected, &result, sizeof(result));
        } else if (zeroing) {
            memset(expected, 0, sizeof(result));
        }
    } else {
        const uint32_t input = UINT32_C(0x40400000);
        const uint32_t result = op->rsqrt ? UINT32_C(0x3f13cc80)
                                          : UINT32_C(0x3eaaaa80);

        memcpy(source2, &input, sizeof(input));
        if (!mask_reg || (mask_value & 1)) {
            memcpy(expected, &result, sizeof(result));
        } else if (zeroing) {
            memset(expected, 0, sizeof(result));
        }
    }
    memcpy(expected + element_bytes, source1 + element_bytes,
           16 - element_bytes);
    memset(expected + 16, 0, 48);
    encode_approx14(code, op, 16, 31, 29, 30, mask_reg, zeroing, ll);

    setup_x86(&uc, code, sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source2));
    if (mask_reg) {
        OK(uc_reg_write(uc, UC_X86_REG_K0 + mask_reg, &mask_value));
    }
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    err = uc_emu_start(uc, test_code_start, test_code_start + sizeof(code),
                       0, 0);
    if (!TEST_CHECK_(err == UC_ERR_OK, "%s LL=%d failed: %s", op->name, ll,
                     uc_strerror(err))) {
        OK(uc_close(uc));
        return false;
    }
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                "%s scalar result mismatch", op->name);
    TEST_CHECK_(mxcsr == UINT32_C(0x1fbf), "%s changed MXCSR", op->name);
    TEST_CHECK_(rip == test_code_start + sizeof(code), "%s RIP mismatch",
                op->name);
    OK(uc_close(uc));
    return true;
}

static void run_daz_ftz_cases(void)
{
    static const TestApprox14Op rcp32_op = {"VRCP14PS", false, false, false};
    static const TestApprox14Op rsqrt32_op = {
        "VRSQRT14PS", true, false, false,
    };
    static const uint32_t input32[4] = {
        UINT32_C(0x00400001), UINT32_C(0x7f000000),
        UINT32_C(0xff000000), UINT32_C(0x40400000),
    };
    static const struct {
        const TestApprox14Op *op;
        uint32_t mxcsr;
        uint32_t result[4];
    } cases32[] = {
        {&rcp32_op,
         UINT32_C(0x1fff),
         {UINT32_C(0x7f800000), UINT32_C(0x00400000),
          UINT32_C(0x80400000), UINT32_C(0x3eaaaa80)}},
        {&rcp32_op,
         UINT32_C(0x9fbf),
         {UINT32_C(0x7efffe00), UINT32_C(0x00000000),
          UINT32_C(0x80000000), UINT32_C(0x3eaaaa80)}},
        {&rsqrt32_op,
         UINT32_C(0x1fff),
         {UINT32_C(0x7f800000), UINT32_C(0x1fb50280),
          UINT32_C(0xffc00000), UINT32_C(0x3f13cc80)}},
    };

    for (size_t i = 0; i < sizeof(cases32) / sizeof(cases32[0]); ++i) {
        uint8_t code[6];
        uint8_t observed[64];
        uint32_t mxcsr = cases32[i].mxcsr;
        uc_engine *uc;

        memset(observed, 0xa5, sizeof(observed));
        encode_approx14(code, cases32[i].op, 16, 31, 0, 30, 0, false, 0);
        setup_x86(&uc, code, sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM30, input32));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_emu_start(uc, test_code_start,
                        test_code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK_(memcmp(observed, cases32[i].result, 16) == 0,
                    "%s DAZ/FTZ result mismatch", cases32[i].op->name);
        for (size_t byte = 16; byte < 64; ++byte) {
            TEST_CHECK_(observed[byte] == 0, "%s upper state not cleared",
                        cases32[i].op->name);
        }
        TEST_CHECK_(mxcsr == cases32[i].mxcsr, "%s changed MXCSR",
                    cases32[i].op->name);
        OK(uc_close(uc));
    }

    {
        static const TestApprox14Op rcp64_op = {
            "VRCP14PD", false, false, true,
        };
        static const uint64_t input[2] = {
            UINT64_C(0x0008000000000001), UINT64_C(0xffe0000000000000),
        };
        static const struct {
            uint32_t mxcsr;
            uint64_t result[2];
        } cases[] = {
            {UINT32_C(0x1fff),
             {UINT64_C(0x7ff0000000000000),
              UINT64_C(0x8008000000000000)}},
            {UINT32_C(0x9fbf),
             {UINT64_C(0x7fdfffc000000000),
              UINT64_C(0x8000000000000000)}},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint8_t code[6];
            uint8_t observed[64] = {0};
            uint32_t mxcsr = cases[i].mxcsr;
            uc_engine *uc;

            encode_approx14(code, &rcp64_op, 16, 31, 0, 30, 0, false, 0);
            setup_x86(&uc, code, sizeof(code));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM30, input));
            OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
            OK(uc_emu_start(uc, test_code_start,
                            test_code_start + sizeof(code), 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
            OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
            TEST_CHECK_(memcmp(observed, cases[i].result, 16) == 0,
                        "VRCP14PD DAZ/FTZ result mismatch");
            TEST_CHECK_(mxcsr == cases[i].mxcsr,
                        "VRCP14PD changed MXCSR");
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
        {{0x62, 0xf2, 0x7d, 0x58, 0x4c, 0xca}, 6, "register EVEX.b"},
        {{0x62, 0xf2, 0x75, 0x48, 0x4c, 0xca}, 6, "packed vvvv"},
        {{0x62, 0xf2, 0x7d, 0x40, 0x4c, 0xca}, 6, "packed V-prime"},
        {{0x62, 0xf2, 0x7d, 0x68, 0x4c, 0xca}, 6, "packed LL=3"},
        {{0x62, 0xf2, 0x7d, 0xc8, 0x4c, 0xca}, 6, "zeroing K0"},
        {{0x62, 0xf2, 0x7c, 0x48, 0x4c, 0xca}, 6, "wrong pp"},
        {{0x62, 0xf1, 0x7d, 0x48, 0x4c, 0xca}, 6, "wrong map"},
        {{0x62, 0xf2, 0x15, 0x18, 0x4d, 0xca}, 6, "scalar EVEX.b"},
        {{0xf0, 0x62, 0xf2, 0x7d, 0x48, 0x4c, 0xca}, 7, "LOCK prefix"},
    };
    const uint64_t data_address = test_code_start + UINT64_C(0x800);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t initial[64];
        uint8_t observed[64];
        uint64_t rax = data_address;
        uint64_t memory = UINT64_C(0x1122334455667788);
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        for (size_t byte = 0; byte < sizeof(initial); ++byte) {
            initial[byte] = (uint8_t)(0x81 + byte * 3);
        }
        setup_x86(&uc, cases[i].code, cases[i].size);
        OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
        err = uc_emu_start(uc, test_code_start,
                           test_code_start + cases[i].size, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM1, observed));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    cases[i].name);
        TEST_CHECK_(memcmp(initial, observed, sizeof(initial)) == 0,
                    "%s changed destination", cases[i].name);
        TEST_CHECK_(rip == test_code_start, "%s advanced RIP",
                    cases[i].name);
        OK(uc_close(uc));
    }
}

static void test_x86_evex_approx14_semantics(void)
{
    static const TestApprox14Op packed[] = {
        {"VRCP14PS", false, false, false},
        {"VRCP14PD", false, false, true},
        {"VRSQRT14PS", true, false, false},
        {"VRSQRT14PD", true, false, true},
    };
    static const TestApprox14Op scalar[] = {
        {"VRCP14SS", false, true, false},
        {"VRCP14SD", false, true, true},
        {"VRSQRT14SS", true, true, false},
        {"VRSQRT14SD", true, true, true},
    };
    static const size_t vector_bytes[] = {16, 32, 64};

    for (size_t op = 0; op < sizeof(packed) / sizeof(packed[0]); ++op) {
        for (size_t vl = 0; vl < sizeof(vector_bytes) / sizeof(vector_bytes[0]);
             ++vl) {
            TEST_CHECK(run_packed(&packed[op], vector_bytes[vl], 0, false));
            TEST_CHECK(run_packed(&packed[op], vector_bytes[vl], 7, false));
            TEST_CHECK(run_packed(&packed[op], vector_bytes[vl], 7, true));
        }
    }
    for (size_t op = 0; op < sizeof(scalar) / sizeof(scalar[0]); ++op) {
        TEST_CHECK(run_scalar(&scalar[op], 0, 0, false, 0));
        TEST_CHECK(run_scalar(&scalar[op], 7, 1, false, 1));
        TEST_CHECK(run_scalar(&scalar[op], 7, 0, false, 3));
        TEST_CHECK(run_scalar(&scalar[op], 7, 0, true, 2));
    }
    run_daz_ftz_cases();
    run_invalid_cases();
}

TEST_LIST = {
    {"test_x86_evex_approx14_semantics", test_x86_evex_approx14_semantics},
    {NULL, NULL},
};
