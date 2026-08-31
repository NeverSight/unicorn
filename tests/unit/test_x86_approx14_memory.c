#include "unicorn_test.h"

static const uint64_t code_start = UINT64_C(0x1000);
static const uint64_t code_size = UINT64_C(0x2000);
static const uint64_t data_page = UINT64_C(0x4000);

typedef struct Approx14Op {
    const char *name;
    bool rsqrt;
    bool scalar;
    bool is_double;
} Approx14Op;

static const Approx14Op packed_operations[] = {
    {"VRCP14PS", false, false, false},
    {"VRCP14PD", false, false, true},
    {"VRSQRT14PS", true, false, false},
    {"VRSQRT14PD", true, false, true},
};

static const Approx14Op scalar_operations[] = {
    {"VRCP14SS", false, true, false},
    {"VRCP14SD", false, true, true},
    {"VRSQRT14SS", true, true, false},
    {"VRSQRT14SD", true, true, true},
};

static size_t encode_approx14(uint8_t code[7], const Approx14Op *op,
                              size_t vector_bytes, unsigned int dst,
                              unsigned int src1, unsigned int src2_or_base,
                              unsigned int mask, bool zeroing, bool memory,
                              bool broadcast, unsigned int scalar_ll,
                              bool disp8, int8_t displacement)
{
    uint8_t p0 = 0xf2;
    uint8_t p1 = (op->is_double ? 0x80 : 0) | 0x05;
    uint8_t p2;
    unsigned int ll;

    TEST_CHECK(dst < 32 && src1 < 32 && src2_or_base < 32 && mask < 8);
    if (dst & 8) {
        p0 &= (uint8_t)~0x80;
    }
    if (dst & 16) {
        p0 &= (uint8_t)~0x10;
    }
    if (src2_or_base & 8) {
        p0 &= (uint8_t)~0x20;
    }
    if (!memory && (src2_or_base & 16)) {
        p0 &= (uint8_t)~0x40;
    }

    if (op->scalar) {
        p1 |= ((~src1) & 15) << 3;
        p2 = (src1 & 16) ? 0 : 0x08;
        ll = scalar_ll & 3;
    } else {
        p1 |= 0x78;
        p2 = 0x08;
        ll = vector_bytes == 16 ? 0 : vector_bytes == 32 ? 1 : 2;
    }

    code[0] = 0x62;
    code[1] = p0;
    code[2] = p1;
    code[3] = (uint8_t)(p2 | (ll << 5) | mask | (zeroing ? 0x80 : 0) |
                        (broadcast ? 0x10 : 0));
    code[4] = (uint8_t)(0x4c + (op->scalar ? 1 : 0) + (op->rsqrt ? 2 : 0));
    code[5] = (uint8_t)((memory ? (disp8 ? 0x40 : 0) : 0xc0) |
                        ((dst & 7) << 3) | (src2_or_base & 7));
    if (memory && disp8) {
        code[6] = (uint8_t)displacement;
        return 7;
    }
    return 6;
}

static uint64_t normal_input(const Approx14Op *op)
{
    return op->is_double ? UINT64_C(0x4008000000000000) : UINT64_C(0x40400000);
}

static uint64_t normal_result(const Approx14Op *op)
{
    if (op->is_double) {
        return op->rsqrt ? UINT64_C(0x3fe2799000000000)
                         : UINT64_C(0x3fd5555000000000);
    }
    return op->rsqrt ? UINT64_C(0x3f13cc80) : UINT64_C(0x3eaaaa80);
}

static void setup_x86(uc_engine **uc, const uint8_t *code, size_t size)
{
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, uc));
    OK(uc_ctl_set_cpu_model(*uc, UC_CPU_X86_ICELAKE_SERVER));
    OK(uc_mem_map(*uc, code_start, code_size, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static bool run_memory_case(const Approx14Op *op, size_t vector_bytes,
                            bool broadcast, unsigned int scalar_ll,
                            unsigned int mask_reg, uint64_t mask, bool zeroing)
{
    const size_t element_bytes = op->is_double ? 8 : 4;
    const size_t elements = op->scalar ? 1 : vector_bytes / element_bytes;
    const size_t disp8_scale =
        op->scalar || broadcast ? element_bytes : vector_bytes;
    const uint64_t effective_mask = mask_reg ? mask : UINT64_MAX;
    const uint64_t input = normal_input(op);
    const uint64_t result = normal_result(op);
    uint8_t memory[64] = {0};
    uint8_t initial[64];
    uint8_t source1[64];
    uint8_t expected[64];
    uint8_t observed[64];
    uint8_t code[7];
    const size_t code_length =
        encode_approx14(code, op, vector_bytes, 31, 29, 13, mask_reg, zeroing,
                        true, broadcast, scalar_ll, true, 1);
    uint64_t r13 = data_page;
    uint32_t mxcsr = UINT32_C(0x1fbf);
    uc_engine *uc;

    for (size_t byte = 0; byte < 64; ++byte) {
        initial[byte] = (uint8_t)(0xa7 - byte * 3);
        source1[byte] = (uint8_t)(0x31 + byte * 7);
    }
    if (broadcast) {
        memcpy(memory, &input, element_bytes);
    } else {
        for (size_t element = 0; element < elements; ++element) {
            memcpy(memory + element * element_bytes, &input, element_bytes);
        }
    }
    memcpy(expected, initial, sizeof(expected));
    for (size_t element = 0; element < elements; ++element) {
        if ((effective_mask >> element) & 1) {
            memcpy(expected + element * element_bytes, &result, element_bytes);
        } else if (zeroing) {
            memset(expected + element * element_bytes, 0, element_bytes);
        }
    }
    if (op->scalar) {
        memcpy(expected + element_bytes, source1 + element_bytes,
               16 - element_bytes);
        memset(expected + 16, 0, 48);
    } else {
        memset(expected + vector_bytes, 0, 64 - vector_bytes);
    }

    setup_x86(&uc, code, code_length);
    OK(uc_mem_map(uc, data_page, 0x3000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, data_page + disp8_scale, memory,
                    broadcast ? element_bytes : elements * element_bytes));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
    if (op->scalar) {
        OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
    }
    OK(uc_reg_write(uc, UC_X86_REG_R13, &r13));
    if (mask_reg) {
        OK(uc_reg_write(uc, UC_X86_REG_K0 + mask_reg, &mask));
    }
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                "%s %s VL%zu mask result mismatch", op->name,
                broadcast ? "broadcast" : "full-memory", vector_bytes * 8);
    TEST_CHECK_(mxcsr == UINT32_C(0x1fbf), "%s changed MXCSR", op->name);
    OK(uc_close(uc));
    return true;
}

static bool run_register_case(const Approx14Op *op, size_t vector_bytes,
                              unsigned int scalar_ll, bool zeroing)
{
    const size_t element_bytes = op->is_double ? 8 : 4;
    const size_t elements = op->scalar ? 1 : vector_bytes / element_bytes;
    const uint64_t input = normal_input(op);
    const uint64_t result = normal_result(op);
    const uint64_t mask = UINT64_C(0xa55a);
    uint8_t initial[64];
    uint8_t source1[64];
    uint8_t source2[64] = {0};
    uint8_t expected[64];
    uint8_t observed[64];
    uint8_t code[7];
    const size_t code_length =
        encode_approx14(code, op, vector_bytes, 31, 29, 30, 7, zeroing, false,
                        false, scalar_ll, false, 0);
    uint32_t mxcsr = UINT32_C(0x1fbf);
    uc_engine *uc;

    for (size_t byte = 0; byte < 64; ++byte) {
        initial[byte] = (uint8_t)(0xa7 - byte * 3);
        source1[byte] = (uint8_t)(0x31 + byte * 7);
    }
    for (size_t element = 0; element < elements; ++element) {
        memcpy(source2 + element * element_bytes, &input, element_bytes);
    }
    memcpy(expected, initial, sizeof(expected));
    for (size_t element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            memcpy(expected + element * element_bytes, &result, element_bytes);
        } else if (zeroing) {
            memset(expected + element * element_bytes, 0, element_bytes);
        }
    }
    if (op->scalar) {
        memcpy(expected + element_bytes, source1 + element_bytes,
               16 - element_bytes);
        memset(expected + 16, 0, 48);
    } else {
        memset(expected + vector_bytes, 0, 64 - vector_bytes);
    }

    setup_x86(&uc, code, code_length);
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source2));
    OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                "%s register VL%zu result mismatch", op->name,
                vector_bytes * 8);
    TEST_CHECK_(mxcsr == UINT32_C(0x1fbf), "%s changed MXCSR", op->name);
    OK(uc_close(uc));
    return true;
}

static void run_shape_matrix(void)
{
    static const size_t vector_bytes[] = {16, 32, 64};

    for (size_t op = 0;
         op < sizeof(packed_operations) / sizeof(packed_operations[0]); ++op) {
        for (size_t vl = 0; vl < sizeof(vector_bytes) / sizeof(vector_bytes[0]);
             ++vl) {
            TEST_CHECK(run_register_case(&packed_operations[op],
                                         vector_bytes[vl], 0, (vl & 1) != 0));
            TEST_CHECK(run_memory_case(&packed_operations[op], vector_bytes[vl],
                                       false, 0, 0, 0, false));
            TEST_CHECK(run_memory_case(&packed_operations[op], vector_bytes[vl],
                                       false, 0, 7, UINT64_C(0xa55a), false));
            TEST_CHECK(run_memory_case(&packed_operations[op], vector_bytes[vl],
                                       false, 0, 7, UINT64_C(0xa55a), true));
            TEST_CHECK(run_memory_case(&packed_operations[op], vector_bytes[vl],
                                       true, 0, 7, UINT64_C(0xa55a), false));
            TEST_CHECK(run_memory_case(&packed_operations[op], vector_bytes[vl],
                                       true, 0, 7, UINT64_C(0xa55a), true));
        }
    }

    for (size_t op = 0;
         op < sizeof(scalar_operations) / sizeof(scalar_operations[0]); ++op) {
        for (unsigned int ll = 0; ll < 4; ++ll) {
            TEST_CHECK(run_register_case(&scalar_operations[op], 16, ll,
                                         (ll & 1) != 0));
            TEST_CHECK(run_memory_case(&scalar_operations[op], 16, false, ll, 0,
                                       0, false));
            TEST_CHECK(run_memory_case(&scalar_operations[op], 16, false, ll, 7,
                                       0, false));
            TEST_CHECK(run_memory_case(&scalar_operations[op], 16, false, ll, 7,
                                       0, true));
        }
    }
}

static bool run_full_expected(const Approx14Op *op, size_t vector_bytes,
                              const void *input, const void *expected_low,
                              uint32_t initial_mxcsr)
{
    uint8_t initial[64];
    uint8_t expected[64] = {0};
    uint8_t observed[64];
    uint8_t code[7];
    const size_t code_length = encode_approx14(
        code, op, vector_bytes, 31, 0, 13, 0, false, true, false, 0, true, 1);
    uint64_t r13 = data_page;
    uint32_t mxcsr = initial_mxcsr;
    uc_engine *uc;

    memset(initial, 0xa5, sizeof(initial));
    memcpy(expected, expected_low, vector_bytes);
    setup_x86(&uc, code, code_length);
    OK(uc_mem_map(uc, data_page, 0x3000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, data_page + vector_bytes, input, vector_bytes));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
    OK(uc_reg_write(uc, UC_X86_REG_R13, &r13));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                "%s special-value result mismatch", op->name);
    TEST_CHECK_(mxcsr == initial_mxcsr, "%s changed MXCSR %08x -> %08x",
                op->name, initial_mxcsr, mxcsr);
    OK(uc_close(uc));
    return true;
}

static void run_special_value_cases(void)
{
    static const uint32_t source32[16] = {
        UINT32_C(0x40400000), UINT32_C(0x40000000), UINT32_C(0x00000000),
        UINT32_C(0x80000000), UINT32_C(0x7f800000), UINT32_C(0xff800000),
        UINT32_C(0x7fc12345), UINT32_C(0x7f812345), UINT32_C(0xc0000000),
        UINT32_C(0x00400001), UINT32_C(0x00000001), UINT32_C(0x7f000000),
        UINT32_C(0xff000000), UINT32_C(0x3f800001), UINT32_C(0x3fc00000),
        UINT32_C(0x40800000),
    };
    static const uint32_t rcp32[16] = {
        UINT32_C(0x3eaaaa80), UINT32_C(0x3f000000), UINT32_C(0x7f800000),
        UINT32_C(0xff800000), UINT32_C(0x00000000), UINT32_C(0x80000000),
        UINT32_C(0x7fc12345), UINT32_C(0x7fc12345), UINT32_C(0xbf000000),
        UINT32_C(0x7efffe00), UINT32_C(0x7f800000), UINT32_C(0x00400000),
        UINT32_C(0x80400000), UINT32_C(0x3f7ffe00), UINT32_C(0x3f2aaa80),
        UINT32_C(0x3e800000),
    };
    static const uint32_t rsqrt32[16] = {
        UINT32_C(0x3f13cc80), UINT32_C(0x3f350280), UINT32_C(0x7f800000),
        UINT32_C(0xff800000), UINT32_C(0x00000000), UINT32_C(0xffc00000),
        UINT32_C(0x7fc12345), UINT32_C(0x7fc12345), UINT32_C(0xffc00000),
        UINT32_C(0x5f350280), UINT32_C(0x64b50280), UINT32_C(0x1fb50280),
        UINT32_C(0xffc00000), UINT32_C(0x3f7ffd00), UINT32_C(0x3f510480),
        UINT32_C(0x3f000000),
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
    static const uint32_t daz_ftz_input32[4] = {
        UINT32_C(0x00400001),
        UINT32_C(0x7f000000),
        UINT32_C(0xff000000),
        UINT32_C(0x40400000),
    };
    static const uint32_t rcp32_daz[4] = {
        UINT32_C(0x7f800000),
        UINT32_C(0x00400000),
        UINT32_C(0x80400000),
        UINT32_C(0x3eaaaa80),
    };
    static const uint32_t rcp32_ftz[4] = {
        UINT32_C(0x7efffe00),
        UINT32_C(0x00000000),
        UINT32_C(0x80000000),
        UINT32_C(0x3eaaaa80),
    };
    static const uint32_t rsqrt32_daz[4] = {
        UINT32_C(0x7f800000),
        UINT32_C(0x1fb50280),
        UINT32_C(0xffc00000),
        UINT32_C(0x3f13cc80),
    };
    static const uint64_t daz_ftz_input64[2] = {
        UINT64_C(0x0008000000000001),
        UINT64_C(0xffe0000000000000),
    };
    static const uint64_t rcp64_daz[2] = {
        UINT64_C(0x7ff0000000000000),
        UINT64_C(0x8008000000000000),
    };
    static const uint64_t rcp64_ftz[2] = {
        UINT64_C(0x7fdfffc000000000),
        UINT64_C(0x8000000000000000),
    };

    TEST_CHECK(run_full_expected(&packed_operations[0], 64, source32, rcp32,
                                 UINT32_C(0x1f80)));
    TEST_CHECK(run_full_expected(&packed_operations[2], 64, source32, rsqrt32,
                                 UINT32_C(0x1f80)));
    TEST_CHECK(run_full_expected(&packed_operations[1], 64, source64, rcp64,
                                 UINT32_C(0x1f80)));
    TEST_CHECK(run_full_expected(&packed_operations[3], 64, source64, rsqrt64,
                                 UINT32_C(0x1f80)));

    TEST_CHECK(run_full_expected(&packed_operations[0], 16, daz_ftz_input32,
                                 rcp32_daz, UINT32_C(0x1fc0)));
    TEST_CHECK(run_full_expected(&packed_operations[0], 16, daz_ftz_input32,
                                 rcp32_ftz, UINT32_C(0x9f80)));
    TEST_CHECK(run_full_expected(&packed_operations[2], 16, daz_ftz_input32,
                                 rsqrt32_daz, UINT32_C(0x1fc0)));
    TEST_CHECK(run_full_expected(&packed_operations[1], 16, daz_ftz_input64,
                                 rcp64_daz, UINT32_C(0x1fc0)));
    TEST_CHECK(run_full_expected(&packed_operations[1], 16, daz_ftz_input64,
                                 rcp64_ftz, UINT32_C(0x9f80)));
}

static void run_fault_suppression_cases(void)
{
    const uint64_t boundary = data_page + UINT64_C(0xffc);

    /* A masked-off lane that crosses the page boundary is never accessed. */
    {
        const uint32_t zero = 0;
        const uint32_t infinity = UINT32_C(0x7f800000);
        uint8_t initial[64];
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[7];
        const size_t code_length =
            encode_approx14(code, &packed_operations[0], 64, 31, 0, 0, 7, false,
                            true, false, 0, false, 0);
        uint64_t rax = boundary;
        uint64_t mask = 1;
        uint32_t mxcsr = UINT32_C(0x1f80);
        uc_engine *uc;

        memset(initial, 0xa5, sizeof(initial));
        memcpy(expected, initial, sizeof(expected));
        memcpy(expected, &infinity, sizeof(infinity));
        setup_x86(&uc, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, boundary, &zero, sizeof(zero)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK(memcmp(observed, expected, sizeof(expected)) == 0);
        TEST_CHECK(mxcsr == UINT32_C(0x1f80));
        OK(uc_close(uc));
    }

    /* If a later active lane faults, no earlier result or MXCSR state commits.
     */
    {
        const uint32_t zero = 0;
        uint8_t initial[64];
        uint8_t observed[64];
        uint8_t code[7];
        const size_t code_length =
            encode_approx14(code, &packed_operations[0], 64, 31, 0, 0, 7, false,
                            true, false, 0, false, 0);
        uint64_t rax = boundary;
        uint64_t mask = 3;
        uint64_t rip = 0;
        uint32_t mxcsr = UINT32_C(0x1fa5);
        uc_engine *uc;
        uc_err err;

        memset(initial, 0x5a, sizeof(initial));
        setup_x86(&uc, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, boundary, &zero, sizeof(zero)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        err = uc_emu_start(uc, code_start, code_start + code_length, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK(err == UC_ERR_READ_UNMAPPED);
        TEST_CHECK(memcmp(observed, initial, sizeof(initial)) == 0);
        TEST_CHECK(mxcsr == UINT32_C(0x1fa5));
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }

    /* An all-zero mask suppresses the sole broadcast load. */
    {
        uint8_t initial[64];
        uint8_t observed[64];
        uint8_t code[7];
        const size_t code_length =
            encode_approx14(code, &packed_operations[3], 32, 31, 0, 0, 7, true,
                            true, true, 0, false, 0);
        uint64_t rax = UINT64_C(0x8000);
        uint64_t mask = 0;
        uint32_t mxcsr = UINT32_C(0x9fc0);
        uc_engine *uc;

        memset(initial, 0xa5, sizeof(initial));
        setup_x86(&uc, code, code_length);
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK(memcmp(observed, (uint8_t[64]){0}, 64) == 0);
        TEST_CHECK(mxcsr == UINT32_C(0x9fc0));
        OK(uc_close(uc));
    }

    /* A masked-off scalar Tuple1 input also suppresses memory access. */
    {
        uint8_t initial[64];
        uint8_t source1[64];
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[7];
        const size_t code_length =
            encode_approx14(code, &scalar_operations[1], 16, 31, 29, 0, 7,
                            false, true, false, 3, false, 0);
        uint64_t rax = UINT64_C(0x8000);
        uint64_t mask = 0;
        uc_engine *uc;

        for (size_t byte = 0; byte < 64; ++byte) {
            initial[byte] = (uint8_t)(0xa7 - byte * 3);
            source1[byte] = (uint8_t)(0x31 + byte * 7);
        }
        memcpy(expected, initial, sizeof(expected));
        memcpy(expected + sizeof(uint64_t), source1 + sizeof(uint64_t),
               16 - sizeof(uint64_t));
        memset(expected + 16, 0, 48);
        setup_x86(&uc, code, code_length);
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        TEST_CHECK(memcmp(observed, expected, sizeof(expected)) == 0);
        OK(uc_close(uc));
    }

    /* Broadcast reads exactly one scalar even when only the final lane is
     * active at the page edge. */
    {
        const uint32_t input = UINT32_C(0x40400000);
        const uint32_t result = UINT32_C(0x3eaaaa80);
        uint8_t initial[64];
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[7];
        const size_t code_length =
            encode_approx14(code, &packed_operations[0], 64, 31, 0, 0, 7, false,
                            true, true, 0, false, 0);
        uint64_t rax = boundary;
        uint64_t mask = UINT64_C(1) << 15;
        uc_engine *uc;

        memset(initial, 0xa5, sizeof(initial));
        memcpy(expected, initial, sizeof(expected));
        memcpy(expected + 15 * sizeof(uint32_t), &result, sizeof(result));
        setup_x86(&uc, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, boundary, &input, sizeof(input)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        TEST_CHECK(memcmp(observed, expected, sizeof(expected)) == 0);
        OK(uc_close(uc));
    }
}

static void run_invalid_cases(void)
{
    static const struct {
        uint8_t code[7];
        size_t size;
        const char *name;
    } cases[] = {
        {{0x62, 0xf2, 0x7d, 0x18, 0x4c, 0xca}, 6, "packed register EVEX.b"},
        {{0x62, 0xf2, 0x15, 0x18, 0x4d, 0xca}, 6, "scalar register EVEX.b"},
        {{0x62, 0xf2, 0x15, 0x18, 0x4d, 0x08}, 6, "scalar memory EVEX.b"},
        {{0x62, 0xf2, 0x7d, 0x68, 0x4c, 0xca}, 6, "packed register LL3"},
        {{0x62, 0xf2, 0x7d, 0x68, 0x4c, 0x08}, 6, "packed full-memory LL3"},
        {{0x62, 0xf2, 0x7d, 0x78, 0x4c, 0x08}, 6, "packed broadcast LL3"},
        {{0x62, 0xf2, 0x75, 0x48, 0x4c, 0x08}, 6, "packed memory vvvv"},
        {{0x62, 0xf2, 0x7d, 0x40, 0x4c, 0x08}, 6, "packed memory V-prime"},
        {{0x62, 0xf2, 0x7d, 0xc8, 0x4c, 0x08}, 6, "memory zeroing K0"},
        {{0xf0, 0x62, 0xf2, 0x7d, 0x48, 0x4c, 0x08}, 7, "memory LOCK prefix"},
    };

    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint8_t initial[64];
        uint8_t observed[64];
        uint64_t rax = UINT64_C(0x8000);
        uint64_t rip = 0;
        uint32_t mxcsr = UINT32_C(0x1fa5);
        uc_engine *uc;
        uc_err err;

        memset(initial, 0xa5, sizeof(initial));
        setup_x86(&uc, cases[index].code, cases[index].size);
        OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        err =
            uc_emu_start(uc, code_start, code_start + cases[index].size, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM1, observed));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    cases[index].name);
        TEST_CHECK_(memcmp(observed, initial, sizeof(initial)) == 0,
                    "%s changed destination", cases[index].name);
        TEST_CHECK_(rip == code_start, "%s advanced RIP", cases[index].name);
        TEST_CHECK_(mxcsr == UINT32_C(0x1fa5), "%s changed MXCSR",
                    cases[index].name);
        OK(uc_close(uc));
    }
}

static void run_high_register_encoding_cases(void)
{
    static const struct {
        uint8_t code[6];
        int destination;
        int source;
        const char *name;
    } cases[] = {
        {{0x62, 0x72, 0x7d, 0x08, 0x4c, 0xc2},
         UC_X86_REG_XMM8,
         UC_X86_REG_XMM2,
         "destination XMM8"},
        {{0x62, 0xe2, 0x7d, 0x08, 0x4c, 0xc2},
         UC_X86_REG_XMM16,
         UC_X86_REG_XMM2,
         "destination XMM16"},
        {{0x62, 0xd2, 0x7d, 0x08, 0x4c, 0xc8},
         UC_X86_REG_XMM1,
         UC_X86_REG_XMM8,
         "source XMM8"},
        {{0x62, 0xb2, 0x7d, 0x08, 0x4c, 0xc8},
         UC_X86_REG_XMM1,
         UC_X86_REG_XMM16,
         "source XMM16"},
    };
    static const uint32_t source[4] = {
        UINT32_C(0x40400000),
        UINT32_C(0x40000000),
        UINT32_C(0x3f800000),
        UINT32_C(0x3fc00000),
    };
    static const uint32_t expected[4] = {
        UINT32_C(0x3eaaaa80),
        UINT32_C(0x3f000000),
        UINT32_C(0x3f800000),
        UINT32_C(0x3f2aaa80),
    };

    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint8_t initial[16];
        uint8_t observed[16];
        uc_engine *uc;

        memset(initial, 0xa5, sizeof(initial));
        setup_x86(&uc, cases[index].code, sizeof(cases[index].code));
        OK(uc_reg_write(uc, cases[index].destination, initial));
        OK(uc_reg_write(uc, cases[index].source, source));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(cases[index].code),
                        0, 0));
        OK(uc_reg_read(uc, cases[index].destination, observed));
        TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                    "%s decoded incorrectly", cases[index].name);
        OK(uc_close(uc));
    }
}

static void run_32bit_mode_case(void)
{
    /* LLVM MC i386 encoding: vrcp14ps 16(%eax), %xmm1 {%k7}. */
    static const uint8_t code[] = {
        0x62, 0xf2, 0x7d, 0x0f, 0x4c, 0x48, 0x01,
    };
    static const uint32_t source[] = {
        UINT32_C(0x40400000),
        UINT32_C(0x40000000),
        UINT32_C(0x3f800000),
        UINT32_C(0x3fc00000),
    };
    static const uint32_t expected_low[] = {
        UINT32_C(0x3eaaaa80),
        UINT32_C(0x3f000000),
        UINT32_C(0x3f800000),
        UINT32_C(0x3f2aaa80),
    };
    uint8_t initial[16];
    uint8_t expected[16] = {0};
    uint8_t observed[16];
    uint32_t eax = (uint32_t)data_page;
    uint32_t eip = 0;
    uint64_t mask = UINT64_C(0xf);
    uc_engine *uc;

    memset(initial, 0xa5, sizeof(initial));
    memcpy(expected, expected_low, sizeof(expected_low));
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_ICELAKE_SERVER));
    OK(uc_mem_map(uc, code_start, code_size, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, data_page + 16, source, sizeof(source)));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, initial));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 1));
    OK(uc_reg_read(uc, UC_X86_REG_XMM1, observed));
    OK(uc_reg_read(uc, UC_X86_REG_EIP, &eip));
    TEST_CHECK(memcmp(observed, expected, sizeof(expected)) == 0);
    TEST_CHECK(eip == code_start + sizeof(code));
    OK(uc_close(uc));

    /* A following byte without mod=11 remains the legacy BOUND opcode. */
    {
        static const uint8_t bound_code[] = {0x62, 0x01};
        static const int32_t bounds[] = {0, 10};
        uint32_t bound_eax = 5;
        uint32_t ecx = (uint32_t)data_page;
        uint32_t bound_eip = 0;
        uc_engine *bound_uc;

        OK(uc_open(UC_ARCH_X86, UC_MODE_32, &bound_uc));
        OK(uc_ctl_set_cpu_model(bound_uc, UC_CPU_X86_ICELAKE_SERVER));
        OK(uc_mem_map(bound_uc, code_start, code_size, UC_PROT_ALL));
        OK(uc_mem_write(bound_uc, code_start, bound_code, sizeof(bound_code)));
        OK(uc_mem_map(bound_uc, data_page, 0x1000,
                      UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(bound_uc, data_page, bounds, sizeof(bounds)));
        OK(uc_reg_write(bound_uc, UC_X86_REG_EAX, &bound_eax));
        OK(uc_reg_write(bound_uc, UC_X86_REG_ECX, &ecx));
        OK(uc_emu_start(bound_uc, code_start, code_start + sizeof(bound_code),
                        0, 1));
        OK(uc_reg_read(bound_uc, UC_X86_REG_EIP, &bound_eip));
        TEST_CHECK(bound_eip == code_start + sizeof(bound_code));
        OK(uc_close(bound_uc));
    }

    /* EVEX extension-register encodings remain illegal outside 64-bit mode. */
    {
        static const uint8_t high_register_code[] = {
            0x62, 0xe2, 0x7d, 0x08, 0x4c, 0xc2,
        };
        uint32_t high_eip = 0;
        uc_engine *high_uc;
        uc_err err;

        OK(uc_open(UC_ARCH_X86, UC_MODE_32, &high_uc));
        OK(uc_ctl_set_cpu_model(high_uc, UC_CPU_X86_ICELAKE_SERVER));
        OK(uc_mem_map(high_uc, code_start, code_size, UC_PROT_ALL));
        OK(uc_mem_write(high_uc, code_start, high_register_code,
                        sizeof(high_register_code)));
        err = uc_emu_start(high_uc, code_start,
                           code_start + sizeof(high_register_code), 0, 1);
        OK(uc_reg_read(high_uc, UC_X86_REG_EIP, &high_eip));
        TEST_CHECK(err == UC_ERR_INSN_INVALID);
        TEST_CHECK(high_eip == code_start);
        OK(uc_close(high_uc));
    }
}

static void test_x86_evex_approx14_memory_semantics(void)
{
    /* LLVM MC/XED encoding: vrcp14ps 16(%rax), %xmm31 {%k7}. */
    static const uint8_t code[] = {
        0x62, 0x62, 0x7d, 0x0f, 0x4c, 0x78, 0x01,
    };
    static const uint32_t source[] = {
        UINT32_C(0x40400000),
        UINT32_C(0x40000000),
        UINT32_C(0x3f800000),
        UINT32_C(0x3fc00000),
    };
    static const uint32_t expected[] = {
        UINT32_C(0x3eaaaa80),
        UINT32_C(0x3f000000),
        UINT32_C(0x3f800000),
        UINT32_C(0x3f2aaa80),
    };
    uint8_t initial[64];
    uint8_t observed[64];
    uint64_t rax = data_page;
    uint64_t mask = UINT64_C(0xf);
    uc_engine *uc;

    memset(initial, 0xa5, sizeof(initial));
    setup_x86(&uc, code, sizeof(code));
    OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, data_page + 16, source, sizeof(source)));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    TEST_CHECK(memcmp(observed, expected, sizeof(expected)) == 0);
    TEST_CHECK(memcmp(observed + 16, (uint8_t[48]){0}, 48) == 0);
    OK(uc_close(uc));

    /* LLVM MC/XED encoding: vrsqrt14pd 8(%rax){1to8}, %zmm31 {%k7}. */
    {
        static const uint8_t broadcast_code[] = {
            0x62, 0x62, 0xfd, 0x5f, 0x4e, 0x78, 0x01,
        };
        const uint64_t input = UINT64_C(0x4008000000000000);
        const uint64_t result = UINT64_C(0x3fe2799000000000);
        const uint64_t broadcast_mask = UINT64_C(0x8a);
        uint64_t broadcast_expected[8];
        uint8_t broadcast_initial[64];
        uint8_t broadcast_observed[64];
        uint64_t broadcast_rax = data_page;
        uc_engine *broadcast_uc;

        for (size_t byte = 0; byte < sizeof(broadcast_initial); ++byte) {
            broadcast_initial[byte] = (uint8_t)(0xa7 - byte * 3);
        }
        memcpy(broadcast_expected, broadcast_initial,
               sizeof(broadcast_expected));
        for (size_t element = 0; element < 8; ++element) {
            if ((broadcast_mask >> element) & 1) {
                broadcast_expected[element] = result;
            }
        }
        setup_x86(&broadcast_uc, broadcast_code, sizeof(broadcast_code));
        OK(uc_mem_map(broadcast_uc, data_page, 0x1000,
                      UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(broadcast_uc, data_page + 8, &input, sizeof(input)));
        OK(uc_reg_write(broadcast_uc, UC_X86_REG_ZMM31, broadcast_initial));
        OK(uc_reg_write(broadcast_uc, UC_X86_REG_RAX, &broadcast_rax));
        OK(uc_reg_write(broadcast_uc, UC_X86_REG_K7, &broadcast_mask));
        OK(uc_emu_start(broadcast_uc, code_start,
                        code_start + sizeof(broadcast_code), 0, 0));
        OK(uc_reg_read(broadcast_uc, UC_X86_REG_ZMM31, broadcast_observed));
        TEST_CHECK(memcmp(broadcast_observed, broadcast_expected,
                          sizeof(broadcast_expected)) == 0);
        OK(uc_close(broadcast_uc));
    }

    /* LLVM MC/XED encoding: vrcp14ss 508(%r13), %xmm29,
     * %xmm31 {%k7} {z}. */
    {
        static const uint8_t scalar_code[] = {
            0x62, 0x42, 0x15, 0x87, 0x4d, 0x7d, 0x7f,
        };
        const uint32_t input = UINT32_C(0x40400000);
        const uint32_t result = UINT32_C(0x3eaaaa80);
        uint8_t scalar_source1[64];
        uint8_t scalar_expected[64] = {0};
        uint8_t scalar_observed[64];
        uint64_t r13 = data_page;
        uint64_t scalar_mask = 1;
        uc_engine *scalar_uc;

        for (size_t byte = 0; byte < sizeof(scalar_source1); ++byte) {
            scalar_source1[byte] = (uint8_t)(0x31 + byte * 7);
        }
        memcpy(scalar_expected, &result, sizeof(result));
        memcpy(scalar_expected + sizeof(result),
               scalar_source1 + sizeof(result), 16 - sizeof(result));
        setup_x86(&scalar_uc, scalar_code, sizeof(scalar_code));
        OK(uc_mem_map(scalar_uc, data_page, 0x1000,
                      UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(scalar_uc, data_page + 508, &input, sizeof(input)));
        OK(uc_reg_write(scalar_uc, UC_X86_REG_ZMM29, scalar_source1));
        OK(uc_reg_write(scalar_uc, UC_X86_REG_R13, &r13));
        OK(uc_reg_write(scalar_uc, UC_X86_REG_K7, &scalar_mask));
        OK(uc_emu_start(scalar_uc, code_start, code_start + sizeof(scalar_code),
                        0, 0));
        OK(uc_reg_read(scalar_uc, UC_X86_REG_ZMM31, scalar_observed));
        TEST_CHECK(memcmp(scalar_observed, scalar_expected,
                          sizeof(scalar_expected)) == 0);
        OK(uc_close(scalar_uc));
    }

    run_shape_matrix();
    run_special_value_cases();
    run_fault_suppression_cases();
    run_invalid_cases();
    run_high_register_encoding_cases();
    run_32bit_mode_case();
}

TEST_LIST = {
    {"test_x86_evex_approx14_memory_semantics",
     test_x86_evex_approx14_memory_semantics},
    {NULL, NULL},
};
