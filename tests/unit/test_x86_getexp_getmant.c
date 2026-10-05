#include "unicorn_test.h"

static const uint64_t code_start = UINT64_C(0x1000);
static const uint64_t code_size = UINT64_C(0x2000);
static const uint64_t data_page = UINT64_C(0x4000);

typedef enum GetKind {
    GET_EXPONENT,
    GET_MANTISSA,
} GetKind;

typedef struct GetOp {
    const char *name;
    GetKind kind;
    bool scalar;
    bool is_double;
} GetOp;

typedef struct InterruptRecord {
    uint32_t vector;
    uint32_t count;
} InterruptRecord;

static const GetOp operations[] = {
    {"VGETEXPPS", GET_EXPONENT, false, false},
    {"VGETEXPPD", GET_EXPONENT, false, true},
    {"VGETEXPSS", GET_EXPONENT, true, false},
    {"VGETEXPSD", GET_EXPONENT, true, true},
    {"VGETMANTPS", GET_MANTISSA, false, false},
    {"VGETMANTPD", GET_MANTISSA, false, true},
    {"VGETMANTSS", GET_MANTISSA, true, false},
    {"VGETMANTSD", GET_MANTISSA, true, true},
};

static void setup_x86(uc_engine **uc, uc_mode mode, const uint8_t *code,
                      size_t size)
{
    OK(uc_open(UC_ARCH_X86, mode, uc));
    OK(uc_ctl_set_cpu_model(*uc, UC_CPU_X86_ICELAKE_SERVER));
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

static void set_element(uint8_t *bytes, size_t element, size_t element_bytes,
                        uint64_t value)
{
    memcpy(bytes + element * element_bytes, &value, element_bytes);
}

static uint64_t get_element(const uint8_t *bytes, size_t element,
                            size_t element_bytes)
{
    uint64_t value = 0;

    memcpy(&value, bytes + element * element_bytes, element_bytes);
    return value;
}

static size_t encode_get(uint8_t code[10], const GetOp *op,
                         size_t vector_bytes, unsigned int dst,
                         unsigned int src1, unsigned int src2_or_base,
                         unsigned int mask, bool zeroing, bool memory,
                         bool evex_b, unsigned int ll, unsigned int immediate,
                         bool disp8, int8_t displacement)
{
    uint8_t p0 = op->kind == GET_MANTISSA ? 0xf3 : 0xf2;
    uint8_t p1 = (op->is_double ? 0x80 : 0) | 0x05;
    uint8_t p2;
    size_t length = 6;

    TEST_CHECK(dst < 32 && src1 < 32 && src2_or_base < 32 && mask < 8);
    TEST_CHECK(vector_bytes == 16 || vector_bytes == 32 || vector_bytes == 64);
    TEST_CHECK(!memory || src2_or_base < 16);
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
    } else {
        p1 |= 0x78;
        p2 = 0x08;
    }

    code[0] = 0x62;
    code[1] = p0;
    code[2] = p1;
    code[3] = (uint8_t)(p2 | ((ll & 3) << 5) | mask |
                        (zeroing ? 0x80 : 0) | (evex_b ? 0x10 : 0));
    code[4] = (uint8_t)(op->kind == GET_MANTISSA
                            ? (op->scalar ? 0x27 : 0x26)
                            : (op->scalar ? 0x43 : 0x42));
    code[5] = (uint8_t)((memory ? (disp8 ? 0x40 : 0) : 0xc0) |
                        ((dst & 7) << 3) | (src2_or_base & 7));
    if (memory && disp8) {
        code[length++] = (uint8_t)displacement;
    }
    if (op->kind == GET_MANTISSA) {
        code[length++] = (uint8_t)immediate;
    }
    return length;
}

static uint64_t normal_input(const GetOp *op)
{
    if (op->kind == GET_EXPONENT) {
        return op->is_double ? UINT64_C(0x4020000000000000)
                             : UINT64_C(0x41000000); /* 8.0 */
    }
    return op->is_double ? UINT64_C(0x4008000000000000)
                         : UINT64_C(0x40400000); /* 3.0 */
}

static uint64_t shape_output(const GetOp *op)
{
    if (op->kind == GET_EXPONENT) {
        return op->is_double ? UINT64_C(0x4008000000000000)
                             : UINT64_C(0x40400000); /* 3.0 */
    }
    return op->is_double ? UINT64_C(0x3ff8000000000000)
                         : UINT64_C(0x3fc00000); /* 1.5 */
}

static unsigned int normal_ll(size_t vector_bytes)
{
    return vector_bytes == 16 ? 0 : vector_bytes == 32 ? 1 : 2;
}

static bool run_shape_case(const GetOp *op, size_t vector_bytes, bool memory,
                           bool evex_b, unsigned int ll, uint64_t mask,
                           bool zeroing)
{
    const size_t element_bytes = op->is_double ? 8 : 4;
    const size_t elements = op->scalar ? 1 : vector_bytes / element_bytes;
    const size_t disp8_scale =
        op->scalar || evex_b ? element_bytes : vector_bytes;
    uint8_t initial[64];
    uint8_t source1[64];
    uint8_t source2[64] = {0};
    uint8_t memory_source[64] = {0};
    uint8_t expected[64];
    uint8_t observed[64];
    uint8_t code[10];
    const size_t code_length = encode_get(
        code, op, vector_bytes, 31, 29, memory ? 13 : 30, 7, zeroing, memory,
        evex_b, ll, 0, memory, 1);
    uint64_t r13 = data_page;
    uint32_t mxcsr = UINT32_C(0x1f80);
    uc_engine *uc;

    for (size_t byte = 0; byte < 64; ++byte) {
        initial[byte] = (uint8_t)(0xa7 - byte * 3);
        source1[byte] = (uint8_t)(0x31 + byte * 7);
    }
    for (size_t element = 0; element < elements; ++element) {
        set_element(source2, element, element_bytes, normal_input(op));
        set_element(memory_source, element, element_bytes, normal_input(op));
    }
    memcpy(expected, initial, sizeof(expected));
    for (size_t element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            set_element(expected, element, element_bytes, shape_output(op));
        } else if (zeroing) {
            set_element(expected, element, element_bytes, 0);
        }
    }
    if (op->scalar) {
        memcpy(expected + element_bytes, source1 + element_bytes,
               16 - element_bytes);
        memset(expected + 16, 0, 48);
    } else {
        memset(expected + vector_bytes, 0, 64 - vector_bytes);
    }

    setup_x86(&uc, UC_MODE_64, code, code_length);
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
    OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    if (memory) {
        OK(uc_mem_map(uc, data_page, 0x3000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, data_page + disp8_scale, memory_source,
                        evex_b ? element_bytes : elements * element_bytes));
        OK(uc_reg_write(uc, UC_X86_REG_R13, &r13));
    } else {
        OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source2));
    }
    OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                "%s %s VL%zu LL%u result mismatch", op->name,
                memory ? (evex_b ? "broadcast" : "full-memory")
                       : (evex_b ? "SAE register" : "register"),
                vector_bytes * 8, ll);
    TEST_CHECK_(mxcsr == UINT32_C(0x1f80), "%s changed MXCSR", op->name);
    OK(uc_close(uc));
    return true;
}

static void test_x86_evex_vget_shape_matrix(void)
{
    static const size_t vector_bytes[] = {16, 32, 64};
    const uint64_t packed_mask = UINT64_C(0xa55a);

    for (size_t op_index = 0;
         op_index < sizeof(operations) / sizeof(operations[0]); ++op_index) {
        const GetOp *op = &operations[op_index];

        if (op->scalar) {
            for (unsigned int ll = 0; ll < 4; ++ll) {
                TEST_CHECK(run_shape_case(op, 16, false, false, ll, 1,
                                          (ll & 1) != 0));
                TEST_CHECK(run_shape_case(op, 16, true, false, ll, 1,
                                          (ll & 1) == 0));
                TEST_CHECK(run_shape_case(op, 16, false, true, ll, 1,
                                          (ll & 1) != 0));
            }
            continue;
        }

        for (size_t vl = 0; vl < 3; ++vl) {
            const unsigned int ll = normal_ll(vector_bytes[vl]);

            TEST_CHECK(run_shape_case(op, vector_bytes[vl], false, false, ll,
                                      packed_mask, (vl & 1) != 0));
            TEST_CHECK(run_shape_case(op, vector_bytes[vl], true, false, ll,
                                      packed_mask, (vl & 1) == 0));
            TEST_CHECK(run_shape_case(op, vector_bytes[vl], true, true, ll,
                                      packed_mask, (vl & 1) != 0));
        }
        for (unsigned int ll = 0; ll < 4; ++ll) {
            TEST_CHECK(run_shape_case(op, 64, false, true, ll, packed_mask,
                                      (ll & 1) != 0));
        }
    }
}

static bool run_scalar_expected(const GetOp *op, uint64_t input,
                                unsigned int immediate, bool sae,
                                uint32_t initial_mxcsr, uint64_t expected_low,
                                uint32_t expected_mxcsr)
{
    const size_t element_bytes = op->is_double ? 8 : 4;
    uint8_t initial[64];
    uint8_t source1[64];
    uint8_t source2[64] = {0};
    uint8_t expected[64];
    uint8_t observed[64];
    uint8_t code[10];
    const size_t code_length = encode_get(code, op, 16, 31, 29, 30, 0, false,
                                          false, sae, sae ? 3 : 0, immediate,
                                          false, 0);
    uint32_t mxcsr = initial_mxcsr;
    uc_engine *uc;

    TEST_CHECK(op->scalar);
    for (size_t byte = 0; byte < 64; ++byte) {
        initial[byte] = (uint8_t)(0xa7 - byte * 3);
        source1[byte] = (uint8_t)(0x31 + byte * 7);
    }
    set_element(source2, 0, element_bytes, input);
    memcpy(expected, initial, sizeof(expected));
    set_element(expected, 0, element_bytes, expected_low);
    memcpy(expected + element_bytes, source1 + element_bytes,
           16 - element_bytes);
    memset(expected + 16, 0, 48);

    setup_x86(&uc, UC_MODE_64, code, code_length);
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source2));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                "%s special result mismatch", op->name);
    TEST_CHECK_(mxcsr == expected_mxcsr, "%s MXCSR mismatch: 0x%x", op->name,
                mxcsr);
    OK(uc_close(uc));
    return true;
}

static void test_x86_evex_vgetexp_special_values(void)
{
    const GetOp *ss = &operations[2];
    const GetOp *sd = &operations[3];

    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x41000000), 0, false,
                                   UINT32_C(0x1f80), UINT32_C(0x40400000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x00000000), 0, false,
                                   UINT32_C(0x1f80), UINT32_C(0xff800000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x80000000), 0, false,
                                   UINT32_C(0x1f80), UINT32_C(0xff800000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0xff800000), 0, false,
                                   UINT32_C(0x1f80), UINT32_C(0x7f800000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0xffc12345), 0, false,
                                   UINT32_C(0x1f80), UINT32_C(0xffc12345),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0xff812345), 0, false,
                                   UINT32_C(0x1f80), UINT32_C(0xffc12345),
                                   UINT32_C(0x1f81)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x00000001), 0, false,
                                   UINT32_C(0x1f80), UINT32_C(0xc3150000),
                                   UINT32_C(0x1f82))); /* -149.0 */
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x007fffff), 0, false,
                                   UINT32_C(0x1f80), UINT32_C(0xc2fe0000),
                                   UINT32_C(0x1f82))); /* -127.0 */
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x00000001), 0, false,
                                   UINT32_C(0x1fc0), UINT32_C(0xff800000),
                                   UINT32_C(0x1fc0)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x7f812345), 0, true,
                                   UINT32_C(0x1f80), UINT32_C(0x7fc12345),
                                   UINT32_C(0x1f80)));

    TEST_CHECK(run_scalar_expected(sd, UINT64_C(0x4020000000000000), 0,
                                   false, UINT32_C(0x1f80),
                                   UINT64_C(0x4008000000000000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(sd, UINT64_C(0x0000000000000001), 0,
                                   false, UINT32_C(0x1f80),
                                   UINT64_C(0xc090c80000000000),
                                   UINT32_C(0x1f82))); /* -1074.0 */
    TEST_CHECK(run_scalar_expected(sd, UINT64_C(0x7ff0000000001234), 0,
                                   false, UINT32_C(0x1f80),
                                   UINT64_C(0x7ff8000000001234),
                                   UINT32_C(0x1f81)));
}

static void test_x86_evex_vgetmant_special_values(void)
{
    const GetOp *ss = &operations[6];
    const GetOp *sd = &operations[7];

    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x40400000), 0, false,
                                   UINT32_C(0x1f80), UINT32_C(0x3fc00000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x40400000), 1, false,
                                   UINT32_C(0x1f80), UINT32_C(0x3f400000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x40c00000), 1, false,
                                   UINT32_C(0x1f80), UINT32_C(0x3fc00000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x40c00000), 2, false,
                                   UINT32_C(0x1f80), UINT32_C(0x3f400000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x3fa00000), 3, false,
                                   UINT32_C(0x1f80), UINT32_C(0x3fa00000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x3fe00000), 3, false,
                                   UINT32_C(0x1f80), UINT32_C(0x3f600000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0xc0400000), 0, false,
                                   UINT32_C(0x1f80), UINT32_C(0xbfc00000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0xc0400000), 4, false,
                                   UINT32_C(0x1f80), UINT32_C(0x3fc00000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0xc0400000), 8, false,
                                   UINT32_C(0x1f80), UINT32_C(0xffc00000),
                                   UINT32_C(0x1f81)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x80000000), 8, false,
                                   UINT32_C(0x1f80), UINT32_C(0xbf800000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x80000000), 12, false,
                                   UINT32_C(0x1f80), UINT32_C(0x3f800000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0xff800000), 0, false,
                                   UINT32_C(0x1f80), UINT32_C(0xbf800000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0xff800000), 8, false,
                                   UINT32_C(0x1f80), UINT32_C(0xffc00000),
                                   UINT32_C(0x1f81)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x7f800000), 15, false,
                                   UINT32_C(0x1f80), UINT32_C(0x3f800000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0xffc12345), 8, false,
                                   UINT32_C(0x1f80), UINT32_C(0xffc12345),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0xff812345), 8, false,
                                   UINT32_C(0x1f80), UINT32_C(0xffc12345),
                                   UINT32_C(0x1f81)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x00000001), 0, false,
                                   UINT32_C(0x1f80), UINT32_C(0x3f800000),
                                   UINT32_C(0x1f82)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x00000001), 1, false,
                                   UINT32_C(0x1f80), UINT32_C(0x3f000000),
                                   UINT32_C(0x1f82)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x007fffff), 0, false,
                                   UINT32_C(0x1f80), UINT32_C(0x3ffffffe),
                                   UINT32_C(0x1f82)));
    /* Invalid sign control takes priority over denormal normalization. */
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x80000001), 8, false,
                                   UINT32_C(0x1f80), UINT32_C(0xffc00000),
                                   UINT32_C(0x1f81)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x80000001), 8, false,
                                   UINT32_C(0x1fc0), UINT32_C(0xbf800000),
                                   UINT32_C(0x1fc0)));
    /* SDM uses only imm8[3:0], and XED exposes an unconstrained UIMM8. */
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x40400000), 0xf0, false,
                                   UINT32_C(0x1f80), UINT32_C(0x3fc00000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0xc0400000), 8, true,
                                   UINT32_C(0x1f80), UINT32_C(0xffc00000),
                                   UINT32_C(0x1f80)));

    TEST_CHECK(run_scalar_expected(sd, UINT64_C(0x4008000000000000), 1,
                                   false, UINT32_C(0x1f80),
                                   UINT64_C(0x3fe8000000000000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(sd, UINT64_C(0x0000000000000001), 1,
                                   false, UINT32_C(0x1f80),
                                   UINT64_C(0x3ff0000000000000),
                                   UINT32_C(0x1f82)));
    TEST_CHECK(run_scalar_expected(sd, UINT64_C(0xfff0000000001234), 8,
                                   false, UINT32_C(0x1f80),
                                   UINT64_C(0xfff8000000001234),
                                   UINT32_C(0x1f81)));
}

static void run_unmasked_exception(const GetOp *op, uint64_t input,
                                   unsigned int immediate)
{
    const size_t element_bytes = op->is_double ? 8 : 4;
    uint8_t initial[64];
    uint8_t source1[64] = {0};
    uint8_t source2[64] = {0};
    uint8_t observed[64];
    uint8_t code[10];
    const size_t code_length = encode_get(code, op, 16, 31, 29, 30, 0, false,
                                          false, false, 0, immediate, false,
                                          0);
    uint64_t cr4;
    uint64_t rip = 0;
    uint32_t mxcsr = UINT32_C(0x1f00);
    InterruptRecord record = {0};
    uc_engine *uc;
    uc_hook hook;

    memset(initial, 0xa5, sizeof(initial));
    set_element(source2, 0, element_bytes, input);
    setup_x86(&uc, UC_MODE_64, code, code_length);
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source2));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
    cr4 |= UINT64_C(1) << 10;
    OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));
    OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, record_interrupt, &record, 1, 0));
    OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    TEST_CHECK_(record.count == 1 && record.vector == 19,
                "%s did not raise #XM", op->name);
    TEST_CHECK(memcmp(observed, initial, sizeof(initial)) == 0);
    TEST_CHECK(mxcsr == UINT32_C(0x1f01));
    TEST_CHECK(rip == code_start);
    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

static void test_x86_evex_vget_exceptions_and_masking(void)
{
    run_unmasked_exception(&operations[2], UINT32_C(0x7f812345), 0);
    run_unmasked_exception(&operations[6], UINT32_C(0xc0400000), 8);

    for (size_t which = 0; which < 2; ++which) {
        const GetOp *op = which ? &operations[6] : &operations[2];
        uint8_t initial[64];
        uint8_t source1[64];
        uint8_t source2[64] = {0};
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[10];
        const bool zeroing = which != 0;
        const size_t code_length = encode_get(
            code, op, 16, 31, 29, 30, 7, zeroing, false, false, 0,
            which ? 8 : 0, false, 0);
        uint64_t mask = 0;
        uint32_t mxcsr = UINT32_C(0x1f80);
        uc_engine *uc;

        for (size_t byte = 0; byte < 64; ++byte) {
            initial[byte] = (uint8_t)(0xa7 - byte * 3);
            source1[byte] = (uint8_t)(0x31 + byte * 7);
        }
        set_element(source2, 0, 4,
                    which ? UINT32_C(0xc0400000) : UINT32_C(0x7f812345));
        memcpy(expected, initial, sizeof(expected));
        if (zeroing) {
            set_element(expected, 0, 4, 0);
        }
        memcpy(expected + 4, source1 + 4, 12);
        memset(expected + 16, 0, 48);

        setup_x86(&uc, UC_MODE_64, code, code_length);
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source2));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK(memcmp(observed, expected, sizeof(expected)) == 0);
        TEST_CHECK(mxcsr == UINT32_C(0x1f80));
        OK(uc_close(uc));
    }

    /* Packed EVEX.b is SAE and fixes the effective length at 512 bits. */
    for (size_t which = 0; which < 2; ++which) {
        const GetOp *op = which ? &operations[4] : &operations[0];
        uint8_t source[64] = {0};
        uint8_t observed[64];
        uint8_t code[10];
        const size_t code_length = encode_get(code, op, 64, 31, 0, 30, 0,
                                              false, false, true, 1,
                                              which ? 8 : 0, false, 0);
        uint32_t mxcsr = UINT32_C(0x1f80);
        uc_engine *uc;

        set_element(source, 0, 4,
                    which ? UINT32_C(0xc0400000) : UINT32_C(0x7f812345));
        setup_x86(&uc, UC_MODE_64, code, code_length);
        OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK(get_element(observed, 0, 4) ==
                   (which ? UINT32_C(0xffc00000) : UINT32_C(0x7fc12345)));
        TEST_CHECK(mxcsr == UINT32_C(0x1f80));
        OK(uc_close(uc));
    }
}

static void test_x86_evex_vget_fault_suppression(void)
{
    const uint64_t boundary = data_page + UINT64_C(0xffc);

    for (size_t which = 0; which < 2; ++which) {
        const GetOp *op = which ? &operations[4] : &operations[0];
        const uint32_t memory_value =
            which ? UINT32_C(0x40400000) : UINT32_C(0x41000000);
        uint8_t initial[64];
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[10];
        const size_t code_length = encode_get(code, op, 64, 31, 0, 0, 7,
                                              false, true, false, 2, 0, false,
                                              0);
        uint64_t rax = boundary;
        uint64_t mask = 1;
        uc_engine *uc;

        memset(initial, 0xa5, sizeof(initial));
        memcpy(expected, initial, sizeof(expected));
        set_element(expected, 0, 4,
                    which ? UINT32_C(0x3fc00000) : UINT32_C(0x40400000));
        setup_x86(&uc, UC_MODE_64, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, boundary, &memory_value, sizeof(memory_value)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        TEST_CHECK(memcmp(observed, expected, sizeof(expected)) == 0);
        OK(uc_close(uc));
    }

    /* A later active-lane memory fault precedes all result and MXCSR writes. */
    for (size_t which = 0; which < 2; ++which) {
        const GetOp *op = which ? &operations[4] : &operations[0];
        const uint32_t memory_value = UINT32_C(0x7f812345);
        uint8_t initial[64];
        uint8_t observed[64];
        uint8_t code[10];
        const size_t code_length = encode_get(code, op, 64, 31, 0, 0, 7,
                                              false, true, false, 2,
                                              which ? 8 : 0, false, 0);
        uint64_t rax = boundary;
        uint64_t mask = 3;
        uint64_t rip = 0;
        uint32_t mxcsr = UINT32_C(0x1f80);
        uc_engine *uc;
        uc_err err;

        memset(initial, 0x5a, sizeof(initial));
        setup_x86(&uc, UC_MODE_64, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, boundary, &memory_value, sizeof(memory_value)));
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
        TEST_CHECK(mxcsr == UINT32_C(0x1f80));
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }

    /* An all-zero mask suppresses the sole broadcast access. */
    for (size_t which = 0; which < 2; ++which) {
        const GetOp *op = which ? &operations[5] : &operations[1];
        uint8_t initial[64];
        uint8_t observed[64];
        uint8_t code[10];
        const size_t code_length = encode_get(code, op, 32, 31, 0, 0, 7, true,
                                              true, true, 1, 0, false, 0);
        uint64_t rax = UINT64_C(0x8000);
        uint64_t mask = 0;
        uc_engine *uc;

        memset(initial, 0xa5, sizeof(initial));
        setup_x86(&uc, UC_MODE_64, code, code_length);
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        TEST_CHECK(memcmp(observed, (uint8_t[64]){0}, 64) == 0);
        OK(uc_close(uc));
    }

    /* A masked-off scalar Tuple1 source is not accessed; upper bits still
     * come from the first register source. */
    for (size_t which = 0; which < 2; ++which) {
        const GetOp *op = which ? &operations[7] : &operations[3];
        uint8_t initial[64];
        uint8_t source1[64];
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[10];
        const size_t code_length = encode_get(code, op, 16, 31, 29, 0, 7,
                                              false, true, false, 3, 0, false,
                                              0);
        uint64_t rax = UINT64_C(0x8000);
        uint64_t mask = 0;
        uc_engine *uc;

        for (size_t byte = 0; byte < 64; ++byte) {
            initial[byte] = (uint8_t)(0xa7 - byte * 3);
            source1[byte] = (uint8_t)(0x31 + byte * 7);
        }
        memcpy(expected, initial, sizeof(expected));
        memcpy(expected + 8, source1 + 8, 8);
        memset(expected + 16, 0, 48);
        setup_x86(&uc, UC_MODE_64, code, code_length);
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        TEST_CHECK(memcmp(observed, expected, sizeof(expected)) == 0);
        OK(uc_close(uc));
    }
}

static void test_x86_evex_vget_memory_exception_and_rip(void)
{
    /* EVEX.b on packed memory is broadcast rather than SAE. */
    for (size_t which = 0; which < 2; ++which) {
        const GetOp *op = which ? &operations[4] : &operations[0];
        const uint32_t snan = UINT32_C(0x7f812345);
        uint8_t observed[64];
        uint8_t code[10];
        const size_t code_length = encode_get(code, op, 64, 31, 0, 0, 7,
                                              false, true, true, 2,
                                              which ? 8 : 0, false, 0);
        uint64_t rax = data_page;
        uint64_t mask = 1;
        uint32_t mxcsr = UINT32_C(0x1f80);
        uc_engine *uc;

        setup_x86(&uc, UC_MODE_64, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, data_page, &snan, sizeof(snan)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK(get_element(observed, 0, 4) == UINT32_C(0x7fc12345));
        TEST_CHECK(mxcsr == UINT32_C(0x1f81));
        OK(uc_close(uc));
    }

    /* The trailing imm8 participates in RIP-relative next-IP calculation. */
    {
        const uint64_t memory_address = code_start + UINT64_C(0x100);
        static const uint32_t source[4] = {
            UINT32_C(0x40400000), UINT32_C(0x40c00000),
            UINT32_C(0x3fa00000), UINT32_C(0x3fe00000),
        };
        static const uint32_t expected[4] = {
            UINT32_C(0x3fc00000), UINT32_C(0x3fc00000),
            UINT32_C(0x3fa00000), UINT32_C(0x3fe00000),
        };
        uint8_t code[] = {
            0x62, 0xf3, 0x7d, 0x08, 0x26, 0x0d,
            0,    0,    0,    0,    0,
        };
        const int32_t displacement =
            (int32_t)(memory_address - (code_start + sizeof(code)));
        uint32_t observed[4];
        uc_engine *uc;

        memcpy(&code[6], &displacement, sizeof(displacement));
        setup_x86(&uc, UC_MODE_64, code, sizeof(code));
        OK(uc_mem_write(uc, memory_address, source, sizeof(source)));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_XMM1, observed));
        TEST_CHECK(memcmp(observed, expected, sizeof(expected)) == 0);
        OK(uc_close(uc));
    }
}

static void test_x86_evex_vget_aliasing(void)
{
    for (size_t op_index = 0;
         op_index < sizeof(operations) / sizeof(operations[0]); ++op_index) {
        const GetOp *op = &operations[op_index];
        const size_t element_bytes = op->is_double ? 8 : 4;
        const size_t vector_bytes = op->scalar ? 16 : 64;
        uint8_t value[64];
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[10];
        const size_t code_length = encode_get(
            code, op, vector_bytes, 30, 30, 30, 0, false, false, false,
            op->scalar ? 3 : 2, 0, false, 0);
        const size_t elements = op->scalar ? 1 : 64 / element_bytes;
        uc_engine *uc;

        for (size_t byte = 0; byte < 64; ++byte) {
            value[byte] = (uint8_t)(0x31 + byte * 7);
        }
        for (size_t element = 0; element < elements; ++element) {
            set_element(value, element, element_bytes, normal_input(op));
        }
        memcpy(expected, value, sizeof(expected));
        for (size_t element = 0; element < elements; ++element) {
            set_element(expected, element, element_bytes, shape_output(op));
        }
        if (op->scalar) {
            memset(expected + 16, 0, 48);
        }

        setup_x86(&uc, UC_MODE_64, code, code_length);
        OK(uc_reg_write(uc, UC_X86_REG_ZMM30, value));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM30, observed));
        TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                    "%s alias mismatch", op->name);
        OK(uc_close(uc));
    }
}

static void test_x86_evex_vget_invalid(void)
{
    static const struct {
        const char *name;
        uint8_t code[8];
        size_t size;
    } cases[] = {
        {"packed vvvv", {0x62, 0xf2, 0x75, 0x08, 0x42, 0xca}, 6},
        {"packed V'", {0x62, 0xf2, 0x7d, 0x00, 0x42, 0xca}, 6},
        {"packed LL=3", {0x62, 0xf2, 0x7d, 0x68, 0x42, 0xca}, 6},
        {"packed memory LL=3",
         {0x62, 0xf2, 0x7d, 0x68, 0x42, 0x08}, 6},
        {"scalar memory EVEX.b",
         {0x62, 0xf2, 0x6d, 0x18, 0x43, 0x08}, 6},
        {"zeroing k0", {0x62, 0xf2, 0x7d, 0x88, 0x42, 0xca}, 6},
        {"wrong pp", {0x62, 0xf2, 0x7e, 0x08, 0x42, 0xca}, 6},
        {"mantissa packed vvvv",
         {0x62, 0xf3, 0x75, 0x08, 0x26, 0xca, 0x00}, 7},
        {"mantissa scalar memory EVEX.b",
         {0x62, 0xf3, 0x6d, 0x18, 0x27, 0x08, 0x00}, 7},
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
        setup_x86(&uc, UC_MODE_64, cases[index].code, cases[index].size);
        OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        err = uc_emu_start(uc, code_start, code_start + cases[index].size, 0,
                           0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM1, observed));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    cases[index].name);
        TEST_CHECK(memcmp(observed, initial, sizeof(initial)) == 0);
        TEST_CHECK(rip == code_start);
        TEST_CHECK(mxcsr == UINT32_C(0x1fa5));
        OK(uc_close(uc));
    }
}

static void test_x86_evex_vget_32bit(void)
{
    static const uint8_t getexp_code[] = {
        0x62, 0xf2, 0x7d, 0x08, 0x42, 0xca,
    };
    static const uint8_t getmant_code[] = {
        0x62, 0xf3, 0x7d, 0x08, 0x26, 0xca, 0x00,
    };
    static const uint32_t exp_source[4] = {
        UINT32_C(0x3f800000), UINT32_C(0x40000000),
        UINT32_C(0x3f000000), UINT32_C(0x40800000),
    };
    static const uint32_t exp_expected[4] = {
        UINT32_C(0x00000000), UINT32_C(0x3f800000),
        UINT32_C(0xbf800000), UINT32_C(0x40000000),
    };
    static const uint32_t mant_source[4] = {
        UINT32_C(0x40400000), UINT32_C(0x40c00000),
        UINT32_C(0x3fa00000), UINT32_C(0x3fe00000),
    };
    static const uint32_t mant_expected[4] = {
        UINT32_C(0x3fc00000), UINT32_C(0x3fc00000),
        UINT32_C(0x3fa00000), UINT32_C(0x3fe00000),
    };

    for (size_t which = 0; which < 2; ++which) {
        const uint8_t *code = which ? getmant_code : getexp_code;
        const size_t length = which ? sizeof(getmant_code)
                                    : sizeof(getexp_code);
        uint32_t observed[4];
        uc_engine *uc;

        memset(observed, 0xa5, sizeof(observed));
        setup_x86(&uc, UC_MODE_32, code, length);
        OK(uc_reg_write(uc, UC_X86_REG_XMM2,
                        which ? mant_source : exp_source));
        OK(uc_emu_start(uc, code_start, code_start + length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_XMM1, observed));
        TEST_CHECK(memcmp(observed, which ? mant_expected : exp_expected,
                          sizeof(observed)) == 0);
        OK(uc_close(uc));
    }
}

TEST_LIST = {
    {"test_x86_evex_vget_shape_matrix", test_x86_evex_vget_shape_matrix},
    {"test_x86_evex_vgetexp_special_values",
     test_x86_evex_vgetexp_special_values},
    {"test_x86_evex_vgetmant_special_values",
     test_x86_evex_vgetmant_special_values},
    {"test_x86_evex_vget_exceptions_and_masking",
     test_x86_evex_vget_exceptions_and_masking},
    {"test_x86_evex_vget_fault_suppression",
     test_x86_evex_vget_fault_suppression},
    {"test_x86_evex_vget_memory_exception_and_rip",
     test_x86_evex_vget_memory_exception_and_rip},
    {"test_x86_evex_vget_aliasing", test_x86_evex_vget_aliasing},
    {"test_x86_evex_vget_invalid", test_x86_evex_vget_invalid},
    {"test_x86_evex_vget_32bit", test_x86_evex_vget_32bit},
    {NULL, NULL},
};
