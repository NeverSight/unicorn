#include "unicorn_test.h"

static const uint64_t code_start = UINT64_C(0x1000);
static const uint64_t code_size = UINT64_C(0x2000);
static const uint64_t data_page = UINT64_C(0x4000);

typedef enum WideKind {
    WIDE_RANGE,
    WIDE_SCALEF,
} WideKind;

typedef struct WideOp {
    const char *name;
    WideKind kind;
    bool scalar;
    bool is_double;
} WideOp;

typedef struct InterruptRecord {
    uint32_t vector;
    uint32_t count;
} InterruptRecord;

static const WideOp operations[] = {
    {"VRANGEPS", WIDE_RANGE, false, false},
    {"VRANGEPD", WIDE_RANGE, false, true},
    {"VRANGESS", WIDE_RANGE, true, false},
    {"VRANGESD", WIDE_RANGE, true, true},
    {"VSCALEFPS", WIDE_SCALEF, false, false},
    {"VSCALEFPD", WIDE_SCALEF, false, true},
    {"VSCALEFSS", WIDE_SCALEF, true, false},
    {"VSCALEFSD", WIDE_SCALEF, true, true},
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

static size_t encode_wide(uint8_t code[8], const WideOp *op,
                          unsigned int vector_bytes, unsigned int dst,
                          unsigned int src1, unsigned int src2_or_base,
                          unsigned int mask, bool zeroing, bool memory,
                          bool evex_b, unsigned int ll, unsigned int immediate,
                          bool disp8, int8_t displacement)
{
    uint8_t p0 = op->kind == WIDE_RANGE ? 0xf3 : 0xf2;
    uint8_t p1 = (op->is_double ? 0x80 : 0) | 0x05;
    uint8_t p2;
    size_t length = 6;

    TEST_CHECK(dst < 32 && src1 < 32 && src2_or_base < 32 && mask < 8);
    TEST_CHECK(vector_bytes == 16 || vector_bytes == 32 || vector_bytes == 64);
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
    p1 |= ((~src1) & 15) << 3;
    p2 = (src1 & 16) ? 0 : 0x08;

    code[0] = 0x62;
    code[1] = p0;
    code[2] = p1;
    code[3] = (uint8_t)(p2 | ((ll & 3) << 5) | mask | (zeroing ? 0x80 : 0) |
                        (evex_b ? 0x10 : 0));
    code[4] = (uint8_t)(op->kind == WIDE_RANGE ? (op->scalar ? 0x51 : 0x50)
                                               : (op->scalar ? 0x2d : 0x2c));
    code[5] = (uint8_t)((memory ? (disp8 ? 0x40 : 0) : 0xc0) |
                        ((dst & 7) << 3) | (src2_or_base & 7));
    if (memory && disp8) {
        code[length++] = (uint8_t)displacement;
    }
    if (op->kind == WIDE_RANGE) {
        code[length++] = (uint8_t)immediate;
    }
    return length;
}

static unsigned int normal_ll(const WideOp *op, size_t vector_bytes)
{
    if (op->scalar) {
        return 0;
    }
    return vector_bytes == 16 ? 0 : vector_bytes == 32 ? 1 : 2;
}

static uint64_t normal_left(const WideOp *op)
{
    return op->is_double ? UINT64_C(0x4008000000000000) : UINT64_C(0x40400000);
}

static uint64_t normal_right(const WideOp *op)
{
    if (op->kind == WIDE_RANGE) {
        return op->is_double ? UINT64_C(0x4010000000000000)
                             : UINT64_C(0x40800000);
    }
    return op->is_double ? UINT64_C(0x3ff8000000000000) : UINT64_C(0x3fc00000);
}

static uint64_t normal_result(const WideOp *op)
{
    if (op->kind == WIDE_RANGE) {
        return normal_right(op);
    }
    return op->is_double ? UINT64_C(0x4018000000000000) : UINT64_C(0x40c00000);
}

static bool run_shape_case(const WideOp *op, size_t vector_bytes, bool memory,
                           bool evex_b, unsigned int ll, uint64_t mask,
                           bool zeroing)
{
    const size_t element_bytes = op->is_double ? 8 : 4;
    const size_t elements = op->scalar ? 1 : vector_bytes / element_bytes;
    const size_t disp8_scale =
        op->scalar || evex_b ? element_bytes : vector_bytes;
    const uint64_t left = normal_left(op);
    const uint64_t right = normal_right(op);
    const uint64_t output = normal_result(op);
    uint8_t initial[64];
    uint8_t source1[64];
    uint8_t source2[64] = {0};
    uint8_t memory_source[64] = {0};
    uint8_t expected[64];
    uint8_t observed[64];
    uint8_t code[8];
    const size_t code_length = encode_wide(code, op, (unsigned int)vector_bytes,
                                           31, 29, memory ? 13 : 30, 7, zeroing,
                                           memory, evex_b, ll, 5, memory, 1);
    uint64_t r13 = data_page;
    uint32_t mxcsr = UINT32_C(0x1f80);
    uc_engine *uc;

    for (size_t byte = 0; byte < sizeof(initial); ++byte) {
        initial[byte] = (uint8_t)(0xa7 - byte * 3);
        source1[byte] = (uint8_t)(0x31 + byte * 7);
    }
    for (size_t element = 0; element < elements; ++element) {
        set_element(source1, element, element_bytes, left);
        set_element(source2, element, element_bytes, right);
        set_element(memory_source, element, element_bytes, right);
    }
    memcpy(expected, initial, sizeof(expected));
    for (size_t element = 0; element < elements; ++element) {
        if ((mask >> element) & 1) {
            set_element(expected, element, element_bytes, output);
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
                       : (evex_b ? "SAE/ER register" : "register"),
                vector_bytes * 8, ll);
    TEST_CHECK_(mxcsr == UINT32_C(0x1f80), "%s changed MXCSR", op->name);
    OK(uc_close(uc));
    return true;
}

static void test_x86_evex_vrange_vscalef_shape_matrix(void)
{
    static const size_t vector_bytes[] = {16, 32, 64};
    const uint64_t mask = UINT64_C(0xa55a);

    for (size_t op_index = 0;
         op_index < sizeof(operations) / sizeof(operations[0]); ++op_index) {
        const WideOp *op = &operations[op_index];

        if (op->scalar) {
            const uint64_t active_mask = mask | 1;

            for (unsigned int ll = 0; ll < 4; ++ll) {
                TEST_CHECK(run_shape_case(op, 16, false, false, ll, active_mask,
                                          (ll & 1) != 0));
                TEST_CHECK(run_shape_case(op, 16, true, false, ll, active_mask,
                                          (ll & 1) == 0));
                TEST_CHECK(run_shape_case(op, 16, false, true, ll, active_mask,
                                          (ll & 1) != 0));
            }
            TEST_CHECK(run_shape_case(op, 16, true, false, 3, 0, false));
            TEST_CHECK(run_shape_case(op, 16, true, false, 3, 0, true));
            continue;
        }

        for (size_t vl = 0; vl < sizeof(vector_bytes) / sizeof(vector_bytes[0]);
             ++vl) {
            const unsigned int ll = normal_ll(op, vector_bytes[vl]);

            TEST_CHECK(run_shape_case(op, vector_bytes[vl], false, false, ll,
                                      mask, (vl & 1) != 0));
            TEST_CHECK(run_shape_case(op, vector_bytes[vl], true, false, ll,
                                      mask, (vl & 1) == 0));
            TEST_CHECK(run_shape_case(op, vector_bytes[vl], true, true, ll,
                                      mask, (vl & 1) != 0));
        }
        for (unsigned int ll = 0; ll < 4; ++ll) {
            TEST_CHECK(
                run_shape_case(op, 64, false, true, ll, mask, (ll & 1) != 0));
        }
    }
}

static bool run_scalar_expected(const WideOp *op, uint64_t src1_value,
                                uint64_t src2_value, unsigned int immediate,
                                bool evex_b, unsigned int ll,
                                uint32_t initial_mxcsr, uint64_t expected_value,
                                uint32_t expected_mxcsr)
{
    const size_t element_bytes = op->is_double ? 8 : 4;
    uint8_t initial[64];
    uint8_t source1[64];
    uint8_t source2[64];
    uint8_t expected[64];
    uint8_t observed[64];
    uint8_t code[8];
    const size_t code_length =
        encode_wide(code, op, 16, 31, 29, 30, 0, false, false, evex_b, ll,
                    immediate, false, 0);
    uint32_t mxcsr = initial_mxcsr;
    uc_engine *uc;

    for (size_t byte = 0; byte < sizeof(initial); ++byte) {
        initial[byte] = (uint8_t)(0xa7 - byte * 3);
        source1[byte] = (uint8_t)(0x31 + byte * 7);
        source2[byte] = (uint8_t)(0x53 + byte * 5);
    }
    set_element(source1, 0, element_bytes, src1_value);
    set_element(source2, 0, element_bytes, src2_value);
    memcpy(expected, initial, sizeof(expected));
    set_element(expected, 0, element_bytes, expected_value);
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
                "%s scalar result mismatch: got 0x%llx expected 0x%llx",
                op->name,
                (unsigned long long)get_element(observed, 0, element_bytes),
                (unsigned long long)expected_value);
    TEST_CHECK_(mxcsr == expected_mxcsr,
                "%s MXCSR mismatch: got 0x%x expected 0x%x", op->name, mxcsr,
                expected_mxcsr);
    OK(uc_close(uc));
    return true;
}

static void test_x86_evex_vrange_special_values(void)
{
    const WideOp *ss = &operations[2];
    const WideOp *sd = &operations[3];

    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0x7f812345), UINT32_C(0x3f800000), 12, false, 0,
        UINT32_C(0x1f80), UINT32_C(0x7fc12345), UINT32_C(0x1f81)));
    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0xffc12345), UINT32_C(0x7fcabcde), 8, false, 1,
        UINT32_C(0x1f80), UINT32_C(0x7fc12345), UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0x7fc12345), UINT32_C(0xc0000000), 5, false, 2,
        UINT32_C(0x1f80), UINT32_C(0xc0000000), UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0xc0400000), UINT32_C(0x7fc12345), 5, false, 3,
        UINT32_C(0x1f80), UINT32_C(0xc0400000), UINT32_C(0x1f80)));

    TEST_CHECK(run_scalar_expected(ss, 0, UINT32_C(0x80000000), 4, false, 0,
                                   UINT32_C(0x1f80), UINT32_C(0x80000000),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x80000000), 0, 5, false, 0,
                                   UINT32_C(0x1f80), 0, UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0x40000000), UINT32_C(0xc0000000), 6, false, 0,
        UINT32_C(0x1f80), UINT32_C(0xc0000000), UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0xc0000000), UINT32_C(0x40000000), 7, false, 0,
        UINT32_C(0x1f80), UINT32_C(0x40000000), UINT32_C(0x1f80)));

    TEST_CHECK(run_scalar_expected(ss, 1, UINT32_C(0x3f800000), 6, false, 0,
                                   UINT32_C(0x1f80), 1, UINT32_C(0x1f82)));
    TEST_CHECK(run_scalar_expected(ss, 1, UINT32_C(0x3f800000), 6, false, 0,
                                   UINT32_C(0x1fc0), 0, UINT32_C(0x1fc0)));
    TEST_CHECK(run_scalar_expected(ss, 1, UINT32_C(0x7fc12345), 5, false, 0,
                                   UINT32_C(0x1f80), 1, UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0x7f812345), UINT32_C(0x3f800000), 12, true, 3,
        UINT32_C(0x1f80), UINT32_C(0x7fc12345), UINT32_C(0x1f80)));

    TEST_CHECK(run_scalar_expected(
        sd, UINT64_C(0x7ff0123456789abc), UINT64_C(0x3ff0000000000000), 12,
        false, 0, UINT32_C(0x1f80), UINT64_C(0x7ff8123456789abc),
        UINT32_C(0x1f81)));
    TEST_CHECK(run_scalar_expected(
        sd, UINT64_C(0x4000000000000000), UINT64_C(0xc000000000000000), 6,
        false, 0, UINT32_C(0x1f80), UINT64_C(0xc000000000000000),
        UINT32_C(0x1f80)));
}

static void test_x86_evex_vscalef_special_values(void)
{
    const WideOp *ss = &operations[6];
    const WideOp *sd = &operations[7];

    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0x7f812345), UINT32_C(0x7f856789), 0, false, 0,
        UINT32_C(0x1f80), UINT32_C(0x7fc12345), UINT32_C(0x1f81)));
    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0x7fc12345), UINT32_C(0x7f856789), 0, false, 0,
        UINT32_C(0x1f80), UINT32_C(0x7fc12345), UINT32_C(0x1f81)));
    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0x3f800000), UINT32_C(0xffc12345), 0, false, 0,
        UINT32_C(0x1f80), UINT32_C(0xffc12345), UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0x7f800000), UINT32_C(0xff800000), 0, false, 0,
        UINT32_C(0x1f80), UINT32_C(0xffc00000), UINT32_C(0x1f81)));
    TEST_CHECK(run_scalar_expected(ss, 0, UINT32_C(0x7f800000), 0, false, 0,
                                   UINT32_C(0x1f80), UINT32_C(0xffc00000),
                                   UINT32_C(0x1f81)));
    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0xc0000000), UINT32_C(0x7f800000), 0, false, 0,
        UINT32_C(0x1f80), UINT32_C(0xff800000), UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0xc0000000), UINT32_C(0xff800000), 0, false, 0,
        UINT32_C(0x1f80), UINT32_C(0x80000000), UINT32_C(0x1f80)));

    TEST_CHECK(run_scalar_expected(ss, 1, UINT32_C(0x7fc12345), 0, false, 0,
                                   UINT32_C(0x1f80), UINT32_C(0x7fc12345),
                                   UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, 1, 0, 0, false, 0, UINT32_C(0x1f80), 1,
                                   UINT32_C(0x1f82)));
    TEST_CHECK(run_scalar_expected(
        ss, UINT32_C(0x40000000), UINT32_C(0x80000001), 0, false, 0,
        UINT32_C(0x1f80), UINT32_C(0x3f800000), UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(ss, 1, UINT32_C(0x80000001), 0, false, 0,
                                   UINT32_C(0x1fc0), 0, UINT32_C(0x1fc0)));

    TEST_CHECK(run_scalar_expected(
        sd, UINT64_C(0x4008000000000000), UINT64_C(0xbff3333333333333), 0,
        false, 0, UINT32_C(0x1f80), UINT64_C(0x3fe8000000000000),
        UINT32_C(0x1f80)));
    TEST_CHECK(run_scalar_expected(
        sd, UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000), 0,
        false, 0, UINT32_C(0x1f80), UINT64_C(0xfff8000000000000),
        UINT32_C(0x1f81)));
}

static bool run_packed_er_rounding(unsigned int rc, uint32_t expected_lane)
{
    const WideOp *op = &operations[4];
    uint32_t source1[16];
    uint32_t source2[16];
    uint32_t expected[16];
    uint8_t observed[64];
    uint8_t code[8];
    const size_t code_length = encode_wide(code, op, 64, 31, 29, 30, 0, false,
                                           false, true, rc, 0, false, 0);
    uint32_t mxcsr = UINT32_C(0x7f80);
    uc_engine *uc;

    for (size_t lane = 0; lane < 16; ++lane) {
        source1[lane] = UINT32_C(0x7f7fffff);
        source2[lane] = UINT32_C(0x3f800000);
        expected[lane] = expected_lane;
    }
    memset(observed, 0xa5, sizeof(observed));
    setup_x86(&uc, UC_MODE_64, code, code_length);
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source2));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                "VSCALEFPS packed ER RC%u mismatch", rc);
    TEST_CHECK(mxcsr == UINT32_C(0x7f80));
    OK(uc_close(uc));
    return true;
}

static void test_x86_evex_vscalef_rounding_and_ftz(void)
{
    const WideOp *ss = &operations[6];
    const WideOp *sd = &operations[7];
    static const uint32_t overflow_expected[4] = {
        UINT32_C(0x7f800000),
        UINT32_C(0x7f7fffff),
        UINT32_C(0x7f800000),
        UINT32_C(0x7f7fffff),
    };

    for (unsigned int rc = 0; rc < 4; ++rc) {
        const uint32_t mxcsr = UINT32_C(0x1f80) | (rc << 13);

        TEST_CHECK(run_scalar_expected(
            ss, UINT32_C(0x7f7fffff), UINT32_C(0x3f800000), 0, false, 0, mxcsr,
            overflow_expected[rc], mxcsr | UINT32_C(0x28)));
        TEST_CHECK(run_scalar_expected(
            ss, UINT32_C(0x7f7fffff), UINT32_C(0x3f800000), 0, true, rc,
            UINT32_C(0x7f80), overflow_expected[rc], UINT32_C(0x7f80)));
        TEST_CHECK(run_packed_er_rounding(rc, overflow_expected[rc]));
    }

    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x00800000),
                                   UINT32_C(0xc1c00000), 0, false, 0,
                                   UINT32_C(0x1f80), 0, UINT32_C(0x1fb0)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x00800000),
                                   UINT32_C(0xc1c00000), 0, false, 0,
                                   UINT32_C(0x5f80), 1, UINT32_C(0x5fb0)));
    TEST_CHECK(run_scalar_expected(ss, UINT32_C(0x00800000),
                                   UINT32_C(0xbf800000), 0, false, 0,
                                   UINT32_C(0x9f80), 0, UINT32_C(0x9fb0)));

    TEST_CHECK(run_scalar_expected(
        sd, UINT64_C(0x7fefffffffffffff), UINT64_C(0x3ff0000000000000), 0,
        false, 0, UINT32_C(0x1f80), UINT64_C(0x7ff0000000000000),
        UINT32_C(0x1fa8)));
}

static void run_unmasked_exception(const WideOp *op, uint64_t src1_value,
                                   uint64_t src2_value, unsigned int immediate,
                                   uint32_t initial_mxcsr,
                                   uint32_t expected_mxcsr)
{
    const size_t element_bytes = op->is_double ? 8 : 4;
    uint8_t initial[64];
    uint8_t source1[64] = {0};
    uint8_t source2[64] = {0};
    uint8_t observed[64];
    uint8_t code[8];
    const size_t code_length =
        encode_wide(code, op, 16, 31, 29, 30, 0, false, false, false, 0,
                    immediate, false, 0);
    uint64_t cr4;
    uint64_t rip = 0;
    uint32_t mxcsr = initial_mxcsr;
    InterruptRecord record = {0};
    uc_engine *uc;
    uc_hook hook;

    memset(initial, 0xa5, sizeof(initial));
    set_element(source1, 0, element_bytes, src1_value);
    set_element(source2, 0, element_bytes, src2_value);
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
    TEST_CHECK(mxcsr == expected_mxcsr);
    TEST_CHECK(rip == code_start);
    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

static void test_x86_evex_vrange_vscalef_exceptions(void)
{
    run_unmasked_exception(&operations[2], UINT32_C(0x7f812345),
                           UINT32_C(0x3f800000), 12, UINT32_C(0x1f00),
                           UINT32_C(0x1f01));
    run_unmasked_exception(&operations[6], UINT32_C(0x7f7fffff),
                           UINT32_C(0x3f800000), 0, UINT32_C(0x1b80),
                           UINT32_C(0x1ba8));

    /* EVEX.b on a memory source is broadcast, not SAE. */
    for (size_t op_index = 0; op_index < 2; ++op_index) {
        const WideOp *op = op_index == 0 ? &operations[0] : &operations[4];
        const uint32_t source_value = op->kind == WIDE_RANGE
                                          ? UINT32_C(0x7f812345)
                                          : UINT32_C(0x3f800000);
        const uint32_t memory_value = op->kind == WIDE_RANGE
                                          ? UINT32_C(0x3f800000)
                                          : UINT32_C(0x7f812345);
        const uint32_t quiet = UINT32_C(0x7fc12345);
        uint8_t initial[64];
        uint8_t source1[64] = {0};
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[8];
        const size_t code_length = encode_wide(
            code, op, 64, 31, 29, 0, 7, false, true, true, 2, 12, false, 0);
        uint64_t rax = data_page;
        uint64_t mask = 1;
        uint32_t mxcsr = UINT32_C(0x1f80);
        uc_engine *uc;

        memset(initial, 0xa5, sizeof(initial));
        set_element(source1, 0, 4, source_value);
        memcpy(expected, initial, sizeof(expected));
        set_element(expected, 0, 4, quiet);
        setup_x86(&uc, UC_MODE_64, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, data_page, &memory_value, sizeof(memory_value)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK(memcmp(observed, expected, sizeof(expected)) == 0);
        TEST_CHECK(mxcsr == UINT32_C(0x1f81));
        OK(uc_close(uc));
    }

    /* Masked-off lanes neither evaluate exceptional operands nor contribute
     * sticky flags. */
    for (size_t op_index = 0; op_index < 2; ++op_index) {
        const WideOp *op = op_index == 0 ? &operations[2] : &operations[6];
        const bool zeroing = op_index != 0;
        const uint32_t source_value = op->kind == WIDE_RANGE
                                          ? UINT32_C(0x7f812345)
                                          : UINT32_C(0x7f7fffff);
        const uint32_t second_value = UINT32_C(0x3f800000);
        uint8_t initial[64];
        uint8_t source1[64];
        uint8_t source2[64] = {0};
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[8];
        const size_t code_length =
            encode_wide(code, op, 16, 31, 29, 30, 7, zeroing, false, false, 0,
                        12, false, 0);
        uint64_t mask = 0;
        uint32_t mxcsr = UINT32_C(0x1f80);
        uc_engine *uc;

        for (size_t byte = 0; byte < 64; ++byte) {
            initial[byte] = (uint8_t)(0xa7 - byte * 3);
            source1[byte] = (uint8_t)(0x31 + byte * 7);
        }
        set_element(source1, 0, 4, source_value);
        set_element(source2, 0, 4, second_value);
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
}

static void test_x86_evex_vrange_vscalef_fault_suppression(void)
{
    const uint64_t boundary = data_page + UINT64_C(0xffc);

    for (size_t op_index = 0; op_index < 2; ++op_index) {
        const WideOp *op = op_index == 0 ? &operations[0] : &operations[4];
        const uint32_t memory_value = op->kind == WIDE_RANGE
                                          ? UINT32_C(0x40000000)
                                          : UINT32_C(0x3f800000);
        uint8_t initial[64];
        uint8_t source1[64] = {0};
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[8];
        const size_t code_length = encode_wide(
            code, op, 64, 31, 29, 0, 7, false, true, false, 2, 5, false, 0);
        uint64_t rax = boundary;
        uint64_t mask = 1;
        uint32_t mxcsr = UINT32_C(0x1f80);
        uc_engine *uc;

        memset(initial, 0xa5, sizeof(initial));
        set_element(source1, 0, 4, UINT32_C(0x40400000));
        memcpy(expected, initial, sizeof(expected));
        set_element(expected, 0, 4,
                    op->kind == WIDE_RANGE ? UINT32_C(0x40400000)
                                           : UINT32_C(0x40c00000));
        setup_x86(&uc, UC_MODE_64, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, boundary, &memory_value, sizeof(memory_value)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                    "%s did not suppress a masked memory fault", op->name);
        OK(uc_close(uc));
    }

    /* A later memory fault has priority over lane zero's potential SIMD
     * exception and leaves both destination and MXCSR untouched. */
    for (size_t op_index = 0; op_index < 2; ++op_index) {
        const WideOp *op = op_index == 0 ? &operations[0] : &operations[4];
        const uint32_t source_value = op->kind == WIDE_RANGE
                                          ? UINT32_C(0x7f812345)
                                          : UINT32_C(0x7f7fffff);
        const uint32_t memory_value = UINT32_C(0x3f800000);
        uint8_t initial[64];
        uint8_t source1[64] = {0};
        uint8_t observed[64];
        uint8_t code[8];
        const size_t code_length = encode_wide(
            code, op, 64, 31, 29, 0, 7, false, true, false, 2, 12, false, 0);
        uint64_t rax = boundary;
        uint64_t mask = 3;
        uint64_t rip = 0;
        uint32_t mxcsr = UINT32_C(0x1f80);
        uc_engine *uc;
        uc_err err;

        memset(initial, 0x5a, sizeof(initial));
        set_element(source1, 0, 4, source_value);
        setup_x86(&uc, UC_MODE_64, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, boundary, &memory_value, sizeof(memory_value)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        err = uc_emu_start(uc, code_start, code_start + code_length, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK_(err == UC_ERR_READ_UNMAPPED, "%s fault mismatch", op->name);
        TEST_CHECK_(memcmp(observed, initial, sizeof(initial)) == 0,
                    "%s partially committed destination", op->name);
        TEST_CHECK_(mxcsr == UINT32_C(0x1f80), "%s partially committed MXCSR",
                    op->name);
        TEST_CHECK_(rip == code_start, "%s advanced RIP", op->name);
        OK(uc_close(uc));
    }

    /* An all-zero mask suppresses the sole broadcast load. */
    for (size_t op_index = 0; op_index < 2; ++op_index) {
        const WideOp *op = op_index == 0 ? &operations[1] : &operations[5];
        uint8_t initial[64];
        uint8_t observed[64];
        uint8_t code[8];
        const size_t code_length = encode_wide(code, op, 32, 31, 29, 0, 7, true,
                                               true, true, 1, 5, false, 0);
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

    /* A masked-off scalar Tuple1 source is not accessed, while the
     * instruction still performs its architectural upper-lane copy. */
    for (size_t op_index = 0; op_index < 2; ++op_index) {
        const WideOp *op = op_index == 0 ? &operations[2] : &operations[6];
        uint8_t initial[64];
        uint8_t source1[64];
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[8];
        const size_t code_length = encode_wide(
            code, op, 16, 31, 29, 0, 7, false, true, false, 3, 5, false, 0);
        uint64_t rax = UINT64_C(0x8000);
        uint64_t mask = 0;
        uc_engine *uc;

        for (size_t byte = 0; byte < 64; ++byte) {
            initial[byte] = (uint8_t)(0xa7 - byte * 3);
            source1[byte] = (uint8_t)(0x31 + byte * 7);
        }
        memcpy(expected, initial, sizeof(expected));
        memcpy(expected + 4, source1 + 4, 12);
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

static void test_x86_evex_vrange_rip_relative_immediate(void)
{
    const uint64_t memory_address = code_start + UINT64_C(0x100);
    const uint32_t left[4] = {
        UINT32_C(0x40400000),
        UINT32_C(0x40400000),
        UINT32_C(0x40400000),
        UINT32_C(0x40400000),
    };
    const uint32_t right[4] = {
        UINT32_C(0x40800000),
        UINT32_C(0x40800000),
        UINT32_C(0x40800000),
        UINT32_C(0x40800000),
    };
    const uint32_t expected[4] = {
        UINT32_C(0x40800000),
        UINT32_C(0x40800000),
        UINT32_C(0x40800000),
        UINT32_C(0x40800000),
    };
    uint8_t code[11] = {0x62, 0xf3, 0x6d, 0x08, 0x50, 0x0d};
    const int32_t displacement =
        (int32_t)(memory_address - (code_start + sizeof(code)));
    uint8_t observed[64];
    uc_engine *uc;

    memcpy(code + 6, &displacement, sizeof(displacement));
    code[sizeof(code) - 1] = 5;
    memset(observed, 0xa5, sizeof(observed));
    setup_x86(&uc, UC_MODE_64, code, sizeof(code));
    OK(uc_mem_write(uc, memory_address, right, sizeof(right)));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM1, observed));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, left));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM1, observed));
    TEST_CHECK(memcmp(observed, expected, sizeof(expected)) == 0);
    TEST_CHECK(memcmp(observed + sizeof(expected), (uint8_t[48]){0}, 48) == 0);
    OK(uc_close(uc));
}

static void test_x86_evex_vrange_vscalef_aliasing(void)
{
    for (size_t op_index = 0; op_index < 2; ++op_index) {
        const WideOp *op = op_index == 0 ? &operations[0] : &operations[4];
        const unsigned int src1_reg = op->kind == WIDE_RANGE ? 29 : 31;
        const unsigned int src2_reg = op->kind == WIDE_RANGE ? 31 : 30;
        uint8_t source1[64] = {0};
        uint8_t source2[64] = {0};
        uint32_t expected_low[4];
        uint8_t expected[64] = {0};
        uint8_t observed[64];
        uint8_t code[8];
        const size_t code_length =
            encode_wide(code, op, 16, 31, src1_reg, src2_reg, 0, false, false,
                        false, 0, 5, false, 0);
        uc_engine *uc;

        for (size_t lane = 0; lane < 4; ++lane) {
            set_element(source1, lane, 4, UINT32_C(0x40400000));
            set_element(source2, lane, 4,
                        op->kind == WIDE_RANGE ? UINT32_C(0x40800000)
                                               : UINT32_C(0x3f800000));
            expected_low[lane] = op->kind == WIDE_RANGE ? UINT32_C(0x40800000)
                                                        : UINT32_C(0x40c00000);
        }
        memcpy(expected, expected_low, sizeof(expected_low));
        memset(observed, 0xa5, sizeof(observed));
        setup_x86(&uc, UC_MODE_64, code, code_length);
        if (op->kind == WIDE_RANGE) {
            OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM31, source2));
        } else {
            OK(uc_reg_write(uc, UC_X86_REG_ZMM31, source1));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source2));
        }
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                    "%s destination alias mismatch", op->name);
        OK(uc_close(uc));
    }
}

static void test_x86_evex_vrange_vscalef_invalid(void)
{
    static const struct {
        uint8_t code[8];
        size_t size;
        const char *name;
    } cases[] = {
        {{0x62, 0xf3, 0x6d, 0x08, 0x50, 0xcb, 0x15},
         7,
         "VRANGE imm8 reserved high nibble"},
        {{0x62, 0xf3, 0x6d, 0x68, 0x50, 0xcb, 0x05},
         7,
         "VRANGE packed register LL3"},
        {{0x62, 0xf3, 0x6d, 0x78, 0x50, 0x08, 0x05},
         7,
         "VRANGE broadcast memory LL3"},
        {{0x62, 0xf3, 0x6d, 0x18, 0x51, 0x08, 0x05},
         7,
         "VRANGE scalar memory EVEX.b"},
        {{0x62, 0xf3, 0x6d, 0x88, 0x50, 0xcb, 0x05}, 7, "VRANGE zeroing K0"},
        {{0x62, 0xf2, 0x6d, 0x68, 0x2c, 0xcb},
         6,
         "VSCALEF packed register LL3"},
        {{0x62, 0xf2, 0x6d, 0x78, 0x2c, 0x08},
         6,
         "VSCALEF broadcast memory LL3"},
        {{0x62, 0xf2, 0x6d, 0x18, 0x2d, 0x08},
         6,
         "VSCALEF scalar memory EVEX.b"},
        {{0x62, 0xf2, 0x6d, 0x88, 0x2c, 0xcb}, 6, "VSCALEF zeroing K0"},
        {{0xf0, 0x62, 0xf2, 0x6d, 0x08, 0x2c, 0xcb}, 7, "VSCALEF LOCK prefix"},
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

static void test_x86_evex_vrange_vscalef_32bit(void)
{
    static const uint8_t range_code[] = {
        0x62, 0xf3, 0x6d, 0x08, 0x50, 0xcb, 0x05,
    };
    static const uint8_t scalef_code[] = {
        0x62, 0xf2, 0x6d, 0x08, 0x2c, 0xcb,
    };
    static const uint32_t left[4] = {
        UINT32_C(0x40400000),
        UINT32_C(0x40400000),
        UINT32_C(0x40400000),
        UINT32_C(0x40400000),
    };
    static const uint32_t right[4] = {
        UINT32_C(0x40800000),
        UINT32_C(0x40800000),
        UINT32_C(0x40800000),
        UINT32_C(0x40800000),
    };
    static const uint32_t range_expected[4] = {
        UINT32_C(0x40800000),
        UINT32_C(0x40800000),
        UINT32_C(0x40800000),
        UINT32_C(0x40800000),
    };
    static const uint32_t scale[4] = {
        UINT32_C(0x3f800000),
        UINT32_C(0x3f800000),
        UINT32_C(0x3f800000),
        UINT32_C(0x3f800000),
    };
    static const uint32_t scalef_expected[4] = {
        UINT32_C(0x40c00000),
        UINT32_C(0x40c00000),
        UINT32_C(0x40c00000),
        UINT32_C(0x40c00000),
    };

    for (size_t which = 0; which < 2; ++which) {
        const uint8_t *code = which ? scalef_code : range_code;
        const size_t length = which ? sizeof(scalef_code) : sizeof(range_code);
        uint8_t observed[16];
        uc_engine *uc;

        memset(observed, 0xa5, sizeof(observed));
        setup_x86(&uc, UC_MODE_32, code, length);
        OK(uc_reg_write(uc, UC_X86_REG_XMM1, observed));
        OK(uc_reg_write(uc, UC_X86_REG_XMM2, left));
        OK(uc_reg_write(uc, UC_X86_REG_XMM3, which ? scale : right));
        OK(uc_emu_start(uc, code_start, code_start + length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_XMM1, observed));
        TEST_CHECK(memcmp(observed, which ? scalef_expected : range_expected,
                          sizeof(observed)) == 0);
        OK(uc_close(uc));
    }
}

TEST_LIST = {
    {"test_x86_evex_vrange_vscalef_shape_matrix",
     test_x86_evex_vrange_vscalef_shape_matrix},
    {"test_x86_evex_vrange_special_values",
     test_x86_evex_vrange_special_values},
    {"test_x86_evex_vscalef_special_values",
     test_x86_evex_vscalef_special_values},
    {"test_x86_evex_vscalef_rounding_and_ftz",
     test_x86_evex_vscalef_rounding_and_ftz},
    {"test_x86_evex_vrange_vscalef_exceptions",
     test_x86_evex_vrange_vscalef_exceptions},
    {"test_x86_evex_vrange_vscalef_fault_suppression",
     test_x86_evex_vrange_vscalef_fault_suppression},
    {"test_x86_evex_vrange_rip_relative_immediate",
     test_x86_evex_vrange_rip_relative_immediate},
    {"test_x86_evex_vrange_vscalef_aliasing",
     test_x86_evex_vrange_vscalef_aliasing},
    {"test_x86_evex_vrange_vscalef_invalid",
     test_x86_evex_vrange_vscalef_invalid},
    {"test_x86_evex_vrange_vscalef_32bit", test_x86_evex_vrange_vscalef_32bit},
    {NULL, NULL},
};
