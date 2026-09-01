#include "unicorn_test.h"

static const uint64_t code_start = UINT64_C(0x1000);
static const uint64_t code_size = UINT64_C(0x2000);
static const uint64_t data_page = UINT64_C(0x4000);

typedef enum Approx28MemoryKind {
    APPROX28_MEMORY_RCP,
    APPROX28_MEMORY_RSQRT,
    APPROX28_MEMORY_EXP2,
} Approx28MemoryKind;

typedef struct Approx28MemoryOp {
    const char *name;
    Approx28MemoryKind kind;
    bool scalar;
    bool is_double;
} Approx28MemoryOp;

typedef struct InterruptRecord {
    uint32_t vector;
    uint32_t count;
} InterruptRecord;

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

static size_t encode_approx28_memory(uint8_t code[7],
                                     const Approx28MemoryOp *op,
                                     unsigned int dst, unsigned int src1,
                                     unsigned int mask, bool zeroing,
                                     bool broadcast, unsigned int ll,
                                     bool disp8, int8_t displacement)
{
    uint8_t p0 = 0xf2;
    uint8_t p1 = (op->is_double ? 0x80 : 0) | 0x05;
    uint8_t p2;
    uint8_t opcode;

    TEST_CHECK(dst < 32 && src1 < 32 && mask < 8 && ll < 4);
    if (dst & 8) {
        p0 &= (uint8_t)~0x80;
    }
    if (dst & 16) {
        p0 &= (uint8_t)~0x10;
    }
    if (op->scalar) {
        p1 |= ((~src1) & 15) << 3;
        p2 = (src1 & 16) ? 0 : 0x08;
        opcode = op->kind == APPROX28_MEMORY_RCP ? 0xcb : 0xcd;
    } else {
        p1 |= 0x78;
        p2 = 0x08;
        opcode = op->kind == APPROX28_MEMORY_RCP     ? 0xca
                 : op->kind == APPROX28_MEMORY_RSQRT ? 0xcc
                                                     : 0xc8;
    }

    code[0] = 0x62;
    code[1] = p0;
    code[2] = p1;
    code[3] = (uint8_t)(p2 | (ll << 5) | mask | (zeroing ? 0x80 : 0) |
                        (broadcast ? 0x10 : 0));
    code[4] = opcode;
    code[5] = (uint8_t)((disp8 ? 0x40 : 0) | ((dst & 7) << 3));
    if (disp8) {
        code[6] = (uint8_t)displacement;
        return 7;
    }
    return 6;
}

static void test_x86_evex_approx28_memory_basic(void)
{
    static const Approx28MemoryOp op = {
        "VRCP28PS",
        APPROX28_MEMORY_RCP,
        false,
        false,
    };
    static const uint32_t source[16] = {
        0x40400000, 0x40000000, 0x3f800000, 0x3fc00000, 0x40800000, 0x3e800000,
        0x41000000, 0x3f000000, 0xc0400000, 0xc0000000, 0xbf800000, 0xbfc00000,
        0xc0800000, 0xbe800000, 0xc1000000, 0xbf000000,
    };
    static const uint32_t expected[16] = {
        0x3eaaaaab, 0x3f000000, 0x3f800000, 0x3f2aaaab, 0x3e800000, 0x40800000,
        0x3e000000, 0x40000000, 0xbeaaaaab, 0xbf000000, 0xbf800000, 0xbf2aaaab,
        0xbe800000, 0xc0800000, 0xbe000000, 0xc0000000,
    };
    uint8_t initial[64];
    uint8_t observed[64];
    uint8_t code[7];
    const size_t code_length =
        encode_approx28_memory(code, &op, 31, 0, 0, false, false, 2, false, 0);
    uint64_t rax = data_page;
    uint32_t mxcsr = UINT32_C(0x1fa0);
    uc_engine *uc;

    memset(initial, 0xa5, sizeof(initial));
    setup_x86(&uc, code, code_length);
    OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, data_page, source, sizeof(source)));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    TEST_CHECK(memcmp(observed, expected, sizeof(expected)) == 0);
    TEST_CHECK(mxcsr == UINT32_C(0x1fa0));
    OK(uc_close(uc));
}

static uint64_t normal_input(const Approx28MemoryOp *op)
{
    return op->is_double ? UINT64_C(0x4008000000000000) : UINT64_C(0x40400000);
}

static uint64_t normal_result(const Approx28MemoryOp *op)
{
    if (op->is_double) {
        return op->kind == APPROX28_MEMORY_RCP ? UINT64_C(0x3fd5555555100000)
               : op->kind == APPROX28_MEMORY_RSQRT
                   ? UINT64_C(0x3fe279a745800000)
                   : UINT64_C(0x4020000000000000);
    }
    return op->kind == APPROX28_MEMORY_RCP     ? UINT64_C(0x3eaaaaab)
           : op->kind == APPROX28_MEMORY_RSQRT ? UINT64_C(0x3f13cd3a)
                                               : UINT64_C(0x41000000);
}

static void test_x86_evex_approx28_memory_broadcast(void)
{
    static const Approx28MemoryOp operations[] = {
        {"VRCP28PS", APPROX28_MEMORY_RCP, false, false},
        {"VRCP28PD", APPROX28_MEMORY_RCP, false, true},
        {"VRSQRT28PS", APPROX28_MEMORY_RSQRT, false, false},
        {"VRSQRT28PD", APPROX28_MEMORY_RSQRT, false, true},
        {"VEXP2PS", APPROX28_MEMORY_EXP2, false, false},
        {"VEXP2PD", APPROX28_MEMORY_EXP2, false, true},
    };
    const uint64_t mask = UINT64_C(0xa55a);

    for (size_t op_index = 0;
         op_index < sizeof(operations) / sizeof(operations[0]); ++op_index) {
        const Approx28MemoryOp *op = &operations[op_index];
        const size_t element_bytes = op->is_double ? 8 : 4;
        const size_t elements = 64 / element_bytes;
        const uint64_t input = normal_input(op);
        const uint64_t result = normal_result(op);
        const bool zeroing = (op_index & 1) != 0;
        uint8_t initial[64];
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[7];
        const size_t code_length = encode_approx28_memory(
            code, op, 31, 0, 7, zeroing, true, 2, true, 1);
        uint64_t rax = data_page;
        uint32_t mxcsr = UINT32_C(0x1fa0);
        uc_engine *uc;

        for (size_t byte = 0; byte < 64; ++byte) {
            initial[byte] = (uint8_t)(0xa7 - byte * 3);
        }
        memcpy(expected, initial, sizeof(expected));
        for (size_t element = 0; element < elements; ++element) {
            if ((mask >> element) & 1) {
                memcpy(expected + element * element_bytes, &result,
                       element_bytes);
            } else if (zeroing) {
                memset(expected + element * element_bytes, 0, element_bytes);
            }
        }
        setup_x86(&uc, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, data_page + element_bytes, &input, element_bytes));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                    "%s broadcast result mismatch", op->name);
        TEST_CHECK_(mxcsr == UINT32_C(0x1fa0), "%s changed MXCSR", op->name);
        OK(uc_close(uc));
    }
}

static bool run_normal_memory(const Approx28MemoryOp *op, unsigned int mask_reg,
                              uint64_t mask, bool zeroing)
{
    const size_t element_bytes = op->is_double ? 8 : 4;
    const size_t elements = op->scalar ? 1 : 64 / element_bytes;
    const size_t disp8_scale = op->scalar ? element_bytes : 64;
    const uint64_t effective_mask = mask_reg ? mask : UINT64_MAX;
    const uint64_t input = normal_input(op);
    const uint64_t result = normal_result(op);
    uint8_t memory[64] = {0};
    uint8_t initial[64];
    uint8_t source1[64];
    uint8_t expected[64];
    uint8_t observed[64];
    uint8_t code[7];
    const size_t code_length = encode_approx28_memory(
        code, op, 31, 29, mask_reg, zeroing, false,
        op->scalar ? ((unsigned int)(op->kind + op->is_double) & 3) : 2, true,
        1);
    uint64_t rax = data_page;
    uint32_t mxcsr = UINT32_C(0x1fa0);
    uc_engine *uc;

    for (size_t byte = 0; byte < 64; ++byte) {
        initial[byte] = (uint8_t)(0xa7 - byte * 3);
        source1[byte] = (uint8_t)(0x31 + byte * 7);
    }
    for (size_t element = 0; element < (op->scalar ? 1 : elements); ++element) {
        memcpy(memory + element * element_bytes, &input, element_bytes);
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
    }

    setup_x86(&uc, code, code_length);
    OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, data_page + disp8_scale, memory,
                    op->scalar ? element_bytes : sizeof(memory)));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source1));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    if (mask_reg) {
        OK(uc_reg_write(uc, UC_X86_REG_K0 + mask_reg, &mask));
    }
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    TEST_CHECK_(memcmp(observed, expected, sizeof(expected)) == 0,
                "%s normal memory result mismatch", op->name);
    TEST_CHECK_(mxcsr == UINT32_C(0x1fa0), "%s changed MXCSR", op->name);
    OK(uc_close(uc));
    return true;
}

static void test_x86_evex_approx28_memory_matrix(void)
{
    static const Approx28MemoryOp operations[] = {
        {"VRCP28PS", APPROX28_MEMORY_RCP, false, false},
        {"VRCP28PD", APPROX28_MEMORY_RCP, false, true},
        {"VRSQRT28PS", APPROX28_MEMORY_RSQRT, false, false},
        {"VRSQRT28PD", APPROX28_MEMORY_RSQRT, false, true},
        {"VEXP2PS", APPROX28_MEMORY_EXP2, false, false},
        {"VEXP2PD", APPROX28_MEMORY_EXP2, false, true},
        {"VRCP28SS", APPROX28_MEMORY_RCP, true, false},
        {"VRCP28SD", APPROX28_MEMORY_RCP, true, true},
        {"VRSQRT28SS", APPROX28_MEMORY_RSQRT, true, false},
        {"VRSQRT28SD", APPROX28_MEMORY_RSQRT, true, true},
    };

    for (size_t op = 0; op < sizeof(operations) / sizeof(operations[0]); ++op) {
        TEST_CHECK(run_normal_memory(&operations[op], 0, 0, false));
        TEST_CHECK(
            run_normal_memory(&operations[op], 7, UINT64_C(0xa55a), false));
        TEST_CHECK(
            run_normal_memory(&operations[op], 7, UINT64_C(0xa55a), true));
    }
}

static void test_x86_evex_approx28_memory_fault_suppression(void)
{
    static const Approx28MemoryOp rcp = {
        "VRCP28PS",
        APPROX28_MEMORY_RCP,
        false,
        false,
    };
    static const Approx28MemoryOp exp2 = {
        "VEXP2PS",
        APPROX28_MEMORY_EXP2,
        false,
        false,
    };
    static const Approx28MemoryOp rcp_ss = {
        "VRCP28SS",
        APPROX28_MEMORY_RCP,
        true,
        false,
    };
    const uint64_t boundary = data_page + UINT64_C(0xffc);

    /* Only lane zero is active, so the unmapped second lane is never read. */
    {
        const uint32_t zero = 0;
        const uint32_t infinity = UINT32_C(0x7f800000);
        uint8_t initial[64];
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[7];
        const size_t code_length = encode_approx28_memory(
            code, &rcp, 31, 0, 7, false, false, 2, false, 0);
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
        TEST_CHECK(mxcsr == UINT32_C(0x1f84));
        OK(uc_close(uc));
    }

    /* Memory faults have priority over an earlier lane's unmasked SIMD
     * exception, and neither destination nor MXCSR may partially commit. */
    {
        const uint32_t zero = 0;
        uint8_t initial[64];
        uint8_t observed[64];
        uint8_t code[7];
        const size_t code_length = encode_approx28_memory(
            code, &rcp, 31, 0, 7, false, false, 2, false, 0);
        uint64_t rax = boundary;
        uint64_t mask = 3;
        uint64_t cr4;
        uint64_t rip = 0;
        uint32_t mxcsr = UINT32_C(0x1d80);
        InterruptRecord record = {0};
        uc_engine *uc;
        uc_hook hook;
        uc_err err;

        memset(initial, 0x5a, sizeof(initial));
        setup_x86(&uc, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, boundary, &zero, sizeof(zero)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
        cr4 |= UINT64_C(1) << 10;
        OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));
        OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, record_interrupt, &record, 1,
                       0));
        err = uc_emu_start(uc, code_start, code_start + code_length, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK(err == UC_ERR_READ_UNMAPPED);
        TEST_CHECK(record.count == 0);
        TEST_CHECK(memcmp(observed, initial, sizeof(initial)) == 0);
        TEST_CHECK(mxcsr == UINT32_C(0x1d80));
        TEST_CHECK(rip == code_start);
        OK(uc_hook_del(uc, hook));
        OK(uc_close(uc));
    }

    /* An all-zero writemask suppresses even the scalar broadcast load. */
    {
        uint8_t initial[64];
        uint8_t observed[64];
        uint8_t code[7];
        const size_t code_length = encode_approx28_memory(
            code, &exp2, 31, 0, 7, true, true, 2, false, 0);
        uint64_t rax = UINT64_C(0x8000);
        uint64_t mask = 0;
        uint32_t mxcsr = UINT32_C(0x1fa0);
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
        TEST_CHECK(mxcsr == UINT32_C(0x1fa0));
        OK(uc_close(uc));
    }

    /* A masked-off scalar input also suppresses its Tuple1 memory access,
     * while retaining the scalar instruction's upper-lane copy behavior. */
    {
        uint8_t initial[64];
        uint8_t source1[64];
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[7];
        const size_t code_length = encode_approx28_memory(
            code, &rcp_ss, 31, 29, 7, false, false, 3, false, 0);
        uint64_t rax = UINT64_C(0x8000);
        uint64_t mask = 0;
        uc_engine *uc;

        for (size_t byte = 0; byte < 64; ++byte) {
            initial[byte] = (uint8_t)(0xa7 - byte * 3);
            source1[byte] = (uint8_t)(0x31 + byte * 7);
        }
        memcpy(expected, initial, sizeof(expected));
        memcpy(expected + sizeof(uint32_t), source1 + sizeof(uint32_t),
               16 - sizeof(uint32_t));
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

    /* Broadcast reads the one scalar at the page edge, not a 512-bit source. */
    {
        const uint32_t three = UINT32_C(0x40400000);
        const uint32_t eight = UINT32_C(0x41000000);
        uint8_t initial[64];
        uint8_t expected[64];
        uint8_t observed[64];
        uint8_t code[7];
        const size_t code_length = encode_approx28_memory(
            code, &exp2, 31, 0, 7, false, true, 2, false, 0);
        uint64_t rax = boundary;
        uint64_t mask = UINT64_C(1) << 15;
        uc_engine *uc;

        memset(initial, 0xa5, sizeof(initial));
        memcpy(expected, initial, sizeof(expected));
        memcpy(expected + 15 * sizeof(uint32_t), &eight, sizeof(eight));
        setup_x86(&uc, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, boundary, &three, sizeof(three)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        TEST_CHECK(memcmp(observed, expected, sizeof(expected)) == 0);
        OK(uc_close(uc));
    }
}

static void test_x86_evex_approx28_memory_exceptions(void)
{
    static const Approx28MemoryOp exp2 = {
        "VEXP2PS",
        APPROX28_MEMORY_EXP2,
        false,
        false,
    };
    const uint32_t snan = UINT32_C(0x7f812345);
    const uint32_t quiet = UINT32_C(0x7fc12345);
    uint8_t code[7];
    const size_t code_length =
        encode_approx28_memory(code, &exp2, 31, 0, 7, false, true, 2, false, 0);

    /* With a memory source EVEX.b means broadcast, not SAE. */
    {
        uint8_t initial[64];
        uint8_t observed[64];
        uint64_t rax = data_page;
        uint64_t mask = 1;
        uint64_t cr4;
        uint64_t rip = 0;
        uint32_t mxcsr = UINT32_C(0x1f00); /* invalid unmasked */
        InterruptRecord record = {0};
        uc_engine *uc;
        uc_hook hook;

        memset(initial, 0xa5, sizeof(initial));
        setup_x86(&uc, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, data_page, &snan, sizeof(snan)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
        cr4 |= UINT64_C(1) << 10;
        OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));
        OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, record_interrupt, &record, 1,
                       0));
        OK(uc_emu_start(uc, code_start, code_start + code_length, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK(record.count == 1 && record.vector == 19);
        TEST_CHECK(memcmp(observed, initial, sizeof(initial)) == 0);
        TEST_CHECK(mxcsr == UINT32_C(0x1f01));
        TEST_CHECK(rip == code_start);
        OK(uc_hook_del(uc, hook));
        OK(uc_close(uc));
    }

    /* Masked exceptions commit the quieted result and sticky status. */
    {
        uint8_t initial[64];
        uint8_t expected[64];
        uint8_t observed[64];
        uint64_t rax = data_page;
        uint64_t mask = 1;
        uint32_t mxcsr = UINT32_C(0x1f80);
        uc_engine *uc;

        memset(initial, 0x5a, sizeof(initial));
        memcpy(expected, initial, sizeof(expected));
        memcpy(expected, &quiet, sizeof(quiet));
        setup_x86(&uc, code, code_length);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, data_page, &snan, sizeof(snan)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
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
}

static void test_x86_evex_approx28_memory_invalid(void)
{
    static const struct {
        uint8_t code[7];
        size_t size;
        const char *name;
    } cases[] = {
        {{0x62, 0xf2, 0x15, 0x18, 0xcb, 0x08}, 6, "scalar memory EVEX.b"},
        {{0x62, 0xf2, 0x7d, 0x08, 0xca, 0x08}, 6, "packed memory VL128"},
        {{0x62, 0xf2, 0x7d, 0x28, 0xca, 0x08}, 6, "packed memory VL256"},
        {{0x62, 0xf2, 0x7d, 0x68, 0xca, 0x08}, 6, "packed memory LL3"},
        {{0x62, 0xf2, 0x75, 0x48, 0xca, 0x08}, 6, "packed memory vvvv"},
        {{0x62, 0xf2, 0x7d, 0x40, 0xca, 0x08}, 6, "packed memory V-prime"},
        {{0x62, 0xf2, 0x7d, 0xc8, 0xca, 0x08}, 6, "memory zeroing K0"},
        {{0xf0, 0x62, 0xf2, 0x7d, 0x48, 0xca, 0x08}, 7, "memory LOCK prefix"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t initial[64];
        uint8_t observed[64];
        uint64_t rax = UINT64_C(0x8000);
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
        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    cases[i].name);
        TEST_CHECK_(memcmp(observed, initial, sizeof(initial)) == 0,
                    "%s changed destination", cases[i].name);
        TEST_CHECK_(rip == code_start, "%s advanced RIP", cases[i].name);
        OK(uc_close(uc));
    }
}

TEST_LIST = {
    {"test_x86_evex_approx28_memory_basic",
     test_x86_evex_approx28_memory_basic},
    {"test_x86_evex_approx28_memory_broadcast",
     test_x86_evex_approx28_memory_broadcast},
    {"test_x86_evex_approx28_memory_matrix",
     test_x86_evex_approx28_memory_matrix},
    {"test_x86_evex_approx28_memory_fault_suppression",
     test_x86_evex_approx28_memory_fault_suppression},
    {"test_x86_evex_approx28_memory_exceptions",
     test_x86_evex_approx28_memory_exceptions},
    {"test_x86_evex_approx28_memory_invalid",
     test_x86_evex_approx28_memory_invalid},
    {NULL, NULL},
};
