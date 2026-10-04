#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

typedef struct TestX86InterruptRecord {
    uint32_t intno;
    uint32_t count;
} TestX86InterruptRecord;

static void test_x86_record_interrupt(uc_engine *uc, uint32_t intno,
                                      void *user_data);

#define MEM_BASE 0x40000000
#define MEM_SIZE 1024 * 1024
#define MEM_STACK MEM_BASE + (MEM_SIZE / 2)
#define MEM_TEXT MEM_STACK + 4096

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void uc_common_setup_cpu(uc_engine **uc, uc_mode mode, int cpu_model,
                                const uint8_t *code, size_t size)
{
    OK(uc_open(UC_ARCH_X86, mode, uc));
    OK(uc_ctl_set_cpu_model(*uc, cpu_model));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

typedef struct RegInfo_t {
    const char *file;
    int line;
    const char *name;
    uc_x86_reg reg;
    uint64_t value;
} RegInfo;

typedef struct QuickTest_t {
    uc_mode mode;
    uint8_t *code_data;
    size_t code_size;
    size_t in_count;
    RegInfo in_regs[32];
    size_t out_count;
    RegInfo out_regs[32];
} QuickTest;

static void QuickTest_run(QuickTest *test)
{
    uc_engine *uc;

    // initialize emulator in X86-64bit mode
    OK(uc_open(UC_ARCH_X86, test->mode, &uc));

    // map 1MB of memory for this emulation
    OK(uc_mem_map(uc, MEM_BASE, MEM_SIZE, UC_PROT_ALL));
    OK(uc_mem_write(uc, MEM_TEXT, test->code_data, test->code_size));
    if (test->mode == UC_MODE_64) {
        uint64_t stack_top = MEM_STACK;
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &stack_top));
    } else {
        uint32_t stack_top = MEM_STACK;
        OK(uc_reg_write(uc, UC_X86_REG_ESP, &stack_top));
    }
    for (size_t i = 0; i < test->in_count; i++) {
        if (test->mode == UC_MODE_64) {
            OK(uc_reg_write(uc, test->in_regs[i].reg, &test->in_regs[i].value));
        } else {
            uint32_t reg = test->in_regs[i].value & 0xFFFFFFFF;
            OK(uc_reg_write(uc, test->in_regs[i].reg, &reg));
        }
    }
    OK(uc_emu_start(uc, MEM_TEXT, MEM_TEXT + test->code_size, 0, 0));
    for (size_t i = 0; i < test->out_count; i++) {
        RegInfo *out = &test->out_regs[i];
        if (test->mode == UC_MODE_64) {
            uint64_t value = 0;
            OK(uc_reg_read(uc, out->reg, &value));
            acutest_check_(value == out->value, out->file, out->line,
                           "OUT_REG(%s, 0x%" PRIx64 ") = 0x%" PRIx64 "",
                           out->name, out->value, value);
        } else {
            uint32_t value = 0;
            OK(uc_reg_read(uc, out->reg, &value));
            acutest_check_(value == (uint32_t)out->value, out->file, out->line,
                           "OUT_REG(%s, 0x%X) = 0x%X", out->name,
                           (uint32_t)out->value, value);
        }
    }
    OK(uc_mem_unmap(uc, MEM_BASE, MEM_SIZE));
    OK(uc_close(uc));
}

#define TEST_CODE(MODE, CODE)                                                  \
    QuickTest t;                                                               \
    memset(&t, 0, sizeof(t));                                                  \
    t.mode = MODE;                                                             \
    t.code_data = CODE;                                                        \
    t.code_size = sizeof(CODE)

#define TEST_IN_REG(NAME, VALUE)                                               \
    t.in_regs[t.in_count].file = __FILE__;                                     \
    t.in_regs[t.in_count].line = __LINE__;                                     \
    t.in_regs[t.in_count].name = #NAME;                                        \
    t.in_regs[t.in_count].reg = UC_X86_REG_##NAME;                             \
    t.in_regs[t.in_count].value = VALUE;                                       \
    t.in_count++

#define TEST_OUT_REG(NAME, VALUE)                                              \
    t.out_regs[t.out_count].file = __FILE__;                                   \
    t.out_regs[t.out_count].line = __LINE__;                                   \
    t.out_regs[t.out_count].name = #NAME;                                      \
    t.out_regs[t.out_count].reg = UC_X86_REG_##NAME;                           \
    t.out_regs[t.out_count].value = VALUE;                                     \
    t.out_count++

#define TEST_RUN() QuickTest_run(&t)

typedef struct _INSN_IN_RESULT {
    uint32_t port;
    int size;
} INSN_IN_RESULT;

static void test_x86_in_callback(uc_engine *uc, uint32_t port, int size,
                                 void *user_data)
{
    INSN_IN_RESULT *result = (INSN_IN_RESULT *)user_data;
    uint32_t eip;

    result->port = port;
    result->size = size;

    OK(uc_reg_read(uc, UC_X86_REG_EIP, (void*)&eip));
    TEST_CHECK(eip == code_start);
}

static void test_x86_in(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\xe5\x10"; // IN eax, 0x10
    INSN_IN_RESULT result;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_hook_add(uc, &hook, UC_HOOK_INSN, test_x86_in_callback, &result, 1, 0,
                   UC_X86_INS_IN));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    TEST_CHECK(result.port == 0x10);
    TEST_CHECK(result.size == 4);

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

typedef struct _INSN_OUT_RESULT {
    uint32_t port;
    int size;
    uint32_t value;
} INSN_OUT_RESULT;

static void test_x86_out_callback(uc_engine *uc, uint32_t port, int size,
                                  uint32_t value, void *user_data)
{
    INSN_OUT_RESULT *result = (INSN_OUT_RESULT *)user_data;

    result->port = port;
    result->size = size;
    result->value = value;
}

static void test_x86_out(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\xb0\x32\xe6\x46"; // MOV al, 0x32; OUT  0x46, al;
    INSN_OUT_RESULT result;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_hook_add(uc, &hook, UC_HOOK_INSN, test_x86_out_callback, &result, 1,
                   0, UC_X86_INS_OUT));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    TEST_CHECK(result.port == 0x46);
    TEST_CHECK(result.size == 1);
    TEST_CHECK(result.value == 0x32);

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

typedef struct _MEM_HOOK_RESULT {
    uc_mem_type type;
    uint64_t address;
    int size;
    uint64_t value;
} MEM_HOOK_RESULT;

typedef struct _MEM_HOOK_RESULTS {
    uint64_t count;
    MEM_HOOK_RESULT results[16];
} MEM_HOOK_RESULTS;

static bool test_x86_mem_hook_all_callback(uc_engine *uc, uc_mem_type type,
                                           uint64_t address, int size,
                                           uint64_t value, void *user_data)
{
    MEM_HOOK_RESULTS *r = (MEM_HOOK_RESULTS *)user_data;
    uint64_t count = r->count;

    if (count >= 16) {
        TEST_ASSERT(false);
    }

    r->results[count].type = type;
    r->results[count].address = address;
    r->results[count].size = size;
    r->results[count].value = value;
    r->count++;

    if (type == UC_MEM_READ_UNMAPPED) {
        uc_mem_map(uc, address, 0x1000, UC_PROT_ALL);
    }

    return true;
}

static void test_x86_mem_hook_all(void)
{
    uc_engine *uc;
    uc_hook hook;
    // mov eax, 0xdeadbeef;
    // mov [0x8000], eax;
    // mov eax, [0x10000];
    char code[] =
        "\xb8\xef\xbe\xad\xde\xa3\x00\x80\x00\x00\xa1\x00\x00\x01\x00";
    MEM_HOOK_RESULTS r = {0};
    MEM_HOOK_RESULT expects[3] = {{UC_MEM_WRITE, 0x8000, 4, 0xdeadbeef},
                                  {UC_MEM_READ_UNMAPPED, 0x10000, 4, 0},
                                  {UC_MEM_READ, 0x10000, 4, 0}};

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, 0x8000, 0x1000, UC_PROT_ALL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_VALID | UC_HOOK_MEM_INVALID,
                   test_x86_mem_hook_all_callback, &r, 1, 0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    TEST_CHECK(r.count == 3);
    for (int i = 0; i < r.count; i++) {
        TEST_CHECK(expects[i].type == r.results[i].type);
        TEST_CHECK(expects[i].address == r.results[i].address);
        TEST_CHECK(expects[i].size == r.results[i].size);
        TEST_CHECK(expects[i].value == r.results[i].value);
    }

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

static void test_x86_inc_dec_pxor(void)
{
    uc_engine *uc;
    char code[] =
        "\x41\x4a\x66\x0f\xef\xc1"; // INC ecx; DEC edx; PXOR xmm0, xmm1
    int r_ecx = 0x1234;
    int r_edx = 0x7890;
    uint64_t r_xmm0[2] = {0x08090a0b0c0d0e0f, 0x0001020304050607};
    uint64_t r_xmm1[2] = {0x8090a0b0c0d0e0f0, 0x0010203040506070};

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, &r_xmm0));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, &r_xmm1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, &r_xmm0));

    TEST_CHECK(r_ecx == 0x1235);
    TEST_CHECK(r_edx == 0x788f);
    TEST_CHECK(r_xmm0[0] == 0x8899aabbccddeeff);
    TEST_CHECK(r_xmm0[1] == 0x0011223344556677);

    OK(uc_close(uc));
}

static void test_x86_pcmpistri_equal_ordered_boundary(void)
{
    uc_engine *uc;
    /* pcmpistri xmm0, xmm1, 0x4c */
    const char code[] = "\x66\x0f\x3a\x63\xc1\x4c";
    uint8_t xmm0[16] = "abcdefghijklmnop";
    uint8_t xmm1[16] = "bcdefghijklmnopa";
    uint32_t ecx = 0;

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ECX, &ecx));
    TEST_CHECK(ecx == 15);

    OK(uc_close(uc));
}

static void test_x86_stmxcsr_stack_operand(void)
{
    /* push 0x1f80; ldmxcsr [esp]; stmxcsr [esp]; pop eax */
    uint8_t code[] = {0x68, 0x80, 0x1f, 0x00, 0x00, 0x0f, 0xae,
                      0x14, 0x24, 0x0f, 0xae, 0x1c, 0x24, 0x58};
    TEST_CODE(UC_MODE_32, code);
    TEST_OUT_REG(EAX, 0x1f80);
    TEST_RUN();
}

static void test_x86_movsxd_honors_protection_after_tlb_prime(void)
{
    static const uint8_t code[] = {
        0x48, 0x63, 0x03, /* movsxd rax, dword ptr [rbx] */
    };
    const uint64_t data_address = 0x6000;
    const uint32_t data = UINT32_C(0x80000001);
    const uint64_t sentinel = UINT64_C(0x1122334455667788);
    uint64_t rax = 0;
    uint64_t rip = 0;
    uc_engine *uc;
    uc_err err;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                        code, sizeof(code));
    OK(uc_mem_map(uc, data_address, 0x1000,
                  UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, data_address, &data, sizeof(data)));
    OK(uc_reg_write(uc, UC_X86_REG_RBX, &data_address));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    TEST_CHECK(rax == UINT64_C(0xffffffff80000001));

    /* Keep WRITE unchanged while withdrawing READ.  This specifically checks
     * that uc_mem_protect invalidates a previously fast read TLB entry. */
    OK(uc_mem_protect(uc, data_address, 0x1000, UC_PROT_WRITE));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &sentinel));
    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    TEST_CHECK(err == UC_ERR_READ_PROT);
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    TEST_CHECK(rax == sentinel);
    TEST_CHECK(rip == code_start);

    OK(uc_close(uc));
}

static void test_x86_rex_prefix_must_be_last(void)
{
    /* A REX prefix separated from the opcode by CS is ignored in long mode. */
    uint8_t code[] = {0x4f, 0x2e, 0x00, 0x00}; /* add byte ptr [rax], al */
    TEST_CODE(UC_MODE_64, code);
    TEST_IN_REG(RAX, MEM_BASE);
    TEST_IN_REG(R8, 0);
    TEST_RUN();

    /* The same adjacency rule applies when the eventual opcode begins with
     * VEX or EVEX instead of a legacy opcode byte. */
    {
        static const struct {
            uint8_t code[8];
            size_t code_size;
            int cpu_model;
            size_t active_lanes;
            const char *name;
        } cases[] = {
            {{0x48, 0x2e, 0xc5, 0xf0, 0x58, 0xc2}, 6,
             UC_CPU_X86_HASWELL, 4, "VEX"},
            {{0x48, 0x2e, 0x62, 0xf1, 0x74, 0x48, 0x58, 0xc2}, 8,
             UC_CPU_X86_ICELAKE_SERVER, 16, "EVEX"},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            float source1[16];
            float source2[16];
            float observed[16];
            uint64_t rip = 0;
            uc_engine *uc;

            for (size_t lane = 0; lane < 16; ++lane) {
                source1[lane] = 1.0f;
                source2[lane] = 2.0f;
            }
            uc_common_setup_cpu(&uc, UC_MODE_64, cases[i].cpu_model,
                                cases[i].code, cases[i].code_size);
            OK(uc_reg_write(uc, UC_X86_REG_ZMM1, source1));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM2, source2));
            OK(uc_emu_start(uc, code_start,
                            code_start + cases[i].code_size, 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_ZMM0, observed));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            for (size_t lane = 0; lane < cases[i].active_lanes; ++lane) {
                TEST_CHECK_(observed[lane] == 3.0f,
                            "%s separated REX lane %zu mismatch",
                            cases[i].name, lane);
            }
            TEST_CHECK_(rip == code_start + cases[i].code_size,
                        "%s separated REX advanced RIP incorrectly",
                        cases[i].name);
            OK(uc_close(uc));
        }
    }
}

static void test_x86_null_segment_prefix_preserves_gs(void)
{
    /* CS is a null prefix in long mode, so the preceding GS override wins. */
    uint8_t code[] = {0x65, 0x2e, 0x00, 0x00}; /* add byte ptr gs:[rax], al */
    TEST_CODE(UC_MODE_64, code);
    TEST_IN_REG(RAX, 0);
    TEST_IN_REG(GS_BASE, MEM_BASE);
    TEST_RUN();
}

static void test_x86_movaps_requires_alignment(void)
{
    uc_engine *uc;
    const uint8_t code[] = {0x0f, 0x28, 0x00}; /* movaps xmm0, [rax] */
    uint64_t rax = code_start + 0x101;
    uc_err err;

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));

    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    TEST_CHECK(err == UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_x86_aligned_move_family_faults(void)
{
    static const uint8_t movapd_load[] = {0x66, 0x0f, 0x28, 0x00};
    static const uint8_t movdqa_load[] = {0x66, 0x0f, 0x6f, 0x00};
    static const uint8_t movaps_store[] = {0x0f, 0x29, 0x00};
    static const uint8_t movapd_store[] = {0x66, 0x0f, 0x29, 0x00};
    static const uint8_t movdqa_store[] = {0x66, 0x0f, 0x7f, 0x00};
    static const uint8_t movntps[] = {0x0f, 0x2b, 0x00};
    static const uint8_t movntpd[] = {0x66, 0x0f, 0x2b, 0x00};
    static const uint8_t movntdq[] = {0x66, 0x0f, 0xe7, 0x00};
    static const struct {
        const uint8_t *code;
        size_t size;
    } cases[] = {
        {movapd_load, sizeof(movapd_load)},
        {movdqa_load, sizeof(movdqa_load)},
        {movaps_store, sizeof(movaps_store)},
        {movapd_store, sizeof(movapd_store)},
        {movdqa_store, sizeof(movdqa_store)},
        {movntps, sizeof(movntps)},
        {movntpd, sizeof(movntpd)},
        {movntdq, sizeof(movntdq)},
    };
    const uint64_t rax = code_start + 0x101;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uc_engine *uc;
        uc_err err;

        OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, cases[i].code, cases[i].size));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        err = uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0);
        TEST_CHECK(err == UC_ERR_EXCEPTION);
        OK(uc_close(uc));
    }
}

static void test_x86_vmovaps_ymm_requires_32_byte_alignment(void)
{
    uc_engine *uc;
    const uint8_t code[] = {0xc5, 0xfc, 0x28, 0x00};
    /* 16-byte aligned but not 32-byte aligned. */
    uint64_t rax = code_start + 0x110;
    uc_err err;

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    TEST_CHECK(err == UC_ERR_EXCEPTION);
    OK(uc_close(uc));
}

static void test_x86_legacy_sse_m128_requires_alignment(void)
{
    static const uint8_t addps[] = {
        0x0f, 0x58, 0x00, /* addps xmm0, xmmword ptr [rax] */
    };
    static const uint8_t movsldup[] = {
        0xf3, 0x0f, 0x12, 0x00, /* movsldup xmm0, xmmword ptr [rax] */
    };
    static const uint8_t vaddps[] = {
        0xc5, 0xf8, 0x58, 0x00, /* vaddps xmm0, xmm0, xmmword ptr [rax] */
    };
    static const uint8_t vmovsldup[] = {
        0xc5, 0xfa, 0x12, 0x00, /* vmovsldup xmm0, xmmword ptr [rax] */
    };
    static const struct {
        const uint8_t *code;
        size_t size;
        uc_err expected;
    } cases[] = {
        {addps, sizeof(addps), UC_ERR_EXCEPTION},
        {movsldup, sizeof(movsldup), UC_ERR_EXCEPTION},
        {vaddps, sizeof(vaddps), UC_ERR_OK},
        {vmovsldup, sizeof(vmovsldup), UC_ERR_OK},
    };
    const uint64_t misaligned = code_start + 0x101;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[i].code, cases[i].size);
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &misaligned));
        err = uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0);
        TEST_CHECK(err == cases[i].expected);
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK(rip == (cases[i].expected == UC_ERR_OK
                               ? code_start + cases[i].size
                               : code_start));
        OK(uc_close(uc));
    }
}

static void test_x86_vmovups_ymm_roundtrip(void)
{
    uc_engine *uc;
    const uint8_t code[] = {0xc5, 0xfc, 0x10, 0x00,
                            0xc5, 0xfc, 0x11, 0x03};
    uint64_t src = code_start + 0x101;
    uint64_t dst = code_start + 0x181;
    uint8_t input[32];
    uint8_t output[32] = {0};

    for (size_t i = 0; i < sizeof(input); ++i)
        input[i] = (uint8_t)(0xa0 + i);

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, src, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &src));
    OK(uc_reg_write(uc, UC_X86_REG_RBX, &dst));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst, output, sizeof(output)));
    TEST_CHECK(memcmp(output, input, sizeof(input)) == 0);
    OK(uc_close(uc));
}

static void test_x86_vpermilps_variable_xmm(void)
{
    uc_engine *uc;
    /* vpermilps xmm0, xmm1, xmm2 */
    const char code[] = "\xc4\xe2\x71\x0c\xc2";
    uint32_t data[4] = {10, 20, 30, 40};
    uint32_t control[4] = {3, 0, 2, 1};
    uint32_t result[4] = {0};
    const uint32_t expected[4] = {40, 10, 30, 20};

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, data));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, control));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, result));
    TEST_CHECK(memcmp(result, expected, sizeof(expected)) == 0);

    OK(uc_close(uc));
}

static void test_x86_vpermilpd_variable_xmm(void)
{
    uc_engine *uc;
    /* vpermilpd xmm0, xmm1, xmm2 */
    const char code[] = "\xc4\xe2\x71\x0d\xc2";
    uint64_t data[2] = {10, 20};
    uint64_t control[2] = {2, 0};
    uint64_t result[2] = {0};
    const uint64_t expected[2] = {20, 10};

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, data));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, control));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, result));
    TEST_CHECK(memcmp(result, expected, sizeof(expected)) == 0);

    OK(uc_close(uc));
}

static void test_x86_vpermilps_variable_ymm(void)
{
    uc_engine *uc;
    /* vpermilps ymm0, ymm1, ymm2 */
    const char code[] = "\xc4\xe2\x75\x0c\xc2";
    uint32_t data[8] = {10, 20, 30, 40, 50, 60, 70, 80};
    uint32_t control[8] = {3, 0, 2, 1, 0, 3, 1, 2};
    uint32_t result[8] = {0};
    const uint32_t expected[8] = {40, 10, 30, 20, 50, 80, 60, 70};

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, data));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, control));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
    TEST_CHECK(memcmp(result, expected, sizeof(expected)) == 0);

    OK(uc_close(uc));
}

static void test_x86_vpermilpd_variable_ymm(void)
{
    uc_engine *uc;
    /* vpermilpd ymm0, ymm1, ymm2 */
    const char code[] = "\xc4\xe2\x75\x0d\xc2";
    uint64_t data[4] = {10, 20, 30, 40};
    uint64_t control[4] = {2, 0, 2, 0};
    uint64_t result[4] = {0};
    const uint64_t expected[4] = {20, 10, 40, 30};

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, data));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, control));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
    TEST_CHECK(memcmp(result, expected, sizeof(expected)) == 0);

    OK(uc_close(uc));
}

static void test_x86_vpermil_variable_memory(void)
{
    uc_engine *uc;
    /* vpermilps xmm0, xmm1, [rax]; vpermilpd ymm3, ymm4, [rax + 32] */
    const char code[] = "\xc4\xe2\x71\x0c\x00"
                        "\xc4\xe2\x5d\x0d\x58\x20";
    uint64_t control_addr = 0x2000;
    uint32_t ps_data[4] = {10, 20, 30, 40};
    uint32_t ps_control[4] = {3, 0, 2, 1};
    uint32_t ps_result[4] = {0};
    const uint32_t ps_expected[4] = {40, 10, 30, 20};
    uint64_t pd_data[4] = {10, 20, 30, 40};
    uint64_t pd_control[4] = {2, 0, 2, 0};
    uint64_t pd_result[4] = {0};
    const uint64_t pd_expected[4] = {20, 10, 40, 30};

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, control_addr, ps_control, sizeof(ps_control)));
    OK(uc_mem_write(uc, control_addr + 32, pd_control, sizeof(pd_control)));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &control_addr));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, ps_data));
    OK(uc_reg_write(uc, UC_X86_REG_YMM4, pd_data));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, ps_result));
    OK(uc_reg_read(uc, UC_X86_REG_YMM3, pd_result));
    TEST_CHECK(memcmp(ps_result, ps_expected, sizeof(ps_expected)) == 0);
    TEST_CHECK(memcmp(pd_result, pd_expected, sizeof(pd_expected)) == 0);

    OK(uc_close(uc));
}

static void test_x86_vpermil_invalid_mmx_encoding(void)
{
    uc_engine *uc;
    const char code[] = "\xc4\x01\x00\x38\x0c\x00";
    uc_err err;

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    err = uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0);
    TEST_CHECK(err == UC_ERR_INSN_INVALID);

    OK(uc_close(uc));
}

static void test_x86_opmask_kandw_semantics(void)
{
    static const uint8_t code[] = {
        0xc5, 0xec, 0x41, 0xcb, /* kandw k1, k2, k3 */
    };
    const uint64_t initial_k1 = UINT64_MAX;
    const uint64_t initial_k2 = UINT64_C(0xaaaaaaaa5555f0f3);
    const uint64_t initial_k3 = UINT64_C(0x55555555aaa50ff5);
    const uint64_t initial_rflags = UINT64_C(0xcd7);
    uint64_t k1 = initial_k1;
    uint64_t k2 = initial_k2;
    uint64_t k3 = initial_k3;
    uint64_t rflags = initial_rflags;
    uint64_t rip = 0;
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
    OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
    OK(uc_reg_write(uc, UC_X86_REG_K3, &k3));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
    OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
    OK(uc_reg_read(uc, UC_X86_REG_K3, &k3));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    TEST_CHECK_(k1 == UINT64_C(0x00f1),
                "KANDW did not zero-extend its 16-bit result");
    TEST_CHECK_(k2 == initial_k2 && k3 == initial_k3,
                "KANDW changed a source opmask register");
    TEST_CHECK_(rflags == initial_rflags, "KANDW changed RFLAGS");
    TEST_CHECK_(rip == code_start + sizeof(code), "KANDW advanced RIP wrong");

    OK(uc_close(uc));
}

static void test_x86_opmask_kandq_semantics(void)
{
    static const uint8_t code[] = {
        0xc4, 0xe1, 0xec, 0x41, 0xcb, /* kandq k1, k2, k3 */
    };
    const uint64_t initial_k2 = UINT64_C(0xf0f0aa55deadbeef);
    const uint64_t initial_k3 = UINT64_C(0xcc33ffff0ff00ff0);
    const uint64_t initial_rflags = UINT64_C(0xcd7);
    uint64_t k1 = 0;
    uint64_t k2 = initial_k2;
    uint64_t k3 = initial_k3;
    uint64_t rflags = initial_rflags;
    uint64_t rip = 0;
    uc_engine *uc;
    uc_err err;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
    OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
    OK(uc_reg_write(uc, UC_X86_REG_K3, &k3));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
    OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
    OK(uc_reg_read(uc, UC_X86_REG_K3, &k3));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    TEST_CHECK_(err == UC_ERR_INSN_INVALID,
                "KANDQ executed without advertised AVX-512BW");
    TEST_CHECK_(k1 == 0, "KANDQ changed its destination before #UD");
    TEST_CHECK_(k2 == initial_k2 && k3 == initial_k3,
                "KANDQ changed a source opmask register");
    TEST_CHECK_(rflags == initial_rflags, "KANDQ changed RFLAGS");
    TEST_CHECK_(rip == code_start, "KANDQ advanced RIP before #UD");

    OK(uc_close(uc));
}

static void run_x86_opmask_binary_case(const uint8_t *code, size_t code_size,
                                       uint64_t initial_k2,
                                       uint64_t initial_k3, uint64_t expected,
                                       const char *mnemonic)
{
    const uint64_t initial_rflags = UINT64_C(0xcd7);
    uint64_t k1 = UINT64_MAX;
    uint64_t k2 = initial_k2;
    uint64_t k3 = initial_k3;
    uint64_t rflags = initial_rflags;
    uint64_t rip = 0;
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER, code,
                        code_size);
    OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
    OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
    OK(uc_reg_write(uc, UC_X86_REG_K3, &k3));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
    OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
    OK(uc_reg_read(uc, UC_X86_REG_K3, &k3));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    TEST_CHECK_(k1 == expected, "%s produced the wrong result", mnemonic);
    TEST_CHECK_(k2 == initial_k2 && k3 == initial_k3,
                "%s changed a source opmask register", mnemonic);
    TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS", mnemonic);
    TEST_CHECK_(rip == code_start + code_size, "%s advanced RIP wrong",
                mnemonic);

    OK(uc_close(uc));
}

static void test_x86_opmask_kand_byte_dword(void)
{
    static const uint8_t kandb[] = {0xc5, 0xed, 0x41, 0xcb};
    static const uint8_t kandd[] = {0xc4, 0xe1, 0xed, 0x41, 0xcb};
    const uint64_t k2 = UINT64_C(0xf0f0aa55deadbeef);
    const uint64_t k3 = UINT64_C(0xcc33ffff0ff00ff0);

    run_x86_opmask_binary_case(kandb, sizeof(kandb), k2, k3,
                               UINT64_C(0xe0), "KANDB");
    {
        const uint64_t initial_k1 = UINT64_C(0x1122334455667788);
        uint64_t k1 = initial_k1;
        uint64_t source2 = k2;
        uint64_t source3 = k3;
        uint64_t rip = 0;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            kandd, sizeof(kandd));
        OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
        OK(uc_reg_write(uc, UC_X86_REG_K2, &source2));
        OK(uc_reg_write(uc, UC_X86_REG_K3, &source3));
        uc_assert_err(UC_ERR_INSN_INVALID,
                      uc_emu_start(uc, code_start,
                                   code_start + sizeof(kandd), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK(k1 == initial_k1);
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }
}

static void test_x86_opmask_kandn_widths(void)
{
    static const struct {
        uint8_t code[5];
        size_t code_size;
        uint64_t expected;
        const char *mnemonic;
    } cases[] = {
        {{0xc5, 0xed, 0x42, 0xcb}, 4, UINT64_C(0x10), "KANDNB"},
        {{0xc5, 0xec, 0x42, 0xcb}, 4, UINT64_C(0x0110), "KANDNW"},
    };
    const uint64_t k2 = UINT64_C(0xf0f0aa55deadbeef);
    const uint64_t k3 = UINT64_C(0xcc33ffff0ff00ff0);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        run_x86_opmask_binary_case(cases[i].code, cases[i].code_size, k2, k3,
                                   cases[i].expected, cases[i].mnemonic);
    }
}

static void test_x86_opmask_kor_widths(void)
{
    static const struct {
        uint8_t code[5];
        size_t code_size;
        uint64_t expected;
        const char *mnemonic;
    } cases[] = {
        {{0xc5, 0xed, 0x45, 0xcb}, 4, UINT64_C(0xff), "KORB"},
        {{0xc5, 0xec, 0x45, 0xcb}, 4, UINT64_C(0xbfff), "KORW"},
    };
    const uint64_t k2 = UINT64_C(0xf0f0aa55deadbeef);
    const uint64_t k3 = UINT64_C(0xcc33ffff0ff00ff0);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        run_x86_opmask_binary_case(cases[i].code, cases[i].code_size, k2, k3,
                                   cases[i].expected, cases[i].mnemonic);
    }
}

static void test_x86_opmask_kxor_widths(void)
{
    static const struct {
        uint8_t code[5];
        size_t code_size;
        uint64_t expected;
        const char *mnemonic;
    } cases[] = {
        {{0xc5, 0xed, 0x47, 0xcb}, 4, UINT64_C(0x1f), "KXORB"},
        {{0xc5, 0xec, 0x47, 0xcb}, 4, UINT64_C(0xb11f), "KXORW"},
    };
    const uint64_t k2 = UINT64_C(0xf0f0aa55deadbeef);
    const uint64_t k3 = UINT64_C(0xcc33ffff0ff00ff0);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        run_x86_opmask_binary_case(cases[i].code, cases[i].code_size, k2, k3,
                                   cases[i].expected, cases[i].mnemonic);
    }
}

static void test_x86_opmask_kxnor_widths(void)
{
    static const struct {
        uint8_t code[5];
        size_t code_size;
        uint64_t expected;
        const char *mnemonic;
    } cases[] = {
        {{0xc5, 0xed, 0x46, 0xcb}, 4, UINT64_C(0xe0), "KXNORB"},
        {{0xc5, 0xec, 0x46, 0xcb}, 4, UINT64_C(0x4ee0), "KXNORW"},
    };
    const uint64_t k2 = UINT64_C(0xf0f0aa55deadbeef);
    const uint64_t k3 = UINT64_C(0xcc33ffff0ff00ff0);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        run_x86_opmask_binary_case(cases[i].code, cases[i].code_size, k2, k3,
                                   cases[i].expected, cases[i].mnemonic);
    }
}

static void test_x86_opmask_kadd_widths(void)
{
    static const struct {
        uint8_t code[5];
        size_t code_size;
        uint64_t expected;
        const char *mnemonic;
    } cases[] = {
        {{0xc5, 0xed, 0x4a, 0xcb}, 4, UINT64_C(0xdf), "KADDB"},
        {{0xc5, 0xec, 0x4a, 0xcb}, 4, UINT64_C(0xcedf), "KADDW"},
    };
    const uint64_t k2 = UINT64_C(0xf0f0aa55deadbeef);
    const uint64_t k3 = UINT64_C(0xcc33ffff0ff00ff0);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        run_x86_opmask_binary_case(cases[i].code, cases[i].code_size, k2, k3,
                                   cases[i].expected, cases[i].mnemonic);
    }
}

static void run_x86_opmask_unary_case(const uint8_t *code, size_t code_size,
                                      uint64_t initial_k2, uint64_t expected,
                                      const char *mnemonic)
{
    const uint64_t initial_rflags = UINT64_C(0xcd7);
    uint64_t k1 = UINT64_MAX;
    uint64_t k2 = initial_k2;
    uint64_t rflags = initial_rflags;
    uint64_t rip = 0;
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER, code,
                        code_size);
    OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
    OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
    OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    TEST_CHECK_(k1 == expected, "%s produced the wrong result", mnemonic);
    TEST_CHECK_(k2 == initial_k2, "%s changed its source", mnemonic);
    TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS", mnemonic);
    TEST_CHECK_(rip == code_start + code_size, "%s advanced RIP wrong",
                mnemonic);

    OK(uc_close(uc));
}

static void test_x86_opmask_knot_widths(void)
{
    static const struct {
        uint8_t code[5];
        size_t code_size;
        uint64_t expected;
        const char *mnemonic;
    } cases[] = {
        {{0xc5, 0xf9, 0x44, 0xca}, 4, UINT64_C(0x10), "KNOTB"},
        {{0xc5, 0xf8, 0x44, 0xca}, 4, UINT64_C(0x4110), "KNOTW"},
    };
    const uint64_t k2 = UINT64_C(0xf0f0aa55deadbeef);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        run_x86_opmask_unary_case(cases[i].code, cases[i].code_size, k2,
                                  cases[i].expected, cases[i].mnemonic);
    }
}

static void test_x86_opmask_kunpack_widths(void)
{
    static const struct {
        uint8_t code[5];
        size_t code_size;
        uint64_t expected;
        const char *mnemonic;
    } cases[] = {
        {{0xc5, 0xed, 0x4b, 0xcb}, 4, UINT64_C(0x8800), "KUNPCKBW"},
    };
    const uint64_t k2 = UINT64_C(0x1122334455667788);
    const uint64_t k3 = UINT64_C(0x99aabbccddeeff00);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        run_x86_opmask_binary_case(cases[i].code, cases[i].code_size, k2, k3,
                                   cases[i].expected, cases[i].mnemonic);
    }
}

static void test_x86_opmask_kshift_widths(void)
{
    static const struct {
        uint8_t code[6];
        uint64_t expected;
        const char *mnemonic;
    } cases[] = {
        {{0xc4, 0xe3, 0x79, 0x32, 0xca, 0x04}, UINT64_C(0xf0),
         "KSHIFTLB"},
        {{0xc4, 0xe3, 0xf9, 0x32, 0xca, 0x04}, UINT64_C(0xeef0),
         "KSHIFTLW"},
        {{0xc4, 0xe3, 0x79, 0x30, 0xca, 0x04}, UINT64_C(0x0e),
         "KSHIFTRB"},
        {{0xc4, 0xe3, 0xf9, 0x30, 0xca, 0x04}, UINT64_C(0x0bee),
         "KSHIFTRW"},
        {{0xc4, 0xe3, 0x79, 0x32, 0xca, 0x08}, UINT64_C(0),
         "KSHIFTLB width-count"},
    };
    const uint64_t k2 = UINT64_C(0xf0f0aa55deadbeef);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        run_x86_opmask_unary_case(cases[i].code, sizeof(cases[i].code), k2,
                                  cases[i].expected, cases[i].mnemonic);
    }
}

static void test_x86_opmask_kmov_register_widths(void)
{
    static const struct {
        uint8_t kk_code[5];
        size_t kk_size;
        uint8_t gpr_to_k_code[5];
        size_t gpr_to_k_size;
        uint8_t k_to_gpr_code[5];
        size_t k_to_gpr_size;
        uint64_t expected;
        const char *mnemonic;
    } cases[] = {
        {{0xc5, 0xf9, 0x90, 0xca}, 4,
         {0xc5, 0xf9, 0x92, 0xc8}, 4,
         {0xc5, 0xf9, 0x93, 0xc2}, 4, UINT64_C(0xef), "KMOVB"},
        {{0xc5, 0xf8, 0x90, 0xca}, 4,
         {0xc5, 0xf8, 0x92, 0xc8}, 4,
         {0xc5, 0xf8, 0x93, 0xc2}, 4, UINT64_C(0xbeef), "KMOVW"},
    };
    const uint64_t source = UINT64_C(0xf0f0aa55deadbeef);
    const uint64_t initial_rflags = UINT64_C(0xcd7);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t k1 = UINT64_MAX;
        uint64_t k2 = source;
        uint64_t rax = source;
        uint64_t rflags = initial_rflags;
        uc_engine *uc;

        run_x86_opmask_unary_case(cases[i].kk_code, cases[i].kk_size,
                                  source, cases[i].expected,
                                  cases[i].mnemonic);

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            cases[i].gpr_to_k_code,
                            cases[i].gpr_to_k_size);
        OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start,
                        code_start + cases[i].gpr_to_k_size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        TEST_CHECK_(k1 == cases[i].expected, "%s GPR-to-K wrong",
                    cases[i].mnemonic);
        TEST_CHECK_(rax == source, "%s GPR-to-K changed its source",
                    cases[i].mnemonic);
        TEST_CHECK_(rflags == initial_rflags, "%s GPR-to-K changed RFLAGS",
                    cases[i].mnemonic);
        OK(uc_close(uc));

        k2 = source;
        rax = UINT64_MAX;
        rflags = initial_rflags;
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            cases[i].k_to_gpr_code,
                            cases[i].k_to_gpr_size);
        OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start,
                        code_start + cases[i].k_to_gpr_size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        TEST_CHECK_(rax == cases[i].expected, "%s K-to-GPR wrong",
                    cases[i].mnemonic);
        TEST_CHECK_(k2 == source, "%s K-to-GPR changed its source",
                    cases[i].mnemonic);
        TEST_CHECK_(rflags == initial_rflags, "%s K-to-GPR changed RFLAGS",
                    cases[i].mnemonic);
        OK(uc_close(uc));
    }
}

static void test_x86_opmask_kmov_memory_widths(void)
{
    static const struct {
        uint8_t load_code[5];
        size_t load_size;
        uint8_t store_code[5];
        size_t store_size;
        uint64_t load_expected;
        uint64_t store_expected;
        const char *mnemonic;
    } cases[] = {
        {{0xc5, 0xf9, 0x90, 0x08}, 4,
         {0xc5, 0xf9, 0x91, 0x10}, 4, UINT64_C(0x88),
         UINT64_C(0x11223344556677ef), "KMOVB"},
        {{0xc5, 0xf8, 0x90, 0x08}, 4,
         {0xc5, 0xf8, 0x91, 0x10}, 4, UINT64_C(0x7788),
         UINT64_C(0x112233445566beef), "KMOVW"},
    };
    const uint64_t data_address = code_start + 0x200;
    const uint64_t initial_memory = UINT64_C(0x1122334455667788);
    const uint64_t source = UINT64_C(0xf0f0aa55deadbeef);
    const uint64_t initial_rflags = UINT64_C(0xcd7);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t k1 = UINT64_MAX;
        uint64_t k2 = source;
        uint64_t rax = data_address;
        uint64_t memory = initial_memory;
        uint64_t rflags = initial_rflags;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            cases[i].load_code, cases[i].load_size);
        OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + cases[i].load_size,
                        0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        TEST_CHECK_(k1 == cases[i].load_expected, "%s memory load wrong",
                    cases[i].mnemonic);
        TEST_CHECK_(rflags == initial_rflags, "%s load changed RFLAGS",
                    cases[i].mnemonic);
        OK(uc_close(uc));

        memory = initial_memory;
        rflags = initial_rflags;
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            cases[i].store_code, cases[i].store_size);
        OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + cases[i].store_size,
                        0, 0));
        OK(uc_mem_read(uc, data_address, &memory, sizeof(memory)));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        TEST_CHECK_(memory == cases[i].store_expected,
                    "%s memory store used the wrong width", cases[i].mnemonic);
        TEST_CHECK_(rflags == initial_rflags, "%s store changed RFLAGS",
                    cases[i].mnemonic);
        OK(uc_close(uc));
    }
}

static void test_x86_opmask_kmov_extended_operands(void)
{
    static const uint8_t gpr_to_k[] = {
        0xc4, 0xc1, 0x78, 0x92, 0xc8, /* kmovw k1, r8d */
    };
    static const uint8_t k_to_gpr[] = {
        0xc5, 0x78, 0x93, 0xca, /* kmovw r9d, k2 */
    };
    static const uint8_t memory_load[] = {
        0xc4, 0x81, 0x78, 0x90, 0x4c, 0x48, 0x10,
        /* kmovw k1, word ptr [r8 + r9*2 + 16] */
    };
    static const uint8_t memory_store[] = {
        0xc4, 0x81, 0x78, 0x91, 0x54, 0x48, 0x10,
        /* kmovw word ptr [r8 + r9*2 + 16], k2 */
    };
    const uint64_t source = UINT64_C(0xf0f0aa55deadbeef);
    const uint64_t data_address = code_start + 0x300;
    const uint64_t r9_index = 3;
    const uint64_t r8_base = data_address - r9_index * 2 - 16;
    const uint64_t initial_memory = UINT64_C(0x1122334455667788);
    uint64_t k1 = UINT64_MAX;
    uint64_t k2 = source;
    uint64_t r8 = source;
    uint64_t r9 = UINT64_MAX;
    uint64_t memory = initial_memory;
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                        gpr_to_k, sizeof(gpr_to_k));
    OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
    OK(uc_reg_write(uc, UC_X86_REG_R8, &r8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(gpr_to_k), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
    OK(uc_reg_read(uc, UC_X86_REG_R8, &r8));
    TEST_CHECK(k1 == UINT64_C(0xbeef));
    TEST_CHECK(r8 == source);
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                        k_to_gpr, sizeof(k_to_gpr));
    OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
    OK(uc_reg_write(uc, UC_X86_REG_R9, &r9));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(k_to_gpr), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
    OK(uc_reg_read(uc, UC_X86_REG_R9, &r9));
    TEST_CHECK(r9 == UINT64_C(0xbeef));
    TEST_CHECK(k2 == source);
    OK(uc_close(uc));

    r8 = r8_base;
    r9 = r9_index;
    k1 = UINT64_MAX;
    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                        memory_load, sizeof(memory_load));
    OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
    OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
    OK(uc_reg_write(uc, UC_X86_REG_R8, &r8));
    OK(uc_reg_write(uc, UC_X86_REG_R9, &r9));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(memory_load), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
    TEST_CHECK(k1 == UINT64_C(0x7788));
    OK(uc_close(uc));

    memory = initial_memory;
    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                        memory_store, sizeof(memory_store));
    OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
    OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
    OK(uc_reg_write(uc, UC_X86_REG_R8, &r8));
    OK(uc_reg_write(uc, UC_X86_REG_R9, &r9));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(memory_store), 0, 0));
    OK(uc_mem_read(uc, data_address, &memory, sizeof(memory)));
    TEST_CHECK(memory == UINT64_C(0x112233445566beef));
    OK(uc_close(uc));
}

static void test_x86_opmask_ktestw_flags(void)
{
    static const uint8_t code[] = {
        0xc5, 0xf8, 0x99, 0xd3, /* ktestw k2, k3 */
    };
    static const struct {
        uint64_t k2;
        uint64_t k3;
        uint64_t expected_status;
    } cases[] = {
        {UINT64_C(0xffff000000000000), UINT64_C(0xaaaa000000000000),
         UINT64_C(0x41)}, /* ZF=1, CF=1 */
        {UINT64_C(0xffff00000000000f), UINT64_C(0xffff0000000000f0),
         UINT64_C(0x40)}, /* ZF=1, CF=0 */
        {UINT64_C(0x000000000000f0f3), UINT64_C(0xffff0000000000f1),
         UINT64_C(0x01)}, /* ZF=0, CF=1 */
        {UINT64_C(0xffff0000000000f3), UINT64_C(0xffff000000000f01),
         UINT64_C(0x00)}, /* ZF=0, CF=0 */
    };
    const uint64_t initial_rflags = UINT64_C(0xcd7);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t k2 = cases[i].k2;
        uint64_t k3 = cases[i].k3;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
        OK(uc_reg_write(uc, UC_X86_REG_K3, &k3));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
        OK(uc_reg_read(uc, UC_X86_REG_K3, &k3));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(k2 == cases[i].k2 && k3 == cases[i].k3,
                    "KTESTW changed an opmask source in case %zu", i);
        TEST_CHECK_(rflags == (UINT64_C(0x402) | cases[i].expected_status),
                    "KTESTW produced wrong flags in case %zu", i);
        TEST_CHECK_(rip == code_start + sizeof(code),
                    "KTESTW advanced RIP wrong in case %zu", i);

        OK(uc_close(uc));
    }
}

static void test_x86_opmask_ktest_other_widths(void)
{
    static const struct {
        uint8_t code[5];
        size_t code_size;
        uint64_t k2;
        uint64_t k3;
        uint64_t expected_status;
        const char *mnemonic;
    } cases[] = {
        {{0xc5, 0xf9, 0x99, 0xd3}, 4, UINT64_C(0xffff00000000000f),
         UINT64_C(0xffff0000000000f0), UINT64_C(0x40), "KTESTB"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t k2 = cases[i].k2;
        uint64_t k3 = cases[i].k3;
        uint64_t rflags = UINT64_C(0xcd7);
        uint64_t rip = 0;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            cases[i].code, cases[i].code_size);
        OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
        OK(uc_reg_write(uc, UC_X86_REG_K3, &k3));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        OK(uc_emu_start(uc, code_start, code_start + cases[i].code_size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
        OK(uc_reg_read(uc, UC_X86_REG_K3, &k3));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(k2 == cases[i].k2 && k3 == cases[i].k3,
                    "%s changed a source", cases[i].mnemonic);
        TEST_CHECK_(rflags == (UINT64_C(0x402) | cases[i].expected_status),
                    "%s produced wrong flags", cases[i].mnemonic);
        TEST_CHECK_(rip == code_start + cases[i].code_size,
                    "%s advanced RIP wrong", cases[i].mnemonic);

        OK(uc_close(uc));
    }
}

static void test_x86_opmask_kortest_widths(void)
{
    static const struct {
        uint8_t code[5];
        size_t code_size;
        uint64_t k2;
        uint64_t k3;
        uint64_t expected_status;
        const char *mnemonic;
    } cases[] = {
        {{0xc5, 0xf9, 0x98, 0xd3}, 4, UINT64_C(0xffff000000000000),
         UINT64_C(0xaaaa000000000000), UINT64_C(0x40), "KORTESTB"},
        {{0xc5, 0xf8, 0x98, 0xd3}, 4, UINT64_C(0xffff000000000f0f),
         UINT64_C(0xaaaa00000000f0f0), UINT64_C(0x01), "KORTESTW"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t k2 = cases[i].k2;
        uint64_t k3 = cases[i].k3;
        uint64_t rflags = UINT64_C(0xcd7);
        uint64_t rip = 0;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            cases[i].code, cases[i].code_size);
        OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
        OK(uc_reg_write(uc, UC_X86_REG_K3, &k3));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        OK(uc_emu_start(uc, code_start, code_start + cases[i].code_size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
        OK(uc_reg_read(uc, UC_X86_REG_K3, &k3));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(k2 == cases[i].k2 && k3 == cases[i].k3,
                    "%s changed a source", cases[i].mnemonic);
        TEST_CHECK_(rflags == (UINT64_C(0x402) | cases[i].expected_status),
                    "%s produced wrong flags", cases[i].mnemonic);
        TEST_CHECK_(rip == code_start + cases[i].code_size,
                    "%s advanced RIP wrong", cases[i].mnemonic);

        OK(uc_close(uc));
    }
}

static void test_x86_reserved_opmask_opcode_stays_fail_closed(void)
{
    static const uint8_t code[] = {
        0xc5, 0xec, 0x43, 0xcb, /* reserved VEX opmask-shaped opcode */
    };
    const uint64_t initial_rcx = UINT64_C(0x1122334455667788);
    const uint64_t initial_rbx = UINT64_C(0x00000000a5a5a5a5);
    const uint64_t initial_rflags = UINT64_C(0xcd7);
    uint64_t rcx = initial_rcx;
    uint64_t rbx = initial_rbx;
    uint64_t rflags = initial_rflags;
    uint64_t rip = 0;
    uc_engine *uc;
    uc_err err;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    TEST_CHECK_(err == UC_ERR_INSN_INVALID,
                "reserved VEX opcode did not report invalid instruction");
    TEST_CHECK_(rcx == initial_rcx,
                "reserved VEX opcode executed legacy CMOVAE semantics");
    TEST_CHECK_(rflags == initial_rflags,
                "reserved VEX opcode changed RFLAGS before #UD");
    TEST_CHECK_(rip == code_start,
                "reserved VEX opcode advanced RIP before #UD");

    OK(uc_close(uc));
}

static void test_x86_opmask_invalid_forms(void)
{
    static const struct {
        uint8_t code[6];
        size_t code_size;
        const char *description;
    } cases[] = {
        {{0xc5, 0xec, 0x41, 0x0b}, 4, "KANDW memory ModRM"},
        {{0xc5, 0xbc, 0x45, 0xcb}, 4, "KORW source K8"},
        {{0xc5, 0x6c, 0x47, 0xcb}, 4, "KXORW extended destination"},
        {{0xc5, 0xe8, 0x4a, 0xcb}, 4, "KADDW with L0"},
        {{0xc5, 0xee, 0x42, 0xcb}, 4, "KANDNW with F2 pp"},
        {{0xc5, 0xf8, 0x44, 0x0a}, 4, "KNOTW memory ModRM"},
        {{0xc5, 0xe8, 0x44, 0xca}, 4, "KNOTW reserved vvvv"},
        {{0xc5, 0xfc, 0x44, 0xca}, 4, "KNOTW with L1"},
        {{0xc5, 0xf8, 0x99, 0x13}, 4, "KTESTW memory ModRM"},
        {{0xc5, 0xe8, 0x99, 0xd3}, 4, "KTESTW reserved vvvv"},
        {{0xc5, 0xfc, 0x99, 0xd3}, 4, "KTESTW with L1"},
        {{0xc5, 0xe8, 0x98, 0xd3}, 4, "KORTESTW reserved vvvv"},
        {{0xc4, 0xe1, 0xed, 0x4b, 0xcb}, 5,
         "KUNPCK with reserved W1+66 width"},
        {{0xc5, 0xe8, 0x4b, 0xcb}, 4, "KUNPCKWD with L0"},
        {{0xc5, 0xec, 0x4b, 0x0b}, 4, "KUNPCKWD memory ModRM"},
        {{0xc4, 0xe3, 0x78, 0x32, 0xca, 0x04}, 6,
         "KSHIFTLB without mandatory 66"},
        {{0xc4, 0xe3, 0x7d, 0x32, 0xca, 0x04}, 6,
         "KSHIFTLB with L1"},
        {{0xc4, 0xe3, 0x71, 0x32, 0xca, 0x04}, 6,
         "KSHIFTLB reserved vvvv"},
        {{0xc4, 0xe3, 0x79, 0x32, 0x0a, 0x04}, 6,
         "KSHIFTLB memory ModRM"},
        {{0xc4, 0xc3, 0x79, 0x32, 0xca, 0x04}, 6,
         "KSHIFTLB extended source"},
        {{0xc5, 0xfc, 0x90, 0xca}, 4, "KMOVW with L1"},
        {{0xc5, 0xe8, 0x90, 0xca}, 4, "KMOVW reserved vvvv"},
        {{0xc5, 0x78, 0x90, 0xca}, 4, "KMOVW extended K destination"},
        {{0xc4, 0xc1, 0x78, 0x90, 0xca}, 5,
         "KMOVW extended K source"},
        {{0xc5, 0xfa, 0x90, 0xca}, 4, "KMOV K-to-K with F2"},
        {{0xc5, 0xf8, 0x91, 0xca}, 4, "KMOV store with register ModRM"},
        {{0xc5, 0xf8, 0x92, 0x08}, 4, "KMOV GPR-to-K memory ModRM"},
        {{0xc5, 0x78, 0x92, 0xc8}, 4,
         "KMOV GPR-to-K extended K destination"},
        {{0xc4, 0xe1, 0xf8, 0x92, 0xc8}, 5,
         "KMOV GPR-to-K reserved W1 no-prefix width"},
        {{0xc5, 0xf8, 0x93, 0x02}, 4, "KMOV K-to-GPR memory ModRM"},
        {{0xc4, 0xc1, 0x78, 0x93, 0xc2}, 5,
         "KMOV K-to-GPR extended K source"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const uint64_t initial_k1 = UINT64_C(0x1111222233334444);
        const uint64_t initial_k2 = UINT64_C(0x5555666677778888);
        const uint64_t initial_k3 = UINT64_C(0x9999aaaabbbbcccc);
        const uint64_t initial_rcx = UINT64_C(0x0123456789abcdef);
        const uint64_t initial_rbx = UINT64_C(0xfedcba9876543210);
        const uint64_t initial_rflags = UINT64_C(0xcd7);
        uint64_t k1 = initial_k1;
        uint64_t k2 = initial_k2;
        uint64_t k3 = initial_k3;
        uint64_t rcx = initial_rcx;
        uint64_t rbx = initial_rbx;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            cases[i].code, cases[i].code_size);
        OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
        OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
        OK(uc_reg_write(uc, UC_X86_REG_K3, &k3));
        OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
        OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err = uc_emu_start(uc, code_start,
                           code_start + cases[i].code_size, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
        OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
        OK(uc_reg_read(uc, UC_X86_REG_K3, &k3));
        OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx));
        OK(uc_reg_read(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    cases[i].description);
        TEST_CHECK_(k1 == initial_k1 && k2 == initial_k2 && k3 == initial_k3,
                    "%s changed an opmask register", cases[i].description);
        TEST_CHECK_(rcx == initial_rcx && rbx == initial_rbx,
                    "%s executed legacy GPR semantics", cases[i].description);
        TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                    cases[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP", cases[i].description);

        OK(uc_close(uc));
    }
}

static void test_x86_opmask_register_roundtrip(void)
{
    static const uint8_t code[] = {0x90};
    static const uc_x86_reg opmask_regs[] = {
        UC_X86_REG_K0, UC_X86_REG_K1, UC_X86_REG_K2, UC_X86_REG_K3,
        UC_X86_REG_K4, UC_X86_REG_K5, UC_X86_REG_K6, UC_X86_REG_K7,
    };
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));

    for (size_t i = 0; i < sizeof(opmask_regs) / sizeof(opmask_regs[0]); ++i) {
        const uint64_t written = UINT64_C(0xfedcba9876543210) ^
                                 (UINT64_C(0x1111111111111111) * i);
        uint64_t observed = ~written;

        OK(uc_reg_write(uc, opmask_regs[i], &written));
        OK(uc_reg_read(uc, opmask_regs[i], &observed));
        TEST_CHECK_(observed == written,
                    "K%zu did not round-trip through the public register API",
                    i);
    }

    OK(uc_close(uc));
}

static void test_x86_zmm_register_roundtrip_and_reset(void)
{
    static const uint8_t code[] = {0x90};
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    for (int reg = 0; reg < 32; ++reg) {
        uint64_t written[8];
        uint64_t observed[8] = {0};

        for (int lane = 0; lane < 8; ++lane) {
            written[lane] = UINT64_C(0x1020304050607080) ^
                            ((uint64_t)reg << 32) ^ (uint64_t)lane;
        }
        OK(uc_reg_write(uc, UC_X86_REG_ZMM0 + reg, written));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM0 + reg, observed));
        TEST_CHECK_(memcmp(written, observed, sizeof(written)) == 0,
                    "ZMM%d did not round-trip all 64 bytes", reg);
    }
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    for (int reg = 0; reg < 32; ++reg) {
        uint64_t observed[8] = {UINT64_MAX, UINT64_MAX, UINT64_MAX,
                                UINT64_MAX, UINT64_MAX, UINT64_MAX,
                                UINT64_MAX, UINT64_MAX};
        uint64_t zero[8] = {0};

        OK(uc_reg_read(uc, UC_X86_REG_ZMM0 + reg, observed));
        TEST_CHECK_(memcmp(zero, observed, sizeof(zero)) == 0,
                    "ZMM%d was not reset to zero", reg);
    }
    OK(uc_close(uc));
}

static void test_x86_evex_vmovdqu64_zmm31_zmm20(void)
{
    static const uint8_t code[] = {
        0x62, 0x21, 0xfe, 0x48, 0x6f, 0xfc,
        /* vmovdqu64 zmm31, zmm20 */
    };
    const uint64_t source[8] = {
        UINT64_C(0x0102030405060708), UINT64_C(0x1112131415161718),
        UINT64_C(0x2122232425262728), UINT64_C(0x3132333435363738),
        UINT64_C(0x4142434445464748), UINT64_C(0x5152535455565758),
        UINT64_C(0x6162636465666768), UINT64_C(0x7172737475767778),
    };
    const uint64_t initial_destination[8] = {
        UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX,
        UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX,
    };
    const uint64_t initial_rflags = UINT64_C(0xcd7);
    uint64_t source_after[8] = {0};
    uint64_t destination[8];
    uint64_t rflags = initial_rflags;
    uint64_t rip = 0;
    uc_engine *uc;

    memcpy(destination, initial_destination, sizeof(destination));
    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM20, source));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, destination));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM20, source_after));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, destination));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    TEST_CHECK(memcmp(source, source_after, sizeof(source)) == 0);
    TEST_CHECK(memcmp(source, destination, sizeof(source)) == 0);
    TEST_CHECK(rflags == initial_rflags);
    TEST_CHECK(rip == code_start + sizeof(code));

    OK(uc_close(uc));
}

static void test_x86_evex_vmovdqu64_vector_length_zeroing(void)
{
    static const struct {
        uint8_t code[6];
        int copied_lanes;
        const char *mnemonic;
    } cases[] = {
        {{0x62, 0x21, 0xfe, 0x08, 0x6f, 0xfc}, 2,
         "VMOVDQU64 XMM31, XMM20"},
        {{0x62, 0x21, 0xfe, 0x28, 0x6f, 0xfc}, 4,
         "VMOVDQU64 YMM31, YMM20"},
    };
    const uint64_t source[8] = {
        UINT64_C(0x0102030405060708), UINT64_C(0x1112131415161718),
        UINT64_C(0x2122232425262728), UINT64_C(0x3132333435363738),
        UINT64_C(0x4142434445464748), UINT64_C(0x5152535455565758),
        UINT64_C(0x6162636465666768), UINT64_C(0x7172737475767778),
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t destination[8] = {
            UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX,
            UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX,
        };
        uint64_t source_after[8] = {0};
        uint64_t expected[8] = {0};
        uint64_t rflags = UINT64_C(0xcd7);
        uc_engine *uc;

        memcpy(expected, source, cases[i].copied_lanes * sizeof(uint64_t));
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            cases[i].code, sizeof(cases[i].code));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM20, source));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, destination));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        OK(uc_emu_start(uc, code_start,
                        code_start + sizeof(cases[i].code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM20, source_after));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, destination));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

        TEST_CHECK_(memcmp(expected, destination, sizeof(expected)) == 0,
                    "%s did not clear destination bits above VL",
                    cases[i].mnemonic);
        TEST_CHECK_(memcmp(source, source_after, sizeof(source)) == 0,
                    "%s changed its source", cases[i].mnemonic);
        TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS",
                    cases[i].mnemonic);
        OK(uc_close(uc));
    }
}

static void test_x86_evex_vmovdqu64_extension_bits(void)
{
    static const uint8_t code[] = {
        0x62, 0x01, 0xfe, 0x48, 0x6f, 0xfc,
        /* vmovdqu64 zmm31, zmm28: R/R'/B/X are all extended */
    };
    const uint64_t source[8] = {
        UINT64_C(0x8877665544332211), UINT64_C(0x8070605040302010),
        UINT64_C(0x78695a4b3c2d1e0f), UINT64_C(0xfedcba9876543210),
        UINT64_C(0x0011223344556677), UINT64_C(0x1021324354657687),
        UINT64_C(0x89abcdef01234567), UINT64_C(0x0f1e2d3c4b5a6978),
    };
    uint64_t destination[8] = {0};
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM28, source));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, destination));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ZMM31, destination));

    TEST_CHECK(memcmp(source, destination, sizeof(source)) == 0);
    OK(uc_close(uc));
}

static uint8_t evex_vmovdqu_p1(size_t element_bytes)
{
    switch (element_bytes) {
    case 1:
        return 0x7f; /* W0, F2 */
    case 2:
        return 0xff; /* W1, F2 */
    case 4:
        return 0x7e; /* W0, F3 */
    case 8:
        return 0xfe; /* W1, F3 */
    default:
        TEST_CHECK_(false, "invalid VMOVDQU element width %zu", element_bytes);
        return 0;
    }
}

static void test_x86_evex_vmovdqu_register_widths_masks_and_directions(void)
{
    static const size_t element_bytes_cases[] = {4, 8};
    static const size_t vector_bytes_cases[] = {16, 32, 64};
    size_t case_index = 0;

    for (size_t element_case = 0;
         element_case < sizeof(element_bytes_cases) /
                            sizeof(element_bytes_cases[0]);
         ++element_case) {
        const size_t element_bytes = element_bytes_cases[element_case];

        for (size_t vector_case = 0;
             vector_case < sizeof(vector_bytes_cases) /
                               sizeof(vector_bytes_cases[0]);
             ++vector_case) {
            const size_t vector_bytes = vector_bytes_cases[vector_case];
            const uint8_t ll = vector_bytes == 16 ? 0 :
                               vector_bytes == 32 ? 1 : 2;

            for (int store_opcode = 0; store_opcode <= 1; ++store_opcode) {
                for (int zeroing = 0; zeroing <= 1; ++zeroing, ++case_index) {
                    const int mask_reg = 1 + (int)(case_index % 7);
                    const uint64_t mask =
                        UINT64_C(0xd6b59a4e31c7285d) ^
                        (UINT64_C(0x1249249249249249) * case_index);
                    uint8_t code[] = {
                        0x62, 0x21, evex_vmovdqu_p1(element_bytes),
                        (uint8_t)((ll << 5) | 0x08 | mask_reg |
                                  (zeroing ? 0x80 : 0)),
                        (uint8_t)(store_opcode ? 0x7f : 0x6f), 0xfc,
                    };
                    uint8_t zmm20[64];
                    uint8_t zmm31[64];
                    uint8_t expected[64];
                    uint8_t source_after[64];
                    uint8_t *destination = store_opcode ? zmm20 : zmm31;
                    const uint8_t *source = store_opcode ? zmm31 : zmm20;
                    const uc_x86_reg destination_reg =
                        store_opcode ? UC_X86_REG_ZMM20 : UC_X86_REG_ZMM31;
                    const uc_x86_reg source_reg =
                        store_opcode ? UC_X86_REG_ZMM31 : UC_X86_REG_ZMM20;
                    uint64_t rflags = UINT64_C(0xcd7);
                    uc_engine *uc;

                    for (size_t i = 0; i < sizeof(zmm20); ++i) {
                        zmm20[i] = (uint8_t)(0x20 + i * 5);
                        zmm31[i] = (uint8_t)(0xd1 - i * 3);
                    }
                    memcpy(expected, destination, sizeof(expected));
                    for (size_t byte = 0; byte < vector_bytes;
                         byte += element_bytes) {
                        const size_t element = byte / element_bytes;

                        if ((mask >> element) & 1) {
                            memcpy(expected + byte, source + byte,
                                   element_bytes);
                        } else if (zeroing) {
                            memset(expected + byte, 0, element_bytes);
                        }
                    }
                    memset(expected + vector_bytes, 0,
                           sizeof(expected) - vector_bytes);

                    uc_common_setup_cpu(&uc, UC_MODE_64,
                                        UC_CPU_X86_ICELAKE_SERVER,
                                        code, sizeof(code));
                    OK(uc_reg_write(uc, UC_X86_REG_ZMM20, zmm20));
                    OK(uc_reg_write(uc, UC_X86_REG_ZMM31, zmm31));
                    OK(uc_reg_write(uc, UC_X86_REG_K0 + mask_reg, &mask));
                    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

                    OK(uc_emu_start(uc, code_start,
                                    code_start + sizeof(code), 0, 0));
                    OK(uc_reg_read(uc, destination_reg, destination));
                    OK(uc_reg_read(uc, source_reg, source_after));
                    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

                    TEST_CHECK_(memcmp(expected, destination,
                                       sizeof(expected)) == 0,
                                "VMOVDQU%zu VL%zu %02x K%d %s mismatch",
                                element_bytes * 8, vector_bytes * 8,
                                code[4], mask_reg,
                                zeroing ? "zero" : "merge");
                    TEST_CHECK_(memcmp(source, source_after,
                                       sizeof(source_after)) == 0,
                                "VMOVDQU%zu VL%zu %02x changed source",
                                element_bytes * 8, vector_bytes * 8,
                                code[4]);
                    TEST_CHECK_(rflags == UINT64_C(0xcd7),
                                "VMOVDQU%zu VL%zu %02x changed RFLAGS",
                                element_bytes * 8, vector_bytes * 8,
                                code[4]);
                    OK(uc_close(uc));
                }
            }
        }
    }
}

static void test_x86_evex_vmovdqu_memory_widths_masks_and_directions(void)
{
    static const size_t element_bytes_cases[] = {4, 8};
    static const size_t vector_bytes_cases[] = {16, 32, 64};
    const uint64_t data_address = code_start + 0x800;
    size_t case_index = 0;

    for (size_t element_case = 0;
         element_case < sizeof(element_bytes_cases) /
                            sizeof(element_bytes_cases[0]);
         ++element_case) {
        const size_t element_bytes = element_bytes_cases[element_case];

        for (size_t vector_case = 0;
             vector_case < sizeof(vector_bytes_cases) /
                               sizeof(vector_bytes_cases[0]);
             ++vector_case) {
            const size_t vector_bytes = vector_bytes_cases[vector_case];
            const uint8_t ll = vector_bytes == 16 ? 0 :
                               vector_bytes == 32 ? 1 : 2;

            for (int store = 0; store <= 1; ++store) {
                const int zeroing_cases = store ? 1 : 2;

                for (int zeroing = 0; zeroing < zeroing_cases;
                     ++zeroing, ++case_index) {
                    const int mask_reg = 1 + (int)(case_index % 7);
                    const uint64_t mask =
                        UINT64_C(0xa69c35e9714bd286) ^
                        (UINT64_C(0x0842108421084211) * case_index);
                    uint8_t code[11] = {
                        0x62,
                        (uint8_t)(store ? 0x81 : 0xe1),
                        evex_vmovdqu_p1(element_bytes),
                        (uint8_t)((ll << 5) | 0x08 | mask_reg |
                                  (zeroing ? 0x80 : 0)),
                        (uint8_t)(store ? 0x7f : 0x6f),
                        (uint8_t)(store ? 0x94 : 0x9c),
                        (uint8_t)(store ? 0x48 : 0x88),
                        (uint8_t)(store ? 0x10 : 0x20), 0x00, 0x00, 0x00,
                    };
                    uint8_t memory[64];
                    uint8_t initial_memory[64];
                    uint8_t vector[64];
                    uint8_t expected[64];
                    uint64_t base;
                    uint64_t index = 0x10;
                    uint64_t rflags = UINT64_C(0xcd7);
                    uc_engine *uc;

                    for (size_t i = 0; i < sizeof(memory); ++i) {
                        initial_memory[i] = (uint8_t)(0x17 + i * 7);
                        vector[i] = (uint8_t)(0xe3 - i * 5);
                    }
                    memcpy(memory, initial_memory, sizeof(memory));
                    memcpy(expected, store ? initial_memory : vector,
                           sizeof(expected));

                    for (size_t byte = 0; byte < vector_bytes;
                         byte += element_bytes) {
                        const size_t element = byte / element_bytes;

                        if ((mask >> element) & 1) {
                            memcpy(expected + byte,
                                   (store ? vector : initial_memory) + byte,
                                   element_bytes);
                        } else if (!store && zeroing) {
                            memset(expected + byte, 0, element_bytes);
                        }
                    }
                    if (!store) {
                        memset(expected + vector_bytes, 0,
                               sizeof(expected) - vector_bytes);
                    }

                    uc_common_setup_cpu(&uc, UC_MODE_64,
                                        UC_CPU_X86_ICELAKE_SERVER,
                                        code, sizeof(code));
                    OK(uc_mem_write(uc, data_address, initial_memory,
                                    sizeof(initial_memory)));
                    OK(uc_reg_write(uc, store ? UC_X86_REG_ZMM18
                                              : UC_X86_REG_ZMM19,
                                    vector));
                    OK(uc_reg_write(uc, UC_X86_REG_K0 + mask_reg, &mask));
                    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
                    if (store) {
                        base = data_address - 0x10 - index * 2;
                        OK(uc_reg_write(uc, UC_X86_REG_R8, &base));
                        OK(uc_reg_write(uc, UC_X86_REG_R9, &index));
                    } else {
                        base = data_address - 0x20 - index * 4;
                        OK(uc_reg_write(uc, UC_X86_REG_RAX, &base));
                        OK(uc_reg_write(uc, UC_X86_REG_RCX, &index));
                    }

                    OK(uc_emu_start(uc, code_start,
                                    code_start + sizeof(code), 0, 0));
                    OK(uc_mem_read(uc, data_address, memory, sizeof(memory)));
                    OK(uc_reg_read(uc, store ? UC_X86_REG_ZMM18
                                             : UC_X86_REG_ZMM19,
                                   vector));
                    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

                    TEST_CHECK_(memcmp(expected, store ? memory : vector,
                                       sizeof(expected)) == 0,
                                "VMOVDQU%zu VL%zu memory %s K%d %s mismatch",
                                element_bytes * 8, vector_bytes * 8,
                                store ? "store" : "load", mask_reg,
                                zeroing ? "zero" : "merge");
                    TEST_CHECK_(memcmp(store ? vector : memory,
                                       store ? vector : initial_memory,
                                       sizeof(memory)) == 0,
                                "VMOVDQU%zu VL%zu memory %s changed source",
                                element_bytes * 8, vector_bytes * 8,
                                store ? "store" : "load");
                    TEST_CHECK_(rflags == UINT64_C(0xcd7),
                                "VMOVDQU%zu VL%zu memory %s changed RFLAGS",
                                element_bytes * 8, vector_bytes * 8,
                                store ? "store" : "load");
                    OK(uc_close(uc));
                }
            }
        }
    }
}

static void test_x86_evex_vmovdqu_memory_addressing_forms(void)
{
    const uint64_t data_address = code_start + 0x1000;

    /* EVEX disp8 is compressed by the full-vector tuple size. */
    for (int ll = 0; ll < 3; ++ll) {
        const size_t vector_bytes = 16U << ll;
        uint8_t code[] = {
            0x62, 0xe1, evex_vmovdqu_p1(4),
            (uint8_t)((ll << 5) | 0x09), 0x6f, 0x58, 0x01,
        };
        uint8_t backing[128];
        uint8_t destination[64];
        uint8_t expected[64] = {0};
        uint64_t base = data_address - vector_bytes;
        uint64_t mask = UINT64_MAX;
        uc_engine *uc;

        for (size_t i = 0; i < sizeof(backing); ++i) {
            backing[i] = (uint8_t)(0x39 + i * 11);
        }
        memset(destination, 0xa5, sizeof(destination));
        memcpy(expected, backing + 64, vector_bytes);
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            code, sizeof(code));
        OK(uc_mem_write(uc, data_address - 64, backing, sizeof(backing)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &base));
        OK(uc_reg_write(uc, UC_X86_REG_K1, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM19, destination));

        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM19, destination));
        TEST_CHECK_(memcmp(expected, destination, sizeof(expected)) == 0,
                    "VMOVDQU compressed disp8 used the wrong VL%zu scale",
                    vector_bytes * 8);
        OK(uc_close(uc));
    }

    /* RIP-relative addressing uses the next instruction as its base. */
    {
        uint8_t code[] = {
            0x62, 0x61, 0xfe, 0x4a, 0x6f, 0x35,
            0, 0, 0, 0,
        };
        const int32_t displacement =
            (int32_t)(data_address - (code_start + sizeof(code)));
        uint8_t source[64];
        uint8_t destination[64] = {0};
        uint64_t mask = UINT64_MAX;
        uc_engine *uc;

        code[6] = (uint8_t)displacement;
        code[7] = (uint8_t)(displacement >> 8);
        code[8] = (uint8_t)(displacement >> 16);
        code[9] = (uint8_t)(displacement >> 24);
        for (size_t i = 0; i < sizeof(source); ++i) {
            source[i] = (uint8_t)(0xf1 - i * 9);
        }
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            code, sizeof(code));
        OK(uc_mem_write(uc, data_address, source, sizeof(source)));
        OK(uc_reg_write(uc, UC_X86_REG_K2, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM30, destination));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM30, destination));
        TEST_CHECK(memcmp(source, destination, sizeof(source)) == 0);
        OK(uc_close(uc));
    }

    /* Address-size override truncates base/index before applying disp8*N. */
    {
        static const uint8_t code[] = {
            0x67, 0x62, 0xe1, 0x7e, 0xab, 0x6f, 0x5c, 0x48, 0x01,
        };
        uint8_t source[32];
        uint8_t destination[64];
        uint8_t expected[64] = {0};
        uint64_t base = UINT64_C(0xfeed000000000000) |
                        (uint32_t)(data_address - 32 - 0x20);
        uint64_t index = UINT64_C(0xbeef000000000010);
        uint64_t mask = UINT64_MAX;
        uc_engine *uc;

        for (size_t i = 0; i < sizeof(source); ++i) {
            source[i] = (uint8_t)(0x42 + i * 13);
        }
        memset(destination, 0xcc, sizeof(destination));
        memcpy(expected, source, sizeof(source));
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            code, sizeof(code));
        OK(uc_mem_write(uc, data_address, source, sizeof(source)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &base));
        OK(uc_reg_write(uc, UC_X86_REG_RCX, &index));
        OK(uc_reg_write(uc, UC_X86_REG_K3, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM19, destination));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM19, destination));
        TEST_CHECK(memcmp(expected, destination, sizeof(expected)) == 0);
        OK(uc_close(uc));
    }

    /* FS override participates in effective address calculation for stores. */
    {
        static const uint8_t code[] = {
            0x64, 0x62, 0xe1, 0xfe, 0x4c, 0x7f, 0x50, 0x01,
        };
        uint8_t source[64];
        uint8_t memory[64];
        uint8_t expected[64];
        uint64_t rax = 0x80;
        uint64_t fs_base = data_address - rax - 64;
        uint64_t mask = UINT64_C(0x5a);
        uc_engine *uc;

        for (size_t i = 0; i < sizeof(source); ++i) {
            source[i] = (uint8_t)(0xb7 - i * 3);
            memory[i] = (uint8_t)(0x11 + i * 5);
        }
        memcpy(expected, memory, sizeof(expected));
        for (int lane = 0; lane < 8; ++lane) {
            if ((mask >> lane) & 1) {
                memcpy(expected + lane * 8, source + lane * 8, 8);
            }
        }
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            code, sizeof(code));
        OK(uc_mem_write(uc, data_address, memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM18, source));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_FS_BASE, &fs_base));
        OK(uc_reg_write(uc, UC_X86_REG_K4, &mask));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_mem_read(uc, data_address, memory, sizeof(memory)));
        TEST_CHECK(memcmp(expected, memory, sizeof(expected)) == 0);
        OK(uc_close(uc));
    }
}

static void test_x86_evex_vmovdqu_masked_memory_fault_atomicity(void)
{
    static const size_t element_bytes_cases[] = {4, 8};
    const uint64_t mapped_page = 0x10000;
    const uint64_t address = mapped_page + 0xff0;

    for (size_t width_case = 0;
         width_case < sizeof(element_bytes_cases) /
                          sizeof(element_bytes_cases[0]);
         ++width_case) {
        const size_t element_bytes = element_bytes_cases[width_case];
        const int mapped_elements = 16 / (int)element_bytes;
        const uint64_t suppress_mask = (UINT64_C(1) << mapped_elements) - 1;
        const uint64_t fault_mask = suppress_mask |
                                    (UINT64_C(1) << mapped_elements);
        uint8_t initial_memory[16];
        uint8_t source[64];
        uint8_t initial_destination[64];

        for (size_t i = 0; i < sizeof(initial_memory); ++i) {
            initial_memory[i] = (uint8_t)(0x23 + i * 7);
        }
        for (size_t i = 0; i < sizeof(source); ++i) {
            source[i] = (uint8_t)(0xf7 - i * 5);
            initial_destination[i] = (uint8_t)(0x51 + i * 3);
        }

        for (int zeroing = 0; zeroing <= 1; ++zeroing) {
            uint8_t code[] = {
                0x62, 0xe1, evex_vmovdqu_p1(element_bytes),
                (uint8_t)(0x49 | (zeroing ? 0x80 : 0)), 0x6f, 0x18,
            };
            uint8_t destination[64];
            uint8_t expected[64];
            uint64_t rax = address;
            uint64_t mask = suppress_mask;
            uc_engine *uc;

            memcpy(destination, initial_destination, sizeof(destination));
            memcpy(expected, initial_destination, sizeof(expected));
            memcpy(expected, initial_memory, sizeof(initial_memory));
            if (zeroing) {
                memset(expected + sizeof(initial_memory), 0,
                       sizeof(expected) - sizeof(initial_memory));
            }
            uc_common_setup_cpu(&uc, UC_MODE_64,
                                UC_CPU_X86_ICELAKE_SERVER,
                                code, sizeof(code));
            OK(uc_mem_map(uc, mapped_page, 0x1000,
                          UC_PROT_READ | UC_PROT_WRITE));
            OK(uc_mem_write(uc, address, initial_memory,
                            sizeof(initial_memory)));
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
            OK(uc_reg_write(uc, UC_X86_REG_K1, &mask));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM19, destination));

            OK(uc_emu_start(uc, code_start,
                            code_start + sizeof(code), 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_ZMM19, destination));
            TEST_CHECK_(memcmp(expected, destination, sizeof(expected)) == 0,
                        "masked VMOVDQU%zu load did not suppress fault (%s)",
                        element_bytes * 8, zeroing ? "zero" : "merge");
            OK(uc_close(uc));
        }

        {
            uint8_t code[] = {
                0x62, 0xe1, evex_vmovdqu_p1(element_bytes),
                0x49, 0x7f, 0x10,
            };
            uint8_t memory[16];
            uint64_t rax = address;
            uint64_t mask = suppress_mask;
            uc_engine *uc;

            uc_common_setup_cpu(&uc, UC_MODE_64,
                                UC_CPU_X86_ICELAKE_SERVER,
                                code, sizeof(code));
            OK(uc_mem_map(uc, mapped_page, 0x1000,
                          UC_PROT_READ | UC_PROT_WRITE));
            OK(uc_mem_write(uc, address, initial_memory,
                            sizeof(initial_memory)));
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
            OK(uc_reg_write(uc, UC_X86_REG_K1, &mask));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM18, source));

            OK(uc_emu_start(uc, code_start,
                            code_start + sizeof(code), 0, 0));
            OK(uc_mem_read(uc, address, memory, sizeof(memory)));
            TEST_CHECK_(memcmp(source, memory, sizeof(memory)) == 0,
                        "masked VMOVDQU%zu store did not suppress fault",
                        element_bytes * 8);
            OK(uc_close(uc));
        }

        {
            uint8_t code[] = {
                0x62, 0xe1, evex_vmovdqu_p1(element_bytes),
                0xc9, 0x6f, 0x18,
            };
            uint8_t destination[64];
            uint64_t rax = address;
            uint64_t mask = fault_mask;
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            memcpy(destination, initial_destination, sizeof(destination));
            uc_common_setup_cpu(&uc, UC_MODE_64,
                                UC_CPU_X86_ICELAKE_SERVER,
                                code, sizeof(code));
            OK(uc_mem_map(uc, mapped_page, 0x1000,
                          UC_PROT_READ | UC_PROT_WRITE));
            OK(uc_mem_write(uc, address, initial_memory,
                            sizeof(initial_memory)));
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
            OK(uc_reg_write(uc, UC_X86_REG_K1, &mask));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM19, destination));

            err = uc_emu_start(uc, code_start,
                               code_start + sizeof(code), 0, 0);
            OK(uc_reg_read(uc, UC_X86_REG_ZMM19, destination));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(err == UC_ERR_READ_UNMAPPED,
                        "active VMOVDQU%zu load lane returned %s",
                        element_bytes * 8, uc_strerror(err));
            TEST_CHECK_(memcmp(initial_destination, destination,
                               sizeof(destination)) == 0,
                        "faulting VMOVDQU%zu load changed destination",
                        element_bytes * 8);
            TEST_CHECK_(rip == code_start,
                        "faulting VMOVDQU%zu load left RIP at 0x%" PRIx64,
                        element_bytes * 8, rip);
            OK(uc_close(uc));
        }

        {
            uint8_t code[] = {
                0x62, 0xe1, evex_vmovdqu_p1(element_bytes),
                0x49, 0x7f, 0x10,
            };
            uint8_t memory[16];
            uint8_t source_after[64];
            uint64_t rax = address;
            uint64_t mask = fault_mask;
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            uc_common_setup_cpu(&uc, UC_MODE_64,
                                UC_CPU_X86_ICELAKE_SERVER,
                                code, sizeof(code));
            OK(uc_mem_map(uc, mapped_page, 0x1000,
                          UC_PROT_READ | UC_PROT_WRITE));
            OK(uc_mem_write(uc, address, initial_memory,
                            sizeof(initial_memory)));
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
            OK(uc_reg_write(uc, UC_X86_REG_K1, &mask));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM18, source));

            err = uc_emu_start(uc, code_start,
                               code_start + sizeof(code), 0, 0);
            OK(uc_mem_read(uc, address, memory, sizeof(memory)));
            OK(uc_reg_read(uc, UC_X86_REG_ZMM18, source_after));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(err == UC_ERR_WRITE_UNMAPPED,
                        "active VMOVDQU%zu store lane returned %s",
                        element_bytes * 8, uc_strerror(err));
            TEST_CHECK_(memcmp(initial_memory, memory, sizeof(memory)) == 0,
                        "faulting VMOVDQU%zu store partially changed memory",
                        element_bytes * 8);
            TEST_CHECK(memcmp(source, source_after, sizeof(source)) == 0);
            TEST_CHECK_(rip == code_start,
                        "faulting VMOVDQU%zu store left RIP at 0x%" PRIx64,
                        element_bytes * 8, rip);
            OK(uc_close(uc));
        }
    }
}

static void test_x86_evex_vmovdqu_invalid_forms(void)
{
    static const struct {
        uint8_t code[7];
        size_t code_size;
        const char *description;
    } cases[] = {
        {{0x62, 0x21, 0xfe, 0xc8, 0x6f, 0xfc}, 6,
         "EVEX.z without a mask"},
        {{0x62, 0x21, 0xfe, 0x58, 0x6f, 0xfc}, 6,
         "EVEX.b register form"},
        {{0x62, 0xe1, 0xfe, 0x58, 0x6f, 0x18}, 6,
         "EVEX.b memory form"},
        {{0x62, 0xe1, 0xfe, 0xc9, 0x7f, 0x20}, 6,
         "zero-masked memory store"},
        {{0x62, 0x21, 0xfe, 0x68, 0x6f, 0xfc}, 6,
         "reserved EVEX.LL=3"},
        {{0x62, 0x21, 0xf6, 0x48, 0x6f, 0xfc}, 6,
         "reserved vvvv"},
        {{0x62, 0x21, 0xfe, 0x40, 0x6f, 0xfc}, 6,
         "reserved V prime"},
        {{0x62, 0x21, 0xfa, 0x48, 0x6f, 0xfc}, 6,
         "clear EVEX P1 fixed bit"},
        {{0x62, 0x25, 0xfe, 0x48, 0x6f, 0xfc}, 6,
         "reserved EVEX P0 bit"},
        {{0x62, 0x22, 0xfe, 0x48, 0x6f, 0xfc}, 6,
         "unsupported opcode map"},
        {{0x62, 0x21, 0xfc, 0x48, 0x6f, 0xfc}, 6,
         "missing mandatory prefix"},
        {{0x62, 0x21, 0xfe, 0x48, 0x6e, 0xfc}, 6,
         "unsupported opcode"},
        {{0x48, 0x62, 0x21, 0xfe, 0x48, 0x6f, 0xfc}, 7,
         "preceding REX"},
        {{0x66, 0x62, 0x21, 0xfe, 0x48, 0x6f, 0xfc}, 7,
         "preceding operand-size prefix"},
        {{0xf2, 0x62, 0x21, 0xfe, 0x48, 0x6f, 0xfc}, 7,
         "preceding REPNE prefix"},
        {{0xf3, 0x62, 0x21, 0xfe, 0x48, 0x6f, 0xfc}, 7,
         "preceding REP prefix"},
        {{0xf0, 0x62, 0x21, 0xfe, 0x48, 0x6f, 0xfc}, 7,
         "preceding LOCK prefix"},
    };
    const uint64_t initial_zmm20[8] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    };
    const uint64_t initial_zmm31[8] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    };
    const uint64_t initial_k1 = UINT64_C(0x0123456789abcdef);
    const uint64_t initial_memory = UINT64_C(0xfedcba9876543210);
    const uint64_t initial_rflags = UINT64_C(0xcd7);
    const uint64_t data_address = code_start + 0x300;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t zmm20[8];
        uint64_t zmm31[8];
        uint64_t k1 = initial_k1;
        uint64_t rax = data_address;
        uint64_t memory = initial_memory;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        memcpy(zmm20, initial_zmm20, sizeof(zmm20));
        memcpy(zmm31, initial_zmm31, sizeof(zmm31));
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            cases[i].code, cases[i].code_size);
        OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM20, zmm20));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, zmm31));
        OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err = uc_emu_start(uc, code_start,
                           code_start + cases[i].code_size, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM20, zmm20));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, zmm31));
        OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_mem_read(uc, data_address, &memory, sizeof(memory)));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    cases[i].description);
        TEST_CHECK_(memcmp(zmm20, initial_zmm20, sizeof(zmm20)) == 0 &&
                        memcmp(zmm31, initial_zmm31, sizeof(zmm31)) == 0,
                    "%s changed vector state", cases[i].description);
        TEST_CHECK_(k1 == initial_k1, "%s changed mask state",
                    cases[i].description);
        TEST_CHECK_(rax == data_address, "%s changed GPR state",
                    cases[i].description);
        TEST_CHECK_(memory == initial_memory, "%s changed memory",
                    cases[i].description);
        TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                    cases[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP", cases[i].description);
        OK(uc_close(uc));
    }
}

static uint64_t test_x86_evex_load_lane(const uint8_t *bytes,
                                        size_t element_bytes)
{
    uint64_t value = 0;

    memcpy(&value, bytes, element_bytes);
    return value;
}

static void test_x86_evex_store_lane(uint8_t *bytes, size_t element_bytes,
                                     uint64_t value)
{
    memcpy(bytes, &value, element_bytes);
}

static void test_x86_evex_vpadd_vpsub_register_semantics(void)
{
    static const struct {
        uint8_t opcode;
        size_t element_bytes;
        bool subtract;
        bool w;
        const char *name;
    } operations[] = {
        {0xfe, 4, false, false, "VPADDD"},
        {0xd4, 8, false, true, "VPADDQ"},
        {0xfa, 4, true, false, "VPSUBD"},
        {0xfb, 8, true, true, "VPSUBQ"},
    };
    static const size_t vector_bytes_cases[] = {16, 32, 64};
    size_t case_index = 0;

    for (size_t operation = 0;
         operation < sizeof(operations) / sizeof(operations[0]);
         ++operation) {
        const size_t element_bytes = operations[operation].element_bytes;

        for (size_t vector_case = 0;
             vector_case < sizeof(vector_bytes_cases) /
                               sizeof(vector_bytes_cases[0]);
             ++vector_case) {
            const size_t vector_bytes = vector_bytes_cases[vector_case];
            const uint8_t ll = vector_bytes == 16 ? 0 :
                               vector_bytes == 32 ? 1 : 2;

            for (int mask_mode = 0; mask_mode < 3;
                 ++mask_mode, ++case_index) {
                const bool high_registers = (case_index & 1) != 0;
                const int mask_reg = mask_mode ? 1 + (case_index % 7) : 0;
                const bool zeroing = mask_mode == 2;
                const bool w = operations[operation].w ||
                               (element_bytes <= 2 && (case_index & 1));
                const uc_x86_reg source1_reg = high_registers
                                                   ? UC_X86_REG_ZMM29
                                                   : UC_X86_REG_ZMM5;
                const uc_x86_reg source2_reg = high_registers
                                                   ? UC_X86_REG_ZMM28
                                                   : UC_X86_REG_ZMM4;
                const uc_x86_reg destination_reg = high_registers
                                                       ? UC_X86_REG_ZMM31
                                                       : UC_X86_REG_ZMM7;
                const uint64_t mask = UINT64_C(0xb6d39ac571e84f2d) ^
                                      (case_index *
                                       UINT64_C(0x1249249249249249));
                uint8_t code[] = {
                    0x62, (uint8_t)(high_registers ? 0x01 : 0xf1),
                    (uint8_t)((high_registers ? 0x15 : 0x55) |
                              (w ? 0x80 : 0)),
                    (uint8_t)((ll << 5) | (high_registers ? 0 : 0x08) |
                              mask_reg |
                              (zeroing ? 0x80 : 0)),
                    operations[operation].opcode, 0xfc,
                };
                uint8_t source1[64];
                uint8_t source2[64];
                uint8_t source1_after[64];
                uint8_t source2_after[64];
                uint8_t destination[64];
                uint8_t expected[64];
                uint64_t rflags = UINT64_C(0xcd7);
                uint64_t rip = 0;
                uc_engine *uc;

                for (size_t byte = 0; byte < sizeof(source1); ++byte) {
                    source1[byte] = (uint8_t)(0xe3 - byte * 7 - operation);
                    source2[byte] = (uint8_t)(0x19 + byte * 11 + vector_case);
                    destination[byte] =
                        (uint8_t)(0x81 ^ byte ^ (case_index * 3));
                }
                memcpy(expected, destination, sizeof(expected));
                for (size_t byte = 0; byte < vector_bytes;
                     byte += element_bytes) {
                    const size_t lane = byte / element_bytes;

                    if (!mask_reg || ((mask >> lane) & 1)) {
                        const uint64_t left = test_x86_evex_load_lane(
                            source1 + byte, element_bytes);
                        const uint64_t right = test_x86_evex_load_lane(
                            source2 + byte, element_bytes);
                        const uint64_t value = operations[operation].subtract
                                                   ? left - right
                                                   : left + right;

                        test_x86_evex_store_lane(expected + byte,
                                                 element_bytes, value);
                    } else if (zeroing) {
                        memset(expected + byte, 0, element_bytes);
                    }
                }
                memset(expected + vector_bytes, 0,
                       sizeof(expected) - vector_bytes);

                uc_common_setup_cpu(&uc, UC_MODE_64,
                                    UC_CPU_X86_ICELAKE_SERVER,
                                    code, sizeof(code));
                OK(uc_reg_write(uc, source1_reg, source1));
                OK(uc_reg_write(uc, source2_reg, source2));
                OK(uc_reg_write(uc, destination_reg, destination));
                if (mask_reg) {
                    OK(uc_reg_write(uc, UC_X86_REG_K0 + mask_reg, &mask));
                }
                OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

                OK(uc_emu_start(uc, code_start,
                                code_start + sizeof(code), 0, 0));
                OK(uc_reg_read(uc, source1_reg, source1_after));
                OK(uc_reg_read(uc, source2_reg, source2_after));
                OK(uc_reg_read(uc, destination_reg, destination));
                OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
                OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

                TEST_CHECK_(memcmp(destination, expected,
                                   sizeof(expected)) == 0,
                            "%s VL%zu K%d %s mismatch",
                            operations[operation].name, vector_bytes * 8,
                            mask_reg, zeroing ? "zero" : "merge");
                TEST_CHECK_(memcmp(source1, source1_after,
                                   sizeof(source1)) == 0,
                            "%s changed its first source",
                            operations[operation].name);
                TEST_CHECK_(memcmp(source2, source2_after,
                                   sizeof(source2)) == 0,
                            "%s changed its second source",
                            operations[operation].name);
                TEST_CHECK_(rflags == UINT64_C(0xcd7),
                            "%s changed RFLAGS", operations[operation].name);
                TEST_CHECK_(rip == code_start + sizeof(code),
                            "%s did not advance RIP",
                            operations[operation].name);
                OK(uc_close(uc));
            }
        }
    }
}

static void test_x86_evex_vpadd_vpsub_invalid_forms(void)
{
    static const struct {
        uint8_t code[7];
        size_t code_size;
        const char *description;
    } cases[] = {
        {{0x62, 0x61, 0x55, 0x40, 0xfe, 0x38}, 6,
         "VPADDD memory source"},
        {{0x62, 0x61, 0x55, 0x50, 0xfe, 0x38}, 6,
         "VPADDD broadcast source"},
        {{0x62, 0x21, 0x55, 0x50, 0xfe, 0xfc}, 6,
         "EVEX.b register form"},
        {{0x62, 0x21, 0x55, 0x60, 0xfe, 0xfc}, 6,
         "reserved EVEX.LL=3"},
        {{0x62, 0x21, 0x55, 0xc0, 0xfe, 0xfc}, 6,
         "EVEX.z without a mask"},
        {{0x62, 0x21, 0x57, 0x40, 0xfe, 0xfc}, 6,
         "wrong mandatory prefix"},
        {{0x62, 0x21, 0x51, 0x40, 0xfe, 0xfc}, 6,
         "clear EVEX P1 fixed bit"},
        {{0x62, 0x25, 0x55, 0x40, 0xfe, 0xfc}, 6,
         "reserved EVEX P0 bit"},
        {{0x62, 0x22, 0x55, 0x40, 0xfe, 0xfc}, 6,
         "unsupported opcode map"},
        {{0x62, 0x21, 0xd5, 0x40, 0xfe, 0xfc}, 6,
         "VPADDD with W1"},
        {{0x62, 0x21, 0x55, 0x40, 0xd4, 0xfc}, 6,
         "VPADDQ with W0"},
        {{0x48, 0x62, 0x21, 0x55, 0x40, 0xfe, 0xfc}, 7,
         "preceding REX"},
        {{0x66, 0x62, 0x21, 0x55, 0x40, 0xfe, 0xfc}, 7,
         "preceding operand-size prefix"},
        {{0xf2, 0x62, 0x21, 0x55, 0x40, 0xfe, 0xfc}, 7,
         "preceding REPNE prefix"},
        {{0xf3, 0x62, 0x21, 0x55, 0x40, 0xfe, 0xfc}, 7,
         "preceding REP prefix"},
        {{0xf0, 0x62, 0x21, 0x55, 0x40, 0xfe, 0xfc}, 7,
         "preceding LOCK prefix"},
    };
    const uint64_t initial_source1[8] = {
        0x211, 0x212, 0x213, 0x214, 0x215, 0x216, 0x217, 0x218,
    };
    const uint64_t initial_source2[8] = {
        0x201, 0x202, 0x203, 0x204, 0x205, 0x206, 0x207, 0x208,
    };
    const uint64_t initial_destination[8] = {
        0x311, 0x312, 0x313, 0x314, 0x315, 0x316, 0x317, 0x318,
    };
    const uint64_t initial_k5 = UINT64_C(0x0123456789abcdef);
    const uint64_t initial_memory = UINT64_C(0xfedcba9876543210);
    const uint64_t initial_rflags = UINT64_C(0xcd7);
    const uint64_t data_address = code_start + 0x300;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t source1[8];
        uint64_t source2[8];
        uint64_t destination[8];
        uint64_t k5 = initial_k5;
        uint64_t rax = data_address;
        uint64_t memory = initial_memory;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        memcpy(source1, initial_source1, sizeof(source1));
        memcpy(source2, initial_source2, sizeof(source2));
        memcpy(destination, initial_destination, sizeof(destination));
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            cases[i].code, cases[i].code_size);
        OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM21, source1));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM20, source2));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, destination));
        OK(uc_reg_write(uc, UC_X86_REG_K5, &k5));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err = uc_emu_start(uc, code_start,
                           code_start + cases[i].code_size, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM21, source1));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM20, source2));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, destination));
        OK(uc_reg_read(uc, UC_X86_REG_K5, &k5));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_mem_read(uc, data_address, &memory, sizeof(memory)));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    cases[i].description);
        TEST_CHECK_(memcmp(source1, initial_source1, sizeof(source1)) == 0 &&
                        memcmp(source2, initial_source2, sizeof(source2)) == 0 &&
                        memcmp(destination, initial_destination,
                               sizeof(destination)) == 0,
                    "%s changed vector state", cases[i].description);
        TEST_CHECK_(k5 == initial_k5, "%s changed mask state",
                    cases[i].description);
        TEST_CHECK_(rax == data_address, "%s changed GPR state",
                    cases[i].description);
        TEST_CHECK_(memory == initial_memory, "%s changed memory",
                    cases[i].description);
        TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                    cases[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP", cases[i].description);
        OK(uc_close(uc));
    }
}

static int64_t test_x86_evex_signed_lane(uint64_t value, size_t element_bytes)
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
        TEST_CHECK_(false, "invalid VPCMP element width %zu", element_bytes);
        return 0;
    }
}

static bool test_x86_evex_compare_lane(uint64_t left, uint64_t right,
                                       size_t element_bytes,
                                       bool unsigned_compare,
                                       unsigned predicate)
{
    bool equal = left == right;
    bool less;

    if (unsigned_compare) {
        less = left < right;
    } else {
        less = test_x86_evex_signed_lane(left, element_bytes) <
               test_x86_evex_signed_lane(right, element_bytes);
    }

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
        TEST_CHECK_(false, "invalid VPCMP predicate %u", predicate);
        return false;
    }
}

static void test_x86_evex_vpcmp_register_semantics(void)
{
    static const struct {
        uint8_t opcode;
        size_t element_bytes;
        bool unsigned_compare;
        const char *name;
    } operations[] = {
        {0x1f, 4, false, "VPCMPD"}, {0x1f, 8, false, "VPCMPQ"},
        {0x1e, 4, true, "VPCMPUD"}, {0x1e, 8, true, "VPCMPUQ"},
    };
    static const size_t vector_bytes_cases[] = {16, 32, 64};

    for (size_t operation = 0;
         operation < sizeof(operations) / sizeof(operations[0]); ++operation) {
        const size_t element_bytes = operations[operation].element_bytes;
        const uint64_t lane_mask =
            element_bytes == 8 ? UINT64_MAX
                               : (UINT64_C(1) << (element_bytes * 8)) - 1;
        const uint64_t sign_bit = UINT64_C(1) << (element_bytes * 8 - 1);

        for (size_t vector_case = 0;
             vector_case <
             sizeof(vector_bytes_cases) / sizeof(vector_bytes_cases[0]);
             ++vector_case) {
            const size_t vector_bytes = vector_bytes_cases[vector_case];
            const size_t lane_count = vector_bytes / element_bytes;
            const uint8_t ll = vector_bytes == 16   ? 0
                               : vector_bytes == 32 ? 1
                                                    : 2;

            for (unsigned predicate = 0; predicate < 8; ++predicate) {
                for (int masked = 0; masked <= 1; ++masked) {
                    const bool high_registers =
                        ((operation + vector_case + predicate + masked) & 1) !=
                        0;
                    const int mask_reg = masked ? 3 : 0;
                    const uint64_t source_mask = UINT64_C(0xb6d39ac571e84f2d);
                    const uc_x86_reg source1_reg =
                        high_registers ? UC_X86_REG_ZMM21 : UC_X86_REG_ZMM5;
                    const uc_x86_reg source2_reg =
                        high_registers ? UC_X86_REG_ZMM20 : UC_X86_REG_ZMM4;
                    uint8_t code[] = {
                        0x62,
                        (uint8_t)(high_registers ? 0xb3 : 0xf3),
                        (uint8_t)(0x55 |
                                  (element_bytes == 2 || element_bytes == 8
                                       ? 0x80
                                       : 0)),
                        (uint8_t)((ll << 5) | (high_registers ? 0 : 0x08) |
                                  mask_reg),
                        operations[operation].opcode,
                        0xec,
                        (uint8_t)predicate,
                    };
                    uint8_t source1[64] = {0};
                    uint8_t source2[64] = {0};
                    uint8_t source1_after[64];
                    uint8_t source2_after[64];
                    uint64_t expected = 0;
                    uint64_t destination = UINT64_C(0xfedcba9876543210);
                    uint64_t observed_mask = source_mask;
                    uint64_t rflags = UINT64_C(0xcd7);
                    uint64_t rip = 0;
                    uc_engine *uc;

                    for (size_t lane = 0; lane < lane_count; ++lane) {
                        uint64_t left;
                        uint64_t right;

                        switch (lane & 7) {
                        case 0:
                            left = right = 0;
                            break;
                        case 1:
                            left = 1;
                            right = 2;
                            break;
                        case 2:
                            left = 3;
                            right = 2;
                            break;
                        case 3:
                            left = sign_bit;
                            right = 0;
                            break;
                        case 4:
                            left = 0;
                            right = sign_bit;
                            break;
                        case 5:
                            left = lane_mask;
                            right = 0;
                            break;
                        case 6:
                            left = 0;
                            right = lane_mask;
                            break;
                        default:
                            left = right = lane_mask;
                            break;
                        }
                        test_x86_evex_store_lane(source1 + lane * element_bytes,
                                                 element_bytes, left);
                        test_x86_evex_store_lane(source2 + lane * element_bytes,
                                                 element_bytes, right);
                        if (test_x86_evex_compare_lane(
                                left, right, element_bytes,
                                operations[operation].unsigned_compare,
                                predicate)) {
                            expected |= UINT64_C(1) << lane;
                        }
                    }
                    if (masked) {
                        expected &= source_mask;
                    }

                    uc_common_setup_cpu(&uc, UC_MODE_64,
                                        UC_CPU_X86_ICELAKE_SERVER,
                                        code, sizeof(code));
                    OK(uc_reg_write(uc, source1_reg, source1));
                    OK(uc_reg_write(uc, source2_reg, source2));
                    OK(uc_reg_write(uc, UC_X86_REG_K5, &destination));
                    if (masked) {
                        OK(uc_reg_write(uc, UC_X86_REG_K3, &source_mask));
                    }
                    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

                    OK(uc_emu_start(uc, code_start, code_start + sizeof(code),
                                    0, 0));
                    OK(uc_reg_read(uc, source1_reg, source1_after));
                    OK(uc_reg_read(uc, source2_reg, source2_after));
                    OK(uc_reg_read(uc, UC_X86_REG_K5, &destination));
                    if (masked) {
                        OK(uc_reg_read(uc, UC_X86_REG_K3, &observed_mask));
                    }
                    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
                    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

                    TEST_CHECK_(destination == expected,
                                "%s VL%zu predicate %u K%d expected "
                                "0x%" PRIx64 ", got 0x%" PRIx64,
                                operations[operation].name, vector_bytes * 8,
                                predicate, mask_reg, expected, destination);
                    TEST_CHECK_(
                        memcmp(source1, source1_after, sizeof(source1)) == 0 &&
                            memcmp(source2, source2_after, sizeof(source2)) ==
                                0,
                        "%s changed a vector source",
                        operations[operation].name);
                    TEST_CHECK_(observed_mask == source_mask,
                                "%s changed its K writemask source",
                                operations[operation].name);
                    TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS",
                                operations[operation].name);
                    TEST_CHECK_(rip == code_start + sizeof(code),
                                "%s did not advance RIP",
                                operations[operation].name);
                    OK(uc_close(uc));
                }
            }
        }
    }
}

static void test_x86_evex_vpcmp_invalid_forms(void)
{
    static const struct {
        uint8_t code[8];
        size_t code_size;
        const char *description;
    } cases[] = {
        {{0x62, 0xf3, 0x55, 0x40, 0x1f, 0x28, 0x02}, 7, "memory source"},
        {{0x62, 0xf3, 0x55, 0x50, 0x1f, 0x28, 0x02},
         7,
         "broadcast memory source"},
        {{0x62, 0xb3, 0x55, 0x50, 0x1f, 0xec, 0x02}, 7, "EVEX.b register form"},
        {{0x62, 0xb3, 0x55, 0x60, 0x1f, 0xec, 0x02}, 7, "reserved EVEX.LL=3"},
        {{0x62, 0xb3, 0x55, 0xc3, 0x1f, 0xec, 0x02},
         7,
         "EVEX.z mask destination"},
        {{0x62, 0xb3, 0x57, 0x40, 0x1f, 0xec, 0x02},
         7,
         "wrong mandatory prefix"},
        {{0x62, 0xb3, 0x51, 0x40, 0x1f, 0xec, 0x02},
         7,
         "clear EVEX P1 fixed bit"},
        {{0x62, 0xb7, 0x55, 0x40, 0x1f, 0xec, 0x02}, 7, "reserved EVEX P0 bit"},
        {{0x62, 0xb1, 0x55, 0x40, 0x1f, 0xec, 0x02}, 7, "wrong opcode map"},
        {{0x62, 0x33, 0x55, 0x40, 0x1f, 0xec, 0x02},
         7,
         "extended mask destination"},
        {{0x62, 0xb3, 0x55, 0x40, 0x1d, 0xec, 0x02}, 7, "unsupported opcode"},
        {{0x62, 0xb3, 0x55, 0x40, 0x1f, 0xec, 0x82},
         7,
         "reserved predicate bits"},
        {{0x48, 0x62, 0xb3, 0x55, 0x40, 0x1f, 0xec, 0x02}, 8, "preceding REX"},
        {{0x66, 0x62, 0xb3, 0x55, 0x40, 0x1f, 0xec, 0x02},
         8,
         "preceding operand-size prefix"},
        {{0xf2, 0x62, 0xb3, 0x55, 0x40, 0x1f, 0xec, 0x02},
         8,
         "preceding REPNE prefix"},
        {{0xf3, 0x62, 0xb3, 0x55, 0x40, 0x1f, 0xec, 0x02},
         8,
         "preceding REP prefix"},
        {{0xf0, 0x62, 0xb3, 0x55, 0x40, 0x1f, 0xec, 0x02},
         8,
         "preceding LOCK prefix"},
    };
    const uint64_t initial_source1[8] = {
        0x211, 0x212, 0x213, 0x214, 0x215, 0x216, 0x217, 0x218,
    };
    const uint64_t initial_source2[8] = {
        0x201, 0x202, 0x203, 0x204, 0x205, 0x206, 0x207, 0x208,
    };
    const uint64_t initial_k3 = UINT64_C(0xb6d39ac571e84f2d);
    const uint64_t initial_k5 = UINT64_C(0x0123456789abcdef);
    const uint64_t initial_memory = UINT64_C(0xfedcba9876543210);
    const uint64_t initial_rflags = UINT64_C(0xcd7);
    const uint64_t data_address = code_start + 0x300;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t source1[8];
        uint64_t source2[8];
        uint64_t k3 = initial_k3;
        uint64_t k5 = initial_k5;
        uint64_t rax = data_address;
        uint64_t memory = initial_memory;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        memcpy(source1, initial_source1, sizeof(source1));
        memcpy(source2, initial_source2, sizeof(source2));
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            cases[i].code, cases[i].code_size);
        OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM21, source1));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM20, source2));
        OK(uc_reg_write(uc, UC_X86_REG_K3, &k3));
        OK(uc_reg_write(uc, UC_X86_REG_K5, &k5));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err =
            uc_emu_start(uc, code_start, code_start + cases[i].code_size, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM21, source1));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM20, source2));
        OK(uc_reg_read(uc, UC_X86_REG_K3, &k3));
        OK(uc_reg_read(uc, UC_X86_REG_K5, &k5));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_mem_read(uc, data_address, &memory, sizeof(memory)));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    cases[i].description);
        TEST_CHECK_(memcmp(source1, initial_source1, sizeof(source1)) == 0 &&
                        memcmp(source2, initial_source2, sizeof(source2)) == 0,
                    "%s changed vector state", cases[i].description);
        TEST_CHECK_(k3 == initial_k3 && k5 == initial_k5,
                    "%s changed opmask state", cases[i].description);
        TEST_CHECK_(rax == data_address, "%s changed GPR state",
                    cases[i].description);
        TEST_CHECK_(memory == initial_memory, "%s changed memory",
                    cases[i].description);
        TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                    cases[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP", cases[i].description);
        OK(uc_close(uc));
    }
}

typedef struct TestX86EvexCompressExpandOp {
    const char *name;
    uint8_t opcode;
    uint8_t element_bytes;
    bool w;
    bool expand;
} TestX86EvexCompressExpandOp;

static void test_x86_evex_compress_expand_expected(
    uint8_t expected[64], const uint8_t initial_destination[64],
    const uint8_t source[64], size_t vector_bytes, size_t element_bytes,
    uint64_t mask, bool zeroing, bool expand)
{
    const size_t element_count = vector_bytes / element_bytes;
    size_t packed = 0;

    memcpy(expected, initial_destination, 64);
    if (expand) {
        for (size_t output = 0; output < element_count; ++output) {
            if ((mask >> output) & 1) {
                memcpy(expected + output * element_bytes,
                       source + packed * element_bytes, element_bytes);
                ++packed;
            } else if (zeroing) {
                memset(expected + output * element_bytes, 0, element_bytes);
            }
        }
    } else {
        for (size_t input = 0; input < element_count; ++input) {
            if ((mask >> input) & 1) {
                memcpy(expected + packed * element_bytes,
                       source + input * element_bytes, element_bytes);
                ++packed;
            }
        }
        if (zeroing) {
            memset(expected + packed * element_bytes, 0,
                   vector_bytes - packed * element_bytes);
        }
    }
    memset(expected + vector_bytes, 0, 64 - vector_bytes);
}

static bool test_x86_evex_run_compress_expand_register(
    const TestX86EvexCompressExpandOp *operation, size_t vector_bytes,
    int mask_reg, bool zeroing, bool alias)
{
    const int ll = vector_bytes == 16 ? 0 : vector_bytes == 32 ? 1 : 2;
    const int destination_index = alias ? 29 : 31;
    const int source_index = alias ? 29 : 30;
    const uint8_t modrm = operation->expand
                              ? (uint8_t)(0xc0 | ((destination_index & 7) << 3) |
                                          (source_index & 7))
                              : (uint8_t)(0xc0 | ((source_index & 7) << 3) |
                                          (destination_index & 7));
    const uint8_t code[] = {
        0x62,
        0x02,
        (uint8_t)(0x7d | (operation->w ? 0x80 : 0)),
        (uint8_t)((ll << 5) | 0x08 | mask_reg | (zeroing ? 0x80 : 0)),
        operation->opcode,
        modrm,
    };
    const uint64_t mask_value = UINT64_C(0xd6a59c3e71b4a5ad);
    const uint64_t effective_mask = mask_reg ? mask_value : UINT64_MAX;
    uint8_t initial_destination[64];
    uint8_t source[64];
    uint8_t source_after[64];
    uint8_t destination[64];
    uint8_t expected[64];
    uint64_t observed_mask = mask_value;
    uint64_t rflags = UINT64_C(0xcd7);
    uint64_t rip = 0;
    uc_engine *uc;
    uc_err err;
    bool passed;

    for (size_t i = 0; i < 64; ++i) {
        initial_destination[i] = (uint8_t)(0x91 + i * 13);
        source[i] = (uint8_t)(0x27 + i * 29);
    }
    if (alias) {
        memcpy(initial_destination, source, sizeof(initial_destination));
    }
    test_x86_evex_compress_expand_expected(
        expected, initial_destination, source, vector_bytes,
        operation->element_bytes, effective_mask, zeroing, operation->expand);

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER, code,
                        sizeof(code));
    if (alias) {
        OK(uc_reg_write(uc, UC_X86_REG_ZMM29, source));
    } else {
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial_destination));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source));
    }
    if (mask_reg) {
        OK(uc_reg_write(uc, UC_X86_REG_K0 + mask_reg, &observed_mask));
    }
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    if (!TEST_CHECK_(err == UC_ERR_OK,
                     "%s VL%zu K%d %s%s did not execute: %s",
                     operation->name, vector_bytes * 8, mask_reg,
                     zeroing ? "zero" : "merge", alias ? " alias" : "",
                     uc_strerror(err))) {
        OK(uc_close(uc));
        return false;
    }

    OK(uc_reg_read(uc, alias ? UC_X86_REG_ZMM29 : UC_X86_REG_ZMM31,
                   destination));
    if (alias) {
        memcpy(source_after, source, sizeof(source_after));
    } else {
        OK(uc_reg_read(uc, UC_X86_REG_ZMM30, source_after));
    }
    if (mask_reg) {
        OK(uc_reg_read(uc, UC_X86_REG_K0 + mask_reg, &observed_mask));
    }
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    passed = TEST_CHECK_(memcmp(destination, expected, sizeof(expected)) == 0,
                         "%s VL%zu K%d %s%s result mismatch",
                         operation->name, vector_bytes * 8, mask_reg,
                         zeroing ? "zero" : "merge",
                         alias ? " alias" : "");
    if (!alias) {
        passed &= TEST_CHECK_(memcmp(source_after, source, sizeof(source)) == 0,
                              "%s changed its source register",
                              operation->name);
    }
    if (mask_reg) {
        passed &= TEST_CHECK_(observed_mask == mask_value,
                              "%s changed its writemask", operation->name);
    }
    passed &= TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS",
                          operation->name);
    passed &= TEST_CHECK_(rip == code_start + sizeof(code),
                          "%s advanced RIP incorrectly", operation->name);
    OK(uc_close(uc));
    return passed;
}

static void test_x86_evex_compress_expand_register_forms(void)
{
    static const TestX86EvexCompressExpandOp operations[] = {
        {"VPCOMPRESSD", 0x8b, 4, false, false},
        {"VPCOMPRESSQ", 0x8b, 8, true, false},
        {"VCOMPRESSPS", 0x8a, 4, false, false},
        {"VCOMPRESSPD", 0x8a, 8, true, false},
        {"VPEXPANDD", 0x89, 4, false, true},
        {"VPEXPANDQ", 0x89, 8, true, true},
        {"VEXPANDPS", 0x88, 4, false, true},
        {"VEXPANDPD", 0x88, 8, true, true},
    };
    static const size_t vector_bytes_cases[] = {16, 32, 64};

    for (size_t operation = 0;
         operation < sizeof(operations) / sizeof(operations[0]);
         ++operation) {
        for (size_t vector_case = 0;
             vector_case < sizeof(vector_bytes_cases) /
                               sizeof(vector_bytes_cases[0]);
             ++vector_case) {
            for (int mask_mode = 0; mask_mode < 3; ++mask_mode) {
                const int mask_reg = mask_mode ? 7 : 0;
                const bool zeroing = mask_mode == 2;

                if (!test_x86_evex_run_compress_expand_register(
                        &operations[operation],
                        vector_bytes_cases[vector_case], mask_reg, zeroing,
                        false)) {
                    return;
                }
            }
        }
    }

    TEST_CHECK(test_x86_evex_run_compress_expand_register(
        &operations[0], 64, 7, false, true));
    TEST_CHECK(test_x86_evex_run_compress_expand_register(
        &operations[5], 64, 7, true, true));

    /* Reserved encodings must fail before changing architectural state. */
    {
        static const struct {
            uint8_t code[6];
            const char *description;
        } invalid_cases[] = {
            {{0x62, 0xf2, 0x7d, 0xcf, 0x8b, 0x10},
             "zeroing memory compress"},
            {{0x62, 0xf2, 0x7d, 0xc8, 0x89, 0xca}, "zeroing without mask"},
            {{0x62, 0xf2, 0x7d, 0x5f, 0x89, 0xca}, "reserved EVEX.b"},
            {{0x62, 0xf2, 0x7d, 0x6f, 0x89, 0xca}, "reserved EVEX.LL"},
            {{0x62, 0xf2, 0x75, 0x4f, 0x89, 0xca}, "reserved EVEX.vvvv"},
            {{0x62, 0xf2, 0x7d, 0x47, 0x89, 0xca}, "reserved EVEX.V'"},
        };
        const uint64_t data_address = code_start + 0x800;
        const uint64_t initial_memory = UINT64_C(0x123456789abcdef0);

        for (size_t i = 0;
             i < sizeof(invalid_cases) / sizeof(invalid_cases[0]); ++i) {
            uint8_t destination[64];
            uint8_t destination_after[64];
            uint8_t source[64];
            uint64_t mask = UINT64_C(0xd6a59c3e71b4a5ad);
            uint64_t rax = data_address;
            uint64_t memory = initial_memory;
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            for (size_t byte = 0; byte < 64; ++byte) {
                destination[byte] = (uint8_t)(0x61 + byte * 11);
                source[byte] = (uint8_t)(0xe3 - byte * 7);
            }
            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                                invalid_cases[i].code,
                                sizeof(invalid_cases[i].code));
            OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM1, destination));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM2, source));
            OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
            err = uc_emu_start(uc, code_start,
                               code_start + sizeof(invalid_cases[i].code), 0,
                               0);
            OK(uc_reg_read(uc, UC_X86_REG_ZMM1, destination_after));
            OK(uc_mem_read(uc, data_address, &memory, sizeof(memory)));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not fail closed",
                        invalid_cases[i].description);
            TEST_CHECK_(memcmp(destination, destination_after,
                               sizeof(destination)) == 0,
                        "%s changed destination",
                        invalid_cases[i].description);
            TEST_CHECK_(memory == initial_memory, "%s changed memory",
                        invalid_cases[i].description);
            TEST_CHECK_(rip == code_start, "%s advanced RIP",
                        invalid_cases[i].description);
            OK(uc_close(uc));
        }
    }
}

static bool test_x86_evex_run_compress_expand_memory(
    const TestX86EvexCompressExpandOp *operation, size_t vector_bytes,
    int mask_reg, bool zeroing)
{
    const int ll = vector_bytes == 16 ? 0 : vector_bytes == 32 ? 1 : 2;
    const int vector_index = 29;
    const uint8_t code[] = {
        0x62,
        0x62,
        (uint8_t)(0x7d | (operation->w ? 0x80 : 0)),
        (uint8_t)((ll << 5) | 0x08 | mask_reg | (zeroing ? 0x80 : 0)),
        operation->opcode,
        (uint8_t)((vector_index & 7) << 3),
    };
    const uint64_t data_address = code_start + 0x800;
    const uint64_t mask_value = UINT64_C(0xd6a59c3e71b4a5ad);
    const uint64_t effective_mask = mask_reg ? mask_value : UINT64_MAX;
    uint8_t initial_vector[64];
    uint8_t vector[64];
    uint8_t initial_memory[64];
    uint8_t memory[64];
    uint8_t expected[64];
    uint64_t observed_mask = mask_value;
    uint64_t rax = data_address;
    uint64_t rflags = UINT64_C(0xcd7);
    uint64_t rip = 0;
    uc_engine *uc;
    uc_err err;
    bool passed;

    for (size_t byte = 0; byte < 64; ++byte) {
        initial_vector[byte] = (uint8_t)(0x91 + byte * 13);
        initial_memory[byte] = (uint8_t)(0x27 + byte * 29);
    }
    memcpy(vector, initial_vector, sizeof(vector));
    memcpy(memory, initial_memory, sizeof(memory));
    if (operation->expand) {
        test_x86_evex_compress_expand_expected(
            expected, initial_vector, initial_memory, vector_bytes,
            operation->element_bytes, effective_mask, zeroing, true);
    } else {
        size_t packed = 0;
        const size_t elements = vector_bytes / operation->element_bytes;

        memcpy(expected, initial_memory, sizeof(expected));
        for (size_t input = 0; input < elements; ++input) {
            if ((effective_mask >> input) & 1) {
                memcpy(expected + packed * operation->element_bytes,
                       initial_vector + input * operation->element_bytes,
                       operation->element_bytes);
                ++packed;
            }
        }
    }

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER, code,
                        sizeof(code));
    OK(uc_mem_write(uc, data_address, memory, sizeof(memory)));
    OK(uc_reg_write(uc, UC_X86_REG_ZMM29, vector));
    if (mask_reg) {
        OK(uc_reg_write(uc, UC_X86_REG_K0 + mask_reg, &observed_mask));
    }
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    if (!TEST_CHECK_(err == UC_ERR_OK,
                     "%s memory VL%zu K%d %s did not execute: %s",
                     operation->name, vector_bytes * 8, mask_reg,
                     zeroing ? "zero" : "merge", uc_strerror(err))) {
        OK(uc_close(uc));
        return false;
    }

    OK(uc_reg_read(uc, UC_X86_REG_ZMM29, vector));
    OK(uc_mem_read(uc, data_address, memory, sizeof(memory)));
    if (mask_reg) {
        OK(uc_reg_read(uc, UC_X86_REG_K0 + mask_reg, &observed_mask));
    }
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    if (operation->expand) {
        passed = TEST_CHECK_(memcmp(vector, expected, sizeof(expected)) == 0,
                             "%s memory result mismatch", operation->name);
        passed &= TEST_CHECK_(memcmp(memory, initial_memory,
                                     sizeof(initial_memory)) == 0,
                              "%s changed source memory", operation->name);
    } else {
        passed = TEST_CHECK_(memcmp(memory, expected, sizeof(expected)) == 0,
                             "%s memory result mismatch", operation->name);
        passed &= TEST_CHECK_(memcmp(vector, initial_vector,
                                     sizeof(initial_vector)) == 0,
                              "%s changed source register", operation->name);
    }
    if (mask_reg) {
        passed &= TEST_CHECK_(observed_mask == mask_value,
                              "%s changed its writemask", operation->name);
    }
    passed &= TEST_CHECK_(rax == data_address, "%s changed its base register",
                          operation->name);
    passed &= TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS",
                          operation->name);
    passed &= TEST_CHECK_(rip == code_start + sizeof(code),
                          "%s advanced RIP incorrectly", operation->name);
    OK(uc_close(uc));
    return passed;
}

static void test_x86_evex_compress_expand_memory_forms(void)
{
    static const TestX86EvexCompressExpandOp operations[] = {
        {"VPCOMPRESSD", 0x8b, 4, false, false},
        {"VPCOMPRESSQ", 0x8b, 8, true, false},
        {"VCOMPRESSPS", 0x8a, 4, false, false},
        {"VCOMPRESSPD", 0x8a, 8, true, false},
        {"VPEXPANDD", 0x89, 4, false, true},
        {"VPEXPANDQ", 0x89, 8, true, true},
        {"VEXPANDPS", 0x88, 4, false, true},
        {"VEXPANDPD", 0x88, 8, true, true},
    };
    static const size_t vector_bytes_cases[] = {16, 32, 64};

    for (size_t operation = 0;
         operation < sizeof(operations) / sizeof(operations[0]);
         ++operation) {
        for (size_t vector_case = 0;
             vector_case < sizeof(vector_bytes_cases) /
                               sizeof(vector_bytes_cases[0]);
             ++vector_case) {
            const int mask_modes = operations[operation].expand ? 3 : 2;

            for (int mask_mode = 0; mask_mode < mask_modes; ++mask_mode) {
                const int mask_reg = mask_mode ? 7 : 0;
                const bool zeroing = mask_mode == 2;

                if (!test_x86_evex_run_compress_expand_memory(
                        &operations[operation],
                        vector_bytes_cases[vector_case], mask_reg,
                        zeroing)) {
                    return;
                }
            }
        }
    }

    /* Complete VBMI2 is not advertised to TCG guests, so its memory forms
     * must fail closed without changing architectural state. */
    {
        static const struct {
            uint8_t code[6];
            const char *name;
        } cases[] = {
            {{0x62, 0xf2, 0x7d, 0x4f, 0x62, 0x08}, "VPEXPANDB memory"},
            {{0x62, 0xf2, 0xfd, 0x4f, 0x62, 0x08}, "VPEXPANDW memory"},
            {{0x62, 0xf2, 0x7d, 0x4f, 0x63, 0x10}, "VPCOMPRESSB memory"},
            {{0x62, 0xf2, 0xfd, 0x4f, 0x63, 0x10}, "VPCOMPRESSW memory"},
        };
        const uint64_t data_address = code_start + 0x800;

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint8_t initial_destination[64];
            uint8_t observed_destination[64];
            uint8_t initial_source[64];
            uint8_t observed_source[64];
            uint8_t initial_memory[64];
            uint8_t observed_memory[64];
            uint64_t mask = UINT64_C(0xd6a59c3e71b4a5ad);
            uint64_t rax = data_address;
            uint64_t rflags = UINT64_C(0xcd7);
            uint64_t rip = UINT64_MAX;
            uc_engine *uc;
            uc_err err;

            for (size_t byte = 0; byte < 64; ++byte) {
                initial_destination[byte] = (uint8_t)(0x91 + byte * 13);
                initial_source[byte] = (uint8_t)(0x43 + byte * 19);
                initial_memory[byte] = (uint8_t)(0xb7 - byte * 11);
            }
            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                                cases[i].code, sizeof(cases[i].code));
            OK(uc_mem_write(uc, data_address, initial_memory,
                            sizeof(initial_memory)));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial_destination));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM2, initial_source));
            OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

            err = uc_emu_start(uc, code_start,
                               code_start + sizeof(cases[i].code), 0, 0);
            OK(uc_reg_read(uc, UC_X86_REG_ZMM1, observed_destination));
            OK(uc_reg_read(uc, UC_X86_REG_ZMM2, observed_source));
            OK(uc_mem_read(uc, data_address, observed_memory,
                           sizeof(observed_memory)));
            OK(uc_reg_read(uc, UC_X86_REG_K7, &mask));
            OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

            TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                        cases[i].name);
            TEST_CHECK_(memcmp(observed_destination, initial_destination,
                               sizeof(initial_destination)) == 0,
                        "%s changed destination", cases[i].name);
            TEST_CHECK_(memcmp(observed_source, initial_source,
                               sizeof(initial_source)) == 0,
                        "%s changed source", cases[i].name);
            TEST_CHECK_(memcmp(observed_memory, initial_memory,
                               sizeof(initial_memory)) == 0,
                        "%s changed memory", cases[i].name);
            TEST_CHECK_(mask == UINT64_C(0xd6a59c3e71b4a5ad),
                        "%s changed its writemask", cases[i].name);
            TEST_CHECK_(rax == data_address, "%s changed its base register",
                        cases[i].name);
            TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS",
                        cases[i].name);
            TEST_CHECK_(rip == code_start, "%s advanced RIP", cases[i].name);
            OK(uc_close(uc));
        }
    }

    /* Tuple1-scalar compressed displacement scales by element width. */
    {
        static const uint8_t code[] = {
            0x62, 0xf2, 0xfd, 0x49, 0x89, 0x48, 0x03,
        };
        const uint64_t data_address = code_start + 0x900;
        const uint64_t wanted = UINT64_C(0x1020304050607080);
        uint64_t memory[32];
        uint64_t destination[8];
        uint64_t expected[8];
        uint64_t mask = 1;
        uint64_t rax = data_address;
        uc_engine *uc;

        for (size_t lane = 0; lane < 32; ++lane) {
            memory[lane] = UINT64_C(0xdead000000000000) + lane;
        }
        for (size_t lane = 0; lane < 8; ++lane) {
            destination[lane] = UINT64_C(0xa000000000000000) + lane;
        }
        memory[3] = wanted;
        memcpy(expected, destination, sizeof(expected));
        expected[0] = wanted;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            code, sizeof(code));
        OK(uc_mem_write(uc, data_address, memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM1, destination));
        OK(uc_reg_write(uc, UC_X86_REG_K1, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM1, destination));
        TEST_CHECK(memcmp(destination, expected, sizeof(expected)) == 0);
        OK(uc_close(uc));
    }

    /* A zero writemask suppresses even a non-canonical memory operand. */
    {
        static const uint8_t code[] = {
            0x62, 0xf2, 0x7d, 0xca, 0x89, 0x08,
        };
        uint8_t destination[64];
        uint8_t expected[64] = {0};
        uint64_t mask = 0;
        uint64_t rax = UINT64_C(0x0000800000000000);
        uc_engine *uc;

        for (size_t byte = 0; byte < 64; ++byte) {
            destination[byte] = (uint8_t)(0x31 + byte * 7);
        }
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            code, sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM1, destination));
        OK(uc_reg_write(uc, UC_X86_REG_K2, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM1, destination));
        TEST_CHECK(memcmp(destination, expected, sizeof(expected)) == 0);
        OK(uc_close(uc));
    }

    {
        static const uint8_t code[] = {
            0x62, 0xf2, 0x7d, 0x4a, 0x8b, 0x10,
        };
        uint8_t source[64];
        uint8_t observed[64];
        uint64_t mask = 0;
        uint64_t rax = UINT64_C(0x0000800000000000);
        uc_engine *uc;

        for (size_t byte = 0; byte < 64; ++byte) {
            source[byte] = (uint8_t)(0x53 + byte * 17);
        }
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            code, sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM2, source));
        OK(uc_reg_write(uc, UC_X86_REG_K2, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM2, observed));
        TEST_CHECK(memcmp(observed, source, sizeof(source)) == 0);
        OK(uc_close(uc));
    }

    /* Active non-canonical accesses select the exception from the default
     * segment without committing vector or memory state. */
    {
        static const struct {
            uint8_t code[7];
            size_t code_size;
            uc_x86_reg base_reg;
            uc_x86_reg vector_reg;
            uint32_t expected_interrupt;
            const char *description;
        } cases[] = {
            {{0x62, 0xf2, 0x7d, 0x49, 0x89, 0x08},
             6,
             UC_X86_REG_RAX,
             UC_X86_REG_ZMM1,
             13,
             "ordinary-base expand #GP"},
            {{0x62, 0xf2, 0x7d, 0x49, 0x8b, 0x55, 0x00},
             7,
             UC_X86_REG_RBP,
             UC_X86_REG_ZMM2,
             12,
             "stack-base compress #SS"},
        };
        const uint64_t noncanonical = UINT64_C(0x0000800000000000);

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint8_t initial_vector[64];
            uint8_t observed_vector[64];
            uint8_t initial_memory[64];
            uint8_t observed_memory[64];
            uint64_t mask = 1;
            uint64_t base = noncanonical;
            uint64_t rip = UINT64_MAX;
            TestX86InterruptRecord record = {0};
            uc_engine *uc;
            uc_hook hook;

            for (size_t byte = 0; byte < 64; ++byte) {
                initial_vector[byte] = (uint8_t)(0x43 + byte * 19);
                initial_memory[byte] = (uint8_t)(0xb7 - byte * 11);
            }
            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                                cases[i].code, cases[i].code_size);
            OK(uc_mem_map(uc, noncanonical, 0x1000, UC_PROT_ALL));
            OK(uc_mem_write(uc, noncanonical, initial_memory,
                            sizeof(initial_memory)));
            OK(uc_reg_write(uc, cases[i].vector_reg, initial_vector));
            OK(uc_reg_write(uc, UC_X86_REG_K1, &mask));
            OK(uc_reg_write(uc, cases[i].base_reg, &base));
            OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_x86_record_interrupt,
                           &record, 1, 0));

            OK(uc_emu_start(uc, code_start, code_start + cases[i].code_size, 0,
                            0));
            OK(uc_reg_read(uc, cases[i].vector_reg, observed_vector));
            OK(uc_mem_read(uc, noncanonical, observed_memory,
                           sizeof(observed_memory)));
            OK(uc_reg_read(uc, cases[i].base_reg, &base));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

            TEST_CHECK_(record.count == 1 &&
                            record.intno == cases[i].expected_interrupt,
                        "%s selected interrupt %u", cases[i].description,
                        record.intno);
            TEST_CHECK_(memcmp(observed_vector, initial_vector,
                               sizeof(initial_vector)) == 0,
                        "%s changed vector state", cases[i].description);
            TEST_CHECK_(memcmp(observed_memory, initial_memory,
                               sizeof(initial_memory)) == 0,
                        "%s changed memory", cases[i].description);
            TEST_CHECK_(base == noncanonical, "%s changed its base register",
                        cases[i].description);
            TEST_CHECK_(rip == code_start, "%s advanced RIP",
                        cases[i].description);
            OK(uc_hook_del(uc, hook));
            OK(uc_close(uc));
        }
    }

    /* Expand commits no destination state if a later compact load faults. */
    {
        static const uint8_t code[] = {
            0x62, 0xf2, 0x7d, 0xcf, 0x89, 0x08,
        };
        const uint64_t page = UINT64_C(0x8000);
        const uint64_t data_address = page + 0x1000 - 4;
        const uint32_t first = UINT32_C(0x10203040);
        uint8_t initial[64];
        uint8_t destination[64];
        uint64_t mask = 5;
        uint64_t rax = data_address;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        for (size_t byte = 0; byte < 64; ++byte) {
            initial[byte] = (uint8_t)(0x61 + byte * 11);
        }
        memcpy(destination, initial, sizeof(destination));
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            code, sizeof(code));
        OK(uc_mem_map(uc, page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, data_address, &first, sizeof(first)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM1, destination));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
        TEST_CHECK(err == UC_ERR_READ_UNMAPPED);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM1, destination));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK(memcmp(destination, initial, sizeof(initial)) == 0);
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }

    /* Compress keeps earlier compact stores when a later store faults. */
    {
        static const uint8_t code[] = {
            0x62, 0xf2, 0x7d, 0x4f, 0x8b, 0x10,
        };
        const uint64_t page = UINT64_C(0x8000);
        const uint64_t data_address = page + 0x1000 - 4;
        uint32_t source[16];
        uint32_t first = UINT32_C(0xdeadbeef);
        uint64_t mask = 5;
        uint64_t rax = data_address;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        for (size_t lane = 0; lane < 16; ++lane) {
            source[lane] = UINT32_C(0x10000000) + (uint32_t)lane;
        }
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_SERVER,
                            code, sizeof(code));
        OK(uc_mem_map(uc, page, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, data_address, &first, sizeof(first)));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM2, source));
        OK(uc_reg_write(uc, UC_X86_REG_K7, &mask));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
        TEST_CHECK(err == UC_ERR_WRITE_UNMAPPED);
        OK(uc_mem_read(uc, data_address, &first, sizeof(first)));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK(first == source[0]);
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }
}

typedef enum TestX86ApxEvexAluOp {
    TEST_X86_APX_EVEX_ADD,
    TEST_X86_APX_EVEX_OR,
    TEST_X86_APX_EVEX_AND,
    TEST_X86_APX_EVEX_SUB,
    TEST_X86_APX_EVEX_XOR,
} TestX86ApxEvexAluOp;

typedef struct TestX86ApxEvexAlu {
    TestX86ApxEvexAluOp operation;
    uint8_t base_opcode;
    const char *name;
} TestX86ApxEvexAlu;

static uc_x86_reg test_x86_apx_full_register(unsigned int number)
{
    static const uc_x86_reg registers[] = {
        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
        UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
        UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        UC_X86_REG_R16, UC_X86_REG_R17, UC_X86_REG_R18, UC_X86_REG_R19,
        UC_X86_REG_R20, UC_X86_REG_R21, UC_X86_REG_R22, UC_X86_REG_R23,
        UC_X86_REG_R24, UC_X86_REG_R25, UC_X86_REG_R26, UC_X86_REG_R27,
        UC_X86_REG_R28, UC_X86_REG_R29, UC_X86_REG_R30, UC_X86_REG_R31,
    };

    TEST_CHECK_(number < sizeof(registers) / sizeof(registers[0]),
                "invalid APX register R%u", number);
    return registers[number & 31];
}

static void test_x86_apx_jmpabs_semantics(void)
{
    static const struct {
        uint8_t prefix;
        uint8_t payload;
        const char *description;
    } cases[] = {
        {0x00, 0x00, "canonical encoding"},
        {0x00, 0x77, "ignored REX2 payload bits"},
        {0x64, 0x00, "segment override"},
    };
    const uint64_t target = code_start + 0x800;
    const uint64_t initial_rax = UINT64_C(0x1122334455667788);
    const uint64_t initial_rflags = UINT64_C(0xcd7);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t code[12];
        size_t offset = 0;
        uint64_t rax = initial_rax;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;

        if (cases[i].prefix) {
            code[offset++] = cases[i].prefix;
        }
        code[offset++] = 0xd5;
        code[offset++] = cases[i].payload;
        code[offset++] = 0xa1;
        memcpy(&code[offset], &target, sizeof(target));
        offset += sizeof(target);

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code, offset);
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        OK(uc_emu_start(uc, code_start, 0, 0, 1));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(rip == target, "%s did not jump to the absolute target",
                    cases[i].description);
        TEST_CHECK_(rax == initial_rax, "%s changed GPR state",
                    cases[i].description);
        TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                    cases[i].description);
        OK(uc_close(uc));
    }
}

static void test_x86_apx_jmpabs_invalid_forms(void)
{
    static const struct {
        uint8_t code[12];
        size_t code_size;
        const char *description;
    } cases[] = {
        {{0xd5, 0x08, 0xa1, 0x00, 0x18}, 11, "REX2.W=1"},
        {{0xd5, 0x80, 0xa1, 0x00, 0x18}, 11, "REX2.M0=1"},
        {{0x66, 0xd5, 0x00, 0xa1, 0x00, 0x18}, 12, "operand-size prefix"},
        {{0x67, 0xd5, 0x00, 0xa1, 0x00, 0x18}, 12, "address-size prefix"},
        {{0xf0, 0xd5, 0x00, 0xa1, 0x00, 0x18}, 12, "LOCK prefix"},
        {{0xf2, 0xd5, 0x00, 0xa1, 0x00, 0x18}, 12, "REPNE prefix"},
        {{0xf3, 0xd5, 0x00, 0xa1, 0x00, 0x18}, 12, "REP prefix"},
        {{0x48, 0xd5, 0x00, 0xa1, 0x00, 0x18}, 12, "REX prefix"},
    };
    const uint64_t initial_rax = UINT64_C(0x1122334455667788);
    const uint64_t initial_rsp = code_start + 0xa00;
    const uint64_t initial_memory = UINT64_C(0xa5a5a5a5a5a5a5a5);
    const uint64_t initial_rflags = UINT64_C(0xcd7);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t rax = initial_rax;
        uint64_t rsp = initial_rsp;
        uint64_t memory = initial_memory;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, cases[i].code,
                            cases[i].code_size);
        OK(uc_mem_write(uc, initial_rsp, &memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err = uc_emu_start(uc, code_start, 0, 0, 1);
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_mem_read(uc, initial_rsp, &memory, sizeof(memory)));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    cases[i].description);
        TEST_CHECK_(rax == initial_rax && rsp == initial_rsp,
                    "%s changed GPR state", cases[i].description);
        TEST_CHECK_(memory == initial_memory, "%s changed memory",
                    cases[i].description);
        TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                    cases[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP",
                    cases[i].description);
        OK(uc_close(uc));
    }

    {
        static const uint8_t noncanonical[] = {
            0xd5, 0x00, 0xa1, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x80, 0x00, 0x00,
        };
        uint64_t rax = initial_rax;
        uint64_t rsp = initial_rsp;
        uint64_t memory = initial_memory;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, noncanonical,
                            sizeof(noncanonical));
        OK(uc_mem_write(uc, initial_rsp, &memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err = uc_emu_start(uc, code_start, 0, 0, 1);
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_mem_read(uc, initial_rsp, &memory, sizeof(memory)));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK(err == UC_ERR_EXCEPTION);
        TEST_CHECK(rax == initial_rax && rsp == initial_rsp);
        TEST_CHECK(memory == initial_memory);
        TEST_CHECK(rflags == initial_rflags);
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }
}

static void test_x86_apx_encode_push2_pop2(uint8_t code[6], bool push,
                                          bool ppx, unsigned int v,
                                          unsigned int b)
{
    code[0] = 0x62;
    code[1] = 0x44 | 0x80 | 0x10 | ((b & 8) ? 0 : 0x20) |
              ((b & 16) ? 0x08 : 0);
    code[2] = (ppx ? 0x80 : 0) | (((~v) & 0xf) << 3) | 0x04;
    code[3] = 0x10 | ((v & 16) ? 0 : 0x08);
    code[4] = push ? 0xff : 0x8f;
    code[5] = 0xc0 | (push ? 0x30 : 0) | (b & 7);
}

static void test_x86_apx_check_push2_pop2(bool push, bool ppx,
                                          unsigned int v_number,
                                          unsigned int b_number,
                                          uint8_t prefix,
                                          bool clear_unused_p0_bits)
{
    const uint64_t stack = code_start + 0x3000;
    const uint64_t v_value = UINT64_C(0x1111111111111111) ^
                             ((uint64_t)v_number << 48);
    const uint64_t b_value = v_number == b_number
                                 ? v_value
                                 : UINT64_C(0x2222222222222222) ^
                                       ((uint64_t)b_number << 40);
    const uint64_t initial_v = UINT64_C(0xaaaaaaaaaaaaaaaa);
    const uint64_t initial_b = UINT64_C(0xbbbbbbbbbbbbbbbb);
    const uint64_t initial_rflags = UINT64_C(0xcd7);
    uint8_t code[7];
    const size_t prefix_size = prefix ? 1 : 0;
    uint64_t memory[2] = {push ? initial_b : v_value,
                          push ? initial_v : b_value};
    uint64_t v = push ? v_value : initial_v;
    uint64_t b = push ? b_value : initial_b;
    uint64_t rsp = stack;
    uint64_t rflags = initial_rflags;
    uint64_t rip = 0;
    uc_engine *uc;

    if (prefix) {
        code[0] = prefix;
    }
    test_x86_apx_encode_push2_pop2(&code[prefix_size], push, ppx, v_number,
                                   b_number);
    if (clear_unused_p0_bits) {
        code[prefix_size + 1] &= (uint8_t)~0xd0;
    }
    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                        prefix_size + 6);
    OK(uc_mem_write(uc, push ? stack - 16 : stack, memory, sizeof(memory)));
    OK(uc_reg_write(uc, test_x86_apx_full_register(v_number), &v));
    OK(uc_reg_write(uc, test_x86_apx_full_register(b_number), &b));
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + prefix_size + 6, 0, 0));
    OK(uc_reg_read(uc, test_x86_apx_full_register(v_number), &v));
    OK(uc_reg_read(uc, test_x86_apx_full_register(b_number), &b));
    OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    OK(uc_mem_read(uc, push ? stack - 16 : stack, memory, sizeof(memory)));

    TEST_CHECK_(v == v_value, "%s2%s R%u V value mismatch",
                push ? "PUSH" : "POP", ppx ? "P" : "", v_number);
    TEST_CHECK_(b == b_value, "%s2%s R%u B value mismatch",
                push ? "PUSH" : "POP", ppx ? "P" : "", b_number);
    TEST_CHECK_(rsp == (push ? stack - 16 : stack + 16),
                "%s2%s updated RSP incorrectly", push ? "PUSH" : "POP",
                ppx ? "P" : "");
    TEST_CHECK_(push ? memory[0] == b_value && memory[1] == v_value
                     : memory[0] == v_value && memory[1] == b_value,
                "%s2%s used the wrong stack order", push ? "PUSH" : "POP",
                ppx ? "P" : "");
    TEST_CHECK_(rflags == initial_rflags, "%s2%s changed RFLAGS",
                push ? "PUSH" : "POP", ppx ? "P" : "");
    TEST_CHECK_(rip == code_start + prefix_size + 6,
                "%s2%s did not advance RIP", push ? "PUSH" : "POP",
                ppx ? "P" : "");
    OK(uc_close(uc));
}

static void test_x86_apx_push2_pop2_semantics(void)
{
    for (unsigned int push = 0; push < 2; ++push) {
        for (unsigned int ppx = 0; ppx < 2; ++ppx) {
            test_x86_apx_check_push2_pop2(push, ppx, 29, 20, 0, false);

            for (unsigned int reg = 0; reg < 32; ++reg) {
                unsigned int partner;

                if (reg == 4) {
                    continue;
                }
                partner = reg == 20 ? 21 : 20;
                test_x86_apx_check_push2_pop2(push, ppx, reg, partner, 0,
                                              false);
                partner = reg == 29 ? 28 : 29;
                test_x86_apx_check_push2_pop2(push, ppx, partner, reg, 0,
                                              false);
            }
        }
    }

    for (unsigned int ppx = 0; ppx < 2; ++ppx) {
        test_x86_apx_check_push2_pop2(true, ppx, 29, 29, 0, false);
    }

    test_x86_apx_check_push2_pop2(true, false, 29, 20, 0x67, false);
    test_x86_apx_check_push2_pop2(false, true, 29, 20, 0x64, false);
    test_x86_apx_check_push2_pop2(true, true, 29, 20, 0, true);
}

typedef struct TestX86ApxPairException {
    uint32_t intno;
    uint32_t count;
} TestX86ApxPairException;

typedef struct TestX86ApxDefaultSegmentCase {
    unsigned int base;
    uint32_t exception;
    const char *name;
} TestX86ApxDefaultSegmentCase;

static const TestX86ApxDefaultSegmentCase
    test_x86_apx_default_segment_cases[] = {
        {4, 12, "RSP"}, {5, 12, "RBP"}, {12, 13, "R12"},
        {13, 13, "R13"}, {20, 13, "R20"}, {21, 13, "R21"},
        {28, 13, "R28"}, {29, 13, "R29"},
    };

static void test_x86_apx_pair_record_exception(uc_engine *uc,
                                               uint32_t intno,
                                               void *user_data)
{
    TestX86ApxPairException *record = user_data;

    record->intno = intno;
    record->count++;
    OK(uc_emu_stop(uc));
}

static void test_x86_apx_push2_pop2_invalid_and_faults(void)
{
    enum InvalidMutation {
        INVALID_PAIR_ND,
        INVALID_PAIR_NF,
        INVALID_PAIR_PP,
        INVALID_PAIR_U,
        INVALID_PAIR_Z,
        INVALID_PAIR_LL,
        INVALID_PAIR_AAA,
        INVALID_PAIR_MEMORY,
        INVALID_PAIR_GROUP,
        INVALID_PAIR_V_RSP,
        INVALID_PAIR_B_RSP,
        INVALID_PAIR_POP_SAME,
        INVALID_PAIR_MAP,
        INVALID_PAIR_PREFIX_66,
        INVALID_PAIR_PREFIX_LOCK,
        INVALID_PAIR_PREFIX_F2,
        INVALID_PAIR_PREFIX_F3,
        INVALID_PAIR_PREFIX_REX,
    };
    static const struct {
        enum InvalidMutation mutation;
        bool push;
        const char *description;
    } invalid_cases[] = {
        {INVALID_PAIR_ND, true, "ND=0"},
        {INVALID_PAIR_NF, true, "NF=1"},
        {INVALID_PAIR_PP, true, "nonzero pp"},
        {INVALID_PAIR_U, true, "EVEX.U=0"},
        {INVALID_PAIR_Z, true, "EVEX.z=1"},
        {INVALID_PAIR_LL, true, "EVEX.LL nonzero"},
        {INVALID_PAIR_AAA, true, "EVEX.aaa nonzero"},
        {INVALID_PAIR_MEMORY, true, "memory form"},
        {INVALID_PAIR_GROUP, true, "wrong PUSH group"},
        {INVALID_PAIR_GROUP, false, "wrong POP group"},
        {INVALID_PAIR_V_RSP, true, "PUSH V=RSP"},
        {INVALID_PAIR_B_RSP, true, "PUSH B=RSP"},
        {INVALID_PAIR_V_RSP, false, "POP V=RSP"},
        {INVALID_PAIR_B_RSP, false, "POP B=RSP"},
        {INVALID_PAIR_POP_SAME, false, "POP duplicate destinations"},
        {INVALID_PAIR_MAP, true, "wrong EVEX map"},
        {INVALID_PAIR_PREFIX_66, true, "66 prefix"},
        {INVALID_PAIR_PREFIX_LOCK, true, "LOCK prefix"},
        {INVALID_PAIR_PREFIX_F2, true, "F2 prefix"},
        {INVALID_PAIR_PREFIX_F3, true, "F3 prefix"},
        {INVALID_PAIR_PREFIX_REX, true, "REX prefix"},
    };
    const uint64_t stack = code_start + 0x3000;
    const uint64_t initial_v = UINT64_C(0x2929292929292929);
    const uint64_t initial_b = UINT64_C(0x2020202020202020);
    const uint64_t initial_memory[2] = {
        UINT64_C(0xa5a5a5a5a5a5a5a5),
        UINT64_C(0x5a5a5a5a5a5a5a5a),
    };
    const uint64_t initial_rflags = UINT64_C(0xcd7);

    for (size_t i = 0; i < sizeof(invalid_cases) / sizeof(invalid_cases[0]);
         ++i) {
        uint8_t code[7];
        size_t prefix_size = 0;
        uint8_t *insn;
        uint64_t v = initial_v;
        uint64_t b = initial_b;
        uint64_t rsp = stack;
        uint64_t memory[2];
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        switch (invalid_cases[i].mutation) {
        case INVALID_PAIR_PREFIX_66:
            code[prefix_size++] = 0x66;
            break;
        case INVALID_PAIR_PREFIX_LOCK:
            code[prefix_size++] = 0xf0;
            break;
        case INVALID_PAIR_PREFIX_F2:
            code[prefix_size++] = 0xf2;
            break;
        case INVALID_PAIR_PREFIX_F3:
            code[prefix_size++] = 0xf3;
            break;
        case INVALID_PAIR_PREFIX_REX:
            code[prefix_size++] = 0x48;
            break;
        default:
            break;
        }
        insn = &code[prefix_size];
        test_x86_apx_encode_push2_pop2(insn, invalid_cases[i].push, false, 29,
                                       20);
        switch (invalid_cases[i].mutation) {
        case INVALID_PAIR_ND:
            insn[3] &= (uint8_t)~0x10;
            break;
        case INVALID_PAIR_NF:
            insn[3] |= 0x04;
            break;
        case INVALID_PAIR_PP:
            insn[2] |= 0x01;
            break;
        case INVALID_PAIR_U:
            insn[2] &= (uint8_t)~0x04;
            break;
        case INVALID_PAIR_Z:
            insn[3] |= 0x80;
            break;
        case INVALID_PAIR_LL:
            insn[3] |= 0x20;
            break;
        case INVALID_PAIR_AAA:
            insn[3] |= 0x01;
            break;
        case INVALID_PAIR_MEMORY:
            insn[5] &= 0x3f;
            break;
        case INVALID_PAIR_GROUP:
            insn[5] ^= 0x08;
            break;
        case INVALID_PAIR_V_RSP:
            test_x86_apx_encode_push2_pop2(insn, invalid_cases[i].push, false,
                                           4, 20);
            break;
        case INVALID_PAIR_B_RSP:
            test_x86_apx_encode_push2_pop2(insn, invalid_cases[i].push, false,
                                           29, 4);
            break;
        case INVALID_PAIR_POP_SAME:
            test_x86_apx_encode_push2_pop2(insn, false, false, 29, 29);
            break;
        case INVALID_PAIR_MAP:
            insn[1] ^= 0x01;
            break;
        default:
            break;
        }

        memcpy(memory, initial_memory, sizeof(memory));
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            prefix_size + 6);
        OK(uc_mem_write(uc, stack - 16, memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_R29, &v));
        OK(uc_reg_write(uc, UC_X86_REG_R20, &b));
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err = uc_emu_start(uc, code_start, 0, 0, 1);
        OK(uc_reg_read(uc, UC_X86_REG_R29, &v));
        OK(uc_reg_read(uc, UC_X86_REG_R20, &b));
        OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        OK(uc_mem_read(uc, stack - 16, memory, sizeof(memory)));

        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    invalid_cases[i].description);
        TEST_CHECK_(v == initial_v && b == initial_b && rsp == stack,
                    "%s changed GPR state", invalid_cases[i].description);
        TEST_CHECK_(memcmp(memory, initial_memory, sizeof(memory)) == 0,
                    "%s changed memory", invalid_cases[i].description);
        TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                    invalid_cases[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP",
                    invalid_cases[i].description);
        OK(uc_close(uc));
    }

    for (unsigned int push = 0; push < 2; ++push) {
        uint8_t code[6];
        uint64_t v = initial_v;
        uint64_t b = initial_b;
        uint64_t rsp = stack + 8;
        uint64_t memory[2];
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        TestX86ApxPairException record = {0};
        uc_engine *uc;
        uc_hook hook;

        test_x86_apx_encode_push2_pop2(code, push, false, 29, 20);
        memcpy(memory, initial_memory, sizeof(memory));
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_mem_write(uc, stack - 16, memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_R29, &v));
        OK(uc_reg_write(uc, UC_X86_REG_R20, &b));
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_hook_add(uc, &hook, UC_HOOK_INTR,
                       test_x86_apx_pair_record_exception, &record, 1, 0));

        OK(uc_emu_start(uc, code_start, 0, 0, 1));
        OK(uc_reg_read(uc, UC_X86_REG_R29, &v));
        OK(uc_reg_read(uc, UC_X86_REG_R20, &b));
        OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        OK(uc_mem_read(uc, stack - 16, memory, sizeof(memory)));

        TEST_CHECK_(record.count == 1 && record.intno == 13,
                    "%s2 misalignment did not raise #GP",
                    push ? "PUSH" : "POP");
        TEST_CHECK(v == initial_v && b == initial_b && rsp == stack + 8);
        TEST_CHECK(memcmp(memory, initial_memory, sizeof(memory)) == 0);
        TEST_CHECK(rflags == initial_rflags);
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }

    for (unsigned int push = 0; push < 2; ++push) {
        uint8_t code[6];
        uint64_t v = initial_v;
        uint64_t b = initial_b;
        uint64_t rsp = UINT64_C(0x0000800000000010);
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        TestX86ApxPairException record = {0};
        uc_engine *uc;
        uc_hook hook;

        test_x86_apx_encode_push2_pop2(code, push, false, 29, 20);
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_R29, &v));
        OK(uc_reg_write(uc, UC_X86_REG_R20, &b));
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_hook_add(uc, &hook, UC_HOOK_INTR,
                       test_x86_apx_pair_record_exception, &record, 1, 0));

        OK(uc_emu_start(uc, code_start, 0, 0, 1));
        OK(uc_reg_read(uc, UC_X86_REG_R29, &v));
        OK(uc_reg_read(uc, UC_X86_REG_R20, &b));
        OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(record.count == 1 && record.intno == 12,
                    "%s2 noncanonical stack access did not raise #SS",
                    push ? "PUSH" : "POP");
        TEST_CHECK(v == initial_v && b == initial_b &&
                   rsp == UINT64_C(0x0000800000000010));
        TEST_CHECK(rflags == initial_rflags);
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }

    for (unsigned int push = 0; push < 2; ++push) {
        for (unsigned int protected_page = 0; protected_page < 2;
             ++protected_page) {
            const uint64_t page = UINT64_C(0x8000);
            const uint64_t rsp_initial = push ? page + 0x1000 : page;
            const uc_err expected = push
                                        ? protected_page ? UC_ERR_WRITE_PROT
                                                         : UC_ERR_WRITE_UNMAPPED
                                        : protected_page ? UC_ERR_READ_PROT
                                                         : UC_ERR_READ_UNMAPPED;
            uint8_t code[6];
            uint64_t v = initial_v;
            uint64_t b = initial_b;
            uint64_t rsp = rsp_initial;
            uint64_t memory[2];
            uint64_t rflags = initial_rflags;
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            test_x86_apx_encode_push2_pop2(code, push, false, 29, 20);
            memcpy(memory, initial_memory, sizeof(memory));
            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                sizeof(code));
            if (protected_page) {
                OK(uc_mem_map(uc, page, 0x1000, UC_PROT_ALL));
                OK(uc_mem_write(uc, push ? rsp_initial - 16 : rsp_initial,
                                memory, sizeof(memory)));
                OK(uc_mem_protect(uc, page, 0x1000,
                                  push ? UC_PROT_READ : UC_PROT_WRITE));
            }
            OK(uc_reg_write(uc, UC_X86_REG_R29, &v));
            OK(uc_reg_write(uc, UC_X86_REG_R20, &b));
            OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

            err = uc_emu_start(uc, code_start, 0, 0, 1);
            OK(uc_reg_read(uc, UC_X86_REG_R29, &v));
            OK(uc_reg_read(uc, UC_X86_REG_R20, &b));
            OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            if (protected_page) {
                OK(uc_mem_read(uc, push ? rsp_initial - 16 : rsp_initial,
                               memory, sizeof(memory)));
            }

            TEST_CHECK_(err == expected, "%s2 fault returned %s",
                        push ? "PUSH" : "POP", uc_strerror(err));
            TEST_CHECK(v == initial_v && b == initial_b &&
                       rsp == rsp_initial);
            if (protected_page) {
                TEST_CHECK(memcmp(memory, initial_memory, sizeof(memory)) ==
                           0);
            }
            TEST_CHECK(rflags == initial_rflags);
            TEST_CHECK(rip == code_start);
            OK(uc_close(uc));
        }
    }

    {
        uint8_t code[6];
        uint32_t eax = UINT32_C(0x11223344);
        uint32_t esp = (uint32_t)stack;
        uint32_t eflags = UINT32_C(0xcd7);
        uint32_t eip = 0;
        uint64_t memory[2];
        uc_engine *uc;
        uc_err err;

        test_x86_apx_encode_push2_pop2(code, true, false, 29, 20);
        memcpy(memory, initial_memory, sizeof(memory));
        uc_common_setup_cpu(&uc, UC_MODE_32, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_mem_write(uc, stack - 16, memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
        OK(uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags));

        err = uc_emu_start(uc, code_start, 0, 0, 1);
        OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_read(uc, UC_X86_REG_ESP, &esp));
        OK(uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags));
        OK(uc_reg_read(uc, UC_X86_REG_EIP, &eip));
        OK(uc_mem_read(uc, stack - 16, memory, sizeof(memory)));

        TEST_CHECK(err == UC_ERR_INSN_INVALID);
        TEST_CHECK(eax == UINT32_C(0x11223344) && esp == (uint32_t)stack);
        TEST_CHECK(eflags == UINT32_C(0xcd7));
        TEST_CHECK(eip == code_start);
        TEST_CHECK(memcmp(memory, initial_memory, sizeof(memory)) == 0);
        OK(uc_close(uc));
    }
}

static void test_x86_apx_encode_rex2_push_pop(uint8_t code[3], bool push,
                                               bool w, unsigned int reg)
{
    code[0] = 0xd5;
    code[1] = (w ? 0x08 : 0) | ((reg & 8) ? 0x01 : 0) |
              ((reg & 16) ? 0x10 : 0);
    code[2] = (push ? 0x50 : 0x58) | (reg & 7);
}

static void test_x86_apx_check_rex2_push_pop(bool push, bool w,
                                             unsigned int reg,
                                             uint8_t prefix,
                                             uint8_t ignored_rex2_bits,
                                             unsigned int width)
{
    const uint64_t stack = code_start + 0x3000;
    const uint64_t initial_reg = UINT64_C(0x1122334455667788) ^
                                 ((uint64_t)reg << 48);
    const uint64_t popped = width == 8 ? code_start + 0x2800
                                       : UINT64_C(0xbeef);
    const uint64_t initial_rflags = UINT64_C(0xcd7);
    uint8_t code[4];
    const size_t prefix_size = prefix ? 1 : 0;
    uint64_t stack_value = push ? UINT64_C(0xa5a5a5a5a5a5a5a5) : popped;
    uint64_t reg_value = initial_reg;
    uint64_t rsp = stack;
    uint64_t rflags = initial_rflags;
    uint64_t rip = 0;
    uc_engine *uc;

    TEST_CHECK(width == 2 || width == 8);
    if (prefix) {
        code[0] = prefix;
    }
    test_x86_apx_encode_rex2_push_pop(&code[prefix_size], push, w, reg);
    code[prefix_size + 1] |= ignored_rex2_bits;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                        prefix_size + 3);
    OK(uc_mem_write(uc, push ? stack - width : stack, &stack_value, width));
    if (reg != 4) {
        OK(uc_reg_write(uc, test_x86_apx_full_register(reg), &reg_value));
    }
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + prefix_size + 3, 0, 0));
    OK(uc_reg_read(uc, test_x86_apx_full_register(reg), &reg_value));
    OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    stack_value = 0;
    OK(uc_mem_read(uc, push ? stack - width : stack, &stack_value, width));

    if (push) {
        const uint64_t expected_source = reg == 4 ? stack : initial_reg;

        TEST_CHECK_(rsp == stack - width,
                    "REX2 %sPUSH R%u updated RSP incorrectly",
                    w ? "P" : "", reg);
        TEST_CHECK_(stack_value ==
                        (width == 8 ? expected_source
                                    : expected_source & UINT64_C(0xffff)),
                    "REX2 %sPUSH R%u stored the wrong value",
                    w ? "P" : "", reg);
        if (reg != 4) {
            TEST_CHECK_(reg_value == initial_reg,
                        "REX2 %sPUSH R%u changed its source",
                        w ? "P" : "", reg);
        }
    } else {
        const uint64_t expected_reg =
            width == 8
                ? popped
                : ((reg == 4 ? stack + 2 : initial_reg) &
                   ~UINT64_C(0xffff)) |
                      (popped & UINT64_C(0xffff));

        TEST_CHECK_(reg_value == expected_reg,
                    "REX2 %sPOP R%u loaded the wrong value", w ? "P" : "",
                    reg);
        TEST_CHECK_(rsp == (reg == 4 ? expected_reg : stack + width),
                    "REX2 %sPOP R%u used the wrong RSP ordering",
                    w ? "P" : "", reg);
        TEST_CHECK_(stack_value == popped,
                    "REX2 %sPOP R%u changed stack memory", w ? "P" : "",
                    reg);
    }
    TEST_CHECK_(rflags == initial_rflags,
                "REX2 %s%s R%u changed RFLAGS", w ? "P" : "",
                push ? "PUSH" : "POP", reg);
    TEST_CHECK_(rip == code_start + prefix_size + 3,
                "REX2 %s%s R%u did not advance RIP", w ? "P" : "",
                push ? "PUSH" : "POP", reg);
    OK(uc_close(uc));
}

static void test_x86_apx_rex2_push_pop_semantics(void)
{
    for (unsigned int push = 0; push < 2; ++push) {
        for (unsigned int reg = 0; reg < 32; ++reg) {
            test_x86_apx_check_rex2_push_pop(push, true, reg, 0, 0, 8);
        }
    }

    for (unsigned int push = 0; push < 2; ++push) {
        test_x86_apx_check_rex2_push_pop(push, false, 29, 0, 0, 8);
        test_x86_apx_check_rex2_push_pop(push, false, 21, 0x66, 0, 2);
        test_x86_apx_check_rex2_push_pop(push, false, 4, 0x66, 0, 2);
        test_x86_apx_check_rex2_push_pop(push, true, 28, 0x66, 0, 8);
    }

    test_x86_apx_check_rex2_push_pop(true, true, 29, 0, 0x66, 8);
    test_x86_apx_check_rex2_push_pop(false, true, 20, 0x67, 0, 8);
    test_x86_apx_check_rex2_push_pop(true, true, 19, 0xf3, 0, 8);
    test_x86_apx_check_rex2_push_pop(false, true, 18, 0x64, 0, 8);
}

static void test_x86_apx_rex2_push_pop_invalid_and_faults(void)
{
    static const struct {
        uint8_t code[4];
        size_t size;
        const char *description;
    } invalid_cases[] = {
        {{0xf0, 0xd5, 0x19, 0x55}, 4, "LOCK prefix"},
        {{0x48, 0xd5, 0x19, 0x55}, 4, "preceding REX prefix"},
        {{0xd5, 0x99, 0x55}, 3, "map 1"},
        {{0xd5, 0x19, 0x66}, 3, "legacy prefix after REX2"},
        {{0xd5, 0x19, 0xd5}, 3, "second REX2 after REX2"},
    };
    const uint64_t stack = code_start + 0x3000;
    const uint64_t initial_r29 = UINT64_C(0x2929292929292929);
    const uint64_t initial_memory = UINT64_C(0xa5a5a5a5a5a5a5a5);
    const uint64_t initial_rflags = UINT64_C(0xcd7);

    for (size_t i = 0; i < sizeof(invalid_cases) / sizeof(invalid_cases[0]);
         ++i) {
        uint64_t r29 = initial_r29;
        uint64_t rsp = stack;
        uint64_t memory = initial_memory;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX,
                            invalid_cases[i].code, invalid_cases[i].size);
        OK(uc_mem_write(uc, stack - 8, &memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_R29, &r29));
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err = uc_emu_start(uc, code_start, 0, 0, 1);
        OK(uc_reg_read(uc, UC_X86_REG_R29, &r29));
        OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_mem_read(uc, stack - 8, &memory, sizeof(memory)));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    invalid_cases[i].description);
        TEST_CHECK_(r29 == initial_r29 && rsp == stack,
                    "%s changed GPR state", invalid_cases[i].description);
        TEST_CHECK_(memory == initial_memory, "%s changed memory",
                    invalid_cases[i].description);
        TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                    invalid_cases[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP",
                    invalid_cases[i].description);
        OK(uc_close(uc));
    }

    for (unsigned int push = 0; push < 2; ++push) {
        const uint64_t page = UINT64_C(0x8000);
        const uint64_t initial_rsp = page;
        const uc_err expected = push ? UC_ERR_WRITE_UNMAPPED
                                     : UC_ERR_READ_UNMAPPED;
        uint8_t code[3];
        uint64_t r29 = initial_r29;
        uint64_t rsp = initial_rsp;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        test_x86_apx_encode_rex2_push_pop(code, push, true, 29);
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_R29, &r29));
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err = uc_emu_start(uc, code_start, 0, 0, 1);
        OK(uc_reg_read(uc, UC_X86_REG_R29, &r29));
        OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == expected, "P%s fault returned %s",
                    push ? "USH" : "OP", uc_strerror(err));
        TEST_CHECK(r29 == initial_r29 && rsp == initial_rsp);
        TEST_CHECK(rflags == initial_rflags);
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }

    for (unsigned int push = 0; push < 2; ++push) {
        uint8_t code[3];
        uint64_t r29 = initial_r29;
        uint64_t rsp = UINT64_C(0x0000800000000008);
        const uint64_t initial_rsp = rsp;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        TestX86ApxPairException record = {0};
        uc_engine *uc;
        uc_hook hook;

        test_x86_apx_encode_rex2_push_pop(code, push, true, 29);
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_R29, &r29));
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_hook_add(uc, &hook, UC_HOOK_INTR,
                       test_x86_apx_pair_record_exception, &record, 1, 0));

        OK(uc_emu_start(uc, code_start, 0, 0, 1));
        OK(uc_reg_read(uc, UC_X86_REG_R29, &r29));
        OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(record.count == 1 && record.intno == 12,
                    "P%s noncanonical stack access did not raise #SS",
                    push ? "USH" : "OP");
        TEST_CHECK(r29 == initial_r29 && rsp == initial_rsp);
        TEST_CHECK(rflags == initial_rflags);
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }
}

static uint64_t test_x86_apx_setcc_flags(unsigned int condition,
                                         bool expected)
{
    const bool inverted = (condition & 1) != 0;
    const bool base_condition = expected ^ inverted;
    uint64_t rflags = UINT64_C(0x202);

    if (!base_condition) {
        return rflags;
    }
    switch (condition >> 1) {
    case 0:
        return rflags | UINT64_C(0x800); /* OF */
    case 1:
        return rflags | UINT64_C(0x001); /* CF */
    case 2:
        return rflags | UINT64_C(0x040); /* ZF */
    case 3:
        return rflags | UINT64_C(0x001); /* CF || ZF */
    case 4:
        return rflags | UINT64_C(0x080); /* SF */
    case 5:
        return rflags | UINT64_C(0x004); /* PF */
    case 6:
        return rflags | UINT64_C(0x080); /* SF != OF */
    default:
        return rflags | UINT64_C(0x040); /* ZF || SF != OF */
    }
}

static void test_x86_apx_encode_setcc_reg(uint8_t code[6],
                                          unsigned int condition, bool nd,
                                          bool w, unsigned int destination,
                                          bool vary_ignored_fields)
{
    uint8_t p0 = 0xf4;

    if (destination & 8) {
        p0 &= (uint8_t)~0x20;
    }
    if (destination & 16) {
        p0 |= 0x08;
    }
    if (vary_ignored_fields) {
        p0 ^= 0xd0; /* R3, X3 and R4 are ignored for register SETcc. */
    }
    code[0] = 0x62;
    code[1] = p0;
    code[2] = (w ? 0x80 : 0) | 0x7f;
    code[3] = (nd ? 0x10 : 0) | 0x08;
    code[4] = 0x40 | (condition & 15);
    code[5] = 0xc0 | (((condition * 5) & 7) << 3) | (destination & 7);
}

static void test_x86_apx_evex_setcc_register_matrix(void)
{
    for (unsigned int condition = 0; condition < 16; ++condition) {
        for (unsigned int nd = 0; nd < 2; ++nd) {
            for (unsigned int destination = 0; destination < 32;
                 ++destination) {
                for (unsigned int expected = 0; expected < 2; ++expected) {
                    const uint64_t initial =
                        UINT64_C(0xa5b6c7d8e9fa1020) ^
                        ((uint64_t)destination << 40);
                    const uint64_t expected_value =
                        nd ? expected : (initial & ~UINT64_C(0xff)) | expected;
                    uint8_t code[6];
                    uint64_t value = initial;
                    uint64_t rflags = test_x86_apx_setcc_flags(
                        condition, expected != 0);
                    const uint64_t initial_rflags = rflags;
                    uint64_t rip = 0;
                    uc_engine *uc;

                    test_x86_apx_encode_setcc_reg(
                        code, condition, nd, (condition ^ destination) & 1,
                        destination, (condition + destination) & 1);
                    uc_common_setup_cpu(&uc, UC_MODE_64,
                                        UC_CPU_X86_APX, code,
                                        sizeof(code));
                    OK(uc_reg_write(
                        uc, test_x86_apx_full_register(destination), &value));
                    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

                    OK(uc_emu_start(uc, code_start,
                                    code_start + sizeof(code), 0, 0));
                    OK(uc_reg_read(
                        uc, test_x86_apx_full_register(destination), &value));
                    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
                    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

                    TEST_CHECK_(
                        value == expected_value,
                        "SETcc condition %u ND=%u R%u returned 0x%" PRIx64,
                        condition, nd, destination, value);
                    TEST_CHECK_(rflags == initial_rflags,
                                "SETcc condition %u changed RFLAGS",
                                condition);
                    TEST_CHECK_(rip == code_start + sizeof(code),
                                "SETcc condition %u did not advance RIP",
                                condition);
                    OK(uc_close(uc));
                }
            }
        }
    }

    {
        uint8_t code[8] = {0x31, 0xc0}; /* xor eax, eax */
        uint64_t r29 = UINT64_MAX;
        uint64_t rflags = UINT64_C(0x202);
        uc_engine *uc;

        test_x86_apx_encode_setcc_reg(&code[2], 4, true, false, 29, false);
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_R29, &r29));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_R29, &r29));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

        TEST_CHECK(r29 == 1);
        TEST_CHECK(rflags == UINT64_C(0x246));
        OK(uc_close(uc));
    }
}

static size_t test_x86_apx_encode_setcc_memory(
    uint8_t code[9], uint8_t prefix, unsigned int condition, bool nd, bool w,
    unsigned int base, int index, unsigned int scale, int8_t displacement,
    unsigned int ignored_modrm_reg)
{
    const size_t prefix_size = prefix ? 1 : 0;
    uint8_t p0 = 0x94;
    uint8_t p1 = (w ? 0x80 : 0) | 0x7f;
    uint8_t *insn = &code[prefix_size];

    if (prefix) {
        code[0] = prefix;
    }
    if (base & 8) {
        p0 &= (uint8_t)~0x20;
    } else {
        p0 |= 0x20;
    }
    if (base & 16) {
        p0 |= 0x08;
    }
    if (index >= 0 && (index & 8)) {
        p0 &= (uint8_t)~0x40;
    } else {
        p0 |= 0x40;
    }
    if (index >= 0 && (index & 16)) {
        p1 &= (uint8_t)~0x04;
    }

    insn[0] = 0x62;
    insn[1] = p0;
    insn[2] = p1;
    insn[3] = (nd ? 0x10 : 0) | 0x08;
    insn[4] = 0x40 | (condition & 15);
    insn[5] = 0x40 | ((ignored_modrm_reg & 7) << 3) | 4;
    insn[6] = ((scale & 3) << 6) |
              (((index < 0 ? 4 : index) & 7) << 3) | (base & 7);
    insn[7] = (uint8_t)displacement;
    return prefix_size + 8;
}

static void test_x86_apx_check_setcc_memory(
    unsigned int condition, bool nd, bool expected, uint8_t prefix,
    unsigned int base, int index, unsigned int scale, int8_t displacement,
    uint64_t base_value, uint64_t index_value, uint64_t segment_base,
    uint64_t target)
{
    uint8_t code[9];
    const size_t code_size = test_x86_apx_encode_setcc_memory(
        code, prefix, condition, nd, (condition + nd) & 1, base, index,
        scale, displacement, condition * 3);
    uint8_t memory[3] = {0xa5, 0xcc, 0x5a};
    uint64_t observed_base = base_value;
    uint64_t observed_index = index_value;
    uint64_t rflags = test_x86_apx_setcc_flags(condition, expected);
    const uint64_t initial_rflags = rflags;
    uint64_t rip = 0;
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                        code_size);
    OK(uc_mem_write(uc, target - 1, memory, sizeof(memory)));
    OK(uc_reg_write(uc, test_x86_apx_full_register(base), &observed_base));
    if (index >= 0) {
        OK(uc_reg_write(uc, test_x86_apx_full_register(index),
                        &observed_index));
    }
    if (prefix == 0x64) {
        OK(uc_reg_write(uc, UC_X86_REG_FS_BASE, &segment_base));
    } else if (prefix == 0x65) {
        OK(uc_reg_write(uc, UC_X86_REG_GS_BASE, &segment_base));
    }
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
    OK(uc_mem_read(uc, target - 1, memory, sizeof(memory)));
    OK(uc_reg_read(uc, test_x86_apx_full_register(base), &observed_base));
    if (index >= 0) {
        OK(uc_reg_read(uc, test_x86_apx_full_register(index),
                       &observed_index));
    }
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    TEST_CHECK_(memory[0] == 0xa5 && memory[1] == expected &&
                    memory[2] == 0x5a,
                "memory SETcc condition %u ND=%u wrote the wrong bytes",
                condition, nd);
    TEST_CHECK_(observed_base == base_value &&
                    (index < 0 || observed_index == index_value),
                "memory SETcc changed an address register");
    TEST_CHECK_(rflags == initial_rflags, "memory SETcc changed RFLAGS");
    TEST_CHECK_(rip == code_start + code_size,
                "memory SETcc did not advance RIP");
    OK(uc_close(uc));
}

static void test_x86_apx_evex_setcc_memory_and_invalid(void)
{
    const uint64_t target = code_start + 0x3000;
    const uint64_t index_value = 0x20;
    const uint64_t base_value = target - index_value * 2 - 7;

    for (unsigned int condition = 0; condition < 16; ++condition) {
        for (unsigned int nd = 0; nd < 2; ++nd) {
            for (unsigned int expected = 0; expected < 2; ++expected) {
                test_x86_apx_check_setcc_memory(
                    condition, nd, expected, 0, 29, 28, 1, 7, base_value,
                    index_value, 0, target);
            }
        }
    }

    {
        const uint64_t addr32_target = code_start + 0x2d00;
        const uint64_t addr32_index = UINT64_C(0xabcdef0000000020);
        const uint64_t addr32_base =
            UINT64_C(0x1234567800000000) |
            ((addr32_target - (uint32_t)addr32_index * 4 + 9) &
             UINT64_C(0xffffffff));

        test_x86_apx_check_setcc_memory(
            0x4, true, true, 0x67, 29, 28, 2, -9, addr32_base,
            addr32_index, 0, addr32_target);
    }
    {
        const uint64_t fs_base = code_start + 0x2000;
        const uint64_t fs_offset = 0x120;

        test_x86_apx_check_setcc_memory(
            0xa, false, true, 0x64, 29, -1, 0, 7, fs_offset, 0, fs_base,
            fs_base + fs_offset + 7);
    }
    {
        const uint64_t gs_base = code_start + 0x2100;
        const uint64_t gs_offset = 0x80;
        const uint64_t gs_index = 0x10;

        test_x86_apx_check_setcc_memory(
            0xd, true, false, 0x65, 21, 20, 1, -3, gs_offset, gs_index,
            gs_base, gs_base + gs_offset + gs_index * 2 - 3);
    }

    {
        enum InvalidSetccMutation {
            INVALID_SETCC_Z,
            INVALID_SETCC_LL,
            INVALID_SETCC_NF,
            INVALID_SETCC_AAA,
            INVALID_SETCC_V4,
            INVALID_SETCC_VVVV,
            INVALID_SETCC_U_REGISTER,
            INVALID_SETCC_PP,
            INVALID_SETCC_MAP,
            INVALID_SETCC_OPCODE,
            INVALID_SETCC_LOCK,
            INVALID_SETCC_66,
            INVALID_SETCC_F2,
            INVALID_SETCC_F3,
            INVALID_SETCC_REX,
        };
        static const struct {
            enum InvalidSetccMutation mutation;
            const char *description;
        } cases[] = {
            {INVALID_SETCC_Z, "EVEX.z"},
            {INVALID_SETCC_LL, "EVEX.LL"},
            {INVALID_SETCC_NF, "EVEX.NF"},
            {INVALID_SETCC_AAA, "EVEX.aaa"},
            {INVALID_SETCC_V4, "reserved V4"},
            {INVALID_SETCC_VVVV, "reserved vvvv"},
            {INVALID_SETCC_U_REGISTER, "U=0 register form"},
            {INVALID_SETCC_PP, "reserved F3 pp"},
            {INVALID_SETCC_MAP, "wrong map"},
            {INVALID_SETCC_OPCODE, "wrong opcode"},
            {INVALID_SETCC_LOCK, "LOCK prefix"},
            {INVALID_SETCC_66, "66 prefix"},
            {INVALID_SETCC_F2, "F2 prefix"},
            {INVALID_SETCC_F3, "F3 prefix"},
            {INVALID_SETCC_REX, "REX prefix"},
        };
        const uint64_t initial_r29 = UINT64_C(0x2929292929292929);
        const uint64_t initial_rflags = UINT64_C(0xcd7);

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint8_t code[7];
            size_t prefix_size = 0;
            uint8_t *insn;
            uint64_t r29 = initial_r29;
            uint64_t rflags = initial_rflags;
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            switch (cases[i].mutation) {
            case INVALID_SETCC_LOCK:
                code[prefix_size++] = 0xf0;
                break;
            case INVALID_SETCC_66:
                code[prefix_size++] = 0x66;
                break;
            case INVALID_SETCC_F2:
                code[prefix_size++] = 0xf2;
                break;
            case INVALID_SETCC_F3:
                code[prefix_size++] = 0xf3;
                break;
            case INVALID_SETCC_REX:
                code[prefix_size++] = 0x48;
                break;
            default:
                break;
            }
            insn = &code[prefix_size];
            test_x86_apx_encode_setcc_reg(insn, 4, true, false, 29, false);
            switch (cases[i].mutation) {
            case INVALID_SETCC_Z:
                insn[3] |= 0x80;
                break;
            case INVALID_SETCC_LL:
                insn[3] |= 0x20;
                break;
            case INVALID_SETCC_NF:
                insn[3] |= 0x04;
                break;
            case INVALID_SETCC_AAA:
                insn[3] |= 0x01;
                break;
            case INVALID_SETCC_V4:
                insn[3] &= (uint8_t)~0x08;
                break;
            case INVALID_SETCC_VVVV:
                insn[2] &= (uint8_t)~0x08;
                break;
            case INVALID_SETCC_U_REGISTER:
                insn[2] &= (uint8_t)~0x04;
                break;
            case INVALID_SETCC_PP:
                insn[2] = (insn[2] & (uint8_t)~0x03) | 0x02;
                break;
            case INVALID_SETCC_MAP:
                insn[1] ^= 0x01;
                break;
            case INVALID_SETCC_OPCODE:
                insn[4] = 0x50;
                break;
            default:
                break;
            }

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                prefix_size + 6);
            OK(uc_reg_write(uc, UC_X86_REG_R29, &r29));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            err = uc_emu_start(uc, code_start, 0, 0, 1);
            OK(uc_reg_read(uc, UC_X86_REG_R29, &r29));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

            TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                        cases[i].description);
            TEST_CHECK_(r29 == initial_r29, "%s changed its destination",
                        cases[i].description);
            TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                        cases[i].description);
            TEST_CHECK_(rip == code_start, "%s advanced RIP",
                        cases[i].description);
            OK(uc_close(uc));
        }
    }

    for (unsigned int nd = 0; nd < 2; ++nd) {
        for (unsigned int protected_page = 0; protected_page < 2;
             ++protected_page) {
            const uint64_t page = UINT64_C(0x8000);
            const uc_err expected_error =
                protected_page ? UC_ERR_WRITE_PROT : UC_ERR_WRITE_UNMAPPED;
            uint8_t code[9];
            const size_t code_size = test_x86_apx_encode_setcc_memory(
                code, 0, 4, nd, false, 29, -1, 0, 0, 7);
            uint64_t r29 = page;
            uint64_t rflags = test_x86_apx_setcc_flags(4, true);
            const uint64_t initial_rflags = rflags;
            uint64_t rip = 0;
            uint8_t memory = 0xcc;
            uc_engine *uc;
            uc_err err;

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                code_size);
            if (protected_page) {
                OK(uc_mem_map(uc, page, 0x1000, UC_PROT_ALL));
                OK(uc_mem_write(uc, page, &memory, sizeof(memory)));
                OK(uc_mem_protect(uc, page, 0x1000, UC_PROT_READ));
            }
            OK(uc_reg_write(uc, UC_X86_REG_R29, &r29));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            err = uc_emu_start(uc, code_start, 0, 0, 1);
            OK(uc_reg_read(uc, UC_X86_REG_R29, &r29));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            if (protected_page) {
                OK(uc_mem_read(uc, page, &memory, sizeof(memory)));
            }

            TEST_CHECK_(err == expected_error,
                        "memory SETcc fault returned %s", uc_strerror(err));
            TEST_CHECK(r29 == page);
            TEST_CHECK(rflags == initial_rflags);
            TEST_CHECK(rip == code_start);
            if (protected_page) {
                TEST_CHECK(memory == 0xcc);
            }
            OK(uc_close(uc));
        }
    }

    for (size_t segment_case = 0;
         segment_case < sizeof(test_x86_apx_default_segment_cases) /
                            sizeof(test_x86_apx_default_segment_cases[0]);
         ++segment_case) {
        const TestX86ApxDefaultSegmentCase *segment =
            &test_x86_apx_default_segment_cases[segment_case];
        const unsigned int base = segment->base;
        const uint64_t noncanonical = UINT64_C(0x0000800000000000);
        uint8_t code[9];
        const size_t code_size = test_x86_apx_encode_setcc_memory(
            code, 0, 4, true, false, base, -1, 0, 0, 0);
        uint64_t base_value = noncanonical;
        uint64_t rflags = test_x86_apx_setcc_flags(4, true);
        const uint64_t initial_rflags = rflags;
        uint64_t rip = 0;
        TestX86ApxPairException record = {0};
        uc_engine *uc;
        uc_hook hook;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            code_size);
        OK(uc_reg_write(uc, test_x86_apx_full_register(base), &base_value));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_hook_add(uc, &hook, UC_HOOK_INTR,
                       test_x86_apx_pair_record_exception, &record, 1, 0));
        OK(uc_emu_start(uc, code_start, 0, 0, 1));
        OK(uc_reg_read(uc, test_x86_apx_full_register(base), &base_value));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(record.count == 1 && record.intno == segment->exception,
                    "noncanonical SETcc %s address raised exception %u",
                    segment->name, record.intno);
        TEST_CHECK(base_value == noncanonical);
        TEST_CHECK(rflags == initial_rflags);
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }

    {
        uint8_t code[16] = {0x48, 0xb8};
        const uint64_t loaded = UINT64_C(0x8877665544332210);
        uint64_t rax = UINT64_C(0x11111111111111ff);
        uint64_t rflags = test_x86_apx_setcc_flags(4, true);
        uint64_t rip = 0;
        uc_engine *uc;

        memcpy(&code[2], &loaded, sizeof(loaded));
        test_x86_apx_encode_setcc_reg(&code[10], 4, false, false, 0, false);
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK(rax == UINT64_C(0x8877665544332201));
        TEST_CHECK(rip == code_start + sizeof(code));
        OK(uc_close(uc));
    }

    {
        uint8_t code[18] = {0x48, 0xb8};
        const uint64_t loaded_address = code_start + 0x2f00;
        uint64_t rax = UINT64_C(0x8000);
        uint64_t rflags = test_x86_apx_setcc_flags(4, true);
        uint8_t memory = 0xcc;
        uc_engine *uc;

        memcpy(&code[2], &loaded_address, sizeof(loaded_address));
        TEST_CHECK(test_x86_apx_encode_setcc_memory(
                       &code[10], 0, 4, false, false, 0, -1, 0, 0, 0) == 8);
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_mem_write(uc, loaded_address, &memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_mem_read(uc, loaded_address, &memory, sizeof(memory)));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));

        TEST_CHECK(memory == 1);
        TEST_CHECK(rax == loaded_address);
        OK(uc_close(uc));
    }

    /* In 64-bit mode, 67 truncates the final RIP-relative EA; it does not
     * turn ModRM mod=00,r/m=101 into an absolute disp32 address. */
    {
        const uint64_t target = code_start + 0x3100;
        uint8_t code[11] = {0x67, 0x62, 0xf4, 0x7f, 0x18, 0x44, 0x05};
        const int32_t displacement =
            (int32_t)(target - (code_start + sizeof(code)));
        uint8_t memory = 0xcc;
        uint64_t rflags = test_x86_apx_setcc_flags(4, true);
        const uint64_t initial_rflags = rflags;
        uint64_t rip = 0;
        uc_engine *uc;

        memcpy(&code[7], &displacement, sizeof(displacement));
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_mem_write(uc, target, &memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_mem_read(uc, target, &memory, sizeof(memory)));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK(memory == 1);
        TEST_CHECK(rflags == initial_rflags);
        TEST_CHECK(rip == code_start + sizeof(code));
        OK(uc_close(uc));
    }
}

static uint64_t test_x86_apx_cmov_width_value(uint64_t value,
                                               unsigned int width)
{
    switch (width) {
    case 2:
        return value & UINT64_C(0xffff);
    case 4:
        return value & UINT64_C(0xffffffff);
    default:
        TEST_CHECK(width == 8);
        return value;
    }
}

static void test_x86_apx_encode_cmov_reg(
    uint8_t code[6], unsigned int condition, unsigned int width, bool nd,
    bool nf, unsigned int reg, unsigned int rm, unsigned int ndd)
{
    uint8_t p0 = 0xf4;

    TEST_CHECK(width == 2 || width == 4 || width == 8);
    if (reg & 8) {
        p0 &= (uint8_t)~0x80;
    }
    if (reg & 16) {
        p0 &= (uint8_t)~0x10;
    }
    if (rm & 8) {
        p0 &= (uint8_t)~0x20;
    }
    if (rm & 16) {
        p0 |= 0x08;
    }

    code[0] = 0x62;
    code[1] = p0;
    code[2] = (width == 8 ? 0x80 : 0) |
              (((~(nd ? ndd : 0)) & 15) << 3) | 0x04 |
              (width == 2 ? 1 : 0);
    code[3] = (nd ? 0x10 : 0) | (nf ? 0x04 : 0) |
              ((nd && (ndd & 16)) ? 0 : 0x08);
    code[4] = 0x40 | (condition & 15);
    code[5] = 0xc0 | ((reg & 7) << 3) | (rm & 7);
}

static void test_x86_apx_check_cmov_reg(
    unsigned int condition, unsigned int width, bool nd, bool nf,
    unsigned int destination, bool taken)
{
    unsigned int reg = (destination + 1) & 31;
    unsigned int rm = (destination + 2) & 31;
    unsigned int ndd = destination;
    uint64_t reg_value = UINT64_C(0x1122334455660000) | reg;
    uint64_t rm_value = UINT64_C(0x88776655aabb0000) | rm;
    uint64_t ndd_value = UINT64_C(0xdeadbeefcafe0000) | ndd;
    uint64_t expected;
    uint64_t observed_destination;
    uint64_t rflags = test_x86_apx_setcc_flags(condition, taken);
    const uint64_t initial_rflags = rflags;
    uint64_t rip = 0;
    uint8_t code[6];
    uc_engine *uc;

    if (!nd && !nf) {
        reg = destination;
        rm = (destination + 1) & 31;
        reg_value = UINT64_C(0x1122334455660000) | reg;
        rm_value = UINT64_C(0x88776655aabb0000) | rm;
    } else if (!nd) {
        rm = destination;
        reg = (destination + 1) & 31;
        reg_value = UINT64_C(0x1122334455660000) | reg;
        rm_value = UINT64_C(0x88776655aabb0000) | rm;
    }

    test_x86_apx_encode_cmov_reg(code, condition, width, nd, nf, reg, rm,
                                 ndd);
    if (taken) {
        expected = test_x86_apx_cmov_width_value(
            !nd && nf ? reg_value : rm_value, width);
    } else {
        expected = nd ? test_x86_apx_cmov_width_value(reg_value, width) : 0;
    }

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                        sizeof(code));
    OK(uc_reg_write(uc, test_x86_apx_full_register(reg), &reg_value));
    OK(uc_reg_write(uc, test_x86_apx_full_register(rm), &rm_value));
    if (nd) {
        OK(uc_reg_write(uc, test_x86_apx_full_register(ndd), &ndd_value));
    }
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, test_x86_apx_full_register(destination),
                   &observed_destination));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    TEST_CHECK_(observed_destination == expected,
                "CMOVcc cc=%u ND=%u NF=%u width=%u R%u returned 0x%" PRIx64,
                condition, nd, nf, width, destination,
                observed_destination);
    TEST_CHECK_(rflags == initial_rflags,
                "CMOVcc cc=%u ND=%u NF=%u changed RFLAGS", condition, nd,
                nf);
    TEST_CHECK_(rip == code_start + sizeof(code),
                "CMOVcc cc=%u ND=%u NF=%u did not advance RIP", condition,
                nd, nf);

    if (reg != destination) {
        uint64_t observed = 0;

        OK(uc_reg_read(uc, test_x86_apx_full_register(reg), &observed));
        TEST_CHECK_(observed == reg_value,
                    "CMOVcc changed register source R%u", reg);
    }
    if (rm != destination) {
        uint64_t observed = 0;

        OK(uc_reg_read(uc, test_x86_apx_full_register(rm), &observed));
        TEST_CHECK_(observed == rm_value,
                    "CMOVcc changed r/m register source R%u", rm);
    }
    OK(uc_close(uc));
}

static void test_x86_apx_evex_cmovcc_register_matrix(void)
{
    static const unsigned int widths[] = {2, 4, 8};

    for (unsigned int condition = 0; condition < 16; ++condition) {
        for (unsigned int form = 0; form < 4; ++form) {
            for (size_t w = 0; w < sizeof(widths) / sizeof(widths[0]); ++w) {
                for (unsigned int taken = 0; taken < 2; ++taken) {
                    const unsigned int destination =
                        (condition * 7 + form * 11 + w * 3) & 31;

                    test_x86_apx_check_cmov_reg(
                        condition, widths[w], (form & 2) != 0,
                        (form & 1) != 0, destination, taken != 0);
                }
            }
        }
    }

    /* Independently force every architectural GPR through a destination. */
    for (unsigned int destination = 0; destination < 32; ++destination) {
        const unsigned int form = destination & 3;

        test_x86_apx_check_cmov_reg(
            destination & 15, (unsigned int[]){2, 4, 8}[destination % 3],
            (form & 2) != 0, (form & 1) != 0, destination,
            (destination & 4) != 0);
    }

    /* NDD may alias either old source; both inputs must be captured first. */
    for (unsigned int ndd_aliases_rm = 0; ndd_aliases_rm < 2;
         ++ndd_aliases_rm) {
        for (unsigned int nf = 0; nf < 2; ++nf) {
            for (unsigned int taken = 0; taken < 2; ++taken) {
                const unsigned int reg = ndd_aliases_rm ? 20 : 29;
                const unsigned int rm = ndd_aliases_rm ? 29 : 20;
                const unsigned int ndd = ndd_aliases_rm ? rm : reg;
                const uint64_t initial_reg = UINT64_C(0x1122334455667788);
                const uint64_t initial_rm = UINT64_C(0x88776655aabbccdd);
                uint64_t reg_value = initial_reg;
                uint64_t rm_value = initial_rm;
                uint64_t destination_value = 0;
                uint64_t rflags = test_x86_apx_setcc_flags(4, taken != 0);
                const uint64_t initial_rflags = rflags;
                uint8_t code[6];
                uc_engine *uc;

                test_x86_apx_encode_cmov_reg(code, 4, 2, true, nf != 0,
                                             reg, rm, ndd);
                uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX,
                                    code, sizeof(code));
                OK(uc_reg_write(uc, test_x86_apx_full_register(reg),
                                &reg_value));
                OK(uc_reg_write(uc, test_x86_apx_full_register(rm),
                                &rm_value));
                OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
                OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0,
                                0));
                OK(uc_reg_read(uc, test_x86_apx_full_register(ndd),
                               &destination_value));
                OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

                TEST_CHECK_(
                    destination_value ==
                        ((taken ? initial_rm : initial_reg) &
                         UINT64_C(0xffff)),
                    "NDD/source alias selected the updated value");
                TEST_CHECK(rflags == initial_rflags);
                OK(uc_close(uc));
            }
        }
    }

    /* W=1 overrides embedded 66 and still selects a 64-bit operation. */
    {
        uint8_t code[6];
        uint64_t r20 = UINT64_C(0x1122334455667788);
        uint64_t r29 = UINT64_C(0x88776655aabbccdd);
        uint64_t r31 = UINT64_C(0xdeadbeefcafef00d);
        uint64_t rflags = test_x86_apx_setcc_flags(4, true);
        uc_engine *uc;

        test_x86_apx_encode_cmov_reg(code, 4, 8, true, false, 20, 29, 31);
        code[2] |= 1;
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_R20, &r20));
        OK(uc_reg_write(uc, UC_X86_REG_R29, &r29));
        OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));

        TEST_CHECK(r31 == UINT64_C(0x88776655aabbccdd));
        OK(uc_close(uc));
    }
}

static size_t test_x86_apx_encode_cmov_memory(
    uint8_t code[9], uint8_t prefix, unsigned int condition,
    unsigned int width, bool nd, bool nf, unsigned int reg,
    unsigned int ndd, unsigned int base, int index, unsigned int scale,
    int8_t displacement)
{
    const size_t prefix_size = prefix ? 1 : 0;
    uint8_t p0 = 0x94;
    uint8_t p1 = (width == 8 ? 0x80 : 0) |
                 (((~(nd ? ndd : 0)) & 15) << 3) | 0x04 |
                 (width == 2 ? 1 : 0);
    uint8_t *insn = &code[prefix_size];

    TEST_CHECK(width == 2 || width == 4 || width == 8);
    if (prefix) {
        code[0] = prefix;
    }
    if (reg & 8) {
        p0 &= (uint8_t)~0x80;
    }
    if (reg & 16) {
        p0 &= (uint8_t)~0x10;
    }
    if (base & 8) {
        p0 &= (uint8_t)~0x20;
    } else {
        p0 |= 0x20;
    }
    if (base & 16) {
        p0 |= 0x08;
    }
    if (index >= 0 && (index & 8)) {
        p0 &= (uint8_t)~0x40;
    } else {
        p0 |= 0x40;
    }
    if (index >= 0 && (index & 16)) {
        p1 &= (uint8_t)~0x04;
    }

    insn[0] = 0x62;
    insn[1] = p0;
    insn[2] = p1;
    insn[3] = (nd ? 0x10 : 0) | (nf ? 0x04 : 0) |
              ((nd && (ndd & 16)) ? 0 : 0x08);
    insn[4] = 0x40 | (condition & 15);
    insn[5] = 0x40 | ((reg & 7) << 3) | 4;
    insn[6] = ((scale & 3) << 6) |
              (((index < 0 ? 4 : index) & 7) << 3) | (base & 7);
    insn[7] = (uint8_t)displacement;
    return prefix_size + 8;
}

static void test_x86_apx_check_cmov_memory(
    unsigned int condition, unsigned int width, bool nd, bool nf, bool taken,
    uint8_t prefix, unsigned int base, int index, unsigned int scale,
    int8_t displacement, uint64_t base_value, uint64_t index_value,
    uint64_t segment_base, uint64_t target)
{
    const unsigned int reg = 20;
    const unsigned int ndd = 31;
    uint8_t code[9];
    const size_t code_size = test_x86_apx_encode_cmov_memory(
        code, prefix, condition, width, nd, nf, reg, ndd, base, index,
        scale, displacement);
    const uint64_t mask = width == 2 ? UINT64_C(0xffff)
                          : width == 4 ? UINT64_C(0xffffffff)
                                       : UINT64_MAX;
    const uint64_t initial_memory = UINT64_C(0xa5b6c7d8e9fa1020);
    const uint64_t initial_reg = UINT64_C(0x1122334455667788);
    const uint64_t initial_ndd = UINT64_C(0xdeadbeefcafef00d);
    uint64_t memory = initial_memory;
    uint64_t reg_value = initial_reg;
    uint64_t ndd_value = initial_ndd;
    uint64_t observed_base = base_value;
    uint64_t observed_index = index_value;
    uint64_t rflags = test_x86_apx_setcc_flags(condition, taken);
    const uint64_t initial_rflags = rflags;
    uint64_t rip = 0;
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                        code_size);
    OK(uc_mem_write(uc, target, &memory, sizeof(memory)));
    OK(uc_reg_write(uc, test_x86_apx_full_register(reg), &reg_value));
    if (nd) {
        OK(uc_reg_write(uc, test_x86_apx_full_register(ndd), &ndd_value));
    }
    OK(uc_reg_write(uc, test_x86_apx_full_register(base), &observed_base));
    if (index >= 0) {
        OK(uc_reg_write(uc, test_x86_apx_full_register(index),
                        &observed_index));
    }
    if (prefix == 0x64) {
        OK(uc_reg_write(uc, UC_X86_REG_FS_BASE, &segment_base));
    } else if (prefix == 0x65) {
        OK(uc_reg_write(uc, UC_X86_REG_GS_BASE, &segment_base));
    }
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
    OK(uc_mem_read(uc, target, &memory, sizeof(memory)));
    OK(uc_reg_read(uc, test_x86_apx_full_register(reg), &reg_value));
    if (nd) {
        OK(uc_reg_read(uc, test_x86_apx_full_register(ndd), &ndd_value));
    }
    OK(uc_reg_read(uc, test_x86_apx_full_register(base), &observed_base));
    if (index >= 0) {
        OK(uc_reg_read(uc, test_x86_apx_full_register(index),
                       &observed_index));
    }
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    if (!nd && nf) {
        const uint64_t expected_memory =
            taken ? (initial_memory & ~mask) | (initial_reg & mask)
                  : initial_memory;

        TEST_CHECK_(memory == expected_memory,
                    "memory CFCMOVcc store wrote 0x%" PRIx64, memory);
    } else {
        const uint64_t expected_destination =
            taken ? initial_memory & mask : nd ? initial_reg & mask : 0;
        const uint64_t observed_destination = nd ? ndd_value : reg_value;

        TEST_CHECK_(observed_destination == expected_destination,
                    "memory CMOVcc load returned 0x%" PRIx64,
                    observed_destination);
        TEST_CHECK(memory == initial_memory);
    }
    if (!(!nd && !nf)) {
        TEST_CHECK(reg_value == initial_reg);
    }
    TEST_CHECK_(observed_base == base_value &&
                    (index < 0 || observed_index == index_value),
                "memory CMOVcc changed an address register");
    TEST_CHECK(rflags == initial_rflags);
    TEST_CHECK(rip == code_start + code_size);
    OK(uc_close(uc));
}

static void test_x86_apx_evex_cmovcc_memory_faults_and_invalid(void)
{
    const uint64_t target = code_start + 0x3200;
    const uint64_t index_value = 0x20;
    const uint64_t base_value = target - index_value * 2 - 7;
    static const unsigned int widths[] = {2, 4, 8};

    for (unsigned int condition = 0; condition < 16; ++condition) {
        for (unsigned int form = 0; form < 4; ++form) {
            for (unsigned int taken = 0; taken < 2; ++taken) {
                test_x86_apx_check_cmov_memory(
                    condition, widths[(condition + form) % 3],
                    (form & 2) != 0, (form & 1) != 0, taken != 0, 0, 29,
                    28, 1, 7, base_value, index_value, 0, target);
            }
        }
    }

    {
        const uint64_t addr32_target = code_start + 0x2d00;
        const uint64_t addr32_index = UINT64_C(0xabcdef0000000020);
        const uint64_t addr32_base =
            UINT64_C(0x1234567800000000) |
            ((addr32_target - (uint32_t)addr32_index * 4 + 9) &
             UINT64_C(0xffffffff));

        test_x86_apx_check_cmov_memory(
            4, 8, true, false, true, 0x67, 29, 28, 2, -9, addr32_base,
            addr32_index, 0, addr32_target);
    }
    test_x86_apx_check_cmov_memory(4, 2, false, false, true, 0x64, 29, -1,
                                   0, 7, 0x120, 0, code_start + 0x2000,
                                   code_start + 0x2127);
    test_x86_apx_check_cmov_memory(5, 4, false, true, true, 0x65, 21, 28,
                                   1, -3, 0x80, 0x10,
                                   code_start + 0x2100,
                                   code_start + 0x219d);

    /* Address-size override still leaves non-SIB r/m=5 RIP-relative, then
     * truncates and zero-extends the complete effective address. */
    {
        const uint64_t instruction_address = UINT64_C(0x100001000);
        const uint64_t rip_target = UINT64_C(0x4150);
        const uint64_t loaded = UINT64_C(0x88776655aabbccdd);
        uint8_t code[11] = {0x67};
        const int32_t displacement =
            (int32_t)(rip_target - (instruction_address + sizeof(code)));
        uint64_t r20 = UINT64_C(0x1122334455667788);
        uint64_t r31 = UINT64_C(0xdeadbeefcafef00d);
        uint64_t rflags = test_x86_apx_setcc_flags(4, true);
        const uint64_t initial_rflags = rflags;
        uint64_t rip = 0;
        uc_engine *uc;

        test_x86_apx_encode_cmov_reg(&code[1], 4, 8, true, false, 20, 29,
                                     31);
        code[6] = (20 & 7) << 3 | 5;
        memcpy(&code[7], &displacement, sizeof(displacement));
        OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_APX));
        OK(uc_mem_map(uc, instruction_address, 0x1000, UC_PROT_ALL));
        OK(uc_mem_map(uc, rip_target & ~UINT64_C(0xfff), 0x1000,
                      UC_PROT_ALL));
        OK(uc_mem_write(uc, instruction_address, code, sizeof(code)));
        OK(uc_mem_write(uc, rip_target, &loaded, sizeof(loaded)));
        OK(uc_reg_write(uc, UC_X86_REG_R20, &r20));
        OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, instruction_address,
                        instruction_address + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_R20, &r20));
        OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK(r20 == UINT64_C(0x1122334455667788));
        TEST_CHECK(r31 == loaded);
        TEST_CHECK(rflags == initial_rflags);
        TEST_CHECK(rip == instruction_address + sizeof(code));
        OK(uc_close(uc));
    }

    /* Invalid encodings must fail before touching architectural state. */
    {
        enum InvalidCmovMutation {
            INVALID_CMOV_Z,
            INVALID_CMOV_LL,
            INVALID_CMOV_AAA,
            INVALID_CMOV_RESERVED_P2,
            INVALID_CMOV_ND0_V4,
            INVALID_CMOV_ND0_VVVV,
            INVALID_CMOV_U_REGISTER,
            INVALID_CMOV_PP_F3,
            INVALID_CMOV_MAP,
            INVALID_CMOV_LOCK,
            INVALID_CMOV_66,
            INVALID_CMOV_F2,
            INVALID_CMOV_F3,
            INVALID_CMOV_REX,
        };
        static const struct {
            enum InvalidCmovMutation mutation;
            const char *description;
        } cases[] = {
            {INVALID_CMOV_Z, "EVEX.z"},
            {INVALID_CMOV_LL, "EVEX.LL"},
            {INVALID_CMOV_AAA, "EVEX.aaa"},
            {INVALID_CMOV_RESERVED_P2, "reserved payload bit"},
            {INVALID_CMOV_ND0_V4, "ND=0 nonzero V4"},
            {INVALID_CMOV_ND0_VVVV, "ND=0 nonzero vvvv"},
            {INVALID_CMOV_U_REGISTER, "U=0 register form"},
            {INVALID_CMOV_PP_F3, "F3 pp"},
            {INVALID_CMOV_MAP, "wrong map"},
            {INVALID_CMOV_LOCK, "LOCK prefix"},
            {INVALID_CMOV_66, "preceding 66 prefix"},
            {INVALID_CMOV_F2, "preceding F2 prefix"},
            {INVALID_CMOV_F3, "preceding F3 prefix"},
            {INVALID_CMOV_REX, "preceding REX prefix"},
        };
        const uint64_t initial_r29 = UINT64_C(0x2929292929292929);
        const uint64_t initial_r20 = UINT64_C(0x2020202020202020);
        const uint64_t initial_rflags = UINT64_C(0xcd7);

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint8_t code[7];
            size_t prefix_size = 0;
            uint8_t *insn;
            uint64_t r29 = initial_r29;
            uint64_t r20 = initial_r20;
            uint64_t rflags = initial_rflags;
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            switch (cases[i].mutation) {
            case INVALID_CMOV_LOCK:
                code[prefix_size++] = 0xf0;
                break;
            case INVALID_CMOV_66:
                code[prefix_size++] = 0x66;
                break;
            case INVALID_CMOV_F2:
                code[prefix_size++] = 0xf2;
                break;
            case INVALID_CMOV_F3:
                code[prefix_size++] = 0xf3;
                break;
            case INVALID_CMOV_REX:
                code[prefix_size++] = 0x48;
                break;
            default:
                break;
            }
            insn = &code[prefix_size];
            test_x86_apx_encode_cmov_reg(insn, 4, 8, false, false, 29, 20,
                                         0);
            switch (cases[i].mutation) {
            case INVALID_CMOV_Z:
                insn[3] |= 0x80;
                break;
            case INVALID_CMOV_LL:
                insn[3] |= 0x20;
                break;
            case INVALID_CMOV_AAA:
                insn[3] |= 0x01;
                break;
            case INVALID_CMOV_RESERVED_P2:
                insn[3] |= 0x40;
                break;
            case INVALID_CMOV_ND0_V4:
                insn[3] &= (uint8_t)~0x08;
                break;
            case INVALID_CMOV_ND0_VVVV:
                insn[2] &= (uint8_t)~0x08;
                break;
            case INVALID_CMOV_U_REGISTER:
                insn[2] &= (uint8_t)~0x04;
                break;
            case INVALID_CMOV_PP_F3:
                insn[2] = (insn[2] & (uint8_t)~3) | 2;
                break;
            case INVALID_CMOV_MAP:
                insn[1] ^= 1;
                break;
            default:
                break;
            }

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                prefix_size + 6);
            OK(uc_reg_write(uc, UC_X86_REG_R29, &r29));
            OK(uc_reg_write(uc, UC_X86_REG_R20, &r20));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            err = uc_emu_start(uc, code_start, 0, 0, 1);
            OK(uc_reg_read(uc, UC_X86_REG_R29, &r29));
            OK(uc_reg_read(uc, UC_X86_REG_R20, &r20));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

            TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                        cases[i].description);
            TEST_CHECK(r29 == initial_r29 && r20 == initial_r20);
            TEST_CHECK(rflags == initial_rflags);
            TEST_CHECK(rip == code_start);
            OK(uc_close(uc));
        }
    }

    /* Condition-false CFCMOV suppresses memory faults; CMOV does not. */
    for (unsigned int form = 0; form < 4; ++form) {
        const bool nd = (form & 2) != 0;
        const bool nf = (form & 1) != 0;
        const uint64_t page = UINT64_C(0x8000);
        uint8_t code[9];
        const size_t code_size = test_x86_apx_encode_cmov_memory(
            code, 0, 4, 8, nd, nf, 20, 31, 29, -1, 0, 0);
        uint64_t r29 = page;
        uint64_t r20 = UINT64_C(0x1122334455667788);
        uint64_t r31 = UINT64_C(0xdeadbeefcafef00d);
        uint64_t rflags = test_x86_apx_setcc_flags(4, false);
        const uint64_t initial_rflags = rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            code_size);
        OK(uc_reg_write(uc, UC_X86_REG_R29, &r29));
        OK(uc_reg_write(uc, UC_X86_REG_R20, &r20));
        OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        err = uc_emu_start(uc, code_start, code_start + code_size, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_R20, &r20));
        OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        if (nd && !nf) {
            TEST_CHECK(err == UC_ERR_READ_UNMAPPED);
            TEST_CHECK(r31 == UINT64_C(0xdeadbeefcafef00d));
            TEST_CHECK(rip == code_start);
        } else {
            OK(err);
            TEST_CHECK(rip == code_start + code_size);
            if (!nd && !nf) {
                TEST_CHECK(r20 == 0);
            } else if (nd) {
                TEST_CHECK(r31 == UINT64_C(0x1122334455667788));
            }
        }
        TEST_CHECK(rflags == initial_rflags);
        OK(uc_close(uc));
    }

    /* Every selected memory form faults before changing its destination. */
    for (unsigned int form = 0; form < 4; ++form) {
        for (unsigned int protected_page = 0; protected_page < 2;
             ++protected_page) {
            const bool nd = (form & 2) != 0;
            const bool nf = (form & 1) != 0;
            const bool store = !nd && nf;
            const uint64_t page = UINT64_C(0x8000);
            const uc_err expected_error =
                protected_page
                    ? store ? UC_ERR_WRITE_PROT : UC_ERR_READ_PROT
                    : store ? UC_ERR_WRITE_UNMAPPED : UC_ERR_READ_UNMAPPED;
            uint8_t code[9];
            const size_t code_size = test_x86_apx_encode_cmov_memory(
                code, 0, 4, 8, nd, nf, 20, 31, 29, -1, 0, 0);
            uint64_t r29 = page;
            uint64_t r20 = UINT64_C(0x1122334455667788);
            uint64_t r31 = UINT64_C(0xdeadbeefcafef00d);
            uint64_t memory = UINT64_C(0xa5b6c7d8e9fa1020);
            uint64_t rflags = test_x86_apx_setcc_flags(4, true);
            const uint64_t initial_rflags = rflags;
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                code_size);
            if (protected_page) {
                OK(uc_mem_map(uc, page, 0x1000, UC_PROT_ALL));
                OK(uc_mem_write(uc, page, &memory, sizeof(memory)));
                OK(uc_mem_protect(uc, page, 0x1000,
                                  store ? UC_PROT_READ : UC_PROT_WRITE));
            }
            OK(uc_reg_write(uc, UC_X86_REG_R29, &r29));
            OK(uc_reg_write(uc, UC_X86_REG_R20, &r20));
            OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            err = uc_emu_start(uc, code_start, code_start + code_size, 0, 0);
            OK(uc_reg_read(uc, UC_X86_REG_R20, &r20));
            OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            if (protected_page) {
                OK(uc_mem_read(uc, page, &memory, sizeof(memory)));
            }

            TEST_CHECK_(err == expected_error,
                        "selected memory CMOVcc fault returned %s",
                        uc_strerror(err));
            TEST_CHECK(r20 == UINT64_C(0x1122334455667788));
            TEST_CHECK(r31 == UINT64_C(0xdeadbeefcafef00d));
            TEST_CHECK(!protected_page ||
                       memory == UINT64_C(0xa5b6c7d8e9fa1020));
            TEST_CHECK(rflags == initial_rflags);
            TEST_CHECK(rip == code_start);
            OK(uc_close(uc));
        }
    }

    /* Only architectural RSP/RBP bases select SS.  Their extended-register
     * aliases retain the default DS classification. */
    for (size_t segment_case = 0;
         segment_case < sizeof(test_x86_apx_default_segment_cases) /
                            sizeof(test_x86_apx_default_segment_cases[0]);
         ++segment_case) {
        for (unsigned int suppress = 0; suppress < 2; ++suppress) {
            const TestX86ApxDefaultSegmentCase *segment =
                &test_x86_apx_default_segment_cases[segment_case];
            const unsigned int base = segment->base;
            const unsigned int source_reg = base == 20 ? 19 : 20;
            const bool nf = suppress != 0;
            uint8_t code[9];
            const size_t code_size = test_x86_apx_encode_cmov_memory(
                code, 0, 4, 8, true, nf, source_reg, 31, base, -1, 0, 0);
            uint64_t base_value = UINT64_C(0x0000800000000000);
            uint64_t source = UINT64_C(0x1122334455667788);
            uint64_t r31 = UINT64_C(0xdeadbeefcafef00d);
            uint64_t rflags = test_x86_apx_setcc_flags(4, false);
            uint64_t rip = 0;
            TestX86ApxPairException record = {0};
            uc_engine *uc;
            uc_hook hook;

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                code_size);
            OK(uc_reg_write(uc, test_x86_apx_full_register(base),
                            &base_value));
            OK(uc_reg_write(uc, test_x86_apx_full_register(source_reg),
                            &source));
            OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_hook_add(uc, &hook, UC_HOOK_INTR,
                           test_x86_apx_pair_record_exception, &record, 1,
                           0));
            OK(uc_emu_start(uc, code_start, 0, 0, 1));
            OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

            if (suppress) {
                TEST_CHECK(record.count == 0);
                TEST_CHECK(r31 == source);
                TEST_CHECK(rip == code_start + code_size);
            } else {
                TEST_CHECK_(record.count == 1 &&
                                record.intno == segment->exception,
                            "CMOVcc %s raised canonicality exception %u",
                            segment->name, record.intno);
                TEST_CHECK(r31 == UINT64_C(0xdeadbeefcafef00d));
                TEST_CHECK(rip == code_start);
            }
            OK(uc_close(uc));
        }
    }
}

static void test_x86_apx_evex_encode_alu(
    uint8_t code[6], const TestX86ApxEvexAlu *operation, uint8_t width,
    bool reverse, bool nd, bool nf, unsigned int destination_number,
    unsigned int source1_number, unsigned int source2_number)
{
    const unsigned int reg_number = reverse ? source1_number : source2_number;
    const unsigned int rm_number = reverse ? source2_number : source1_number;
    const unsigned int ndd_number = nd ? destination_number : 0;
    const uint8_t opcode =
        operation->base_opcode + (reverse ? 2 : 0) + (width == 1 ? 0 : 1);
    const uint8_t pp = width == 2 ? 1 : 0;
    const uint8_t w = width == 8 ? 0x80 : 0;

    code[0] = 0x62;
    code[1] = 0x44 | ((reg_number & 8) ? 0 : 0x80) |
              ((rm_number & 8) ? 0 : 0x20) | ((reg_number & 16) ? 0 : 0x10) |
              ((rm_number & 16) ? 0x08 : 0);
    code[2] = w | (((~ndd_number) & 0xf) << 3) | 0x04 | pp;
    code[3] =
        (nd ? 0x10 : 0) | (nf ? 0x04 : 0) | ((ndd_number & 16) ? 0 : 0x08);
    code[4] = opcode;
    code[5] = 0xc0 | ((reg_number & 7) << 3) | (rm_number & 7);
}

static uint64_t test_x86_apx_evex_expected_flags(TestX86ApxEvexAluOp operation,
                                                 uint8_t width)
{
    switch (operation) {
    case TEST_X86_APX_EVEX_ADD:
        return width == 1 ? UINT64_C(0xa92) : UINT64_C(0xa96);
    case TEST_X86_APX_EVEX_OR:
        return width == 1 ? UINT64_C(0x286) : UINT64_C(0x206);
    case TEST_X86_APX_EVEX_AND:
    case TEST_X86_APX_EVEX_XOR:
        return UINT64_C(0x246);
    case TEST_X86_APX_EVEX_SUB:
        return UINT64_C(0x297);
    default:
        TEST_CHECK_(false, "invalid APX EVEX ALU operation %u", operation);
        return 0;
    }
}

static void test_x86_apx_evex_alu_register_semantics(void)
{
    static const TestX86ApxEvexAlu operations[] = {
        {TEST_X86_APX_EVEX_ADD, 0x00, "ADD"},
        {TEST_X86_APX_EVEX_OR, 0x08, "OR"},
        {TEST_X86_APX_EVEX_AND, 0x20, "AND"},
        {TEST_X86_APX_EVEX_SUB, 0x28, "SUB"},
        {TEST_X86_APX_EVEX_XOR, 0x30, "XOR"},
    };
    static const uint8_t widths[] = {1, 2, 4, 8};
    const uint64_t destination_pattern = UINT64_C(0x3c3c3c3c3c3c3c3c);

    {
        static const uint8_t high_ndd_nf_add[] = {
            0x62, 0x4c, 0x84, 0x14, 0x01, 0xee,
        };
        static const uint8_t high_nf_sub[] = {
            0x62, 0xec, 0x7c, 0x0c, 0x29, 0xc8,
        };
        static const uint8_t high_ndd_nf_or[] = {
            0x62, 0x4c, 0x04, 0x14, 0x08, 0xee,
        };
        static const uint8_t high_ndd_and[] = {
            0x62, 0x4c, 0x05, 0x10, 0x21, 0xee,
        };
        static const uint8_t high_ndd_nf_xor[] = {
            0x62, 0x4c, 0x04, 0x14, 0x31, 0xee,
        };
        static const struct {
            size_t operation_index;
            uint8_t width;
            bool nd;
            bool nf;
            unsigned int destination;
            unsigned int source1;
            unsigned int source2;
            const uint8_t *expected;
        } anchors[] = {
            {0, 8, true, true, 31, 30, 29, high_ndd_nf_add},
            {3, 4, false, true, 16, 16, 17, high_nf_sub},
            {1, 1, true, true, 31, 30, 29, high_ndd_nf_or},
            {2, 2, true, false, 31, 30, 29, high_ndd_and},
            {4, 4, true, true, 31, 30, 29, high_ndd_nf_xor},
        };

        for (size_t i = 0; i < sizeof(anchors) / sizeof(anchors[0]); ++i) {
            uint8_t code[6];

            test_x86_apx_evex_encode_alu(
                code, &operations[anchors[i].operation_index], anchors[i].width,
                false, anchors[i].nd, anchors[i].nf, anchors[i].destination,
                anchors[i].source1, anchors[i].source2);
            TEST_CHECK_(memcmp(code, anchors[i].expected, sizeof(code)) == 0,
                        "%s encoding anchor mismatch",
                        operations[anchors[i].operation_index].name);
        }
    }

    for (size_t operation_index = 0;
         operation_index < sizeof(operations) / sizeof(operations[0]);
         ++operation_index) {
        const TestX86ApxEvexAlu *operation = &operations[operation_index];

        for (size_t width_index = 0;
             width_index < sizeof(widths) / sizeof(widths[0]); ++width_index) {
            const uint8_t width = widths[width_index];
            const uint64_t width_mask =
                width == 8 ? UINT64_MAX : (UINT64_C(1) << (width * 8)) - 1;
            uint64_t left;
            uint64_t right;
            uint64_t result;

            switch (operation->operation) {
            case TEST_X86_APX_EVEX_ADD:
                left = width_mask >> 1;
                right = 1;
                result = UINT64_C(1) << (width * 8 - 1);
                break;
            case TEST_X86_APX_EVEX_OR:
                left = 0;
                right = 0x81;
                result = 0x81;
                break;
            case TEST_X86_APX_EVEX_AND:
                left = 0;
                right = 0x81;
                result = 0;
                break;
            case TEST_X86_APX_EVEX_SUB:
                left = 0;
                right = 1;
                result = width_mask;
                break;
            case TEST_X86_APX_EVEX_XOR:
                left = 0x81;
                right = 0x81;
                result = 0;
                break;
            default:
                TEST_CHECK_(false, "invalid APX EVEX operation");
                return;
            }

            for (unsigned int reverse = 0; reverse < 2; ++reverse) {
                for (unsigned int nd = 0; nd < 2; ++nd) {
                    for (unsigned int nf = 0; nf < 2; ++nf) {
                        for (unsigned int seed = 0; seed < 32; ++seed) {
                            const unsigned int destination_number = seed;
                            const unsigned int source1_number =
                                nd ? (seed + 11) & 31 : seed;
                            const unsigned int source2_number =
                                (seed + 23) & 31;
                            const uc_x86_reg destination_reg =
                                test_x86_apx_full_register(destination_number);
                            const uc_x86_reg source1_reg =
                                test_x86_apx_full_register(source1_number);
                            const uc_x86_reg source2_reg =
                                test_x86_apx_full_register(source2_number);
                            const uint64_t source1_initial =
                                (UINT64_C(0xa5a5a5a5a5a5a5a5) & ~width_mask) |
                                left;
                            const uint64_t source2_initial =
                                (UINT64_C(0x5a5a5a5a5a5a5a5a) & ~width_mask) |
                                right;
                            const uint64_t destination_initial =
                                nd ? destination_pattern : source1_initial;
                            const uint64_t expected_destination =
                                width == 8 ? result
                                : width == 4
                                    ? result & UINT32_MAX
                                    : (destination_initial & ~width_mask) |
                                          result;
                            const uint64_t initial_rflags =
                                nf ? UINT64_C(0xcd7) : UINT64_C(0x202);
                            const uint64_t expected_rflags =
                                nf ? initial_rflags
                                   : test_x86_apx_evex_expected_flags(
                                         operation->operation, width);
                            uint8_t code[6];
                            uint64_t destination = destination_initial;
                            uint64_t source1 = source1_initial;
                            uint64_t source2 = source2_initial;
                            uint64_t rflags = initial_rflags;
                            uint64_t rip = 0;
                            uc_engine *uc;
                            uc_err err;

                            test_x86_apx_evex_encode_alu(
                                code, operation, width, reverse, nd, nf,
                                destination_number, source1_number,
                                source2_number);
                            uc_common_setup_cpu(&uc, UC_MODE_64,
                                                UC_CPU_X86_APX, code,
                                                sizeof(code));
                            if (nd) {
                                OK(uc_reg_write(uc, destination_reg,
                                                &destination));
                            }
                            OK(uc_reg_write(uc, source1_reg, &source1));
                            OK(uc_reg_write(uc, source2_reg, &source2));
                            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

                            err = uc_emu_start(uc, code_start,
                                               code_start + sizeof(code), 0, 0);
                            if (err != UC_ERR_OK) {
                                TEST_CHECK_(
                                    false,
                                    "%s width %u reverse=%u ND=%u NF=%u "
                                    "R%u/R%u/R%u failed: %s",
                                    operation->name, width, reverse, nd, nf,
                                    destination_number, source1_number,
                                    source2_number, uc_strerror(err));
                                OK(uc_close(uc));
                                return;
                            }
                            OK(uc_reg_read(uc, destination_reg, &destination));
                            OK(uc_reg_read(uc, source1_reg, &source1));
                            OK(uc_reg_read(uc, source2_reg, &source2));
                            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
                            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

                            TEST_CHECK_(
                                destination == expected_destination,
                                "%s width %u reverse=%u ND=%u NF=%u R%u "
                                "result 0x%" PRIx64 ", expected 0x%" PRIx64,
                                operation->name, width, reverse, nd, nf,
                                destination_number, destination,
                                expected_destination);
                            TEST_CHECK_(source1 == (nd ? source1_initial
                                                       : expected_destination),
                                        "%s width %u ND=%u changed source1 R%u",
                                        operation->name, width, nd,
                                        source1_number);
                            TEST_CHECK_(source2 == source2_initial,
                                        "%s width %u changed source2 R%u",
                                        operation->name, width, source2_number);
                            TEST_CHECK_(rflags == expected_rflags,
                                        "%s width %u reverse=%u ND=%u NF=%u "
                                        "RFLAGS 0x%" PRIx64
                                        ", expected 0x%" PRIx64,
                                        operation->name, width, reverse, nd, nf,
                                        rflags, expected_rflags);
                            TEST_CHECK_(rip == code_start + sizeof(code),
                                        "%s did not advance RIP",
                                        operation->name);
                            OK(uc_close(uc));
                        }
                    }
                }
            }
        }
    }

    {
        static const uint8_t code[] = {
            0x48, 0x39, 0xc0,                   /* cmp rax, rax */
            0x62, 0xf4, 0x7c, 0x0c, 0x00, 0xd9, /* {nf} add cl, bl */
        };
        uint64_t rax = UINT64_C(0x123456789abcdef0);
        uint64_t rcx = UINT64_C(0xaaaaaaaaaaaaaa00);
        uint64_t rbx = UINT64_C(0xbbbbbbbbbbbbbb01);
        uint64_t rflags = UINT64_C(0x202);
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
        OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

        TEST_CHECK(rcx == UINT64_C(0xaaaaaaaaaaaaaa01));
        TEST_CHECK_(rflags == UINT64_C(0x246),
                    "NF did not preserve prior lazy RFLAGS");
        OK(uc_close(uc));
    }
}

static void test_x86_apx_ccmp_ctest_register_semantics(void)
{
    static const struct {
        uint8_t code[6];
        uint64_t rcx;
        uint64_t rbx;
        uint64_t initial_rflags;
        uint64_t expected_rflags;
        const char *name;
    } cases[] = {
        /* CCMPB.S is true because SF is set.  CL-BL is 0x10-0x20, so the
         * computed status is CF|PF|SF with no AF/ZF/OF. */
        {{0x62, 0xf4, 0x7c, 0x08, 0x38, 0xd9},
         UINT64_C(0x1122334455667710), UINT64_C(0x8877665544332220),
         UINT64_C(0x282), UINT64_C(0x287), "CCMPB true condition"},
        /* CTESTQ.F is always false.  DFV=0xa selects OF|ZF rather than the
         * flags from RCX&RBX. */
        {{0x62, 0xf4, 0xd4, 0x0b, 0x85, 0xd9},
         UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210),
         UINT64_C(0x202), UINT64_C(0xa42), "CTESTQ false condition"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t rcx = cases[i].rcx;
        uint64_t rbx = cases[i].rbx;
        uint64_t rflags = cases[i].initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX,
                            cases[i].code, sizeof(cases[i].code));
        OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
        OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err = uc_emu_start(uc, code_start,
                           code_start + sizeof(cases[i].code), 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx));
        OK(uc_reg_read(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == UC_ERR_OK, "%s returned %s", cases[i].name,
                    uc_strerror(err));
        TEST_CHECK_(rcx == cases[i].rcx && rbx == cases[i].rbx,
                    "%s changed a GPR operand", cases[i].name);
        TEST_CHECK_(rflags == cases[i].expected_rflags,
                    "%s produced RFLAGS 0x%" PRIx64, cases[i].name,
                    rflags);
        TEST_CHECK_(rip == code_start + sizeof(cases[i].code),
                    "%s did not advance RIP", cases[i].name);
        OK(uc_close(uc));
    }
}

static void test_x86_apx_evex_alu_invalid_forms(void)
{
    static const struct {
        uint8_t code[7];
        size_t code_size;
        const char *description;
    } cases[] = {
        {{0x62, 0xf4, 0x7c, 0x88, 0x00, 0xd9}, 6, "reserved EVEX.z"},
        {{0x62, 0xf4, 0x7c, 0x48, 0x00, 0xd9}, 6, "reserved EVEX.L1"},
        {{0x62, 0xf4, 0x7c, 0x28, 0x00, 0xd9}, 6, "reserved EVEX.L0"},
        {{0x62, 0xf4, 0x7c, 0x0a, 0x00, 0xd9}, 6, "reserved EVEX.aaa bit1"},
        {{0x62, 0xf4, 0x7c, 0x09, 0x00, 0xd9}, 6, "reserved EVEX.aaa bit0"},
        {{0x62, 0xf4, 0x78, 0x08, 0x00, 0xd9}, 6, "EVEX.U clear"},
        {{0x62, 0xf4, 0x74, 0x08, 0x00, 0xd9}, 6, "ND=0 with vvvv"},
        {{0x62, 0xf4, 0x7c, 0x00, 0x00, 0xd9}, 6, "ND=0 with V4"},
        {{0x62, 0xf4, 0x7d, 0x08, 0x00, 0xd9}, 6, "byte form with 66 pp"},
        {{0x62, 0xf4, 0x7e, 0x08, 0x00, 0xd9}, 6, "byte form with F3 pp"},
        {{0x62, 0xf4, 0x7f, 0x08, 0x00, 0xd9}, 6, "byte form with F2 pp"},
        {{0x62, 0xf4, 0x7e, 0x08, 0x01, 0xd9}, 6, "scalable form with F3 pp"},
        {{0x62, 0xf4, 0x7f, 0x08, 0x01, 0xd9}, 6, "scalable form with F2 pp"},
        {{0x62, 0xf4, 0x7c, 0x08, 0x00, 0x19}, 6, "memory form"},
        {{0x62, 0xf4, 0x7c, 0x08, 0x80, 0xd9}, 6, "immediate-group opcode"},
        {{0x62, 0xf4, 0x7c, 0x08, 0xfc, 0xd9}, 6, "uncovered map4 opcode"},
        {{0x66, 0x62, 0xf4, 0x7c, 0x08, 0x00, 0xd9},
         7,
         "preceding operand-size prefix"},
        {{0xf0, 0x62, 0xf4, 0x7c, 0x08, 0x00, 0xd9},
         7,
         "preceding LOCK prefix"},
        {{0xf2, 0x62, 0xf4, 0x7c, 0x08, 0x00, 0xd9},
         7,
         "preceding REPNE prefix"},
        {{0xf3, 0x62, 0xf4, 0x7c, 0x08, 0x00, 0xd9}, 7, "preceding REP prefix"},
        {{0x40, 0x62, 0xf4, 0x7c, 0x08, 0x00, 0xd9}, 7, "preceding REX prefix"},
        {{0x48, 0x62, 0xf4, 0x7c, 0x08, 0x00, 0xd9},
         7,
         "preceding REX.W prefix"},
    };
    const uint64_t initial_rax = UINT64_C(0x1111111111111111);
    const uint64_t initial_rcx = code_start + 0x600;
    const uint64_t initial_rbx = UINT64_C(0x3333333333333333);
    const uint64_t initial_r31 = UINT64_C(0x3131313131313131);
    const uint64_t initial_memory = UINT64_C(0xfedcba9876543210);
    const uint64_t initial_rflags = UINT64_C(0xcd7);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t rax = initial_rax;
        uint64_t rcx = initial_rcx;
        uint64_t rbx = initial_rbx;
        uint64_t r31 = initial_r31;
        uint64_t memory = initial_memory;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, cases[i].code,
                            cases[i].code_size);
        OK(uc_mem_write(uc, initial_rcx, &memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
        OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err =
            uc_emu_start(uc, code_start, code_start + cases[i].code_size, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx));
        OK(uc_reg_read(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
        OK(uc_mem_read(uc, initial_rcx, &memory, sizeof(memory)));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    cases[i].description);
        TEST_CHECK_(rax == initial_rax && rcx == initial_rcx &&
                        rbx == initial_rbx && r31 == initial_r31,
                    "%s changed GPR state", cases[i].description);
        TEST_CHECK_(memory == initial_memory, "%s changed memory",
                    cases[i].description);
        TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                    cases[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP", cases[i].description);
        OK(uc_close(uc));
    }
}

static void test_x86_apx_register_roundtrip_and_reset(void)
{
    static const uint8_t code[] = {0x90};
    uc_engine *uc;
    uc_context *context;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                        sizeof(code));
    for (int reg = 0; reg < 16; ++reg) {
        uint64_t written = UINT64_C(0x1020304050607080) ^ ((uint64_t)reg << 40);
        uint64_t observed = 0;

        OK(uc_reg_write(uc, UC_X86_REG_R16 + reg, &written));
        OK(uc_reg_read(uc, UC_X86_REG_R16 + reg, &observed));
        TEST_CHECK_(observed == written, "R%d did not round-trip", reg + 16);
    }
    OK(uc_context_alloc(uc, &context));
    OK(uc_context_save(uc, context));
    for (int reg = 0; reg < 16; ++reg) {
        uint64_t cleared = 0;
        OK(uc_reg_write(uc, UC_X86_REG_R16 + reg, &cleared));
    }
    OK(uc_context_restore(uc, context));
    for (int reg = 0; reg < 16; ++reg) {
        const uint64_t expected =
            UINT64_C(0x1020304050607080) ^ ((uint64_t)reg << 40);
        uint64_t observed = 0;

        OK(uc_reg_read(uc, UC_X86_REG_R16 + reg, &observed));
        TEST_CHECK_(observed == expected, "R%d was not restored from context",
                    reg + 16);
    }
    OK(uc_context_free(context));
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                        sizeof(code));
    for (int reg = 0; reg < 16; ++reg) {
        uint64_t observed = UINT64_MAX;

        OK(uc_reg_read(uc, UC_X86_REG_R16 + reg, &observed));
        TEST_CHECK_(observed == 0, "R%d was not reset", reg + 16);
    }
    OK(uc_close(uc));
}

static void test_x86_apx_subregister_api_semantics(void)
{
    static const uint8_t code[] = {0x90};
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                        sizeof(code));
    for (int reg = 0; reg < 16; ++reg) {
        uint64_t full = UINT64_C(0x8877665544332211);
        uint64_t observed_full = 0;
        uint32_t dword = UINT32_C(0xa1b2c3d4);
        uint32_t observed_dword = 0;
        uint16_t word = UINT16_C(0xe5f6);
        uint16_t observed_word = 0;
        uint8_t byte = UINT8_C(0x7a);
        uint8_t observed_byte = 0;

        OK(uc_reg_write(uc, UC_X86_REG_R16 + reg, &full));
        OK(uc_reg_read(uc, UC_X86_REG_R16B + reg, &observed_byte));
        OK(uc_reg_read(uc, UC_X86_REG_R16W + reg, &observed_word));
        OK(uc_reg_read(uc, UC_X86_REG_R16D + reg, &observed_dword));
        TEST_CHECK(observed_byte == UINT8_C(0x11));
        TEST_CHECK(observed_word == UINT16_C(0x2211));
        TEST_CHECK(observed_dword == UINT32_C(0x44332211));

        OK(uc_reg_write(uc, UC_X86_REG_R16B + reg, &byte));
        OK(uc_reg_read(uc, UC_X86_REG_R16 + reg, &observed_full));
        TEST_CHECK(observed_full == UINT64_C(0x887766554433227a));

        OK(uc_reg_write(uc, UC_X86_REG_R16W + reg, &word));
        OK(uc_reg_read(uc, UC_X86_REG_R16 + reg, &observed_full));
        TEST_CHECK(observed_full == UINT64_C(0x887766554433e5f6));

        OK(uc_reg_write(uc, UC_X86_REG_R16D + reg, &dword));
        OK(uc_reg_read(uc, UC_X86_REG_R16 + reg, &observed_full));
        TEST_CHECK(observed_full == UINT64_C(0x00000000a1b2c3d4));
    }
    OK(uc_close(uc));
}

static void test_x86_apx_rex2_mov_widths_and_directions(void)
{
    static const struct {
        uint8_t code[5];
        size_t code_size;
        bool reverse;
        uint64_t expected_destination;
        const char *description;
    } cases[] = {
        {{0xd5, 0x55, 0x88, 0xc7},
         4,
         false,
         UINT64_C(0xfedcba98765432ef),
         "mov r31b, r24b"},
        {{0x66, 0xd5, 0x55, 0x89, 0xc7},
         5,
         false,
         UINT64_C(0xfedcba987654cdef),
         "mov r31w, r24w"},
        {{0xd5, 0x55, 0x89, 0xc7},
         4,
         false,
         UINT64_C(0x0000000089abcdef),
         "mov r31d, r24d"},
        {{0xd5, 0x5d, 0x89, 0xc7},
         4,
         false,
         UINT64_C(0x0123456789abcdef),
         "mov r31, r24"},
        {{0xd5, 0x55, 0x8a, 0xc7},
         4,
         true,
         UINT64_C(0x0123456789abcd10),
         "mov r24b, r31b"},
        {{0x66, 0xd5, 0x55, 0x8b, 0xc7},
         5,
         true,
         UINT64_C(0x0123456789ab3210),
         "mov r24w, r31w"},
        {{0xd5, 0x55, 0x8b, 0xc7},
         4,
         true,
         UINT64_C(0x0000000076543210),
         "mov r24d, r31d"},
        {{0xd5, 0x5d, 0x8b, 0xc7},
         4,
         true,
         UINT64_C(0xfedcba9876543210),
         "mov r24, r31"},
    };
    const uint64_t initial_r24 = UINT64_C(0x0123456789abcdef);
    const uint64_t initial_r31 = UINT64_C(0xfedcba9876543210);
    const uint64_t initial_rflags = UINT64_C(0xcd7);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t r24 = initial_r24;
        uint64_t r31 = initial_r31;
        uint64_t rflags = initial_rflags;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, cases[i].code,
                            cases[i].code_size);
        OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + cases[i].code_size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

        TEST_CHECK_(cases[i].reverse ? r24 == cases[i].expected_destination
                                     : r31 == cases[i].expected_destination,
                    "%s produced the wrong destination", cases[i].description);
        TEST_CHECK_(cases[i].reverse ? r31 == initial_r31 : r24 == initial_r24,
                    "%s changed its source", cases[i].description);
        TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                    cases[i].description);
        OK(uc_close(uc));
    }
}

static void test_x86_apx_rex2_mov_memory_widths_and_directions(void)
{
    static const uint8_t widths[] = {1, 2, 4, 8};
    static const uint64_t expected_loads[] = {
        UINT64_C(0x0123456789abcd10),
        UINT64_C(0x0123456789ab3210),
        UINT64_C(0x0000000076543210),
        UINT64_C(0xfedcba9876543210),
    };
    static const uint64_t expected_stores[] = {
        UINT64_C(0xfedcba98765432ef),
        UINT64_C(0xfedcba987654cdef),
        UINT64_C(0xfedcba9889abcdef),
        UINT64_C(0x0123456789abcdef),
    };
    const uint64_t data_address = code_start + 0x800;
    const uint64_t source = UINT64_C(0x0123456789abcdef);
    const uint64_t initial_memory = UINT64_C(0xfedcba9876543210);

    for (size_t width_index = 0;
         width_index < sizeof(widths) / sizeof(widths[0]); ++width_index) {
        const uint8_t width = widths[width_index];

        for (unsigned int load = 0; load < 2; ++load) {
            uint8_t code[5];
            size_t code_size = 0;
            uint64_t r24 = source;
            uint64_t r25 = data_address;
            uint64_t memory = initial_memory;
            uint64_t rflags = UINT64_C(0xcd7);
            uc_engine *uc;

            if (width == 2) {
                code[code_size++] = 0x66;
            }
            code[code_size++] = 0xd5;
            code[code_size++] = width == 8 ? 0x5d : 0x55;
            code[code_size++] =
                width == 1 ? (load ? 0x8a : 0x88) : (load ? 0x8b : 0x89);
            code[code_size++] = 0x01;

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                code_size);
            OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
            OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
            OK(uc_reg_write(uc, UC_X86_REG_R25, &r25));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
            OK(uc_reg_read(uc, UC_X86_REG_R25, &r25));
            OK(uc_mem_read(uc, data_address, &memory, sizeof(memory)));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

            TEST_CHECK_(load ? r24 == expected_loads[width_index]
                             : r24 == source,
                        "MOV memory width %u direction %u register mismatch",
                        width, load);
            TEST_CHECK_(load ? memory == initial_memory
                             : memory == expected_stores[width_index],
                        "MOV memory width %u direction %u memory mismatch",
                        width, load);
            TEST_CHECK_(r25 == data_address,
                        "MOV memory width %u changed its base", width);
            TEST_CHECK_(rflags == UINT64_C(0xcd7),
                        "MOV memory width %u changed RFLAGS", width);
            OK(uc_close(uc));
        }
    }
}

static void test_x86_apx_rex2_memory_addressing_forms(void)
{
    static const struct {
        uint8_t code[9];
        size_t code_size;
        uint64_t data_address;
        uint64_t r25;
        uint64_t r26;
        uint64_t r28;
        uint64_t fs_base;
        const char *description;
    } cases[] = {
        {{0xd5, 0x7f, 0x8b, 0x44, 0x91, 0x20},
         6,
         0x2000,
         0x1800,
         0x1f8,
         0,
         0,
         "R25 base plus scaled R26 index and disp8"},
        {{0xd5, 0x7f, 0x8b, 0x04, 0x61},
         5,
         0x2000,
         0x1800,
         0,
         0x400,
         0,
         "extended raw-index-four R28"},
        {{0xd5, 0x5d, 0x8b, 0x81, 0x00, 0x01, 0x00, 0x00},
         8,
         0x2000,
         0x1f00,
         0,
         0,
         0,
         "R25 base plus disp32"},
        {{0xd5, 0x7f, 0x8b, 0x04, 0x95, 0x00, 0x10, 0x00, 0x00},
         9,
         0x2000,
         UINT64_MAX,
         0x400,
         0,
         0,
         "SIB no-base disp32 with ignored B extensions"},
        {{0xd5, 0x5d, 0x8b, 0x05, 0xf8, 0x0b, 0x00, 0x00},
         8,
         0x1c00,
         UINT64_MAX,
         0,
         0,
         0,
         "RIP-relative disp32 with ignored B extensions"},
        {{0x67, 0xd5, 0x5d, 0x8b, 0x01},
         5,
         0x2000,
         UINT64_C(0x1234567800002000),
         0,
         0,
         0,
         "addr32 extended base truncation"},
        {{0x67, 0xd5, 0x5d, 0x8b, 0x05, 0x00, 0x20, 0x00, 0x00},
         9,
         0x3009,
         UINT64_MAX,
         0,
         0,
         0,
         "addr32 truncated RIP-relative disp32"},
        {{0x64, 0xd5, 0x5d, 0x8b, 0x01},
         5,
         0x2000,
         0x800,
         0,
         0,
         0x1800,
         "FS segment override"},
    };
    const uint64_t value = UINT64_C(0x8877665544332211);
    const uint64_t stored_value = UINT64_C(0x1020304050607080);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        for (unsigned int load = 0; load < 2; ++load) {
            uint8_t code[sizeof(cases[i].code)];
            size_t opcode_offset = 0;
            uint64_t memory = value;
            uint64_t r24 = load ? UINT64_C(0xfedcba9876543210) : stored_value;
            uint64_t r25 = cases[i].r25;
            uint64_t r26 = cases[i].r26;
            uint64_t r28 = cases[i].r28;
            uint64_t fs_base = cases[i].fs_base;
            uint64_t rflags = UINT64_C(0xcd7);
            uc_engine *uc;

            memcpy(code, cases[i].code, cases[i].code_size);
            while (opcode_offset < cases[i].code_size &&
                   code[opcode_offset] != 0x8b) {
                opcode_offset++;
            }
            TEST_CHECK(opcode_offset < cases[i].code_size);
            if (!load) {
                code[opcode_offset] = 0x89;
            }

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                cases[i].code_size);
            OK(uc_mem_write(uc, cases[i].data_address, &memory,
                            sizeof(memory)));
            OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
            OK(uc_reg_write(uc, UC_X86_REG_R25, &r25));
            OK(uc_reg_write(uc, UC_X86_REG_R26, &r26));
            OK(uc_reg_write(uc, UC_X86_REG_R28, &r28));
            OK(uc_reg_write(uc, UC_X86_REG_FS_BASE, &fs_base));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_emu_start(uc, code_start, code_start + cases[i].code_size, 0,
                            0));
            OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
            OK(uc_reg_read(uc, UC_X86_REG_R25, &r25));
            OK(uc_reg_read(uc, UC_X86_REG_R26, &r26));
            OK(uc_reg_read(uc, UC_X86_REG_R28, &r28));
            OK(uc_reg_read(uc, UC_X86_REG_FS_BASE, &fs_base));
            OK(uc_mem_read(uc, cases[i].data_address, &memory, sizeof(memory)));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

            TEST_CHECK_(load ? r24 == value : r24 == stored_value,
                        "%s direction %u register mismatch",
                        cases[i].description, load);
            TEST_CHECK_(load ? memory == value : memory == stored_value,
                        "%s direction %u used the wrong address",
                        cases[i].description, load);
            TEST_CHECK_(r25 == cases[i].r25 && r26 == cases[i].r26 &&
                            r28 == cases[i].r28,
                        "%s changed an address register", cases[i].description);
            TEST_CHECK_(fs_base == cases[i].fs_base, "%s changed FS base",
                        cases[i].description);
            TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS",
                        cases[i].description);
            OK(uc_close(uc));
        }
    }
}

static void test_x86_apx_rex2_extended_address_register_matrix(void)
{
    const uint64_t data_address = code_start + 0x1800;
    const uint64_t value = UINT64_C(0x8877665544332211);
    const uint64_t initial_rflags = UINT64_C(0xcd7);

    for (int reg = 16; reg < 32; ++reg) {
        uint8_t code[6] = {0xd5, 0x08, 0x8b};
        size_t code_size;
        uint64_t base = data_address;
        uint64_t rax = 0;
        uint64_t rflags = initial_rflags;
        uc_engine *uc;

        code[1] |= (reg & 8) ? 0x01 : 0;
        code[1] |= (reg & 16) ? 0x10 : 0;
        if ((reg & 7) == 4) {
            code[3] = 0x44;
            code[4] = 0x24;
            code[5] = 0;
            code_size = 6;
        } else {
            code[3] = 0x40 | (reg & 7);
            code[4] = 0;
            code_size = 5;
        }

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            code_size);
        OK(uc_mem_write(uc, data_address, &value, sizeof(value)));
        OK(uc_reg_write(uc, UC_X86_REG_R16 + reg - 16, &base));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_R16 + reg - 16, &base));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

        TEST_CHECK_(rax == value, "R%d base addressed the wrong memory", reg);
        TEST_CHECK_(base == data_address, "R%d base was changed", reg);
        TEST_CHECK(rflags == initial_rflags);
        OK(uc_close(uc));
    }

    for (int reg = 16; reg < 32; ++reg) {
        uint8_t code[] = {0xd5, 0x08, 0x8b, 0x04, 0x83};
        const uint64_t index_value = UINT64_C(0x20);
        uint64_t index = index_value;
        uint64_t rbx = data_address - index_value * 4;
        uint64_t rax = 0;
        uint64_t rflags = initial_rflags;
        uc_engine *uc;

        code[1] |= (reg & 8) ? 0x02 : 0;
        code[1] |= (reg & 16) ? 0x20 : 0;
        code[4] = 0x80 | ((reg & 7) << 3) | 3;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_mem_write(uc, data_address, &value, sizeof(value)));
        OK(uc_reg_write(uc, UC_X86_REG_R16 + reg - 16, &index));
        OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_R16 + reg - 16, &index));
        OK(uc_reg_read(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

        TEST_CHECK_(rax == value, "R%d index addressed the wrong memory", reg);
        TEST_CHECK_(index == index_value, "R%d index was changed", reg);
        TEST_CHECK_(rbx == data_address - index_value * 4,
                    "R%d index changed its base", reg);
        TEST_CHECK(rflags == initial_rflags);
        OK(uc_close(uc));
    }
}

typedef struct TestX86ApxWriteRepair {
    uc_mem_type expected_type;
    uint64_t page;
    unsigned int calls;
    uint64_t address;
    int size;
    uint64_t value;
} TestX86ApxWriteRepair;

static bool test_x86_apx_repair_cross_page_write(uc_engine *uc,
                                                 uc_mem_type type,
                                                 uint64_t address, int size,
                                                 uint64_t value,
                                                 void *user_data)
{
    TestX86ApxWriteRepair *repair = user_data;

    repair->calls++;
    repair->address = address;
    repair->size = size;
    repair->value = value;
    if (type != repair->expected_type || address != repair->page) {
        return false;
    }
    if (type == UC_MEM_WRITE_UNMAPPED) {
        return uc_mem_map(uc, repair->page, 0x1000, UC_PROT_ALL) == UC_ERR_OK;
    }
    return uc_mem_protect(uc, repair->page, 0x1000, UC_PROT_ALL) == UC_ERR_OK;
}

static void test_x86_apx_rex2_memory_faults_are_atomic(void)
{
    static const struct {
        uint8_t code[4];
        uc_err expected_error;
        const char *description;
    } unmapped_cases[] = {
        {{0xd5, 0x5d, 0x8b, 0x01}, UC_ERR_READ_UNMAPPED, "MOV memory load"},
        {{0xd5, 0x5d, 0x89, 0x01}, UC_ERR_WRITE_UNMAPPED, "MOV memory store"},
        {{0xd5, 0x5d, 0x03, 0x01},
         UC_ERR_READ_UNMAPPED,
         "ADD register destination"},
        {{0xd5, 0x5d, 0x01, 0x01},
         UC_ERR_READ_UNMAPPED,
         "ADD memory destination read"},
    };
    const uint64_t unmapped = UINT64_C(0x8000);
    const uint64_t initial_r24 = UINT64_C(0x7fffffffffffffff);
    const uint64_t initial_rflags = UINT64_C(0xcd7);

    for (size_t i = 0; i < sizeof(unmapped_cases) / sizeof(unmapped_cases[0]);
         ++i) {
        uint64_t r24 = initial_r24;
        uint64_t r25 = unmapped;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX,
                            unmapped_cases[i].code,
                            sizeof(unmapped_cases[i].code));
        OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_write(uc, UC_X86_REG_R25, &r25));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        err = uc_emu_start(uc, code_start,
                           code_start + sizeof(unmapped_cases[i].code), 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_read(uc, UC_X86_REG_R25, &r25));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == unmapped_cases[i].expected_error, "%s returned %s",
                    unmapped_cases[i].description, uc_strerror(err));
        TEST_CHECK_(r24 == initial_r24 && r25 == unmapped,
                    "%s changed GPR state", unmapped_cases[i].description);
        TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                    unmapped_cases[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP",
                    unmapped_cases[i].description);
        OK(uc_close(uc));
    }

    {
        static const uint8_t code[] = {0xd5, 0x5d, 0x01, 0x01};
        const uint64_t page = UINT64_C(0x8000);
        const uint64_t initial_memory = UINT64_C(0x7fffffffffffffff);
        uint64_t memory = initial_memory;
        uint64_t r24 = 1;
        uint64_t r25 = page;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_mem_map(uc, page, 0x1000, UC_PROT_ALL));
        OK(uc_mem_write(uc, page, &memory, sizeof(memory)));
        OK(uc_mem_protect(uc, page, 0x1000, UC_PROT_READ));
        OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_write(uc, UC_X86_REG_R25, &r25));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
        OK(uc_mem_read(uc, page, &memory, sizeof(memory)));
        OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_read(uc, UC_X86_REG_R25, &r25));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK(err == UC_ERR_WRITE_PROT);
        TEST_CHECK(memory == initial_memory);
        TEST_CHECK(r24 == 1 && r25 == page);
        TEST_CHECK(rflags == initial_rflags);
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }

    {
        static const struct {
            uint8_t code[4];
            uc_err expected_error;
            const char *description;
        } cases[] = {
            {{0xd5, 0x5d, 0x8b, 0x01},
             UC_ERR_READ_UNMAPPED,
             "cross-page MOV load"},
            {{0xd5, 0x5d, 0x89, 0x01},
             UC_ERR_WRITE_UNMAPPED,
             "cross-page MOV store"},
            {{0xd5, 0x5d, 0x01, 0x01},
             UC_ERR_READ_UNMAPPED,
             "cross-page ADD memory destination"},
        };
        const uint64_t page = UINT64_C(0x8000);
        const uint64_t address = page + 0xffc;
        const uint32_t initial_prefix = UINT32_C(0xa5a5a5a5);

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint32_t prefix = initial_prefix;
            uint64_t r24 = initial_r24;
            uint64_t r25 = address;
            uint64_t rflags = initial_rflags;
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX,
                                cases[i].code, sizeof(cases[i].code));
            OK(uc_mem_map(uc, page, 0x1000, UC_PROT_ALL));
            OK(uc_mem_write(uc, address, &prefix, sizeof(prefix)));
            OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
            OK(uc_reg_write(uc, UC_X86_REG_R25, &r25));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            err = uc_emu_start(uc, code_start,
                               code_start + sizeof(cases[i].code), 0, 0);
            OK(uc_mem_read(uc, address, &prefix, sizeof(prefix)));
            OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
            OK(uc_reg_read(uc, UC_X86_REG_R25, &r25));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

            TEST_CHECK_(err == cases[i].expected_error, "%s returned %s",
                        cases[i].description, uc_strerror(err));
            TEST_CHECK_(prefix == initial_prefix,
                        "%s partially changed memory: 0x%x",
                        cases[i].description, prefix);
            TEST_CHECK_(r24 == initial_r24 && r25 == address,
                        "%s changed GPR state", cases[i].description);
            TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                        cases[i].description);
            TEST_CHECK_(rip == code_start, "%s advanced RIP",
                        cases[i].description);
            OK(uc_close(uc));
        }
    }

    {
        static const struct {
            uint8_t code[4];
            uint32_t second_page_perms;
            uc_err expected_error;
            const char *description;
        } cases[] = {
            {{0xd5, 0x5d, 0x8b, 0x01},
             UC_PROT_WRITE,
             UC_ERR_READ_PROT,
             "cross-page protected MOV load"},
            {{0xd5, 0x5d, 0x89, 0x01},
             UC_PROT_READ,
             UC_ERR_WRITE_PROT,
             "cross-page protected MOV store"},
            {{0xd5, 0x5d, 0x01, 0x01},
             UC_PROT_WRITE,
             UC_ERR_READ_PROT,
             "cross-page protected ADD read"},
            {{0xd5, 0x5d, 0x01, 0x01},
             UC_PROT_READ,
             UC_ERR_WRITE_PROT,
             "cross-page protected ADD write"},
        };
        const uint64_t page = UINT64_C(0x8000);
        const uint64_t second_page = page + 0x1000;
        const uint64_t address = second_page - 4;
        const uint64_t initial_memory = UINT64_C(0xa5a5a5a5a5a5a5a5);

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint64_t memory = initial_memory;
            uint64_t r24 = initial_r24;
            uint64_t r25 = address;
            uint64_t rflags = initial_rflags;
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX,
                                cases[i].code, sizeof(cases[i].code));
            OK(uc_mem_map(uc, page, 0x2000, UC_PROT_ALL));
            OK(uc_mem_write(uc, address, &memory, sizeof(memory)));
            OK(uc_mem_protect(uc, second_page, 0x1000,
                              cases[i].second_page_perms));
            OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
            OK(uc_reg_write(uc, UC_X86_REG_R25, &r25));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            err = uc_emu_start(uc, code_start,
                               code_start + sizeof(cases[i].code), 0, 0);
            OK(uc_mem_read(uc, address, &memory, sizeof(memory)));
            OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
            OK(uc_reg_read(uc, UC_X86_REG_R25, &r25));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

            TEST_CHECK_(err == cases[i].expected_error, "%s returned %s",
                        cases[i].description, uc_strerror(err));
            TEST_CHECK_(memory == initial_memory, "%s changed memory",
                        cases[i].description);
            TEST_CHECK_(r24 == initial_r24 && r25 == address,
                        "%s changed GPR state", cases[i].description);
            TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                        cases[i].description);
            TEST_CHECK_(rip == code_start, "%s advanced RIP",
                        cases[i].description);
            OK(uc_close(uc));
        }
    }

    {
        static const uint8_t code[] = {0xd5, 0x5d, 0x89, 0x01};
        static const uc_mem_type repair_types[] = {
            UC_MEM_WRITE_UNMAPPED,
            UC_MEM_WRITE_PROT,
        };
        const uint64_t page = UINT64_C(0x8000);
        const uint64_t second_page = page + 0x1000;
        const uint64_t address = second_page - 4;
        const uint64_t source = UINT64_C(0x1122334455667788);

        for (size_t i = 0; i < sizeof(repair_types) / sizeof(repair_types[0]);
             ++i) {
            TestX86ApxWriteRepair repair = {
                .expected_type = repair_types[i],
                .page = second_page,
            };
            uint64_t memory = 0;
            uint64_t r24 = source;
            uint64_t r25 = address;
            uc_engine *uc;
            uc_hook hook;

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                sizeof(code));
            OK(uc_mem_map(uc, page, 0x1000, UC_PROT_ALL));
            if (repair_types[i] == UC_MEM_WRITE_PROT) {
                OK(uc_mem_map(uc, second_page, 0x1000, UC_PROT_READ));
            }
            OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
            OK(uc_reg_write(uc, UC_X86_REG_R25, &r25));
            OK(uc_hook_add(uc, &hook,
                           repair_types[i] == UC_MEM_WRITE_UNMAPPED
                               ? UC_HOOK_MEM_WRITE_UNMAPPED
                               : UC_HOOK_MEM_WRITE_PROT,
                           test_x86_apx_repair_cross_page_write, &repair, 1,
                           0));

            OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
            OK(uc_mem_read(uc, address, &memory, sizeof(memory)));
            TEST_CHECK(memory == source);
            TEST_CHECK(repair.calls == 1);
            TEST_CHECK(repair.address == second_page);
            TEST_CHECK(repair.size == 4);
            TEST_CHECK(repair.value == UINT64_C(0x11223344));
            OK(uc_close(uc));
        }
    }
}

static void test_x86_apx_rex2_add_widths_directions_and_flags(void)
{
    static const uint8_t widths[] = {1, 2, 4, 8};
    const uint64_t destination_base = UINT64_C(0xa5a5a5a5a5a5a5a5);

    for (size_t width_index = 0;
         width_index < sizeof(widths) / sizeof(widths[0]); ++width_index) {
        const uint8_t width = widths[width_index];
        const uint64_t width_mask =
            width == 8 ? UINT64_MAX : (UINT64_C(1) << (width * 8)) - 1;
        const uint64_t sign_max = width_mask >> 1;
        const uint64_t sign_min = UINT64_C(1) << (width * 8 - 1);

        for (unsigned int reverse = 0; reverse < 2; ++reverse) {
            uint8_t code[5];
            size_t code_size = 0;
            uint64_t r24 =
                reverse ? ((destination_base & ~width_mask) | sign_max) : 1;
            uint64_t r31 =
                reverse ? 1 : ((destination_base & ~width_mask) | sign_max);
            const uint64_t expected_destination =
                width >= 4 ? sign_min
                           : ((destination_base & ~width_mask) | sign_min);
            const uint64_t expected_rflags =
                width == 1 ? UINT64_C(0xa92) : UINT64_C(0xa96);
            uint64_t rflags = UINT64_C(0x202);
            uc_engine *uc;

            if (width == 2) {
                code[code_size++] = 0x66;
            }
            code[code_size++] = 0xd5;
            code[code_size++] = width == 8 ? 0x5d : 0x55;
            code[code_size++] =
                width == 1 ? (reverse ? 0x02 : 0x00) : (reverse ? 0x03 : 0x01);
            code[code_size++] = 0xc7;

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                code_size);
            OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
            OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
            OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

            TEST_CHECK_(reverse ? r24 == expected_destination
                                : r31 == expected_destination,
                        "ADD width %u direction %u produced the wrong result",
                        width, reverse);
            TEST_CHECK_(reverse ? r31 == 1 : r24 == 1,
                        "ADD width %u direction %u changed its source", width,
                        reverse);
            TEST_CHECK_(rflags == expected_rflags,
                        "ADD width %u direction %u produced RFLAGS 0x%llx",
                        width, reverse, (unsigned long long)rflags);
            OK(uc_close(uc));
        }
    }
}

static void
test_x86_apx_rex2_arithmetic_memory_widths_directions_and_flags(void)
{
    static const struct {
        uint8_t forward_byte;
        uint8_t forward_wide;
        uint8_t reverse_byte;
        uint8_t reverse_wide;
        bool writes_destination;
        bool addition;
        const char *name;
    } kinds[] = {
        {0x00, 0x01, 0x02, 0x03, true, true, "ADD"},
        {0x28, 0x29, 0x2a, 0x2b, true, false, "SUB"},
        {0x38, 0x39, 0x3a, 0x3b, false, false, "CMP"},
    };
    static const uint8_t widths[] = {1, 2, 4, 8};
    const uint64_t data_address = code_start + 0x900;
    const uint64_t destination_base = UINT64_C(0xa5a5a5a5a5a5a5a5);

    for (size_t kind_index = 0; kind_index < sizeof(kinds) / sizeof(kinds[0]);
         ++kind_index) {
        for (size_t width_index = 0;
             width_index < sizeof(widths) / sizeof(widths[0]); ++width_index) {
            const uint8_t width = widths[width_index];
            const uint64_t width_mask =
                width == 8 ? UINT64_MAX : (UINT64_C(1) << (width * 8)) - 1;
            const uint64_t destination_low =
                kinds[kind_index].addition ? width_mask >> 1 : 0;
            const uint64_t result_low = kinds[kind_index].addition
                                            ? UINT64_C(1) << (width * 8 - 1)
                                            : width_mask;
            const uint64_t initial_destination =
                (destination_base & ~width_mask) | destination_low;

            for (unsigned int register_destination = 0;
                 register_destination < 2; ++register_destination) {
                uint8_t code[5];
                size_t code_size = 0;
                uint64_t r24 = register_destination ? initial_destination : 1;
                uint64_t r25 = data_address;
                uint64_t memory =
                    register_destination ? 1 : initial_destination;
                const uint64_t initial_r24 = r24;
                const uint64_t initial_memory = memory;
                const uint64_t expected_destination =
                    kinds[kind_index].writes_destination
                        ? (register_destination
                               ? (width >= 4
                                      ? result_low
                                      : (destination_base & ~width_mask) |
                                            result_low)
                               : (destination_base & ~width_mask) | result_low)
                        : initial_destination;
                const uint64_t expected_rflags =
                    kinds[kind_index].addition
                        ? (width == 1 ? UINT64_C(0xa92) : UINT64_C(0xa96))
                        : UINT64_C(0x297);
                uint64_t rflags = UINT64_C(0x202);
                uc_engine *uc;

                if (width == 2) {
                    code[code_size++] = 0x66;
                }
                code[code_size++] = 0xd5;
                code[code_size++] = width == 8 ? 0x5d : 0x55;
                code[code_size++] =
                    width == 1 ? (register_destination
                                      ? kinds[kind_index].reverse_byte
                                      : kinds[kind_index].forward_byte)
                               : (register_destination
                                      ? kinds[kind_index].reverse_wide
                                      : kinds[kind_index].forward_wide);
                code[code_size++] = 0x01;

                uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                    code_size);
                OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
                OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
                OK(uc_reg_write(uc, UC_X86_REG_R25, &r25));
                OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
                OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
                OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
                OK(uc_reg_read(uc, UC_X86_REG_R25, &r25));
                OK(uc_mem_read(uc, data_address, &memory, sizeof(memory)));
                OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

                TEST_CHECK_(register_destination ? r24 == expected_destination
                                                 : r24 == initial_r24,
                            "%s memory width %u direction %u register mismatch",
                            kinds[kind_index].name, width,
                            register_destination);
                TEST_CHECK_(
                    register_destination ? memory == initial_memory
                                         : memory == expected_destination,
                    "%s memory width %u direction %u memory mismatch",
                    kinds[kind_index].name, width, register_destination);
                TEST_CHECK_(r25 == data_address,
                            "%s memory width %u changed its base",
                            kinds[kind_index].name, width);
                TEST_CHECK_(rflags == expected_rflags,
                            "%s memory width %u direction %u RFLAGS 0x%llx",
                            kinds[kind_index].name, width, register_destination,
                            (unsigned long long)rflags);
                OK(uc_close(uc));
            }
        }
    }
}

static void test_x86_apx_rex2_logical_widths_directions_and_flags(void)
{
    static const struct {
        uint8_t forward_byte;
        uint8_t forward_wide;
        uint8_t reverse_byte;
        uint8_t reverse_wide;
        uint64_t destination_low;
        uint64_t source_low;
        uint64_t result_low;
        uint64_t byte_flags;
        uint64_t wide_flags;
        const char *name;
    } kinds[] = {
        {0x08, 0x09, 0x0a, 0x0b, 0, 0x81, 0x81, 0x286, 0x206, "OR"},
        {0x20, 0x21, 0x22, 0x23, 0, 0x81, 0, 0x246, 0x246, "AND"},
        {0x30, 0x31, 0x32, 0x33, 0x81, 0x81, 0, 0x246, 0x246, "XOR"},
    };
    static const uint8_t widths[] = {1, 2, 4, 8};
    const uint64_t destination_base = UINT64_C(0xa5a5a5a5a5a5a5a5);

    for (size_t kind_index = 0; kind_index < sizeof(kinds) / sizeof(kinds[0]);
         ++kind_index) {
        for (size_t width_index = 0;
             width_index < sizeof(widths) / sizeof(widths[0]); ++width_index) {
            const uint8_t width = widths[width_index];
            const uint64_t width_mask =
                width == 8 ? UINT64_MAX : (UINT64_C(1) << (width * 8)) - 1;

            for (unsigned int reverse = 0; reverse < 2; ++reverse) {
                uint8_t code[5];
                size_t code_size = 0;
                const uint64_t initial_destination =
                    (destination_base & ~width_mask) |
                    kinds[kind_index].destination_low;
                const uint64_t source = kinds[kind_index].source_low;
                const uint64_t expected_destination =
                    width >= 4 ? kinds[kind_index].result_low
                               : (destination_base & ~width_mask) |
                                     kinds[kind_index].result_low;
                const uint64_t expected_rflags =
                    width == 1 ? kinds[kind_index].byte_flags
                               : kinds[kind_index].wide_flags;
                uint64_t r24 = reverse ? initial_destination : source;
                uint64_t r31 = reverse ? source : initial_destination;
                uint64_t rflags = UINT64_C(0xa92);
                uc_engine *uc;

                if (width == 2) {
                    code[code_size++] = 0x66;
                }
                code[code_size++] = 0xd5;
                code[code_size++] = width == 8 ? 0x5d : 0x55;
                code[code_size++] =
                    width == 1 ? (reverse ? kinds[kind_index].reverse_byte
                                          : kinds[kind_index].forward_byte)
                               : (reverse ? kinds[kind_index].reverse_wide
                                          : kinds[kind_index].forward_wide);
                code[code_size++] = 0xc7;

                uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                    code_size);
                OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
                OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
                OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
                OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
                OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
                OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
                OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

                TEST_CHECK_(reverse ? r24 == expected_destination
                                    : r31 == expected_destination,
                            "%s width %u direction %u result mismatch",
                            kinds[kind_index].name, width, reverse);
                TEST_CHECK_(reverse ? r31 == source : r24 == source,
                            "%s width %u direction %u changed its source",
                            kinds[kind_index].name, width, reverse);
                TEST_CHECK_(rflags == expected_rflags,
                            "%s width %u direction %u RFLAGS 0x%llx",
                            kinds[kind_index].name, width, reverse,
                            (unsigned long long)rflags);
                OK(uc_close(uc));
            }
        }
    }

    for (size_t width_index = 0;
         width_index < sizeof(widths) / sizeof(widths[0]); ++width_index) {
        const uint8_t width = widths[width_index];
        uint8_t code[5];
        size_t code_size = 0;
        uint64_t r24 = UINT64_C(0x81);
        uint64_t r31 =
            destination_base &
            ~(width == 8 ? UINT64_MAX : (UINT64_C(1) << (width * 8)) - 1);
        const uint64_t initial_r24 = r24;
        const uint64_t initial_r31 = r31;
        uint64_t rflags = UINT64_C(0xa92);
        uc_engine *uc;

        if (width == 2) {
            code[code_size++] = 0x66;
        }
        code[code_size++] = 0xd5;
        code[code_size++] = width == 8 ? 0x5d : 0x55;
        code[code_size++] = width == 1 ? 0x84 : 0x85;
        code[code_size++] = 0xc7;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            code_size);
        OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

        TEST_CHECK_(r24 == initial_r24 && r31 == initial_r31,
                    "TEST width %u changed an operand", width);
        TEST_CHECK_(rflags == UINT64_C(0x246),
                    "TEST width %u produced RFLAGS 0x%llx", width,
                    (unsigned long long)rflags);
        OK(uc_close(uc));
    }
}

static void test_x86_apx_rex2_logical_memory_widths_directions_and_flags(void)
{
    static const struct {
        uint8_t forward_byte;
        uint8_t forward_wide;
        uint8_t reverse_byte;
        uint8_t reverse_wide;
        uint64_t destination_low;
        uint64_t source_low;
        uint64_t result_low;
        uint64_t byte_flags;
        uint64_t wide_flags;
        bool writes_destination;
        bool has_reverse;
        const char *name;
    } kinds[] = {
        {0x08, 0x09, 0x0a, 0x0b, 0, 0x81, 0x81, 0x286, 0x206, true, true, "OR"},
        {0x20, 0x21, 0x22, 0x23, 0, 0x81, 0, 0x246, 0x246, true, true, "AND"},
        {0x30, 0x31, 0x32, 0x33, 0x81, 0x81, 0, 0x246, 0x246, true, true,
         "XOR"},
        {0x84, 0x85, 0, 0, 0, 0x81, 0, 0x246, 0x246, false, false, "TEST"},
    };
    static const uint8_t widths[] = {1, 2, 4, 8};
    const uint64_t data_address = code_start + 0xa00;
    const uint64_t destination_base = UINT64_C(0xa5a5a5a5a5a5a5a5);

    for (size_t kind_index = 0; kind_index < sizeof(kinds) / sizeof(kinds[0]);
         ++kind_index) {
        for (size_t width_index = 0;
             width_index < sizeof(widths) / sizeof(widths[0]); ++width_index) {
            const uint8_t width = widths[width_index];
            const uint64_t width_mask =
                width == 8 ? UINT64_MAX : (UINT64_C(1) << (width * 8)) - 1;
            const uint64_t initial_destination =
                (destination_base & ~width_mask) |
                kinds[kind_index].destination_low;

            for (unsigned int register_destination = 0;
                 register_destination <
                 (kinds[kind_index].has_reverse ? 2U : 1U);
                 ++register_destination) {
                uint8_t code[5];
                size_t code_size = 0;
                uint64_t r24 = register_destination
                                   ? initial_destination
                                   : kinds[kind_index].source_low;
                uint64_t r25 = data_address;
                uint64_t memory = register_destination
                                      ? kinds[kind_index].source_low
                                      : initial_destination;
                const uint64_t initial_r24 = r24;
                const uint64_t initial_memory = memory;
                const uint64_t expected_destination =
                    kinds[kind_index].writes_destination
                        ? (register_destination
                               ? (width >= 4
                                      ? kinds[kind_index].result_low
                                      : (destination_base & ~width_mask) |
                                            kinds[kind_index].result_low)
                               : (destination_base & ~width_mask) |
                                     kinds[kind_index].result_low)
                        : initial_destination;
                const uint64_t expected_rflags =
                    width == 1 ? kinds[kind_index].byte_flags
                               : kinds[kind_index].wide_flags;
                uint64_t rflags = UINT64_C(0xa92);
                uc_engine *uc;

                if (width == 2) {
                    code[code_size++] = 0x66;
                }
                code[code_size++] = 0xd5;
                code[code_size++] = width == 8 ? 0x5d : 0x55;
                code[code_size++] =
                    width == 1 ? (register_destination
                                      ? kinds[kind_index].reverse_byte
                                      : kinds[kind_index].forward_byte)
                               : (register_destination
                                      ? kinds[kind_index].reverse_wide
                                      : kinds[kind_index].forward_wide);
                code[code_size++] = 0x01;

                uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                    code_size);
                OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
                OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
                OK(uc_reg_write(uc, UC_X86_REG_R25, &r25));
                OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
                OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
                OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
                OK(uc_reg_read(uc, UC_X86_REG_R25, &r25));
                OK(uc_mem_read(uc, data_address, &memory, sizeof(memory)));
                OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

                TEST_CHECK_(register_destination ? r24 == expected_destination
                                                 : r24 == initial_r24,
                            "%s memory width %u direction %u register mismatch",
                            kinds[kind_index].name, width,
                            register_destination);
                TEST_CHECK_(
                    register_destination ? memory == initial_memory
                                         : memory == expected_destination,
                    "%s memory width %u direction %u memory mismatch",
                    kinds[kind_index].name, width, register_destination);
                TEST_CHECK_(r25 == data_address,
                            "%s memory width %u changed its base",
                            kinds[kind_index].name, width);
                TEST_CHECK_(rflags == expected_rflags,
                            "%s memory width %u direction %u RFLAGS 0x%llx",
                            kinds[kind_index].name, width, register_destination,
                            (unsigned long long)rflags);
                OK(uc_close(uc));
            }
        }
    }
}

static void test_x86_apx_rex2_sub_cmp_widths_directions_and_flags(void)
{
    static const struct {
        uint8_t forward_byte;
        uint8_t forward_wide;
        uint8_t reverse_byte;
        uint8_t reverse_wide;
        bool writes_destination;
        const char *name;
    } kinds[] = {
        {0x28, 0x29, 0x2a, 0x2b, true, "SUB"},
        {0x38, 0x39, 0x3a, 0x3b, false, "CMP"},
    };
    static const uint8_t widths[] = {1, 2, 4, 8};
    const uint64_t destination_base = UINT64_C(0xa5a5a5a5a5a50000);

    for (size_t kind_index = 0; kind_index < sizeof(kinds) / sizeof(kinds[0]);
         ++kind_index) {
        for (size_t width_index = 0;
             width_index < sizeof(widths) / sizeof(widths[0]); ++width_index) {
            const uint8_t width = widths[width_index];
            const uint64_t width_mask =
                width == 8 ? UINT64_MAX : (UINT64_C(1) << (width * 8)) - 1;
            const uint64_t initial_destination = destination_base & ~width_mask;
            const uint64_t expected_destination =
                kinds[kind_index].writes_destination
                    ? (width >= 4
                           ? width_mask
                           : (destination_base & ~width_mask) | width_mask)
                    : initial_destination;

            for (unsigned int reverse = 0; reverse < 2; ++reverse) {
                uint8_t code[5];
                size_t code_size = 0;
                uint64_t r24 = reverse ? initial_destination : 1;
                uint64_t r31 = reverse ? 1 : initial_destination;
                uint64_t rflags = UINT64_C(0xa96);
                uc_engine *uc;

                if (width == 2) {
                    code[code_size++] = 0x66;
                }
                code[code_size++] = 0xd5;
                code[code_size++] = width == 8 ? 0x5d : 0x55;
                code[code_size++] =
                    width == 1 ? (reverse ? kinds[kind_index].reverse_byte
                                          : kinds[kind_index].forward_byte)
                               : (reverse ? kinds[kind_index].reverse_wide
                                          : kinds[kind_index].forward_wide);
                code[code_size++] = 0xc7;

                uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                    code_size);
                OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
                OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
                OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
                OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
                OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
                OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
                OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

                TEST_CHECK_(reverse ? r24 == expected_destination
                                    : r31 == expected_destination,
                            "%s width %u direction %u destination mismatch",
                            kinds[kind_index].name, width, reverse);
                TEST_CHECK_(reverse ? r31 == 1 : r24 == 1,
                            "%s width %u direction %u changed its source",
                            kinds[kind_index].name, width, reverse);
                TEST_CHECK_(rflags == UINT64_C(0x297),
                            "%s width %u direction %u RFLAGS 0x%llx",
                            kinds[kind_index].name, width, reverse,
                            (unsigned long long)rflags);
                OK(uc_close(uc));
            }
        }
    }
}

static void test_x86_apx_rex2_mov_r26_r25(void)
{
    static const uint8_t code[] = {
        0xd5,
        0x5d,
        0x89,
        0xca, /* mov r26, r25 */
    };
    const uint64_t source = UINT64_C(0x0123456789abcdef);
    const uint64_t initial_destination = UINT64_C(0xfedcba9876543210);
    const uint64_t initial_rflags = UINT64_C(0xcd7);
    uint64_t r25 = source;
    uint64_t r26 = initial_destination;
    uint64_t rflags = initial_rflags;
    uint64_t rip = 0;
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_R25, &r25));
    OK(uc_reg_write(uc, UC_X86_REG_R26, &r26));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_R25, &r25));
    OK(uc_reg_read(uc, UC_X86_REG_R26, &r26));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    TEST_CHECK(r25 == source);
    TEST_CHECK(r26 == source);
    TEST_CHECK(rflags == initial_rflags);
    TEST_CHECK(rip == code_start + sizeof(code));
    OK(uc_close(uc));
}

static void test_x86_apx_rex2_add_r31_r24_flags(void)
{
    static const uint8_t code[] = {
        0xd5,
        0x5d,
        0x01,
        0xc7, /* add r31, r24 */
    };
    const uint64_t initial_r24 = UINT64_C(1);
    const uint64_t initial_r31 = UINT64_C(0x7fffffffffffffff);
    uint64_t r24 = initial_r24;
    uint64_t r31 = initial_r31;
    uint64_t rflags = UINT64_C(0x202);
    uint64_t rip = 0;
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
    OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
    OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    TEST_CHECK(r24 == initial_r24);
    TEST_CHECK(r31 == UINT64_C(0x8000000000000000));
    TEST_CHECK(rflags == UINT64_C(0xa96));
    TEST_CHECK(rip == code_start + sizeof(code));
    OK(uc_close(uc));
}

static void test_x86_apx_rex2_add_carry_zero_flags(void)
{
    static const uint8_t code[] = {
        0xd5,
        0x5d,
        0x01,
        0xc7, /* add r31, r24 */
    };
    const uint64_t initial_r24 = UINT64_C(1);
    const uint64_t initial_r31 = UINT64_MAX;
    uint64_t r24 = initial_r24;
    uint64_t r31 = initial_r31;
    uint64_t rflags = UINT64_C(0xa96);
    uint64_t rip = 0;
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
    OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
    OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    TEST_CHECK(r24 == initial_r24);
    TEST_CHECK(r31 == 0);
    TEST_CHECK(rflags == UINT64_C(0x257));
    TEST_CHECK(rip == code_start + sizeof(code));
    OK(uc_close(uc));
}

static void test_x86_apx_rex2_adc_sbb_consume_carry(void)
{
    static const struct {
        uint8_t opcode;
        uint64_t expected_destination;
        uint64_t expected_rflags;
        const char *name;
    } cases[] = {
        {0x11, UINT64_C(1), UINT64_C(0x202), "ADC"},
        {0x19, UINT64_MAX, UINT64_C(0x297), "SBB"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const uint8_t code[] = {
            0xd5,
            0x5d,
            cases[i].opcode,
            0xc7, /* adc/sbb r31, r24 */
        };
        const uint64_t initial_r24 = 0;
        uint64_t r24 = initial_r24;
        uint64_t r31 = 0;
        uint64_t rflags = UINT64_C(0x203);
        uint64_t rip = 0;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(r24 == initial_r24, "%s changed its source",
                    cases[i].name);
        TEST_CHECK_(r31 == cases[i].expected_destination,
                    "%s ignored the carry input", cases[i].name);
        TEST_CHECK_(rflags == cases[i].expected_rflags,
                    "%s produced RFLAGS 0x%llx", cases[i].name,
                    (unsigned long long)rflags);
        TEST_CHECK_(rip == code_start + sizeof(code), "%s did not retire",
                    cases[i].name);
        OK(uc_close(uc));
    }
}

static void test_x86_apx_rex2_map1_imul_semantics(void)
{
    static const struct {
        uint8_t code[5];
        size_t code_size;
        uint64_t destination;
        uint64_t source;
        uint64_t expected_destination;
        bool overflow;
        const char *name;
    } register_cases[] = {
        {{0xd5, 0xdd, 0xaf, 0xc7}, 4, 3, UINT64_C(-4), UINT64_C(-12),
         false, "qword fit"},
        {{0xd5, 0xdd, 0xaf, 0xc7}, 4, INT64_MAX, 2, UINT64_C(-2), true,
         "qword overflow"},
        {{0xd5, 0xd5, 0xaf, 0xc7}, 4, UINT64_C(0xaaaaaaaaffffffff),
         2, UINT64_C(0xfffffffe), false, "dword clears upper half"},
        {{0x66, 0xd5, 0xd5, 0xaf, 0xc7}, 5,
         UINT64_C(0xaaaaaaaaaaaa7fff), 2,
         UINT64_C(0xaaaaaaaaaaaafffe), true, "word preserves upper bits"},
    };

    for (size_t i = 0;
         i < sizeof(register_cases) / sizeof(register_cases[0]); ++i) {
        uint64_t r24 = register_cases[i].destination;
        uint64_t r31 = register_cases[i].source;
        uint64_t rflags = UINT64_C(0xa03);
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX,
                            register_cases[i].code,
                            register_cases[i].code_size);
        OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start,
                        code_start + register_cases[i].code_size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

        TEST_CHECK_(r24 == register_cases[i].expected_destination,
                    "IMUL %s result 0x%llx", register_cases[i].name,
                    (unsigned long long)r24);
        TEST_CHECK_(r31 == register_cases[i].source,
                    "IMUL %s changed its source", register_cases[i].name);
        TEST_CHECK_(((rflags & UINT64_C(0x801)) != 0) ==
                        register_cases[i].overflow,
                    "IMUL %s overflow flags 0x%llx",
                    register_cases[i].name, (unsigned long long)rflags);
        TEST_CHECK_(((rflags >> 11) & 1) == (rflags & 1),
                    "IMUL %s disagreed on OF and CF",
                    register_cases[i].name);
        OK(uc_close(uc));
    }

    {
        static const uint8_t code[] = {0xd5, 0xdd, 0xaf, 0x11};
        const uint64_t address = code_start + 0xb00;
        const uint64_t source = UINT64_C(-7);
        uint64_t r25 = address;
        uint64_t r26 = 6;
        uint64_t memory = source;
        uint64_t rflags = UINT64_C(0x202);
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_mem_write(uc, address, &memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_R25, &r25));
        OK(uc_reg_write(uc, UC_X86_REG_R26, &r26));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_R25, &r25));
        OK(uc_reg_read(uc, UC_X86_REG_R26, &r26));
        OK(uc_mem_read(uc, address, &memory, sizeof(memory)));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

        TEST_CHECK(r25 == address);
        TEST_CHECK(r26 == UINT64_C(-42));
        TEST_CHECK(memory == source);
        TEST_CHECK((rflags & UINT64_C(0x801)) == 0);
        OK(uc_close(uc));
    }
}

static void test_x86_evex_feature_and_xstate_gates(void)
{
    static const uint8_t code[] = {
        0x62, 0xf1, 0x74, 0x48, 0x58, 0xc2, /* vaddps zmm0, zmm1, zmm2 */
    };
    static const struct {
        int cpu_model;
        bool clear_osxsave;
        uc_err expected;
        const char *name;
    } cases[] = {
        {UC_CPU_X86_HASWELL, false, UC_ERR_INSN_INVALID,
         "CPUID without AVX-512F"},
        {UC_CPU_X86_KNIGHTSMILL, false, UC_ERR_OK,
         "AVX-512F with complete state"},
        {UC_CPU_X86_SKYLAKE_SERVER, true, UC_ERR_INSN_INVALID,
         "CR4.OSXSAVE clear"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        float source1[16];
        float source2[16];
        uint8_t initial[64];
        float observed[16];
        uint64_t cr4 = 0;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        for (size_t lane = 0; lane < 16; ++lane) {
            source1[lane] = 1.0f;
            source2[lane] = 2.0f;
        }
        memset(initial, 0xa5, sizeof(initial));
        uc_common_setup_cpu(&uc, UC_MODE_64, cases[i].cpu_model, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM0, initial));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM1, source1));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM2, source2));
        if (cases[i].clear_osxsave) {
            OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
            cr4 &= ~(UINT64_C(1) << 18);
            OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));
        }

        err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM0, observed));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK_(err == cases[i].expected, "%s returned %s",
                    cases[i].name, uc_strerror(err));
        if (cases[i].expected == UC_ERR_OK) {
            for (size_t lane = 0; lane < 16; ++lane)
                TEST_CHECK_(observed[lane] == 3.0f,
                            "%s lane %zu result mismatch", cases[i].name,
                            lane);
            TEST_CHECK(rip == code_start + sizeof(code));
        } else {
            TEST_CHECK(memcmp(observed, initial, sizeof(initial)) == 0);
            TEST_CHECK(rip == code_start);
        }
        OK(uc_close(uc));
    }

    /* EVEX follows the same CR0 exception rules as the SSE/VEX families:
     * task-switched state raises #NM, while emulation mode raises #UD. */
    {
        static const struct {
            uint64_t cr0_bits;
            uc_err expected;
            const char *name;
        } cr0_cases[] = {
            {UINT64_C(1) << 3, UC_ERR_EXCEPTION, "CR0.TS set"},
            {UINT64_C(1) << 2, UC_ERR_INSN_INVALID, "CR0.EM set"},
        };

        for (size_t i = 0;
             i < sizeof(cr0_cases) / sizeof(cr0_cases[0]); ++i) {
            float source1[16];
            float source2[16];
            uint8_t initial[64];
            uint8_t observed[64];
            uint64_t cr0 = 0;
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            for (size_t lane = 0; lane < 16; ++lane) {
                source1[lane] = 1.0f;
                source2[lane] = 2.0f;
            }
            memset(initial, 0xc3, sizeof(initial));
            uc_common_setup_cpu(&uc, UC_MODE_64,
                                UC_CPU_X86_ICELAKE_SERVER, code,
                                sizeof(code));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM0, initial));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM1, source1));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM2, source2));
            OK(uc_reg_read(uc, UC_X86_REG_CR0, &cr0));
            cr0 |= cr0_cases[i].cr0_bits;
            OK(uc_reg_write(uc, UC_X86_REG_CR0, &cr0));

            err = uc_emu_start(uc, code_start,
                               code_start + sizeof(code), 0, 0);
            OK(uc_reg_read(uc, UC_X86_REG_ZMM0, observed));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(err == cr0_cases[i].expected,
                        "%s returned %s", cr0_cases[i].name,
                        uc_strerror(err));
            TEST_CHECK_(memcmp(observed, initial, sizeof(initial)) == 0,
                        "%s changed destination", cr0_cases[i].name);
            TEST_CHECK_(rip == code_start, "%s advanced RIP",
                        cr0_cases[i].name);
            OK(uc_close(uc));
        }
    }

    /* Re-enter the same guest PC after changing XCR0.  A stale translated
     * block must not keep executing after the opmask/ZMM state is disabled. */
    {
        static const unsigned int required_xcr0_bits[] = {5, 6, 7};

        for (size_t state = 0;
             state < sizeof(required_xcr0_bits) /
                         sizeof(required_xcr0_bits[0]);
             ++state) {
            float source1[16];
            float source2[16];
            uint8_t initial[64];
            uint8_t observed[64];
            uint64_t xcr0 = 0;
            uint64_t rip = 0;
            uc_engine *uc;

            for (size_t lane = 0; lane < 16; ++lane) {
                source1[lane] = 1.0f;
                source2[lane] = 2.0f;
            }
            memset(initial, 0x5a, sizeof(initial));
            uc_common_setup_cpu(&uc, UC_MODE_64,
                                UC_CPU_X86_ICELAKE_SERVER, code,
                                sizeof(code));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM1, source1));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM2, source2));
            OK(uc_emu_start(uc, code_start,
                            code_start + sizeof(code), 0, 0));

            OK(uc_reg_write(uc, UC_X86_REG_ZMM0, initial));
            OK(uc_reg_read(uc, UC_X86_REG_XCR0, &xcr0));
            xcr0 &= ~(UINT64_C(1) << required_xcr0_bits[state]);
            OK(uc_reg_write(uc, UC_X86_REG_XCR0, &xcr0));
            uc_assert_err(UC_ERR_INSN_INVALID,
                          uc_emu_start(uc, code_start,
                                       code_start + sizeof(code), 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_ZMM0, observed));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(memcmp(observed, initial, sizeof(initial)) == 0,
                        "XCR0 bit %u changed destination",
                        required_xcr0_bits[state]);
            TEST_CHECK_(rip == code_start, "XCR0 bit %u advanced RIP",
                        required_xcr0_bits[state]);
            OK(uc_close(uc));
        }
    }

    /* Knights Mill implements AVX-512F but not AVX-512VL: the ZMM form
     * above is valid while the packed YMM form must fault. */
    {
        static const uint8_t ymm_code[] = {
            0x62, 0xf1, 0x74, 0x28, 0x58, 0xc2,
        };
        static const struct {
            int cpu_model;
            uc_err expected;
        } vl_cases[] = {
            {UC_CPU_X86_KNIGHTSMILL, UC_ERR_INSN_INVALID},
            {UC_CPU_X86_ICELAKE_SERVER, UC_ERR_OK},
        };

        for (size_t i = 0; i < sizeof(vl_cases) / sizeof(vl_cases[0]); ++i) {
            float source1[16];
            float source2[16];
            uint8_t initial[64];
            float observed[16];
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            for (size_t lane = 0; lane < 16; ++lane) {
                source1[lane] = 1.0f;
                source2[lane] = 2.0f;
            }
            memset(initial, 0x6d, sizeof(initial));
            uc_common_setup_cpu(&uc, UC_MODE_64, vl_cases[i].cpu_model,
                                ymm_code, sizeof(ymm_code));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM0, initial));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM1, source1));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM2, source2));
            err = uc_emu_start(uc, code_start,
                               code_start + sizeof(ymm_code), 0, 0);
            OK(uc_reg_read(uc, UC_X86_REG_ZMM0, observed));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(err == vl_cases[i].expected,
                        "AVX-512VL gate returned %s", uc_strerror(err));
            TEST_CHECK_(rip == (vl_cases[i].expected == UC_ERR_OK
                                    ? code_start + sizeof(ymm_code)
                                    : code_start),
                        "AVX-512VL gate advanced RIP unexpectedly");
            if (vl_cases[i].expected == UC_ERR_OK) {
                for (size_t lane = 0; lane < 8; ++lane) {
                    TEST_CHECK_(observed[lane] == 3.0f,
                                "AVX-512VL lane %zu result mismatch",
                                lane);
                }
            } else {
                TEST_CHECK(memcmp(observed, initial, sizeof(initial)) == 0);
            }
            OK(uc_close(uc));
        }

        /* The same VL rule applies to non-arithmetic EVEX families. */
        {
            static const uint8_t vmovdqu64_ymm[] = {
                0x62, 0x21, 0xfe, 0x28, 0x6f, 0xfc,
            };
            uint8_t source[64];
            uint8_t initial[64];
            uint8_t observed[64];

            for (size_t i = 0; i < sizeof(vl_cases) / sizeof(vl_cases[0]);
                 ++i) {
                uint64_t rip = 0;
                uc_engine *uc;
                uc_err err;

                memset(source, 0x24, sizeof(source));
                memset(initial, 0x81, sizeof(initial));
                uc_common_setup_cpu(&uc, UC_MODE_64,
                                    vl_cases[i].cpu_model, vmovdqu64_ymm,
                                    sizeof(vmovdqu64_ymm));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM20, source));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
                err = uc_emu_start(uc, code_start,
                                   code_start + sizeof(vmovdqu64_ymm), 0, 0);
                OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
                OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
                TEST_CHECK_(err == vl_cases[i].expected,
                            "VMOVDQU64 AVX-512VL gate returned %s",
                            uc_strerror(err));
                if (vl_cases[i].expected == UC_ERR_OK) {
                    TEST_CHECK(memcmp(observed, source, 32) == 0);
                    TEST_CHECK(rip == code_start + sizeof(vmovdqu64_ymm));
                } else {
                    TEST_CHECK(memcmp(observed, initial, sizeof(initial)) ==
                               0);
                    TEST_CHECK(rip == code_start);
                }
                OK(uc_close(uc));
            }
        }
    }

    /* Knights Mill isolates AVX-512F from DQ and VL.  These cases lock the
     * per-family gates as well as the fixed-XMM exceptions that need neither
     * a variable vector length nor AVX-512VL. */
    {
        static const struct {
            uint8_t code[7];
            size_t code_size;
            int destination;
            const char *name;
        } invalid_cases[] = {
            {{0x62, 0x01, 0xfe, 0x48, 0x7a, 0xf5}, 6,
             UC_X86_REG_ZMM30, "VCVTUQQ2PD without AVX-512DQ"},
            {{0x62, 0x03, 0x15, 0x00, 0x51, 0xfe, 0x00}, 7,
             UC_X86_REG_ZMM31, "VRANGESS without AVX-512DQ"},
            {{0x62, 0xe3, 0x7d, 0x08, 0x16, 0xc8, 0x00}, 7,
             UC_X86_REG_RAX, "VPEXTRD without AVX-512DQ"},
            {{0x62, 0xf3, 0x6d, 0x08, 0x1f, 0xcb, 0x00}, 7,
             UC_X86_REG_K1, "VPCMPD without AVX-512VL"},
            {{0x62, 0xf2, 0x75, 0x28, 0x98, 0xc2}, 6,
             UC_X86_REG_ZMM0, "VFMADD132PS without AVX-512VL"},
            {{0x62, 0xf3, 0x7d, 0x48, 0x66, 0xc9, 0x00}, 7,
             UC_X86_REG_K1, "VFPCLASSPS without AVX-512DQ"},
        };
        static const int source_regs[] = {
            UC_X86_REG_ZMM1, UC_X86_REG_ZMM2, UC_X86_REG_ZMM3,
            UC_X86_REG_ZMM17, UC_X86_REG_ZMM29, UC_X86_REG_ZMM30,
        };

        for (size_t i = 0;
             i < sizeof(invalid_cases) / sizeof(invalid_cases[0]); ++i) {
            uint8_t source[64];
            uint8_t initial[64];
            uint8_t observed[64];
            const uint64_t initial_scalar =
                UINT64_C(0x8877665544332211);
            const uint64_t initial_rflags = UINT64_C(0xcd7);
            uint64_t scalar = initial_scalar;
            uint64_t rflags = initial_rflags;
            uint64_t rip = 0;
            uc_engine *uc;

            memset(source, 0x35, sizeof(source));
            memset(initial, 0xa9, sizeof(initial));
            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_KNIGHTSMILL,
                                invalid_cases[i].code,
                                invalid_cases[i].code_size);
            for (size_t reg = 0;
                 reg < sizeof(source_regs) / sizeof(source_regs[0]); ++reg) {
                if (source_regs[reg] != invalid_cases[i].destination) {
                    OK(uc_reg_write(uc, source_regs[reg], source));
                }
            }
            if (invalid_cases[i].destination == UC_X86_REG_RAX ||
                invalid_cases[i].destination == UC_X86_REG_K1) {
                OK(uc_reg_write(uc, invalid_cases[i].destination, &scalar));
            } else {
                OK(uc_reg_write(uc, invalid_cases[i].destination, initial));
            }
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            uc_assert_err(
                UC_ERR_INSN_INVALID,
                uc_emu_start(uc, code_start,
                             code_start + invalid_cases[i].code_size, 0, 0));
            if (invalid_cases[i].destination == UC_X86_REG_RAX ||
                invalid_cases[i].destination == UC_X86_REG_K1) {
                OK(uc_reg_read(uc, invalid_cases[i].destination, &scalar));
                TEST_CHECK_(scalar == initial_scalar,
                            "%s changed destination",
                            invalid_cases[i].name);
            } else {
                OK(uc_reg_read(uc, invalid_cases[i].destination, observed));
                TEST_CHECK_(memcmp(observed, initial, sizeof(initial)) == 0,
                            "%s changed destination",
                            invalid_cases[i].name);
            }
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                        invalid_cases[i].name);
            TEST_CHECK_(rip == code_start, "%s advanced RIP",
                        invalid_cases[i].name);
            OK(uc_close(uc));
        }

        {
            static const struct {
                uint8_t code[8];
                size_t code_size;
                const char *name;
            } valid_cases[] = {
                {{0x62, 0xf2, 0xed, 0x48, 0x27, 0xc9}, 6,
                 "VPTESTMQ AVX-512F form"},
                {{0x62, 0xf3, 0xed, 0x48, 0x23, 0xd9, 0x00}, 7,
                 "VSHUFF64X2 AVX-512F form"},
                {{0x62, 0xe1, 0x7d, 0x08, 0x7e, 0xc8}, 6,
                 "fixed-XMM VMOVD"},
                {{0x62, 0xe1, 0x74, 0x00, 0x12, 0x10}, 6,
                 "fixed-XMM VMOVLPS"},
                {{0x62, 0xa3, 0x6d, 0x00, 0x21, 0xd9, 0x00}, 7,
                 "fixed-XMM VINSERTPS"},
            };
            const uint64_t data_address = code_start + 0x380;

            for (size_t i = 0;
                 i < sizeof(valid_cases) / sizeof(valid_cases[0]); ++i) {
                uint8_t source[64];
                uint64_t memory = UINT64_C(0x1122334455667788);
                uint64_t rax = data_address;
                uint64_t rip = 0;
                uc_engine *uc;

                memset(source, 0x7f, sizeof(source));
                uc_common_setup_cpu(&uc, UC_MODE_64,
                                    UC_CPU_X86_KNIGHTSMILL,
                                    valid_cases[i].code,
                                    valid_cases[i].code_size);
                OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
                OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM1, source));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM2, source));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM17, source));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM18, source));
                OK(uc_emu_start(uc, code_start,
                                code_start + valid_cases[i].code_size,
                                0, 0));
                OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
                TEST_CHECK_(rip == code_start + valid_cases[i].code_size,
                            "%s did not complete", valid_cases[i].name);
                OK(uc_close(uc));
            }
        }
    }

    /* VEX-encoded K operations still require AVX-512F and the complete
     * opmask/ZMM XSTATE contract; the VEX prefix alone does not make them
     * part of the AVX or AVX2 feature surface. */
    {
        static const uint8_t kandw[] = {
            0xc5, 0xec, 0x41, 0xcb,
        };
        static const struct {
            int cpu_model;
            bool clear_opmask_state;
            uc_err expected;
            const char *name;
        } opmask_cases[] = {
            {UC_CPU_X86_HASWELL, false, UC_ERR_INSN_INVALID,
             "KANDW without AVX-512F"},
            {UC_CPU_X86_ICELAKE_SERVER, false, UC_ERR_OK,
             "KANDW with AVX-512 state"},
            {UC_CPU_X86_ICELAKE_SERVER, true, UC_ERR_INSN_INVALID,
             "KANDW without opmask XSTATE"},
        };

        for (size_t i = 0;
             i < sizeof(opmask_cases) / sizeof(opmask_cases[0]); ++i) {
            const uint64_t initial_k1 = UINT64_C(0x1122334455667788);
            const uint64_t initial_k2 = UINT64_C(0xaaaaaaaa5555f0f3);
            const uint64_t initial_k3 = UINT64_C(0x55555555aaa50ff5);
            const uint64_t initial_rflags = UINT64_C(0xcd7);
            uint64_t k1 = initial_k1;
            uint64_t k2 = initial_k2;
            uint64_t k3 = initial_k3;
            uint64_t rflags = initial_rflags;
            uint64_t xcr0 = 0;
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            uc_common_setup_cpu(&uc, UC_MODE_64,
                                opmask_cases[i].cpu_model, kandw,
                                sizeof(kandw));
            OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
            OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
            OK(uc_reg_write(uc, UC_X86_REG_K3, &k3));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            if (opmask_cases[i].clear_opmask_state) {
                OK(uc_reg_read(uc, UC_X86_REG_XCR0, &xcr0));
                xcr0 &= ~(UINT64_C(1) << 5);
                OK(uc_reg_write(uc, UC_X86_REG_XCR0, &xcr0));
            }
            err = uc_emu_start(uc, code_start,
                               code_start + sizeof(kandw), 0, 0);
            OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
            OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
            OK(uc_reg_read(uc, UC_X86_REG_K3, &k3));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(err == opmask_cases[i].expected,
                        "%s returned %s", opmask_cases[i].name,
                        uc_strerror(err));
            TEST_CHECK_(k2 == initial_k2 && k3 == initial_k3,
                        "%s changed an opmask source",
                        opmask_cases[i].name);
            TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                        opmask_cases[i].name);
            if (opmask_cases[i].expected == UC_ERR_OK) {
                TEST_CHECK_(k1 == UINT64_C(0x00f1),
                            "%s produced the wrong result",
                            opmask_cases[i].name);
                TEST_CHECK(rip == code_start + sizeof(kandw));
            } else {
                TEST_CHECK_(k1 == initial_k1, "%s changed destination",
                            opmask_cases[i].name);
                TEST_CHECK(rip == code_start);
            }
            OK(uc_close(uc));
        }

        /* Opmask instructions use the SIMD state even though their operands
         * live in K registers, so CR0.TS/#NM and CR0.EM/#UD apply before any
         * architectural destination or flag update. */
        {
            static const struct {
                uint64_t cr0_bit;
                uc_err expected;
                const char *name;
            } cr0_cases[] = {
                {UINT64_C(1) << 3, UC_ERR_EXCEPTION, "KANDW with CR0.TS"},
                {UINT64_C(1) << 2, UC_ERR_INSN_INVALID,
                 "KANDW with CR0.EM"},
            };

            for (size_t i = 0;
                 i < sizeof(cr0_cases) / sizeof(cr0_cases[0]); ++i) {
                const uint64_t initial_k1 =
                    UINT64_C(0x1122334455667788);
                const uint64_t initial_k2 =
                    UINT64_C(0xaaaaaaaa5555f0f3);
                const uint64_t initial_k3 =
                    UINT64_C(0x55555555aaa50ff5);
                const uint64_t initial_rflags = UINT64_C(0xcd7);
                uint64_t k1 = initial_k1;
                uint64_t k2 = initial_k2;
                uint64_t k3 = initial_k3;
                uint64_t rflags = initial_rflags;
                uint64_t cr0 = 0;
                uint64_t rip = 0;
                uc_engine *uc;
                uc_err err;

                uc_common_setup_cpu(&uc, UC_MODE_64,
                                    UC_CPU_X86_ICELAKE_SERVER, kandw,
                                    sizeof(kandw));
                OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
                OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
                OK(uc_reg_write(uc, UC_X86_REG_K3, &k3));
                OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
                OK(uc_reg_read(uc, UC_X86_REG_CR0, &cr0));
                cr0 |= cr0_cases[i].cr0_bit;
                OK(uc_reg_write(uc, UC_X86_REG_CR0, &cr0));

                err = uc_emu_start(uc, code_start,
                                   code_start + sizeof(kandw), 0, 0);
                OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
                OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
                OK(uc_reg_read(uc, UC_X86_REG_K3, &k3));
                OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
                OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
                TEST_CHECK_(err == cr0_cases[i].expected,
                            "%s returned %s", cr0_cases[i].name,
                            uc_strerror(err));
                TEST_CHECK_(k1 == initial_k1 && k2 == initial_k2 &&
                                k3 == initial_k3,
                            "%s changed opmask state", cr0_cases[i].name);
                TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                            cr0_cases[i].name);
                TEST_CHECK_(rip == code_start, "%s advanced RIP",
                            cr0_cases[i].name);
                OK(uc_close(uc));
            }
        }

        {
            static const struct {
                uint8_t code[6];
                size_t code_size;
                int cpu_model;
                const char *name;
            } width_cases[] = {
                {{0xc5, 0xed, 0x41, 0xcb}, 4,
                 UC_CPU_X86_KNIGHTSMILL, "KANDB without AVX-512DQ"},
                {{0xc5, 0xec, 0x4a, 0xcb}, 4,
                 UC_CPU_X86_KNIGHTSMILL, "KADDW without AVX-512DQ"},
                {{0xc5, 0xf8, 0x99, 0xd3}, 4,
                 UC_CPU_X86_KNIGHTSMILL, "KTESTW without AVX-512DQ"},
                {{0xc4, 0xe1, 0xed, 0x41, 0xcb}, 5,
                 UC_CPU_X86_ICELAKE_SERVER, "KANDD without AVX-512BW"},
                {{0xc4, 0xe1, 0xf9, 0x90, 0xca}, 5,
                 UC_CPU_X86_ICELAKE_SERVER, "KMOVD without AVX-512BW"},
                {{0xc4, 0xe1, 0xf9, 0x44, 0xca}, 5,
                 UC_CPU_X86_ICELAKE_SERVER, "KNOTD without AVX-512BW"},
                {{0xc4, 0xe3, 0x79, 0x33, 0xca, 0x04}, 6,
                 UC_CPU_X86_ICELAKE_SERVER, "KSHIFTLD without AVX-512BW"},
                {{0xc5, 0xec, 0x4b, 0xcb}, 4,
                 UC_CPU_X86_ICELAKE_SERVER, "KUNPCKWD without AVX-512BW"},
                {{0xc4, 0xe1, 0xf9, 0x99, 0xd3}, 5,
                 UC_CPU_X86_ICELAKE_SERVER, "KTESTD without AVX-512BW"},
                {{0xc4, 0xe1, 0xf9, 0x98, 0xd3}, 5,
                 UC_CPU_X86_ICELAKE_SERVER, "KORTESTD without AVX-512BW"},
                {{0xc4, 0xe1, 0xed, 0x4a, 0xcb}, 5,
                 UC_CPU_X86_ICELAKE_SERVER, "KADDD without AVX-512BW"},
            };

            for (size_t i = 0;
                 i < sizeof(width_cases) / sizeof(width_cases[0]); ++i) {
                const uint64_t initial_k1 =
                    UINT64_C(0x1122334455667788);
                const uint64_t initial_k2 =
                    UINT64_C(0x8877665544332211);
                const uint64_t initial_k3 =
                    UINT64_C(0x55aa55aa33cc33cc);
                const uint64_t initial_rflags = UINT64_C(0xcd7);
                uint64_t k1 = initial_k1;
                uint64_t k2 = initial_k2;
                uint64_t k3 = initial_k3;
                uint64_t rflags = initial_rflags;
                uint64_t rip = 0;
                uc_engine *uc;

                uc_common_setup_cpu(&uc, UC_MODE_64,
                                    width_cases[i].cpu_model,
                                    width_cases[i].code,
                                    width_cases[i].code_size);
                OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
                OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
                OK(uc_reg_write(uc, UC_X86_REG_K3, &k3));
                OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
                uc_assert_err(
                    UC_ERR_INSN_INVALID,
                    uc_emu_start(uc, code_start,
                                 code_start + width_cases[i].code_size,
                                 0, 0));
                OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
                OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
                OK(uc_reg_read(uc, UC_X86_REG_K3, &k3));
                OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
                OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
                TEST_CHECK_(k1 == initial_k1 && k2 == initial_k2 &&
                                k3 == initial_k3,
                            "%s changed opmask state", width_cases[i].name);
                TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                            width_cases[i].name);
                TEST_CHECK_(rip == code_start, "%s advanced RIP",
                            width_cases[i].name);
                OK(uc_close(uc));
            }
        }
    }

    /* APX promotes the scalar-conversion GPR operand through B4.  It must
     * select the EGPR bank on an APX model and stay #UD elsewhere. */
    {
        static const uint8_t convert[] = {
            0x62, 0xd9, 0x6e, 0x08, 0x2a, 0xcd,
        }; /* vcvtsi2ss xmm1, xmm2, r29d */
        static const struct {
            int cpu_model;
            uc_err expected;
            const char *name;
        } convert_cases[] = {
            {UC_CPU_X86_APX, UC_ERR_OK, "APX EGPR scalar conversion"},
            {UC_CPU_X86_ICELAKE_SERVER, UC_ERR_INSN_INVALID,
             "EGPR scalar conversion without APX"},
        };

        for (size_t i = 0;
             i < sizeof(convert_cases) / sizeof(convert_cases[0]); ++i) {
            float merge_source[16];
            uint8_t initial[64];
            float observed[16];
            uint64_t r13 = UINT64_C(0xfffffff7);
            uint64_t r29 = 37;
            uint64_t rflags = UINT64_C(0xcd7);
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            for (size_t lane = 0; lane < 16; ++lane) {
                merge_source[lane] = 10.0f + (float)lane;
            }
            memset(initial, 0x96, sizeof(initial));
            uc_common_setup_cpu(&uc, UC_MODE_64,
                                convert_cases[i].cpu_model, convert,
                                sizeof(convert));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM2, merge_source));
            OK(uc_reg_write(uc, UC_X86_REG_R13, &r13));
            if (convert_cases[i].expected == UC_ERR_OK) {
                OK(uc_reg_write(uc, UC_X86_REG_R29, &r29));
            }
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            err = uc_emu_start(uc, code_start,
                               code_start + sizeof(convert), 0, 0);
            OK(uc_reg_read(uc, UC_X86_REG_ZMM1, observed));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(err == convert_cases[i].expected,
                        "%s returned %s", convert_cases[i].name,
                        uc_strerror(err));
            TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS",
                        convert_cases[i].name);
            if (convert_cases[i].expected == UC_ERR_OK) {
                TEST_CHECK_(observed[0] == 37.0f,
                            "%s read the wrong GPR bank",
                            convert_cases[i].name);
                for (size_t lane = 1; lane < 4; ++lane) {
                    TEST_CHECK_(observed[lane] == merge_source[lane],
                                "%s merge lane %zu mismatch",
                                convert_cases[i].name, lane);
                }
                TEST_CHECK(rip == code_start + sizeof(convert));
            } else {
                TEST_CHECK(memcmp(observed, initial, sizeof(initial)) == 0);
                TEST_CHECK(rip == code_start);
            }
            OK(uc_close(uc));
        }

        {
            static const uint8_t low_gpr_cases[][6] = {
                {0x62, 0xf1, 0x6e, 0x08, 0x2a, 0xcd},
                {0x62, 0xb1, 0x6e, 0x08, 0x2a, 0xcd},
            };

            for (size_t i = 0;
                 i < sizeof(low_gpr_cases) / sizeof(low_gpr_cases[0]); ++i) {
                float merge_source[16];
                float observed[16];
                uint64_t rbp = 37;
                uint64_t rip = 0;
                uc_engine *uc;

                for (size_t lane = 0; lane < 16; ++lane) {
                    merge_source[lane] = 20.0f + (float)lane;
                }
                uc_common_setup_cpu(&uc, UC_MODE_64,
                                    UC_CPU_X86_KNIGHTSMILL,
                                    low_gpr_cases[i],
                                    sizeof(low_gpr_cases[i]));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM2, merge_source));
                OK(uc_reg_write(uc, UC_X86_REG_RBP, &rbp));
                OK(uc_emu_start(uc, code_start,
                                code_start + sizeof(low_gpr_cases[i]),
                                0, 0));
                OK(uc_reg_read(uc, UC_X86_REG_ZMM1, observed));
                OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
                TEST_CHECK_(observed[0] == 37.0f,
                            "scalar conversion used X3 as a GPR bit");
                TEST_CHECK(rip == code_start + sizeof(low_gpr_cases[i]));
                OK(uc_close(uc));
            }
        }
    }

    /* B4/X4 are ignored when an existing EVEX form has no corresponding GPR
     * operand.  Memory forms require APX only when the decoded base or index
     * really selects r16-r31, not merely because an unused prefix bit is set. */
    {
        static const struct {
            uint8_t code[10];
            size_t code_size;
            bool memory;
            bool rip_relative;
            const char *name;
        } ignored_cases[] = {
#define UC_DECODE_IGNORED(Name, Size, Memory, Rip, ...) \
    {{__VA_ARGS__}, Size, Memory, Rip, #Name},
#include "x86_decode_boundaries.def"
#undef UC_DECODE_IGNORED
        };

        for (size_t i = 0;
             i < sizeof(ignored_cases) / sizeof(ignored_cases[0]); ++i) {
            float source1[16];
            float source2[16];
            float observed[16];
            const uint64_t memory_address =
                ignored_cases[i].rip_relative
                    ? code_start + ignored_cases[i].code_size
                    : code_start + 0x500;
            uint64_t rax = memory_address;
            uint64_t rip = 0;
            uc_engine *uc;

            for (size_t lane = 0; lane < 16; ++lane) {
                source1[lane] = 1.0f;
                source2[lane] = 2.0f;
            }
            uc_common_setup_cpu(&uc, UC_MODE_64,
                                UC_CPU_X86_ICELAKE_SERVER,
                                ignored_cases[i].code,
                                ignored_cases[i].code_size);
            OK(uc_reg_write(uc, UC_X86_REG_ZMM1, source1));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM2, source2));
            if (ignored_cases[i].memory) {
                OK(uc_mem_write(uc, memory_address, source2,
                                sizeof(source2)));
                OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
            }
            OK(uc_emu_start(uc, code_start,
                            code_start + ignored_cases[i].code_size, 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_ZMM0, observed));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            for (size_t lane = 0; lane < 16; ++lane) {
                TEST_CHECK_(observed[lane] == 3.0f,
                            "%s lane %zu mismatch", ignored_cases[i].name,
                            lane);
            }
            TEST_CHECK_(rip == code_start + ignored_cases[i].code_size,
                        "%s did not retire", ignored_cases[i].name);
            OK(uc_close(uc));
        }

        {
            static const uint8_t broadcast[] = {
#define UC_DECODE_BROADCAST(...) __VA_ARGS__,
#include "x86_decode_boundaries.def"
#undef UC_DECODE_BROADCAST
            }; /* vpbroadcastd zmm0, xmm1 with unused B4 */
            uint32_t source[16] = {UINT32_C(0x12345678)};
            uint32_t observed[16];
            uc_engine *uc;

            uc_common_setup_cpu(&uc, UC_MODE_64,
                                UC_CPU_X86_ICELAKE_SERVER, broadcast,
                                sizeof(broadcast));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM1, source));
            OK(uc_emu_start(uc, code_start,
                            code_start + sizeof(broadcast), 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_ZMM0, observed));
            for (size_t lane = 0; lane < 16; ++lane) {
                TEST_CHECK(observed[lane] == source[0]);
            }
            OK(uc_close(uc));
        }
    }

    /* A decoded EGPR base/index is the point where the same EVEX arithmetic
     * form starts requiring APX_F. */
    {
        static const uint8_t code[] = {
            0x62, 0xf9, 0x70, 0x48, 0x58, 0x04, 0x08,
        }; /* vaddps zmm0, zmm1, [r16+r17] */
        static const struct {
            int cpu_model;
            uc_err expected;
            const char *name;
        } cases[] = {
            {UC_CPU_X86_APX, UC_ERR_OK, "EGPR address with APX"},
            {UC_CPU_X86_ICELAKE_SERVER, UC_ERR_INSN_INVALID,
             "EGPR address without APX"},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            const uint64_t memory_address = code_start + 0x600;
            uint64_t r16 = memory_address - 0x20;
            uint64_t r17 = 0x20;
            float source1[16];
            float memory[16];
            uint8_t initial[64];
            float observed[16];
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            for (size_t lane = 0; lane < 16; ++lane) {
                source1[lane] = 1.0f;
                memory[lane] = 2.0f;
            }
            memset(initial, 0xa7, sizeof(initial));
            uc_common_setup_cpu(&uc, UC_MODE_64, cases[i].cpu_model, code,
                                sizeof(code));
            OK(uc_mem_write(uc, memory_address, memory, sizeof(memory)));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM0, initial));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM1, source1));
            OK(uc_reg_write(uc, UC_X86_REG_R16, &r16));
            OK(uc_reg_write(uc, UC_X86_REG_R17, &r17));
            err = uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0);
            OK(uc_reg_read(uc, UC_X86_REG_ZMM0, observed));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(err == cases[i].expected, "%s returned %s",
                        cases[i].name, uc_strerror(err));
            if (cases[i].expected == UC_ERR_OK) {
                for (size_t lane = 0; lane < 16; ++lane) {
                    TEST_CHECK_(observed[lane] == 3.0f,
                                "%s lane %zu mismatch", cases[i].name,
                                lane);
                }
                TEST_CHECK(rip == code_start + sizeof(code));
            } else {
                TEST_CHECK(memcmp(observed, initial, sizeof(initial)) == 0);
                TEST_CHECK(rip == code_start);
            }
            OK(uc_close(uc));
        }
    }

    /* Canonicality follows the active memory elements.  A zero mask suppresses
     * every fault, and an active lane beyond a noncanonical masked-off lane is
     * checked at its own address rather than at the tuple base. */
    {
        static const uint8_t code[] = {
            0x62, 0xf9, 0x70, 0x49, 0x58, 0x04, 0x08,
        }; /* vaddps zmm0 {k1}, zmm1, [r16+r17] */
        static const struct {
            uint64_t base;
            uint64_t mask;
            uc_err expected;
            bool lane1_result;
            const char *name;
        } cases[] = {
            {UINT64_C(0x0000800000000000), 0, UC_ERR_OK, false,
             "all lanes masked"},
            {UINT64_C(0xffff7ffffffffffc), 2, UC_ERR_OK, true,
             "masked base before upper canonical range"},
            {UINT64_C(0x0000800000000000), 1, UC_ERR_EXCEPTION, false,
             "active noncanonical lane"},
        };
        /* Paging is disabled in these unit tests, so softmmu applies the
         * model's physical-address width after the canonical virtual check. */
        const uint64_t upper_memory_alias = UINT64_C(0x000f800000000000);

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            float source1[16];
            float initial[16];
            float observed[16];
            float memory = 2.0f;
            uint64_t r16 = cases[i].base;
            uint64_t r17 = 0;
            uint64_t k1 = cases[i].mask;
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            for (size_t lane = 0; lane < 16; ++lane) {
                source1[lane] = 1.0f;
                initial[lane] = 10.0f + (float)lane;
            }
            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                                sizeof(code));
            OK(uc_mem_map(uc, upper_memory_alias, 0x1000, UC_PROT_ALL));
            OK(uc_mem_write(uc, upper_memory_alias, &memory,
                            sizeof(memory)));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM0, initial));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM1, source1));
            OK(uc_reg_write(uc, UC_X86_REG_R16, &r16));
            OK(uc_reg_write(uc, UC_X86_REG_R17, &r17));
            OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
            err = uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0);
            OK(uc_reg_read(uc, UC_X86_REG_ZMM0, observed));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(err == cases[i].expected, "%s returned %s",
                        cases[i].name, uc_strerror(err));
            for (size_t lane = 0; lane < 16; ++lane) {
                const float expected =
                    cases[i].lane1_result && lane == 1
                        ? 3.0f
                        : initial[lane];
                TEST_CHECK_(observed[lane] == expected,
                            "%s lane %zu mismatch", cases[i].name, lane);
            }
            TEST_CHECK_(rip == (cases[i].expected == UC_ERR_OK
                                    ? code_start + sizeof(code)
                                    : code_start),
                        "%s RIP mismatch", cases[i].name);
            OK(uc_close(uc));
        }

        {
            static const uint8_t ordinary[] = {
                0x62, 0xf1, 0x74, 0x49, 0x58, 0x00,
            }; /* vaddps zmm0 {k1}, zmm1, [rax] */
            static const struct {
                uint64_t mask;
                uc_err expected;
            } ordinary_cases[] = {
                {0, UC_ERR_OK},
                {1, UC_ERR_EXCEPTION},
            };

            for (size_t i = 0;
                 i < sizeof(ordinary_cases) / sizeof(ordinary_cases[0]);
                 ++i) {
                float initial[16];
                float observed[16];
                uint64_t rax = UINT64_C(0x0000800000000000);
                uint64_t k1 = ordinary_cases[i].mask;
                uint64_t rip = 0;
                uc_engine *uc;
                uc_err err;

                for (size_t lane = 0; lane < 16; ++lane) {
                    initial[lane] = 30.0f + (float)lane;
                }
                uc_common_setup_cpu(&uc, UC_MODE_64,
                                    UC_CPU_X86_ICELAKE_SERVER, ordinary,
                                    sizeof(ordinary));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM0, initial));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial));
                OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
                OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
                err = uc_emu_start(uc, code_start,
                                   code_start + sizeof(ordinary), 0, 0);
                OK(uc_reg_read(uc, UC_X86_REG_ZMM0, observed));
                OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
                TEST_CHECK(err == ordinary_cases[i].expected);
                TEST_CHECK(memcmp(observed, initial, sizeof(initial)) == 0);
                TEST_CHECK(rip == (ordinary_cases[i].expected == UC_ERR_OK
                                       ? code_start + sizeof(ordinary)
                                       : code_start));
                OK(uc_close(uc));
            }
        }

        /* Tuple broadcasts access only source components selected by at
         * least one destination lane.  Component zero ends at the canonical
         * boundary; component one begins outside it. */
        {
            static const uint8_t broadcast[] = {
                0x62, 0xfa, 0x7d, 0x4b, 0x1a, 0x08,
            }; /* vbroadcastf32x4 zmm1 {k3}, [r16] */
            static const struct {
                uint64_t mask;
                uc_err expected;
                const char *name;
            } broadcast_cases[] = {
                {1, UC_ERR_OK, "active canonical tuple component"},
                {2, UC_ERR_EXCEPTION, "active noncanonical tuple component"},
            };
            const uint64_t address = UINT64_C(0x00007ffffffffffc);
            const uint64_t page = UINT64_C(0x00007ffffffff000);

            for (size_t i = 0;
                 i < sizeof(broadcast_cases) / sizeof(broadcast_cases[0]);
                 ++i) {
                float initial[16];
                float observed[16];
                float memory = 7.0f;
                uint64_t r16 = address;
                uint64_t k3 = broadcast_cases[i].mask;
                uint64_t rip = 0;
                uc_engine *uc;
                uc_err err;

                for (size_t lane = 0; lane < 16; ++lane) {
                    initial[lane] = 20.0f + (float)lane;
                }
                uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX,
                                    broadcast, sizeof(broadcast));
                OK(uc_mem_map(uc, page, 0x1000, UC_PROT_ALL));
                OK(uc_mem_write(uc, address, &memory, sizeof(memory)));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial));
                OK(uc_reg_write(uc, UC_X86_REG_R16, &r16));
                OK(uc_reg_write(uc, UC_X86_REG_K3, &k3));
                err = uc_emu_start(uc, code_start,
                                   code_start + sizeof(broadcast), 0, 0);
                OK(uc_reg_read(uc, UC_X86_REG_ZMM1, observed));
                OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
                TEST_CHECK_(err == broadcast_cases[i].expected,
                            "%s returned %s", broadcast_cases[i].name,
                            uc_strerror(err));
                if (broadcast_cases[i].expected == UC_ERR_OK) {
                    TEST_CHECK(observed[0] == memory);
                    for (size_t lane = 1; lane < 16; ++lane) {
                        TEST_CHECK(observed[lane] == initial[lane]);
                    }
                    TEST_CHECK(rip == code_start + sizeof(broadcast));
                } else {
                    TEST_CHECK(memcmp(observed, initial, sizeof(initial)) ==
                               0);
                    TEST_CHECK(rip == code_start);
                }
                OK(uc_close(uc));
            }
        }
    }

    /* APX only extends the GPR operand of KMOV.  The instruction still
     * requires the architectural AVX-512 opmask/ZMM state. */
    {
        static const uint8_t apx_kmov[] = {
            0x62, 0xd9, 0x7c, 0x08, 0x92, 0xc8, /* kmovw k1, r24d */
        };
        const uint64_t source = UINT64_C(0x8877665544332211);
        const uint64_t initial = UINT64_C(0x0123456789abcdef);
        uint64_t k1 = initial;
        uint64_t r24 = source;
        uint64_t xcr0 = 0;
        uint64_t rip = 0;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, apx_kmov,
                            sizeof(apx_kmov));
        OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
        OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(apx_kmov), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
        TEST_CHECK(k1 == (source & UINT16_MAX));

        k1 = initial;
        OK(uc_reg_write(uc, UC_X86_REG_K1, &k1));
        OK(uc_reg_read(uc, UC_X86_REG_XCR0, &xcr0));
        xcr0 &= ~(UINT64_C(1) << 5); /* OPMASK state. */
        OK(uc_reg_write(uc, UC_X86_REG_XCR0, &xcr0));
        uc_assert_err(UC_ERR_INSN_INVALID,
                      uc_emu_start(uc, code_start,
                                   code_start + sizeof(apx_kmov), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_K1, &k1));
        OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK(k1 == initial);
        TEST_CHECK(r24 == source);
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }

    /* AVX-512F alone must not make extension-family instructions legal.
     * Knights Mill advertises ER, 4VNNIW, and 4FMAPS; Ice Lake does not. */
    {
        static const struct {
            uint8_t code[6];
            int destination;
            const char *name;
        } extension_cases[] = {
            {{0x62, 0x02, 0x7d, 0x48, 0xca, 0xfe}, UC_X86_REG_ZMM31,
             "AVX-512ER"},
            {{0x62, 0xe2, 0x5f, 0x40, 0x52, 0x08}, UC_X86_REG_ZMM17,
             "AVX-512_4VNNIW"},
            {{0x62, 0xe2, 0x5f, 0x40, 0x9a, 0x08}, UC_X86_REG_ZMM17,
             "AVX-512_4FMAPS"},
        };
        static const struct {
            int cpu_model;
            uc_err expected;
        } cpu_cases[] = {
            {UC_CPU_X86_ICELAKE_SERVER, UC_ERR_INSN_INVALID},
            {UC_CPU_X86_KNIGHTSMILL, UC_ERR_OK},
        };

        for (size_t op = 0;
             op < sizeof(extension_cases) / sizeof(extension_cases[0]);
             ++op) {
            for (size_t cpu = 0;
                 cpu < sizeof(cpu_cases) / sizeof(cpu_cases[0]); ++cpu) {
                const uint64_t data_address = code_start + 0x100;
                uint8_t initial[64];
                uint8_t observed[64];
                uint8_t source[64];
                uint8_t memory[16] = {0};
                uint64_t rax = data_address;
                uint64_t rip = 0;
                uint32_t mxcsr = UINT32_C(0x1fa0);
                uc_engine *uc;
                uc_err err;

                memset(initial, 0x3c, sizeof(initial));
                memset(source, 0x40, sizeof(source));
                uc_common_setup_cpu(&uc, UC_MODE_64,
                                    cpu_cases[cpu].cpu_model,
                                    extension_cases[op].code,
                                    sizeof(extension_cases[op].code));
                OK(uc_mem_write(uc, data_address, memory, sizeof(memory)));
                OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
                OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
                OK(uc_reg_write(uc, extension_cases[op].destination,
                                initial));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM1, source));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM30, source));
                for (int reg = UC_X86_REG_ZMM20; reg <= UC_X86_REG_ZMM23;
                     ++reg) {
                    OK(uc_reg_write(uc, reg, source));
                }

                err = uc_emu_start(uc, code_start,
                                   code_start + sizeof(extension_cases[op].code),
                                   0, 0);
                OK(uc_reg_read(uc, extension_cases[op].destination,
                               observed));
                OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
                TEST_CHECK_(err == cpu_cases[cpu].expected,
                            "%s feature gate returned %s",
                            extension_cases[op].name, uc_strerror(err));
                if (cpu_cases[cpu].expected == UC_ERR_INSN_INVALID) {
                    TEST_CHECK_(memcmp(observed, initial, sizeof(initial)) ==
                                    0,
                                "%s changed destination without CPUID",
                                extension_cases[op].name);
                    TEST_CHECK_(rip == code_start,
                                "%s advanced RIP without CPUID",
                                extension_cases[op].name);
                } else {
                    TEST_CHECK_(rip ==
                                    code_start +
                                        sizeof(extension_cases[op].code),
                                "%s did not complete with CPUID",
                                extension_cases[op].name);
                }
                OK(uc_close(uc));
            }
        }
    }

    /* VMOVDQU8/16 require AVX-512BW.  The conservative TCG feature surface
     * keeps BW hidden until the complete family is available. */
    {
        static const struct {
            uint8_t code[6];
            const char *name;
        } cases[] = {
            {{0x62, 0x21, 0x7f, 0x48, 0x6f, 0xfc}, "VMOVDQU8"},
            {{0x62, 0x21, 0xff, 0x48, 0x6f, 0xfc}, "VMOVDQU16"},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint8_t source[64];
            uint8_t initial[64];
            uint8_t observed[64];
            uint64_t rip = 0;
            uc_engine *uc;

            memset(source, 0x26, sizeof(source));
            memset(initial, 0x93, sizeof(initial));
            uc_common_setup_cpu(&uc, UC_MODE_64,
                                UC_CPU_X86_ICELAKE_SERVER, cases[i].code,
                                sizeof(cases[i].code));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM20, source));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
            uc_assert_err(
                UC_ERR_INSN_INVALID,
                uc_emu_start(uc, code_start,
                             code_start + sizeof(cases[i].code), 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_ZMM31, observed));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(memcmp(observed, initial, sizeof(initial)) == 0,
                        "%s changed destination", cases[i].name);
            TEST_CHECK_(rip == code_start, "%s advanced RIP",
                        cases[i].name);
            OK(uc_close(uc));
        }
    }

    /* EVEX crypto opcodes retain their individual CPUID requirements in
     * addition to AVX-512F and the architectural vector state. */
    {
        static const int cpu_models[] = {
            UC_CPU_X86_ICELAKE_SERVER,
            UC_CPU_X86_KNIGHTSMILL,
        };
        static const struct {
            uint8_t code[7];
            size_t code_size;
            uc_err expected[2];
            const char *name;
        } cases[] = {
            {{0x62, 0xf2, 0x6d, 0x48, 0xdc, 0xcb}, 6,
             {UC_ERR_INSN_INVALID, UC_ERR_INSN_INVALID}, "VAES"},
            {{0x62, 0xf2, 0x6d, 0x48, 0xcf, 0xcb}, 6,
             {UC_ERR_OK, UC_ERR_INSN_INVALID}, "GFNI"},
            {{0x62, 0xf3, 0x6d, 0x48, 0x44, 0xcb, 0x00}, 7,
             {UC_ERR_OK, UC_ERR_INSN_INVALID}, "VPCLMULQDQ"},
        };

        for (size_t op = 0; op < sizeof(cases) / sizeof(cases[0]); ++op) {
            for (size_t cpu = 0;
                 cpu < sizeof(cpu_models) / sizeof(cpu_models[0]); ++cpu) {
                uint8_t source1[64];
                uint8_t source2[64];
                uint8_t initial[64];
                uint8_t observed[64];
                uint64_t rip = 0;
                uc_engine *uc;
                uc_err err;

                memset(source1, 0x11, sizeof(source1));
                memset(source2, 0x37, sizeof(source2));
                memset(initial, 0xa6, sizeof(initial));
                uc_common_setup_cpu(&uc, UC_MODE_64, cpu_models[cpu],
                                    cases[op].code, cases[op].code_size);
                OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM2, source1));
                OK(uc_reg_write(uc, UC_X86_REG_ZMM3, source2));
                err = uc_emu_start(uc, code_start,
                                   code_start + cases[op].code_size, 0, 0);
                OK(uc_reg_read(uc, UC_X86_REG_ZMM1, observed));
                OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
                TEST_CHECK_(err == cases[op].expected[cpu],
                            "%s feature gate returned %s",
                            cases[op].name, uc_strerror(err));
                if (cases[op].expected[cpu] == UC_ERR_INSN_INVALID) {
                    TEST_CHECK_(memcmp(observed, initial, sizeof(initial)) ==
                                    0,
                                "%s changed destination without CPUID",
                                cases[op].name);
                    TEST_CHECK_(rip == code_start,
                                "%s advanced RIP without CPUID",
                                cases[op].name);
                } else {
                    TEST_CHECK_(rip == code_start + cases[op].code_size,
                                "%s did not complete with CPUID",
                                cases[op].name);
                }
                OK(uc_close(uc));
            }
        }
    }

    /* Hidden extension families must remain unreachable until their whole
     * architectural surface is exposed by TCG. */
    {
        static const struct {
            uint8_t code[7];
            size_t code_size;
            const char *name;
        } cases[] = {
            {{0x62, 0xf2, 0x7d, 0x48, 0x44, 0xc1}, 6, "AVX-512CD"},
            {{0x62, 0xf2, 0xf5, 0x48, 0xb4, 0xc2}, 6, "AVX-512IFMA"},
            {{0x62, 0xf2, 0x75, 0x48, 0x8d, 0xc2}, 6, "AVX-512VBMI"},
            {{0x62, 0xf2, 0x7d, 0x48, 0x62, 0xc1}, 6, "AVX-512VBMI2"},
            {{0x62, 0xf2, 0x75, 0x48, 0x71, 0xc2}, 6,
             "AVX-512VBMI2 variable shift"},
            {{0x62, 0xf3, 0x75, 0x48, 0x71, 0xc2, 0x05}, 7,
             "AVX-512VBMI2 immediate shift"},
            {{0x62, 0xf2, 0x75, 0x48, 0x50, 0xc2}, 6, "AVX-512VNNI"},
            {{0x62, 0xf2, 0x7d, 0x48, 0x54, 0xc1}, 6, "AVX-512BITALG"},
            {{0x62, 0xf2, 0x7d, 0x48, 0x55, 0xc1}, 6,
             "AVX-512VPOPCNTDQ"},
            {{0x62, 0xf3, 0x75, 0x48, 0x42, 0xc2, 0xe4}, 7,
             "AVX-512BW DBPSADBW"},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint8_t source1[64];
            uint8_t source2[64];
            uint8_t initial[64];
            uint8_t observed[64];
            uint64_t rip = 0;
            uc_engine *uc;

            memset(source1, 0x12, sizeof(source1));
            memset(source2, 0x34, sizeof(source2));
            memset(initial, 0x9b, sizeof(initial));
            uc_common_setup_cpu(&uc, UC_MODE_64,
                                UC_CPU_X86_ICELAKE_SERVER, cases[i].code,
                                cases[i].code_size);
            OK(uc_reg_write(uc, UC_X86_REG_ZMM0, initial));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM1, source1));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM2, source1));
            OK(uc_reg_write(uc, UC_X86_REG_ZMM3, source2));
            uc_assert_err(
                UC_ERR_INSN_INVALID,
                uc_emu_start(uc, code_start,
                             code_start + cases[i].code_size, 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_ZMM0, observed));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(memcmp(observed, initial, sizeof(initial)) == 0,
                        "%s changed destination", cases[i].name);
            TEST_CHECK_(rip == code_start, "%s advanced RIP",
                        cases[i].name);
            OK(uc_close(uc));
        }
    }

    /* APX EVEX-promoted atomics are long-mode-only even when their P0 byte
     * is EVEX-shaped in a 32-bit code segment. */
    {
        static const struct {
            uint8_t code[6];
            uint32_t edx;
            uint32_t ebx;
            const char *name;
        } cases[] = {
            {{0x62, 0xf4, 0x7c, 0x08, 0xfc, 0x11}, 3, 0x12345678,
             "RAO-INT"},
            {{0x62, 0xf2, 0x65, 0x08, 0xe4, 0x11}, 5, 3,
             "CMPccXADD"},
        };
        const uint32_t data_address = 0x1800;
        const uint32_t initial_memory = 5;
        const uint32_t initial_eflags = UINT32_C(0xcd7);

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint32_t ecx = data_address;
            uint32_t edx = cases[i].edx;
            uint32_t ebx = cases[i].ebx;
            uint32_t memory = initial_memory;
            uint32_t eflags = initial_eflags;
            uint32_t eip = 0;
            uc_engine *uc;

            uc_common_setup_cpu(&uc, UC_MODE_32, UC_CPU_X86_APX,
                                cases[i].code, sizeof(cases[i].code));
            OK(uc_mem_write(uc, data_address, &memory, sizeof(memory)));
            OK(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
            OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
            OK(uc_reg_write(uc, UC_X86_REG_EBX, &ebx));
            OK(uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags));
            uc_assert_err(
                UC_ERR_INSN_INVALID,
                uc_emu_start(uc, code_start,
                             code_start + sizeof(cases[i].code), 0, 0));
            OK(uc_mem_read(uc, data_address, &memory, sizeof(memory)));
            OK(uc_reg_read(uc, UC_X86_REG_ECX, &ecx));
            OK(uc_reg_read(uc, UC_X86_REG_EDX, &edx));
            OK(uc_reg_read(uc, UC_X86_REG_EBX, &ebx));
            OK(uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags));
            OK(uc_reg_read(uc, UC_X86_REG_EIP, &eip));
            TEST_CHECK_(memory == initial_memory, "%s changed memory",
                        cases[i].name);
            TEST_CHECK_(ecx == data_address, "%s changed ECX",
                        cases[i].name);
            TEST_CHECK_(edx == cases[i].edx, "%s changed EDX",
                        cases[i].name);
            TEST_CHECK_(ebx == cases[i].ebx, "%s changed EBX",
                        cases[i].name);
            TEST_CHECK_(eflags == initial_eflags, "%s changed EFLAGS",
                        cases[i].name);
            TEST_CHECK_(eip == code_start, "%s advanced EIP",
                        cases[i].name);
            OK(uc_close(uc));
        }
    }
}

static void test_x86_avx512_4fmaps_scalar_accepts_all_llig_spellings(void)
{
    const uint64_t data_address = code_start + 0x100;
    const float memory[4] = { 10.0f, 20.0f, 30.0f, 40.0f };

    for (unsigned ll = 0; ll < 4; ++ll) {
        uint8_t code[] = {
            0x62, 0xf2, 0x5f, (uint8_t)(0x08 | (ll << 5)), 0x9b, 0x08,
        };
        const float initial[4] = { 5.0f, 9.0f, 10.0f, 11.0f };
        float observed[4] = { 0 };
        uint64_t rax = data_address;
        uint64_t rip = 0;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_KNIGHTSMILL, code,
                            sizeof(code));
        OK(uc_mem_write(uc, data_address, memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_XMM1, initial));
        for (unsigned source = 0; source < 4; ++source) {
            const float value[4] = { (float)(source + 1), 0.0f, 0.0f, 0.0f };
            OK(uc_reg_write(uc, UC_X86_REG_XMM4 + source, value));
        }

        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_XMM1, observed));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK_(observed[0] == 305.0f,
                    "LLIG spelling %u produced %g", ll, observed[0]);
        TEST_CHECK(observed[1] == initial[1]);
        TEST_CHECK(observed[2] == initial[2]);
        TEST_CHECK(observed[3] == initial[3]);
        TEST_CHECK(rip == code_start + sizeof(code));
        OK(uc_close(uc));
    }
}

static void test_x86_apx_rex2_mov_extension_fields(void)
{
    static const uint8_t code[] = {
        0xd5, 0x58, 0x89, 0xc8, /* mov r16, r17 */
        0xd5, 0x49, 0x89, 0xc9, /* mov r9, r17 */
        0xd5, 0x1c, 0x89, 0xc9, /* mov r17, r9 */
    };
    const uint64_t source = UINT64_C(0x8877665544332211);
    uint64_t r16 = 0;
    uint64_t r17 = source;
    uint64_t r9 = 0;
    uint64_t rflags = UINT64_C(0xcd7);
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_R16, &r16));
    OK(uc_reg_write(uc, UC_X86_REG_R17, &r17));
    OK(uc_reg_write(uc, UC_X86_REG_R9, &r9));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_R16, &r16));
    OK(uc_reg_read(uc, UC_X86_REG_R17, &r17));
    OK(uc_reg_read(uc, UC_X86_REG_R9, &r9));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

    TEST_CHECK(r16 == source);
    TEST_CHECK(r17 == source);
    TEST_CHECK(r9 == source);
    TEST_CHECK(rflags == UINT64_C(0xcd7));
    OK(uc_close(uc));
}

static void test_x86_apx_rex2_register_fields_and_ignored_prefixes(void)
{
    static const struct {
        uint8_t code[6];
        size_t code_size;
        uint64_t expected;
        const char *description;
    } cases[] = {
        {{0xd5, 0x77, 0x89, 0xc7},
         4,
         UINT64_C(0x0000000089abcdef),
         "unused X4/X3 bits"},
        {{0xf3, 0xd5, 0x55, 0x89, 0xc7},
         5,
         UINT64_C(0x0000000089abcdef),
         "F3 prefix"},
        {{0xf2, 0xd5, 0x55, 0x89, 0xc7},
         5,
         UINT64_C(0x0000000089abcdef),
         "F2 prefix"},
        {{0x67, 0xd5, 0x55, 0x89, 0xc7},
         5,
         UINT64_C(0x0000000089abcdef),
         "address-size prefix"},
        {{0x64, 0xd5, 0x55, 0x89, 0xc7},
         5,
         UINT64_C(0x0000000089abcdef),
         "segment prefix"},
        {{0xd5, 0x5d, 0x88, 0xc7},
         4,
         UINT64_C(0xfedcba98765432ef),
         "W ignored for a byte operation"},
        {{0x66, 0xd5, 0x55, 0x88, 0xc7},
         5,
         UINT64_C(0xfedcba98765432ef),
         "66 ignored for a byte operation"},
        {{0x66, 0xd5, 0x55, 0x89, 0xc7},
         5,
         UINT64_C(0xfedcba987654cdef),
         "66 selecting a word operation"},
        {{0x4f, 0x66, 0xd5, 0x55, 0x89, 0xc7},
         6,
         UINT64_C(0xfedcba987654cdef),
         "REX invalidated before REX2"},
        {{0x4f, 0x2e, 0xd5, 0x55, 0x89, 0xc7},
         6,
         UINT64_C(0x0000000089abcdef),
         "REX separated from REX2 by a segment prefix"},
        {{0x66, 0xd5, 0x5d, 0x89, 0xc7},
         5,
         UINT64_C(0x0123456789abcdef),
         "W overriding 66"},
    };
    const uint64_t source = UINT64_C(0x0123456789abcdef);
    const uint64_t initial_destination = UINT64_C(0xfedcba9876543210);
    const uint64_t initial_rflags = UINT64_C(0xcd7);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t r24 = source;
        uint64_t r31 = initial_destination;
        uint64_t rflags = initial_rflags;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, cases[i].code,
                            cases[i].code_size);
        OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + cases[i].code_size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

        TEST_CHECK_(r31 == cases[i].expected,
                    "%s produced the wrong destination", cases[i].description);
        TEST_CHECK_(r24 == source, "%s changed its source",
                    cases[i].description);
        TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                    cases[i].description);
        OK(uc_close(uc));
    }
}

static void test_x86_apx_rex2_low_and_extended_register_fields(void)
{
    {
        static const uint8_t code[] = {0xd5, 0x00, 0x88, 0xe5};
        uint64_t rsp = UINT64_C(0x0123456789abcd11);
        uint64_t rbp = UINT64_C(0xfedcba98765432aa);
        uint64_t rflags = UINT64_C(0xcd7);
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_write(uc, UC_X86_REG_RBP, &rbp));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_read(uc, UC_X86_REG_RBP, &rbp));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        TEST_CHECK(rsp == UINT64_C(0x0123456789abcd11));
        TEST_CHECK(rbp == UINT64_C(0xfedcba9876543211));
        TEST_CHECK(rflags == UINT64_C(0xcd7));
        OK(uc_close(uc));
    }

    {
        static const uint8_t code[] = {0xd5, 0x05, 0x00, 0xc1};
        uint64_t r8 = 1;
        uint64_t r9 = UINT64_C(0xfedcba987654327f);
        uint64_t rflags = UINT64_C(0x202);
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_R8, &r8));
        OK(uc_reg_write(uc, UC_X86_REG_R9, &r9));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_R8, &r8));
        OK(uc_reg_read(uc, UC_X86_REG_R9, &r9));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        TEST_CHECK(r8 == 1);
        TEST_CHECK(r9 == UINT64_C(0xfedcba9876543280));
        TEST_CHECK(rflags == UINT64_C(0xa92));
        OK(uc_close(uc));
    }

    {
        static const struct {
            uint8_t code[4];
            bool extended_destination;
        } cases[] = {
            {{0xd5, 0x40, 0x8b, 0xc0}, true},
            {{0xd5, 0x10, 0x8b, 0xc0}, false},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint64_t rax = cases[i].extended_destination
                               ? UINT64_C(0x0123456789abcdef)
                               : UINT64_C(0xfedcba9876543210);
            uint64_t r16 = cases[i].extended_destination
                               ? UINT64_C(0xfedcba9876543210)
                               : UINT64_C(0x0123456789abcdef);
            uint64_t rflags = UINT64_C(0xcd7);
            uc_engine *uc;

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX,
                                cases[i].code, sizeof(cases[i].code));
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
            OK(uc_reg_write(uc, UC_X86_REG_R16, &r16));
            OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
            OK(uc_emu_start(uc, code_start, code_start + sizeof(cases[i].code),
                            0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
            OK(uc_reg_read(uc, UC_X86_REG_R16, &r16));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

            TEST_CHECK_(cases[i].extended_destination
                            ? r16 == UINT64_C(0x0000000089abcdef)
                            : rax == UINT64_C(0x0000000089abcdef),
                        "mixed legacy/extended MOV destination mismatch");
            TEST_CHECK_(cases[i].extended_destination
                            ? rax == UINT64_C(0x0123456789abcdef)
                            : r16 == UINT64_C(0x0123456789abcdef),
                        "mixed legacy/extended MOV changed its source");
            TEST_CHECK(rflags == UINT64_C(0xcd7));
            OK(uc_close(uc));
        }
    }
}

static void test_x86_apx_unimplemented_forms_fail_closed(void)
{
    static const struct {
        uint8_t code[7];
        size_t code_size;
        const char *description;
    } cases[] = {
        {{0xd5, 0x5d, 0x83, 0xc7}, 4, "unimplemented immediate group"},
        {{0xd5, 0x50, 0x40, 0xc0}, 4, "reserved map-0 row"},
        {{0xd5, 0x80, 0x30, 0xc0}, 4, "reserved map-1 row"},
        {{0x48, 0xd5, 0x5d, 0x89, 0xca}, 5, "preceding REX"},
        {{0x66, 0x4f, 0xd5, 0x55, 0x89, 0xc7},
         6,
         "effective REX immediately before REX2"},
        {{0xf0, 0xd5, 0x5d, 0x01, 0x07}, 5, "unsupported locked memory ADD"},
        {{0xd5, 0x5d, 0x66, 0x89, 0xca}, 5, "legacy prefix after REX2"},
        {{0xd5, 0xdd, 0x0f, 0xaf, 0xd1},
         5,
         "legacy map escape after map-1 REX2"},
        {{0xd5, 0x55, 0xff}, 3, "unsupported REX2 opcode"},
    };
    const uint64_t initial_r9 = UINT64_C(0x0909090909090909);
    const uint64_t initial_r16 = UINT64_C(0x1616161616161616);
    const uint64_t initial_r24 = UINT64_C(0x2424242424242424);
    const uint64_t initial_r25 = code_start + 0x300;
    const uint64_t initial_r26 = UINT64_C(0x2626262626262626);
    const uint64_t initial_r31 = UINT64_C(0x3131313131313131);
    const uint64_t initial_memory = UINT64_C(0xa5a5a5a5a5a5a5a5);
    const uint64_t initial_rflags = UINT64_C(0xcd7);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t r9 = initial_r9;
        uint64_t r16 = initial_r16;
        uint64_t r24 = initial_r24;
        uint64_t r25 = initial_r25;
        uint64_t r26 = initial_r26;
        uint64_t r31 = initial_r31;
        uint64_t memory = initial_memory;
        uint64_t rflags = initial_rflags;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX, cases[i].code,
                            cases[i].code_size);
        OK(uc_mem_write(uc, initial_r25, &memory, sizeof(memory)));
        OK(uc_reg_write(uc, UC_X86_REG_R9, &r9));
        OK(uc_reg_write(uc, UC_X86_REG_R16, &r16));
        OK(uc_reg_write(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_write(uc, UC_X86_REG_R25, &r25));
        OK(uc_reg_write(uc, UC_X86_REG_R26, &r26));
        OK(uc_reg_write(uc, UC_X86_REG_R31, &r31));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err =
            uc_emu_start(uc, code_start, code_start + cases[i].code_size, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_R9, &r9));
        OK(uc_reg_read(uc, UC_X86_REG_R16, &r16));
        OK(uc_reg_read(uc, UC_X86_REG_R24, &r24));
        OK(uc_reg_read(uc, UC_X86_REG_R25, &r25));
        OK(uc_reg_read(uc, UC_X86_REG_R26, &r26));
        OK(uc_reg_read(uc, UC_X86_REG_R31, &r31));
        OK(uc_mem_read(uc, initial_r25, &memory, sizeof(memory)));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    cases[i].description);
        TEST_CHECK_(r9 == initial_r9 && r16 == initial_r16 &&
                        r24 == initial_r24 && r25 == initial_r25 &&
                        r26 == initial_r26 && r31 == initial_r31,
                    "%s changed GPR state", cases[i].description);
        TEST_CHECK_(memory == initial_memory, "%s changed memory",
                    cases[i].description);
        TEST_CHECK_(rflags == initial_rflags, "%s changed RFLAGS",
                    cases[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP", cases[i].description);
        OK(uc_close(uc));
    }
}

static void run_x86_sha_reg(const char *code, size_t code_size,
                            const uint32_t dst_init[4], const uint32_t src[4],
                            const uint32_t xmm0[4], const uint32_t expected[4])
{
    uc_engine *uc;
    uint32_t dst[4];

    memcpy(dst, dst_init, sizeof(dst));

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_DENVERTON));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, code_size));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, dst));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, src));
    if (xmm0 != NULL) {
        OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0));
    }

    OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_XMM1, dst));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void run_x86_sha_mem(const char *code, size_t code_size,
                            const uint32_t dst_init[4],
                            const uint32_t src[4],
                            const uint32_t expected[4])
{
    uc_engine *uc;
    uint64_t src_addr = 0x2000;
    uint32_t dst[4];

    memcpy(dst, dst_init, sizeof(dst));
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_DENVERTON));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, code_size));
    OK(uc_mem_write(uc, src_addr, src, 16));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &src_addr));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, dst));

    OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_XMM1, dst));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static const uint32_t sha_dst[4] = {0x01234567, 0x89abcdef, 0xfedcba98,
                                    0x76543210};
static const uint32_t sha_src[4] = {0x0f1e2d3c, 0x4b5a6978, 0x8796a5b4,
                                    0xc3d2e1f0};

static void test_x86_sha1msg1(void)
{
    /* sha1msg1 xmm1, xmm2 */
    const char code[] = "\x0f\x38\xc9\xca";
    const uint32_t dst[4] = {0x11111111, 0x22222222, 0x33333333,
                             0x44444444};
    const uint32_t src[4] = {0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc,
                             0xdddddddd};
    const uint32_t expected[4] = {0xdddddddd, 0xffffffff, 0x22222222,
                                  0x66666666};
    run_x86_sha_reg(code, sizeof(code) - 1, dst, src, NULL, expected);
}

static void test_x86_sha1nexte(void)
{
    /* sha1nexte xmm1, xmm2 */
    const char code[] = "\x0f\x38\xc8\xca";
    const uint32_t expected[4] = {0x0f1e2d3c, 0x4b5a6978, 0x8796a5b4,
                                  0xe167ee74};
    run_x86_sha_reg(code, sizeof(code) - 1, sha_dst, sha_src, NULL, expected);
}

static void test_x86_sha1msg2_memory(void)
{
    /* sha1msg2 xmm1, [rax] */
    const char code[] = "\x0f\x38\xca\x08";
    const uint32_t expected[4] = {0xc54cd45d, 0x0d6bc1a7, 0x6b0da7c1,
                                  0xe3852f49};
    run_x86_sha_mem(code, sizeof(code) - 1, sha_dst, sha_src, expected);
}

static void test_x86_sha1rnds4_immediates(void)
{
    static const uint32_t expected[4][4] = {
        {0x9ca1dae1, 0x7cfa715c, 0xca766be2, 0x94db1ab9},
        {0xdce1d06b, 0xca313780, 0xae2146fa, 0x6b8829c4},
        {0x69c82bb2, 0x4ee8abf4, 0x182d1cee, 0x1d14e611},
        {0x33c405f9, 0xfd5a1eb8, 0x39aa8b81, 0x29c3017d},
    };
    char code[] = "\x0f\x3a\xcc\xca\x00"; /* sha1rnds4 xmm1, xmm2, imm8 */
    unsigned i;

    for (i = 0; i < 4; ++i) {
        code[4] = (char)i;
        run_x86_sha_reg(code, sizeof(code) - 1, sha_dst, sha_src, NULL,
                        expected[i]);
    }
}

static void test_x86_sha256msg1(void)
{
    /* sha256msg1 xmm1, xmm2 */
    const char code[] = "\x0f\x38\xcc\xca";
    const uint32_t expected[4] = {0x3e8111b3, 0x8a2bdf80, 0x217eee4b,
                                  0x69072c4a};
    run_x86_sha_reg(code, sizeof(code) - 1, sha_dst, sha_src, NULL, expected);
}

static void test_x86_sha256msg2_memory(void)
{
    /* sha256msg2 xmm1, [rax] */
    const char code[] = "\x0f\x38\xcd\x08";
    const uint32_t expected[4] = {0x87707bf7, 0xb6a25b1a, 0x3181a9e0,
                                  0xdd17d723};
    run_x86_sha_mem(code, sizeof(code) - 1, sha_dst, sha_src, expected);
}

static void test_x86_sha256rnds2(void)
{
    /* sha256rnds2 xmm1, xmm2; XMM0 supplies the two message words. */
    const char code[] = "\x0f\x38\xcb\xca";
    const uint32_t xmm0[4] = {0x10203040, 0x50607080, 0, 0};
    const uint32_t expected[4] = {0xfeec9ccb, 0x5c84a41a, 0x3cdbe9c7,
                                  0x5cab545b};
    run_x86_sha_reg(code, sizeof(code) - 1, sha_dst, sha_src, xmm0, expected);
}

static const uint8_t gfni_x[32] = {
    0x00, 0x01, 0x02, 0x03, 0x10, 0x20, 0x40, 0x80,
    0xff, 0x53, 0xca, 0x7f, 0x81, 0x1b, 0xae, 0x37,
    0x11, 0x22, 0x44, 0x88, 0x99, 0xaa, 0xcc, 0xee,
    0x13, 0x26, 0x4c, 0x98, 0x2f, 0x5e, 0xbc, 0x7d,
};

static const uint8_t gfni_a[32] = {
    0x00, 0x01, 0x03, 0x05, 0x07, 0x0b, 0x0d, 0x11,
    0xf1, 0xe2, 0xd4, 0xb8, 0x70, 0x60, 0x50, 0x40,
    0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01,
    0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
};

static void run_x86_gfni(const char *code, size_t code_size, bool vex,
                         bool ymm, bool memory_source,
                         const uint8_t *expected)
{
    uc_engine *uc;
    uint64_t src_addr = 0x3000;
    uint8_t result[32] = {0};
    int dst_reg = ymm ? UC_X86_REG_YMM1 : UC_X86_REG_XMM1;
    int src1_reg = ymm ? UC_X86_REG_YMM2 : UC_X86_REG_XMM2;
    int src2_reg = ymm ? UC_X86_REG_YMM3 : UC_X86_REG_XMM3;
    size_t width = ymm ? 32 : 16;

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_ICELAKE_CLIENT));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, code_size));
    if (vex) {
        OK(uc_reg_write(uc, src1_reg, gfni_x));
    } else {
        OK(uc_reg_write(uc, dst_reg, gfni_x));
    }
    if (memory_source) {
        OK(uc_mem_write(uc, src_addr, gfni_a, width));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &src_addr));
    } else {
        OK(uc_reg_write(uc, vex ? src2_reg : src1_reg, gfni_a));
    }

    OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
    OK(uc_reg_read(uc, dst_reg, result));
    TEST_CHECK(memcmp(result, expected, width) == 0);

    OK(uc_close(uc));
}

static void test_x86_gf2p8mulb_legacy(void)
{
    const char code[] = "\x66\x0f\x38\xcf\xca";
    const uint8_t expected[16] = {0x00, 0x01, 0x06, 0x0f, 0x70, 0x7b,
                                  0x6d, 0x58, 0x9e, 0x21, 0xe1, 0xe2,
                                  0x4e, 0xd7, 0x36, 0x6f};
    run_x86_gfni(code, sizeof(code) - 1, false, false, false, expected);
}

static void test_x86_vgf2p8mulb_xmm(void)
{
    const char code[] = "\xc4\xe2\x69\xcf\xcb";
    const uint8_t expected[16] = {0x00, 0x01, 0x06, 0x0f, 0x70, 0x7b,
                                  0x6d, 0x58, 0x9e, 0x21, 0xe1, 0xe2,
                                  0x4e, 0xd7, 0x36, 0x6f};
    run_x86_gfni(code, sizeof(code) - 1, true, false, false, expected);
}

static void test_x86_vgf2p8mulb_ymm_memory(void)
{
    const char code[] = "\xc4\xe2\x6d\xcf\x08";
    const uint8_t expected[32] = {
        0x00, 0x01, 0x06, 0x0f, 0x70, 0x7b, 0x6d, 0x58,
        0x9e, 0x21, 0xe1, 0xe2, 0x4e, 0xd7, 0x36, 0x6f,
        0x58, 0x58, 0x58, 0x58, 0xa4, 0x9e, 0x83, 0xee,
        0x86, 0x2e, 0xb8, 0xd6, 0xef, 0x91, 0x72, 0x94,
    };
    run_x86_gfni(code, sizeof(code) - 1, true, true, true, expected);
}

static void test_x86_gf2p8affineqb_legacy(void)
{
    const char code[] = "\x66\x0f\x3a\xce\xca\x63";
    const uint8_t expected[16] = {0x63, 0x1c, 0x4f, 0x30, 0x62, 0x63,
                                  0x63, 0x63, 0xea, 0xf6, 0x2c, 0x1a,
                                  0x13, 0x09, 0x3f, 0xe5};
    run_x86_gfni(code, sizeof(code) - 1, false, false, false, expected);
}

static void test_x86_gf2p8affineinvqb_legacy_memory(void)
{
    const char code[] = "\x66\x0f\x3a\xcf\x08\xa5";
    const uint8_t expected[16] = {0xa5, 0xda, 0xc6, 0x92, 0xbe, 0x8e,
                                  0xc7, 0xf6, 0x2f, 0xea, 0x30, 0x15,
                                  0x5c, 0x8a, 0x40, 0x0a};
    run_x86_gfni(code, sizeof(code) - 1, false, false, true, expected);
}

static void test_x86_vgf2p8affineqb_xmm(void)
{
    const char code[] = "\xc4\xe3\xe9\xce\xcb\x5a";
    const uint8_t expected[16] = {0x5a, 0x25, 0x76, 0x09, 0x5b, 0x5a,
                                  0x5a, 0x5a, 0xd3, 0xcf, 0x15, 0x23,
                                  0x2a, 0x30, 0x06, 0xdc};
    run_x86_gfni(code, sizeof(code) - 1, true, false, false, expected);
}

static void test_x86_vgf2p8affineinvqb_ymm(void)
{
    const char code[] = "\xc4\xe3\xed\xcf\xcb\xc3";
    const uint8_t expected[32] = {
        0xc3, 0xbc, 0xa0, 0xf4, 0xd8, 0xe8, 0xa1, 0x90,
        0x49, 0x8c, 0x56, 0x73, 0x3a, 0xec, 0x26, 0x6c,
        0x77, 0x99, 0xee, 0x58, 0xd7, 0xd1, 0xd8, 0xdd,
        0x0e, 0x0f, 0x40, 0xde, 0x26, 0x13, 0x35, 0x22,
    };
    run_x86_gfni(code, sizeof(code) - 1, true, true, false, expected);
}

static void test_x86_relative_jump(void)
{
    uc_engine *uc;
    char code[] = "\xeb\x02\x90\x90\x90\x90\x90\x90"; // jmp 4; nop; nop; nop;
                                                      // nop; nop; nop
    int r_eip;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EIP, &r_eip));

    TEST_CHECK(r_eip == code_start + 4);

    OK(uc_close(uc));
}

static void test_x86_loop(void)
{
    uc_engine *uc;
    char code[] = "\x41\x4a\xeb\xfe"; // inc ecx; dec edx; jmp $;
    int r_ecx = 0x1234;
    int r_edx = 0x7890;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 1 * 1000000,
                    0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_ecx == 0x1235);
    TEST_CHECK(r_edx == 0x788f);

    OK(uc_close(uc));
}

static void test_x86_invalid_mem_read(void)
{
    uc_engine *uc;
    char code[] = "\x8b\x0d\xaa\xaa\xaa\xaa"; // mov  ecx, [0xAAAAAAAA]

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    uc_assert_err(
        UC_ERR_READ_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_x86_invalid_mem_write(void)
{
    uc_engine *uc;
    char code[] = "\x89\x0d\xaa\xaa\xaa\xaa"; // mov  ecx, [0xAAAAAAAA]

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    uc_assert_err(
        UC_ERR_WRITE_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_x86_invalid_jump(void)
{
    uc_engine *uc;
    char code[] = "\xe9\xe9\xee\xee\xee"; // jmp 0xEEEEEEEE

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    uc_assert_err(
        UC_ERR_FETCH_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_x86_64_syscall_callback(uc_engine *uc, void *user_data)
{
    uint64_t rax;

    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));

    TEST_CHECK(rax == 0x100);
}

static void test_x86_64_syscall(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\x0f\x05"; // syscall
    uint64_t r_rax = 0x100;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_hook_add(uc, &hook, UC_HOOK_INSN, test_x86_64_syscall_callback, NULL,
                   1, 0, UC_X86_INS_SYSCALL));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

static void test_x86_16_add(void)
{
    uc_engine *uc;
    char code[] = "\x00\x00"; // add   byte ptr [bx + si], al
    uint16_t r_ax = 7;
    uint16_t r_bx = 5;
    uint16_t r_si = 6;
    uint8_t result;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_16, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, 0, 0x1000, UC_PROT_ALL));
    OK(uc_reg_write(uc, UC_X86_REG_AX, &r_ax));
    OK(uc_reg_write(uc, UC_X86_REG_BX, &r_bx));
    OK(uc_reg_write(uc, UC_X86_REG_SI, &r_si));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, r_bx + r_si, &result, 1));
    TEST_CHECK(result == 7);
    OK(uc_close(uc));
}

static void test_x86_reg_save(void)
{
    uc_engine *uc;
    uc_context *ctx;
    char code[] = "\x40"; // inc eax
    int r_eax = 1;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &r_eax));

    OK(uc_context_alloc(uc, &ctx));
    OK(uc_context_save(uc, ctx));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &r_eax));
    TEST_CHECK(r_eax == 2);

    OK(uc_context_restore(uc, ctx));

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &r_eax));
    TEST_CHECK(r_eax == 1);

    OK(uc_context_free(ctx));
    OK(uc_close(uc));
}

static bool
test_x86_invalid_mem_read_stop_in_cb_callback(uc_engine *uc, uc_mem_type type,
                                              uint64_t address, int size,
                                              uint64_t value, void *user_data)
{
    // False indicates that we fail to handle this ERROR and let the emulation
    // stop.
    //
    // Note that the memory must be mapped properly if we return true! Check
    // test_x86_mem_hook_all for example.
    return false;
}

static void test_x86_invalid_mem_read_stop_in_cb(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\x40\x8b\x1d\x00\x00\x10\x00\x42"; // inc eax; mov ebx,
                                                      // [0x100000]; inc edx
    int r_eax = 0x1234;
    int r_edx = 0x5678;
    int r_eip = 0;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_READ,
                   test_x86_invalid_mem_read_stop_in_cb_callback, NULL, 1, 0));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &r_eax));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));

    uc_assert_err(
        UC_ERR_READ_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    // The state of Unicorn should be correct at this time.
    OK(uc_reg_read(uc, UC_X86_REG_EIP, &r_eip));
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &r_eax));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_eip == code_start + 1);
    TEST_CHECK(r_eax == 0x1235);
    TEST_CHECK(r_edx == 0x5678);

    OK(uc_close(uc));
}

static void test_x86_x87_fnstenv_callback(uc_engine *uc, uint64_t address,
                                          uint32_t size, void *user_data)
{
    uint32_t r_eip;
    uint32_t r_eax;
    uint32_t fnstenv[7];

    if (address == code_start + 4) { // The first fnstenv executed
        // Save the address of the fld.
        OK(uc_reg_read(uc, UC_X86_REG_EIP, &r_eip));
        *((uint32_t *)user_data) = r_eip;

        OK(uc_reg_read(uc, UC_X86_REG_EAX, &r_eax));
        OK(uc_mem_read(uc, r_eax, fnstenv, sizeof(fnstenv)));
        // Don't update FCS:FIP for fnop.
        TEST_CHECK(fnstenv[3] == 0);
    }
}

static void test_x86_x87_fnstenv(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] =
        "\xd9\xd0\xd9\x30\xd9\x00\xd9\x30"; // fnop;fnstenv [eax];fld dword ptr
                                            // [eax];fnstenv [eax]
    uint32_t base = code_start + 3 * code_len;
    uint32_t last_eip;
    uint32_t fnstenv[7];

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, base, code_len, UC_PROT_ALL));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &base));

    OK(uc_hook_add(uc, &hook, UC_HOOK_CODE, test_x86_x87_fnstenv_callback,
                   &last_eip, 1, 0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, base, fnstenv, sizeof(fnstenv)));
    // But update FCS:FIP for fld.
    TEST_CHECK(LEINT32(fnstenv[3]) == last_eip);

    OK(uc_close(uc));
}

typedef union X87Reg_t {
    uint64_t alignment;
    uint8_t bytes[10];
} X87Reg;

static X87Reg x87_reg(uint64_t significand, uint16_t sign_exponent)
{
    X87Reg reg = {0};

    memcpy(reg.bytes, &significand, sizeof(significand));
    memcpy(reg.bytes + sizeof(significand), &sign_exponent,
           sizeof(sign_exponent));
    return reg;
}

static void x87_reg_unpack(const X87Reg *reg, uint64_t *significand,
                           uint16_t *sign_exponent)
{
    memcpy(significand, reg->bytes, sizeof(*significand));
    memcpy(sign_exponent, reg->bytes + sizeof(*significand),
           sizeof(*sign_exponent));
}

enum {
    X87_C0 = 0x0100,
    X87_C1 = 0x0200,
    X87_C2 = 0x0400,
    X87_C3 = 0x4000,
    X87_CC_MASK = X87_C0 | X87_C1 | X87_C2 | X87_C3,
};

static uc_engine *x87_setup(const char *code, size_t code_size, unsigned top,
                            X87Reg st0, X87Reg st1, uint16_t condition_codes)
{
    uc_engine *uc;
    uint16_t fpsw = (uint16_t)((top & 7) << 11) | condition_codes;
    uint16_t fptag = 0;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, code_size);
    OK(uc_reg_write(uc, UC_X86_REG_FPSW, &fpsw));
    OK(uc_reg_write(uc, UC_X86_REG_FPTAG, &fptag));
    OK(uc_reg_write(uc, UC_X86_REG_FP0 + (top & 7), &st0));
    OK(uc_reg_write(uc, UC_X86_REG_FP0 + ((top + 1) & 7), &st1));
    return uc;
}

static void x87_read_st0(uc_engine *uc, unsigned top, uint16_t *fpsw,
                         uint64_t *significand, uint16_t *sign_exponent)
{
    X87Reg st0 = {0};

    OK(uc_reg_read(uc, UC_X86_REG_FPSW, fpsw));
    OK(uc_reg_read(uc, UC_X86_REG_FP0 + (top & 7), &st0));
    x87_reg_unpack(&st0, significand, sign_exponent);
}

static void test_x86_fprem_large_exponent_partial(void)
{
    const char fprem[] = "\xd9\xf8";
    const char fprem1[] = "\xd9\xf5";
    const char *codes[] = {fprem, fprem1};
    const unsigned tops[] = {0, 7};
    unsigned code_index, top_index;

    for (code_index = 0; code_index < sizeof(codes) / sizeof(codes[0]);
         code_index++) {
        for (top_index = 0; top_index < sizeof(tops) / sizeof(tops[0]);
             top_index++) {
            uc_engine *uc;
            X87Reg st0 = x87_reg(UINT64_C(0x8000000000000001),
                                 0x7ffe);
            X87Reg st1 = x87_reg(UINT64_C(0x8000000000000003),
                                 0xffbe);
            uint16_t fpsw;
            uint64_t significand;
            uint16_t sign_exponent;
            unsigned top = tops[top_index];

            uc = x87_setup(codes[code_index], 2, top, st0, st1,
                           X87_CC_MASK);
            OK(uc_emu_start(uc, code_start, code_start + 2, 0, 0));
            x87_read_st0(uc, top, &fpsw, &significand, &sign_exponent);

            TEST_CHECK(((fpsw >> 11) & 7) == top);
            TEST_CHECK((fpsw & X87_CC_MASK) == X87_C2);
            TEST_CHECK(sign_exponent == 0x7f82);
            TEST_CHECK(significand == UINT64_C(0xc000000000000000));
            OK(uc_close(uc));
        }
    }
}

static void test_x86_fprem_count_callback(uc_engine *uc, uint64_t address,
                                          uint32_t size, void *user_data)
{
    unsigned *count = user_data;

    if (address == code_start) {
        ++*count;
    }
}

static void test_x86_fprem_d64_loop_converges(void)
{
    uc_engine *uc;
    uc_hook hook;
    const char code[] = "\xd9\xf8\xdf\xe0\xf6\xc4\x04\x75\xf7";
    X87Reg st0 = x87_reg(UINT64_C(0x8000000000000001), 0x7ffe);
    X87Reg st1 = x87_reg(UINT64_C(0x8000000000000003), 0xffbe);
    unsigned count = 0;
    uint16_t fpsw;
    uint64_t significand;
    uint16_t sign_exponent;

    uc = x87_setup(code, sizeof(code) - 1, 0, st0, st1, 0);
    OK(uc_hook_add(uc, &hook, UC_HOOK_CODE, test_x86_fprem_count_callback,
                   &count, 1, 0));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    x87_read_st0(uc, 0, &fpsw, &significand, &sign_exponent);

    TEST_CHECK(count == 2);
    TEST_CHECK((fpsw & X87_CC_MASK) == 0);
    TEST_CHECK(sign_exponent == 0x7f82);
    TEST_CHECK(significand == UINT64_C(0xc000000000000000));
    OK(uc_close(uc));
}

static void test_x86_fprem_d200_converges(void)
{
    static const struct {
        uint64_t significand;
        uint16_t sign_exponent;
        uint16_t condition_codes;
        int exponent_gap;
    } expected[] = {
        {UINT64_C(0xc000000000000000), 0x4f84, X87_C2, 76},
        {UINT64_C(0x800000000000001e), 0x4f44, X87_C2, 12},
        {UINT64_C(0xd800000000000000), 0x4f09, 0, -47},
    };
    uc_engine *uc;
    const char code[] = "\xd9\xf8";
    X87Reg st0 = x87_reg(UINT64_C(0x8000000000000001), 0x5000);
    X87Reg st1 = x87_reg(UINT64_C(0x8000000000000003), 0x4f38);
    int previous_gap = 200;
    unsigned i;

    uc = x87_setup(code, sizeof(code) - 1, 0, st0, st1, 0);
    for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        uint16_t fpsw;
        uint64_t significand;
        uint16_t sign_exponent;

        OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                        0, 0));
        x87_read_st0(uc, 0, &fpsw, &significand, &sign_exponent);

        TEST_CHECK((sign_exponent & 0x7fff) != 0x7fff);
        TEST_CHECK(significand == expected[i].significand);
        TEST_CHECK(sign_exponent == expected[i].sign_exponent);
        TEST_CHECK((fpsw & X87_CC_MASK) == expected[i].condition_codes);
        TEST_CHECK(expected[i].exponent_gap < previous_gap);
        previous_gap = expected[i].exponent_gap;
    }
    TEST_CHECK((expected[2].condition_codes & X87_C2) == 0);
    OK(uc_close(uc));
}

static void test_x86_fprem_terminal_thresholds(void)
{
    static const struct {
        unsigned exponent_gap;
        uint64_t significand;
        uint16_t sign_exponent;
        uint16_t condition_codes;
    } cases[] = {
        {52, UINT64_C(0xffc0000000000006), 0x3eff,
         X87_C0 | X87_C1 | X87_C3},
        {53, UINT64_C(0xff80000000000006), 0x3eff,
         X87_C0 | X87_C1 | X87_C3},
        {63, UINT64_C(0xc000000000000000), 0x3ec3,
         X87_C0 | X87_C3},
        {64, UINT64_C(0xc000000000000000), 0x3ec4, X87_C2},
    };
    const char code[] = "\xd9\xf8";
    unsigned i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uc_engine *uc;
        X87Reg st0 = x87_reg(UINT64_C(0x8000000000000001),
                             (uint16_t)(0x3f00 + cases[i].exponent_gap));
        X87Reg st1 = x87_reg(UINT64_C(0x8000000000000003), 0x3f00);
        uint16_t fpsw;
        uint64_t significand;
        uint16_t sign_exponent;

        uc = x87_setup(code, sizeof(code) - 1, 0, st0, st1,
                       X87_CC_MASK);
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                        0, 0));
        x87_read_st0(uc, 0, &fpsw, &significand, &sign_exponent);
        TEST_CHECK(significand == cases[i].significand);
        TEST_CHECK(sign_exponent == cases[i].sign_exponent);
        TEST_CHECK((fpsw & X87_CC_MASK) == cases[i].condition_codes);
        OK(uc_close(uc));
    }
}

static void test_x86_fprem_and_fprem1_quotients(void)
{
    static const struct {
        uint8_t opcode;
        uint64_t dividend_significand;
        uint16_t dividend_sign_exponent;
        uint64_t result_significand;
        uint16_t result_sign_exponent;
        uint16_t condition_codes;
    } cases[] = {
        {0xf8, UINT64_C(0xa000000000000000), 0x4001,
         UINT64_C(0x8000000000000000), 0x4000, X87_C1},
        {0xf5, UINT64_C(0xa000000000000000), 0x4001,
         UINT64_C(0x8000000000000000), 0xbfff, X87_C3},
        {0xf5, UINT64_C(0x9000000000000000), 0x4001,
         UINT64_C(0xc000000000000000), 0xbfff, X87_C3},
        {0xf8, UINT64_C(0xa000000000000000), 0xc001,
         UINT64_C(0x8000000000000000), 0xc000, X87_C1},
    };
    unsigned i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uc_engine *uc;
        char code[] = "\xd9\x00";
        X87Reg st0 = x87_reg(cases[i].dividend_significand,
                             cases[i].dividend_sign_exponent);
        X87Reg st1 = x87_reg(UINT64_C(0xc000000000000000), 0x4000);
        uint16_t fpsw;
        uint64_t significand;
        uint16_t sign_exponent;

        code[1] = (char)cases[i].opcode;
        uc = x87_setup(code, sizeof(code) - 1, 0, st0, st1,
                       X87_CC_MASK);
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                        0, 0));
        x87_read_st0(uc, 0, &fpsw, &significand, &sign_exponent);
        TEST_CHECK(significand == cases[i].result_significand);
        TEST_CHECK(sign_exponent == cases[i].result_sign_exponent);
        TEST_CHECK((fpsw & X87_CC_MASK) == cases[i].condition_codes);
        OK(uc_close(uc));
    }
}

static void test_x86_fprem_special_operands(void)
{
    const char code[] = "\xd9\xf8";
    X87Reg inputs[][2] = {
        {x87_reg(UINT64_C(0x8000000000000000), 0x3fff),
         x87_reg(UINT64_C(0x8000000000000000), 0x4000)},
        {x87_reg(UINT64_C(0x8000000000000000), 0x3fff),
         x87_reg(0, 0)},
        {x87_reg(UINT64_C(0x8000000000000000), 0x7fff),
         x87_reg(UINT64_C(0x8000000000000000), 0x3fff)},
        {x87_reg(UINT64_C(0xc000000000000000), 0x7fff),
         x87_reg(UINT64_C(0x8000000000000000), 0x3fff)},
        {x87_reg(UINT64_C(0x8000000000000000), 0x3fff),
         x87_reg(UINT64_C(0x8000000000000000), 0x7fff)},
    };
    const bool expect_nan[] = {false, true, true, true, false};
    unsigned i;

    for (i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        uc_engine *uc;
        uint16_t fpsw;
        uint64_t significand;
        uint16_t sign_exponent;

        uc = x87_setup(code, sizeof(code) - 1, 0, inputs[i][0],
                       inputs[i][1], X87_CC_MASK);
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                        0, 0));
        x87_read_st0(uc, 0, &fpsw, &significand, &sign_exponent);

        TEST_CHECK((fpsw & X87_CC_MASK) == 0);
        if (expect_nan[i]) {
            TEST_CHECK((sign_exponent & 0x7fff) == 0x7fff);
            TEST_CHECK((significand << 1) != 0);
        } else {
            TEST_CHECK(significand == UINT64_C(0x8000000000000000));
            TEST_CHECK(sign_exponent == 0x3fff);
        }
        OK(uc_close(uc));
    }
}

static uint64_t test_x86_mmio_read_callback(uc_engine *uc, uint64_t offset,
                                            unsigned size, void *user_data)
{
    TEST_CHECK(offset == 4);
    TEST_CHECK(size == 4);

    return 0x19260817;
}

static void test_x86_mmio_write_callback(uc_engine *uc, uint64_t offset,
                                         unsigned size, uint64_t value,
                                         void *user_data)
{
    TEST_CHECK(offset == 4);
    TEST_CHECK(size == 4);
    TEST_CHECK(value == 0xdeadbeef);

    return;
}

static void test_x86_mmio(void)
{
    uc_engine *uc;
    int r_ecx = 0xdeadbeef;
    char code[] =
        "\x89\x0d\x04\x00\x02\x00\x8b\x0d\x04\x00\x02\x00"; // mov [0x20004],
                                                            // ecx; mov ecx,
                                                            // [0x20004]

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_mmio_map(uc, 0x20000, 0x1000, test_x86_mmio_read_callback, NULL,
                   test_x86_mmio_write_callback, NULL));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));

    TEST_CHECK(r_ecx == 0x19260817);

    OK(uc_close(uc));
}

static bool test_x86_missing_code_callback(uc_engine *uc, uc_mem_type type,
                                           uint64_t address, int size,
                                           uint64_t value, void *user_data)
{
    char code[] = "\x41\x4a"; // inc ecx; dec edx;
    uint64_t algined_address = address & 0xFFFFFFFFFFFFF000ULL;
    int aligned_size = ((int)(size / 0x1000) + 1) * 0x1000;

    OK(uc_mem_map(uc, algined_address, aligned_size, UC_PROT_ALL));

    OK(uc_mem_write(uc, algined_address, code, sizeof(code) - 1));

    return true;
}

static void test_x86_missing_code(void)
{
    uc_engine *uc;
    uc_hook hook;
    int r_ecx = 0x1234;
    int r_edx = 0x7890;

    // Don't write any code by design.
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_UNMAPPED,
                   test_x86_missing_code_callback, NULL, 1, 0));

    OK(uc_emu_start(uc, code_start, code_start + 2, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_ecx == 0x1235);
    TEST_CHECK(r_edx == 0x788f);

    OK(uc_close(uc));
}

static void test_x86_smc_xor(void)
{
    uc_engine *uc;
    /*
     * 0x1000 xor dword ptr [edi+0x3], eax ; edi=0x1000, eax=0xbc4177e6
     * 0x1003 dw 0x3ea98b13
     */
    char code[] = "\x31\x47\x03\x13\x8b\xa9\x3e";
    int r_edi = code_start;
    int r_eax = 0xbc4177e6;
    uint32_t result;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    uc_reg_write(uc, UC_X86_REG_EDI, &r_edi);
    uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);

    OK(uc_emu_start(uc, code_start, code_start + 3, 0, 0));

    OK(uc_mem_read(uc, code_start + 3, (void *)&result, 4));

    TEST_CHECK(LEINT32(result) == (0x3ea98b13 ^ 0xbc4177e6));

    OK(uc_close(uc));
}

static void test_x86_smc_add(void)
{
    uc_engine *uc;
    uint64_t stack_base = 0x20000;
    uint64_t r_rsp;
    /*
     * mov qword ptr [rip+0x10], rax
     * mov word ptr [rip], 0x0548
     * [orig] mov eax, dword ptr [rax + 0x12345678]; [after SMC] 480578563412
     * add rax, 0x12345678 hlt
     */
    char code[] = "\x48\x89\x05\x10\x00\x00\x00\x66\xc7\x05\x00\x00\x00\x00\x48"
                  "\x05\x8b\x80\x78\x56\x34\x12\xf4";
    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);

    OK(uc_mem_map(uc, stack_base, 0x2000, UC_PROT_ALL));
    r_rsp = stack_base + 0x1800;
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp));
    OK(uc_emu_start(uc, code_start, -1, 0, 0));

    OK(uc_close(uc));
}

static void test_x86_smc_mem_hook_callback(uc_engine *uc, uc_mem_type t,
                                           uint64_t addr, int size,
                                           uint64_t value, void *user_data)
{
    uint64_t write_addresses[] = {0x1030, 0x1010, 0x1010, 0x1018,
                                  0x1018, 0x1029, 0x1029};
    unsigned int *i = user_data;

    TEST_CHECK(*i < (sizeof(write_addresses) / sizeof(write_addresses[0])));
    TEST_CHECK(write_addresses[*i] == addr);
    (*i)++;
}

static void test_x86_smc_mem_hook(void)
{
    uc_engine *uc;
    uc_hook hook;
    uint64_t stack_base = 0x20000;
    uint64_t r_rsp;
    unsigned int i = 0;
    /*
     * mov qword ptr [rip+0x29], rax
     * mov word ptr [rip], 0x0548
     * [orig] mov eax, dword ptr [rax + 0x12345678]; [after SMC] 480578563412
     * add rax, 0x12345678 nop nop nop mov qword ptr [rip-0x08], rax mov word
     * ptr [rip], 0x0548 [orig] mov eax, dword ptr [rax + 0x12345678]; [after
     * SMC] 480578563412 add rax, 0x12345678 hlt
     */
    char code[] =
        "\x48\x89\x05\x29\x00\x00\x00\x66\xC7\x05\x00\x00\x00\x00\x48\x05\x8B"
        "\x80\x78\x56\x34\x12\x90\x90\x90\x48\x89\x05\xF8\xFF\xFF\xFF\x66\xC7"
        "\x05\x00\x00\x00\x00\x48\x05\x8B\x80\x78\x56\x34\x12\xF4";
    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE, test_x86_smc_mem_hook_callback,
                   &i, 1, 0));
    OK(uc_mem_map(uc, stack_base, 0x2000, UC_PROT_ALL));
    r_rsp = stack_base + 0x1800;
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp));
    OK(uc_emu_start(uc, code_start, -1, 0, 0));

    OK(uc_close(uc));
}

typedef struct TestX86SmcExecUpgrade {
    uint64_t upgrade_at;
    uint64_t function_page;
    uint64_t write_alias;
    uint64_t exec_alias;
    uc_err protect_result;
    unsigned int protect_count;
} TestX86SmcExecUpgrade;

static bool test_x86_smc_exec_upgrade_tlb_fill(uc_engine *uc,
                                                uint64_t address,
                                                uc_mem_type type,
                                                uc_tlb_entry *result,
                                                void *user_data)
{
    TestX86SmcExecUpgrade *state = user_data;
    uint64_t page = address & ~UINT64_C(0xfff);

    if (page == state->write_alias) {
        result->paddr = state->function_page + (address & 0xfff);
        result->perms = UC_PROT_WRITE;
    } else if (page == state->exec_alias) {
        result->paddr = state->function_page + (address & 0xfff);
        result->perms = UC_PROT_EXEC;
    } else {
        result->paddr = address;
        result->perms = UC_PROT_ALL;
    }
    return true;
}

typedef struct TestX86WriteHookProtect {
    uint64_t page;
    uint64_t nested_address;
    uc_err protect_result;
    uc_err nested_result;
    unsigned int hook_count;
    bool upgrade_write;
    bool nested;
} TestX86WriteHookProtect;

static void test_x86_nested_add_exec_code_hook(uc_engine *uc,
                                                uint64_t address,
                                                uint32_t size,
                                                void *user_data)
{
    TestX86WriteHookProtect *state = user_data;

    if (address == state->nested_address) {
        state->protect_result = uc_mem_protect(
            uc, state->page, 0x1000,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC);
    }
}

static void test_x86_write_hook_add_exec(uc_engine *uc, uc_mem_type type,
                                         uint64_t address, int size,
                                         int64_t value, void *user_data)
{
    TestX86WriteHookProtect *state = user_data;

    if (state->hook_count++ == 0) {
        if (state->nested) {
            state->nested_result = uc_emu_start(
                uc, state->nested_address, 0, 0, 1);
        } else {
            state->protect_result = uc_mem_protect(
                uc, state->page, 0x1000,
                UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC);
        }
    }
}

static bool test_x86_write_prot_hook(uc_engine *uc, uc_mem_type type,
                                     uint64_t address, int size,
                                     int64_t value, void *user_data)
{
    TestX86WriteHookProtect *state = user_data;

    state->hook_count++;
    if (state->upgrade_write) {
        state->protect_result = uc_mem_protect(
            uc, state->page, 0x1000, UC_PROT_READ | UC_PROT_WRITE);
    }
    return true;
}

static void test_x86_write_hook_tlb_flush_preserves_store(void)
{
    static const uint8_t code[] = {
        0xc6, 0x05, 0x00, 0x60, 0x00, 0x00, 0x5a,
        /* mov byte ptr [0x6000], 0x5a */
    };
    static const uint8_t nested_code[] = {0x90}; /* nop */

    for (int nested = 0; nested < 2; ++nested) {
        TestX86WriteHookProtect state = {
            .page = 0x6000,
            .nested_address = 0x2000,
            .protect_result = UC_ERR_ARG,
            .nested_result = UC_ERR_ARG,
            .nested = nested,
        };
        uint8_t byte = 0;
        uc_engine *uc;
        uc_hook code_hook;
        uc_hook write_hook;

        OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
        OK(uc_mem_map(uc, code_start, 0x2000,
                      UC_PROT_READ | UC_PROT_EXEC));
        OK(uc_mem_map(uc, state.page, 0x1000,
                      UC_PROT_READ | UC_PROT_WRITE));
        OK(uc_mem_write(uc, code_start, code, sizeof(code)));
        OK(uc_mem_write(uc, state.nested_address, nested_code,
                        sizeof(nested_code)));
        OK(uc_hook_add(uc, &write_hook, UC_HOOK_MEM_WRITE,
                       test_x86_write_hook_add_exec, &state,
                       state.page, state.page + 0xfff));
        if (nested) {
            OK(uc_hook_add(uc, &code_hook, UC_HOOK_CODE,
                           test_x86_nested_add_exec_code_hook, &state,
                           state.nested_address, state.nested_address));
        }

        OK(uc_emu_start(uc, code_start, 0, 0, 1));
        OK(uc_mem_read(uc, state.page, &byte, sizeof(byte)));
        TEST_CHECK(state.hook_count == 1);
        TEST_CHECK(state.protect_result == UC_ERR_OK);
        if (nested) {
            TEST_CHECK(state.nested_result == UC_ERR_OK);
        }
        TEST_CHECK(byte == 0x5a);

        OK(uc_close(uc));
    }
}

static void test_x86_write_prot_hook_must_repair_permission(void)
{
    static const uint8_t code[] = {
        0xc6, 0x05, 0x00, 0x60, 0x00, 0x00, 0x5a,
        /* mov byte ptr [0x6000], 0x5a */
    };

    for (int upgrade_write = 0; upgrade_write < 2; ++upgrade_write) {
        TestX86WriteHookProtect state = {
            .page = 0x6000,
            .protect_result = UC_ERR_ARG,
            .upgrade_write = upgrade_write,
        };
        const uc_err expected = upgrade_write ? UC_ERR_OK
                                              : UC_ERR_WRITE_PROT;
        const uint8_t initial_byte = 0x11;
        uint8_t byte = 0;
        uc_engine *uc;
        uc_hook hook;
        uc_err err;

        OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
        OK(uc_mem_map(uc, code_start, 0x1000,
                      UC_PROT_READ | UC_PROT_EXEC));
        OK(uc_mem_map(uc, state.page, 0x1000, UC_PROT_READ));
        OK(uc_mem_write(uc, code_start, code, sizeof(code)));
        OK(uc_mem_write(uc, state.page, &initial_byte,
                        sizeof(initial_byte)));
        OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE_PROT,
                       test_x86_write_prot_hook, &state,
                       state.page, state.page + 0xfff));

        err = uc_emu_start(uc, code_start, 0, 0, 1);
        TEST_CHECK(err == expected);
        OK(uc_mem_read(uc, state.page, &byte, sizeof(byte)));
        TEST_CHECK(state.hook_count == 1);
        TEST_CHECK(byte == (upgrade_write ? 0x5a : initial_byte));
        if (upgrade_write) {
            TEST_CHECK(state.protect_result == UC_ERR_OK);
        }

        OK(uc_close(uc));
    }
}

static void test_x86_smc_exec_upgrade_code_hook(uc_engine *uc,
                                                uint64_t address,
                                                uint32_t size,
                                                void *user_data)
{
    TestX86SmcExecUpgrade *state = user_data;

    if (address == state->upgrade_at && state->protect_count == 0) {
        state->protect_result = uc_mem_protect(
            uc, state->function_page, 0x1000,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC);
        state->protect_count++;
    }
}

static void test_x86_smc_after_exec_permission_upgrade(void)
{
    static const uint8_t function_code[] = {
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3,
    };
    static const uint8_t main_code[] = {
        0xc6, 0x05, 0xff, 0x60, 0x01, 0x00, 0x55,
        0xb8, 0x00, 0x60, 0x02, 0x00,
        0xff, 0xd0,
        0x89, 0xc1,
        0xc6, 0x05, 0x0c, 0x60, 0x01, 0x00, 0x55,
        0xb8, 0x00, 0x60, 0x02, 0x00,
        0xff, 0xd0,
    };
    const uint64_t function_page = 0x6000;
    const uint64_t write_alias = 0x16000;
    const uint64_t exec_alias = 0x26000;
    const uint64_t stack_page = 0x8000;
    TestX86SmcExecUpgrade state = {
        .upgrade_at = code_start + 7,
        .function_page = function_page,
        .write_alias = write_alias,
        .exec_alias = exec_alias,
        .protect_result = UC_ERR_ARG,
    };
    uc_engine *uc;
    uc_hook code_hook;
    uc_hook tlb_hook;
    uint32_t eax = 0;
    uint32_t ecx = 0;
    uint32_t esp = stack_page + 0xff0;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_mem_map(uc, code_start, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, function_page, 0x1000,
                  UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_map(uc, stack_page, 0x1000,
                  UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, code_start, main_code, sizeof(main_code)));
    OK(uc_mem_write(uc, function_page, function_code,
                    sizeof(function_code)));
    OK(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    OK(uc_hook_add(uc, &code_hook, UC_HOOK_CODE,
                   test_x86_smc_exec_upgrade_code_hook, &state, 1, 0));
    OK(uc_hook_add(uc, &tlb_hook, UC_HOOK_TLB_FILL,
                   test_x86_smc_exec_upgrade_tlb_fill, &state, 1, 0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(main_code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_read(uc, UC_X86_REG_ECX, &ecx));

    TEST_CHECK(state.protect_count == 1);
    TEST_CHECK(state.protect_result == UC_ERR_OK);
    TEST_CHECK(ecx == 0x12345678U);
    TEST_CHECK(eax == 0x55345678U);

    OK(uc_close(uc));
}

static uint64_t test_x86_mmio_uc_mem_rw_read_callback(uc_engine *uc,
                                                      uint64_t offset,
                                                      unsigned size,
                                                      void *user_data)
{
    TEST_CHECK(offset == 8);
    TEST_CHECK(size == 4);

    return 0x19260817;
}

static void test_x86_mmio_uc_mem_rw_write_callback(uc_engine *uc,
                                                   uint64_t offset,
                                                   unsigned size,
                                                   uint64_t value,
                                                   void *user_data)
{
    TEST_CHECK(offset == 4);
    TEST_CHECK(size == 4);
    TEST_CHECK(value == 0xdeadbeef);

    return;
}

static void test_x86_mmio_uc_mem_rw(void)
{
    uc_engine *uc;
    int data = LEINT32(0xdeadbeef);

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    OK(uc_mmio_map(uc, 0x20000, 0x1000, test_x86_mmio_uc_mem_rw_read_callback,
                   NULL, test_x86_mmio_uc_mem_rw_write_callback, NULL));

    OK(uc_mem_write(uc, 0x20004, (void *)&data, 4));
    OK(uc_mem_read(uc, 0x20008, (void *)&data, 4));

    TEST_CHECK(LEINT32(data) == 0x19260817);

    OK(uc_close(uc));
}

static void test_x86_sysenter_hook(uc_engine *uc, void *user)
{
    *(int *)user = 1;
}

static void test_x86_sysenter(void)
{
    uc_engine *uc;
    char code[] = "\x0F\x34"; // sysenter
    uc_hook h;
    int called = 0;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &h, UC_HOOK_INSN, test_x86_sysenter_hook, &called, 1, 0,
                   UC_X86_INS_SYSENTER));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    TEST_CHECK(called == 1);

    OK(uc_close(uc));
}

static int test_x86_hook_cpuid_callback(uc_engine *uc, void *data)
{
    uint32_t reg = 7;
    uint32_t eip;

    OK(uc_reg_read(uc, UC_X86_REG_EIP, (void*)&eip));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &reg));

    TEST_CHECK(eip == code_start + 1);
    // Overwrite the cpuid instruction.
    return 1;
}

static void test_x86_hook_cpuid(void)
{
    uc_engine *uc;
    char code[] = "\x40\x0F\xA2"; // INC EAX; CPUID
    uc_hook h;
    int reg;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &h, UC_HOOK_INSN, test_x86_hook_cpuid_callback, NULL, 1,
                   0, UC_X86_INS_CPUID));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &reg));

    TEST_CHECK(reg == 7);

    OK(uc_close(uc));
}

static void test_x86_486_cpuid(void)
{
    uc_engine *uc;
    uint32_t eax;
    uint32_t ebx;

    char code[] = {0x31, 0xC0, 0x0F, 0xA2}; // XOR EAX EAX; CPUID

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_486));
    OK(uc_mem_map(uc, 0, 4 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0, code, sizeof(code) / sizeof(code[0])));
    OK(uc_emu_start(uc, 0, sizeof(code) / sizeof(code[0]), 0, 0));

    /* Read eax after emulation */
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_read(uc, UC_X86_REG_EBX, &ebx));

    TEST_CHECK(eax != 0);
    TEST_CHECK(ebx == 0x756e6547); // magic string "Genu" for intel cpu

    OK(uc_close(uc));
}

// This is a regression bug.
static void test_x86_clear_tb_cache(void)
{
    uc_engine *uc;
    char code[] = "\x83\xc1\x01\x4a"; // ADD ecx, 1; DEC edx;
    int r_ecx = 0x1234;
    int r_edx = 0x7890;
    uint64_t code_start = 0x1240; // Choose this address by design
    uint64_t code_len = 0x1000;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, code_start & (1 << 12), code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));

    // This emulation should take no effect at all.
    OK(uc_emu_start(uc, code_start, code_start, 0, 0));

    // Emulate ADD ecx, 1.
    OK(uc_emu_start(uc, code_start, code_start + 3, 0, 0));

    // If tb cache is not cleared, edx would be still 0x7890
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_ecx == 0x1236);
    TEST_CHECK(r_edx == 0x788f);

    OK(uc_close(uc));
}

static void test_x86_clear_count_cache(void)
{
    uc_engine *uc;
    // uc_emu_start will clear last TB when exiting so generating a tb at last
    // by design
    char code[] =
        "\x83\xc1\x01\x4a\xeb\x00\x83\xc3\x01"; // ADD ecx, 1; DEC edx;
                                                // jmp t;
                                                // t:
                                                // ADD ebx, 1
    int r_ecx = 0x1234;
    int r_edx = 0x7890;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 2));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_ecx == 0x1236);
    TEST_CHECK(r_edx == 0x788e);

    OK(uc_close(uc));
}

// This is a regression bug.
static void test_x86_clear_empty_tb(void)
{
    uc_engine *uc;
    // lb:
    //    add ecx, 1;
    //    cmp ecx, 0;
    //    jz lb;
    //    dec edx;
    char code[] = "\x83\xc1\x01\x83\xf9\x00\x74\xf8\x4a";
    int r_edx = 0x7890;
    uint64_t code_start = 0x1240; // Choose this address by design
    uint64_t code_len = 0x1000;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, code_start & (1 << 12), code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));

    // Make sure we generate an empty tb at the exit address by stopping at dec
    // edx.
    OK(uc_emu_start(uc, code_start, code_start + 8, 0, 0));

    // If tb cache is not cleared, edx would be still 0x7890
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_edx == 0x788f);

    OK(uc_close(uc));
}

static void test_x86_page_boundary_speculative_translation(void)
{
    const uint64_t page_start = 0x1000;
    const uint64_t page_end = 0x2000;
    const uint64_t stack_page = 0x3000;
    const uint64_t initial_rsp = stack_page + 0x800;
    const uint64_t expected_rax = UINT64_C(0x1122334455667788);
    uint8_t code[0x1000];
    uint64_t rax = 0;
    uint64_t rip;
    uint64_t rsp = initial_rsp;
    uc_engine *uc;

    memset(code, 0x90, sizeof(code));
    code[sizeof(code) - 1] = 0x58; /* pop rax */

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, page_start, sizeof(code), UC_PROT_ALL));
    OK(uc_mem_map(uc, stack_page, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, page_start, code, sizeof(code)));
    OK(uc_mem_write(uc, initial_rsp, &expected_rax, sizeof(expected_rax)));

    /* An aligned start fills the last 512-instruction TB exactly. */
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
    uc_assert_err(UC_ERR_FETCH_UNMAPPED,
                  uc_emu_start(uc, page_start, 0, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
    TEST_CHECK(rax == expected_rax);
    TEST_CHECK(rip == page_end);
    TEST_CHECK(rsp == initial_rsp + sizeof(expected_rax));

    /* An offset start must commit the short final TB before the fetch fault. */
    rax = 0;
    rsp = initial_rsp;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
    uc_assert_err(UC_ERR_FETCH_UNMAPPED,
                  uc_emu_start(uc, page_start + 1, 0, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
    TEST_CHECK(rax == expected_rax);
    TEST_CHECK(rip == page_end);
    TEST_CHECK(rsp == initial_rsp + sizeof(expected_rax));

    /* Reaching an unmapped page that is also @until must not fetch it. */
    rax = 0;
    rsp = initial_rsp;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
    OK(uc_emu_start(uc, page_start + 1, page_end, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
    TEST_CHECK(rax == expected_rax);
    TEST_CHECK(rip == page_end);
    TEST_CHECK(rsp == initial_rsp + sizeof(expected_rax));

    OK(uc_close(uc));
}

typedef struct _HOOK_TCG_OP_RESULT {
    uint64_t address;
    uint64_t arg1;
    uint64_t arg2;
} HOOK_TCG_OP_RESULT;

typedef struct _HOOK_TCG_OP_RESULTS {
    HOOK_TCG_OP_RESULT results[128];
    uint64_t len;
} HOOK_TCG_OP_RESULTS;

static void test_x86_hook_tcg_op_cb(uc_engine *uc, uint64_t address,
                                    uint64_t arg1, uint64_t arg2, uint32_t size,
                                    void *data)
{
    HOOK_TCG_OP_RESULTS *results = (HOOK_TCG_OP_RESULTS *)data;
    HOOK_TCG_OP_RESULT *result = &results->results[results->len++];

    result->address = address;
    result->arg1 = arg1;
    result->arg2 = arg2;
}

static void test_x86_hook_tcg_op(void)
{
    uc_engine *uc;
    uc_hook h;
    int flag;
    HOOK_TCG_OP_RESULTS results;
    // sub esi, [0x1000];
    // sub eax, ebx;
    // sub eax, 1;
    // cmp eax, 0;
    // cmp ebx, edx;
    // cmp esi, [0x1000];
    char code[] = "\x2b\x35\x00\x10\x00\x00\x29\xd8\x83\xe8\x01\x83\xf8\x00\x39"
                  "\xd3\x3b\x35\x00\x10\x00\x00";
    int r_eax = 0x1234;
    int r_ebx = 2;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &r_eax));
    OK(uc_reg_write(uc, UC_X86_REG_EBX, &r_ebx));

    memset(&results, 0, sizeof(HOOK_TCG_OP_RESULTS));
    flag = 0;
    OK(uc_hook_add(uc, &h, UC_HOOK_TCG_OPCODE, test_x86_hook_tcg_op_cb,
                   &results, 0, -1, UC_TCG_OP_SUB, flag));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_hook_del(uc, h));

    TEST_CHECK(results.len == 6);

    memset(&results, 0, sizeof(HOOK_TCG_OP_RESULTS));
    flag = UC_TCG_OP_FLAG_DIRECT;
    OK(uc_hook_add(uc, &h, UC_HOOK_TCG_OPCODE, test_x86_hook_tcg_op_cb,
                   &results, 0, -1, UC_TCG_OP_SUB, flag));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_hook_del(uc, h));

    TEST_CHECK(results.len == 3);

    memset(&results, 0, sizeof(HOOK_TCG_OP_RESULTS));
    flag = UC_TCG_OP_FLAG_CMP;
    OK(uc_hook_add(uc, &h, UC_HOOK_TCG_OPCODE, test_x86_hook_tcg_op_cb,
                   &results, 0, -1, UC_TCG_OP_SUB, flag));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_hook_del(uc, h));

    TEST_CHECK(results.len == 3);

    OK(uc_close(uc));
}

static bool test_x86_cmpxchg_mem_hook(uc_engine *uc, uc_mem_type type,
                                      uint64_t address, int size, int64_t val,
                                      void *data)
{
    if (type == UC_MEM_READ) {
        *((int *)data) |= 1;
    } else {
        *((int *)data) |= 2;
    }

    return true;
}

static void test_x86_cmpxchg(void)
{
    uc_engine *uc;
    char code[] = "\x0F\xC7\x0D\xE0\xBE\xAD\xDE"; // cmpxchg8b [0xdeadbee0]
    int r_zero = 0;
    int r_aaaa = 0x41414141;
    uint64_t mem;
    uc_hook h;
    int result = 0;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, 0xdeadb000, 0x1000, UC_PROT_ALL));
    OK(uc_hook_add(uc, &h, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                   test_x86_cmpxchg_mem_hook, &result, 1, 0));

    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_zero));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &r_zero));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_aaaa));
    OK(uc_reg_write(uc, UC_X86_REG_EBX, &r_aaaa));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, 0xdeadbee0, &mem, 8));

    TEST_CHECK(mem == 0x4141414141414141);

    // Both read and write happened.
    TEST_CHECK(result == 3);

    OK(uc_close(uc));
}

static void test_x86_cmpxchg32_acc_case(uint64_t initial_rax,
                                        uint64_t initial_mem,
                                        uint64_t expected_rax,
                                        uint64_t expected_mem,
                                        bool expected_zf)
{
    uc_engine *uc;
    char code[] = "\x41\x0f\xb1\x18"; /* cmpxchg dword ptr [r8], ebx */
    uint64_t data_address = 0x2000000;
    uint64_t rax = initial_rax;
    uint64_t rbx = 0;
    uint64_t r8 = data_address;
    uint64_t rflags;
    uint64_t mem;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, data_address, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, data_address, &initial_mem, sizeof(initial_mem)));
    OK(uc_reg_write(uc, UC_X86_REG_R8, &r8));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    OK(uc_mem_read(uc, data_address, &mem, sizeof(mem)));

    TEST_CHECK(rax == expected_rax);
    TEST_CHECK(mem == expected_mem);
    TEST_CHECK((bool)(rflags & 0x40) == expected_zf);

    OK(uc_close(uc));
}

static void test_x86_cmpxchg32_accumulator(void)
{
    test_x86_cmpxchg32_acc_case(0xffffffffffffffffULL,
                                0xffffffffffffffffULL,
                                0xffffffffffffffffULL,
                                0xffffffff00000000ULL, true);
    test_x86_cmpxchg32_acc_case(0xffffffff00000000ULL,
                                0xffffffffffffffffULL,
                                0x00000000ffffffffULL,
                                0xffffffffffffffffULL, false);
}

static void test_x86_cmpxchg32_reg_case(uint64_t initial_rax,
                                        uint64_t initial_rcx,
                                        uint64_t initial_rbx,
                                        uint64_t expected_rax,
                                        uint64_t expected_rcx,
                                        bool expected_zf)
{
    uc_engine *uc;
    char code[] = "\x0f\xb1\xd9"; /* cmpxchg ecx, ebx */
    uint64_t rax = initial_rax;
    uint64_t rcx = initial_rcx;
    uint64_t rbx = initial_rbx;
    uint64_t rflags;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

    TEST_CHECK(rax == expected_rax);
    TEST_CHECK(rcx == expected_rcx);
    TEST_CHECK((bool)(rflags & 0x40) == expected_zf);

    OK(uc_close(uc));
}

static void test_x86_cmpxchg32_register(void)
{
    test_x86_cmpxchg32_reg_case(0xeeeeeeeeffffffffULL,
                                0xaaaaaaaaffffffffULL,
                                0x1111111122222222ULL,
                                0xeeeeeeeeffffffffULL,
                                0x0000000022222222ULL, true);
    test_x86_cmpxchg32_reg_case(0x1111111112345678ULL,
                                0xaaaaaaaaffffffffULL,
                                0x1111111122222222ULL,
                                0x00000000ffffffffULL,
                                0xaaaaaaaaffffffffULL, false);
}

static void test_x86_ret_imm16_unsigned(void)
{
    uc_engine *uc;
    char code[] = "\xc2\x00\xff"; /* ret 0xff00 */
    uint64_t stack_address = 0x2000000;
    uint64_t return_address = code_start + sizeof(code) - 1;
    uint64_t rsp = stack_address;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, stack_address, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, stack_address, &return_address,
                    sizeof(return_address)));
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));

    OK(uc_emu_start(uc, code_start, return_address, 0, 1));
    OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));

    TEST_CHECK(rsp == stack_address + 8 + 0xff00);

    OK(uc_close(uc));
}

static void test_x86_rorx_rip_relative_imm(void)
{
    uc_engine *uc;
    char code[] = "\xc4\xe3\x7b\xf0\x05\xf6\x14\x00\x00\x00";
    uint64_t expected_address = code_start + sizeof(code) - 1 + 0x14f6;
    uint8_t data[] = {0xaa, 0x11, 0x22, 0x33, 0x44};
    uint64_t rax;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_mem_write(uc, expected_address - 1, data, sizeof(data)));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));

    TEST_CHECK(rax == 0x44332211);

    OK(uc_close(uc));
}

static void test_x86_shiftd_rip_relative_imm(const char *code,
                                             size_t code_size, uint64_t rbx,
                                             uint16_t expected_value)
{
    uc_engine *uc;
    uint64_t expected_address = code_start + code_size + 0x14f7;
    uint8_t data[] = {0xaa, 0x11, 0x22, 0x33, 0x44};
    uint8_t previous;
    uint16_t mem;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, code_size);
    OK(uc_mem_write(uc, expected_address - 1, data, sizeof(data)));
    OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));

    OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 1));
    OK(uc_mem_read(uc, expected_address - 1, &previous, sizeof(previous)));
    OK(uc_mem_read(uc, expected_address, &mem, sizeof(mem)));

    TEST_CHECK(previous == 0xaa);
    TEST_CHECK(mem == expected_value);

    OK(uc_close(uc));
}

static void test_x86_shld_rip_relative_imm(void)
{
    char code[] = "\x66\x0f\xa4\x1d\xf7\x14\x00\x00\x01";

    test_x86_shiftd_rip_relative_imm(code, sizeof(code) - 1, 0x8000, 0x4423);
}

static void test_x86_shrd_rip_relative_imm(void)
{
    char code[] = "\x66\x0f\xac\x1d\xf7\x14\x00\x00\x01";

    test_x86_shiftd_rip_relative_imm(code, sizeof(code) - 1, 1, 0x9108);
}

static void test_x86_pdep32_zero_extend(void)
{
    uc_engine *uc;
    char code[] = "\xc4\xe2\x63\xf5\xc1"; /* pdep eax, ebx, ecx */
    uint64_t rax = 0xffffffffffffffffULL;
    uint64_t rbx = 0xffffffffffffff00ULL;
    uint64_t rcx = 0xffffffffffffff00ULL;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));

    TEST_CHECK(rax == 0x00000000ffff0000ULL);

    OK(uc_close(uc));
}

static void test_x86_nested_emu_start_cb(uc_engine *uc, uint64_t addr,
                                         size_t size, void *data)
{
    OK(uc_emu_start(uc, code_start + 1, code_start + 2, 0, 0));
}

static void test_x86_nested_emu_start(void)
{
    uc_engine *uc;
    char code[] = "\x41\x4a"; // INC ecx; DEC edx;
    int r_ecx = 0x1234;
    int r_edx = 0x7890;
    uc_hook h;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));
    // Emulate DEC in the nested hook.
    OK(uc_hook_add(uc, &h, UC_HOOK_CODE, test_x86_nested_emu_start_cb, NULL,
                   code_start, code_start));

    // Emulate INC
    OK(uc_emu_start(uc, code_start, code_start + 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_ecx == 0x1235);
    TEST_CHECK(r_edx == 0x788f);

    OK(uc_close(uc));
}

static void test_x86_nested_emu_stop_cb(uc_engine *uc, uint64_t addr,
                                        size_t size, void *data)
{
    OK(uc_emu_start(uc, code_start + 1, code_start + 2, 0, 0));
    // ecx shouldn't be changed!
    OK(uc_emu_stop(uc));
}

static void test_x86_nested_emu_stop(void)
{
    uc_engine *uc;
    // INC ecx; DEC edx; DEC edx;
    char code[] = "\x41\x4a\x4a";
    int r_ecx = 0x1234;
    int r_edx = 0x7890;
    uc_hook h;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));
    // Emulate DEC in the nested hook.
    OK(uc_hook_add(uc, &h, UC_HOOK_CODE, test_x86_nested_emu_stop_cb, NULL,
                   code_start, code_start));

    OK(uc_emu_start(uc, code_start, code_start + 3, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_ecx == 0x1234);
    TEST_CHECK(r_edx == 0x788f);

    OK(uc_close(uc));
}

static void test_x86_nested_emu_start_error_cb(uc_engine *uc, uint64_t addr,
                                               size_t size, void *data)
{
    uc_assert_err(UC_ERR_READ_UNMAPPED,
                  uc_emu_start(uc, code_start + 2, 0, 0, 0));
}

static void test_x86_64_nested_emu_start_error(void)
{
    uc_engine *uc;
    // "nop;nop;mov rax, [0x10000]"
    char code[] = "\x90\x90\x48\xa1\x00\x00\x01\x00\x00\x00\x00\x00";
    uc_hook hk;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_hook_add(uc, &hk, UC_HOOK_CODE, test_x86_nested_emu_start_error_cb,
                   NULL, code_start, code_start));

    // This call shouldn't fail!
    OK(uc_emu_start(uc, code_start, code_start + 2, 0, 0));

    OK(uc_close(uc));
}

static void test_x86_eflags_reserved_bit(void)
{
    uc_engine *uc;
    uint32_t r_eflags;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    OK(uc_reg_read(uc, UC_X86_REG_EFLAGS, &r_eflags));

    TEST_CHECK((r_eflags & 2) != 0);

    OK(uc_reg_write(uc, UC_X86_REG_EFLAGS, &r_eflags));

    OK(uc_reg_read(uc, UC_X86_REG_EFLAGS, &r_eflags));

    TEST_CHECK((r_eflags & 2) != 0);

    OK(uc_close(uc));
}

static void test_x86_nested_uc_emu_start_exits_cb(uc_engine *uc, uint64_t addr,
                                                  size_t size, void *data)
{
    OK(uc_emu_start(uc, code_start + 5, code_start + 6, 0, 0));
}

static void test_x86_nested_uc_emu_start_exits(void)
{
    uc_engine *uc;
    //  cmp eax, 0
    //  jnz t
    //  nop <-- nested emu_start
    // t:mov dword ptr [eax], 0
    char code[] = "\x83\xf8\x00\x75\x01\x90\xc7\x00\x00\x00\x00\x00";
    uc_hook hk;
    uint32_t r_pc;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &hk, UC_HOOK_CODE, test_x86_nested_uc_emu_start_exits_cb,
                   NULL, code_start, code_start));
    OK(uc_emu_start(uc, code_start, code_start + 5, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_EIP, &r_pc));

    TEST_CHECK(r_pc == code_start + 5);

    OK(uc_close(uc));
}

static bool test_x86_correct_address_in_small_jump_hook_callback(
    uc_engine *uc, int type, uint64_t address, int size, int64_t value,
    void *user_data)
{
    // Check registers
    uint64_t r_rax = 0x0;
    uint64_t r_rip = 0x0;
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &r_rip));
    TEST_CHECK(r_rax == 0x7F00);
    TEST_CHECK(r_rip == 0x7F00);

    // Check address
    // printf("%lx\n", address);
    TEST_CHECK(address == 0x7F00);

    return false;
}

static void test_x86_correct_address_in_small_jump_hook(void)
{
    uc_engine *uc;
    // movabs $0x7F00, %rax
    // jmp  *%rax
    char code[] = "\x48\xb8\x00\x7F\x00\x00\x00\x00\x00\x00\xff\xe0";

    uint64_t r_rax = 0x0;
    uint64_t r_rip = 0x0;
    uc_hook hook;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_UNMAPPED,
                   test_x86_correct_address_in_small_jump_hook_callback, NULL,
                   1, 0));

    uc_assert_err(
        UC_ERR_FETCH_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &r_rip));
    TEST_CHECK(r_rax == 0x7F00);
    TEST_CHECK(r_rip == 0x7F00);

    OK(uc_close(uc));
}

static bool test_x86_correct_address_in_long_jump_hook_callback(
    uc_engine *uc, int type, uint64_t address, int size, int64_t value,
    void *user_data)
{
    // Check registers
    uint64_t r_rax = 0x0;
    uint64_t r_rip = 0x0;
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &r_rip));
    TEST_CHECK(r_rax == 0x7FFFFFFFFFFFFF00);
    TEST_CHECK(r_rip == 0x7FFFFFFFFFFFFF00);

    // Check address
    // printf("%lx\n", address);
    TEST_CHECK(address == 0x7FFFFFFFFFFFFF00);

    return false;
}

static void test_x86_correct_address_in_long_jump_hook(void)
{
    uc_engine *uc;
    // movabs $0x7FFFFFFFFFFFFF00, %rax
    // jmp  *%rax
    char code[] = "\x48\xb8\x00\xff\xff\xff\xff\xff\xff\x7f\xff\xe0";

    uint64_t r_rax = 0x0;
    uint64_t r_rip = 0x0;
    uc_hook hook;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_UNMAPPED,
                   test_x86_correct_address_in_long_jump_hook_callback, NULL, 1,
                   0));

    uc_assert_err(
        UC_ERR_FETCH_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &r_rip));
    TEST_CHECK(r_rax == 0x7FFFFFFFFFFFFF00);
    TEST_CHECK(r_rip == 0x7FFFFFFFFFFFFF00);

    OK(uc_close(uc));
}

static void test_x86_vex_l_256(void)
{
    uc_engine *uc;
    uint64_t rcx = 0x1000;
    uint8_t input[32];
    uint8_t ymm1[32] = {0};
    unsigned i;

    /* vmovdqu ymm1, [rcx] */
    char code[] = {'\xC5', '\xFE', '\x6F', '\x09'};

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)i;
    }

    /* VEX.L=1 selects the architecturally valid 256-bit form on Haswell. */
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0, code, sizeof(code) / sizeof(code[0])));
    OK(uc_mem_write(uc, rcx, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));

    OK(uc_emu_start(uc, 0, sizeof(code) / sizeof(code[0]), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM1, ymm1));
    TEST_CHECK(memcmp(ymm1, input, sizeof(input)) == 0);
    OK(uc_close(uc));
}

// AARCH64 inline the read while s390x won't split the access. Though not tested
// on other hosts but we restrict a bit more.
#if !defined(TARGET_READ_INLINED) && defined(BOOST_LITTLE_ENDIAN)

struct writelog_t {
    uint32_t addr, size;
};

static void test_x86_unaligned_access_callback(uc_engine *uc, uc_mem_type type,
                                               uint64_t address, int size,
                                               int64_t value, void *user_data)
{
    TEST_CHECK(size != 0);
    struct writelog_t *write_log = (struct writelog_t *)user_data;

    for (int i = 0; i < 10; i++) {
        if (write_log[i].size == 0) {
            write_log[i].addr = (uint32_t)address;
            write_log[i].size = (uint32_t)size;
            return;
        }
    }
    TEST_ASSERT(false);
}

static void test_x86_unaligned_access(void)
{
    uc_engine *uc;
    uc_hook hook;
    // mov dword ptr [0x200001], eax; mov eax, dword ptr [0x200001]
    char code[] = "\xa3\x01\x00\x20\x00\xa1\x01\x00\x20\x00";
    uint32_t r_eax = LEINT32(0x41424344);
    struct writelog_t write_log[10];
    struct writelog_t read_log[10];
    memset(write_log, 0, sizeof(write_log));
    memset(read_log, 0, sizeof(read_log));

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, 0x200000, 0x1000, UC_PROT_ALL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE,
                   test_x86_unaligned_access_callback, write_log, 1, 0));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_READ,
                   test_x86_unaligned_access_callback, read_log, 1, 0));

    OK(uc_reg_write(uc, UC_X86_REG_EAX, &r_eax));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    TEST_CHECK(write_log[0].addr == 0x200001);
    TEST_CHECK(write_log[0].size == 4);
    TEST_CHECK(write_log[1].size == 0);

    TEST_CHECK(read_log[0].addr == 0x200001);
    TEST_CHECK(read_log[0].size == 4);
    TEST_CHECK(read_log[1].size == 0);

    char b;
    OK(uc_mem_read(uc, 0x200001, &b, 1));
    TEST_CHECK(b == 0x44);
    OK(uc_mem_read(uc, 0x200002, &b, 1));
    TEST_CHECK(b == 0x43);
    OK(uc_mem_read(uc, 0x200003, &b, 1));
    TEST_CHECK(b == 0x42);
    OK(uc_mem_read(uc, 0x200004, &b, 1));
    TEST_CHECK(b == 0x41);

    OK(uc_close(uc));
}

static void test_x86_64_unaligned_access(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = {"\x48\x89\x01" //   mov         qword ptr [rcx],rax
                   "\x48\x8b\x00" //  mov         rax,qword ptr [rax]
                   "\xcc"};
    uint64_t r_rax = LEINT64(0x2fffff);
    uint64_t r_rcx = LEINT64(0x2fffff);
    struct writelog_t write_log[10];
    struct writelog_t read_log[10];
    memset(write_log, 0, sizeof(write_log));
    memset(read_log, 0, sizeof(read_log));
    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, 0x200000, 0x200000, UC_PROT_ALL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE,
                   test_x86_unaligned_access_callback, write_log, 1, 0));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_READ,
                   test_x86_unaligned_access_callback, read_log, 1, 0));

    OK(uc_reg_write(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &r_rcx));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 2));

    TEST_CHECK(write_log[0].addr == 0x2fffff);
    TEST_CHECK(write_log[0].size == 8);
    TEST_CHECK(write_log[1].size == 0);

    TEST_CHECK(read_log[0].addr == 0x2fffff);
    TEST_CHECK(read_log[0].size == 8);
    TEST_CHECK(read_log[1].size == 0);

    uint64_t b;
    OK(uc_mem_read(uc, 0x2fffff, &b, 8));
    TEST_CHECK(b == 0x2fffff);

    OK(uc_close(uc));
}
#endif

static bool test_x86_lazy_mapping_mem_callback(uc_engine *uc, uc_mem_type type,
                                               uint64_t address, int size,
                                               int64_t value, void *user_data)
{
    OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, "\x90\x90", 2)); // nop; nop

    // Handled!
    return true;
}

static void test_x86_lazy_mapping_block_callback(uc_engine *uc,
                                                 uint64_t address,
                                                 uint32_t size, void *user_data)
{
    int *block_count = (int *)user_data;
    (*block_count)++;
}

static void test_x86_lazy_mapping(void)
{
    uc_engine *uc;
    uc_hook mem_hook, block_hook;
    int block_count = 0;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_hook_add(uc, &mem_hook, UC_HOOK_MEM_FETCH_UNMAPPED,
                   test_x86_lazy_mapping_mem_callback, NULL, 1, 0));
    OK(uc_hook_add(uc, &block_hook, UC_HOOK_BLOCK,
                   test_x86_lazy_mapping_block_callback, &block_count, 1, 0));

    OK(uc_emu_start(uc, 0x1000, 0x1002, 0, 0));
    TEST_CHECK(block_count == 1);
    OK(uc_close(uc));
}

static void test_x86_16_incorrect_ip_cb(uc_engine *uc, uint64_t address,
                                        uint32_t size, void *data)
{
    uint16_t cs, ip;

    OK(uc_reg_read(uc, UC_X86_REG_CS, &cs));
    OK(uc_reg_read(uc, UC_X86_REG_IP, &ip));

    TEST_CHECK(cs == 0x20);
    TEST_CHECK(address == ((cs << 4) + ip));
}

static void test_x86_16_incorrect_ip(void)
{
    uc_engine *uc;
    uc_hook hk1, hk2;
    uint16_t cs = 0x20;
    char code[] = "\x41"; // INC cx;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_16, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &hk1, UC_HOOK_BLOCK, test_x86_16_incorrect_ip_cb, NULL,
                   1, 0));
    OK(uc_hook_add(uc, &hk2, UC_HOOK_CODE, test_x86_16_incorrect_ip_cb, NULL, 1,
                   0));

    OK(uc_reg_write(uc, UC_X86_REG_CS, &cs));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

// Porting to BE: Only uc_mem_read/write needs endian fixing
static void test_x86_mmu_prepare_tlb(uc_engine *uc, uint64_t vaddr,
                                     uint64_t tlb_base)
{
    uint64_t cr0;
    uint64_t cr4;
    uc_x86_msr msr = {.rid = 0x0c0000080, .value = 0};
    uint64_t pml4o = ((vaddr & 0x00ff8000000000) >> 39) * 8;
    uint64_t pdpo = ((vaddr & 0x00007fc0000000) >> 30) * 8;
    uint64_t pdo = ((vaddr & 0x0000003fe00000) >> 21) * 8;
    uint64_t pml4e = (tlb_base + 0x1000) | 1 | (1 << 2);
    uint64_t pdpe = (tlb_base + 0x2000) | 1 | (1 << 2);
    uint64_t pde = (tlb_base + 0x3000) | 1 | (1 << 2);
    uint64_t pml4e_mem = LEINT64(pml4e);
    uint64_t pde_mem = LEINT64(pde);
    uint64_t pdpe_mem = LEINT64(pdpe);
    OK(uc_mem_write(uc, tlb_base + pml4o, &pml4e_mem, sizeof(pml4o)));
    OK(uc_mem_write(uc, tlb_base + 0x1000 + pdpo, &pdpe_mem, sizeof(pdpe)));
    OK(uc_mem_write(uc, tlb_base + 0x2000 + pdo, &pde_mem, sizeof(pde)));
    OK(uc_reg_write(uc, UC_X86_REG_CR3, &tlb_base));
    OK(uc_reg_read(uc, UC_X86_REG_CR0, &cr0));
    OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
    OK(uc_reg_read(uc, UC_X86_REG_MSR, &msr));
    cr0 |= 1;
    cr0 |= 1l << 31;
    cr4 |= 1l << 5;
    msr.value |= 1l << 8;
    OK(uc_reg_write(uc, UC_X86_REG_CR0, &cr0));
    OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));
    OK(uc_reg_write(uc, UC_X86_REG_MSR, &msr));
}

static void test_x86_mmu_pt_set(uc_engine *uc, uint64_t vaddr, uint64_t paddr,
                                uint64_t tlb_base, bool readwrite)
{
    uint64_t pto = ((vaddr & 0x000000001ff000) >> 12) * 8;
    uint32_t pte;
    if (readwrite)
        pte = (paddr) | 1 | (1 << 2);
    else
        pte = (paddr) | 1;
    pte = LEINT32(pte);

    uc_mem_write(uc, tlb_base + 0x3000 + pto, &pte, sizeof(pte));
}

static void test_x86_mmu_callback(uc_engine *uc, void *userdata)
{
    bool *parrent_done = userdata;
    uint64_t rax;
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    switch (rax) {
    case 57:
        /* fork */
        break;
    case 60:
        /* exit */
        uc_emu_stop(uc);
        return;
    default:
        TEST_CHECK(false);
    }

    if (!(*parrent_done)) {
        *parrent_done = true;
        rax = 27;
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        uc_emu_stop(uc);
    }
}

static void test_x86_mmu(void)
{
    bool parrent_done = false;
    uint64_t tlb_base = 0x3000;
    uint64_t parrent, child;
    uint64_t rax, rip;
    uc_context *context;
    uc_engine *uc;
    uc_hook h1;

    /*
     * mov rax, 57
     * syscall
     * test rax, rax
     * jz child
     * xor rax, rax
     * mov rax, 60
     * mov [0x4000], rax
     * syscall
     *
     * child:
     * xor rcx, rcx
     * mov rcx, 42
     * mov [0x4000], rcx
     * mov rax, 60
     * syscall
     */
    char code[] =
        "\xB8\x39\x00\x00\x00\x0F\x05\x48\x85\xC0\x74\x0F\xB8\x3C\x00\x00\x00"
        "\x48\x89\x04\x25\x00\x40\x00\x00\x0F\x05\xB9\x2A\x00\x00\x00\x48\x89"
        "\x0C\x25\x00\x40\x00\x00\xB8\x3C\x00\x00\x00\x0F\x05";

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_CPU));
    OK(uc_hook_add(uc, &h1, UC_HOOK_INSN, &test_x86_mmu_callback, &parrent_done,
                   1, 0, UC_X86_INS_SYSCALL));
    OK(uc_context_alloc(uc, &context));

    OK(uc_mem_map(uc, 0x0, 0x1000, UC_PROT_ALL)); // Code
    OK(uc_mem_write(uc, 0x0, code, sizeof(code) - 1));
    OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL));   // Parrent
    OK(uc_mem_map(uc, 0x2000, 0x1000, UC_PROT_ALL));   // Child
    OK(uc_mem_map(uc, tlb_base, 0x4000, UC_PROT_ALL)); // TLB

    test_x86_mmu_prepare_tlb(uc, 0x0, tlb_base);
    test_x86_mmu_pt_set(uc, 0x2000, 0x0, tlb_base, true);
    test_x86_mmu_pt_set(uc, 0x4000, 0x1000, tlb_base, true);

    OK(uc_ctl_flush_tlb(uc));
    OK(uc_emu_start(uc, 0x2000, 0x0, 0, 0));

    OK(uc_context_save(uc, context));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    OK(uc_emu_start(uc, rip, 0x0, 0, 0));

    /* restore for child */
    OK(uc_context_restore(uc, context));
    test_x86_mmu_prepare_tlb(uc, 0x0, tlb_base);
    test_x86_mmu_pt_set(uc, 0x4000, 0x2000, tlb_base, true);
    rax = 0;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_ctl_flush_tlb(uc));

    OK(uc_emu_start(uc, rip, 0x0, 0, 0));
    OK(uc_mem_read(uc, 0x1000, &parrent, sizeof(parrent)));
    OK(uc_mem_read(uc, 0x2000, &child, sizeof(child)));
    TEST_CHECK(LEINT64(parrent) == 60);
    TEST_CHECK(LEINT64(child) == 42);
    OK(uc_context_free(context));
    OK(uc_close(uc));
}

static void test_x86_read_virtual(void)
{
    bool parrent_done = false;
    uint64_t tlb_base = 0x3000;
    uint64_t parrent, child, tmp;
    uint64_t rax, rip;
    uc_context *context;
    uc_engine *uc;
    uc_hook h1;

    /*
     * mov rax, 57
     * syscall
     * test rax, rax
     * jz child
     * xor rax, rax
     * mov rax, 60
     * mov [0x4000], rax
     * syscall
     *
     * child:
     * xor rcx, rcx
     * mov rcx, 42
     * mov [0x4000], rcx
     * mov rax, 60
     * syscall
     */
    char code[] =
        "\xB8\x39\x00\x00\x00\x0F\x05\x48\x85\xC0\x74\x0F\xB8\x3C\x00\x00\x00"
        "\x48\x89\x04\x25\x00\x40\x00\x00\x0F\x05\xB9\x2A\x00\x00\x00\x48\x89"
        "\x0C\x25\x00\x40\x00\x00\xB8\x3C\x00\x00\x00\x0F\x05";

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_CPU));
    OK(uc_hook_add(uc, &h1, UC_HOOK_INSN, &test_x86_mmu_callback, &parrent_done,
                   1, 0, UC_X86_INS_SYSCALL));
    OK(uc_context_alloc(uc, &context));

    OK(uc_mem_map(uc, 0x0, 0x1000, UC_PROT_ALL)); // Code
    OK(uc_mem_write(uc, 0x0, code, sizeof(code) - 1));
    OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL));   // Parrent
    OK(uc_mem_map(uc, 0x2000, 0x1000, UC_PROT_ALL));   // Child
    OK(uc_mem_map(uc, tlb_base, 0x4000, UC_PROT_ALL)); // TLB

    test_x86_mmu_prepare_tlb(uc, 0x0, tlb_base);
    test_x86_mmu_pt_set(uc, 0x2000, 0x0, tlb_base, false);
    test_x86_mmu_pt_set(uc, 0x4000, 0x1000, tlb_base, true);

    OK(uc_ctl_flush_tlb(uc));
    OK(uc_emu_start(uc, 0x2000, 0x0, 0, 0));

    OK(uc_context_save(uc, context));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    OK(uc_emu_start(uc, rip, 0x0, 0, 0));
    OK(uc_vmem_read(uc, 0x4000, UC_PROT_READ, &parrent,
                           sizeof(parrent)));

    /* restore for child */
    OK(uc_context_restore(uc, context));
    test_x86_mmu_prepare_tlb(uc, 0x0, tlb_base);
    test_x86_mmu_pt_set(uc, 0x4000, 0x2000, tlb_base, true);
    rax = 0;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_ctl_flush_tlb(uc));

    OK(uc_emu_start(uc, rip, 0x0, 0, 0));
    OK(uc_vmem_read(uc, 0x4000, UC_PROT_READ, &child, sizeof(child)));
    uc_assert_err(
        UC_ERR_READ_PROT,
        uc_vmem_read(uc, 0x1000, UC_PROT_WRITE, &tmp, sizeof(tmp)));
    TEST_CHECK(parrent == 60);
    TEST_CHECK(child == 42);
}

static bool test_x86_vtlb_callback(uc_engine *uc, uint64_t addr,
                                   uc_mem_type type, uc_tlb_entry *result,
                                   void *user_data)
{
    result->paddr = addr;
    result->perms = UC_PROT_ALL;
    return true;
}

static void test_x86_vtlb(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\xeb\x02\x90\x90\x90\x90\x90\x90"; // jmp 4; nop; nop; nop;
                                                      // nop; nop; nop
    uint32_t r_eip = 0;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_TLB_FILL, test_x86_vtlb_callback, NULL, 1,
                   0));

    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EIP, &r_eip));

    TEST_CHECK(r_eip == code_start + 4);

    OK(uc_close(uc));
}

static void test_x86_segmentation(void)
{
    uc_engine *uc;
    uint16_t fs = 0x53;
    uc_x86_mmr gdtr = {0, 0xfffff8076d962000, 0x57, 0};

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr));
    uc_assert_err(UC_ERR_EXCEPTION, uc_reg_write(uc, UC_X86_REG_FS, &fs));
    OK(uc_close(uc));
}

static void test_x86_0xff_lcall_callback(uc_engine *uc, uint64_t address,
                                         uint32_t size, void *user_data)
{
    // do nothing
    return;
}

// This aborts prior to a7a5d187e77f7853755eff4768658daf8095c3b7
static void test_x86_0xff_lcall(void)
{
    uc_engine *uc;
    uc_hook hk;
    const char code[] =
        "\xB8\x01\x00\x00\x00\xBB\x01\x00\x00\x00\xB9\x01\x00\x00\x00\xFF\xDD"
        "\xBA\x01\x00\x00\x00\xB8\x02\x00\x00\x00\xBB\x02\x00\x00\x00";
    // Taken from #1842
    // 0:  b8 01 00 00 00          mov    eax,0x1
    // 5:  bb 01 00 00 00          mov    ebx,0x1
    // a:  b9 01 00 00 00          mov    ecx,0x1
    // f:  ff                      (bad)
    // 10: dd ba 01 00 00 00       fnstsw WORD PTR [edx+0x1]
    // 16: b8 02 00 00 00          mov    eax,0x2
    // 1b: bb 02 00 00 00          mov    ebx,0x2

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &hk, UC_HOOK_CODE, test_x86_0xff_lcall_callback, NULL, 1,
                   0));

    uc_assert_err(
        UC_ERR_INSN_INVALID,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static bool test_x86_64_not_overwriting_tmp0_for_pc_update_cb(
    uc_engine *uc, uc_mem_type type, uint64_t address, int size, uint64_t value,
    void *user_data)
{
    return true;
}

// https://github.com/unicorn-engine/unicorn/issues/1717
// https://github.com/unicorn-engine/unicorn/issues/1862
static void test_x86_64_not_overwriting_tmp0_for_pc_update(void)
{
    uc_engine *uc;
    uc_hook hk;
    const char code[] = "\x48\xb9\xff\xff\xff\xff\xff\xff\xff\xff\x48\x89\x0c"
                        "\x24\x48\xd3\x24\x24\x73\x0a";
    uint64_t rsp, pc;
    uint32_t eflags;

    // 0x1000: movabs  rcx, 0xffffffffffffffff
    // 0x100a: mov     qword ptr [rsp], rcx
    // 0x100e: shl     qword ptr [rsp], cl ; (Shift to CF=1)
    // 0x1012: jae     0xd ; this jump should not be taken! (CF=1 but jae
    // expects CF=0)
    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                   test_x86_64_not_overwriting_tmp0_for_pc_update_cb, NULL, 1,
                   0));

    rsp = 0x2000;
    OK(uc_reg_write(uc, UC_X86_REG_RSP, (void *)&rsp));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 4));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &pc));
    OK(uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags));

    TEST_CHECK(pc == 0x1014);
    TEST_CHECK((eflags & 0x1) == 1);

    OK(uc_close(uc));
}

static void test_fxsave_fpip_x86(void)
{
    // note: fxsave was introduced in Pentium II
    uint8_t code_x86[] = {
        // help testing through NOP offset      [disassembly in at&t syntax]
        0x90, 0x90, 0x90, 0x90, // nop nop nop nop
        // run a floating point instruction
        0xdb, 0xc9, // fcmovne %st(1), %st
        // fxsave needs 512 bytes of storage space
        0x81, 0xec, 0x00, 0x02, 0x00, 0x00, // subl $512, %esp
        // fxsave needs a 16-byte aligned address for storage
        0x83, 0xe4, 0xf0, // andl $0xfffffff0, %esp
        // store fxsave data on the stack
        0x0f, 0xae, 0x04, 0x24, // fxsave (%esp)
        // fxsave stores FPIP at an 8-byte offset, move FPIP to eax register
        0x8b, 0x44, 0x24, 0x08 // movl 0x8(%esp), %eax
    };
    uint32_t X86_NOP_OFFSET = 4;
    uint32_t stack_top = (uint32_t)MEM_STACK;
    uint32_t value;
    uc_engine *uc;

    // initialize emulator in X86-32bit mode
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    // map 1MB of memory for this emulation
    OK(uc_mem_map(uc, MEM_BASE, MEM_SIZE, UC_PROT_ALL));
    OK(uc_mem_write(uc, MEM_TEXT, code_x86, sizeof(code_x86)));
    OK(uc_reg_write(uc, UC_X86_REG_ESP, &stack_top));
    OK(uc_emu_start(uc, MEM_TEXT, MEM_TEXT + sizeof(code_x86), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &value));
    TEST_CHECK(value == ((uint32_t)MEM_TEXT + X86_NOP_OFFSET));
    OK(uc_mem_unmap(uc, MEM_BASE, MEM_SIZE));
    OK(uc_close(uc));
}

static void test_fxsave_fpip_x64(void)
{
    uint8_t code_x64[] = {
        // help testing through NOP offset     [disassembly in at&t]
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // nops
        // run a floating point instruction
        0xdb, 0xc9, // fcmovne %st(1), %st
        // fxsave64 needs 512 bytes of storage space
        0x48, 0x81, 0xec, 0x00, 0x02, 0x00, 0x00, // subq $512, %rsp
        // fxsave needs a 16-byte aligned address for storage
        0x48, 0x83, 0xe4, 0xf0, // andq 0xfffffffffffffff0, %rsp
        // store fxsave64 data on the stack
        0x48, 0x0f, 0xae, 0x04, 0x24, // fxsave64 (%rsp)
        // fxsave64 stores FPIP at an 8-byte offset, move FPIP to rax register
        0x48, 0x8b, 0x44, 0x24, 0x08, // movq 0x8(%rsp), %rax
    };

    uint64_t stack_top = (uint64_t)MEM_STACK;
    uint64_t X64_NOP_OFFSET = 8;
    uint64_t value;
    uc_engine *uc;

    // initialize emulator in X86-32bit mode
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));

    // map 1MB of memory for this emulation
    OK(uc_mem_map(uc, MEM_BASE, MEM_SIZE, UC_PROT_ALL));
    OK(uc_mem_write(uc, MEM_TEXT, code_x64, sizeof(code_x64)));
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &stack_top));
    OK(uc_emu_start(uc, MEM_TEXT, MEM_TEXT + sizeof(code_x64), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &value));
    TEST_CHECK(value == ((uint64_t)MEM_TEXT + X64_NOP_OFFSET));
    OK(uc_mem_unmap(uc, MEM_BASE, MEM_SIZE));
    OK(uc_close(uc));
}

static void test_x86_fxsave_writes_complete_legacy_fpu_state(void)
{
    static const uint8_t fxsave[] = {
        0x0f, 0xae, 0x07, /* fxsave [rdi] */
    };
    static const uint8_t xsave[] = {
        0x31, 0xc9,       /* xor ecx, ecx */
        0x0f, 0x01, 0xd1, /* xsetbv */
        0x0f, 0xae, 0x27, /* xsave [rdi] */
    };
    static const struct {
        const uint8_t *code;
        size_t size;
        bool needs_xcr0;
    } cases[] = {
        {fxsave, sizeof(fxsave), false},
        {xsave, sizeof(xsave), true},
    };
    const uint64_t save_area = UINT64_C(0x8000);
    const uint16_t fop = 0x05a5;

    for (size_t case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]); ++case_index) {
        uint8_t saved[512];
        uint16_t saved_fop;
        uint32_t eax = 1; /* Save and enable the x87 state component. */
        uint32_t edx = 0;
        uc_engine *uc;

        memset(saved, 0xcc, sizeof(saved));
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[case_index].code, cases[case_index].size);
        OK(uc_mem_map(uc, save_area, 0x1000, UC_PROT_ALL));
        OK(uc_mem_write(uc, save_area, saved, sizeof(saved)));
        OK(uc_reg_write(uc, UC_X86_REG_RDI, &save_area));
        OK(uc_reg_write(uc, UC_X86_REG_FOP, &fop));
        if (cases[case_index].needs_xcr0) {
            OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
            OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
        }

        OK(uc_emu_start(uc, code_start,
                        code_start + cases[case_index].size, 0, 0));
        OK(uc_mem_read(uc, save_area, saved, sizeof(saved)));

        memcpy(&saved_fop, &saved[6], sizeof(saved_fop));
        TEST_CHECK(saved_fop == fop);
        for (size_t slot = 0; slot < 8; ++slot) {
            for (size_t byte = 10; byte < 16; ++byte) {
                TEST_CHECK(saved[32 + slot * 16 + byte] == 0);
            }
        }

        OK(uc_close(uc));
    }
}

static void test_bswap_ax(void)
{
    // References:
    // - https://gynvael.coldwind.pl/?id=268
    // - https://github.com/JonathanSalwan/Triton/issues/1131
    {
        uint8_t code[] = {
            // bswap ax
            0x66,
            0x0F,
            0xC8,
        };
        TEST_CODE(UC_MODE_32, code);
        TEST_IN_REG(EAX, 0x44332211);
        TEST_OUT_REG(EAX, 0x44330000);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // bswap ax
            0x66,
            0x0F,
            0xC8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_OUT_REG(RAX, 0x8877665544330000);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // bswap rax (66h ignored)
            0x66,
            0x48,
            0x0F,
            0xC8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_OUT_REG(RAX, 0x1122334455667788);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // bswap ax (rex ignored)
            0x48,
            0x66,
            0x0F,
            0xC8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_OUT_REG(RAX, 0x8877665544330000);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // bswap eax
            0x0F,
            0xC8,
        };
        TEST_CODE(UC_MODE_32, code);
        TEST_IN_REG(EAX, 0x44332211);
        TEST_OUT_REG(EAX, 0x11223344);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // bswap eax
            0x0F,
            0xC8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_OUT_REG(RAX, 0x0000000011223344);
        TEST_RUN();
    }
}

static void test_rex_x64(void)
{
    {
        uint8_t code[] = {
            // mov ax, bx (rex.w ignored)
            0x48,
            0x66,
            0x89,
            0xD8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_IN_REG(RBX, 0x1122334455667788);
        TEST_OUT_REG(RAX, 0x8877665544337788);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // mov rax, rbx (66h ignored)
            0x66,
            0x48,
            0x89,
            0xD8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_IN_REG(RBX, 0x1122334455667788);
        TEST_OUT_REG(RAX, 0x1122334455667788);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // mov ax, bx (expected encoding)
            0x66,
            0x89,
            0xD8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_IN_REG(RBX, 0x1122334455667788);
        TEST_OUT_REG(RAX, 0x8877665544337788);
        TEST_RUN();
    }
}

static bool test_x86_ro_segfault_cb(uc_engine *uc, uc_mem_type type,
                                    uint64_t address, int size, uint64_t value,
                                    void *user_data)
{
    const char code[] = "\xA1\x00\x10\x00\x00\xA1\x00\x10\x00\x00";
    OK(uc_mem_write(uc, address, code, sizeof(code) - 1));
    return true;
}

static void test_x86_ro_segfault(void)
{
    uc_engine *uc;
    // mov eax, [0x1000]
    // mov eax, [0x1000]
    const char code[] = "\xA1\x00\x10\x00\x00\xA1\x00\x10\x00\x00";
    uint32_t out;
    uc_hook hh;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, 0, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0, code, sizeof(code) - 1));
    OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_READ));

    OK(uc_hook_add(uc, &hh, UC_HOOK_MEM_READ, test_x86_ro_segfault_cb, NULL, 1,
                   0));
    OK(uc_emu_start(uc, 0, sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EAX, (void *)&out));
    TEST_CHECK(out == 0x001000a1);
    OK(uc_close(uc));
}

static bool test_x86_hook_insn_rdtsc_cb(uc_engine *uc, void *user_data)
{
    uint64_t h = 0x00000000FEDCBA98;
    OK(uc_reg_write(uc, UC_X86_REG_RDX, &h));

    uint64_t l = 0x0000000076543210;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &l));

    return true;
}

static void test_x86_hook_insn_rdtsc(void)
{
    char code[] = "\x0F\x31"; // RDTSC

    uc_engine *uc;
    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof code - 1);

    uc_hook hook;
    OK(uc_hook_add(uc, &hook, UC_HOOK_INSN, test_x86_hook_insn_rdtsc_cb, NULL,
                   1, 0, UC_X86_INS_RDTSC));

    OK(uc_emu_start(uc, code_start, code_start + sizeof code - 1, 0, 0));

    OK(uc_hook_del(uc, hook));

    uint64_t h = 0;
    OK(uc_reg_read(uc, UC_X86_REG_RDX, &h));
    TEST_CHECK(h == 0x00000000FEDCBA98);

    uint64_t l = 0;
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &l));
    TEST_CHECK(l == 0x0000000076543210);

    OK(uc_close(uc));
}

static bool test_x86_hook_insn_rdtscp_cb(uc_engine *uc, void *user_data)
{
    uint64_t h = 0x0000000001234567;
    OK(uc_reg_write(uc, UC_X86_REG_RDX, &h));

    uint64_t l = 0x0000000089ABCDEF;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &l));

    uint64_t i = 0x00000000DEADBEEF;
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &i));

    return true;
}

static void test_x86_hook_insn_rdtscp(void)
{
    uc_engine *uc;
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));

    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));

    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));

    char code[] = "\x0F\x01\xF9"; // RDTSCP
    OK(uc_mem_write(uc, code_start, code, sizeof code - 1));

    uc_hook hook;
    OK(uc_hook_add(uc, &hook, UC_HOOK_INSN, test_x86_hook_insn_rdtscp_cb, NULL,
                   1, 0, UC_X86_INS_RDTSCP));

    OK(uc_emu_start(uc, code_start, code_start + sizeof code - 1, 0, 0));

    OK(uc_hook_del(uc, hook));

    uint64_t h = 0;
    OK(uc_reg_read(uc, UC_X86_REG_RDX, &h));
    TEST_CHECK(h == 0x0000000001234567);

    uint64_t l = 0;
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &l));
    TEST_CHECK(l == 0x0000000089ABCDEF);

    uint64_t i = 0;
    OK(uc_reg_read(uc, UC_X86_REG_RCX, &i));
    TEST_CHECK(i == 0x00000000DEADBEEF);

    OK(uc_close(uc));
}

static void test_x86_dr7()
{
    uc_engine *uc;
    char code[] =
        "\x48\xC7\xC0\x05\x00\x01\x00\x0F\x23\xF8"; // mov rax, 0x10005
                                                    // mov dr7, rax
    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_x86_hook_block_cb(uc_engine *uc, uint64_t address,
                                   uint32_t size, void *user_data)
{
    uint32_t pc;

    OK(uc_reg_read(uc, UC_X86_REG_EIP, (void *)&pc));

    TEST_CHECK(pc == address);
    *((uint64_t *)user_data) += 1;
}

static void test_x86_hook_block()
{
    uc_engine *uc;
    char code[] = "\xeb\x02\x90\x90\x90\x90\x90\x90"; // jmp 4; nop; nop; nop;
                                                      // nop; nop; nop
    uint64_t cnt = 0;
    uc_hook hk;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &hk, UC_HOOK_BLOCK, test_x86_hook_block_cb, (void *)&cnt,
                   1, 0));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    TEST_CHECK(cnt == 2);
    OK(uc_close(uc));
}

static bool test_x86_mem_hooks_pc_guarante_mem(uc_engine *uc, uc_mem_type type,
                                               uint64_t addr, int size,
                                               int64_t val, void *data)
{
    if (addr >= code_start + code_len) {
        uint32_t eip;
        OK(uc_reg_read(uc, UC_X86_REG_EIP, (void*)&eip));
        TEST_CHECK(eip == code_start + 1);
    }
    return true;
}

static void test_x86_mem_hooks_pc_guarantee(void)
{
    uc_engine *uc;
    // bs, _ = ks.asm("inc edx; t: mov eax, [ebx]; inc ebx; cmp ebx, ecx; jnz t;")
    char code[] = "\x42\x8b\x03\x43\x39\xcb\x75\xf9";
    uint32_t ebx=code_start + code_len, ecx = code_start + code_len + 0x10;
    uc_hook hk;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_mem_map(uc, code_start + code_len, 0x1000, UC_PROT_ALL));
    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_READ, test_x86_mem_hooks_pc_guarante_mem, NULL,
                   1, 0));
    OK(uc_reg_write(uc, UC_X86_REG_EBX, (void*)&ebx));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, (void*)&ecx));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_x86_rflags_after_fault(const uint8_t *code, size_t code_size,
                                        uc_err expected_error,
                                        uint64_t expected_rflags,
                                        uint64_t read_only_page_base)
{
    uc_engine *uc;
    uint64_t rflags;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    code_size);

    if (read_only_page_base != 0) {
        OK(uc_mem_map(uc, read_only_page_base, 0x1000, UC_PROT_READ));
        OK(uc_reg_write(uc, UC_X86_REG_RBX, &read_only_page_base));
    }

    uc_assert_err(expected_error,
                  uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

    TEST_CHECK_(rflags == expected_rflags,
                "RFLAGS after fault: expected 0x%" PRIx64 ", got 0x%" PRIx64,
                expected_rflags, rflags);

    OK(uc_close(uc));
}

static void test_x86_rotate_rflags_after_fault(void)
{
    const uint8_t rcl_code[] = {
        0x01, 0xc0,       /* add eax, eax */
        0xc0, 0x13, 0x00, /* rcl byte ptr [rbx], 0 */
    };
    const uint8_t rcr_code[] = {
        0x01, 0xc0,       /* add eax, eax */
        0xc0, 0x1b, 0x00, /* rcr byte ptr [rbx], 0 */
    };
    const uint64_t read_only_page_base = code_start + code_len;

    test_x86_rflags_after_fault(rcl_code, sizeof(rcl_code),
                                UC_ERR_READ_UNMAPPED, 0x46, 0);
    test_x86_rflags_after_fault(rcl_code, sizeof(rcl_code),
                                UC_ERR_WRITE_PROT, 0x46,
                                read_only_page_base);
    test_x86_rflags_after_fault(rcr_code, sizeof(rcr_code),
                                UC_ERR_READ_UNMAPPED, 0x46, 0);
    test_x86_rflags_after_fault(rcr_code, sizeof(rcr_code),
                                UC_ERR_WRITE_PROT, 0x46,
                                read_only_page_base);
}

static void test_x86_setcc_rflags_after_fault(void)
{
    uint8_t setcc_code[] = {
        0x01, 0xc0,       /* add eax, eax */
        0x0f, 0x90, 0x03, /* seto byte ptr [rbx] */
    };
    const uint64_t read_only_page_base = code_start + code_len;

    for (uint8_t condition = 0x90; condition <= 0x9f; condition++) {
        setcc_code[3] = condition;
        test_x86_rflags_after_fault(setcc_code, sizeof(setcc_code),
                                    UC_ERR_WRITE_UNMAPPED, 0x46, 0);
        test_x86_rflags_after_fault(setcc_code, sizeof(setcc_code),
                                    UC_ERR_WRITE_PROT, 0x46,
                                    read_only_page_base);
    }
}

static void test_x86_group_1a_reserved_encodings(void)
{
    const uint64_t stack_base = 0x2000000;
    const uint64_t stack_value = 0x0123456789abcdefULL;
    const uint64_t initial_rax = 0xfedcba9876543210ULL;

    for (uint8_t extension = 1; extension <= 7; extension++) {
        uc_engine *uc;
        uint8_t code[] = {0x8f, (uint8_t)(0xc0 | (extension << 3))};
        uint64_t rsp = stack_base;
        uint64_t rax = initial_rax;

        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                        sizeof(code));
        OK(uc_mem_map(uc, stack_base, 0x1000, UC_PROT_ALL));
        OK(uc_mem_write(uc, stack_base, &stack_value, sizeof(stack_value)));
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));

        uc_assert_err(UC_ERR_INSN_INVALID,
                      uc_emu_start(uc, code_start,
                                   code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));

        TEST_CHECK_(rsp == stack_base,
                    "reserved 8f /%u changed RSP to 0x%" PRIx64,
                    extension, rsp);
        TEST_CHECK_(rax == initial_rax,
                    "reserved 8f /%u changed RAX to 0x%" PRIx64,
                    extension, rax);

        OK(uc_close(uc));
    }
}

static void test_x86_group_5_reserved_fault_priority(void)
{
    uc_engine *uc;
    const uint8_t code[] = {0xff, 0x38}; /* reserved ff /7, qword ptr [rax] */
    uint64_t rax = code_start + code_len + 0x100;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));

    uc_assert_err(UC_ERR_INSN_INVALID,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));

    OK(uc_close(uc));
}

static void test_x86_group_11_decode_rules(void)
{
    const uint64_t initial_rax = 0x1122334455667788ULL;

    for (uint8_t opcode = 0xc6; opcode <= 0xc7; opcode++) {
        for (uint8_t extension = 1; extension <= 7; extension++) {
            uc_engine *uc;
            uint8_t code[] = {
                opcode, (uint8_t)(0xc0 | (extension << 3)),
                0x78, 0x56, 0x34, 0x12,
            };
            size_t code_size = opcode == 0xc6 ? 3 : sizeof(code);
            uint64_t rax = initial_rax;

            uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64,
                            (const char *)code, code_size);
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));

            uc_assert_err(UC_ERR_INSN_INVALID,
                          uc_emu_start(uc, code_start,
                                       code_start + code_size, 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
            TEST_CHECK_(rax == initial_rax,
                        "reserved %02x /%u changed RAX to 0x%" PRIx64,
                        opcode, extension, rax);

            OK(uc_close(uc));
        }
    }

    {
        uc_engine *uc;
        const uint8_t code[] = {
            0x44, 0xc6, 0xc0, 0xab,                   /* mov al, 0xab */
            0x44, 0xc7, 0xc1, 0x78, 0x56, 0x34, 0x12, /* mov ecx, imm32 */
        };
        uint64_t rax = initial_rax;
        uint64_t rcx = 0xaabbccddeeff0011ULL;

        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                        sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));

        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx));

        TEST_CHECK(rax == 0x11223344556677abULL);
        TEST_CHECK(rcx == 0x0000000012345678ULL);

        OK(uc_close(uc));
    }
}

static void test_x86_group_3_extension_1_test(void)
{
    uc_engine *uc;
    const uint8_t code[] = {
        0xb8, 0x10, 0x00, 0x00, 0x00,       /* mov eax, 0x10 */
        0xf6, 0xc8, 0x0f,                   /* test al, 0x0f */
        0x0f, 0x94, 0xc3,                   /* sete bl */
        0x0f, 0x92, 0xc2,                   /* setc dl */
        0xf7, 0xc8, 0x18, 0x00, 0x00, 0x00, /* test eax, 0x18 */
        0x0f, 0x95, 0xc1,                   /* setne cl */
        0x0f, 0x90, 0xc6,                   /* seto dh */
    };
    const uint64_t status_mask = (1ULL << 0) | (1ULL << 2) | (1ULL << 6)
                                 | (1ULL << 7) | (1ULL << 11);
    uint64_t rax = 0;
    uint64_t rbx = 0;
    uint64_t rcx = 0;
    uint64_t rdx = 0;
    uint64_t rflags = status_mask | 2;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_reg_write(uc, UC_X86_REG_RDX, &rdx));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_read(uc, UC_X86_REG_RBX, &rbx));
    OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_reg_read(uc, UC_X86_REG_RDX, &rdx));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

    TEST_CHECK(rax == 0x10);
    TEST_CHECK(rbx == 1);
    TEST_CHECK(rcx == 1);
    TEST_CHECK(rdx == 0);
    TEST_CHECK((rflags & status_mask) == 0);

    OK(uc_close(uc));
}

static void test_x86_dpps_pairwise_reduction(void)
{
    uc_engine *uc;
    const uint8_t code[] = {
        0x66, 0x0f, 0x3a, 0x40, 0xc1, 0xf1, /* dpps xmm0, xmm1, 0xf1 */
    };
    const uint32_t lhs[4] = {
        0x60ad78ec, 0x3f800000, 0xe0ad78ec, 0x3f800000,
    };
    const uint32_t rhs[4] = {
        0x3f800000, 0x3f800000, 0x3f800000, 0x3f800000,
    };
    uint32_t mxcsr = 0x1f80;
    uint32_t result[4] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, lhs));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, rhs));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, result));

    for (size_t lane = 0; lane < 4; lane++) {
        TEST_CHECK_(result[lane] == 0,
                    "DPPS lane %zu has bits 0x%08" PRIx32, lane,
                    result[lane]);
    }

    OK(uc_close(uc));
}

static void test_x86_dppd_signed_zero_reduction(void)
{
    uc_engine *uc;
    const uint8_t code[] = {
        0x66, 0x0f, 0x3a, 0x41, 0xc1, 0x31, /* dppd xmm0, xmm1, 0x31 */
    };
    const uint64_t lhs[2] = {
        0x8000000000000000ULL, 0x8000000000000000ULL,
    };
    const uint64_t rhs[2] = {
        0x3ff0000000000000ULL, 0x3ff0000000000000ULL,
    };
    uint32_t mxcsr = 0x1f80;
    uint64_t result[2] = {0xffffffffffffffffULL, 0xffffffffffffffffULL};

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, lhs));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, rhs));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, result));

    TEST_CHECK_(result[0] == 0x8000000000000000ULL,
                "DPPD lane 0 has bits 0x%016" PRIx64, result[0]);
    TEST_CHECK_(result[1] == 0,
                "DPPD lane 1 has bits 0x%016" PRIx64, result[1]);

    OK(uc_close(uc));
}

static void test_x86_vdpps_ymm_pairwise_lanes(void)
{
    uc_engine *uc;
    const uint8_t code[] = {
        0xc4, 0xe3, 0x75, 0x40, 0xc2, 0xf1, /* vdpps ymm0, ymm1, ymm2, 0xf1 */
    };
    const uint32_t lhs[8] = {
        0x60ad78ec, 0x3f800000, 0xe0ad78ec, 0x3f800000,
        0x3f800000, 0x40000000, 0x40400000, 0x40800000,
    };
    const uint32_t rhs[8] = {
        0x3f800000, 0x3f800000, 0x3f800000, 0x3f800000,
        0x3f800000, 0x3f800000, 0x3f800000, 0x3f800000,
    };
    const uint32_t expected[8] = {
        0, 0, 0, 0, 0x41200000, 0, 0, 0,
    };
    uint32_t mxcsr = 0x1f80;
    uint32_t result[8] = {
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    };

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, lhs));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, rhs));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));

    for (size_t lane = 0; lane < 8; lane++) {
        TEST_CHECK_(result[lane] == expected[lane],
                    "VDPPS lane %zu has bits 0x%08" PRIx32, lane,
                    result[lane]);
    }

    OK(uc_close(uc));
}

static void test_x86_vzero_state(void)
{
    static const uint8_t code[][3] = {
        { 0xc5, 0xf8, 0x77 }, /* vzeroupper */
        { 0xc5, 0xfc, 0x77 }, /* vzeroall */
    };
    const uint64_t initial[4] = {
        0x1111111122222222ULL, 0x3333333344444444ULL,
        0x5555555566666666ULL, 0x7777777788888888ULL,
    };
    int case_index;

    for (case_index = 0; case_index < 2; case_index++) {
        uint64_t result0[4] = { 0, 0, 0, 0 };
        uint64_t result15[4] = { 0, 0, 0, 0 };
        uc_engine *uc;

        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64,
                        (const char *)code[case_index],
                        sizeof(code[case_index]));
        OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
        OK(uc_reg_write(uc, UC_X86_REG_YMM15, initial));
        OK(uc_emu_start(uc, code_start,
                        code_start + sizeof(code[case_index]), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_YMM0, result0));
        OK(uc_reg_read(uc, UC_X86_REG_YMM15, result15));

        for (int reg_index = 0; reg_index < 2; reg_index++) {
            const uint64_t *result = reg_index ? result15 : result0;

            if (case_index == 0) {
                TEST_CHECK(result[0] == initial[0]);
                TEST_CHECK(result[1] == initial[1]);
            } else {
                TEST_CHECK(result[0] == 0);
                TEST_CHECK(result[1] == 0);
            }
            TEST_CHECK(result[2] == 0);
            TEST_CHECK(result[3] == 0);
        }
        OK(uc_close(uc));
    }

    {
        const uint8_t invalid_vvvv[] = { 0xc5, 0xf0, 0x77 };
        uc_engine *uc;

        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64,
                        (const char *)invalid_vvvv, sizeof(invalid_vvvv));
        TEST_CHECK(uc_emu_start(uc, code_start,
                                code_start + sizeof(invalid_vvvv), 0, 0) ==
                   UC_ERR_INSN_INVALID);
        OK(uc_close(uc));
    }
}

static void test_x86_lazy_jcc_materializes_condition_before_branch(void)
{
    const uint8_t code[] = {
        0xb8, 0x01, 0x00, 0x00, 0x00,       /* mov eax, 1 */
        0x48, 0x85, 0xff,                   /* test rdi, rdi */
        0x7f, 0x0f,                         /* jg +15 */
        0x48, 0xc1, 0xff, 0x3f,             /* sar rdi, 63 */
        0x89, 0xf9,                         /* mov ecx, edi */
        0xc1, 0xe1, 0x08,                   /* shl ecx, 8 */
        0x40, 0x0f, 0xb6, 0xc7,             /* movzx eax, dil */
        0x09, 0xc8,                         /* or eax, ecx */
        0x48, 0x98,                         /* cdqe */
        0xc3,                               /* ret (not executed) */
    };
    uint64_t rdi = UINT64_C(0xffffffffffffff00);
    uint64_t rax = 0;
    uc_engine *uc;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_RDI, &rdi));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    TEST_CHECK_(rax == UINT64_MAX,
                "lazy signed JCC returned 0x%016" PRIx64, rax);
    OK(uc_close(uc));
}

static void test_x86_count_hook_syncs_dirty_cc_op(void)
{
    const uint8_t code[] = {
        0x83, 0xc8, 0x00,                   /* or eax, 0 */
        0x83, 0xc8, 0x00,                   /* or eax, 0 */
        0x74, 0x05,                         /* je +5 */
        0xb8, 0xad, 0xde, 0x00, 0x00,       /* mov eax, 0xdead */
    };
    const size_t counts[] = { 0, 64 };

    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        uint32_t eax = 0;
        uc_engine *uc;

        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                        sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0,
                        counts[i]));
        OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
        TEST_CHECK_(eax == 0,
                    "count=%zu left EAX at 0x%08" PRIx32, counts[i], eax);
        OK(uc_close(uc));
    }
}

static void test_x86_adox_uses_current_static_lazy_op(void)
{
    const uint8_t code[] = {
        0x45, 0x31, 0xc0,                   /* xor r8d, r8d */
        0xb8, 0xff, 0xff, 0xff, 0xff,       /* mov eax, -1 */
        0x01, 0xc0,                         /* add eax, eax: CF=1, OF=0 */
        0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff, /* mov rcx, -1 */
        0xba, 0x01, 0x00, 0x00, 0x00,       /* mov edx, 1 */
        0xf3, 0x48, 0x0f, 0x38, 0xf6, 0xca, /* adox rcx, rdx */
        0x41, 0x0f, 0x90, 0xc0,             /* seto r8b */
    };
    uint64_t rcx = UINT64_MAX;
    uint64_t r8 = 0;
    uc_engine *uc;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    sizeof(code));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_reg_read(uc, UC_X86_REG_R8, &r8));
    TEST_CHECK_(rcx == 0 && r8 == 1,
                "ADOX used stale carry state: rcx=0x%016" PRIx64
                ", of=%" PRIu64,
                rcx, r8);
    OK(uc_close(uc));
}

static void test_x86_lahf_uses_current_static_lazy_op(void)
{
    const uint8_t code[] = {
        0xb8, 0x0f, 0x00, 0x00, 0x00,       /* mov eax, 0x0f */
        0x83, 0xc0, 0x01,                   /* add eax, 1: AF=1, PF=0 */
        0x9f,                               /* lahf */
        0x0f, 0xb6, 0xcc,                   /* movzx ecx, ah */
        0xb8, 0x10, 0x00, 0x00, 0x00,       /* mov eax, 0x10 */
        0x83, 0xe8, 0x01,                   /* sub eax, 1: AF=1, PF=1 */
        0x9f,                               /* lahf */
        0x0f, 0xb6, 0xd4,                   /* movzx edx, ah */
    };
    uint64_t rcx = 0;
    uint64_t rdx = 0;
    uc_engine *uc;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    sizeof(code));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_reg_read(uc, UC_X86_REG_RDX, &rdx));
    TEST_CHECK_(rcx == 0x12 && rdx == 0x16,
                "LAHF used stale lazy state: add=0x%02" PRIx64
                ", sub=0x%02" PRIx64,
                rcx, rdx);
    OK(uc_close(uc));
}

static void test_x86_lazy_jcc_keeps_prior_cmov_condition(void)
{
    const uint8_t code[] = {
        0xb8, 0x09, 0x00, 0x00, 0x00,       /* mov eax, 9 */
        0x31, 0xc9,                         /* xor ecx, ecx */
        0x41, 0x89, 0xc0,                   /* mov r8d, eax */
        0x41, 0xf7, 0xd8,                   /* neg r8d */
        0x45, 0x89, 0xc1,                   /* mov r9d, r8d */
        0x41, 0xc1, 0xf9, 0x1f,             /* sar r9d, 31 */
        0x41, 0x21, 0xc1,                   /* and r9d, eax */
        0x45, 0x85, 0xc0,                   /* test r8d, r8d */
        0x44, 0x0f, 0x4e, 0xc1,             /* cmovle r8d, ecx */
        0x45, 0x09, 0xc8,                   /* or r8d, r9d */
        0x31, 0xd2,                         /* xor edx, edx */
        0xff, 0xc2,                         /* inc edx */
        0x83, 0xfa, 0x01,                   /* cmp edx, 1 */
        0x75, 0xf9,                         /* jne -7 */
        0x44, 0x89, 0xc0,                   /* mov eax, r8d */
        0xc3,                               /* ret (not executed) */
    };
    uint32_t eax = 0;
    uc_engine *uc;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    sizeof(code));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    TEST_CHECK_(eax == 9,
                "lazy JCC corrupted an earlier CMOV result: 0x%08" PRIx32,
                eax);
    OK(uc_close(uc));
}

static void test_x86_masked_vector_memory_suppresses_faults(void)
{
    static const uint8_t mask_load_128[] = {
        0xc4, 0xe2, 0x71, 0x8c, 0x00, /* vpmaskmovd xmm0, xmm1, [rax] */
    };
    static const uint8_t mask_load[] = {
        0xc4, 0xe2, 0x75, 0x8c, 0x00, /* vpmaskmovd ymm0, ymm1, [rax] */
    };
    static const uint8_t mask_store[] = {
        0xc4, 0xe2, 0x75, 0x8e, 0x00, /* vpmaskmovd [rax], ymm1, ymm0 */
    };
    static const uint8_t gather[] = {
        0xc4, 0xe2, 0x75, 0x90, 0x04, 0x90,
        /* vpgatherdd ymm0, [rax + ymm2*4], ymm1 */
    };
    static const struct {
        const uint8_t *code;
        size_t size;
        bool zeros_destination;
    } cases[] = {
        {mask_load_128, sizeof(mask_load_128), true},
        {mask_load, sizeof(mask_load), true},
        {mask_store, sizeof(mask_store), false},
        {gather, sizeof(gather), false},
    };
    const uint64_t unmapped = UINT64_C(0x80000000);
    const uint32_t initial[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint32_t zero[8] = {0};

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint32_t result[8] = {0};
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[i].code, cases[i].size);
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &unmapped));
        OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
        OK(uc_reg_write(uc, UC_X86_REG_YMM1, zero));
        OK(uc_reg_write(uc, UC_X86_REG_YMM2, zero));

        OK(uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
        TEST_CHECK(memcmp(result, cases[i].zeros_destination ? zero : initial,
                          sizeof(result)) == 0);
        OK(uc_close(uc));
    }
}

static void test_x86_gather_fault_preserves_lane_progress(void)
{
    const uint8_t code[] = {
        0xc4, 0xe2, 0x75, 0x90, 0x04, 0x90,
        /* vpgatherdd ymm0, [rax + ymm2*4], ymm1 */
    };
    const uint64_t data_addr = UINT64_C(0x6000);
    const uint32_t first_value = 0x12345678;
    const uint32_t initial[8] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    };
    const uint32_t indices[8] = {0, 1024, 0, 0, 0, 0, 0, 0};
    const uint32_t mask[8] = {
        0x80000000U, 0x80000000U, 0x80000001U, 1, 0, 0, 0, 0,
    };
    uint32_t result[8] = {0};
    uint32_t mask_after[8] = {0};
    uc_engine *uc;
    uc_err err;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    OK(uc_mem_map(uc, data_addr, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, data_addr, &first_value, sizeof(first_value)));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &data_addr));
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, mask));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, indices));

    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    TEST_CHECK(err == UC_ERR_READ_UNMAPPED);
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
    OK(uc_reg_read(uc, UC_X86_REG_YMM1, mask_after));
    TEST_CHECK(result[0] == first_value);
    TEST_CHECK(result[1] == initial[1]);
    TEST_CHECK(mask_after[0] == 0);
    TEST_CHECK(mask_after[1] == UINT32_MAX);
    TEST_CHECK(mask_after[2] == UINT32_MAX);
    TEST_CHECK(mask_after[3] == 0);
    OK(uc_close(uc));
}

static void test_x86_masked_load_fault_preserves_destination(void)
{
    const uint8_t code[] = {
        0xc4, 0xe2, 0x75, 0x8c, 0x00, /* vpmaskmovd ymm0, ymm1, [rax] */
    };
    const uint64_t page = UINT64_C(0x6000);
    const uint64_t first_lane = page + 0xffc;
    const uint32_t memory_value = 0x12345678U;
    const uint32_t initial[8] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    };
    const uint32_t mask[8] = {
        0x80000000U, 0x80000000U, 0, 0, 0, 0, 0, 0,
    };
    uint32_t result[8] = {0};
    uc_engine *uc;
    uc_err err;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    OK(uc_mem_map(uc, page, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, first_lane, &memory_value, sizeof(memory_value)));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &first_lane));
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, mask));
    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    TEST_CHECK(err == UC_ERR_READ_UNMAPPED);
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
    TEST_CHECK(memcmp(result, initial, sizeof(result)) == 0);
    OK(uc_close(uc));
}

static void test_x86_avx_rejects_reserved_vex_w(void)
{
    static const uint8_t mask_ps_128[] = {
        0xc4, 0xe2, 0xf1, 0x2c, 0x00, /* reserved W1 vmaskmovps xmm */
    };
    static const uint8_t mask_ps_256[] = {
        0xc4, 0xe2, 0xf5, 0x2c, 0x00, /* reserved W1 vmaskmovps ymm */
    };
    static const uint8_t vpsravd_128[] = {
        0xc4, 0xe2, 0xf1, 0x46, 0xc2, /* reserved W1 vpsravd xmm */
    };
    static const uint8_t vpsravd_256[] = {
        0xc4, 0xe2, 0xf5, 0x46, 0xc2, /* reserved W1 vpsravd ymm */
    };
    static const uint8_t vpermd_256[] = {
        0xc4, 0xe2, 0xf5, 0x36, 0xc2, /* reserved W1 vpermd ymm */
    };
    static const uint8_t vpblendd_128[] = {
        0xc4, 0xe3, 0xf1, 0x02, 0xc2, 0x00,
    };
    static const uint8_t vpblendd_256[] = {
        0xc4, 0xe3, 0xf5, 0x02, 0xc2, 0x00,
    };
    static const uint8_t vpermq_w0[] = {
        0xc4, 0xe3, 0x7d, 0x00, 0xc1, 0x00,
    };
    static const uint8_t broadcast_128[] = {
        0xc4, 0xe2, 0xf1, 0x58, 0xc1,
    };
    static const uint8_t broadcast_256[] = {
        0xc4, 0xe2, 0xf5, 0x58, 0xc1,
    };
    static const struct {
        const uint8_t *code;
        size_t size;
    } cases[] = {
        {mask_ps_128, sizeof(mask_ps_128)},
        {mask_ps_256, sizeof(mask_ps_256)},
        {vpsravd_128, sizeof(vpsravd_128)},
        {vpsravd_256, sizeof(vpsravd_256)},
        {vpermd_256, sizeof(vpermd_256)},
        {vpblendd_128, sizeof(vpblendd_128)},
        {vpblendd_256, sizeof(vpblendd_256)},
        {vpermq_w0, sizeof(vpermq_w0)},
        {broadcast_128, sizeof(broadcast_128)},
        {broadcast_256, sizeof(broadcast_256)},
    };
    const uint64_t unmapped = UINT64_C(0x80000000);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[i].code, cases[i].size);
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &unmapped));
        uc_assert_err(UC_ERR_INSN_INVALID,
                      uc_emu_start(uc, code_start,
                                   code_start + cases[i].size, 0, 0));
        OK(uc_close(uc));
    }
}

static void test_x86_vtest_ymm_reduces_high_lane_flags(void)
{
    static const uint8_t vtestps_128[] = {
        0xc4, 0xe2, 0x78, 0x0e, 0xc1,
    };
    static const uint8_t vtestpd_128[] = {
        0xc4, 0xe2, 0x79, 0x0f, 0xc1,
    };
    static const uint8_t vptest[] = {
        0xc4, 0xe2, 0x7d, 0x17, 0xc1,
    };
    static const uint8_t vtestps[] = {
        0xc4, 0xe2, 0x7c, 0x0e, 0xc1,
    };
    static const uint8_t vtestpd[] = {
        0xc4, 0xe2, 0x7d, 0x0f, 0xc1,
    };
    static const struct {
        const uint8_t *code;
        size_t size;
        bool high_lane;
        unsigned element_bits;
    } cases[] = {
        {vtestps_128, sizeof(vtestps_128), false, 32},
        {vtestpd_128, sizeof(vtestpd_128), false, 64},
        {vptest, sizeof(vptest), true, 0},
        {vtestps, sizeof(vtestps), true, 32},
        {vtestpd, sizeof(vtestpd), true, 64},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t lhs[4] = {0};
        uint64_t rhs[4] = {0};
        uint64_t rflags = 0;
        uc_engine *uc;

        const size_t lane = cases[i].high_lane ? 2 : 0;
        const uint64_t tested_bit = cases[i].element_bits
                                        ? UINT64_C(1)
                                              << (cases[i].element_bits - 1)
                                        : UINT64_C(1);

        lhs[lane] = tested_bit;
        rhs[lane] = tested_bit;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[i].code, cases[i].size);
        OK(uc_reg_write(uc, UC_X86_REG_YMM0, lhs));
        OK(uc_reg_write(uc, UC_X86_REG_YMM1, rhs));
        OK(uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        TEST_CHECK((rflags & (UINT64_C(1) << 6)) == 0); /* ZF */
        TEST_CHECK((rflags & 1) != 0);                  /* CF */
        OK(uc_close(uc));

        lhs[lane] = 0;
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[i].code, cases[i].size);
        OK(uc_reg_write(uc, UC_X86_REG_YMM0, lhs));
        OK(uc_reg_write(uc, UC_X86_REG_YMM1, rhs));
        OK(uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        TEST_CHECK((rflags & (UINT64_C(1) << 6)) != 0); /* ZF */
        TEST_CHECK((rflags & 1) == 0);                  /* CF */
        OK(uc_close(uc));

        if (cases[i].element_bits) {
            /* VTESTPS/PD reduce only element sign bits.  Ordinary payload
             * bits must not affect either flag. */
            lhs[lane] = 1;
            rhs[lane] = 1;
            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                                cases[i].code, cases[i].size);
            OK(uc_reg_write(uc, UC_X86_REG_YMM0, lhs));
            OK(uc_reg_write(uc, UC_X86_REG_YMM1, rhs));
            OK(uc_emu_start(uc, code_start,
                            code_start + cases[i].size, 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
            TEST_CHECK((rflags & (UINT64_C(1) << 6)) != 0); /* ZF */
            TEST_CHECK((rflags & 1) != 0);                  /* CF */
            OK(uc_close(uc));
        }
    }
}

static void test_x86_broadcast_128_block_to_ymm(void)
{
    static const uint8_t vbroadcastf128[] = {
        0xc4, 0xe2, 0x7d, 0x1a, 0x00,
    };
    static const uint8_t vpbroadcasti128[] = {
        0xc4, 0xe2, 0x7d, 0x5a, 0x00,
    };
    static const struct {
        const uint8_t *code;
        size_t size;
    } cases[] = {
        {vbroadcastf128, sizeof(vbroadcastf128)},
        {vpbroadcasti128, sizeof(vpbroadcasti128)},
    };
    const uint64_t data_addr = code_start + 0x400;
    const uint32_t source[4] = {
        0x01020304U, 0x11121314U, 0x21222324U, 0x31323334U,
    };
    const uint32_t expected[8] = {
        0x01020304U, 0x11121314U, 0x21222324U, 0x31323334U,
        0x01020304U, 0x11121314U, 0x21222324U, 0x31323334U,
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint32_t result[8] = {0};
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[i].code, cases[i].size);
        OK(uc_mem_write(uc, data_addr, source, sizeof(source)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &data_addr));
        OK(uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
        TEST_CHECK(memcmp(result, expected, sizeof(result)) == 0);
        OK(uc_close(uc));
    }
}

static void test_x86_vpermil_immediate_ymm(void)
{
    static const uint8_t vpermilps_128[] = {
        0xc4, 0xe3, 0x79, 0x04, 0xc1, 0x1b,
    };
    static const uint8_t vpermilps[] = {
        0xc4, 0xe3, 0x7d, 0x04, 0xc1, 0x1b,
    };
    static const uint8_t vpermilpd[] = {
        0xc4, 0xe3, 0x7d, 0x05, 0xc1, 0x05,
    };
    const uint32_t ps_source[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    const uint32_t ps_expected_128[8] = {3, 2, 1, 0, 0, 0, 0, 0};
    const uint32_t ps_expected[8] = {3, 2, 1, 0, 7, 6, 5, 4};
    const uint64_t pd_source[4] = {10, 11, 12, 13};
    const uint64_t pd_expected[4] = {11, 10, 13, 12};
    uint64_t result[4] = {0};
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, vpermilps_128,
                        sizeof(vpermilps_128));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ps_source));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(vpermilps_128), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
    TEST_CHECK(memcmp(result, ps_expected_128, sizeof(result)) == 0);
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, vpermilps,
                        sizeof(vpermilps));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ps_source));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(vpermilps), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
    TEST_CHECK(memcmp(result, ps_expected, sizeof(result)) == 0);
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, vpermilpd,
                        sizeof(vpermilpd));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, pd_source));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(vpermilpd), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
    TEST_CHECK(memcmp(result, pd_expected, sizeof(result)) == 0);
    OK(uc_close(uc));
}

static void test_x86_avx_requires_enabled_state_and_features(void)
{
    static const uint8_t xsetbv[] = {0x0f, 0x01, 0xd1};
    static const uint8_t vmovups[] = {0xc5, 0xf8, 0x10, 0xc1};
    static const uint8_t disable_ymm_then_avx[] = {
        0x31, 0xc9,                         /* xor ecx, ecx */
        0xb8, 0x01, 0x00, 0x00, 0x00,       /* mov eax, XSTATE_FP */
        0x31, 0xd2,                         /* xor edx, edx */
        0x0f, 0x01, 0xd1,                   /* xsetbv */
        0xc5, 0xf8, 0x10, 0xc1,             /* vmovups xmm0, xmm1 */
    };
    static const uint8_t disable_ymm_then_pdep[] = {
        0x31, 0xc9,
        0xb8, 0x01, 0x00, 0x00, 0x00,
        0x31, 0xd2,
        0x0f, 0x01, 0xd1,
        0xbb, 0xff, 0x00, 0x00, 0x00,       /* mov ebx, 0xff */
        0xb9, 0x00, 0xff, 0x00, 0x00,       /* mov ecx, 0xff00 */
        0xc4, 0xe2, 0x63, 0xf5, 0xc1,       /* pdep eax, ebx, ecx */
    };
    static const uint8_t vpsravd_128[] = {
        0xc4, 0xe2, 0x71, 0x46, 0xc2,
    };
    static const uint8_t vpsravd_256[] = {
        0xc4, 0xe2, 0x75, 0x46, 0xc2,
    };
    static const uint8_t vpxor_256[] = {
        0xc5, 0xf5, 0xef, 0xc2,
    };
    static const uint8_t vpshufb_256[] = {
        0xc4, 0xe2, 0x75, 0x00, 0xc2,
    };
    static const uint8_t vpalignr_256[] = {
        0xc4, 0xe3, 0x75, 0x0f, 0xc2, 0x01,
    };
    static const uint8_t vpmovmskb_256[] = {
        0xc5, 0xfd, 0xd7, 0xc1,
    };
    static const uint8_t vpblendd_128[] = {
        0xc4, 0xe3, 0x71, 0x02, 0xc2, 0x00,
    };
    static const uint8_t vmovntdqa_256[] = {
        0xc4, 0xe2, 0x7d, 0x2a, 0x00,
    };
    static const uint8_t vbroadcastss_128_reg[] = {
        0xc4, 0xe2, 0x79, 0x18, 0xc1,
    };
    static const uint8_t vbroadcastss_256_reg[] = {
        0xc4, 0xe2, 0x7d, 0x18, 0xc1,
    };
    static const uint8_t vbroadcastsd_256_reg[] = {
        0xc4, 0xe2, 0x7d, 0x19, 0xc1,
    };
    static const uint8_t vaddps_256[] = {
        0xc5, 0xf4, 0x58, 0xc2,
    };
    uint32_t eax = 5; /* X87 and YMM enabled, SSE disabled. */
    uint32_t ecx = 0;
    uint32_t edx = 0;
    uint64_t cr4 = 0;
    uint64_t rip = 0;
    uc_engine *uc;
    uc_err err;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, xsetbv,
                        sizeof(xsetbv));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
    err = uc_emu_start(uc, code_start, code_start + sizeof(xsetbv), 0, 0);
    TEST_CHECK(err == UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    TEST_CHECK(rip == code_start);
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_WESTMERE, vmovups,
                        sizeof(vmovups));
    uc_assert_err(UC_ERR_INSN_INVALID,
                  uc_emu_start(uc, code_start,
                               code_start + sizeof(vmovups), 0, 0));
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, vmovups,
                        sizeof(vmovups));
    OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
    cr4 &= ~(UINT64_C(1) << 18); /* CR4.OSXSAVE */
    OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));
    uc_assert_err(UC_ERR_INSN_INVALID,
                  uc_emu_start(uc, code_start,
                               code_start + sizeof(vmovups), 0, 0));
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                        disable_ymm_then_avx, sizeof(disable_ymm_then_avx));
    uc_assert_err(UC_ERR_INSN_INVALID,
                  uc_emu_start(uc, code_start,
                               code_start + sizeof(disable_ymm_then_avx), 0,
                               0));
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                        disable_ymm_then_pdep, sizeof(disable_ymm_then_pdep));
    OK(uc_emu_start(uc, code_start,
                    code_start + sizeof(disable_ymm_then_pdep), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    TEST_CHECK(eax == 0xff00);
    OK(uc_close(uc));

    {
        static const struct {
            const uint8_t *code;
            size_t size;
        } avx2_cases[] = {
            {vpsravd_128, sizeof(vpsravd_128)},
            {vpsravd_256, sizeof(vpsravd_256)},
            {vpxor_256, sizeof(vpxor_256)},
            {vpshufb_256, sizeof(vpshufb_256)},
            {vpalignr_256, sizeof(vpalignr_256)},
            {vpmovmskb_256, sizeof(vpmovmskb_256)},
            {vpblendd_128, sizeof(vpblendd_128)},
            {vmovntdqa_256, sizeof(vmovntdqa_256)},
            {vbroadcastss_128_reg, sizeof(vbroadcastss_128_reg)},
            {vbroadcastss_256_reg, sizeof(vbroadcastss_256_reg)},
            {vbroadcastsd_256_reg, sizeof(vbroadcastsd_256_reg)},
        };

        for (size_t i = 0; i < sizeof(avx2_cases) / sizeof(avx2_cases[0]); ++i) {
            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_SANDYBRIDGE,
                                avx2_cases[i].code, avx2_cases[i].size);
            uc_assert_err(UC_ERR_INSN_INVALID,
                          uc_emu_start(uc, code_start,
                                       code_start + avx2_cases[i].size, 0, 0));
            OK(uc_close(uc));
        }
    }

    /* Sandy Bridge has AVX but not AVX2: a floating-point YMM operation must
     * remain valid while the integer YMM forms above raise #UD. */
    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_SANDYBRIDGE,
                        vaddps_256, sizeof(vaddps_256));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(vaddps_256), 0, 0));
    OK(uc_close(uc));
}

static void test_x86_vpblendvb_xmm_requires_only_avx(void)
{
    static const uint8_t code[] = {
        0xc4, 0xe3, 0x71, 0x4c, 0xc2, 0x30,
    };
    uint8_t src1[16];
    uint8_t src2[16];
    uint8_t mask[16];
    uint8_t expected[16];
    uint8_t result[16] = {0};
    uc_engine *uc;

    for (int i = 0; i < 16; i++) {
        src1[i] = (uint8_t)(0x10 + i);
        src2[i] = (uint8_t)(0x80 + i);
        mask[i] = (i & 1) ? 0x80 : 0;
        expected[i] = (i & 1) ? src2[i] : src1[i];
    }

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_SANDYBRIDGE, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, src1));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, src2));
    OK(uc_reg_write(uc, UC_X86_REG_XMM3, mask));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, result));
    TEST_CHECK(memcmp(result, expected, sizeof(result)) == 0);
    OK(uc_close(uc));
}

static void test_x86_vex_rejects_reserved_fields_and_missing_prefixes(void)
{
    static const uint8_t missing_pp_vpunpcklbw_128[] = {
        0xc5, 0xf8, 0x60, 0xc1,
    };
    static const uint8_t missing_pp_vpunpcklbw[] = {
        0xc5, 0xfc, 0x60, 0xc1,
    };
    static const uint8_t missing_pp_vpshufd[] = {
        0xc5, 0xfc, 0x70, 0xc1, 0x00,
    };
    static const uint8_t missing_pp_vpsravd[] = {
        0xc4, 0xe2, 0x74, 0x46, 0xc2,
    };
    static const uint8_t missing_pp_vpblendd[] = {
        0xc4, 0xe3, 0x74, 0x02, 0xc2, 0x00,
    };
    static const uint8_t missing_pp_vpshufb_128[] = {
        0xc4, 0xe2, 0x78, 0x00, 0xc1,
    };
    static const uint8_t missing_pp_vpalignr_128[] = {
        0xc4, 0xe3, 0x70, 0x0f, 0xc2, 0x01,
    };
    static const uint8_t bad_vvvv_vmovups_128[] = {
        0xc5, 0xf0, 0x10, 0xc1,
    };
    static const uint8_t bad_vvvv_vmovups_256[] = {
        0xc5, 0xf4, 0x10, 0xc1,
    };
    static const uint8_t memory_vmovmskps_128[] = {
        0xc5, 0xf8, 0x50, 0x00,
    };
    static const uint8_t memory_vmovmskps_256[] = {
        0xc5, 0xfc, 0x50, 0x00,
    };
    static const uint8_t memory_vpmovmskb_256[] = {
        0xc5, 0xfd, 0xd7, 0x00,
    };
    static const uint8_t bad_vvvv_vmovntdqa_256[] = {
        0xc4, 0xe2, 0x75, 0x2a, 0x00,
    };
    static const uint8_t register_vmovntdqa_256[] = {
        0xc4, 0xe2, 0x7d, 0x2a, 0xc1,
    };
    static const uint8_t bad_vvvv_vmovntps_128[] = {
        0xc5, 0xf0, 0x2b, 0x00,
    };
    static const uint8_t bad_vvvv_vmovntpd_128[] = {
        0xc5, 0xf1, 0x2b, 0x00,
    };
    static const uint8_t bad_vvvv_vmovntdq_128[] = {
        0xc5, 0xf1, 0xe7, 0x00,
    };
    static const uint8_t bad_vvvv_vmovss_memory[] = {
        0xc5, 0xf2, 0x10, 0x00,
    };
    static const uint8_t bad_vvvv_vmovsd_memory[] = {
        0xc5, 0xf3, 0x10, 0x00,
    };
    static const struct {
        const uint8_t *code;
        size_t size;
    } cases[] = {
        {missing_pp_vpunpcklbw_128, sizeof(missing_pp_vpunpcklbw_128)},
        {missing_pp_vpunpcklbw, sizeof(missing_pp_vpunpcklbw)},
        {missing_pp_vpshufd, sizeof(missing_pp_vpshufd)},
        {missing_pp_vpsravd, sizeof(missing_pp_vpsravd)},
        {missing_pp_vpblendd, sizeof(missing_pp_vpblendd)},
        {missing_pp_vpshufb_128, sizeof(missing_pp_vpshufb_128)},
        {missing_pp_vpalignr_128, sizeof(missing_pp_vpalignr_128)},
        {bad_vvvv_vmovups_128, sizeof(bad_vvvv_vmovups_128)},
        {bad_vvvv_vmovups_256, sizeof(bad_vvvv_vmovups_256)},
        {memory_vmovmskps_128, sizeof(memory_vmovmskps_128)},
        {memory_vmovmskps_256, sizeof(memory_vmovmskps_256)},
        {memory_vpmovmskb_256, sizeof(memory_vpmovmskb_256)},
        {bad_vvvv_vmovntdqa_256, sizeof(bad_vvvv_vmovntdqa_256)},
        {register_vmovntdqa_256, sizeof(register_vmovntdqa_256)},
        {bad_vvvv_vmovntps_128, sizeof(bad_vvvv_vmovntps_128)},
        {bad_vvvv_vmovntpd_128, sizeof(bad_vvvv_vmovntpd_128)},
        {bad_vvvv_vmovntdq_128, sizeof(bad_vvvv_vmovntdq_128)},
        {bad_vvvv_vmovss_memory, sizeof(bad_vvvv_vmovss_memory)},
        {bad_vvvv_vmovsd_memory, sizeof(bad_vvvv_vmovsd_memory)},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint64_t rip = 0;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[i].code, cases[i].size);
        uc_assert_err(UC_ERR_INSN_INVALID,
                      uc_emu_start(uc, code_start,
                                   code_start + cases[i].size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }
}

static void test_x86_vmovntdqa_requires_vector_alignment(void)
{
    static const uint8_t ymm_code[] = {
        0xc4, 0xe2, 0x7d, 0x2a, 0x00,
    };
    static const uint8_t xmm_code[] = {
        0xc4, 0xe2, 0x79, 0x2a, 0x00,
    };
    static const uint8_t legacy_code[] = {
        0x66, 0x0f, 0x38, 0x2a, 0x00,
    };
    static const uint32_t source[8] = {
        0x01020304U, 0x11121314U, 0x21222324U, 0x31323334U,
        0x41424344U, 0x51525354U, 0x61626364U, 0x71727374U,
    };
    const uint64_t data_addr = code_start + 0x400;
    uint32_t result[8] = {0};
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, ymm_code,
                        sizeof(ymm_code));
    OK(uc_mem_write(uc, data_addr, source, sizeof(source)));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &data_addr));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(ymm_code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
    TEST_CHECK(memcmp(result, source, sizeof(result)) == 0);
    OK(uc_close(uc));

    {
        const uint64_t misaligned_xmm = code_start + 0x401;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, xmm_code,
                            sizeof(xmm_code));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &misaligned_xmm));
        err = uc_emu_start(uc, code_start,
                           code_start + sizeof(xmm_code), 0, 0);
        TEST_CHECK(err == UC_ERR_EXCEPTION);
        OK(uc_close(uc));

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            legacy_code, sizeof(legacy_code));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &misaligned_xmm));
        err = uc_emu_start(uc, code_start,
                           code_start + sizeof(legacy_code), 0, 0);
        TEST_CHECK(err == UC_ERR_EXCEPTION);
        OK(uc_close(uc));
    }

    {
        /* 16-byte aligned but not 32-byte aligned. */
        const uint64_t misaligned_ymm = code_start + 0x410;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, ymm_code,
                            sizeof(ymm_code));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &misaligned_ymm));
        err = uc_emu_start(uc, code_start,
                           code_start + sizeof(ymm_code), 0, 0);
        TEST_CHECK(err == UC_ERR_EXCEPTION);
        OK(uc_close(uc));
    }
}

static void test_x86_vlddqu_vector_lengths_and_reserved_vvvv(void)
{
    static const uint8_t code[] = {
        0xc5, 0xfb, 0xf0, 0x00, /* vlddqu xmm0, [rax] */
        0xc5, 0xff, 0xf0, 0x0b, /* vlddqu ymm1, [rbx] */
    };
    static const uint8_t bad_vvvv_128[] = {
        0xc5, 0xf3, 0xf0, 0x00,
    };
    static const uint8_t bad_vvvv_256[] = {
        0xc5, 0xf7, 0xf0, 0x00,
    };
    uint8_t source[48];
    uint8_t initial[32];
    uint8_t xmm_result[32] = {0};
    uint8_t ymm_result[32] = {0};
    const uint64_t xmm_addr = code_start + 0x401;
    const uint64_t ymm_addr = code_start + 0x421;
    uc_engine *uc;

    for (size_t i = 0; i < sizeof(source); ++i)
        source[i] = (uint8_t)(0x20 + i);
    memset(initial, 0xa5, sizeof(initial));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    OK(uc_mem_write(uc, xmm_addr, source, sizeof(source)));
    OK(uc_mem_write(uc, ymm_addr, source + 16, 32));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &xmm_addr));
    OK(uc_reg_write(uc, UC_X86_REG_RBX, &ymm_addr));
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, xmm_result));
    OK(uc_reg_read(uc, UC_X86_REG_YMM1, ymm_result));
    TEST_CHECK(memcmp(xmm_result, source, 16) == 0);
    TEST_CHECK(memcmp(xmm_result + 16, (uint8_t[16]){0}, 16) == 0);
    TEST_CHECK(memcmp(ymm_result, source + 16, 32) == 0);
    OK(uc_close(uc));

    {
        static const struct {
            const uint8_t *code;
            size_t size;
        } cases[] = {
            {bad_vvvv_128, sizeof(bad_vvvv_128)},
            {bad_vvvv_256, sizeof(bad_vvvv_256)},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint64_t rip = 0;

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                                cases[i].code, cases[i].size);
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &xmm_addr));
            uc_assert_err(UC_ERR_INSN_INVALID,
                          uc_emu_start(uc, code_start,
                                       code_start + cases[i].size, 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK(rip == code_start);
            OK(uc_close(uc));
        }
    }
}

static void test_x86_vmovnt_ymm_stores_require_alignment_and_features(void)
{
    static const uint8_t vmovntps[] = {0xc5, 0xfc, 0x2b, 0x00};
    static const uint8_t vmovntdq[] = {0xc5, 0xfd, 0xe7, 0x00};
    static const uint8_t bad_vvvv_vmovntps[] = {0xc5, 0xf4, 0x2b, 0x00};
    static const uint8_t bad_vvvv_vmovntdq[] = {0xc5, 0xf5, 0xe7, 0x00};
    static const uint8_t register_vmovntps[] = {0xc5, 0xfc, 0x2b, 0xc0};
    static const uint8_t register_vmovntdq[] = {0xc5, 0xfd, 0xe7, 0xc0};
    static const uint32_t source[8] = {
        0x01020304U, 0x11121314U, 0x21222324U, 0x31323334U,
        0x41424344U, 0x51525354U, 0x61626364U, 0x71727374U,
    };
    const uint64_t aligned = code_start + 0x400;
    const uint64_t misaligned = code_start + 0x410;
    uc_engine *uc;

    {
        static const struct {
            const uint8_t *code;
            size_t size;
            int cpu;
        } cases[] = {
            {vmovntps, sizeof(vmovntps), UC_CPU_X86_SANDYBRIDGE},
            {vmovntdq, sizeof(vmovntdq), UC_CPU_X86_HASWELL},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint32_t result[8] = {0};

            uc_common_setup_cpu(&uc, UC_MODE_64, cases[i].cpu,
                                cases[i].code, cases[i].size);
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &aligned));
            OK(uc_reg_write(uc, UC_X86_REG_YMM0, source));
            OK(uc_emu_start(uc, code_start,
                            code_start + cases[i].size, 0, 0));
            OK(uc_mem_read(uc, aligned, result, sizeof(result)));
            TEST_CHECK(memcmp(result, source, sizeof(result)) == 0);
            OK(uc_close(uc));
        }
    }

    {
        static const struct {
            const uint8_t *code;
            size_t size;
        } cases[] = {
            {vmovntps, sizeof(vmovntps)},
            {vmovntdq, sizeof(vmovntdq)},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uc_err err;

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                                cases[i].code, cases[i].size);
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &misaligned));
            OK(uc_reg_write(uc, UC_X86_REG_YMM0, source));
            err = uc_emu_start(uc, code_start,
                               code_start + cases[i].size, 0, 0);
            TEST_CHECK(err == UC_ERR_EXCEPTION);
            OK(uc_close(uc));
        }
    }

    {
        static const struct {
            const uint8_t *code;
            size_t size;
        } cases[] = {
            {bad_vvvv_vmovntps, sizeof(bad_vvvv_vmovntps)},
            {bad_vvvv_vmovntdq, sizeof(bad_vvvv_vmovntdq)},
            {register_vmovntps, sizeof(register_vmovntps)},
            {register_vmovntdq, sizeof(register_vmovntdq)},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                                cases[i].code, cases[i].size);
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &aligned));
            uc_assert_err(UC_ERR_INSN_INVALID,
                          uc_emu_start(uc, code_start,
                                       code_start + cases[i].size, 0, 0));
            OK(uc_close(uc));
        }
    }

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_SANDYBRIDGE,
                        vmovntdq, sizeof(vmovntdq));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &aligned));
    uc_assert_err(UC_ERR_INSN_INVALID,
                  uc_emu_start(uc, code_start,
                               code_start + sizeof(vmovntdq), 0, 0));
    OK(uc_close(uc));
}

static void test_x86_broadcast_operand_form_feature_gates(void)
{
    static const uint8_t mem_ss_128[] = {
        0xc4, 0xe2, 0x79, 0x18, 0x00,
    };
    static const uint8_t mem_ss_256[] = {
        0xc4, 0xe2, 0x7d, 0x18, 0x00,
    };
    static const uint8_t mem_sd_256[] = {
        0xc4, 0xe2, 0x7d, 0x19, 0x00,
    };
    static const uint8_t reg_ss_128[] = {
        0xc4, 0xe2, 0x79, 0x18, 0xc1,
    };
    static const uint8_t reg_ss_256[] = {
        0xc4, 0xe2, 0x7d, 0x18, 0xc1,
    };
    static const uint8_t reg_sd_256[] = {
        0xc4, 0xe2, 0x7d, 0x19, 0xc1,
    };
    static const struct {
        const uint8_t *code;
        size_t size;
        int cpu_model;
        bool memory_source;
        uint64_t expected[4];
    } cases[] = {
        {mem_ss_128, sizeof(mem_ss_128), UC_CPU_X86_SANDYBRIDGE, true,
         {UINT64_C(0x89abcdef89abcdef), UINT64_C(0x89abcdef89abcdef), 0, 0}},
        {mem_ss_256, sizeof(mem_ss_256), UC_CPU_X86_SANDYBRIDGE, true,
         {UINT64_C(0x89abcdef89abcdef), UINT64_C(0x89abcdef89abcdef),
          UINT64_C(0x89abcdef89abcdef), UINT64_C(0x89abcdef89abcdef)}},
        {mem_sd_256, sizeof(mem_sd_256), UC_CPU_X86_SANDYBRIDGE, true,
         {UINT64_C(0x0123456789abcdef), UINT64_C(0x0123456789abcdef),
          UINT64_C(0x0123456789abcdef), UINT64_C(0x0123456789abcdef)}},
        {reg_ss_128, sizeof(reg_ss_128), UC_CPU_X86_HASWELL, false,
         {UINT64_C(0x89abcdef89abcdef), UINT64_C(0x89abcdef89abcdef), 0, 0}},
        {reg_ss_256, sizeof(reg_ss_256), UC_CPU_X86_HASWELL, false,
         {UINT64_C(0x89abcdef89abcdef), UINT64_C(0x89abcdef89abcdef),
          UINT64_C(0x89abcdef89abcdef), UINT64_C(0x89abcdef89abcdef)}},
        {reg_sd_256, sizeof(reg_sd_256), UC_CPU_X86_HASWELL, false,
         {UINT64_C(0x0123456789abcdef), UINT64_C(0x0123456789abcdef),
          UINT64_C(0x0123456789abcdef), UINT64_C(0x0123456789abcdef)}},
    };
    const uint64_t source[2] = {
        UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210),
    };
    const uint64_t data_addr = code_start + 0x400;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint64_t result[4] = {0};
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, cases[i].cpu_model,
                            cases[i].code, cases[i].size);
        if (cases[i].memory_source) {
            OK(uc_mem_write(uc, data_addr, source, sizeof(source)));
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &data_addr));
        } else {
            OK(uc_reg_write(uc, UC_X86_REG_XMM1, source));
        }
        OK(uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
        TEST_CHECK(memcmp(result, cases[i].expected, sizeof(result)) == 0);
        OK(uc_close(uc));
    }
}

static void test_x86_vpclmulqdq_ymm_uses_independent_lanes(void)
{
    /* vpclmulqdq ymm2, ymm1, ymm2, 0x11: dst aliases src2 deliberately. */
    static const uint8_t code[] = {
        0xc4, 0xe3, 0x75, 0x44, 0xd2, 0x11,
    };
    static const uint64_t src1[4] = {0, 3, 0, 5};
    static const uint64_t src2[4] = {0, 7, 0, 9};
    static const uint64_t expected[4] = {9, 0, 45, 0};
    uint64_t result[4] = {0};
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_CLIENT, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, src1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, src2));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM2, result));
    TEST_CHECK(memcmp(result, expected, sizeof(result)) == 0);
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    uc_assert_err(UC_ERR_INSN_INVALID,
                  uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_close(uc));
}

static void test_x86_icebp_reports_trap_rip(void)
{
    const uint8_t code[] = {0xf1}; /* icebp */
    uint64_t rip = 0;
    uint64_t rflags = UINT64_C(0x10002); /* RF plus the fixed bit. */
    uc_engine *uc;
    uc_err err;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    TEST_CHECK(err == UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
    TEST_CHECK(rip == code_start + sizeof(code));
    TEST_CHECK((rflags & (UINT64_C(1) << 16)) == 0); /* RF */
    OK(uc_close(uc));
}

static void test_x86_movbe_crc32_use_16bit_default_width(void)
{
    static const uint8_t movbe_load[] = {
        0x67, 0x0f, 0x38, 0xf0, 0x02, /* movbe ax, [edx] */
    };
    static const uint8_t movbe_store[] = {
        0x67, 0x0f, 0x38, 0xf1, 0x02, /* movbe [edx], ax */
    };
    static const uint8_t crc32[] = {
        0x67, 0xf2, 0x0f, 0x38, 0xf1, 0x02, /* crc32 ax, word [edx] */
    };
    static const struct {
        const uint8_t *code;
        size_t size;
        bool is_store;
    } cases[] = {
        {movbe_load, sizeof(movbe_load), false},
        {movbe_store, sizeof(movbe_store), true},
        {crc32, sizeof(crc32), false},
    };
    const uint64_t data_page = UINT64_C(0x7000);
    const uint32_t edx = 0x7ffe;
    const uint32_t eax = 0x1234;
    const uint8_t input[2] = {0x12, 0x34};

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t output[2] = {0};
        uc_engine *uc;

        OK(uc_open(UC_ARCH_X86, UC_MODE_16, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
        OK(uc_mem_map(uc, code_start, 0x1000, UC_PROT_ALL));
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, cases[i].code, cases[i].size));
        OK(uc_mem_write(uc, edx, input, sizeof(input)));
        OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
        OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
        OK(uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0));
        if (cases[i].is_store) {
            OK(uc_mem_read(uc, edx, output, sizeof(output)));
            TEST_CHECK(memcmp(output, input, sizeof(output)) == 0);
        }
        OK(uc_close(uc));
    }
}

static void test_x86_movbe_rejects_register_encoding(void)
{
    const uint8_t code[] = {
        0x0f, 0x38, 0xf0, 0xc0, /* reserved register form of movbe eax, eax */
    };
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    uc_assert_err(UC_ERR_INSN_INVALID,
                  uc_emu_start(uc, code_start, code_start + sizeof(code), 0,
                               0));
    OK(uc_close(uc));
}

static void test_x86_popcnt_rex_w_overrides_data16(void)
{
    const uint8_t code[] = {
        0x66, 0xf3, 0x48, 0x0f, 0xb8, 0xc1, /* popcnt rax, rcx */
    };
    const uint64_t rcx = UINT64_C(0xffff000000000001);
    uint64_t rax = 0;
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    TEST_CHECK(rax == 17);
    OK(uc_close(uc));
}

static void test_x86_mxcsr_ftz_applies_to_sse(void)
{
    const uint8_t code[] = {
        0x0f, 0xae, 0x10,       /* ldmxcsr [rax] */
        0xf3, 0x0f, 0x59, 0xc1, /* mulss xmm0, xmm1 */
    };
    const uint64_t mxcsr_addr = code_start + 0x200;
    const uint32_t mxcsr = 0x9f80; /* Default masks with flush-to-zero. */
    const uint32_t lhs[4] = {0x00800000U, 0, 0, 0}; /* Smallest normal. */
    const uint32_t rhs[4] = {0x3f000000U, 0, 0, 0}; /* 0.5f. */
    uint32_t result[4] = {0};
    uc_engine *uc;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    sizeof(code));
    OK(uc_mem_write(uc, mxcsr_addr, &mxcsr, sizeof(mxcsr)));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &mxcsr_addr));
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, lhs));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, rhs));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, result));
    TEST_CHECK(result[0] == 0);
    OK(uc_close(uc));
}

typedef struct TestX86RoundMemoryRead {
    uint64_t expected_address;
    int expected_size;
    unsigned count;
} TestX86RoundMemoryRead;

static void test_x86_round_memory_read_callback(uc_engine *uc,
                                                uc_mem_type type,
                                                uint64_t address, int size,
                                                int64_t value,
                                                void *user_data)
{
    TestX86RoundMemoryRead *record = user_data;

    (void)uc;
    (void)value;
    TEST_CHECK(type == UC_MEM_READ);
    TEST_CHECK(address == record->expected_address);
    TEST_CHECK(size == record->expected_size);
    record->count++;
}

static void test_x86_round_scalar_memory_access_width(void)
{
    static const uint8_t roundss[] = {
        0x66, 0x0f, 0x3a, 0x0a, 0x00, 0x00,
        /* roundss xmm0, dword ptr [rax], 0 */
    };
    static const uint8_t roundsd[] = {
        0x66, 0x0f, 0x3a, 0x0b, 0x00, 0x00,
        /* roundsd xmm0, qword ptr [rax], 0 */
    };
    static const uint8_t vroundss[] = {
        0xc4, 0xe3, 0x71, 0x0a, 0x00, 0x00,
        /* vroundss xmm0, xmm1, dword ptr [rax], 0 */
    };
    static const uint8_t vroundsd[] = {
        0xc4, 0xe3, 0x71, 0x0b, 0x00, 0x00,
        /* vroundsd xmm0, xmm1, qword ptr [rax], 0 */
    };
    /* NeverD correction, 2026-10-04: the unaligned packed control must
     * use VEX; legacy ROUNDPS raises #GP before the missing-page access. */
#define UC_DECODE_ROUND(Name, ...) static const uint8_t Name[] = {__VA_ARGS__};
#include "x86_decode_boundaries.def"
#undef UC_DECODE_ROUND
    static const struct {
        const uint8_t *code;
        size_t size;
        int memory_size;
        bool vex;
    } scalar_cases[] = {
        {roundss, sizeof(roundss), 4, false},
        {roundsd, sizeof(roundsd), 8, false},
        {vroundss, sizeof(vroundss), 4, true},
        {vroundsd, sizeof(vroundsd), 8, true},
    };
    const uint64_t data_page = UINT64_C(0x6000);
    const uint32_t single_input = UINT32_C(0x3fe00000); /* 1.75f */
    const uint64_t double_input = UINT64_C(0x3ffc000000000000); /* 1.75 */
    const uint64_t initial[4] = {
        UINT64_C(0xdeadbeef11223344), UINT64_C(0x5566778899aabbcc),
        UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210),
    };
    const uint64_t vex_src1[4] = {
        UINT64_C(0xaabbccdd10203040), UINT64_C(0x5060708090a0b0c0),
        UINT64_C(0x1111111122222222), UINT64_C(0x3333333344444444),
    };

    for (size_t i = 0; i < sizeof(scalar_cases) / sizeof(scalar_cases[0]);
         ++i) {
        const uint64_t data_address =
            data_page + 0x1000 - scalar_cases[i].memory_size;
        TestX86RoundMemoryRead record = {
            data_address, scalar_cases[i].memory_size, 0,
        };
        uint64_t expected[4];
        uint64_t result[4] = {0};
        uc_engine *uc;
        uc_hook hook;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            scalar_cases[i].code, scalar_cases[i].size);
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_ALL));
        if (scalar_cases[i].memory_size == 4) {
            OK(uc_mem_write(uc, data_address, &single_input,
                            sizeof(single_input)));
        } else {
            OK(uc_mem_write(uc, data_address, &double_input,
                            sizeof(double_input)));
        }
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &data_address));
        OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
        OK(uc_reg_write(uc, UC_X86_REG_YMM1, vex_src1));
        OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_READ,
                       test_x86_round_memory_read_callback, &record,
                       data_address,
                       data_address + scalar_cases[i].memory_size - 1));

        OK(uc_emu_start(uc, code_start,
                        code_start + scalar_cases[i].size, 0, 0));
        TEST_CHECK(record.count == 1);
        OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));

        memcpy(expected, scalar_cases[i].vex ? vex_src1 : initial,
               sizeof(expected));
        if (scalar_cases[i].memory_size == 4) {
            expected[0] = (expected[0] & UINT64_C(0xffffffff00000000)) |
                          UINT64_C(0x40000000);
        } else {
            expected[0] = UINT64_C(0x4000000000000000);
        }
        if (scalar_cases[i].vex) {
            expected[2] = 0;
            expected[3] = 0;
        }
        TEST_CHECK(memcmp(result, expected, sizeof(result)) == 0);
        OK(uc_hook_del(uc, hook));
        OK(uc_close(uc));
    }

    {
        const uint64_t data_address = data_page + 0xffc;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, VRoundPS,
                            sizeof(VRoundPS));
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_ALL));
        OK(uc_mem_write(uc, data_address, &single_input,
                        sizeof(single_input)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &data_address));
        uc_assert_err(UC_ERR_READ_UNMAPPED,
                      uc_emu_start(uc, code_start,
                                   code_start + sizeof(VRoundPS), 0, 0));
        OK(uc_close(uc));
    }
}

static void test_x86_ldmxcsr_rejects_reserved_bits(void)
{
    const uint8_t code[] = {0x0f, 0xae, 0x10}; /* ldmxcsr [rax] */
    const uint64_t mxcsr_addr = code_start + 0x200;
    const uint32_t invalid_mxcsr = 0x00010000;
    const uint32_t initial_mxcsr = 0x00001f80;
    const uint16_t restored_fpcw = 0x027f;
    const uint16_t initial_fpcw = 0x037f;
    uint32_t mxcsr_after = 0;
    uint16_t fpcw_after = 0;
    uint64_t rip = 0;
    uc_engine *uc;
    uc_err err;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    sizeof(code));
    OK(uc_mem_write(uc, mxcsr_addr, &invalid_mxcsr, sizeof(invalid_mxcsr)));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &mxcsr_addr));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &initial_mxcsr));
    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    TEST_CHECK(err == UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr_after));
    TEST_CHECK(rip == code_start);
    TEST_CHECK(mxcsr_after == initial_mxcsr);
    OK(uc_close(uc));

    {
        const uint8_t fxrstor[] = {0x0f, 0xae, 0x08}; /* fxrstor [rax] */
        uint8_t fxstate[512] = {0};

        memcpy(fxstate, &restored_fpcw, sizeof(restored_fpcw));
        memcpy(fxstate + 24, &invalid_mxcsr, sizeof(invalid_mxcsr));
        rip = 0;
        mxcsr_after = 0;
        fpcw_after = 0;
        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64,
                        (const char *)fxrstor, sizeof(fxrstor));
        OK(uc_mem_write(uc, mxcsr_addr, fxstate, sizeof(fxstate)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &mxcsr_addr));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &initial_mxcsr));
        OK(uc_reg_write(uc, UC_X86_REG_FPCW, &initial_fpcw));
        err = uc_emu_start(uc, code_start, code_start + sizeof(fxrstor), 0,
                           0);
        TEST_CHECK(err == UC_ERR_EXCEPTION);
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr_after));
        OK(uc_reg_read(uc, UC_X86_REG_FPCW, &fpcw_after));
        TEST_CHECK(rip == code_start);
        TEST_CHECK(mxcsr_after == initial_mxcsr);
        TEST_CHECK(fpcw_after == initial_fpcw);
        OK(uc_close(uc));
    }

    {
        const uint8_t xrstor[] = {0x0f, 0xae, 0x2f}; /* xrstor [rdi] */
        const uint64_t xstate_bv = 3; /* Restore x87 and SSE state. */
        uint8_t xstate[576] = {0};
        uint32_t eax = 3;
        uint32_t edx = 0;

        memcpy(xstate, &restored_fpcw, sizeof(restored_fpcw));
        memcpy(xstate + 24, &invalid_mxcsr, sizeof(invalid_mxcsr));
        memcpy(xstate + 512, &xstate_bv, sizeof(xstate_bv));
        rip = 0;
        mxcsr_after = 0;
        fpcw_after = 0;
        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, xrstor,
                            sizeof(xrstor));
        OK(uc_mem_write(uc, mxcsr_addr, xstate, sizeof(xstate)));
        OK(uc_reg_write(uc, UC_X86_REG_RDI, &mxcsr_addr));
        OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &initial_mxcsr));
        OK(uc_reg_write(uc, UC_X86_REG_FPCW, &initial_fpcw));
        err = uc_emu_start(uc, code_start, code_start + sizeof(xrstor), 0, 0);
        TEST_CHECK(err == UC_ERR_EXCEPTION);
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr_after));
        OK(uc_reg_read(uc, UC_X86_REG_FPCW, &fpcw_after));
        TEST_CHECK(rip == code_start);
        TEST_CHECK(mxcsr_after == initial_mxcsr);
        TEST_CHECK(fpcw_after == initial_fpcw);
        OK(uc_close(uc));
    }
}

static void test_x86_vcvtps2ph_uses_immediate_rounding(void)
{
    const uint8_t code[] = {
        0xc4, 0xe3, 0x79, 0x1d, 0xc8, 0x02,
        /* vcvtps2ph xmm0, xmm1, round-up */
    };
    const uint32_t input[4] = {0x3f801000U, 0, 0, 0};
    const uint32_t initial[8] = {
        0xaaaaaaaaU, 0xbbbbbbbbU, 0xccccccccU, 0xddddddddU,
        0x11111111U, 0x22222222U, 0x33333333U, 0x44444444U,
    };
    uint32_t result[8] = {0};
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, input));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
    TEST_CHECK(((uint16_t *)result)[0] == 0x3c01);
    TEST_CHECK(result[4] == 0 && result[5] == 0 && result[6] == 0 &&
               result[7] == 0);
    OK(uc_close(uc));
}

static void test_x86_vcvtps2ph_rejects_vex_w1(void)
{
    static const uint8_t code_128[] = {
        0xc4, 0xe3, 0xf9, 0x1d, 0xc8, 0x00,
        /* Reserved VEX.W1 form of vcvtps2ph xmm0, xmm1, 0. */
    };
    static const uint8_t code_256[] = {
        0xc4, 0xe3, 0xfd, 0x1d, 0xc8, 0x00,
        /* Reserved VEX.W1 form of vcvtps2ph xmm0, ymm1, 0. */
    };
    static const uint8_t code_bad_vvvv_128[] = {
        0xc4, 0xe3, 0x71, 0x1d, 0xc8, 0x00,
        /* Reserved VEX.vvvv form of vcvtps2ph xmm0, xmm1, 0. */
    };
    static const uint8_t code_bad_vvvv_256[] = {
        0xc4, 0xe3, 0x75, 0x1d, 0xc8, 0x00,
        /* Reserved VEX.vvvv form of vcvtps2ph xmm0, ymm1, 0. */
    };
    static const uint8_t cvtph_bad_vvvv_128[] = {
        0xc4, 0xe2, 0x71, 0x13, 0xc1,
        /* Reserved VEX.vvvv form of vcvtph2ps xmm0, xmm1. */
    };
    static const uint8_t cvtph_bad_vvvv_256[] = {
        0xc4, 0xe2, 0x75, 0x13, 0xc1,
        /* Reserved VEX.vvvv form of vcvtph2ps ymm0, xmm1. */
    };
    static const uint8_t cvtps_no_f16c_128[] = {
        0xc4, 0xe3, 0x79, 0x1d, 0xc8, 0x00,
    };
    static const uint8_t cvtps_no_f16c_256[] = {
        0xc4, 0xe3, 0x7d, 0x1d, 0xc8, 0x00,
    };
    static const uint8_t cvtph_no_f16c_128[] = {
        0xc4, 0xe2, 0x79, 0x13, 0xc1,
    };
    static const uint8_t cvtph_no_f16c_256[] = {
        0xc4, 0xe2, 0x7d, 0x13, 0xc1,
    };
    static const struct {
        const uint8_t *code;
        size_t size;
    } cases[] = {
        {code_128, sizeof(code_128)},
        {code_256, sizeof(code_256)},
        {code_bad_vvvv_128, sizeof(code_bad_vvvv_128)},
        {code_bad_vvvv_256, sizeof(code_bad_vvvv_256)},
        {cvtph_bad_vvvv_128, sizeof(cvtph_bad_vvvv_128)},
        {cvtph_bad_vvvv_256, sizeof(cvtph_bad_vvvv_256)},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[i].code, cases[i].size);
        uc_assert_err(UC_ERR_INSN_INVALID,
                      uc_emu_start(uc, code_start,
                                   code_start + cases[i].size, 0, 0));
        OK(uc_close(uc));
    }

    {
        static const struct {
            const uint8_t *code;
            size_t size;
        } feature_cases[] = {
            {cvtps_no_f16c_128, sizeof(cvtps_no_f16c_128)},
            {cvtps_no_f16c_256, sizeof(cvtps_no_f16c_256)},
            {cvtph_no_f16c_128, sizeof(cvtph_no_f16c_128)},
            {cvtph_no_f16c_256, sizeof(cvtph_no_f16c_256)},
        };

        for (size_t i = 0;
             i < sizeof(feature_cases) / sizeof(feature_cases[0]); ++i) {
            uc_engine *uc;

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_SANDYBRIDGE,
                                feature_cases[i].code, feature_cases[i].size);
            uc_assert_err(UC_ERR_INSN_INVALID,
                          uc_emu_start(uc, code_start,
                                       code_start + feature_cases[i].size, 0,
                                       0));
            OK(uc_close(uc));
        }
    }
}

static void test_x86_vcvtps2ph_ignores_mxcsr_ftz(void)
{
    const uint8_t code[] = {
        0xc4, 0xe3, 0x79, 0x1d, 0xc8, 0x00,
        /* vcvtps2ph xmm0, xmm1, nearest-even */
    };
    const uint32_t input[4] = {0x33800000U, 0, 0, 0}; /* 2^-24 */
    const uint32_t mxcsr = 0x9f80; /* Default masks with FTZ enabled. */
    uint16_t result[8] = {0};
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, input));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, result));
    TEST_CHECK(result[0] == 1); /* Smallest positive half subnormal. */
    OK(uc_close(uc));
}

static void test_x86_vcvtph2ps_ignores_mxcsr_daz(void)
{
    const uint8_t code[] = {
        0xc4, 0xe2, 0x79, 0x13, 0xc1, /* vcvtph2ps xmm0, xmm1 */
    };
    const uint16_t input[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    uint32_t result[4] = {0};
    uint32_t mxcsr = 0x1fc0; /* all exceptions masked, DAZ enabled */
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, input));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, result));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    TEST_CHECK(result[0] == 0x33800000U); /* Exact widening of 2^-24. */
    TEST_CHECK((mxcsr & 0x3f) == 0);
    OK(uc_close(uc));
}

static void test_x86_vcvtps2ph_ignores_immediate_bit3(void)
{
    static const uint8_t immediate_zero[] = {
        0xc4, 0xe3, 0x79, 0x1d, 0xc8, 0x00,
    };
    static const uint8_t immediate_bit3[] = {
        0xc4, 0xe3, 0x79, 0x1d, 0xc8, 0x08,
    };
    static const struct {
        const uint8_t *code;
        size_t size;
    } cases[] = {
        {immediate_zero, sizeof(immediate_zero)},
        {immediate_bit3, sizeof(immediate_bit3)},
    };
    const uint32_t input[4] = {0x3f801000U, 0, 0, 0};

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint32_t mxcsr = 0x1f80;
        uint16_t result[8] = {0};
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[i].code, cases[i].size);
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_write(uc, UC_X86_REG_XMM1, input));
        OK(uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_XMM0, result));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK(result[0] == 0x3c00);
        TEST_CHECK((mxcsr & (1U << 5)) != 0);
        OK(uc_close(uc));
    }
}

static void test_x86_fma_alternating_packed_lanes(void)
{
    static const uint8_t maddsub_ps_128[] = {
        0xc4, 0xe2, 0x71, 0x96, 0xc2, /* vfmaddsub132ps xmm0,xmm1,xmm2 */
    };
    static const uint8_t msubadd_ps_256[] = {
        0xc4, 0xe2, 0x75, 0x97, 0xc2, /* vfmsubadd132ps ymm0,ymm1,ymm2 */
    };
    static const uint8_t maddsub_pd_128[] = {
        0xc4, 0xe2, 0xf1, 0xa6, 0xc2, /* vfmaddsub213pd xmm0,xmm1,xmm2 */
    };
    static const uint8_t msubadd_pd_256[] = {
        0xc4, 0xe2, 0xf5, 0xb7, 0xc2, /* vfmsubadd231pd ymm0,ymm1,ymm2 */
    };
    static const uint8_t scalar_lig_l1[] = {
        0xc4, 0xe2, 0x75, 0x99, 0xc2, /* vfmadd132ss, encoded VEX.L=1 */
    };
    const float ps0[8] = {2, 2, 2, 2, 2, 2, 2, 2};
    const float ps1[8] = {3, 3, 3, 3, 3, 3, 3, 3};
    const float ps2[8] = {4, 4, 4, 4, 4, 4, 4, 4};
    const float expected_maddsub_ps[8] = {5, 11, 5, 11, 0, 0, 0, 0};
    const float expected_msubadd_ps[8] = {11, 5, 11, 5, 11, 5, 11, 5};
    const double pd0[4] = {2, 2, 2, 2};
    const double pd1[4] = {3, 3, 3, 3};
    const double pd2[4] = {4, 4, 4, 4};
    const double expected_maddsub_pd[4] = {2, 10, 0, 0};
    const double expected_msubadd_pd[4] = {14, 10, 14, 10};
    float ps_result[8] = {0};
    double pd_result[4] = {0};
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, maddsub_ps_128,
                        sizeof(maddsub_ps_128));
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, ps0));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ps1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ps2));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(maddsub_ps_128), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ps_result));
    TEST_CHECK(memcmp(ps_result, expected_maddsub_ps, sizeof(ps_result)) == 0);
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, msubadd_ps_256,
                        sizeof(msubadd_ps_256));
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, ps0));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ps1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ps2));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(msubadd_ps_256), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ps_result));
    TEST_CHECK(memcmp(ps_result, expected_msubadd_ps, sizeof(ps_result)) == 0);
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, maddsub_pd_128,
                        sizeof(maddsub_pd_128));
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, pd0));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, pd1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, pd2));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(maddsub_pd_128), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, pd_result));
    TEST_CHECK(memcmp(pd_result, expected_maddsub_pd, sizeof(pd_result)) == 0);
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, msubadd_pd_256,
                        sizeof(msubadd_pd_256));
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, pd0));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, pd1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, pd2));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(msubadd_pd_256), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, pd_result));
    TEST_CHECK(memcmp(pd_result, expected_msubadd_pd, sizeof(pd_result)) == 0);
    OK(uc_close(uc));

    memset(ps_result, 0xa5, sizeof(ps_result));
    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, scalar_lig_l1,
                        sizeof(scalar_lig_l1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, ps_result));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ps1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ps2));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(scalar_lig_l1), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ps_result));
    TEST_CHECK(ps_result[4] == 0 && ps_result[5] == 0 &&
               ps_result[6] == 0 && ps_result[7] == 0);
    OK(uc_close(uc));
}

static void test_x86_fma_ftz_after_rounding(void)
{
    const uint8_t code[] = {
        0xc4, 0xe2, 0xf1, 0xb9, 0xc2, /* vfmadd231sd xmm0,xmm1,xmm2 */
    };
    static const struct {
        uint64_t n;
        uint64_t m;
        uint64_t a;
        uint64_t result;
        uint32_t flags;
    } cases[] = {
        {UINT64_C(0x3fdfffffffffffff), UINT64_C(0x001fffffffffffff),
         UINT64_C(0x801fffffffffffff), UINT64_C(0x8010000000000000), 0x20},
        {UINT64_C(0x3cc8000000000000), UINT64_C(0),
         UINT64_C(0x8008000000000000), UINT64_C(0x8000000000000000), 0x32},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t xmm0[2] = {cases[i].a, 0};
        uint64_t xmm1[2] = {cases[i].m, 0};
        uint64_t xmm2[2] = {cases[i].n, 0};
        uint32_t mxcsr = 0x9f80;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0));
        OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1));
        OK(uc_reg_write(uc, UC_X86_REG_XMM2, xmm2));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_XMM0, xmm0));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK(xmm0[0] == cases[i].result);
        TEST_CHECK_((mxcsr & 0x3f) == cases[i].flags,
                    "MXCSR flags 0x%x, expected 0x%x", mxcsr & 0x3f,
                    cases[i].flags);
        OK(uc_close(uc));
    }
}

static void test_x86_fma_daz_suppresses_denormal_operand_flag(void)
{
    const uint8_t code[] = {
        0xc4, 0xe2, 0xf1, 0xb9, 0xc2, /* vfmadd231sd xmm0,xmm1,xmm2 */
    };
    uint64_t xmm0[2] = {UINT64_C(0x3ff0000000000000), 0};
    const uint64_t xmm1[2] = {UINT64_C(0x0000000000000001), 0};
    const uint64_t xmm2[2] = {UINT64_C(0x3ff0000000000000), 0};
    uint32_t mxcsr = 0x1fc0; /* all exceptions masked, DAZ enabled */
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, xmm2));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, xmm0));
    OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
    TEST_CHECK(xmm0[0] == UINT64_C(0x3ff0000000000000));
    TEST_CHECK((mxcsr & 0x3f) == 0);
    OK(uc_close(uc));
}

static void test_x86_vex_uses_low_byte_registers(void)
{
    const uint8_t code[] = {
        0xc4, 0xe3, 0x71, 0x20, 0xc4, 0x00,
        /* vpinsrb xmm0, xmm1, spl, 0 */
    };
    const uint64_t rax = UINT64_C(0x000000000000bb00);
    const uint64_t rsp = UINT64_C(0x00000000000000aa);
    const uint8_t source[16] = {0};
    uint8_t result[16] = {0};
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, source));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, result));
    TEST_CHECK(result[0] == 0xaa);
    OK(uc_close(uc));
}

static void test_x86_vex128_clears_upper_vector_state(void)
{
    const uint8_t code[] = {
        0xc5, 0xf1, 0xef, 0xc2, /* vpxor xmm0, xmm1, xmm2 */
    };
    const uint32_t lhs[4] = {
        0x00000000U, 0xffffffffU, 0x12345678U, 0xaaaaaaaaU,
    };
    const uint32_t rhs[4] = {
        0xffffffffU, 0x00000000U, 0x87654321U, 0x55555555U,
    };
    const uint32_t initial[8] = {
        1, 2, 3, 4, 0x11111111U, 0x22222222U, 0x33333333U, 0x44444444U,
    };
    uint32_t result[8] = {0};
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, lhs));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, rhs));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
    for (size_t i = 0; i < 4; ++i)
        TEST_CHECK(result[i] == (lhs[i] ^ rhs[i]));
    for (size_t i = 4; i < 8; ++i)
        TEST_CHECK(result[i] == 0);
    OK(uc_close(uc));
}

static void test_x86_vex128_partial_moves_merge_source_lanes(void)
{
    static const uint8_t vmovss_reg[] = {
        0xc5, 0xf2, 0x10, 0xc2, /* vmovss xmm0, xmm1, xmm2 */
    };
    static const uint8_t vmovsd_reg[] = {
        0xc5, 0xf3, 0x10, 0xc2, /* vmovsd xmm0, xmm1, xmm2 */
    };
    static const uint64_t src1[2] = {
        UINT64_C(0x1111222233334444), UINT64_C(0x5555666677778888),
    };
    static const uint64_t src2[2] = {
        UINT64_C(0x9999aaaabbbbcccc), UINT64_C(0xddddeeeeffff0000),
    };
    static const uint64_t initial[4] = {
        UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX,
    };
    uc_engine *uc;

    {
        uint64_t result[4] = {0};

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            vmovss_reg, sizeof(vmovss_reg));
        OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
        OK(uc_reg_write(uc, UC_X86_REG_XMM1, src1));
        OK(uc_reg_write(uc, UC_X86_REG_XMM2, src2));
        OK(uc_emu_start(uc, code_start,
                        code_start + sizeof(vmovss_reg), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
        TEST_CHECK(result[0] == ((src1[0] & UINT64_C(0xffffffff00000000)) |
                                 (src2[0] & UINT64_C(0x00000000ffffffff))));
        TEST_CHECK(result[1] == src1[1]);
        TEST_CHECK(result[2] == 0 && result[3] == 0);
        OK(uc_close(uc));
    }

    {
        uint64_t result[4] = {0};

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            vmovsd_reg, sizeof(vmovsd_reg));
        OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
        OK(uc_reg_write(uc, UC_X86_REG_XMM1, src1));
        OK(uc_reg_write(uc, UC_X86_REG_XMM2, src2));
        OK(uc_emu_start(uc, code_start,
                        code_start + sizeof(vmovsd_reg), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
        TEST_CHECK(result[0] == src2[0]);
        TEST_CHECK(result[1] == src1[1]);
        TEST_CHECK(result[2] == 0 && result[3] == 0);
        OK(uc_close(uc));
    }

    {
        static const uint8_t vmovss_mem[] = {0xc5, 0xfa, 0x10, 0x00};
        static const uint8_t vmovsd_mem[] = {0xc5, 0xfb, 0x10, 0x00};
        static const uint8_t vmovlps_mem[] = {0xc5, 0xf0, 0x12, 0x00};
        static const uint8_t vmovlpd_mem[] = {0xc5, 0xf1, 0x12, 0x00};
        static const uint8_t vmovhps_mem[] = {0xc5, 0xf0, 0x16, 0x00};
        static const uint8_t vmovhpd_mem[] = {0xc5, 0xf1, 0x16, 0x00};
        static const struct {
            const uint8_t *code;
            size_t size;
            uint64_t q0;
            uint64_t q1;
        } cases[] = {
            {vmovss_mem, sizeof(vmovss_mem),
             UINT64_C(0x00000000abcdef01), 0},
            {vmovsd_mem, sizeof(vmovsd_mem),
             UINT64_C(0x01234567abcdef01), 0},
            {vmovlps_mem, sizeof(vmovlps_mem),
             UINT64_C(0x01234567abcdef01),
             UINT64_C(0x5555666677778888)},
            {vmovlpd_mem, sizeof(vmovlpd_mem),
             UINT64_C(0x01234567abcdef01),
             UINT64_C(0x5555666677778888)},
            {vmovhps_mem, sizeof(vmovhps_mem),
             UINT64_C(0x1111222233334444),
             UINT64_C(0x01234567abcdef01)},
            {vmovhpd_mem, sizeof(vmovhpd_mem),
             UINT64_C(0x1111222233334444),
             UINT64_C(0x01234567abcdef01)},
        };
        const uint64_t data_addr = code_start + 0x401;
        const uint64_t memory_value = UINT64_C(0x01234567abcdef01);

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint64_t result[4] = {0};

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                                cases[i].code, cases[i].size);
            OK(uc_mem_write(uc, data_addr, &memory_value,
                            sizeof(memory_value)));
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &data_addr));
            OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
            OK(uc_reg_write(uc, UC_X86_REG_XMM1, src1));
            OK(uc_emu_start(uc, code_start,
                            code_start + cases[i].size, 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
            TEST_CHECK(result[0] == cases[i].q0);
            TEST_CHECK(result[1] == cases[i].q1);
            TEST_CHECK(result[2] == 0 && result[3] == 0);
            OK(uc_close(uc));
        }
    }
}

static void test_x86_vmovd_vmovq_vex_rules_and_upper_clear(void)
{
    static const uint8_t vmovd_to_xmm[] = {0xc5, 0xf9, 0x6e, 0xc0};
    static const uint8_t vmovq_to_xmm[] = {
        0xc4, 0xe1, 0xf9, 0x6e, 0xc0,
    };
    static const uint8_t vmovq_xmm_to_xmm[] = {0xc5, 0xfa, 0x7e, 0xc1};
    static const uint8_t vmovq_from_xmm[] = {
        0xc4, 0xe1, 0xf9, 0x7e, 0xc0,
    };
    static const uint8_t bad_vvvv_vmovd_to_xmm[] = {
        0xc5, 0xf1, 0x6e, 0xc0,
    };
    static const uint8_t bad_vvvv_vmovd_from_xmm[] = {
        0xc5, 0xf1, 0x7e, 0xc0,
    };
    static const uint8_t bad_vvvv_vmovq_xmm_to_xmm[] = {
        0xc5, 0xf2, 0x7e, 0xc1,
    };
    static const uint8_t bad_l_vmovd_to_xmm[] = {
        0xc5, 0xfd, 0x6e, 0xc0,
    };
    static const uint8_t bad_l_vmovd_from_xmm[] = {
        0xc5, 0xfd, 0x7e, 0xc0,
    };
    static const uint8_t bad_l_vmovq_xmm_to_xmm[] = {
        0xc5, 0xfe, 0x7e, 0xc1,
    };
    static const uint64_t initial[4] = {
        UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX,
    };
    const uint64_t value = UINT64_C(0x1122334455667788);
    const uint64_t xmm_value[2] = {UINT64_C(0x1122334455667788), 0};
    uc_engine *uc;

    {
        static const struct {
            const uint8_t *code;
            size_t size;
            uint64_t expected;
        } cases[] = {
            {vmovd_to_xmm, sizeof(vmovd_to_xmm), UINT64_C(0x55667788)},
            {vmovq_to_xmm, sizeof(vmovq_to_xmm),
             UINT64_C(0x1122334455667788)},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint64_t result[4] = {0};

            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                                cases[i].code, cases[i].size);
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &value));
            OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
            OK(uc_emu_start(uc, code_start,
                            code_start + cases[i].size, 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
            TEST_CHECK(result[0] == cases[i].expected);
            TEST_CHECK(result[1] == 0 && result[2] == 0 && result[3] == 0);
            OK(uc_close(uc));
        }
    }

    {
        uint64_t result[4] = {0};

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            vmovq_xmm_to_xmm,
                            sizeof(vmovq_xmm_to_xmm));
        OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
        OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm_value));
        OK(uc_emu_start(uc, code_start,
                        code_start + sizeof(vmovq_xmm_to_xmm), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
        TEST_CHECK(result[0] == value);
        TEST_CHECK(result[1] == 0 && result[2] == 0 && result[3] == 0);
        OK(uc_close(uc));
    }

    {
        uint64_t rax = 0;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            vmovq_from_xmm, sizeof(vmovq_from_xmm));
        OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm_value));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_emu_start(uc, code_start,
                        code_start + sizeof(vmovq_from_xmm), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        TEST_CHECK(rax == value);
        OK(uc_close(uc));
    }

    {
        static const struct {
            const uint8_t *code;
            size_t size;
        } cases[] = {
            {bad_vvvv_vmovd_to_xmm, sizeof(bad_vvvv_vmovd_to_xmm)},
            {bad_vvvv_vmovd_from_xmm, sizeof(bad_vvvv_vmovd_from_xmm)},
            {bad_vvvv_vmovq_xmm_to_xmm,
             sizeof(bad_vvvv_vmovq_xmm_to_xmm)},
            {bad_l_vmovd_to_xmm, sizeof(bad_l_vmovd_to_xmm)},
            {bad_l_vmovd_from_xmm, sizeof(bad_l_vmovd_from_xmm)},
            {bad_l_vmovq_xmm_to_xmm,
             sizeof(bad_l_vmovq_xmm_to_xmm)},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                                cases[i].code, cases[i].size);
            uc_assert_err(UC_ERR_INSN_INVALID,
                          uc_emu_start(uc, code_start,
                                       code_start + cases[i].size, 0, 0));
            OK(uc_close(uc));
        }
    }
}

static void test_x86_vex128_special_forms_clear_upper_vector_state(void)
{
    static const uint8_t vpshufd[] = {
        0xc5, 0xf9, 0x70, 0xc1, 0x1b, /* vpshufd xmm0, xmm1, 0x1b */
    };
    static const uint8_t vmovntdqa[] = {
        0xc4, 0xe2, 0x79, 0x2a, 0x00, /* vmovntdqa xmm0, [rax] */
    };
    static const uint8_t vpbroadcastd[] = {
        0xc4, 0xe2, 0x79, 0x58, 0xc1, /* vpbroadcastd xmm0, xmm1 */
    };
    static const uint8_t vlddqu[] = {
        0xc5, 0xfb, 0xf0, 0x00, /* vlddqu xmm0, [rax] */
    };
    static const uint8_t vmovups_load[] = {0xc5, 0xf8, 0x10, 0xc1};
    static const uint8_t vmovupd_load[] = {0xc5, 0xf9, 0x10, 0xc1};
    static const uint8_t vmovdqu_load[] = {0xc5, 0xfa, 0x6f, 0xc1};
    static const uint8_t vmovaps_load[] = {0xc5, 0xf8, 0x28, 0xc1};
    static const uint8_t vmovapd_load[] = {0xc5, 0xf9, 0x28, 0xc1};
    static const uint8_t vmovdqa_load[] = {0xc5, 0xf9, 0x6f, 0xc1};
    /* Force the alternate store-opcode register forms: xmm1 is the
     * architectural destination even though assemblers normally choose the
     * equivalent load opcode for register-to-register moves. */
    static const uint8_t vmovups_store_reg[] = {0xc5, 0xf8, 0x11, 0xc1};
    static const uint8_t vmovupd_store_reg[] = {0xc5, 0xf9, 0x11, 0xc1};
    static const uint8_t vmovdqu_store_reg[] = {0xc5, 0xfa, 0x7f, 0xc1};
    static const uint8_t vmovaps_store_reg[] = {0xc5, 0xf8, 0x29, 0xc1};
    static const uint8_t vmovapd_store_reg[] = {0xc5, 0xf9, 0x29, 0xc1};
    static const uint8_t vmovdqa_store_reg[] = {0xc5, 0xf9, 0x7f, 0xc1};
    static const struct {
        const uint8_t *code;
        size_t size;
        bool uses_memory;
        int destination;
    } cases[] = {
        {vpshufd, sizeof(vpshufd), false, UC_X86_REG_YMM0},
        {vmovntdqa, sizeof(vmovntdqa), true, UC_X86_REG_YMM0},
        {vpbroadcastd, sizeof(vpbroadcastd), false, UC_X86_REG_YMM0},
        {vlddqu, sizeof(vlddqu), true, UC_X86_REG_YMM0},
        {vmovups_load, sizeof(vmovups_load), false, UC_X86_REG_YMM0},
        {vmovupd_load, sizeof(vmovupd_load), false, UC_X86_REG_YMM0},
        {vmovdqu_load, sizeof(vmovdqu_load), false, UC_X86_REG_YMM0},
        {vmovaps_load, sizeof(vmovaps_load), false, UC_X86_REG_YMM0},
        {vmovapd_load, sizeof(vmovapd_load), false, UC_X86_REG_YMM0},
        {vmovdqa_load, sizeof(vmovdqa_load), false, UC_X86_REG_YMM0},
        {vmovups_store_reg, sizeof(vmovups_store_reg), false,
         UC_X86_REG_YMM1},
        {vmovupd_store_reg, sizeof(vmovupd_store_reg), false,
         UC_X86_REG_YMM1},
        {vmovdqu_store_reg, sizeof(vmovdqu_store_reg), false,
         UC_X86_REG_YMM1},
        {vmovaps_store_reg, sizeof(vmovaps_store_reg), false,
         UC_X86_REG_YMM1},
        {vmovapd_store_reg, sizeof(vmovapd_store_reg), false,
         UC_X86_REG_YMM1},
        {vmovdqa_store_reg, sizeof(vmovdqa_store_reg), false,
         UC_X86_REG_YMM1},
    };
    const uint64_t data_addr = code_start + 0x400;
    const uint32_t source[4] = {
        0x01020304U, 0x11121314U, 0x21222324U, 0x31323334U,
    };
    const uint32_t initial[8] = {
        1, 2, 3, 4, 0x11111111U, 0x22222222U, 0x33333333U, 0x44444444U,
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint32_t result[8] = {0};
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[i].code, cases[i].size);
        OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
        OK(uc_reg_write(uc, UC_X86_REG_YMM1, initial));
        if (cases[i].uses_memory) {
            OK(uc_mem_write(uc, data_addr, source, sizeof(source)));
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &data_addr));
        }
        OK(uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0));
        OK(uc_reg_read(uc, cases[i].destination, result));
        TEST_CHECK(result[4] == 0 && result[5] == 0 && result[6] == 0 &&
                   result[7] == 0);
        OK(uc_close(uc));
    }
}

static void test_x86_gather_rejects_overlapping_operands(void)
{
    static const uint8_t dst_mask_overlap[] = {
        0xc4, 0xe2, 0x7d, 0x90, 0x04, 0x90,
    };
    static const uint8_t dst_index_overlap[] = {
        0xc4, 0xe2, 0x75, 0x90, 0x04, 0x80,
    };
    static const uint8_t mask_index_overlap[] = {
        0xc4, 0xe2, 0x75, 0x90, 0x04, 0x88,
    };
    static const struct {
        const uint8_t *code;
        size_t size;
    } cases[] = {
        {dst_mask_overlap, sizeof(dst_mask_overlap)},
        {dst_index_overlap, sizeof(dst_index_overlap)},
        {mask_index_overlap, sizeof(mask_index_overlap)},
    };
    const uint64_t base = code_start + 0x400;
    const uint32_t zero[8] = {0};

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uc_engine *uc;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[i].code, cases[i].size);
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &base));
        OK(uc_reg_write(uc, UC_X86_REG_YMM0, zero));
        OK(uc_reg_write(uc, UC_X86_REG_YMM1, zero));
        err = uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0);
        TEST_CHECK(err == UC_ERR_INSN_INVALID);
        OK(uc_close(uc));
    }
}

static void test_x86_mxcsr_tracks_simd_exceptions(void)
{
    static const uint8_t divss[] = {
        0x0f, 0xae, 0x10, 0xf3, 0x0f, 0x5e, 0xc1, 0x0f, 0xae, 0x18,
    };
    static const uint8_t rcpss[] = {
        0x0f, 0xae, 0x10, 0xf3, 0x0f, 0x53, 0xc1, 0x0f, 0xae, 0x18,
    };
    static const uint8_t rsqrtss[] = {
        0x0f, 0xae, 0x10, 0xf3, 0x0f, 0x52, 0xc1, 0x0f, 0xae, 0x18,
    };
    static const struct {
        const uint8_t *code;
        size_t size;
        uint32_t lhs;
        uint32_t rhs;
        uint32_t expected_flags;
    } cases[] = {
        {divss, sizeof(divss), 0x3f800000U, 0x00000000U, 0x04},
        {rcpss, sizeof(rcpss), 0, 0x00000000U, 0x00},
        {rsqrtss, sizeof(rsqrtss), 0, 0xbf800000U, 0x00},
    };
    const uint64_t mxcsr_addr = code_start + 0x200;
    const uint32_t initial_mxcsr = 0x1f80;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint32_t xmm0[4] = {cases[i].lhs, 0, 0, 0};
        uint32_t xmm1[4] = {cases[i].rhs, 0, 0, 0};
        uint32_t mxcsr_after = 0;
        uc_engine *uc;

        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64,
                        (const char *)cases[i].code, cases[i].size);
        OK(uc_mem_write(uc, mxcsr_addr, &initial_mxcsr,
                        sizeof(initial_mxcsr)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &mxcsr_addr));
        OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0));
        OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1));
        OK(uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0));
        OK(uc_mem_read(uc, mxcsr_addr, &mxcsr_after, sizeof(mxcsr_after)));
        TEST_CHECK((mxcsr_after & 0x3f) == cases[i].expected_flags);
        OK(uc_close(uc));
    }
}

/* NeverD contributors, 2026-09-30: preserve SSE denormal status and its
 * priority relative to NaN, divide-by-zero and negative square root. */
static void test_x86_sse_denormal_status(void)
{
    static const struct {
        uint8_t opcode;
        uint32_t lhs, rhs, flags;
    } cases[] = {
        {0x58, 1, 0x3f800000, 0x22},
        {0x58, 1, 0x7fc00011, 0},
        {0x58, 1, 0x7f800011, 1},
        {0x5e, 1, 0, 4},
        {0x51, 0x3f800000, 1, 0x22},
        {0x51, 0x3f800000, 0x80000001, 1},
        {0x5d, 1, 0x3f800000, 2},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const uint8_t code[] = {0xf3, 0x0f, cases[i].opcode, 0xc1};
        uint32_t xmm0[4] = {cases[i].lhs, 0, 0, 0};
        uint32_t xmm1[4] = {cases[i].rhs, 0, 0, 0};
        uint32_t mxcsr = 0x1f80;
        uc_engine *uc;
        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64,
                        (const char *)code, sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0));
        OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK((mxcsr & 0x3f) == cases[i].flags);
        OK(uc_close(uc));
    }
}

static void test_x86_xsave_roundtrips_ymmh(void)
{
    const uint8_t code[] = {
        0x31, 0xc9,             /* xor ecx, ecx */
        0x0f, 0x01, 0xd1,       /* xsetbv */
        0x0f, 0xae, 0x27,       /* xsave [rdi] */
        0xc5, 0xfd, 0xef, 0xc0, /* vpxor ymm0, ymm0, ymm0 */
        0x0f, 0xae, 0x2f,       /* xrstor [rdi] */
    };
    const uint64_t save_area = UINT64_C(0x8000);
    const uint32_t initial[8] = {
        0x01020304U, 0x11121314U, 0x21222324U, 0x31323334U,
        0x41424344U, 0x51525354U, 0x61626364U, 0x71727374U,
    };
    uint32_t saved_ymmh[4] = {0};
    uint32_t result[8] = {0};
    uint32_t eax = 7; /* X87, SSE and YMM state components. */
    uint32_t edx = 0;
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                        sizeof(code));
    OK(uc_mem_map(uc, save_area, 0x1000, UC_PROT_ALL));
    OK(uc_reg_write(uc, UC_X86_REG_RDI, &save_area));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, initial));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, save_area + 0x240, saved_ymmh,
                   sizeof(saved_ymmh)));
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, result));
    TEST_CHECK(memcmp(saved_ymmh, &initial[4], sizeof(saved_ymmh)) == 0);
    TEST_CHECK(memcmp(result, initial, sizeof(result)) == 0);
    OK(uc_close(uc));
}

static void test_x86_record_interrupt(uc_engine *uc, uint32_t intno,
                                      void *user_data)
{
    TestX86InterruptRecord *record = user_data;

    record->intno = intno;
    record->count++;
    OK(uc_emu_stop(uc));
}

static void test_x86_mov_ss_rejects_null_selector_rpl_mismatch(void)
{
    for (int mismatch = 0; mismatch < 2; ++mismatch) {
        uint8_t code[] = {
            0x66, 0xb8, mismatch ? 0x03 : 0x00, 0x00, /* mov ax, selector */
            0x8e, 0xd0,                               /* mov ss, ax */
            0x90,                                     /* nop */
        };
        TestX86InterruptRecord record = {0};
        uint16_t ss_before = 0;
        uint16_t ss_after = 0;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_hook hook;

        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                        sizeof(code));
        OK(uc_reg_read(uc, UC_X86_REG_SS, &ss_before));
        OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_x86_record_interrupt,
                       &record, 1, 0));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_SS, &ss_after));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        if (mismatch) {
            TEST_CHECK(record.count == 1);
            TEST_CHECK(record.intno == 13); /* #GP(0) */
            TEST_CHECK(ss_after == ss_before);
            TEST_CHECK(rip == code_start + 4);
        } else {
            TEST_CHECK(record.count == 0);
            TEST_CHECK(ss_after == 0);
            TEST_CHECK(rip == code_start + sizeof(code));
        }

        OK(uc_hook_del(uc, hook));
        OK(uc_close(uc));
    }
}

static void test_x86_bsf_bsr_zero_input_preserves_destination(void)
{
    static const uint8_t code[] = {
        0x0f, 0xbc, 0xd1, /* bsf edx, ecx */
        0x0f, 0xbd, 0xde, /* bsr ebx, esi */
    };

    for (int zero_input = 0; zero_input < 2; ++zero_input) {
        const uint64_t initial_rdx = UINT64_C(0x1122334455667788);
        const uint64_t initial_rbx = UINT64_C(0x99aabbccddeeff11);
        uint64_t rcx = zero_input ? 0 : UINT64_C(0x10);
        uint64_t rsi = zero_input ? 0 : UINT64_C(0x80000000);
        uint64_t rdx = initial_rdx;
        uint64_t rbx = initial_rbx;
        uint64_t rflags = 0;
        uc_engine *uc;

        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                        sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
        OK(uc_reg_write(uc, UC_X86_REG_RSI, &rsi));
        OK(uc_reg_write(uc, UC_X86_REG_RDX, &rdx));
        OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_RDX, &rdx));
        OK(uc_reg_read(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));

        if (zero_input) {
            TEST_CHECK(rdx == initial_rdx);
            TEST_CHECK(rbx == initial_rbx);
            TEST_CHECK((rflags & (UINT64_C(1) << 6)) != 0); /* ZF */
        } else {
            TEST_CHECK(rdx == 4);
            TEST_CHECK(rbx == 31);
            TEST_CHECK((rflags & (UINT64_C(1) << 6)) == 0); /* ZF */
        }

        OK(uc_close(uc));
    }
}

static void test_x86_cvtsi2sd_xmm7_followed_by_call(void)
{
    uint8_t code[] = {
        0xf2, 0x0f, 0x2a, 0xf8,       /* cvtsi2sd xmm7, eax */
        0xe8, 0x02, 0x00, 0x00, 0x00, /* call subroutine */
        0xeb, 0x01,                   /* jmp conversion */
        0xc3,                         /* subroutine: ret */
        0xf2, 0x0f, 0x2c, 0xc7,       /* conversion: cvttsd2si eax, xmm7 */
    };
    const uc_mode modes[] = {UC_MODE_32, UC_MODE_64};

    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
        TEST_CODE(modes[i], code);
        TEST_IN_REG(EAX, 42);
        TEST_OUT_REG(EAX, 42);
        TEST_RUN();
    }
}

static void test_x86_cvttss2si_followed_by_rep_prefixed_instruction(void)
{
    uint8_t code[] = {
        0xb8, 0x00, 0x00, 0x28, 0x42, /* mov eax, 42.0f */
        0x66, 0x0f, 0x6e, 0xc0,       /* movd xmm0, eax */
        0xf3, 0x0f, 0x2c, 0xf8,       /* cvttss2si edi, xmm0 */
        0xf3, 0x90,                   /* pause */
        0x89, 0xf8,                   /* mov eax, edi */
    };
    const uc_mode modes[] = {UC_MODE_32, UC_MODE_64};

    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
        TEST_CODE(modes[i], code);
        TEST_OUT_REG(EAX, 42);
        TEST_RUN();
    }
}

static void test_x86_rdpmc_fails_without_virtual_pmu(void)
{
    const uint8_t code[] = {0x0f, 0x33}; /* rdpmc */
    uint32_t eax = 0xaaaaaaaaU;
    uint32_t edx = 0xbbbbbbbbU;
    uint32_t ecx = 0;
    uint64_t rip = 0;
    uc_engine *uc;
    uc_err err;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                    sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    TEST_CHECK(err == UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &edx));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    TEST_CHECK(eax == 0xaaaaaaaaU);
    TEST_CHECK(edx == 0xbbbbbbbbU);
    TEST_CHECK(rip == code_start);
    OK(uc_close(uc));
}

static void test_x86_unimplemented_msr_raises_gp(void)
{
    static const uint8_t rdmsr[] = {0x0f, 0x32};
    static const uint8_t wrmsr[] = {0x0f, 0x30};
    static const struct {
        const uint8_t *code;
        size_t size;
    } cases[] = {
        {rdmsr, sizeof(rdmsr)},
        {wrmsr, sizeof(wrmsr)},
    };
    const uint32_t reserved_msr = 0x40000000U;
    const uint32_t initial_eax = 0x11223344U;
    const uint32_t initial_edx = 0x55667788U;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint32_t eax = initial_eax;
        uint32_t ecx = reserved_msr;
        uint32_t edx = initial_edx;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64,
                        (const char *)cases[i].code, cases[i].size);
        OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
        OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));

        err = uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0);
        TEST_CHECK(err == UC_ERR_EXCEPTION);

        OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_read(uc, UC_X86_REG_ECX, &ecx));
        OK(uc_reg_read(uc, UC_X86_REG_EDX, &edx));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK(eax == initial_eax);
        TEST_CHECK(ecx == reserved_msr);
        TEST_CHECK(edx == initial_edx);
        TEST_CHECK(rip == code_start);

        OK(uc_close(uc));
    }
}

static void test_x86_rdpmc_user_access_fails_without_virtual_pmu(void)
{
    const uint8_t iretq[] = {0x48, 0xcf};
    const uint8_t rdpmc[] = {0x0f, 0x33};
    const uint64_t gdt_addr = UINT64_C(0x9000);
    const uint64_t stack_addr = UINT64_C(0xa000);
    const uint64_t kernel_rsp = stack_addr + 0x800;
    const uint64_t user_rsp = stack_addr + 0xff0;
    const uint64_t user_rip = code_start + 0x100;
    const uint64_t user_code_descriptor = UINT64_C(0x00affb000000ffff);
    const uint64_t user_data_descriptor = UINT64_C(0x00cff3000000ffff);
    const uint64_t iret_frame[] = {user_rip, 0x0b, 0x02, user_rsp, 0x13};
    uc_x86_mmr gdtr = {0, gdt_addr, 0x17, 0};

    for (int pce_enabled = 0; pce_enabled < 2; ++pce_enabled) {
        TestX86InterruptRecord record = {0};
        uint64_t cr4 = 0;
        uint32_t ecx = 0;
        uc_engine *uc;
        uc_hook hook;

        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)iretq,
                        sizeof(iretq));
        OK(uc_mem_map(uc, gdt_addr, 0x1000, UC_PROT_ALL));
        OK(uc_mem_map(uc, stack_addr, 0x1000, UC_PROT_ALL));
        OK(uc_mem_write(uc, gdt_addr + 8, &user_code_descriptor,
                        sizeof(user_code_descriptor)));
        OK(uc_mem_write(uc, gdt_addr + 16, &user_data_descriptor,
                        sizeof(user_data_descriptor)));
        OK(uc_mem_write(uc, kernel_rsp, iret_frame, sizeof(iret_frame)));
        OK(uc_mem_write(uc, user_rip, rdpmc, sizeof(rdpmc)));
        OK(uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr));
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &kernel_rsp));
        OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
        if (pce_enabled) {
            cr4 |= UINT64_C(1) << 8;
        } else {
            cr4 &= ~(UINT64_C(1) << 8);
        }
        OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));
        OK(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
        OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_x86_record_interrupt,
                       &record, 1, 0));
        OK(uc_emu_start(uc, code_start, user_rip + sizeof(rdpmc), 0, 0));
        TEST_CHECK(record.count == 1);
        TEST_CHECK(record.intno == 13);
        OK(uc_close(uc));
    }
}

static void test_x86_haswell_exposes_vector_features_and_state(void)
{
    static const uint8_t cpuid[] = {0x0f, 0xa2};
    static const uint8_t xgetbv[] = {0x0f, 0x01, 0xd0};
    uint32_t eax = 1;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, cpuid,
                        sizeof(cpuid));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(cpuid), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_ECX, &ecx));
    TEST_CHECK((ecx & (1U << 12)) != 0); /* FMA */
    TEST_CHECK((ecx & (1U << 28)) != 0); /* AVX */

    eax = 7;
    ecx = 0;
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(cpuid), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_EBX, &ebx));
    TEST_CHECK((ebx & (1U << 5)) != 0); /* AVX2 */

    OK(uc_mem_write(uc, code_start, xgetbv, sizeof(xgetbv)));
    ecx = 0;
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(xgetbv), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &edx));
    TEST_CHECK((((uint64_t)edx << 32) | eax) & UINT64_C(0x6));
    TEST_CHECK((eax & 0x6) == 0x6); /* SSE and YMM state enabled. */
    OK(uc_close(uc));
}

static void test_x86_rdseed_uses_its_own_cpuid_feature(void)
{
    static const uint8_t rdrand[] = {
        0x48, 0x0f, 0xc7, 0xf0, /* rdrand rax */
    };
    static const uint8_t rdseed[] = {
        0x48, 0x0f, 0xc7, 0xf8, /* rdseed rax */
    };
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_IVYBRIDGE, rdrand,
                        sizeof(rdrand));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(rdrand), 0, 0));
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_IVYBRIDGE, rdseed,
                        sizeof(rdseed));
    uc_assert_err(UC_ERR_INSN_INVALID,
                  uc_emu_start(uc, code_start, code_start + sizeof(rdseed), 0,
                               0));
    OK(uc_close(uc));
}

static void test_x86_rdpid_reads_tsc_aux_and_checks_cpuid(void)
{
    const uint8_t code[] = {
        0xf3, 0x0f, 0xc7, 0xf8, /* rdpid eax */
    };
    uc_x86_msr tsc_aux = {
        .rid = UINT32_C(0xc0000103),
        .value = UINT64_C(0x1122334455667788),
    };
    uint64_t rax = UINT64_MAX;
    uc_engine *uc;

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_ICELAKE_CLIENT, code,
                        sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_MSR, &tsc_aux));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    TEST_CHECK(rax == UINT64_C(0x55667788));
    OK(uc_close(uc));

    uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_IVYBRIDGE, code,
                        sizeof(code));
    uc_assert_err(UC_ERR_INSN_INVALID,
                  uc_emu_start(uc, code_start, code_start + sizeof(code), 0,
                               0));
    OK(uc_close(uc));
}

typedef struct TestX86NestedExitCache {
    uint64_t inner_begin;
    uc_err inner_result;
    unsigned int call_count;
} TestX86NestedExitCache;

static void test_x86_nested_exit_cache_hook(uc_engine *uc, uint64_t address,
                                            uint32_t size, void *user_data)
{
    TestX86NestedExitCache *state = user_data;
    uint32_t zero = 0;

    TEST_CHECK(address == code_start);
    TEST_CHECK(size == 1);
    state->call_count++;
    state->inner_result = uc_emu_start(uc, state->inner_begin, 0, 0, 0);

    /* Isolate the outer run's result from the inner cache-priming run. */
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &zero));
    OK(uc_reg_write(uc, UC_X86_REG_EBX, &zero));
}

static void test_x86_until_honored_after_cached_tb_chaining(void)
{
    static const uint8_t func_a[] = {
        0xb8, 0xfe, 0xff, 0xff, 0xff, /* mov eax, 0xfffffffe */
        0xc3,                         /* ret */
    };
    static const uint8_t func_b[] = {
        0x41, 0x57,                         /* push r15 */
        0x41, 0x56,                         /* push r14 */
        0x41, 0x55,                         /* push r13 */
        0x41, 0x54,                         /* push r12 */
        0x55,                               /* push rbp */
        0x53,                               /* push rbx */
        0x48, 0x83, 0xec, 0x08,             /* sub rsp, 8 */
        0x48, 0xa1, 0x00, 0x30, 0x00, 0x00, /* mov rax, [0x3000] */
        0x00, 0x00, 0x00, 0x00,
        0x48, 0x85, 0xc0,                   /* test rax, rax */
        0x74, 0x01,                         /* je error_exit */
        0x90,                               /* nop */
        0x41, 0xbd, 0xff, 0xff, 0xff, 0xff, /* mov r13d, 0xffffffff */
        0xeb, 0x00,                         /* jmp epilogue */
        0x44, 0x89, 0xe8,                   /* mov eax, r13d */
        0x48, 0x83, 0xc4, 0x08,             /* add rsp, 8 */
        0x5b,                               /* pop rbx */
        0x5d,                               /* pop rbp */
        0x41, 0x5c,                         /* pop r12 */
        0x41, 0x5d,                         /* pop r13 */
        0x41, 0x5e,                         /* pop r14 */
        0x41, 0x5f,                         /* pop r15 */
        0xc3,                               /* ret */
    };
    uint8_t code[sizeof(func_a) + sizeof(func_b)];
    const uint64_t func_a_start = code_start;
    const uint64_t func_a_end = func_a_start + sizeof(func_a);
    const uint64_t func_b_start = func_a_end;
    const uint64_t func_b_end = func_b_start + sizeof(func_b);
    const uint64_t stack_page = UINT64_C(0x700000);
    const uint64_t initial_rsp = UINT64_C(0x7ffff0);
    const uint64_t poison = UINT64_C(0xdeadbeef);

    memcpy(code, func_a, sizeof(func_a));
    memcpy(code + sizeof(func_a), func_b, sizeof(func_b));

    for (int b_first = 0; b_first < 2; ++b_first) {
        const char *order = b_first ? "B then A" : "A then B";
        uc_engine *uc;

        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                        sizeof(code));
        OK(uc_mem_map(uc, stack_page, 0x100000, UC_PROT_ALL));

        for (int step = 0; step < 2; ++step) {
            bool run_b = b_first ? step == 0 : step == 1;
            uint64_t begin = run_b ? func_b_start : func_a_start;
            uint64_t until = run_b ? func_b_end : func_a_end;
            uint64_t expected_rax = run_b ? UINT64_C(0xffffffff)
                                          : UINT64_C(0xfffffffe);
            uint64_t return_slots[2] = {until, poison};
            uint64_t rsp = initial_rsp;
            uint64_t rip = 0;
            uint64_t rax = 0;
            uc_err err;

            OK(uc_mem_write(uc, initial_rsp, return_slots,
                            sizeof(return_slots)));
            OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
            err = uc_emu_start(uc, begin, until, 0, 0);
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp));
            OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));

            TEST_CHECK_(err == UC_ERR_OK,
                        "%s, step %d returned %s", order, step,
                        uc_strerror(err));
            TEST_CHECK_(rip == until,
                        "%s, step %d stopped at 0x%" PRIx64
                        ", expected 0x%" PRIx64,
                        order, step, rip, until);
            TEST_CHECK_(rax == expected_rax,
                        "%s, step %d produced RAX=0x%" PRIx64,
                        order, step, rax);
            TEST_CHECK_(rsp == initial_rsp + sizeof(uint64_t),
                        "%s, step %d consumed the poison return slot",
                        order, step);
        }

        OK(uc_close(uc));
    }

    {
        uint8_t nested_code[0x105];
        const uint64_t cached_path = code_start + 0x100;
        const uint64_t outer_until = cached_path + 2;
        TestX86NestedExitCache state = {
            .inner_begin = cached_path,
            .inner_result = UC_ERR_ARG,
        };
        uint32_t eax = 0;
        uint32_t ebx = 0;
        uint32_t eip = 0;
        uc_engine *uc;
        uc_hook hook;

        memset(nested_code, 0x90, sizeof(nested_code));
        nested_code[0] = 0x90; /* nop: hook primes the inner TB here */
        nested_code[1] = 0xe9; /* jmp cached_path */
        nested_code[2] = 0xfa;
        nested_code[3] = 0x00;
        nested_code[4] = 0x00;
        nested_code[5] = 0x00;
        nested_code[0x100] = 0xff; /* inc eax */
        nested_code[0x101] = 0xc0;
        nested_code[0x102] = 0xff; /* inc ebx: outer until */
        nested_code[0x103] = 0xc3;
        nested_code[0x104] = 0xf4; /* hlt ends the inner run */

        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32,
                        (const char *)nested_code, sizeof(nested_code));
        OK(uc_hook_add(uc, &hook, UC_HOOK_CODE,
                       test_x86_nested_exit_cache_hook, &state,
                       code_start, code_start));

        OK(uc_emu_start(uc, code_start, outer_until, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_EIP, &eip));
        OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_read(uc, UC_X86_REG_EBX, &ebx));

        TEST_CHECK(state.call_count == 1);
        TEST_CHECK(state.inner_result == UC_ERR_OK);
        TEST_CHECK(eip == outer_until);
        TEST_CHECK(eax == 1);
        TEST_CHECK(ebx == 0);

        OK(uc_close(uc));
    }
}

static void test_x86_sse_avx_nan_first_source(void)
{
    static const uint8_t addss[] = {
        0xf3, 0x0f, 0x58, 0xc1, /* addss xmm0, xmm1 */
    };
    static const uint8_t vaddss[] = {
        0xc5, 0xf2, 0x58, 0xc2, /* vaddss xmm0, xmm1, xmm2 */
    };
    static const uint8_t haddps[] = {
        0xf2, 0x0f, 0x7c, 0xc1, /* haddps xmm0, xmm1 */
    };
    static const uint8_t addsubps[] = {
        0xf2, 0x0f, 0xd0, 0xc1, /* addsubps xmm0, xmm1 */
    };
    static const uint8_t dpps[] = {
        0x66, 0x0f, 0x3a, 0x40, 0xc1, 0xf1, /* dpps xmm0, xmm1, 0xf1 */
    };
    static const uint8_t minss[] = {
        0xf3, 0x0f, 0x5d, 0xc1, /* minss xmm0, xmm1 */
    };
    static const uint32_t first_qnan[4] = {
        0x7fc00011U, 0x3f800000U, 0x3f800000U, 0x3f800000U,
    };
    static const uint32_t second_qnan[4] = {
        0xffc12345U, 0x40000000U, 0x40000000U, 0x40000000U,
    };
    static const uint32_t hadd_first[4] = {
        0x7fc00011U, 0xffc12345U, 0x3f800000U, 0x3f800000U,
    };
    static const uint32_t all_ones[4] = {
        0x3f800000U, 0x3f800000U, 0x3f800000U, 0x3f800000U,
    };
    static const uint32_t dpps_first[4] = {
        0x7fc00011U, 0xffc12345U, 0, 0,
    };
    static const uint32_t snan_first[4] = {
        0xff800123U, 0, 0, 0,
    };
    static const struct {
        const char *name;
        const uint8_t *code;
        size_t code_size;
        int first_reg;
        int second_reg;
        const uint32_t *first;
        const uint32_t *second;
        uint32_t expected;
        bool expect_invalid;
    } cases[] = {
        {"ADDSS", addss, sizeof(addss), UC_X86_REG_XMM0,
         UC_X86_REG_XMM1, first_qnan, second_qnan, first_qnan[0], false},
        {"VADDSS", vaddss, sizeof(vaddss), UC_X86_REG_XMM1,
         UC_X86_REG_XMM2, first_qnan, second_qnan, first_qnan[0], false},
        {"HADDPS", haddps, sizeof(haddps), UC_X86_REG_XMM0,
         UC_X86_REG_XMM1, hadd_first, all_ones, hadd_first[0], false},
        {"ADDSUBPS", addsubps, sizeof(addsubps), UC_X86_REG_XMM0,
         UC_X86_REG_XMM1, first_qnan, second_qnan, first_qnan[0], false},
        {"DPPS", dpps, sizeof(dpps), UC_X86_REG_XMM0, UC_X86_REG_XMM1,
         dpps_first, all_ones, dpps_first[0], false},
        {"MINSS control", minss, sizeof(minss), UC_X86_REG_XMM0,
         UC_X86_REG_XMM1, first_qnan, second_qnan, second_qnan[0], false},
        {"ADDSS signaling", addss, sizeof(addss), UC_X86_REG_XMM0,
         UC_X86_REG_XMM1, snan_first, second_qnan, 0xffc00123U, true},
    };
    const uint32_t initial_mxcsr = 0x1f80;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint32_t result[4] = {0};
        uint32_t mxcsr = initial_mxcsr;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[i].code, cases[i].code_size);
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_write(uc, cases[i].first_reg, cases[i].first));
        OK(uc_reg_write(uc, cases[i].second_reg, cases[i].second));
        OK(uc_emu_start(uc, code_start, code_start + cases[i].code_size, 0,
                        0));
        OK(uc_reg_read(uc, UC_X86_REG_XMM0, result));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK_(result[0] == cases[i].expected,
                    "%s produced 0x%08" PRIx32 ", expected 0x%08" PRIx32,
                    cases[i].name, result[0], cases[i].expected);
        if (cases[i].expect_invalid) {
            TEST_CHECK_((mxcsr & 1) != 0,
                        "%s did not set MXCSR.Invalid", cases[i].name);
        }
        OK(uc_close(uc));
    }
}

static void test_x86_mmx_writes_set_x87_exponent(void)
{
    static const struct {
        const char *name;
        uint8_t opcode;
        uint8_t modrm;
        uint8_t suffix;
        uint8_t fxch_modrm;
        uint16_t expected_sign_exponent;
    } cases[] = {
        {"PXOR mm0", 0xef, 0xc0, 0x90, 0xc8, UINT16_MAX},
        {"PADDB mm1", 0xfc, 0xc9, 0x90, 0xc9, UINT16_MAX},
        {"PMOVMSKB control", 0xd7, 0xc8, 0x90, 0xc8, 0},
        {"PEXTRW control", 0xc5, 0xc8, 0x00, 0xc8, 0},
        {"MASKMOVQ control", 0xf7, 0xc0, 0x90, 0xc8, 0},
        {"MOVNTQ control", 0xe7, 0x00, 0x90, 0xc8, 0},
        {"MOVD from MMX control", 0x7e, 0xc1, 0x90, 0xc8, 0},
        {"MOVQ from MMX control", 0x7f, 0x00, 0x90, 0xc8, 0},
    };
    const uint64_t result_address = code_start + 0x100;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t code[] = {
            0x9b, 0xdb, 0xe3, /* finit */
            0xd9, 0xee,       /* fldz */
            0xd9, 0xee,       /* fldz */
            0xd9, 0xee,       /* fldz */
            0xd9, 0xee,       /* fldz */
            0xd9, 0xee,       /* fldz */
            0xd9, 0xee,       /* fldz */
            0xd9, 0xee,       /* fldz */
            0xd9, 0xee,       /* fldz */
            0x0f, 0x00, 0xc0, /* MMX operation, patched per case */
            0x90,             /* immediate or padding nop */
            0xd9, 0xc8,       /* fxch st(0/1) to select the destination */
            0xdb, 0x38,       /* fstp tbyte ptr [rax] */
        };
        X87Reg result = {0};
        uint64_t significand;
        uint16_t sign_exponent;
        uc_engine *uc;

        code[20] = cases[i].opcode;
        code[21] = cases[i].modrm;
        code[22] = cases[i].suffix;
        code[24] = cases[i].fxch_modrm;
        uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, (const char *)code,
                        sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &result_address));
        OK(uc_reg_write(uc, UC_X86_REG_RDI, &result_address));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_mem_read(uc, result_address, result.bytes,
                       sizeof(result.bytes)));
        x87_reg_unpack(&result, &significand, &sign_exponent);

        TEST_CHECK_(significand == 0,
                    "%s stored significand 0x%016" PRIx64 ", expected 0",
                    cases[i].name, significand);
        TEST_CHECK_(sign_exponent == cases[i].expected_sign_exponent,
                    "%s stored sign/exponent 0x%04" PRIx16
                    ", expected 0x%04" PRIx16,
                    cases[i].name, sign_exponent,
                    cases[i].expected_sign_exponent);
        OK(uc_close(uc));
    }

    {
        static const uint8_t pshufb[] = {
            0x9b, 0xdb, 0xe3,       /* finit */
            0xd9, 0xee,             /* fldz: TOP=7, only ST0 valid */
            0x0f, 0x38, 0x00, 0xc0, /* pshufb mm0, mm0 */
            0x0f, 0xae, 0x07,       /* fxsave [rdi] */
        };
        static const uint8_t palignr[] = {
            0x9b, 0xdb, 0xe3,             /* finit */
            0xd9, 0xee,                   /* fldz: TOP=7, only ST0 valid */
            0x0f, 0x3a, 0x0f, 0xc0, 0x00, /* palignr mm0, mm0, 0 */
            0x0f, 0xae, 0x07,             /* fxsave [rdi] */
        };
        static const struct {
            const char *name;
            const uint8_t *code;
            size_t size;
        } state_cases[] = {
            {"PSHUFB", pshufb, sizeof(pshufb)},
            {"PALIGNR", palignr, sizeof(palignr)},
        };
        const uint64_t save_area = code_start + 0x100;

        for (size_t i = 0;
             i < sizeof(state_cases) / sizeof(state_cases[0]); ++i) {
            uint8_t saved[512];
            uint16_t fsw;
            uc_engine *uc;

            memset(saved, 0xcc, sizeof(saved));
            uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                                state_cases[i].code, state_cases[i].size);
            OK(uc_mem_write(uc, save_area, saved, sizeof(saved)));
            OK(uc_reg_write(uc, UC_X86_REG_RDI, &save_area));
            OK(uc_emu_start(uc, code_start,
                            code_start + state_cases[i].size, 0, 0));
            OK(uc_mem_read(uc, save_area, saved, sizeof(saved)));

            memcpy(&fsw, &saved[2], sizeof(fsw));
            TEST_CHECK_(saved[4] == 0xff,
                        "%s left abridged FTW at 0x%02x, expected 0xff",
                        state_cases[i].name, saved[4]);
            TEST_CHECK_((fsw & 0x3800) == 0,
                        "%s left x87 TOP at %u, expected 0",
                        state_cases[i].name, (fsw >> 11) & 7);
            OK(uc_close(uc));
        }
    }
}

static void test_x86_sysretq_rejects_noncanonical_rcx(void)
{
    static const uint8_t code[] = {
        0x48, 0x0f, 0x07, /* sysretq */
        0x90,             /* canonical return target: nop */
    };
    const uint64_t canonical_rip = code_start + 3;
    const uint64_t noncanonical_rip = UINT64_C(0x0000800000000000);

    for (int scenario = 0; scenario < 3; ++scenario) {
        const bool valid = scenario == 2;
        const bool catch_fault = scenario == 1;
        uc_x86_msr efer = {.rid = UINT32_C(0xc0000080)};
        uc_x86_msr star = {
            .rid = UINT32_C(0xc0000081),
            .value = UINT64_C(0x0010) << 48,
        };
        uint64_t rcx = valid ? canonical_rip : noncanonical_rip;
        uint64_t rsp = UINT64_C(0x1122334455667788);
        uint64_t r11;
        uint64_t rip_after = 0;
        uint64_t rcx_after = 0;
        uint64_t rsp_after = 0;
        uint64_t r11_after = 0;
        uint64_t rflags_before = 0;
        uint64_t rflags_after = 0;
        uint16_t cs_before = 0;
        uint16_t ss_before = 0;
        uint16_t cs_after = 0;
        uint16_t ss_after = 0;
        TestX86InterruptRecord record = {0};
        uc_engine *uc;
        uc_hook hook = 0;
        uc_err err;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, code,
                            sizeof(code));
        OK(uc_reg_read(uc, UC_X86_REG_MSR, &efer));
        efer.value |= 1; /* IA32_EFER.SCE */
        OK(uc_reg_write(uc, UC_X86_REG_MSR, &efer));
        OK(uc_reg_write(uc, UC_X86_REG_MSR, &star));
        OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));
        OK(uc_reg_read(uc, UC_X86_REG_CS, &cs_before));
        OK(uc_reg_read(uc, UC_X86_REG_SS, &ss_before));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags_before));
        r11 = rflags_before ^ (UINT64_C(1) << 9); /* Toggle IF. */
        OK(uc_reg_write(uc, UC_X86_REG_R11, &r11));
        if (catch_fault) {
            OK(uc_hook_add(uc, &hook, UC_HOOK_INTR,
                           test_x86_record_interrupt, &record, 1, 0));
        }

        err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip_after));
        OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx_after));
        OK(uc_reg_read(uc, UC_X86_REG_RSP, &rsp_after));
        OK(uc_reg_read(uc, UC_X86_REG_R11, &r11_after));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags_after));
        OK(uc_reg_read(uc, UC_X86_REG_CS, &cs_after));
        OK(uc_reg_read(uc, UC_X86_REG_SS, &ss_after));

        if (valid) {
            TEST_CHECK(err == UC_ERR_OK);
            TEST_CHECK(rip_after == code_start + sizeof(code));
            TEST_CHECK(cs_after == 0x23);
            TEST_CHECK(ss_after == 0x1b);
            TEST_CHECK((rflags_after & (UINT64_C(1) << 9)) ==
                       (r11 & (UINT64_C(1) << 9)));
        } else {
            if (catch_fault) {
                TEST_CHECK(err == UC_ERR_OK);
                TEST_CHECK(record.count == 1);
                TEST_CHECK(record.intno == 13); /* #GP */
            } else {
                TEST_CHECK(err == UC_ERR_EXCEPTION);
            }
            TEST_CHECK(rip_after == code_start);
            TEST_CHECK(cs_after == cs_before);
            TEST_CHECK(ss_after == ss_before);
            TEST_CHECK(rflags_after == rflags_before);
        }
        TEST_CHECK(rcx_after == rcx);
        TEST_CHECK(rsp_after == rsp);
        TEST_CHECK(r11_after == r11);
        if (catch_fault) {
            OK(uc_hook_del(uc, hook));
        }
        OK(uc_close(uc));
    }
}

#define TEST_X86_XSTATE_FP          (UINT64_C(1) << 0)
#define TEST_X86_XSTATE_SSE         (UINT64_C(1) << 1)
#define TEST_X86_XSTATE_YMM         (UINT64_C(1) << 2)
#define TEST_X86_XSTATE_OPMASK      (UINT64_C(1) << 5)
#define TEST_X86_XSTATE_ZMM_HI256   (UINT64_C(1) << 6)
#define TEST_X86_XSTATE_HI16_ZMM    (UINT64_C(1) << 7)
#define TEST_X86_XSTATE_XTILE_CFG   (UINT64_C(1) << 17)
#define TEST_X86_XSTATE_XTILE_DATA  (UINT64_C(1) << 18)
#define TEST_X86_XSTATE_APX         (UINT64_C(1) << 19)

static uint64_t test_x86_amx_enabled_xcr0(void)
{
    return TEST_X86_XSTATE_FP | TEST_X86_XSTATE_SSE |
           TEST_X86_XSTATE_YMM | TEST_X86_XSTATE_OPMASK |
           TEST_X86_XSTATE_ZMM_HI256 | TEST_X86_XSTATE_HI16_ZMM |
           TEST_X86_XSTATE_XTILE_CFG | TEST_X86_XSTATE_XTILE_DATA |
           TEST_X86_XSTATE_APX;
}

static void test_x86_amx_enable_guest_state(uc_engine *uc)
{
    uint64_t cr4;
    uint64_t xcr0 = test_x86_amx_enabled_xcr0();

    OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
    cr4 |= UINT64_C(1) << 18; /* CR4.OSXSAVE */
    OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));
    OK(uc_reg_write(uc, UC_X86_REG_XCR0, &xcr0));
}

static void test_x86_amx_setup_cpu(uc_engine **uc, const uint8_t *code,
                                   size_t size)
{
    uc_common_setup_cpu(uc, UC_MODE_64, UC_CPU_X86_APX, code, size);
    test_x86_amx_enable_guest_state(*uc);
}

static void test_x86_amx_read_cpuid(uc_engine *uc, uint32_t leaf,
                                    uint32_t subleaf, uint32_t output[4])
{
    uint32_t eax = leaf;
    uint32_t ebx;
    uint32_t ecx = subleaf;
    uint32_t edx;

    OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
    OK(uc_emu_start(uc, code_start, code_start + 2, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_read(uc, UC_X86_REG_EBX, &ebx));
    OK(uc_reg_read(uc, UC_X86_REG_ECX, &ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &edx));
    output[0] = eax;
    output[1] = ebx;
    output[2] = ecx;
    output[3] = edx;
}

static uint64_t test_x86_amx_read_xinuse(uc_engine *uc, uint64_t pc)
{
    uint32_t ecx = 1;
    uint64_t value;

    OK(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
    OK(uc_emu_start(uc, pc, pc + 3, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &value));
    return value;
}

static void test_x86_amx_guest_cpuid_xstate_and_xsave(void)
{
    static const uint8_t cpuid[] = {0x0f, 0xa2};
    static const uint8_t xsetbv[] = {0x0f, 0x01, 0xd1};
    static const uint8_t ldtilecfg[] = {
        0xc4, 0xe2, 0x78, 0x49, 0x00, /* ldtilecfg [rax] */
    };
    static const uint8_t tilezero_tmm1[] = {
        0xc4, 0xe2, 0x7b, 0x49, 0xc8, /* tilezero tmm1 */
    };
    static const uint8_t tileload_tmm2[] = {
        0xc4, 0xe2, 0x7b, 0x4b, 0x14, 0x08,
        /* tileloadd tmm2,[rax+rcx] */
    };
    static const uint8_t tileload_tmm3[] = {
        0xc4, 0xe2, 0x7b, 0x4b, 0x1c, 0x0b,
        /* tileloadd tmm3,[rbx+rcx] */
    };
    static const uint8_t tdpbuud[] = {
        0xc4, 0xe2, 0x60, 0x5e, 0xca, /* tdpbuud tmm1,tmm2,tmm3 */
    };
    static const uint8_t xgetbv[] = {0x0f, 0x01, 0xd0};
    static const uint8_t xsaveopt[] = {0x0f, 0xae, 0x37};
    static const uint8_t xrstor[] = {0x0f, 0xae, 0x2f};
    static const uint8_t tilerelease[] = {
        0xc4, 0xe2, 0x78, 0x49, 0xc0,
    };
    const uint64_t base_xcr0 =
        TEST_X86_XSTATE_FP | TEST_X86_XSTATE_SSE | TEST_X86_XSTATE_YMM;
    const uint64_t avx512_xstate =
        TEST_X86_XSTATE_OPMASK | TEST_X86_XSTATE_ZMM_HI256 |
        TEST_X86_XSTATE_HI16_ZMM;
    const uint64_t tile_xstate =
        TEST_X86_XSTATE_XTILE_CFG | TEST_X86_XSTATE_XTILE_DATA;

    {
        uint32_t regs[4];
        uc_engine *uc;

        test_x86_amx_setup_cpu(&uc, cpuid, sizeof(cpuid));
        test_x86_amx_read_cpuid(uc, 7, 0, regs);
        TEST_CHECK((regs[3] & ((UINT32_C(1) << 22) |
                               (UINT32_C(1) << 24) |
                               (UINT32_C(1) << 25))) ==
                   ((UINT32_C(1) << 22) | (UINT32_C(1) << 24) |
                    (UINT32_C(1) << 25)));
        test_x86_amx_read_cpuid(uc, 7, 1, regs);
        TEST_CHECK((regs[0] & (UINT32_C(1) << 21)) != 0);
        TEST_CHECK((regs[3] & (UINT32_C(1) << 8)) != 0);

        test_x86_amx_read_cpuid(uc, 0x1d, 0, regs);
        TEST_CHECK(regs[0] == 1 && regs[1] == 0 && regs[2] == 0 &&
                   regs[3] == 0);
        test_x86_amx_read_cpuid(uc, 0x1d, 1, regs);
        TEST_CHECK(regs[0] == UINT32_C(0x04002000));
        TEST_CHECK(regs[1] == UINT32_C(0x00080040));
        TEST_CHECK(regs[2] == 16 && regs[3] == 0);

        test_x86_amx_read_cpuid(uc, 0x1e, 0, regs);
        TEST_CHECK(regs[0] == 0);
        TEST_CHECK(regs[1] == UINT32_C(0x00004010));
        TEST_CHECK(regs[2] == 0 && regs[3] == 0);
        test_x86_amx_read_cpuid(uc, 0x1e, 1, regs);
        TEST_CHECK(regs[0] == UINT32_C(0x0000019f));
        TEST_CHECK(regs[1] == 0 && regs[2] == 0 && regs[3] == 0);

        test_x86_amx_read_cpuid(uc, 0x0d, 0, regs);
        TEST_CHECK((regs[0] & (uint32_t)(avx512_xstate | tile_xstate |
                                         TEST_X86_XSTATE_APX)) ==
                   (uint32_t)(avx512_xstate | tile_xstate |
                              TEST_X86_XSTATE_APX));
        TEST_CHECK(regs[1] == UINT32_C(0x2b00));
        TEST_CHECK(regs[2] == UINT32_C(0x2b00));
        test_x86_amx_read_cpuid(uc, 0x0d, 17, regs);
        TEST_CHECK(regs[0] == 64 && regs[1] == UINT32_C(0x0ac0) &&
                   regs[2] == 2 && regs[3] == 0);
        test_x86_amx_read_cpuid(uc, 0x0d, 18, regs);
        TEST_CHECK(regs[0] == UINT32_C(0x2000) &&
                   regs[1] == UINT32_C(0x0b00) && regs[2] == 2 &&
                   regs[3] == 0);
        OK(uc_close(uc));
    }

    {
        static const struct {
            uint64_t mask;
            bool valid;
            const char *description;
        } cases[] = {
            {TEST_X86_XSTATE_FP | TEST_X86_XSTATE_SSE |
                 TEST_X86_XSTATE_YMM | TEST_X86_XSTATE_OPMASK,
             false, "partial AVX-512 group"},
            {TEST_X86_XSTATE_FP | TEST_X86_XSTATE_SSE |
                 TEST_X86_XSTATE_OPMASK | TEST_X86_XSTATE_ZMM_HI256 |
                 TEST_X86_XSTATE_HI16_ZMM,
             false, "AVX-512 without YMM"},
            {base_xcr0 | avx512_xstate, true, "complete AVX-512 group"},
            {base_xcr0 | TEST_X86_XSTATE_XTILE_CFG, false,
             "TILECFG without TILEDATA"},
            {base_xcr0 | TEST_X86_XSTATE_XTILE_DATA, false,
             "TILEDATA without TILECFG"},
            {base_xcr0 | tile_xstate, true, "complete tile group"},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint32_t eax = (uint32_t)cases[i].mask;
            uint32_t ecx = 0;
            uint32_t edx = (uint32_t)(cases[i].mask >> 32);
            uint64_t rip = 0;
            uc_engine *uc;
            uc_err err;

            test_x86_amx_setup_cpu(&uc, xsetbv, sizeof(xsetbv));
            OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
            OK(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
            OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
            err = uc_emu_start(uc, code_start,
                               code_start + sizeof(xsetbv), 0, 0);
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(err == (cases[i].valid ? UC_ERR_OK
                                                : UC_ERR_EXCEPTION),
                        "%s returned %s", cases[i].description,
                        uc_strerror(err));
            TEST_CHECK_(rip == code_start +
                                   (cases[i].valid ? sizeof(xsetbv) : 0),
                        "%s advanced RIP incorrectly", cases[i].description);
            OK(uc_close(uc));
        }
    }

    {
        static const struct {
            int cpu_model;
            bool osxsave;
            bool complete_tile_xcr0;
            uc_err expected;
            const char *description;
        } cases[] = {
            {UC_CPU_X86_HASWELL, true, true, UC_ERR_INSN_INVALID,
             "missing AMX CPUID"},
            {UC_CPU_X86_APX, false, true, UC_ERR_INSN_INVALID,
             "CR4.OSXSAVE clear"},
            {UC_CPU_X86_APX, true, false, UC_ERR_INSN_INVALID,
             "incomplete tile XCR0"},
            {UC_CPU_X86_APX, true, true, UC_ERR_OK,
             "AMX CPUID and state enabled"},
        };
        const uint64_t config_address = code_start + 0x400;
        uint8_t config[64] = {0};

        config[0] = 1;
        config[18] = 4;
        config[49] = 1;
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint64_t cr4;
            uint64_t rax = config_address;
            uint64_t rip = 0;
            uint64_t xcr0 = test_x86_amx_enabled_xcr0();
            uc_engine *uc;
            uc_err err;

            uc_common_setup_cpu(&uc, UC_MODE_64, cases[i].cpu_model,
                                ldtilecfg, sizeof(ldtilecfg));
            OK(uc_mem_write(uc, config_address, config, sizeof(config)));
            OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
            if (cases[i].osxsave) {
                cr4 |= UINT64_C(1) << 18;
            } else {
                cr4 &= ~(UINT64_C(1) << 18);
            }
            if (!cases[i].complete_tile_xcr0) {
                xcr0 &= ~TEST_X86_XSTATE_XTILE_DATA;
            }
            OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));
            OK(uc_reg_write(uc, UC_X86_REG_XCR0, &xcr0));
            OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
            err = uc_emu_start(uc, code_start,
                               code_start + sizeof(ldtilecfg), 0, 0);
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(err == cases[i].expected, "%s returned %s",
                        cases[i].description, uc_strerror(err));
            TEST_CHECK_(rip == code_start +
                                   (cases[i].expected == UC_ERR_OK
                                        ? sizeof(ldtilecfg)
                                        : 0),
                        "%s advanced RIP incorrectly", cases[i].description);
            OK(uc_close(uc));
        }
    }

    {
        const uint64_t save_address = UINT64_C(0x10000);
        const uint64_t config_address = UINT64_C(0x14000);
        const uint64_t source2_address = UINT64_C(0x14100);
        const uint64_t source3_address = UINT64_C(0x14200);
        const uint64_t tilezero_pc = code_start + 0x20;
        const uint64_t tileload2_pc = code_start + 0x40;
        const uint64_t tileload3_pc = code_start + 0x60;
        const uint64_t compute_pc = code_start + 0x80;
        const uint64_t xgetbv_pc = code_start + 0xa0;
        const uint64_t xsaveopt_pc = code_start + 0xc0;
        const uint64_t xrstor_pc = code_start + 0xe0;
        const uint64_t tilerelease_pc = code_start + 0x100;
        uint8_t config[64] = {0};
        uint8_t invalid_config[64];
        uint8_t saved_config[64];
        uint8_t save_area[0x2b00];
        uint8_t source2[64] = {1, 2, 3, 4};
        uint8_t source3[64] = {5, 6, 7, 8};
        uint8_t tile[1024];
        uint8_t preserved_tile[1024];
        uint8_t zero_tile[1024] = {0};
        uint32_t eax;
        uint32_t ecx;
        uint32_t edx = 0;
        uint32_t dot;
        uint64_t rax;
        uint64_t rbx;
        uint64_t rdi = save_address;
        uint64_t xinuse;
        uint64_t xstate_bv;
        uc_engine *uc;

        config[0] = 1;
        for (unsigned int tile_index = 1; tile_index <= 3; ++tile_index) {
            config[16 + tile_index * 2] = 4;
            config[48 + tile_index] = 1;
        }

        test_x86_amx_setup_cpu(&uc, ldtilecfg, sizeof(ldtilecfg));
        OK(uc_mem_map(uc, save_address, 0x8000, UC_PROT_ALL));
        OK(uc_mem_write(uc, tilezero_pc, tilezero_tmm1,
                        sizeof(tilezero_tmm1)));
        OK(uc_mem_write(uc, tileload2_pc, tileload_tmm2,
                        sizeof(tileload_tmm2)));
        OK(uc_mem_write(uc, tileload3_pc, tileload_tmm3,
                        sizeof(tileload_tmm3)));
        OK(uc_mem_write(uc, compute_pc, tdpbuud, sizeof(tdpbuud)));
        OK(uc_mem_write(uc, xgetbv_pc, xgetbv, sizeof(xgetbv)));
        OK(uc_mem_write(uc, xsaveopt_pc, xsaveopt, sizeof(xsaveopt)));
        OK(uc_mem_write(uc, xrstor_pc, xrstor, sizeof(xrstor)));
        OK(uc_mem_write(uc, tilerelease_pc, tilerelease,
                        sizeof(tilerelease)));
        OK(uc_mem_write(uc, config_address, config, sizeof(config)));
        OK(uc_mem_write(uc, source2_address, source2, sizeof(source2)));
        OK(uc_mem_write(uc, source3_address, source3, sizeof(source3)));

        rax = config_address;
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_emu_start(uc, code_start,
                        code_start + sizeof(ldtilecfg), 0, 0));
        xinuse = test_x86_amx_read_xinuse(uc, xgetbv_pc);
        TEST_CHECK((xinuse & tile_xstate) == TEST_X86_XSTATE_XTILE_CFG);

        OK(uc_emu_start(uc, tilezero_pc,
                        tilezero_pc + sizeof(tilezero_tmm1), 0, 0));
        xinuse = test_x86_amx_read_xinuse(uc, xgetbv_pc);
        TEST_CHECK((xinuse & tile_xstate) == tile_xstate);

        rax = source2_address;
        rbx = source3_address;
        ecx = 0;
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
        OK(uc_emu_start(uc, tileload2_pc,
                        tileload2_pc + sizeof(tileload_tmm2), 0, 0));
        OK(uc_emu_start(uc, tileload3_pc,
                        tileload3_pc + sizeof(tileload_tmm3), 0, 0));
        OK(uc_emu_start(uc, compute_pc,
                        compute_pc + sizeof(tdpbuud), 0, 0));
        memset(tile, 0, sizeof(tile));
        OK(uc_reg_read(uc, UC_X86_REG_TMM1, tile));
        memcpy(&dot, tile, sizeof(dot));
        TEST_CHECK(dot == 70);
        xinuse = test_x86_amx_read_xinuse(uc, xgetbv_pc);
        TEST_CHECK((xinuse & tile_xstate) == tile_xstate);

        memset(save_area, 0xa5, sizeof(save_area));
        memset(&save_area[0x200], 0, 64);
        OK(uc_mem_write(uc, save_address, save_area, sizeof(save_area)));
        eax = (uint32_t)tile_xstate;
        OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
        OK(uc_reg_write(uc, UC_X86_REG_RDI, &rdi));
        OK(uc_emu_start(uc, xsaveopt_pc,
                        xsaveopt_pc + sizeof(xsaveopt), 0, 0));
        OK(uc_mem_read(uc, save_address + 0x200, &xstate_bv,
                       sizeof(xstate_bv)));
        TEST_CHECK((xstate_bv & tile_xstate) == tile_xstate);
        memset(saved_config, 0, sizeof(saved_config));
        OK(uc_mem_read(uc, save_address + 0xac0, saved_config,
                       sizeof(saved_config)));
        TEST_CHECK(memcmp(saved_config, config, sizeof(config)) == 0);
        OK(uc_mem_read(uc, save_address + 0xb00 + 1024, &dot,
                       sizeof(dot)));
        TEST_CHECK(dot == 70);
        OK(uc_mem_read(uc, save_address + 0xb00 + 2 * 1024, tile,
                       sizeof(tile)));
        TEST_CHECK(memcmp(tile, source2, 4) == 0);
        OK(uc_mem_read(uc, save_address + 0xb00 + 3 * 1024, tile,
                       sizeof(tile)));
        TEST_CHECK(memcmp(tile, source3, 4) == 0);

        OK(uc_emu_start(uc, tilerelease_pc,
                        tilerelease_pc + sizeof(tilerelease), 0, 0));
        xinuse = test_x86_amx_read_xinuse(uc, xgetbv_pc);
        TEST_CHECK((xinuse & tile_xstate) == 0);

        eax = (uint32_t)TEST_X86_XSTATE_XTILE_DATA;
        OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
        OK(uc_reg_write(uc, UC_X86_REG_RDI, &rdi));
        OK(uc_emu_start(uc, xrstor_pc,
                        xrstor_pc + sizeof(xrstor), 0, 0));
        memset(saved_config, 0xa5, sizeof(saved_config));
        memset(tile, 0, sizeof(tile));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, saved_config));
        OK(uc_reg_read(uc, UC_X86_REG_TMM1, tile));
        memcpy(&dot, tile, sizeof(dot));
        TEST_CHECK(memcmp(saved_config, (uint8_t[64]){0}, 64) == 0);
        TEST_CHECK(dot == 70);
        xinuse = test_x86_amx_read_xinuse(uc, xgetbv_pc);
        TEST_CHECK((xinuse & tile_xstate) == TEST_X86_XSTATE_XTILE_DATA);

        eax = (uint32_t)TEST_X86_XSTATE_XTILE_CFG;
        OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
        OK(uc_reg_write(uc, UC_X86_REG_RDI, &rdi));
        OK(uc_emu_start(uc, xrstor_pc,
                        xrstor_pc + sizeof(xrstor), 0, 0));
        memset(saved_config, 0, sizeof(saved_config));
        memset(tile, 0, sizeof(tile));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, saved_config));
        OK(uc_reg_read(uc, UC_X86_REG_TMM1, tile));
        memcpy(&dot, tile, sizeof(dot));
        TEST_CHECK(memcmp(saved_config, config, sizeof(config)) == 0);
        TEST_CHECK(dot == 70);
        xinuse = test_x86_amx_read_xinuse(uc, xgetbv_pc);
        TEST_CHECK((xinuse & tile_xstate) == tile_xstate);

        xstate_bv = TEST_X86_XSTATE_XTILE_CFG;
        OK(uc_mem_write(uc, save_address + 0x200, &xstate_bv,
                        sizeof(xstate_bv)));
        eax = (uint32_t)TEST_X86_XSTATE_XTILE_DATA;
        OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
        OK(uc_emu_start(uc, xrstor_pc,
                        xrstor_pc + sizeof(xrstor), 0, 0));
        memset(tile, 0xa5, sizeof(tile));
        OK(uc_reg_read(uc, UC_X86_REG_TMM1, tile));
        TEST_CHECK(memcmp(tile, zero_tile, sizeof(tile)) == 0);
        xinuse = test_x86_amx_read_xinuse(uc, xgetbv_pc);
        TEST_CHECK((xinuse & tile_xstate) == TEST_X86_XSTATE_XTILE_CFG);

        for (size_t i = 0; i < sizeof(preserved_tile); ++i) {
            preserved_tile[i] = (uint8_t)(i * 17 + 3);
        }
        OK(uc_reg_write(uc, UC_X86_REG_TMM1, preserved_tile));
        memcpy(invalid_config, config, sizeof(invalid_config));
        invalid_config[7] = 1;
        OK(uc_mem_write(uc, save_address + 0xac0, invalid_config,
                        sizeof(invalid_config)));
        eax = (uint32_t)TEST_X86_XSTATE_XTILE_CFG;
        OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
        OK(uc_emu_start(uc, xrstor_pc,
                        xrstor_pc + sizeof(xrstor), 0, 0));
        memset(saved_config, 0xa5, sizeof(saved_config));
        memset(tile, 0xa5, sizeof(tile));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, saved_config));
        OK(uc_reg_read(uc, UC_X86_REG_TMM1, tile));
        TEST_CHECK(memcmp(saved_config, (uint8_t[64]){0}, 64) == 0);
        TEST_CHECK(memcmp(tile, preserved_tile, sizeof(tile)) == 0);
        xinuse = test_x86_amx_read_xinuse(uc, xgetbv_pc);
        TEST_CHECK((xinuse & tile_xstate) == TEST_X86_XSTATE_XTILE_DATA);

        /* Reserved standard-header bytes must fault before either requested
         * tile component is modified. */
        memset(&save_area[0x200], 0, 64);
        xstate_bv = tile_xstate;
        memcpy(&save_area[0x200], &xstate_bv, sizeof(xstate_bv));
        save_area[0x200 + 24] = 1;
        OK(uc_mem_write(uc, save_address + 0x200, &save_area[0x200], 64));
        eax = (uint32_t)tile_xstate;
        OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
        uc_assert_err(UC_ERR_EXCEPTION,
                      uc_emu_start(uc, xrstor_pc,
                                   xrstor_pc + sizeof(xrstor), 0, 0));
        memset(saved_config, 0xa5, sizeof(saved_config));
        memset(tile, 0xa5, sizeof(tile));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, saved_config));
        OK(uc_reg_read(uc, UC_X86_REG_TMM1, tile));
        TEST_CHECK(memcmp(saved_config, (uint8_t[64]){0}, 64) == 0);
        TEST_CHECK(memcmp(tile, preserved_tile, sizeof(tile)) == 0);

        memset(save_area, 0xa5, sizeof(save_area));
        OK(uc_mem_write(uc, save_address, save_area, sizeof(save_area)));
        eax = (uint32_t)tile_xstate;
        OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
        OK(uc_emu_start(uc, xsaveopt_pc,
                        xsaveopt_pc + sizeof(xsaveopt), 0, 0));
        OK(uc_mem_read(uc, save_address + 0x200, &xstate_bv,
                       sizeof(xstate_bv)));
        TEST_CHECK((xstate_bv & tile_xstate) ==
                   TEST_X86_XSTATE_XTILE_DATA);
        OK(uc_mem_read(uc, save_address + 0xac0, saved_config,
                       sizeof(saved_config)));
        TEST_CHECK(saved_config[0] == 0xa5);
        OK(uc_mem_read(uc, save_address + 0xb00 + 1024, tile,
                       sizeof(tile)));
        TEST_CHECK(memcmp(tile, preserved_tile, sizeof(tile)) == 0);
        OK(uc_close(uc));
    }
}

static void test_x86_movrs_current_encodings_and_gates(void)
{
    static const struct {
        uint8_t code[6];
        size_t size;
        uint64_t expected;
        const char *name;
    } scalar_cases[] = {
        {{0x0f, 0x38, 0x8a, 0x03}, 4, UINT64_C(0xffffffffffffff88),
         "MOVRS byte"},
        {{0x66, 0x48, 0x0f, 0x38, 0x8a, 0x03}, 6,
         UINT64_C(0xffffffffffffff88), "MOVRS byte with 66 and REX.W"},
        {{0x66, 0x0f, 0x38, 0x8b, 0x03}, 5,
         UINT64_C(0xffffffffffff7788), "MOVRS word"},
        {{0x0f, 0x38, 0x8b, 0x03}, 4, UINT64_C(0x0000000055667788),
         "MOVRS dword"},
        {{0x48, 0x0f, 0x38, 0x8b, 0x03}, 5,
         UINT64_C(0x1122334455667788), "MOVRS qword"},
        {{0x66, 0x48, 0x0f, 0x38, 0x8b, 0x03}, 6,
         UINT64_C(0x1122334455667788), "MOVRS qword with 66 and REX.W"},
    };
    const uint64_t data_address = code_start + 0x800;
    const uint64_t source = UINT64_C(0x1122334455667788);

    for (size_t i = 0; i < sizeof(scalar_cases) / sizeof(scalar_cases[0]); ++i) {
        uint64_t rax = UINT64_MAX;
        uint64_t rbx = data_address;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_APX,
                            scalar_cases[i].code, scalar_cases[i].size);
        OK(uc_mem_write(uc, data_address, &source, sizeof(source)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_emu_start(uc, code_start, code_start + scalar_cases[i].size,
                        0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        TEST_CHECK_(rax == scalar_cases[i].expected,
                    "%s produced 0x%" PRIx64, scalar_cases[i].name, rax);
        OK(uc_close(uc));
    }

    {
        static const uint8_t invalid_register[] = {0x0f, 0x38, 0x8b, 0xc3};
        static const uint8_t feature_off[] = {0x0f, 0x38, 0x8b, 0x03};
        const struct {
            const uint8_t *code;
            size_t size;
            int cpu;
            const char *name;
        } cases[] = {
            {invalid_register, sizeof(invalid_register), UC_CPU_X86_APX,
             "register-form MOVRS"},
            {feature_off, sizeof(feature_off), UC_CPU_X86_HASWELL,
             "MOVRS without CPUID"},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint64_t rbx = data_address;
            uc_engine *uc;
            uc_err err;

            uc_common_setup_cpu(&uc, UC_MODE_64, cases[i].cpu, cases[i].code,
                                cases[i].size);
            OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
            err = uc_emu_start(uc, code_start, code_start + cases[i].size,
                               0, 0);
            TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                        cases[i].name);
            OK(uc_close(uc));
        }
    }

    {
        static const uint8_t prefetchrst2[] = {0x0f, 0x18, 0x23};
        static const uint8_t prefetchrst2_66[] = {0x66, 0x0f, 0x18, 0x23};
        static const uint8_t prefetchrst2_f2[] = {0xf2, 0x0f, 0x18, 0x23};
        static const uint8_t prefetchrst2_f3[] = {0xf3, 0x0f, 0x18, 0x23};
        static const uint8_t locked_prefetchrst2[] = {
            0xf0, 0x0f, 0x18, 0x23,
        };
        static const uint8_t register_form[] = {0x0f, 0x18, 0xe3};
        const struct {
            const uint8_t *code;
            size_t size;
            int cpu;
            uc_mode mode;
            uc_err expected;
            const char *name;
        } cases[] = {
            {prefetchrst2, sizeof(prefetchrst2), UC_CPU_X86_APX, UC_MODE_64,
             UC_ERR_OK, "PREFETCHRST2 memory"},
            {prefetchrst2_66, sizeof(prefetchrst2_66), UC_CPU_X86_APX,
             UC_MODE_64, UC_ERR_OK, "66 PREFETCHRST2 memory"},
            {prefetchrst2_f2, sizeof(prefetchrst2_f2), UC_CPU_X86_APX,
             UC_MODE_64, UC_ERR_OK, "F2 PREFETCHRST2 memory"},
            {prefetchrst2_f3, sizeof(prefetchrst2_f3), UC_CPU_X86_APX,
             UC_MODE_64, UC_ERR_OK, "F3 PREFETCHRST2 memory"},
            {prefetchrst2, sizeof(prefetchrst2), UC_CPU_X86_APX, UC_MODE_32,
             UC_ERR_OK, "32-bit PREFETCHRST2 memory"},
            {prefetchrst2, sizeof(prefetchrst2), UC_CPU_X86_HASWELL,
             UC_MODE_64, UC_ERR_OK, "PREFETCHRST2 compatibility NOP"},
            {locked_prefetchrst2, sizeof(locked_prefetchrst2),
             UC_CPU_X86_APX, UC_MODE_64, UC_ERR_INSN_INVALID,
             "LOCK PREFETCHRST2 memory"},
            {register_form, sizeof(register_form), UC_CPU_X86_APX, UC_MODE_64,
             UC_ERR_INSN_INVALID, "register-form PREFETCHRST2"},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint64_t rbx = UINT64_C(0x70000000);
            uc_engine *uc;
            uc_err err;

            uc_common_setup_cpu(&uc, cases[i].mode, cases[i].cpu, cases[i].code,
                                cases[i].size);
            OK(uc_reg_write(uc, cases[i].mode == UC_MODE_32 ? UC_X86_REG_EBX
                                                            : UC_X86_REG_RBX,
                            &rbx));
            err = uc_emu_start(uc, code_start, code_start + cases[i].size,
                               0, 0);
            TEST_CHECK_(err == cases[i].expected, "%s returned %s",
                        cases[i].name, uc_strerror(err));
            OK(uc_close(uc));
        }
    }

    {
        static const struct {
            uint8_t code[6];
            const char *name;
        } cases[] = {
            {{0x62, 0xf5, 0x7f, 0x09, 0x6f, 0x03}, "VMOVRSB xmm"},
            {{0x62, 0xf5, 0xff, 0x29, 0x6f, 0x03}, "VMOVRSW ymm"},
            {{0x62, 0xf5, 0x7e, 0x49, 0x6f, 0x03}, "VMOVRSD zmm"},
            {{0x62, 0xf5, 0xfe, 0x09, 0x6f, 0x03}, "VMOVRSQ xmm"},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint64_t rbx = data_address;
            uc_engine *uc;
            uc_err err;

            test_x86_amx_setup_cpu(&uc, cases[i].code,
                                   sizeof(cases[i].code));
            OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
            err = uc_emu_start(uc, code_start,
                               code_start + sizeof(cases[i].code), 0, 0);
            TEST_CHECK_(err == UC_ERR_INSN_INVALID,
                        "%s did not fail closed without AVX10",
                        cases[i].name);
            OK(uc_close(uc));
        }
    }

    {
        static const uint8_t vmovrsb[] = {
            0x62, 0xf5, 0x7f, 0x09, 0x6f, 0x03,
        };
        const struct {
            int cpu;
            const char *name;
        } cases[] = {
            {UC_CPU_X86_HASWELL, "VMOVRS without CPUID"},
            {UC_CPU_X86_APX, "VMOVRS without enabled SIMD state"},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint64_t rbx = data_address;
            uc_engine *uc;
            uc_err err;

            uc_common_setup_cpu(&uc, UC_MODE_64, cases[i].cpu, vmovrsb,
                                sizeof(vmovrsb));
            OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
            err = uc_emu_start(uc, code_start, code_start + sizeof(vmovrsb),
                               0, 0);
            TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                        cases[i].name);
            OK(uc_close(uc));
        }
    }

    {
        static const uint8_t cpuid[] = {0x0f, 0xa2};
        static const uint8_t withdrawn_tf32[] = {
            0xc4, 0xe2, 0x79, 0x48, 0xca,
        };
        uint32_t regs[4];
        uc_engine *uc;

        test_x86_amx_setup_cpu(&uc, cpuid, sizeof(cpuid));
        test_x86_amx_read_cpuid(uc, 0x1e, 1, regs);
        TEST_CHECK((regs[0] & (UINT32_C(1) << 6)) == 0);
        OK(uc_close(uc));

        test_x86_amx_setup_cpu(&uc, withdrawn_tf32, sizeof(withdrawn_tf32));
        uc_assert_err(UC_ERR_INSN_INVALID,
                      uc_emu_start(uc, code_start,
                                   code_start + sizeof(withdrawn_tf32), 0, 0));
        OK(uc_close(uc));
    }
}

static void test_x86_apx_evex_full_width_canonical_ranges(void)
{
    static const struct {
        uint8_t code[7];
        size_t size;
        uint32_t exception;
        uint64_t rflags;
        bool movdir64b;
        const char *name;
    } cases[] = {
        {{0x62, 0xf4, 0xfc, 0x08, 0x8b, 0x10}, 6, 13,
         UINT64_C(0xcd7), false, "MOVRSQ load"},
        {{0x62, 0xf4, 0xfc, 0x08, 0x60, 0x10}, 6, 13,
         UINT64_C(0xcd7), false, "MOVBEQ load"},
        {{0x62, 0xf4, 0xfc, 0x08, 0x61, 0x10}, 6, 13,
         UINT64_C(0xcd7), false, "MOVBEQ store"},
        {{0x62, 0xf4, 0x7c, 0x08, 0xfc, 0x11}, 6, 13,
         UINT64_C(0xcd7), false, "RAO-INT dword"},
        {{0x62, 0xf4, 0xfc, 0x08, 0xfc, 0x11}, 6, 13,
         UINT64_C(0xcd7), false, "RAO-INT qword"},
        {{0x62, 0xf2, 0x65, 0x08, 0xe4, 0x11}, 6, 13,
         UINT64_C(0xcd7), false, "CMPCCXADD dword"},
        {{0x62, 0xf2, 0xe5, 0x08, 0xe4, 0x11}, 6, 13,
         UINT64_C(0xcd7), false, "CMPCCXADD qword"},
        {{0x62, 0xf4, 0xac, 0x02, 0x39, 0x10}, 6, 13,
         UINT64_C(0xcd7), false, "CCMP qword"},
        {{0x62, 0xf4, 0xac, 0x02, 0x85, 0x10}, 6, 13,
         UINT64_C(0xcd7), false, "CTEST qword"},
        {{0x62, 0xf4, 0x7d, 0x08, 0xf8, 0x10}, 6, 13,
         UINT64_C(0xcd7), true, "MOVDIR64B source"},
        {{0x62, 0xf4, 0xbc, 0x18, 0x44, 0x10}, 6, 13,
         UINT64_C(0xcd7), false, "CMOVZQ load"},
        {{0x62, 0xf1, 0x7c, 0x08, 0x90, 0x10}, 6, 13,
         UINT64_C(0xcd7), false, "KMOVW load"},
        {{0x62, 0xf4, 0xfc, 0x08, 0xf7, 0x20}, 6, 13,
         UINT64_C(0xcd7), false, "MULQ memory"},
        {{0x62, 0xf4, 0xfc, 0x08, 0xf7, 0x30}, 6, 13,
         UINT64_C(0xcd7), false, "DIVQ memory"},
        /* NF reverses the two-operand form into a conditional store.  A
         * false condition suppresses both the access and its range fault. */
        {{0x62, 0xf4, 0xfc, 0x0c, 0x44, 0x10}, 6, 0,
         UINT64_C(0xc97), false, "CFCMOVZQ false-path store"},
        {{0x62, 0xf4, 0xfc, 0x08, 0x8b, 0x55, 0x00}, 7, 12,
         UINT64_C(0xcd7), false, "RBP-default SS MOVRSQ load"},
    };
    const uint64_t boundary = UINT64_C(0x00007fffffffffff);
    const uint64_t boundary_page = boundary & ~UINT64_C(0xfff);
    const uint64_t movdir_destination = UINT64_C(0x8000);
    const uint64_t initial_rbx = UINT64_C(0x1122334455667788);
    const uint64_t initial_r8 = UINT64_C(0x8877665544332211);
    const uint64_t initial_k2 = UINT64_C(0xa5a55a5af0f00f0f);
    const uint8_t initial_boundary = 0xa5;
    uint8_t initial_destination[64];

    for (size_t byte = 0; byte < sizeof(initial_destination); ++byte) {
        initial_destination[byte] = (uint8_t)(byte * 13 + 7);
    }

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint64_t rax = boundary;
        uint64_t rcx = boundary;
        uint64_t rbp = boundary;
        uint64_t rdx = cases[i].movdir64b
                           ? movdir_destination
                           : UINT64_C(0xfeedfacecafebeef);
        uint64_t rbx = initial_rbx;
        uint64_t r8 = initial_r8;
        uint64_t k2 = initial_k2;
        uint64_t rflags = cases[i].rflags;
        uint64_t rip = 0;
        uint8_t boundary_after = 0;
        uint8_t destination_after[64];
        TestX86InterruptRecord interrupt = {0};
        int memory_access = 0;
        int emulation_memory_access;
        uc_engine *uc;
        uc_hook interrupt_hook;
        uc_hook memory_hook;
        uc_err err;

        test_x86_amx_setup_cpu(&uc, cases[i].code, cases[i].size);
        OK(uc_mem_map(uc, boundary_page, 0x1000, UC_PROT_ALL));
        OK(uc_mem_map(uc, movdir_destination, 0x1000, UC_PROT_ALL));
        OK(uc_mem_write(uc, boundary, &initial_boundary,
                        sizeof(initial_boundary)));
        OK(uc_mem_write(uc, movdir_destination, initial_destination,
                        sizeof(initial_destination)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
        OK(uc_reg_write(uc, UC_X86_REG_RBP, &rbp));
        OK(uc_reg_write(uc, UC_X86_REG_RDX, &rdx));
        OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_write(uc, UC_X86_REG_R8, &r8));
        OK(uc_reg_write(uc, UC_X86_REG_K2, &k2));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_hook_add(uc, &interrupt_hook, UC_HOOK_INTR,
                       test_x86_record_interrupt, &interrupt, 1, 0));
        OK(uc_hook_add(uc, &memory_hook,
                       UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                       test_x86_cmpxchg_mem_hook, &memory_access, 1, 0));

        err = uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0);
        emulation_memory_access = memory_access;
        OK(uc_mem_read(uc, boundary, &boundary_after,
                       sizeof(boundary_after)));
        OK(uc_mem_read(uc, movdir_destination, destination_after,
                       sizeof(destination_after)));
        OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx));
        OK(uc_reg_read(uc, UC_X86_REG_RBP, &rbp));
        OK(uc_reg_read(uc, UC_X86_REG_RDX, &rdx));
        OK(uc_reg_read(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_read(uc, UC_X86_REG_R8, &r8));
        OK(uc_reg_read(uc, UC_X86_REG_K2, &k2));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == UC_ERR_OK, "%s returned %s", cases[i].name,
                    uc_strerror(err));
        TEST_CHECK_(interrupt.count == (cases[i].exception != 0) &&
                        (!cases[i].exception ||
                         interrupt.intno == cases[i].exception),
                    "%s produced exception count=%u vector=%u",
                    cases[i].name, interrupt.count, interrupt.intno);
        TEST_CHECK_(emulation_memory_access == 0,
                    "%s performed a data-memory access", cases[i].name);
        TEST_CHECK_(boundary_after == initial_boundary,
                    "%s changed the canonical boundary byte",
                    cases[i].name);
        TEST_CHECK_(memcmp(destination_after, initial_destination,
                           sizeof(destination_after)) == 0,
                    "%s changed the MOVDIR64B destination sentinel",
                    cases[i].name);
        TEST_CHECK_(rax == boundary && rcx == boundary && rbp == boundary &&
                        rdx == (cases[i].movdir64b
                                    ? movdir_destination
                                    : UINT64_C(0xfeedfacecafebeef)) &&
                        rbx == initial_rbx && r8 == initial_r8 &&
                        k2 == initial_k2,
                    "%s committed register state", cases[i].name);
        TEST_CHECK_(rflags == cases[i].rflags, "%s changed RFLAGS",
                    cases[i].name);
        TEST_CHECK_(rip == (cases[i].exception
                                ? code_start
                                : code_start + cases[i].size),
                    "%s left RIP at 0x%" PRIx64, cases[i].name, rip);

        OK(uc_hook_del(uc, memory_hook));
        OK(uc_hook_del(uc, interrupt_hook));
        OK(uc_close(uc));
    }
}

static void test_x86_amx_config_state_and_control(void)
{
    static const uint8_t ldtilecfg[] = {
        0xc4, 0xe2, 0x78, 0x49, 0x00, /* ldtilecfg [rax] */
    };
    static const uint8_t sttilecfg[] = {
        0xc4, 0xe2, 0x79, 0x49, 0x03, /* sttilecfg [rbx] */
    };
    static const uint8_t tilezero[] = {
        0xc4, 0xe2, 0x7b, 0x49, 0xd8, /* tilezero tmm3 */
    };
    static const uint8_t tilerelease[] = {
        0xc4, 0xe2, 0x78, 0x49, 0xc0, /* tilerelease */
    };
    const uint64_t config_address = code_start + 0x400;
    const uint64_t saved_address = code_start + 0x500;
    const uint64_t ldtilecfg_pc = code_start;
    const uint64_t sttilecfg_pc = code_start + 0x20;
    const uint64_t tilezero_pc = code_start + 0x40;
    const uint64_t tilerelease_pc = code_start + 0x60;
    uint8_t config[64] = {0};
    uint8_t invalid_config[64];
    uint8_t saved_config[64];
    uint8_t tile[1024];
    uint8_t result[1024];
    uint8_t zero_tile[1024] = {0};
    uint64_t rax = config_address;
    uint64_t rbx = saved_address;
    uint64_t flags = UINT64_C(0xcd7);
    uint64_t flags_before;
    uint64_t flags_after;
    uint64_t rip;
    TestX86InterruptRecord record = {0};
    uc_engine *uc;
    uc_context *context;
    uc_hook hook;
    uc_err err;

    config[0] = 1;
    config[16 + 3 * 2] = 16;
    config[48 + 3] = 2;
    for (size_t i = 0; i < sizeof(tile); ++i) {
        tile[i] = (uint8_t)(i * 29 + 7);
    }

    test_x86_amx_setup_cpu(&uc, ldtilecfg, sizeof(ldtilecfg));
    OK(uc_mem_write(uc, sttilecfg_pc, sttilecfg, sizeof(sttilecfg)));
    OK(uc_mem_write(uc, tilezero_pc, tilezero, sizeof(tilezero)));
    OK(uc_mem_write(uc, tilerelease_pc, tilerelease, sizeof(tilerelease)));
    OK(uc_mem_write(uc, config_address, config, sizeof(config)));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
    OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &flags));

    memset(saved_config, 0xa5, sizeof(saved_config));
    OK(uc_reg_read(uc, UC_X86_REG_TILECFG, saved_config));
    TEST_CHECK(memcmp(saved_config, (uint8_t[64]){0}, 64) == 0);
    OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
    OK(uc_reg_write(uc, UC_X86_REG_TMM3, tile));
    memset(saved_config, 0, sizeof(saved_config));
    memset(result, 0, sizeof(result));
    OK(uc_reg_read(uc, UC_X86_REG_TILECFG, saved_config));
    OK(uc_reg_read(uc, UC_X86_REG_TMM3, result));
    TEST_CHECK(memcmp(saved_config, config, sizeof(config)) == 0);
    TEST_CHECK(memcmp(result, tile, sizeof(tile)) == 0);

    OK(uc_context_alloc(uc, &context));
    OK(uc_context_save(uc, context));
    OK(uc_reg_write(uc, UC_X86_REG_TILECFG, (uint8_t[64]){0}));
    OK(uc_reg_write(uc, UC_X86_REG_TMM3, zero_tile));
    OK(uc_context_restore(uc, context));
    memset(saved_config, 0, sizeof(saved_config));
    memset(result, 0, sizeof(result));
    OK(uc_reg_read(uc, UC_X86_REG_TILECFG, saved_config));
    OK(uc_reg_read(uc, UC_X86_REG_TMM3, result));
    TEST_CHECK(memcmp(saved_config, config, sizeof(config)) == 0);
    TEST_CHECK(memcmp(result, tile, sizeof(tile)) == 0);
    OK(uc_context_free(context));

    OK(uc_reg_write(uc, UC_X86_REG_TMM3, tile));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &flags_before));
    OK(uc_emu_start(uc, ldtilecfg_pc, ldtilecfg_pc + sizeof(ldtilecfg), 0,
                    0));
    memset(result, 0xa5, sizeof(result));
    OK(uc_reg_read(uc, UC_X86_REG_TMM3, result));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &flags_after));
    TEST_CHECK(memcmp(result, zero_tile, sizeof(result)) == 0);
    TEST_CHECK(flags_after == flags_before);

    config[1] = 9;
    OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
    OK(uc_reg_write(uc, UC_X86_REG_TMM3, tile));
    OK(uc_emu_start(uc, tilezero_pc, tilezero_pc + sizeof(tilezero), 0, 0));
    memset(saved_config, 0, sizeof(saved_config));
    memset(result, 0xa5, sizeof(result));
    OK(uc_reg_read(uc, UC_X86_REG_TILECFG, saved_config));
    OK(uc_reg_read(uc, UC_X86_REG_TMM3, result));
    TEST_CHECK(saved_config[1] == 0);
    TEST_CHECK(memcmp(result, zero_tile, sizeof(result)) == 0);

    OK(uc_emu_start(uc, sttilecfg_pc, sttilecfg_pc + sizeof(sttilecfg), 0,
                    0));
    memset(saved_config, 0xa5, sizeof(saved_config));
    OK(uc_mem_read(uc, saved_address, saved_config, sizeof(saved_config)));
    config[1] = 0;
    TEST_CHECK(memcmp(saved_config, config, sizeof(config)) == 0);

    OK(uc_reg_write(uc, UC_X86_REG_TMM3, tile));
    memcpy(invalid_config, config, sizeof(invalid_config));
    invalid_config[7] = 1;
    OK(uc_mem_write(uc, config_address, invalid_config,
                    sizeof(invalid_config)));
    OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_x86_record_interrupt,
                   &record, 1, 0));
    err = uc_emu_start(uc, ldtilecfg_pc,
                       ldtilecfg_pc + sizeof(ldtilecfg), 0, 0);
    TEST_CHECK(err == UC_ERR_OK);
    TEST_CHECK(record.count == 1 && record.intno == 13);
    memset(saved_config, 0, sizeof(saved_config));
    memset(result, 0, sizeof(result));
    OK(uc_reg_read(uc, UC_X86_REG_TILECFG, saved_config));
    OK(uc_reg_read(uc, UC_X86_REG_TMM3, result));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    TEST_CHECK(memcmp(saved_config, config, sizeof(config)) == 0);
    TEST_CHECK(memcmp(result, tile, sizeof(tile)) == 0);
    TEST_CHECK(rip == ldtilecfg_pc);
    OK(uc_hook_del(uc, hook));

    memset(invalid_config, 0xa5, sizeof(invalid_config));
    invalid_config[0] = 0;
    OK(uc_mem_write(uc, config_address, invalid_config,
                    sizeof(invalid_config)));
    OK(uc_emu_start(uc, ldtilecfg_pc, ldtilecfg_pc + sizeof(ldtilecfg), 0,
                    0));
    memset(saved_config, 0xa5, sizeof(saved_config));
    memset(result, 0xa5, sizeof(result));
    OK(uc_reg_read(uc, UC_X86_REG_TILECFG, saved_config));
    OK(uc_reg_read(uc, UC_X86_REG_TMM3, result));
    TEST_CHECK(memcmp(saved_config, (uint8_t[64]){0}, 64) == 0);
    TEST_CHECK(memcmp(result, zero_tile, sizeof(result)) == 0);

    OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
    OK(uc_reg_write(uc, UC_X86_REG_TMM3, tile));
    OK(uc_emu_start(uc, tilerelease_pc,
                    tilerelease_pc + sizeof(tilerelease), 0, 0));
    memset(saved_config, 0xa5, sizeof(saved_config));
    memset(result, 0xa5, sizeof(result));
    OK(uc_reg_read(uc, UC_X86_REG_TILECFG, saved_config));
    OK(uc_reg_read(uc, UC_X86_REG_TMM3, result));
    TEST_CHECK(memcmp(saved_config, (uint8_t[64]){0}, 64) == 0);
    TEST_CHECK(memcmp(result, zero_tile, sizeof(result)) == 0);

    err = uc_emu_start(uc, tilezero_pc, tilezero_pc + sizeof(tilezero), 0, 0);
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    TEST_CHECK(err == UC_ERR_INSN_INVALID);
    TEST_CHECK(rip == tilezero_pc);
    OK(uc_close(uc));
}

static void test_x86_amx_vex_ignored_extension_bits(void)
{
    enum {
        TEST_X86_AMX_LOAD_CONFIG,
        TEST_X86_AMX_STORE_CONFIG,
        TEST_X86_AMX_RELEASE,
        TEST_X86_AMX_ZERO,
    };
    static const struct {
        uint8_t code[5];
        unsigned int operation;
        const char *name;
    } cases[] = {
        {{0xc4, 0x62, 0x78, 0x49, 0x00}, TEST_X86_AMX_LOAD_CONFIG,
         "LDTILECFG ignored VEX.R"},
        {{0xc4, 0xa2, 0x78, 0x49, 0x00}, TEST_X86_AMX_LOAD_CONFIG,
         "LDTILECFG ignored VEX.X"},
        {{0xc4, 0x62, 0x79, 0x49, 0x03}, TEST_X86_AMX_STORE_CONFIG,
         "STTILECFG ignored VEX.R"},
        {{0xc4, 0xa2, 0x79, 0x49, 0x03}, TEST_X86_AMX_STORE_CONFIG,
         "STTILECFG ignored VEX.X"},
        {{0xc4, 0x62, 0x78, 0x49, 0xc0}, TEST_X86_AMX_RELEASE,
         "TILERELEASE ignored VEX.R"},
        {{0xc4, 0xa2, 0x78, 0x49, 0xc0}, TEST_X86_AMX_RELEASE,
         "TILERELEASE ignored VEX.X"},
        {{0xc4, 0xc2, 0x78, 0x49, 0xc0}, TEST_X86_AMX_RELEASE,
         "TILERELEASE ignored VEX.B"},
        {{0xc4, 0xa2, 0x7b, 0x49, 0xd8}, TEST_X86_AMX_ZERO,
         "TILEZERO ignored VEX.X"},
        {{0xc4, 0xc2, 0x7b, 0x49, 0xd8}, TEST_X86_AMX_ZERO,
         "TILEZERO ignored VEX.B"},
    };
    const uint64_t config_address = code_start + 0x800;
    const uint64_t saved_address = code_start + 0x900;
    uint8_t config[64] = {0};
    uint8_t tile[1024];
    uint8_t zero_tile[1024] = {0};

    config[0] = 1;
    config[16 + 3 * 2] = 16;
    config[48 + 3] = 2;
    for (size_t byte = 0; byte < sizeof(tile); ++byte) {
        tile[byte] = (uint8_t)(byte * 29 + 7);
    }

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t config_after[64];
        uint8_t saved_after[64];
        uint8_t tile_after[1024];
        uint64_t rax = config_address;
        uint64_t rbx = saved_address;
        uint64_t rflags = UINT64_C(0xcd7);
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        memset(saved_after, 0xa5, sizeof(saved_after));
        test_x86_amx_setup_cpu(&uc, cases[i].code, sizeof(cases[i].code));
        OK(uc_mem_write(uc, config_address, config, sizeof(config)));
        OK(uc_mem_write(uc, saved_address, saved_after,
                        sizeof(saved_after)));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM3, tile));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err = uc_emu_start(uc, code_start,
                           code_start + sizeof(cases[i].code), 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config_after));
        OK(uc_reg_read(uc, UC_X86_REG_TMM3, tile_after));
        OK(uc_mem_read(uc, saved_address, saved_after,
                       sizeof(saved_after)));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == UC_ERR_OK, "%s returned %s", cases[i].name,
                    uc_strerror(err));
        TEST_CHECK_(memcmp(config_after,
                           cases[i].operation == TEST_X86_AMX_RELEASE
                               ? (uint8_t[64]){0}
                               : config,
                           sizeof(config_after)) == 0,
                    "%s produced the wrong TILECFG state", cases[i].name);
        TEST_CHECK_(memcmp(tile_after,
                           cases[i].operation == TEST_X86_AMX_STORE_CONFIG
                               ? tile
                               : zero_tile,
                           sizeof(tile_after)) == 0,
                    "%s produced the wrong tile state", cases[i].name);
        if (cases[i].operation == TEST_X86_AMX_STORE_CONFIG) {
            TEST_CHECK_(memcmp(saved_after, config, sizeof(saved_after)) == 0,
                        "%s stored the wrong TILECFG image", cases[i].name);
        }
        TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS",
                    cases[i].name);
        TEST_CHECK_(rip == code_start + sizeof(cases[i].code),
                    "%s did not advance RIP", cases[i].name);
        OK(uc_close(uc));
    }
}

static void test_x86_amx_tile_transfer_restart_and_invalid(void)
{
    static const uint8_t tileloadd[] = {
        0xc4, 0xe2, 0x7b, 0x4b, 0x14, 0x08, /* tileloadd tmm2,[rax+rcx] */
    };
    static const uint8_t tileloaddt1[] = {
        0xc4, 0xe2, 0x79, 0x4b, 0x14, 0x08, /* tileloaddt1 tmm2,[rax+rcx] */
    };
    static const uint8_t tilestored[] = {
        0xc4, 0xe2, 0x7a, 0x4b, 0x14, 0x0b, /* tilestored [rbx+rcx],tmm2 */
    };
    static const uint8_t tileloadd_extended[] = {
        0xc4, 0x82, 0x7b, 0x4b, 0x54, 0x65, 0x00,
        /* tileloadd tmm2,[r13+r12*2] */
    };
    static const uint8_t tileloadd_addr32_fs[] = {
        0x64, 0x67, 0xc4, 0xe2, 0x7b, 0x4b, 0x14, 0x08,
        /* tileloadd tmm2,fs:[eax+ecx] */
    };
    static const uint8_t nonsib[] = {
        0xc4, 0xe2, 0x7b, 0x4b, 0x10, /* reserved non-SIB tile load */
    };
    const uint64_t normal_base = UINT64_C(0x8000);
    const uint64_t normal_store = UINT64_C(0xa000);
    const uint64_t segmented_base = UINT64_C(0x18000);
    const uint64_t fault_load = UINT64_C(0x20000);
    const uint64_t fault_store = UINT64_C(0x30000);
    const uint64_t loadd_pc = code_start;
    const uint64_t loaddt1_pc = code_start + 0x20;
    const uint64_t stored_pc = code_start + 0x40;
    const uint64_t nonsib_pc = code_start + 0x60;
    const uint64_t extended_pc = code_start + 0x80;
    const uint64_t addr32_fs_pc = code_start + 0xa0;
    uint8_t config[64] = {0};
    uint8_t source[0x100] = {0};
    uint8_t destination[0x100];
    uint8_t tile[1024];
    uint8_t result[1024];
    uint8_t before[1024];
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t r12;
    uint64_t r13;
    uint64_t fs_base;
    uint64_t rip;
    uc_engine *uc;
    uc_err err;

    config[0] = 1;
    config[16 + 2 * 2] = 16;
    config[48 + 2] = 3;
    for (size_t i = 0; i < sizeof(source); ++i) {
        source[i] = (uint8_t)(i ^ 0x5a);
    }
    memset(tile, 0xcc, sizeof(tile));
    memset(destination, 0xa5, sizeof(destination));

    test_x86_amx_setup_cpu(&uc, tileloadd, sizeof(tileloadd));
    OK(uc_mem_map(uc, normal_base, 0x4000, UC_PROT_ALL));
    OK(uc_mem_map(uc, segmented_base, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, loaddt1_pc, tileloaddt1, sizeof(tileloaddt1)));
    OK(uc_mem_write(uc, stored_pc, tilestored, sizeof(tilestored)));
    OK(uc_mem_write(uc, nonsib_pc, nonsib, sizeof(nonsib)));
    OK(uc_mem_write(uc, extended_pc, tileloadd_extended,
                    sizeof(tileloadd_extended)));
    OK(uc_mem_write(uc, addr32_fs_pc, tileloadd_addr32_fs,
                    sizeof(tileloadd_addr32_fs)));
    OK(uc_mem_write(uc, normal_base, source, sizeof(source)));
    OK(uc_mem_write(uc, normal_store, destination, sizeof(destination)));
    OK(uc_mem_write(uc, segmented_base, source, sizeof(source)));
    OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
    OK(uc_reg_write(uc, UC_X86_REG_TMM2, tile));

    rax = normal_base;
    rcx = 32;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_emu_start(uc, loadd_pc, loadd_pc + sizeof(tileloadd), 0, 0));
    memset(result, 0, sizeof(result));
    OK(uc_reg_read(uc, UC_X86_REG_TMM2, result));
    for (size_t row = 0; row < 3; ++row) {
        TEST_CHECK(memcmp(&result[row * 64], &source[row * 32], 16) == 0);
        TEST_CHECK(memcmp(&result[row * 64 + 16],
                          (uint8_t[48]){0}, 48) == 0);
    }
    TEST_CHECK(memcmp(&result[3 * 64],
                      (uint8_t[1024 - 3 * 64]){0},
                      1024 - 3 * 64) == 0);
    OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config));
    TEST_CHECK(config[1] == 0);

    source[0] ^= 0xff;
    OK(uc_mem_write(uc, normal_base, source, sizeof(source)));
    OK(uc_emu_start(uc, loaddt1_pc, loaddt1_pc + sizeof(tileloaddt1), 0,
                    0));
    OK(uc_reg_read(uc, UC_X86_REG_TMM2, result));
    TEST_CHECK(result[0] == source[0]);

    r12 = 16;
    r13 = normal_base;
    OK(uc_reg_write(uc, UC_X86_REG_TMM2, tile));
    OK(uc_reg_write(uc, UC_X86_REG_R12, &r12));
    OK(uc_reg_write(uc, UC_X86_REG_R13, &r13));
    OK(uc_emu_start(uc, extended_pc,
                    extended_pc + sizeof(tileloadd_extended), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_TMM2, result));
    for (size_t row = 0; row < 3; ++row) {
        TEST_CHECK(memcmp(&result[row * 64], &source[row * 32], 16) == 0);
    }

    rax = UINT64_C(0xfeed000000008000);
    rcx = UINT64_C(0x1234000000000020);
    fs_base = UINT64_C(0x10000);
    OK(uc_mem_write(uc, segmented_base, source, sizeof(source)));
    OK(uc_reg_write(uc, UC_X86_REG_TMM2, tile));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_reg_write(uc, UC_X86_REG_FS_BASE, &fs_base));
    OK(uc_emu_start(uc, addr32_fs_pc,
                    addr32_fs_pc + sizeof(tileloadd_addr32_fs), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_TMM2, result));
    for (size_t row = 0; row < 3; ++row) {
        TEST_CHECK(memcmp(&result[row * 64], &source[row * 32], 16) == 0);
    }
    fs_base = 0;
    OK(uc_reg_write(uc, UC_X86_REG_FS_BASE, &fs_base));

    rbx = normal_store;
    rcx = 32;
    OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_emu_start(uc, stored_pc, stored_pc + sizeof(tilestored), 0, 0));
    memset(destination, 0, sizeof(destination));
    OK(uc_mem_read(uc, normal_store, destination, sizeof(destination)));
    for (size_t row = 0; row < 3; ++row) {
        TEST_CHECK(memcmp(&destination[row * 32], &result[row * 64], 16) ==
                   0);
        for (size_t byte = 16; byte < 32; ++byte) {
            TEST_CHECK(destination[row * 32 + byte] == 0xa5);
        }
    }

    OK(uc_mem_map(uc, fault_load, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, fault_load, source, 16));
    OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
    OK(uc_reg_write(uc, UC_X86_REG_TMM2, tile));
    rax = fault_load;
    rcx = 0x1000;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
    err = uc_emu_start(uc, loadd_pc, loadd_pc + sizeof(tileloadd), 0, 0);
    TEST_CHECK(err == UC_ERR_READ_UNMAPPED);
    OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config));
    OK(uc_reg_read(uc, UC_X86_REG_TMM2, result));
    TEST_CHECK(config[1] == 1);
    TEST_CHECK(memcmp(result, source, 16) == 0);
    TEST_CHECK(memcmp(&result[64], (uint8_t[1024 - 64]){0},
                      1024 - 64) == 0);

    OK(uc_mem_map(uc, fault_load + 0x1000, 0x2000, UC_PROT_ALL));
    OK(uc_mem_write(uc, fault_load + 0x1000, &source[32], 16));
    OK(uc_mem_write(uc, fault_load + 0x2000, &source[64], 16));
    OK(uc_emu_start(uc, loadd_pc, loadd_pc + sizeof(tileloadd), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config));
    OK(uc_reg_read(uc, UC_X86_REG_TMM2, result));
    TEST_CHECK(config[1] == 0);
    TEST_CHECK(memcmp(&result[64], &source[32], 16) == 0);
    TEST_CHECK(memcmp(&result[128], &source[64], 16) == 0);

    OK(uc_mem_map(uc, fault_store, 0x1000, UC_PROT_ALL));
    config[1] = 0;
    OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
    OK(uc_reg_write(uc, UC_X86_REG_TMM2, result));
    rbx = fault_store;
    rcx = 0x1000;
    OK(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
    err = uc_emu_start(uc, stored_pc, stored_pc + sizeof(tilestored), 0, 0);
    TEST_CHECK(err == UC_ERR_WRITE_UNMAPPED);
    OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config));
    TEST_CHECK(config[1] == 1);
    memset(destination, 0, 16);
    OK(uc_mem_read(uc, fault_store, destination, 16));
    TEST_CHECK(memcmp(destination, result, 16) == 0);
    OK(uc_mem_map(uc, fault_store + 0x1000, 0x2000, UC_PROT_ALL));
    OK(uc_emu_start(uc, stored_pc, stored_pc + sizeof(tilestored), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config));
    TEST_CHECK(config[1] == 0);

    memcpy(before, result, sizeof(before));
    err = uc_emu_start(uc, nonsib_pc, nonsib_pc + sizeof(nonsib), 0, 0);
    OK(uc_reg_read(uc, UC_X86_REG_TMM2, result));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    TEST_CHECK(err == UC_ERR_INSN_INVALID);
    TEST_CHECK(memcmp(result, before, sizeof(result)) == 0);
    TEST_CHECK(rip == nonsib_pc);

    config[16 + 2 * 2] = 14;
    OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
    err = uc_emu_start(uc, loadd_pc, loadd_pc + sizeof(tileloadd), 0, 0);
    TEST_CHECK(err == UC_ERR_INSN_INVALID);
    OK(uc_reg_read(uc, UC_X86_REG_TMM2, result));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    TEST_CHECK(memcmp(result, before, sizeof(result)) == 0);
    TEST_CHECK(rip == loadd_pc);
    OK(uc_close(uc));
}

static void test_x86_amx_movrs_load_semantics_and_invalid(void)
{
    static const struct {
        uint8_t code[7];
        size_t size;
        const char *name;
    } valid[] = {
        {{0xc4, 0xe2, 0x7b, 0x4a, 0x14, 0x08}, 6, "TILELOADDRS"},
        {{0xc4, 0xe2, 0x79, 0x4a, 0x14, 0x08}, 6,
         "TILELOADDRST1"},
        {{0x62, 0xf2, 0x7f, 0x08, 0x4a, 0x14, 0x08}, 7,
         "EVEX TILELOADDRS z=0"},
        {{0x62, 0xf2, 0x7f, 0x88, 0x4a, 0x14, 0x08}, 7,
         "EVEX TILELOADDRS z=1 ignored"},
    };
    static const struct {
        uint8_t code[7];
        size_t size;
        const char *description;
    } invalid[] = {
        {{0xc4, 0xe2, 0x78, 0x4a, 0x14, 0x08}, 6,
         "missing mandatory prefix"},
        {{0xc4, 0xe2, 0x7b, 0x4a, 0x10}, 5, "non-SIB memory form"},
        {{0xc4, 0xe2, 0x7b, 0x4a, 0xd0}, 5, "register form"},
        {{0xc4, 0xe2, 0x73, 0x4a, 0x14, 0x08}, 6,
         "reserved VEX.vvvv"},
        {{0xc4, 0xe2, 0xfb, 0x4a, 0x14, 0x08}, 6, "VEX.W1"},
        {{0xc4, 0xe2, 0x7f, 0x4a, 0x14, 0x08}, 6, "VEX.L1"},
        {{0xc4, 0x62, 0x7b, 0x4a, 0x14, 0x08}, 6,
         "extended tile destination"},
        {{0x62, 0x72, 0x7f, 0x08, 0x4a, 0x14, 0x08}, 7,
         "EVEX TILELOADDRS with P0.R cleared"},
        {{0x62, 0xe2, 0x7f, 0x08, 0x4a, 0x14, 0x08}, 7,
         "EVEX TILELOADDRS with P0.R' cleared"},
        {{0x62, 0x72, 0x7d, 0x08, 0x4a, 0x14, 0x08}, 7,
         "EVEX TILELOADDRST1 with P0.R cleared"},
        {{0x62, 0xe2, 0x7d, 0x08, 0x4a, 0x14, 0x08}, 7,
         "EVEX TILELOADDRST1 with P0.R' cleared"},
        {{0x62, 0x72, 0x7f, 0x08, 0x4b, 0x14, 0x08}, 7,
         "EVEX TILELOADD with P0.R cleared"},
        {{0x62, 0xe2, 0x7f, 0x08, 0x4b, 0x14, 0x08}, 7,
         "EVEX TILELOADD with P0.R' cleared"},
        {{0x62, 0x72, 0x7d, 0x08, 0x4b, 0x14, 0x08}, 7,
         "EVEX TILELOADDT1 with P0.R cleared"},
        {{0x62, 0xe2, 0x7d, 0x08, 0x4b, 0x14, 0x08}, 7,
         "EVEX TILELOADDT1 with P0.R' cleared"},
        {{0x62, 0x72, 0x7e, 0x08, 0x4b, 0x14, 0x08}, 7,
         "EVEX TILESTORED with P0.R cleared"},
        {{0x62, 0xe2, 0x7e, 0x08, 0x4b, 0x14, 0x08}, 7,
         "EVEX TILESTORED with P0.R' cleared"},
    };
    const uint64_t data_address = code_start + 0x800;
    uint8_t config[64] = {0};
    uint8_t source[64];
    uint8_t initial[1024];
    uint8_t zero_tile[1024] = {0};

    config[0] = 1;
    config[16 + 2 * 2] = 16;
    config[48 + 2] = 2;
    for (size_t i = 0; i < sizeof(source); ++i) {
        source[i] = (uint8_t)(i * 37 + 9);
    }
    memset(initial, 0xa5, sizeof(initial));

    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
        uint8_t result[1024];
        uint8_t config_after[64];
        uint64_t rax = data_address;
        uint64_t rcx = 32;
        uint64_t rip = 0;
        uc_engine *uc;

        test_x86_amx_setup_cpu(&uc, valid[i].code, valid[i].size);
        OK(uc_mem_write(uc, data_address, source, sizeof(source)));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));

        OK(uc_emu_start(uc, code_start, code_start + valid[i].size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_TMM2, result));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config_after));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK_(memcmp(result, source, 16) == 0 &&
                        memcmp(result + 64, source + 32, 16) == 0,
                    "%s row data mismatch", valid[i].name);
        TEST_CHECK_(memcmp(result + 16, (uint8_t[48]){0}, 48) == 0 &&
                        memcmp(result + 80, (uint8_t[1024 - 80]){0},
                               1024 - 80) == 0,
                    "%s inactive data mismatch", valid[i].name);
        TEST_CHECK_(config_after[1] == 0, "%s did not clear start_row",
                    valid[i].name);
        TEST_CHECK_(rip == code_start + valid[i].size,
                    "%s did not advance RIP", valid[i].name);
        OK(uc_close(uc));
    }

    /* Extended registers whose low encoding is BP retain the DS default;
     * only the architectural RBP base selects SS. */
    {
        static const struct {
            uint8_t code[8];
            int base_reg;
            const char *name;
        } cases[] = {
            {{0x62, 0xd2, 0x7f, 0x08, 0x4a, 0x54, 0x0d, 0x00},
             UC_X86_REG_R13, "R13"},
            {{0x62, 0xfa, 0x7f, 0x08, 0x4a, 0x54, 0x0d, 0x00},
             UC_X86_REG_R21, "R21"},
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            const uint64_t noncanonical = UINT64_C(0x0000800000000000);
            uint8_t result[1024];
            uint8_t config_after[64];
            uint64_t base = noncanonical;
            uint64_t rcx = 0;
            uint64_t rip = 0;
            TestX86InterruptRecord record = {0};
            uc_engine *uc;
            uc_hook hook;

            test_x86_amx_setup_cpu(&uc, cases[i].code,
                                   sizeof(cases[i].code));
            OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
            OK(uc_reg_write(uc, UC_X86_REG_TMM2, initial));
            OK(uc_reg_write(uc, cases[i].base_reg, &base));
            OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
            OK(uc_hook_add(uc, &hook, UC_HOOK_INTR,
                           test_x86_record_interrupt, &record, 1, 0));
            OK(uc_emu_start(uc, code_start,
                            code_start + sizeof(cases[i].code), 0, 0));
            OK(uc_reg_read(uc, UC_X86_REG_TMM2, result));
            OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config_after));
            OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
            TEST_CHECK_(record.count == 1 && record.intno == 13,
                        "EVEX TILELOADDRS %s did not raise #GP",
                        cases[i].name);
            TEST_CHECK_(memcmp(result, zero_tile, sizeof(result)) == 0,
                        "EVEX TILELOADDRS %s did not clear tile state",
                        cases[i].name);
            TEST_CHECK_(memcmp(config_after, config,
                               sizeof(config_after)) == 0,
                        "EVEX TILELOADDRS %s changed TILECFG",
                        cases[i].name);
            TEST_CHECK_(rip == code_start,
                        "EVEX TILELOADDRS %s advanced RIP", cases[i].name);
            OK(uc_hook_del(uc, hook));
            OK(uc_close(uc));
        }
    }

    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        uint8_t result[1024];
        uint8_t config_after[64];
        uint64_t rax = data_address;
        uint64_t rcx = 32;
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        test_x86_amx_setup_cpu(&uc,
                            invalid[i].code, invalid[i].size);
        OK(uc_mem_write(uc, data_address, source, sizeof(source)));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, initial));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));

        err = uc_emu_start(uc, code_start, code_start + invalid[i].size, 0,
                           0);
        OK(uc_reg_read(uc, UC_X86_REG_TMM2, result));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config_after));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    invalid[i].description);
        TEST_CHECK_(memcmp(result, initial, sizeof(result)) == 0,
                    "%s changed tile state", invalid[i].description);
        TEST_CHECK_(memcmp(config_after, config, sizeof(config_after)) == 0,
                    "%s changed TILECFG", invalid[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP",
                    invalid[i].description);
        OK(uc_close(uc));
    }
}

static void test_x86_amx_set_shape(uint8_t config[64], unsigned int tile,
                                   uint16_t colsb, uint8_t rows)
{
    config[16 + tile * 2] = colsb;
    config[16 + tile * 2 + 1] = colsb >> 8;
    config[48 + tile] = rows;
}

static uint32_t test_x86_amx_get_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void test_x86_amx_put_u32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = value;
    bytes[1] = value >> 8;
    bytes[2] = value >> 16;
    bytes[3] = value >> 24;
}

static void test_x86_amx_put_u16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = value;
    bytes[1] = value >> 8;
}

static int32_t test_x86_amx_byte(uint8_t value, bool is_signed)
{
    return is_signed ? (int8_t)value : value;
}

static void test_x86_amx_integer_expected(uint8_t result[1024],
                                          const uint8_t accumulator[1024],
                                          const uint8_t src1[1024],
                                          const uint8_t src2[1024],
                                          bool src1_signed,
                                          bool src2_signed)
{
    memset(result, 0, 1024);
    for (unsigned int m = 0; m < 2; ++m) {
        for (unsigned int n = 0; n < 2; ++n) {
            uint32_t value =
                test_x86_amx_get_u32(&accumulator[m * 64 + n * 4]);

            for (unsigned int k = 0; k < 2; ++k) {
                int32_t dot = 0;

                for (unsigned int lane = 0; lane < 4; ++lane) {
                    dot += test_x86_amx_byte(
                               src1[m * 64 + k * 4 + lane], src1_signed) *
                           test_x86_amx_byte(
                               src2[k * 64 + n * 4 + lane], src2_signed);
                }
                value += (uint32_t)dot;
            }
            test_x86_amx_put_u32(&result[m * 64 + n * 4], value);
        }
    }
}

static void test_x86_amx_integer_compute_semantics_and_invalid(void)
{
    static const struct {
        uint8_t vex2;
        uint8_t pp;
        bool src1_signed;
        bool src2_signed;
        const char *name;
    } operations[] = {
        {0xe2, 0x63, true, true, "TDPBSSD"},
        {0xe2, 0x62, true, false, "TDPBSUD"},
        {0xe2, 0x61, false, true, "TDPBUSD"},
        {0xe2, 0x60, false, false, "TDPBUUD"},
        {0xa2, 0x60, false, false, "TDPBUUD with ignored VEX.X"},
    };
    static const struct {
        uint8_t code[5];
        bool bad_shape;
        const char *description;
    } invalid[] = {
        {{0xc4, 0xe2, 0x63, 0x5e, 0xc9}, false,
         "destination aliases first source"},
        {{0xc4, 0xe2, 0x73, 0x5e, 0xca}, false,
         "destination aliases second source"},
        {{0xc4, 0xe2, 0x6b, 0x5e, 0xca}, false, "sources alias"},
        {{0xc4, 0xe2, 0x63, 0x5e, 0x0a}, false, "memory form"},
        {{0xc4, 0x62, 0x63, 0x5e, 0xca}, false,
         "extended destination"},
        {{0xc4, 0xc2, 0x63, 0x5e, 0xca}, false, "extended source"},
        {{0xc4, 0xe2, 0xe3, 0x5e, 0xca}, false, "VEX.W1"},
        {{0xc4, 0xe2, 0x67, 0x5e, 0xca}, false, "VEX.L1"},
        {{0xc4, 0xe2, 0x63, 0x5e, 0xca}, true, "shape mismatch"},
    };
    uint8_t config[64] = {0};
    uint8_t accumulator[1024];
    uint8_t src1[1024];
    uint8_t src2[1024];
    uint8_t expected[1024];

    config[0] = 1;
    config[1] = 9;
    test_x86_amx_set_shape(config, 1, 8, 2);
    test_x86_amx_set_shape(config, 2, 8, 2);
    test_x86_amx_set_shape(config, 3, 8, 2);
    memset(accumulator, 0xa5, sizeof(accumulator));
    memset(src1, 0x5a, sizeof(src1));
    memset(src2, 0xc3, sizeof(src2));
    for (unsigned int row = 0; row < 2; ++row) {
        for (unsigned int byte = 0; byte < 8; ++byte) {
            src1[row * 64 + byte] =
                (uint8_t)(row * 73 + byte * 61 + 0x80);
            src2[row * 64 + byte] =
                (uint8_t)(row * 47 + byte * 37 + 0x7f);
        }
        test_x86_amx_put_u32(&accumulator[row * 64],
                             UINT32_C(0xfffffff0) + row);
        test_x86_amx_put_u32(&accumulator[row * 64 + 4],
                             UINT32_C(0x7ffffff0) - row);
    }

    for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i) {
        uint8_t code[] = {
            0xc4, operations[i].vex2, operations[i].pp, 0x5e, 0xca,
        };
        uint8_t result[1024];
        uint8_t src1_after[1024];
        uint8_t src2_after[1024];
        uint8_t config_after[64];
        uint64_t rflags = UINT64_C(0xcd7);
        uint64_t rip = 0;
        uc_engine *uc;

        test_x86_amx_integer_expected(
            expected, accumulator, src1, src2, operations[i].src1_signed,
            operations[i].src2_signed);
        test_x86_amx_setup_cpu(&uc, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM1, accumulator));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, src1));
        OK(uc_reg_write(uc, UC_X86_REG_TMM3, src2));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_TMM1, result));
        OK(uc_reg_read(uc, UC_X86_REG_TMM2, src1_after));
        OK(uc_reg_read(uc, UC_X86_REG_TMM3, src2_after));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config_after));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(memcmp(result, expected, sizeof(result)) == 0,
                    "%s result or inactive zeroing mismatch",
                    operations[i].name);
        TEST_CHECK_(memcmp(src1_after, src1, sizeof(src1)) == 0 &&
                        memcmp(src2_after, src2, sizeof(src2)) == 0,
                    "%s changed a source tile", operations[i].name);
        TEST_CHECK_(config_after[1] == 0, "%s did not clear start_row",
                    operations[i].name);
        TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS",
                    operations[i].name);
        TEST_CHECK_(rip == code_start + sizeof(code),
                    "%s did not advance RIP", operations[i].name);
        OK(uc_close(uc));
    }

    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        uint8_t invalid_config[64];
        uint8_t result[1024];
        uint8_t src1_after[1024];
        uint8_t src2_after[1024];
        uint8_t config_after[64];
        uint64_t rflags = UINT64_C(0xcd7);
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        memcpy(invalid_config, config, sizeof(invalid_config));
        if (invalid[i].bad_shape) {
            test_x86_amx_set_shape(invalid_config, 3, 8, 1);
        }
        test_x86_amx_setup_cpu(&uc,
                            invalid[i].code, sizeof(invalid[i].code));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, invalid_config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM1, accumulator));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, src1));
        OK(uc_reg_write(uc, UC_X86_REG_TMM3, src2));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        err = uc_emu_start(uc, code_start, code_start + 5, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_TMM1, result));
        OK(uc_reg_read(uc, UC_X86_REG_TMM2, src1_after));
        OK(uc_reg_read(uc, UC_X86_REG_TMM3, src2_after));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config_after));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    invalid[i].description);
        TEST_CHECK_(memcmp(result, accumulator, sizeof(result)) == 0 &&
                        memcmp(src1_after, src1, sizeof(src1)) == 0 &&
                        memcmp(src2_after, src2, sizeof(src2)) == 0,
                    "%s changed tile state", invalid[i].description);
        TEST_CHECK_(memcmp(config_after, invalid_config,
                           sizeof(config_after)) == 0,
                    "%s changed TILECFG", invalid[i].description);
        TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS",
                    invalid[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP",
                    invalid[i].description);
        OK(uc_close(uc));
    }
}

typedef enum TestX86AmxFloatInput {
    TEST_X86_AMX_BF16,
    TEST_X86_AMX_FP16,
    TEST_X86_AMX_COMPLEX_REAL,
    TEST_X86_AMX_COMPLEX_IMAG,
    TEST_X86_AMX_BF8_BF8,
    TEST_X86_AMX_BF8_HF8,
    TEST_X86_AMX_HF8_BF8,
    TEST_X86_AMX_HF8_HF8,
    TEST_X86_AMX_BF16_DENORMAL,
    TEST_X86_AMX_FP16_DENORMAL,
    TEST_X86_AMX_FP8_NAN,
} TestX86AmxFloatInput;

static void test_x86_amx_floating_compute_semantics_and_invalid(void)
{
    static const struct {
        uint8_t code[5];
        TestX86AmxFloatInput input;
        uint32_t expected;
        const char *name;
    } operations[] = {
        {{0xc4, 0xe2, 0x62, 0x5c, 0xca}, TEST_X86_AMX_BF16,
         UINT32_C(0x41800000), "TDPBF16PS"},
        {{0xc4, 0xe2, 0x63, 0x5c, 0xca}, TEST_X86_AMX_FP16,
         UINT32_C(0x41800000), "TDPFP16PS"},
        {{0xc4, 0xe2, 0x60, 0x6c, 0xca}, TEST_X86_AMX_COMPLEX_REAL,
         UINT32_C(0x00000000), "TCMMRLFP16PS"},
        {{0xc4, 0xe2, 0x61, 0x6c, 0xca}, TEST_X86_AMX_COMPLEX_IMAG,
         UINT32_C(0x41700000), "TCMMIMFP16PS"},
        {{0xc4, 0xe5, 0x60, 0xfd, 0xca}, TEST_X86_AMX_BF8_BF8,
         UINT32_C(0x41500000), "TDPBF8PS"},
        {{0xc4, 0xe5, 0x63, 0xfd, 0xca}, TEST_X86_AMX_BF8_HF8,
         UINT32_C(0x41500000), "TDPBHF8PS"},
        {{0xc4, 0xe5, 0x62, 0xfd, 0xca}, TEST_X86_AMX_HF8_BF8,
         UINT32_C(0x41500000), "TDPHBF8PS"},
        {{0xc4, 0xe5, 0x61, 0xfd, 0xca}, TEST_X86_AMX_HF8_HF8,
         UINT32_C(0x41500000), "TDPHF8PS"},
        {{0xc4, 0xe2, 0x62, 0x5c, 0xca}, TEST_X86_AMX_BF16_DENORMAL,
         UINT32_C(0x00000000), "TDPBF16PS DAZ"},
        {{0xc4, 0xe2, 0x63, 0x5c, 0xca}, TEST_X86_AMX_FP16_DENORMAL,
         UINT32_C(0x33800000), "TDPFP16PS gradual FP16 input"},
        {{0xc4, 0xe5, 0x60, 0xfd, 0xca}, TEST_X86_AMX_FP8_NAN,
         UINT32_C(0xffc00000), "TDPBF8PS NaN indefinite"},
    };
    static const struct {
        uint8_t code[5];
        const char *description;
    } invalid[] = {
        {{0xc4, 0xe2, 0x60, 0x5c, 0xca}, "unassigned opcode 5C prefix"},
        {{0xc4, 0xe2, 0x62, 0x6c, 0xca}, "unassigned opcode 6C prefix"},
        {{0xc4, 0xe2, 0x60, 0x48, 0xca}, "TF32 without 66"},
        {{0xc4, 0xe5, 0xe0, 0xfd, 0xca}, "FP8 VEX.W1"},
        {{0xc4, 0xe5, 0x64, 0xfd, 0xca}, "FP8 VEX.L1"},
        {{0xc4, 0xe5, 0x60, 0xfd, 0x0a}, "FP8 memory form"},
        {{0xc4, 0xe5, 0x70, 0xfd, 0xca}, "FP8 destination alias"},
    };
    uint8_t config[64] = {0};

    config[0] = 1;
    config[1] = 11;
    test_x86_amx_set_shape(config, 1, 4, 1);
    test_x86_amx_set_shape(config, 2, 4, 1);
    test_x86_amx_set_shape(config, 3, 4, 1);

    for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i) {
        uint8_t accumulator[1024];
        uint8_t src1[1024];
        uint8_t src2[1024];
        uint8_t result[1024];
        uint8_t expected[1024] = {0};
        uint8_t src1_after[1024];
        uint8_t src2_after[1024];
        uint8_t config_after[64];
        uint32_t mxcsr = UINT32_C(0xffc0);
        uint64_t rflags = UINT64_C(0xcd7);
        uint64_t rip = 0;
        uc_engine *uc;

        memset(accumulator, 0xa5, sizeof(accumulator));
        memset(src1, 0x5a, sizeof(src1));
        memset(src2, 0xc3, sizeof(src2));
        test_x86_amx_put_u32(accumulator, UINT32_C(0x40a00000)); /* 5 */

        switch (operations[i].input) {
        case TEST_X86_AMX_BF16:
            test_x86_amx_put_u16(src1, 0x3f80);
            test_x86_amx_put_u16(src1 + 2, 0x4000);
            test_x86_amx_put_u16(src2, 0x4040);
            test_x86_amx_put_u16(src2 + 2, 0x4080);
            break;
        case TEST_X86_AMX_FP16:
        case TEST_X86_AMX_COMPLEX_REAL:
        case TEST_X86_AMX_COMPLEX_IMAG:
            test_x86_amx_put_u16(src1, 0x3c00);
            test_x86_amx_put_u16(src1 + 2, 0x4000);
            test_x86_amx_put_u16(src2, 0x4200);
            test_x86_amx_put_u16(src2 + 2, 0x4400);
            break;
        case TEST_X86_AMX_BF8_BF8:
        case TEST_X86_AMX_BF8_HF8:
        case TEST_X86_AMX_HF8_BF8:
        case TEST_X86_AMX_HF8_HF8: {
            bool src1_hf = operations[i].input == TEST_X86_AMX_HF8_BF8 ||
                           operations[i].input == TEST_X86_AMX_HF8_HF8;
            bool src2_hf = operations[i].input == TEST_X86_AMX_BF8_HF8 ||
                           operations[i].input == TEST_X86_AMX_HF8_HF8;

            memset(src1, src1_hf ? 0x38 : 0x3c, 4);
            memset(src2, src2_hf ? 0x40 : 0x40, 4);
            break;
        }
        case TEST_X86_AMX_BF16_DENORMAL:
            test_x86_amx_put_u32(accumulator, 0);
            test_x86_amx_put_u16(src1, 0x0001);
            test_x86_amx_put_u16(src1 + 2, 0);
            test_x86_amx_put_u16(src2, 0x3f80);
            test_x86_amx_put_u16(src2 + 2, 0);
            break;
        case TEST_X86_AMX_FP16_DENORMAL:
            test_x86_amx_put_u32(accumulator, 0);
            test_x86_amx_put_u16(src1, 0x0001);
            test_x86_amx_put_u16(src1 + 2, 0);
            test_x86_amx_put_u16(src2, 0x3c00);
            test_x86_amx_put_u16(src2 + 2, 0);
            break;
        case TEST_X86_AMX_FP8_NAN:
            src1[0] = 0x7d;
            memset(src1 + 1, 0, 3);
            memset(src2, 0x3c, 4);
            break;
        }
        test_x86_amx_put_u32(expected, operations[i].expected);

        test_x86_amx_setup_cpu(&uc,
                            operations[i].code, sizeof(operations[i].code));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM1, accumulator));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, src1));
        OK(uc_reg_write(uc, UC_X86_REG_TMM3, src2));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        OK(uc_emu_start(uc, code_start, code_start + 5, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_TMM1, result));
        OK(uc_reg_read(uc, UC_X86_REG_TMM2, src1_after));
        OK(uc_reg_read(uc, UC_X86_REG_TMM3, src2_after));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config_after));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

        TEST_CHECK_(memcmp(result, expected, sizeof(result)) == 0,
                    "%s result or inactive zeroing mismatch",
                    operations[i].name);
        TEST_CHECK_(memcmp(src1_after, src1, sizeof(src1)) == 0 &&
                        memcmp(src2_after, src2, sizeof(src2)) == 0,
                    "%s changed a source tile", operations[i].name);
        TEST_CHECK_(config_after[1] == 0, "%s did not clear start_row",
                    operations[i].name);
        TEST_CHECK_(mxcsr == UINT32_C(0xffc0), "%s changed MXCSR",
                    operations[i].name);
        TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS",
                    operations[i].name);
        TEST_CHECK_(rip == code_start + 5, "%s did not advance RIP",
                    operations[i].name);
        OK(uc_close(uc));
    }

    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        uint8_t accumulator[1024];
        uint8_t src1[1024];
        uint8_t src2[1024];
        uint8_t result[1024];
        uint8_t config_after[64];
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        memset(accumulator, 0xa5, sizeof(accumulator));
        memset(src1, 0x5a, sizeof(src1));
        memset(src2, 0xc3, sizeof(src2));
        test_x86_amx_setup_cpu(&uc,
                            invalid[i].code, sizeof(invalid[i].code));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM1, accumulator));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, src1));
        OK(uc_reg_write(uc, UC_X86_REG_TMM3, src2));

        err = uc_emu_start(uc, code_start, code_start + 5, 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_TMM1, result));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config_after));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    invalid[i].description);
        TEST_CHECK_(memcmp(result, accumulator, sizeof(result)) == 0,
                    "%s changed destination", invalid[i].description);
        TEST_CHECK_(memcmp(config_after, config, sizeof(config_after)) == 0,
                    "%s changed TILECFG", invalid[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP",
                    invalid[i].description);
        OK(uc_close(uc));
    }
}

static void test_x86_amx_fp8_fixed_accumulation_and_specials(void)
{
    static const struct {
        uint8_t code[5];
        uint8_t value;
        uint32_t expected;
        const char *name;
    } finite[] = {
        {{0xc4, 0xe5, 0x60, 0xfd, 0xca}, 0x7b,
         UINT32_C(0x52440000), "E5M2 full-shape accumulation"},
        {{0xc4, 0xe5, 0x61, 0xfd, 0xca}, 0x7e,
         UINT32_C(0x4b440000), "E4M3 full-shape accumulation"},
    };
    static const struct {
        uint8_t src1[4];
        uint8_t src2[4];
        uint32_t accumulator;
        uint32_t expected;
        const char *name;
    } special[] = {
        {{0x7c, 0x00, 0x00, 0x00}, {0x3c, 0x3c, 0x3c, 0x3c}, 0,
         UINT32_C(0x7f800000), "infinity times finite"},
        {{0x7c, 0x00, 0x00, 0x00}, {0x00, 0x3c, 0x3c, 0x3c}, 0,
         UINT32_C(0xffc00000), "infinity times zero"},
        {{0x7c, 0xfc, 0x00, 0x00}, {0x3c, 0x3c, 0x3c, 0x3c}, 0,
         UINT32_C(0xffc00000), "opposite infinities"},
        {{0x7d, 0x00, 0x00, 0x00}, {0x3c, 0x3c, 0x3c, 0x3c}, 0,
         UINT32_C(0xffc00000), "FP8 NaN"},
        {{0x3c, 0x00, 0x00, 0x00}, {0x3c, 0x3c, 0x3c, 0x3c},
         UINT32_C(0x7fc00001), UINT32_C(0xffc00000),
         "accumulator NaN"},
        {{0x7b, 0x48, 0x00, 0x00}, {0x7b, 0x4c, 0x00, 0x00}, 0,
         UINT32_C(0x4f440000), "fixed-point RNE tie to even down"},
        {{0x7b, 0x48, 0x48, 0x00}, {0x7b, 0x50, 0x4c, 0x00}, 0,
         UINT32_C(0x4f440002), "fixed-point RNE tie to even up"},
    };

    for (size_t i = 0; i < sizeof(finite) / sizeof(finite[0]); ++i) {
        uint8_t config[64] = {0};
        uint8_t accumulator[1024] = {0};
        uint8_t src1[1024] = {0};
        uint8_t src2[1024] = {0};
        uint8_t result[1024];
        uint8_t expected[1024] = {0};
        uint8_t config_after[64];
        uint32_t mxcsr = UINT32_C(0xffc0);
        uc_engine *uc;

        config[0] = 1;
        config[1] = 13;
        test_x86_amx_set_shape(config, 1, 4, 1);
        test_x86_amx_set_shape(config, 2, 64, 1);
        test_x86_amx_set_shape(config, 3, 4, 16);
        memset(src1, finite[i].value, 64);
        for (size_t row = 0; row < 16; ++row) {
            memset(src2 + row * 64, finite[i].value, 4);
        }
        test_x86_amx_put_u32(expected, finite[i].expected);

        test_x86_amx_setup_cpu(&uc,
                            finite[i].code, sizeof(finite[i].code));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM1, accumulator));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, src1));
        OK(uc_reg_write(uc, UC_X86_REG_TMM3, src2));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(finite[i].code),
                        0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_TMM1, result));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config_after));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK_(memcmp(result, expected, sizeof(result)) == 0,
                    "%s result mismatch", finite[i].name);
        TEST_CHECK_(config_after[1] == 0, "%s did not clear start_row",
                    finite[i].name);
        TEST_CHECK_(mxcsr == UINT32_C(0xffc0), "%s changed MXCSR",
                    finite[i].name);
        OK(uc_close(uc));
    }

    for (size_t i = 0; i < sizeof(special) / sizeof(special[0]); ++i) {
        static const uint8_t code[] = {
            0xc4, 0xe5, 0x60, 0xfd, 0xca, /* tdpbf8ps tmm1,tmm2,tmm3 */
        };
        uint8_t config[64] = {0};
        uint8_t accumulator[1024] = {0};
        uint8_t src1[1024] = {0};
        uint8_t src2[1024] = {0};
        uint8_t result[1024];
        uint8_t expected[1024] = {0};
        uc_engine *uc;

        config[0] = 1;
        test_x86_amx_set_shape(config, 1, 4, 1);
        test_x86_amx_set_shape(config, 2, 4, 1);
        test_x86_amx_set_shape(config, 3, 4, 1);
        memcpy(src1, special[i].src1, 4);
        memcpy(src2, special[i].src2, 4);
        test_x86_amx_put_u32(accumulator, special[i].accumulator);
        test_x86_amx_put_u32(expected, special[i].expected);

        test_x86_amx_setup_cpu(&uc, code,
                            sizeof(code));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM1, accumulator));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, src1));
        OK(uc_reg_write(uc, UC_X86_REG_TMM3, src2));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_TMM1, result));
        TEST_CHECK_(memcmp(result, expected, sizeof(result)) == 0,
                    "%s result mismatch", special[i].name);
        OK(uc_close(uc));
    }
}

typedef enum TestX86AmxRowOperation {
    TEST_X86_AMX_ROW_MOVE,
    TEST_X86_AMX_ROW_D2PS,
    TEST_X86_AMX_ROW_BF16H,
    TEST_X86_AMX_ROW_BF16L,
    TEST_X86_AMX_ROW_PH16H,
    TEST_X86_AMX_ROW_PH16L,
} TestX86AmxRowOperation;

static void test_x86_amx_avx512_row_moves_and_converts(void)
{
    static const struct {
        uint8_t code[7];
        size_t size;
        TestX86AmxRowOperation operation;
        uint32_t expected_dword;
        const char *name;
    } operations[] = {
        {{0x62, 0xf2, 0x7d, 0x48, 0x4a, 0xca}, 6,
         TEST_X86_AMX_ROW_MOVE, 0, "TILEMOVROW r32"},
        {{0x62, 0xf3, 0x7d, 0x48, 0x07, 0xca, 0x01}, 7,
         TEST_X86_AMX_ROW_MOVE, 0, "TILEMOVROW imm8"},
        {{0x62, 0xf2, 0x7e, 0x48, 0x4a, 0xca}, 6,
         TEST_X86_AMX_ROW_D2PS, UINT32_C(0x40400000), "TCVTROWD2PS r32"},
        {{0x62, 0xf3, 0x7e, 0x48, 0x07, 0xca, 0x01}, 7,
         TEST_X86_AMX_ROW_D2PS, UINT32_C(0x40400000), "TCVTROWD2PS imm8"},
        {{0x62, 0xf2, 0x7f, 0x48, 0x6d, 0xca}, 6,
         TEST_X86_AMX_ROW_BF16H, UINT32_C(0x3f800000),
         "TCVTROWPS2BF16H r32"},
        {{0x62, 0xf3, 0x7f, 0x48, 0x07, 0xca, 0x01}, 7,
         TEST_X86_AMX_ROW_BF16H, UINT32_C(0x3f800000),
         "TCVTROWPS2BF16H imm8"},
        {{0x62, 0xf2, 0x7e, 0x48, 0x6d, 0xca}, 6,
         TEST_X86_AMX_ROW_BF16L, UINT32_C(0x00003f80),
         "TCVTROWPS2BF16L r32"},
        {{0x62, 0xf3, 0x7e, 0x48, 0x77, 0xca, 0x01}, 7,
         TEST_X86_AMX_ROW_BF16L, UINT32_C(0x00003f80),
         "TCVTROWPS2BF16L imm8"},
        {{0x62, 0xf2, 0x7c, 0x48, 0x6d, 0xca}, 6,
         TEST_X86_AMX_ROW_PH16H, UINT32_C(0x3c000000),
         "TCVTROWPS2PHH r32"},
        {{0x62, 0xf3, 0x7c, 0x48, 0x07, 0xca, 0x01}, 7,
         TEST_X86_AMX_ROW_PH16H, UINT32_C(0x3c000000),
         "TCVTROWPS2PHH imm8"},
        {{0x62, 0xf2, 0x7d, 0x48, 0x6d, 0xca}, 6,
         TEST_X86_AMX_ROW_PH16L, UINT32_C(0x00003c00),
         "TCVTROWPS2PHL r32"},
        {{0x62, 0xf3, 0x7f, 0x48, 0x77, 0xca, 0x01}, 7,
         TEST_X86_AMX_ROW_PH16L, UINT32_C(0x00003c00),
         "TCVTROWPS2PHL imm8"},
    };
    uint8_t config[64] = {0};

    config[0] = 1;
    config[1] = 9;
    test_x86_amx_set_shape(config, 2, 64, 2);

    for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i) {
        uint8_t tile[1024] = {0};
        uint8_t initial[64];
        uint8_t expected[64] = {0};
        uint8_t result[64];
        uint8_t config_after[64];
        uint32_t eax = 1;
        uint32_t mxcsr = UINT32_C(0xffc0);
        uint64_t rflags = UINT64_C(0xcd7);
        uint64_t rip = 0;
        uc_engine *uc;

        memset(initial, 0xa5, sizeof(initial));
        if (operations[i].operation == TEST_X86_AMX_ROW_MOVE) {
            for (size_t byte = 0; byte < 64; ++byte) {
                tile[64 + byte] = (uint8_t)(byte * 29 + 7);
            }
            memcpy(expected, tile + 64, sizeof(expected));
        } else {
            const uint32_t source =
                operations[i].operation == TEST_X86_AMX_ROW_D2PS
                    ? UINT32_C(3)
                    : UINT32_C(0x3f800000);

            for (size_t lane = 0; lane < 16; ++lane) {
                test_x86_amx_put_u32(tile + 64 + lane * 4, source);
                test_x86_amx_put_u32(expected + lane * 4,
                                     operations[i].expected_dword);
            }
        }

        test_x86_amx_setup_cpu(&uc,
                            operations[i].code, operations[i].size);
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, tile));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial));
        OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_write(uc, UC_X86_REG_RFLAGS, &rflags));

        OK(uc_emu_start(uc, code_start, code_start + operations[i].size, 0,
                        0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM1, result));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config_after));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK_(memcmp(result, expected, sizeof(result)) == 0,
                    "%s result mismatch", operations[i].name);
        TEST_CHECK_(config_after[1] == 0, "%s did not clear start_row",
                    operations[i].name);
        TEST_CHECK_(mxcsr == UINT32_C(0xffc0), "%s changed MXCSR",
                    operations[i].name);
        TEST_CHECK_(rflags == UINT64_C(0xcd7), "%s changed RFLAGS",
                    operations[i].name);
        TEST_CHECK_(rip == code_start + operations[i].size,
                    "%s did not advance RIP", operations[i].name);
        OK(uc_close(uc));
    }
}

static void test_x86_amx_avx512_row_faults_and_conversion_edges(void)
{
    static const struct {
        uint8_t code[7];
        const char *description;
    } invalid[] = {
        {{0x62, 0xf3, 0xfd, 0x48, 0x07, 0xca, 0x01}, "EVEX.W1"},
        {{0x62, 0xf3, 0x7d, 0x28, 0x07, 0xca, 0x01}, "wrong EVEX.LL"},
        {{0x62, 0xf3, 0x7d, 0xc8, 0x07, 0xca, 0x01}, "EVEX.z"},
        {{0x62, 0xf3, 0x7d, 0x58, 0x07, 0xca, 0x01}, "EVEX.b"},
        {{0x62, 0xf3, 0x7d, 0x49, 0x07, 0xca, 0x01}, "writemask"},
        {{0x62, 0xf3, 0x75, 0x48, 0x07, 0xca, 0x01},
         "reserved immediate VVVV"},
        {{0x62, 0xf3, 0x7d, 0x40, 0x07, 0xca, 0x01},
         "reserved immediate V-prime"},
        {{0x62, 0xd3, 0x7d, 0x48, 0x07, 0xca, 0x01},
         "extended tile source"},
        {{0x62, 0xf3, 0x7d, 0x48, 0x07, 0x0a, 0x01}, "memory source"},
    };
    static const struct {
        uint8_t code[7];
        const char *description;
    } gp[] = {
        {{0x62, 0xf3, 0x7d, 0x48, 0x07, 0xca, 0x02},
         "row outside configured tile"},
        {{0x62, 0xf3, 0x7d, 0x48, 0x07, 0xca, 0x41},
         "chunk outside configured row"},
    };
    static const struct {
        uint8_t code[7];
        uint32_t source[4];
        uint32_t expected[4];
        const char *name;
    } conversions[] = {
        {{0x62, 0xf3, 0x7e, 0x48, 0x07, 0xca, 0x01},
         {UINT32_C(3), UINT32_C(0xffffffff), UINT32_C(16777217),
          UINT32_C(0xfeffffff)},
         {UINT32_C(0x40400000), UINT32_C(0xbf800000),
          UINT32_C(0x4b800000), UINT32_C(0xcb800000)},
         "TCVTROWD2PS RNE"},
        {{0x62, 0xf3, 0x7e, 0x48, 0x77, 0xca, 0x01},
         {UINT32_C(0x3f808000), UINT32_C(0x3f818000),
          UINT32_C(0x00000001), UINT32_C(0x7f800001)},
         {UINT32_C(0x00003f80), UINT32_C(0x00003f82), 0,
          UINT32_C(0x00007fc0)},
         "TCVTROWPS2BF16L RNE and specials"},
        {{0x62, 0xf3, 0x7f, 0x48, 0x77, 0xca, 0x01},
         {UINT32_C(0x33800000), UINT32_C(0x00000001),
          UINT32_C(0x3f800000), UINT32_C(0xc0000000)},
         {UINT32_C(0x00000001), 0, UINT32_C(0x00003c00),
          UINT32_C(0x0000c000)},
         "TCVTROWPS2PHL denormal handling"},
    };
    const uint8_t valid_move[] = {
        0x62, 0xf3, 0x7d, 0x48, 0x07, 0xca, 0x01,
    };
    uint8_t config[64] = {0};
    uint8_t tile[1024] = {0};
    uint8_t initial[64];

    config[0] = 1;
    config[1] = 9;
    test_x86_amx_set_shape(config, 2, 64, 2);
    for (size_t byte = 0; byte < 64; ++byte) {
        tile[64 + byte] = (uint8_t)(byte * 11 + 5);
    }
    memset(initial, 0xa5, sizeof(initial));

    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        uint8_t result[64];
        uint8_t config_after[64];
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        test_x86_amx_setup_cpu(&uc,
                            invalid[i].code, sizeof(invalid[i].code));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, tile));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial));
        err = uc_emu_start(uc, code_start,
                           code_start + sizeof(invalid[i].code), 0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM1, result));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config_after));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK_(err == UC_ERR_INSN_INVALID, "%s did not #UD",
                    invalid[i].description);
        TEST_CHECK_(memcmp(result, initial, sizeof(result)) == 0,
                    "%s changed destination", invalid[i].description);
        TEST_CHECK_(memcmp(config_after, config, sizeof(config_after)) == 0,
                    "%s changed TILECFG", invalid[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP",
                    invalid[i].description);
        OK(uc_close(uc));
    }

    {
        uint8_t invalid_config[64];
        uint8_t result[64];
        uint64_t rip = 0;
        uc_engine *uc;
        uc_err err;

        memcpy(invalid_config, config, sizeof(invalid_config));
        test_x86_amx_set_shape(invalid_config, 2, 14, 2);
        test_x86_amx_setup_cpu(&uc,
                            valid_move, sizeof(valid_move));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, invalid_config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, tile));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial));
        err = uc_emu_start(uc, code_start, code_start + sizeof(valid_move),
                           0, 0);
        OK(uc_reg_read(uc, UC_X86_REG_ZMM1, result));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK(err == UC_ERR_INSN_INVALID);
        TEST_CHECK(memcmp(result, initial, sizeof(result)) == 0);
        TEST_CHECK(rip == code_start);
        OK(uc_close(uc));
    }

    for (size_t i = 0; i < sizeof(gp) / sizeof(gp[0]); ++i) {
        uint8_t result[64];
        uint8_t config_after[64];
        uint64_t rip = 0;
        TestX86InterruptRecord record = {0};
        uc_engine *uc;
        uc_hook hook;

        test_x86_amx_setup_cpu(&uc,
                            gp[i].code, sizeof(gp[i].code));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, tile));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial));
        OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_x86_record_interrupt,
                       &record, 1, 0));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(gp[i].code), 0,
                        0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM1, result));
        OK(uc_reg_read(uc, UC_X86_REG_TILECFG, config_after));
        OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
        TEST_CHECK_(record.count == 1 && record.intno == 13,
                    "%s did not raise #GP", gp[i].description);
        TEST_CHECK_(memcmp(result, initial, sizeof(result)) == 0,
                    "%s changed destination", gp[i].description);
        TEST_CHECK_(memcmp(config_after, config, sizeof(config_after)) == 0,
                    "%s changed TILECFG", gp[i].description);
        TEST_CHECK_(rip == code_start, "%s advanced RIP",
                    gp[i].description);
        OK(uc_hook_del(uc, hook));
        OK(uc_close(uc));
    }

    {
        static const uint8_t extended[] = {
            0x62, 0x62, 0x7d, 0x40, 0x4a, 0xfa,
            /* tilemovrow zmm31,tmm2,r16d */
        };
        uint8_t result[64];
        uint32_t r16d = 1;
        uc_engine *uc;

        test_x86_amx_setup_cpu(&uc, extended,
                            sizeof(extended));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, tile));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM31, initial));
        OK(uc_reg_write(uc, UC_X86_REG_R16D, &r16d));
        OK(uc_emu_start(uc, code_start, code_start + sizeof(extended), 0,
                        0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM31, result));
        TEST_CHECK(memcmp(result, tile + 64, sizeof(result)) == 0);
        OK(uc_close(uc));
    }

    for (size_t i = 0; i < sizeof(conversions) / sizeof(conversions[0]);
         ++i) {
        uint8_t input_tile[1024] = {0};
        uint8_t result[64];
        uint8_t expected[64] = {0};
        uint32_t mxcsr = UINT32_C(0xffc0);
        uc_engine *uc;

        for (size_t lane = 0; lane < 4; ++lane) {
            test_x86_amx_put_u32(input_tile + 64 + lane * 4,
                                 conversions[i].source[lane]);
            test_x86_amx_put_u32(expected + lane * 4,
                                 conversions[i].expected[lane]);
        }
        test_x86_amx_setup_cpu(&uc,
                            conversions[i].code,
                            sizeof(conversions[i].code));
        OK(uc_reg_write(uc, UC_X86_REG_TILECFG, config));
        OK(uc_reg_write(uc, UC_X86_REG_TMM2, input_tile));
        OK(uc_reg_write(uc, UC_X86_REG_ZMM1, initial));
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_emu_start(uc, code_start,
                        code_start + sizeof(conversions[i].code), 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_ZMM1, result));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK_(memcmp(result, expected, sizeof(result)) == 0,
                    "%s result mismatch", conversions[i].name);
        TEST_CHECK_(mxcsr == UINT32_C(0xffc0), "%s changed MXCSR",
                    conversions[i].name);
        OK(uc_close(uc));
    }
}

TEST_LIST = {
    {"test_x86_in", test_x86_in},
    {"test_x86_out", test_x86_out},
    {"test_x86_mem_hook_all", test_x86_mem_hook_all},
    {"test_x86_inc_dec_pxor", test_x86_inc_dec_pxor},
    {"test_x86_pcmpistri_equal_ordered_boundary",
     test_x86_pcmpistri_equal_ordered_boundary},
    {"test_x86_stmxcsr_stack_operand", test_x86_stmxcsr_stack_operand},
    {"test_x86_movsxd_honors_protection_after_tlb_prime",
     test_x86_movsxd_honors_protection_after_tlb_prime},
    {"test_x86_rex_prefix_must_be_last", test_x86_rex_prefix_must_be_last},
    {"test_x86_null_segment_prefix_preserves_gs",
     test_x86_null_segment_prefix_preserves_gs},
    {"test_x86_movaps_requires_alignment", test_x86_movaps_requires_alignment},
    {"test_x86_aligned_move_family_faults",
     test_x86_aligned_move_family_faults},
    {"test_x86_vmovaps_ymm_requires_32_byte_alignment",
     test_x86_vmovaps_ymm_requires_32_byte_alignment},
    {"test_x86_legacy_sse_m128_requires_alignment",
     test_x86_legacy_sse_m128_requires_alignment},
    {"test_x86_vmovups_ymm_roundtrip", test_x86_vmovups_ymm_roundtrip},
    {"test_x86_vpermilps_variable_xmm", test_x86_vpermilps_variable_xmm},
    {"test_x86_vpermilpd_variable_xmm", test_x86_vpermilpd_variable_xmm},
    {"test_x86_vpermilps_variable_ymm", test_x86_vpermilps_variable_ymm},
    {"test_x86_vpermilpd_variable_ymm", test_x86_vpermilpd_variable_ymm},
    {"test_x86_vpermil_variable_memory", test_x86_vpermil_variable_memory},
    {"test_x86_vpermil_invalid_mmx_encoding",
     test_x86_vpermil_invalid_mmx_encoding},
    {"test_x86_opmask_kandw_semantics", test_x86_opmask_kandw_semantics},
    {"test_x86_opmask_kandq_semantics", test_x86_opmask_kandq_semantics},
    {"test_x86_opmask_kand_byte_dword", test_x86_opmask_kand_byte_dword},
    {"test_x86_opmask_kandn_widths", test_x86_opmask_kandn_widths},
    {"test_x86_opmask_kor_widths", test_x86_opmask_kor_widths},
    {"test_x86_opmask_kxor_widths", test_x86_opmask_kxor_widths},
    {"test_x86_opmask_kxnor_widths", test_x86_opmask_kxnor_widths},
    {"test_x86_opmask_kadd_widths", test_x86_opmask_kadd_widths},
    {"test_x86_opmask_knot_widths", test_x86_opmask_knot_widths},
    {"test_x86_opmask_kunpack_widths", test_x86_opmask_kunpack_widths},
    {"test_x86_opmask_kshift_widths", test_x86_opmask_kshift_widths},
    {"test_x86_opmask_kmov_register_widths",
     test_x86_opmask_kmov_register_widths},
    {"test_x86_opmask_kmov_memory_widths", test_x86_opmask_kmov_memory_widths},
    {"test_x86_opmask_kmov_extended_operands",
     test_x86_opmask_kmov_extended_operands},
    {"test_x86_opmask_ktestw_flags", test_x86_opmask_ktestw_flags},
    {"test_x86_opmask_ktest_other_widths", test_x86_opmask_ktest_other_widths},
    {"test_x86_opmask_kortest_widths", test_x86_opmask_kortest_widths},
    {"test_x86_reserved_opmask_opcode_stays_fail_closed",
     test_x86_reserved_opmask_opcode_stays_fail_closed},
    {"test_x86_opmask_invalid_forms", test_x86_opmask_invalid_forms},
    {"test_x86_opmask_register_roundtrip", test_x86_opmask_register_roundtrip},
    {"test_x86_zmm_register_roundtrip_and_reset",
     test_x86_zmm_register_roundtrip_and_reset},
    {"test_x86_evex_vmovdqu64_zmm31_zmm20",
     test_x86_evex_vmovdqu64_zmm31_zmm20},
    {"test_x86_evex_vmovdqu64_vector_length_zeroing",
     test_x86_evex_vmovdqu64_vector_length_zeroing},
    {"test_x86_evex_vmovdqu64_extension_bits",
     test_x86_evex_vmovdqu64_extension_bits},
    {"test_x86_evex_vmovdqu_register_widths_masks_and_directions",
     test_x86_evex_vmovdqu_register_widths_masks_and_directions},
    {"test_x86_evex_vmovdqu_memory_widths_masks_and_directions",
     test_x86_evex_vmovdqu_memory_widths_masks_and_directions},
    {"test_x86_evex_vmovdqu_memory_addressing_forms",
     test_x86_evex_vmovdqu_memory_addressing_forms},
    {"test_x86_evex_vmovdqu_masked_memory_fault_atomicity",
     test_x86_evex_vmovdqu_masked_memory_fault_atomicity},
    {"test_x86_evex_vmovdqu_invalid_forms",
     test_x86_evex_vmovdqu_invalid_forms},
    {"test_x86_evex_vpadd_vpsub_register_semantics",
     test_x86_evex_vpadd_vpsub_register_semantics},
    {"test_x86_evex_vpadd_vpsub_invalid_forms",
     test_x86_evex_vpadd_vpsub_invalid_forms},
    {"test_x86_evex_vpcmp_register_semantics",
     test_x86_evex_vpcmp_register_semantics},
    {"test_x86_evex_vpcmp_invalid_forms",
     test_x86_evex_vpcmp_invalid_forms},
    {"test_x86_evex_compress_expand_register_forms",
     test_x86_evex_compress_expand_register_forms},
    {"test_x86_evex_compress_expand_memory_forms",
     test_x86_evex_compress_expand_memory_forms},
    {"test_x86_apx_evex_alu_register_semantics",
     test_x86_apx_evex_alu_register_semantics},
    {"test_x86_apx_ccmp_ctest_register_semantics",
     test_x86_apx_ccmp_ctest_register_semantics},
    {"test_x86_apx_jmpabs_semantics", test_x86_apx_jmpabs_semantics},
    {"test_x86_apx_jmpabs_invalid_forms",
     test_x86_apx_jmpabs_invalid_forms},
    {"test_x86_apx_push2_pop2_semantics",
     test_x86_apx_push2_pop2_semantics},
    {"test_x86_apx_push2_pop2_invalid_and_faults",
     test_x86_apx_push2_pop2_invalid_and_faults},
    {"test_x86_apx_rex2_push_pop_semantics",
     test_x86_apx_rex2_push_pop_semantics},
    {"test_x86_apx_rex2_push_pop_invalid_and_faults",
     test_x86_apx_rex2_push_pop_invalid_and_faults},
    {"test_x86_apx_evex_setcc_register_matrix",
     test_x86_apx_evex_setcc_register_matrix},
    {"test_x86_apx_evex_setcc_memory_and_invalid",
     test_x86_apx_evex_setcc_memory_and_invalid},
    {"test_x86_apx_evex_cmovcc_register_matrix",
     test_x86_apx_evex_cmovcc_register_matrix},
    {"test_x86_apx_evex_cmovcc_memory_faults_and_invalid",
     test_x86_apx_evex_cmovcc_memory_faults_and_invalid},
    {"test_x86_amx_guest_cpuid_xstate_and_xsave",
     test_x86_amx_guest_cpuid_xstate_and_xsave},
    {"test_x86_movrs_current_encodings_and_gates",
     test_x86_movrs_current_encodings_and_gates},
    {"test_x86_apx_evex_full_width_canonical_ranges",
     test_x86_apx_evex_full_width_canonical_ranges},
    {"test_x86_amx_config_state_and_control",
     test_x86_amx_config_state_and_control},
    {"test_x86_amx_vex_ignored_extension_bits",
     test_x86_amx_vex_ignored_extension_bits},
    {"test_x86_amx_tile_transfer_restart_and_invalid",
     test_x86_amx_tile_transfer_restart_and_invalid},
    {"test_x86_amx_movrs_load_semantics_and_invalid",
     test_x86_amx_movrs_load_semantics_and_invalid},
    {"test_x86_amx_integer_compute_semantics_and_invalid",
     test_x86_amx_integer_compute_semantics_and_invalid},
    {"test_x86_amx_floating_compute_semantics_and_invalid",
     test_x86_amx_floating_compute_semantics_and_invalid},
    {"test_x86_amx_fp8_fixed_accumulation_and_specials",
     test_x86_amx_fp8_fixed_accumulation_and_specials},
    {"test_x86_amx_avx512_row_moves_and_converts",
     test_x86_amx_avx512_row_moves_and_converts},
    {"test_x86_amx_avx512_row_faults_and_conversion_edges",
     test_x86_amx_avx512_row_faults_and_conversion_edges},
    {"test_x86_apx_evex_alu_invalid_forms",
     test_x86_apx_evex_alu_invalid_forms},
    {"test_x86_apx_register_roundtrip_and_reset",
     test_x86_apx_register_roundtrip_and_reset},
    {"test_x86_apx_subregister_api_semantics",
     test_x86_apx_subregister_api_semantics},
    {"test_x86_apx_rex2_mov_widths_and_directions",
     test_x86_apx_rex2_mov_widths_and_directions},
    {"test_x86_apx_rex2_mov_memory_widths_and_directions",
     test_x86_apx_rex2_mov_memory_widths_and_directions},
    {"test_x86_apx_rex2_memory_addressing_forms",
     test_x86_apx_rex2_memory_addressing_forms},
    {"test_x86_apx_rex2_extended_address_register_matrix",
     test_x86_apx_rex2_extended_address_register_matrix},
    {"test_x86_apx_rex2_memory_faults_are_atomic",
     test_x86_apx_rex2_memory_faults_are_atomic},
    {"test_x86_apx_rex2_add_widths_directions_and_flags",
     test_x86_apx_rex2_add_widths_directions_and_flags},
    {"test_x86_apx_rex2_arithmetic_memory_widths_directions_and_flags",
     test_x86_apx_rex2_arithmetic_memory_widths_directions_and_flags},
    {"test_x86_apx_rex2_logical_widths_directions_and_flags",
     test_x86_apx_rex2_logical_widths_directions_and_flags},
    {"test_x86_apx_rex2_logical_memory_widths_directions_and_flags",
     test_x86_apx_rex2_logical_memory_widths_directions_and_flags},
    {"test_x86_apx_rex2_sub_cmp_widths_directions_and_flags",
     test_x86_apx_rex2_sub_cmp_widths_directions_and_flags},
    {"test_x86_apx_rex2_mov_r26_r25", test_x86_apx_rex2_mov_r26_r25},
    {"test_x86_apx_rex2_add_r31_r24_flags",
     test_x86_apx_rex2_add_r31_r24_flags},
    {"test_x86_apx_rex2_add_carry_zero_flags",
     test_x86_apx_rex2_add_carry_zero_flags},
    {"test_x86_apx_rex2_adc_sbb_consume_carry",
     test_x86_apx_rex2_adc_sbb_consume_carry},
    {"test_x86_apx_rex2_map1_imul_semantics",
     test_x86_apx_rex2_map1_imul_semantics},
    {"test_x86_evex_feature_and_xstate_gates",
     test_x86_evex_feature_and_xstate_gates},
    {"test_x86_avx512_4fmaps_scalar_accepts_all_llig_spellings",
     test_x86_avx512_4fmaps_scalar_accepts_all_llig_spellings},
    {"test_x86_apx_rex2_mov_extension_fields",
     test_x86_apx_rex2_mov_extension_fields},
    {"test_x86_apx_rex2_register_fields_and_ignored_prefixes",
     test_x86_apx_rex2_register_fields_and_ignored_prefixes},
    {"test_x86_apx_rex2_low_and_extended_register_fields",
     test_x86_apx_rex2_low_and_extended_register_fields},
    {"test_x86_apx_unimplemented_forms_fail_closed",
     test_x86_apx_unimplemented_forms_fail_closed},
    {"test_x86_sha1msg1", test_x86_sha1msg1},
    {"test_x86_sha1nexte", test_x86_sha1nexte},
    {"test_x86_sha1msg2_memory", test_x86_sha1msg2_memory},
    {"test_x86_sha1rnds4_immediates", test_x86_sha1rnds4_immediates},
    {"test_x86_sha256msg1", test_x86_sha256msg1},
    {"test_x86_sha256msg2_memory", test_x86_sha256msg2_memory},
    {"test_x86_sha256rnds2", test_x86_sha256rnds2},
    {"test_x86_gf2p8mulb_legacy", test_x86_gf2p8mulb_legacy},
    {"test_x86_vgf2p8mulb_xmm", test_x86_vgf2p8mulb_xmm},
    {"test_x86_vgf2p8mulb_ymm_memory", test_x86_vgf2p8mulb_ymm_memory},
    {"test_x86_gf2p8affineqb_legacy", test_x86_gf2p8affineqb_legacy},
    {"test_x86_gf2p8affineinvqb_legacy_memory",
     test_x86_gf2p8affineinvqb_legacy_memory},
    {"test_x86_vgf2p8affineqb_xmm", test_x86_vgf2p8affineqb_xmm},
    {"test_x86_vgf2p8affineinvqb_ymm", test_x86_vgf2p8affineinvqb_ymm},
    {"test_x86_relative_jump", test_x86_relative_jump},
    {"test_x86_loop", test_x86_loop},
    {"test_x86_invalid_mem_read", test_x86_invalid_mem_read},
    {"test_x86_invalid_mem_write", test_x86_invalid_mem_write},
    {"test_x86_invalid_jump", test_x86_invalid_jump},
    {"test_x86_64_syscall", test_x86_64_syscall},
    {"test_x86_16_add", test_x86_16_add},
    {"test_x86_reg_save", test_x86_reg_save},
    {"test_x86_invalid_mem_read_stop_in_cb",
     test_x86_invalid_mem_read_stop_in_cb},
    {"test_x86_x87_fnstenv", test_x86_x87_fnstenv},
    {"test_x86_fprem_large_exponent_partial",
     test_x86_fprem_large_exponent_partial},
    {"test_x86_fprem_d64_loop_converges", test_x86_fprem_d64_loop_converges},
    {"test_x86_fprem_d200_converges", test_x86_fprem_d200_converges},
    {"test_x86_fprem_terminal_thresholds", test_x86_fprem_terminal_thresholds},
    {"test_x86_fprem_and_fprem1_quotients",
     test_x86_fprem_and_fprem1_quotients},
    {"test_x86_fprem_special_operands", test_x86_fprem_special_operands},
    {"test_x86_mmio", test_x86_mmio},
    {"test_x86_missing_code", test_x86_missing_code},
    {"test_x86_smc_xor", test_x86_smc_xor},
    {"test_x86_smc_add", test_x86_smc_add},
    {"test_x86_smc_mem_hook", test_x86_smc_mem_hook},
    {"test_x86_write_hook_tlb_flush_preserves_store",
     test_x86_write_hook_tlb_flush_preserves_store},
    {"test_x86_write_prot_hook_must_repair_permission",
     test_x86_write_prot_hook_must_repair_permission},
    {"test_x86_smc_after_exec_permission_upgrade",
     test_x86_smc_after_exec_permission_upgrade},
    {"test_x86_mmio_uc_mem_rw", test_x86_mmio_uc_mem_rw},
    {"test_x86_sysenter", test_x86_sysenter},
    {"test_x86_sysretq_rejects_noncanonical_rcx",
     test_x86_sysretq_rejects_noncanonical_rcx},
    {"test_x86_hook_cpuid", test_x86_hook_cpuid},
    {"test_x86_486_cpuid", test_x86_486_cpuid},
    {"test_x86_clear_tb_cache", test_x86_clear_tb_cache},
    {"test_x86_clear_empty_tb", test_x86_clear_empty_tb},
    {"test_x86_page_boundary_speculative_translation",
     test_x86_page_boundary_speculative_translation},
    {"test_x86_hook_tcg_op", test_x86_hook_tcg_op},
    {"test_x86_cmpxchg", test_x86_cmpxchg},
    {"test_x86_cmpxchg32_accumulator", test_x86_cmpxchg32_accumulator},
    {"test_x86_cmpxchg32_register", test_x86_cmpxchg32_register},
    {"test_x86_ret_imm16_unsigned", test_x86_ret_imm16_unsigned},
    {"test_x86_rorx_rip_relative_imm", test_x86_rorx_rip_relative_imm},
    {"test_x86_shld_rip_relative_imm", test_x86_shld_rip_relative_imm},
    {"test_x86_shrd_rip_relative_imm", test_x86_shrd_rip_relative_imm},
    {"test_x86_pdep32_zero_extend", test_x86_pdep32_zero_extend},
    {"test_x86_nested_emu_start", test_x86_nested_emu_start},
    {"test_x86_nested_emu_stop", test_x86_nested_emu_stop},
    {"test_x86_64_nested_emu_start_error", test_x86_64_nested_emu_start_error},
    {"test_x86_eflags_reserved_bit", test_x86_eflags_reserved_bit},
    {"test_x86_nested_uc_emu_start_exits", test_x86_nested_uc_emu_start_exits},
    {"test_x86_clear_count_cache", test_x86_clear_count_cache},
    {"test_x86_correct_address_in_small_jump_hook",
     test_x86_correct_address_in_small_jump_hook},
    {"test_x86_correct_address_in_long_jump_hook",
     test_x86_correct_address_in_long_jump_hook},
    {"test_x86_vex_l_256", test_x86_vex_l_256},
#if !defined(TARGET_READ_INLINED) && defined(BOOST_LITTLE_ENDIAN)
    {"test_x86_unaligned_access", test_x86_unaligned_access},
    {"test_x86_64_unaligned_access", test_x86_64_unaligned_access},

#endif
    {"test_x86_lazy_mapping", test_x86_lazy_mapping},
    {"test_x86_16_incorrect_ip", test_x86_16_incorrect_ip},
    {"test_x86_mmu", test_x86_mmu},
    {"test_x86_read_virtual", test_x86_read_virtual},
    {"test_x86_vtlb", test_x86_vtlb},
    {"test_x86_segmentation", test_x86_segmentation},
    {"test_x86_0xff_lcall", test_x86_0xff_lcall},
    {"test_x86_64_not_overwriting_tmp0_for_pc_update",
     test_x86_64_not_overwriting_tmp0_for_pc_update},
    {"test_fxsave_fpip_x86", test_fxsave_fpip_x86},
    {"test_fxsave_fpip_x64", test_fxsave_fpip_x64},
    {"test_x86_fxsave_writes_complete_legacy_fpu_state",
     test_x86_fxsave_writes_complete_legacy_fpu_state},
    {"test_bswap_x64", test_bswap_ax},
    {"test_rex_x64", test_rex_x64},
    {"test_x86_ro_segfault", test_x86_ro_segfault},
    {"test_x86_hook_insn_rdtsc", test_x86_hook_insn_rdtsc},
    {"test_x86_hook_insn_rdtscp", test_x86_hook_insn_rdtscp},
    {"test_x86_dr7", test_x86_dr7},
    {"test_x86_hook_block", test_x86_hook_block},
    {"test_x86_mem_hooks_pc_guarantee", test_x86_mem_hooks_pc_guarantee},
    {"test_x86_rotate_rflags_after_fault", test_x86_rotate_rflags_after_fault},
    {"test_x86_setcc_rflags_after_fault", test_x86_setcc_rflags_after_fault},
    {"test_x86_group_1a_reserved_encodings",
     test_x86_group_1a_reserved_encodings},
    {"test_x86_group_5_reserved_fault_priority",
     test_x86_group_5_reserved_fault_priority},
    {"test_x86_group_11_decode_rules", test_x86_group_11_decode_rules},
    {"test_x86_group_3_extension_1_test", test_x86_group_3_extension_1_test},
    {"test_x86_dpps_pairwise_reduction", test_x86_dpps_pairwise_reduction},
    {"test_x86_dppd_signed_zero_reduction",
     test_x86_dppd_signed_zero_reduction},
    {"test_x86_vdpps_ymm_pairwise_lanes", test_x86_vdpps_ymm_pairwise_lanes},
    {"test_x86_vzero_state", test_x86_vzero_state},
    {"test_x86_lazy_jcc_materializes_condition_before_branch",
     test_x86_lazy_jcc_materializes_condition_before_branch},
    {"test_x86_count_hook_syncs_dirty_cc_op",
     test_x86_count_hook_syncs_dirty_cc_op},
    {"test_x86_adox_uses_current_static_lazy_op",
     test_x86_adox_uses_current_static_lazy_op},
    {"test_x86_lahf_uses_current_static_lazy_op",
     test_x86_lahf_uses_current_static_lazy_op},
    {"test_x86_lazy_jcc_keeps_prior_cmov_condition",
     test_x86_lazy_jcc_keeps_prior_cmov_condition},
    {"test_x86_masked_vector_memory_suppresses_faults",
     test_x86_masked_vector_memory_suppresses_faults},
    {"test_x86_gather_fault_preserves_lane_progress",
     test_x86_gather_fault_preserves_lane_progress},
    {"test_x86_masked_load_fault_preserves_destination",
     test_x86_masked_load_fault_preserves_destination},
    {"test_x86_avx_rejects_reserved_vex_w",
     test_x86_avx_rejects_reserved_vex_w},
    {"test_x86_vtest_ymm_reduces_high_lane_flags",
     test_x86_vtest_ymm_reduces_high_lane_flags},
    {"test_x86_broadcast_128_block_to_ymm",
     test_x86_broadcast_128_block_to_ymm},
    {"test_x86_vpermil_immediate_ymm", test_x86_vpermil_immediate_ymm},
    {"test_x86_avx_requires_enabled_state_and_features",
     test_x86_avx_requires_enabled_state_and_features},
    {"test_x86_vpblendvb_xmm_requires_only_avx",
     test_x86_vpblendvb_xmm_requires_only_avx},
    {"test_x86_vex_rejects_reserved_fields_and_missing_prefixes",
     test_x86_vex_rejects_reserved_fields_and_missing_prefixes},
    {"test_x86_vmovntdqa_requires_vector_alignment",
     test_x86_vmovntdqa_requires_vector_alignment},
    {"test_x86_vlddqu_vector_lengths_and_reserved_vvvv",
     test_x86_vlddqu_vector_lengths_and_reserved_vvvv},
    {"test_x86_vmovnt_ymm_stores_require_alignment_and_features",
     test_x86_vmovnt_ymm_stores_require_alignment_and_features},
    {"test_x86_broadcast_operand_form_feature_gates",
     test_x86_broadcast_operand_form_feature_gates},
    {"test_x86_vpclmulqdq_ymm_uses_independent_lanes",
     test_x86_vpclmulqdq_ymm_uses_independent_lanes},
    {"test_x86_icebp_reports_trap_rip", test_x86_icebp_reports_trap_rip},
    {"test_x86_movbe_crc32_use_16bit_default_width",
     test_x86_movbe_crc32_use_16bit_default_width},
    {"test_x86_movbe_rejects_register_encoding",
     test_x86_movbe_rejects_register_encoding},
    {"test_x86_popcnt_rex_w_overrides_data16",
     test_x86_popcnt_rex_w_overrides_data16},
    {"test_x86_mxcsr_ftz_applies_to_sse", test_x86_mxcsr_ftz_applies_to_sse},
    {"test_x86_round_scalar_memory_access_width",
     test_x86_round_scalar_memory_access_width},
    {"test_x86_ldmxcsr_rejects_reserved_bits",
     test_x86_ldmxcsr_rejects_reserved_bits},
    {"test_x86_vcvtps2ph_uses_immediate_rounding",
     test_x86_vcvtps2ph_uses_immediate_rounding},
    {"test_x86_vcvtps2ph_rejects_vex_w1", test_x86_vcvtps2ph_rejects_vex_w1},
    {"test_x86_vcvtps2ph_ignores_mxcsr_ftz",
     test_x86_vcvtps2ph_ignores_mxcsr_ftz},
    {"test_x86_vcvtph2ps_ignores_mxcsr_daz",
     test_x86_vcvtph2ps_ignores_mxcsr_daz},
    {"test_x86_vcvtps2ph_ignores_immediate_bit3",
     test_x86_vcvtps2ph_ignores_immediate_bit3},
    {"test_x86_fma_alternating_packed_lanes",
     test_x86_fma_alternating_packed_lanes},
    {"test_x86_fma_ftz_after_rounding", test_x86_fma_ftz_after_rounding},
    {"test_x86_fma_daz_suppresses_denormal_operand_flag",
     test_x86_fma_daz_suppresses_denormal_operand_flag},
    {"test_x86_vex_uses_low_byte_registers",
     test_x86_vex_uses_low_byte_registers},
    {"test_x86_vex128_clears_upper_vector_state",
     test_x86_vex128_clears_upper_vector_state},
    {"test_x86_vex128_partial_moves_merge_source_lanes",
     test_x86_vex128_partial_moves_merge_source_lanes},
    {"test_x86_vmovd_vmovq_vex_rules_and_upper_clear",
     test_x86_vmovd_vmovq_vex_rules_and_upper_clear},
    {"test_x86_vex128_special_forms_clear_upper_vector_state",
     test_x86_vex128_special_forms_clear_upper_vector_state},
    {"test_x86_gather_rejects_overlapping_operands",
     test_x86_gather_rejects_overlapping_operands},
    {"test_x86_sse_denormal_status", test_x86_sse_denormal_status},
    {"test_x86_mxcsr_tracks_simd_exceptions",
     test_x86_mxcsr_tracks_simd_exceptions},
    {"test_x86_mov_ss_rejects_null_selector_rpl_mismatch",
     test_x86_mov_ss_rejects_null_selector_rpl_mismatch},
    {"test_x86_bsf_bsr_zero_input_preserves_destination",
     test_x86_bsf_bsr_zero_input_preserves_destination},
    {"test_x86_cvtsi2sd_xmm7_followed_by_call",
     test_x86_cvtsi2sd_xmm7_followed_by_call},
    {"test_x86_cvttss2si_followed_by_rep_prefixed_instruction",
     test_x86_cvttss2si_followed_by_rep_prefixed_instruction},
    {"test_x86_xsave_roundtrips_ymmh", test_x86_xsave_roundtrips_ymmh},
    {"test_x86_rdpmc_fails_without_virtual_pmu",
     test_x86_rdpmc_fails_without_virtual_pmu},
    {"test_x86_unimplemented_msr_raises_gp",
     test_x86_unimplemented_msr_raises_gp},
    {"test_x86_rdpmc_user_access_fails_without_virtual_pmu",
     test_x86_rdpmc_user_access_fails_without_virtual_pmu},
    {"test_x86_haswell_exposes_vector_features_and_state",
     test_x86_haswell_exposes_vector_features_and_state},
    {"test_x86_rdseed_uses_its_own_cpuid_feature",
     test_x86_rdseed_uses_its_own_cpuid_feature},
    {"test_x86_rdpid_reads_tsc_aux_and_checks_cpuid",
     test_x86_rdpid_reads_tsc_aux_and_checks_cpuid},
    {"test_x86_until_honored_after_cached_tb_chaining",
     test_x86_until_honored_after_cached_tb_chaining},
    {"test_x86_sse_avx_nan_first_source", test_x86_sse_avx_nan_first_source},
    {"test_x86_mmx_writes_set_x87_exponent",
     test_x86_mmx_writes_set_x87_exponent},
    {NULL, NULL}};
