#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

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

static void run_x86_sha_reg(const char *code, size_t code_size,
                            const uint32_t dst_init[4],
                            const uint32_t src[4],
                            const uint32_t xmm0[4],
                            const uint32_t expected[4])
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
    static const uint8_t roundps[] = {
        0x66, 0x0f, 0x3a, 0x08, 0x00, 0x00,
        /* roundps xmm0, xmmword ptr [rax], 0 */
    };
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

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL, roundps,
                            sizeof(roundps));
        OK(uc_mem_map(uc, data_page, 0x1000, UC_PROT_ALL));
        OK(uc_mem_write(uc, data_address, &single_input,
                        sizeof(single_input)));
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &data_address));
        uc_assert_err(UC_ERR_READ_UNMAPPED,
                      uc_emu_start(uc, code_start,
                                   code_start + sizeof(roundps), 0, 0));
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

static void test_x86_vcvtps2ph_suppresses_precision_flag(void)
{
    static const uint8_t report_precision[] = {
        0xc4, 0xe3, 0x79, 0x1d, 0xc8, 0x00,
    };
    static const uint8_t suppress_precision[] = {
        0xc4, 0xe3, 0x79, 0x1d, 0xc8, 0x08,
    };
    static const struct {
        const uint8_t *code;
        size_t size;
        bool expects_precision;
    } cases[] = {
        {report_precision, sizeof(report_precision), true},
        {suppress_precision, sizeof(suppress_precision), false},
    };
    const uint32_t input[4] = {0x3f801000U, 0, 0, 0};

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint32_t mxcsr = 0x1f80;
        uc_engine *uc;

        uc_common_setup_cpu(&uc, UC_MODE_64, UC_CPU_X86_HASWELL,
                            cases[i].code, cases[i].size);
        OK(uc_reg_write(uc, UC_X86_REG_MXCSR, &mxcsr));
        OK(uc_reg_write(uc, UC_X86_REG_XMM1, input));
        OK(uc_emu_start(uc, code_start, code_start + cases[i].size, 0, 0));
        OK(uc_reg_read(uc, UC_X86_REG_MXCSR, &mxcsr));
        TEST_CHECK(((mxcsr & (1U << 5)) != 0) == cases[i].expects_precision);
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

typedef struct TestX86InterruptRecord {
    uint32_t intno;
    uint32_t count;
} TestX86InterruptRecord;

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
    {"test_x86_movaps_requires_alignment",
     test_x86_movaps_requires_alignment},
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
    {"test_x86_vgf2p8affineinvqb_ymm",
     test_x86_vgf2p8affineinvqb_ymm},
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
    {"test_x86_fprem_d64_loop_converges",
     test_x86_fprem_d64_loop_converges},
    {"test_x86_fprem_d200_converges", test_x86_fprem_d200_converges},
    {"test_x86_fprem_terminal_thresholds",
     test_x86_fprem_terminal_thresholds},
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
    {"test_x86_rotate_rflags_after_fault",
     test_x86_rotate_rflags_after_fault},
    {"test_x86_setcc_rflags_after_fault",
     test_x86_setcc_rflags_after_fault},
    {"test_x86_group_1a_reserved_encodings",
     test_x86_group_1a_reserved_encodings},
    {"test_x86_group_5_reserved_fault_priority",
     test_x86_group_5_reserved_fault_priority},
    {"test_x86_group_11_decode_rules", test_x86_group_11_decode_rules},
    {"test_x86_group_3_extension_1_test",
     test_x86_group_3_extension_1_test},
    {"test_x86_dpps_pairwise_reduction",
     test_x86_dpps_pairwise_reduction},
    {"test_x86_dppd_signed_zero_reduction",
     test_x86_dppd_signed_zero_reduction},
    {"test_x86_vdpps_ymm_pairwise_lanes",
     test_x86_vdpps_ymm_pairwise_lanes},
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
    {"test_x86_vpermil_immediate_ymm",
     test_x86_vpermil_immediate_ymm},
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
    {"test_x86_mxcsr_ftz_applies_to_sse",
     test_x86_mxcsr_ftz_applies_to_sse},
    {"test_x86_round_scalar_memory_access_width",
     test_x86_round_scalar_memory_access_width},
    {"test_x86_ldmxcsr_rejects_reserved_bits",
     test_x86_ldmxcsr_rejects_reserved_bits},
    {"test_x86_vcvtps2ph_uses_immediate_rounding",
     test_x86_vcvtps2ph_uses_immediate_rounding},
    {"test_x86_vcvtps2ph_rejects_vex_w1",
     test_x86_vcvtps2ph_rejects_vex_w1},
    {"test_x86_vcvtps2ph_ignores_mxcsr_ftz",
     test_x86_vcvtps2ph_ignores_mxcsr_ftz},
    {"test_x86_vcvtph2ps_ignores_mxcsr_daz",
     test_x86_vcvtph2ps_ignores_mxcsr_daz},
    {"test_x86_vcvtps2ph_suppresses_precision_flag",
     test_x86_vcvtps2ph_suppresses_precision_flag},
    {"test_x86_fma_alternating_packed_lanes",
     test_x86_fma_alternating_packed_lanes},
    {"test_x86_fma_ftz_after_rounding",
     test_x86_fma_ftz_after_rounding},
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
    {"test_x86_mxcsr_tracks_simd_exceptions",
     test_x86_mxcsr_tracks_simd_exceptions},
    {"test_x86_mov_ss_rejects_null_selector_rpl_mismatch",
     test_x86_mov_ss_rejects_null_selector_rpl_mismatch},
    {"test_x86_bsf_bsr_zero_input_preserves_destination",
     test_x86_bsf_bsr_zero_input_preserves_destination},
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
    {"test_x86_sse_avx_nan_first_source",
     test_x86_sse_avx_nan_first_source},
    {"test_x86_mmx_writes_set_x87_exponent",
     test_x86_mmx_writes_set_x87_exponent},
    {NULL, NULL}};
