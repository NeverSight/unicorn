#include "unicorn_test.h"

const uint64_t code_start = 0x10000000;
const uint64_t code_len = 0x4000;

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void test_mips_el_ori(void)
{
    uc_engine *uc;
    char code[] = "\x56\x34\x21\x34"; // ori $at, $at, 0x3456;
    int r_r1 = 0x6789;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_1, &r_r1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_1, &r_r1));

    TEST_CHECK(r_r1 == 0x77df);

    OK(uc_close(uc));
}

static void test_mips_eb_ori(void)
{
    uc_engine *uc;
    char code[] = "\x34\x21\x34\x56"; // ori $at, $at, 0x3456;
    int r_r1 = 0x6789;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_1, &r_r1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_1, &r_r1));

    TEST_CHECK(r_r1 == 0x77df);

    OK(uc_close(uc));
}

static void test_mips_stop_at_branch(void)
{
    uc_engine *uc;
    char code[] =
        "\x02\x00\x00\x08\x21\x10\x62\x00"; // j 0x8; addu $v0, $v1, $v0;
    int r_pc = 0x0;
    uint32_t v1 = 5;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);

    OK(uc_reg_write(uc, UC_MIPS_REG_V1, &v1));
    // Execute one instruction with branch delay slot.
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));

    OK(uc_reg_read(uc, UC_MIPS_REG_PC, &r_pc));
    OK(uc_reg_read(uc, UC_MIPS_REG_V0, &v1));

    // Even if we just execute one instruction, the instruction in the
    // delay slot would also be executed.
    TEST_CHECK(r_pc == code_start + 0x8);
    TEST_CHECK(v1 == 0x5);

    OK(uc_close(uc));
}

static void test_mips_stop_at_delay_slot(void)
{
    uc_engine *uc;
    char code[] =
        "\x02\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"; // j 0x8; nop;
    int r_pc = 0x0;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);

    // Stop at the delay slot by design.
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_PC, &r_pc));

    // The branch instruction isn't committed and the PC is not updated.
    // Users is responsible to restart emulation at the branch instruction.
    TEST_CHECK(r_pc == code_start);

    OK(uc_close(uc));
}

static void test_mips_stop_delay_slot_from_qiling(void)
{
    uc_engine *uc;
    // 24 06 00 03          addiu                $a2, $zero, 3
    // 10 a6 00 79          beq                  $a1, $a2, 0x1e8
    // 30 42 00 fc          andi                 $v0, $v0, 0xfc
    // 10 40 00 32          beqz                 $v0, 0x47c8c90
    // 24 ab ff da          addiu                $t3, $a1, -0x26
    // 2d 62 00 02          sltiu                $v0, $t3, 2
    // 10 40 00 32          beqz                 $v0, 0x47c8c9c
    // 00 00 00 00          nop
    char code[] =
        "\x24\x06\x00\x03\x10\xa6\x00\x79\x30\x42\x00\xfc\x10\x40\x00\x32\x24"
        "\xab\xff\xda\x2d\x62\x00\x02\x10\x40\x00\x32\x00\x00\x00\x00";
    uint32_t r_pc = 0x0;
    uint32_t r_v0 = 0xff;
    uint32_t r_a1 = 0x3;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_V0, &r_v0));
    OK(uc_reg_write(uc, UC_MIPS_REG_A1, &r_a1));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) + 16, 0, 2));

    OK(uc_reg_read(uc, UC_MIPS_REG_PC, &r_pc));
    OK(uc_reg_read(uc, UC_MIPS_REG_V0, &r_v0));
    TEST_CHECK(r_pc == code_start + 4 + 0x1e8);
    TEST_CHECK(r_v0 == 0xfc);

    OK(uc_close(uc));
}

static void test_mips_lwx_exception_issue_1314(void)
{
    uc_engine *uc;
    char code[] = "\x0a\xc8\x79\x7e"; // lwx $t9, $t9($s3)
    int reg;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_mem_map(uc, 0x10000, 0x4000, UC_PROT_ALL));

    // Enable DSP
    // https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MD00090-2B-MIPS32PRA-AFP-06.02.pdf
    OK(uc_reg_read(uc, UC_MIPS_REG_CP0_STATUS, &reg));
    reg |= (1 << 24);
    OK(uc_reg_write(uc, UC_MIPS_REG_CP0_STATUS, &reg));

    reg = 0;
    OK(uc_reg_write(uc, UC_MIPS_REG_1, &reg));
    OK(uc_reg_write(uc, UC_MIPS_REG_T9, &reg));
    reg = LEINT32(0xdeadbeef);
    OK(uc_mem_write(uc, 0x10000, &reg, 4));
    reg = 0x10000;
    OK(uc_reg_write(uc, UC_MIPS_REG_S3, &reg));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_T9, &reg));

    TEST_CHECK(reg == 0xdeadbeef);

    OK(uc_close(uc));
}

static void test_mips_mips16(void)
{
    uc_engine *uc;
    char code[] = "\xC4\x6B\x49\xE3"; // li $v1, 0xC4;  addu $v0, $v1, $v0
    int r_v0 = 0x6789;
    int mips16_lowbit = 1;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_V0, &r_v0));

    OK(uc_emu_start(uc, code_start | mips16_lowbit,
                    code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_V0, &r_v0));

    TEST_CHECK(r_v0 == 0x684D);

    OK(uc_close(uc));
}

static void test_mips_mips_fpr(void)
{
    uc_engine *uc;
    uint64_t r_f1;
    // ks.asm("li $t1, 0x42f6e979;mtc1 $t1, $f1")
    const char code[] = "\xf6\x42\x09\x3c\x79\xe9\x29\x35\x00\x08\x89\x44";
    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32, code, sizeof(code) - 1);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_F1, (void *)&r_f1));

    TEST_CHECK(r_f1 = 0x42f6e979);

    OK(uc_close(uc));
}

static void test_mips_simple_coredump_2134(void)
{
    uc_engine *uc;
    const char code[] = "\x25\xc8\x80\x03\x25\x78\xe0\x03\x09\xf8\x20\x03\x10\x00\x18\x24";
    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32, code, sizeof(code) - 1);

    uc_assert_err(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0), UC_ERR_FETCH_UNMAPPED);

    OK(uc_close(uc));
}

static void test_mips_simple_coredump_2137(void)
{
    uc_engine *uc;
    const char code[] = "\x1c\x00\x40\x54\xe8\x00\xc4\xaf";
    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32, code, sizeof(code) - 1);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_mips_dsp_maq_full_accumulator(void)
{
    static const struct {
        uint32_t hi, lo, a, b, result_hi, result_lo, flag;
    } cases[] = {
        {0x80000000, 0x80000000, 0x80008000, 0x80008000, UINT32_MAX, 0x80000000,
         1},
        {0x40000000, 0x00000000, 0, 0, 0, 0x7fffffff, 1},
        {0xc0000000, 0x00000000, 0, 0, UINT32_MAX, 0x80000000, 1},
        {0, 0x7fffffff, 0, 0, 0, 0x7fffffff, 0},
        {UINT32_MAX, 0x80000000, 0, 0, UINT32_MAX, 0x80000000, 0},
        {UINT32_MAX, 0xffffffff, 0x00010001, 0x00010001, 0, 1, 0},
        {0x7fffffff, 0xffffffff, 0x00010001, 0x00010001, UINT32_MAX, 0x80000000,
         1},
    };
    for (unsigned big = 0; big < 2; ++big) {
        for (unsigned right = 0; right < 2; ++right) {
            uc_engine *uc;
            OK(uc_open(UC_ARCH_MIPS,
                       UC_MODE_MIPS32 |
                           (big ? UC_MODE_BIG_ENDIAN : UC_MODE_LITTLE_ENDIAN),
                       &uc));
            OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS32_74KF));
            OK(uc_mem_map(uc, code_start, 4096, UC_PROT_ALL));
            // Enable DSP, clear DSPControl, write AC2, execute MAQ_SA and read
            // AC2/OUTFLAG.
            const uint32_t ops[] = {
                0x40086000, 0x3c090100, 0x01094025,
                0x40886000, 0xc0,       0x7c01fcf8,
                0x00801011, 0x00a01013, 0x7cc71430 | (right << 7),
                0x00401010, 0x00401812, 0x7c3f44b8};
            uint8_t code[sizeof(ops)];
            for (unsigned j = 0; j < sizeof(ops) / sizeof(ops[0]); ++j)
                for (unsigned k = 0; k < 4; ++k)
                    code[4 * j + k] = ops[j] >> (8 * (big ? 3 - k : k));
            OK(uc_mem_write(uc, code_start, code, sizeof(code)));
            for (unsigned k = 0; k < sizeof(cases) / sizeof(cases[0]); ++k) {
                uint32_t hi = 0, lo = 0, flags = 0;
                OK(uc_reg_write(uc, UC_MIPS_REG_A0, &cases[k].hi));
                OK(uc_reg_write(uc, UC_MIPS_REG_A1, &cases[k].lo));
                OK(uc_reg_write(uc, UC_MIPS_REG_A2, &cases[k].a));
                OK(uc_reg_write(uc, UC_MIPS_REG_A3, &cases[k].b));
                OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0,
                                0));
                OK(uc_reg_read(uc, UC_MIPS_REG_V0, &hi));
                OK(uc_reg_read(uc, UC_MIPS_REG_V1, &lo));
                OK(uc_reg_read(uc, UC_MIPS_REG_T0, &flags));
                TEST_CHECK(hi == cases[k].result_hi);
                TEST_CHECK(lo == cases[k].result_lo);
                TEST_CHECK(flags == (cases[k].flag << 18));
            }
            OK(uc_close(uc));
        }
    }
}

static void test_micromips64r6_generic(void)
{
    // Physical halfword order is independent of host and target byte order.
    // These execute directly in the microMIPS translator, without conversion
    // into classic opcodes by the caller.
    const uint32_t words[] = {0x54c41130, 0xbc440000, 0xb8440008, 0x41020003};
    for (unsigned big = 0; big < 2; ++big) {
        uc_engine *uc;
        OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 |
                       (big ? UC_MODE_BIG_ENDIAN : UC_MODE_LITTLE_ENDIAN), &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_MICROMIPS64R6_GENERIC));
        OK(uc_mem_map(uc, code_start, 4096, UC_PROT_ALL));
        uint64_t status = 0;
        OK(uc_reg_read(uc, UC_MIPS_REG_CP0_STATUS, &status));
        status |= 0x24000000; // CU1 and FR
        OK(uc_reg_write(uc, UC_MIPS_REG_CP0_STATUS, &status));
        uint8_t code[sizeof(words)];
        for (unsigned j = 0; j < sizeof(words) / sizeof(words[0]); ++j)
            for (unsigned k = 0; k < 4; ++k) {
                unsigned half = words[j] >> (k < 2 ? 16 : 0);
                code[j * 4 + k] = half >> (8 * (big ? 1 - k % 2 : k % 2));
            }
        OK(uc_mem_write(uc, code_start, code, sizeof(code)));
        uint64_t a = 0x3ff4000000000000ull, b = 0xbff8000000000000ull;
        uint64_t actual = 0;
        uint32_t csr = 0xc0000;
        OK(uc_reg_write(uc, UC_MIPS_REG_F4, &a));
        OK(uc_reg_write(uc, UC_MIPS_REG_F6, &b));
        OK(uc_reg_write(uc, UC_MIPS_REG_FCSR, &csr));
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 1));
        OK(uc_reg_read(uc, UC_MIPS_REG_F2, &actual));
        TEST_CHECK(actual == 0xbfd0000000000000ull); // 1.25 - 1.5
        OK(uc_reg_read(uc, UC_MIPS_REG_FCSR, &csr));
        TEST_CHECK(csr == 0xc0000);

        uint64_t address = code_start + 256;
        const uint8_t data[] = {0x81, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
        uint8_t copied[8] = {0};
        OK(uc_reg_write(uc, UC_MIPS_REG_A0, &address));
        OK(uc_mem_write(uc, address, data, sizeof(data)));
        OK(uc_emu_start(uc, (code_start + 4) | 1, code_start + 12, 0, 2));
        OK(uc_mem_read(uc, address + 8, copied, sizeof(copied)));
        TEST_CHECK(memcmp(copied, data, sizeof(data)) == 0);
        for (unsigned odd = 0; odd < 2; ++odd) {
            uint64_t fp = odd, pc = 0;
            OK(uc_reg_write(uc, UC_MIPS_REG_F2, &fp));
            OK(uc_emu_start(uc, (code_start + 12) | 1, code_start + 64, 0, 1));
            OK(uc_reg_read(uc, UC_MIPS_REG_PC, &pc));
            TEST_CHECK((pc & ~1ull) == code_start + (odd ? 16 : 22));
        }
        OK(uc_close(uc));
    }
}

static void test_micromips64r6_doublewords(void)
{
    const struct {
        uint32_t word;
        uint64_t a, b, expected;
        int result;
    } cases[] = {
        {0x58a41018, 0x100000001ull, 3, 0x300000003ull, UC_MIPS_REG_V0},
        {0x58a41058, (uint64_t)-3, 3, UINT64_MAX, UC_MIPS_REG_V0},
        {0x58a410d8, UINT64_MAX, 2, 1, UC_MIPS_REG_V0},
        {0x58a41118, (uint64_t)-55, 3, (uint64_t)-18, UC_MIPS_REG_V0},
        {0x58a41158, (uint64_t)-55, 3, UINT64_MAX, UC_MIPS_REG_V0},
        {0x58445b3c, 0x100000001ull, 3, 31, UC_MIPS_REG_V0},
        {0x58447b3c, 0x0123456789abcdefull, 3, 0x23016745ab89efcdull, UC_MIPS_REG_V0},
        {0x5844fb3c, 0x0123456789abcdefull, 3, 0xcdef89ab45670123ull, UC_MIPS_REG_V0},
        {0x4224fffc, 0x123456789abcdef0ull, 3, 0x123456749abcdef0ull, UC_MIPS_REG_A0},
        {0x4204fffc, 0x123456789abcdef0ull, 3, 0x123056789abcdef0ull, UC_MIPS_REG_A0},
        {0x5c44fff8, 0x100000001ull, 3, 0xfffffff9ull, UC_MIPS_REG_V0},
    };
    for (unsigned big = 0; big < 2; ++big) {
        uc_engine *uc;
        OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 |
                       (big ? UC_MODE_BIG_ENDIAN : UC_MODE_LITTLE_ENDIAN), &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_MICROMIPS64R6_GENERIC));
        OK(uc_mem_map(uc, code_start, 4096, UC_PROT_ALL));
        for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint8_t code[4];
            for (unsigned k = 0; k < 4; ++k) {
                unsigned half = cases[i].word >> (k < 2 ? 16 : 0);
                code[k] = half >> (8 * (big ? 1 - k % 2 : k % 2));
            }
            OK(uc_mem_write(uc, code_start + 4 * i, code, 4));
        }
        for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            uint64_t actual = 0, pc = 0;
            OK(uc_reg_write(uc, UC_MIPS_REG_A0, &cases[i].a));
            OK(uc_reg_write(uc, UC_MIPS_REG_A1, &cases[i].b));
            OK(uc_emu_start(uc, (code_start + 4 * i) | 1,
                            code_start + 4096, 0, 1));
            OK(uc_reg_read(uc, cases[i].result, &actual));
            TEST_CHECK(actual == cases[i].expected);
            OK(uc_reg_read(uc, UC_MIPS_REG_PC, &pc));
            TEST_CHECK(pc == code_start + 4 * (i + 1));
        }
        // LD/SD consume raw target-order memory, with no host integer cast.
        const uint32_t memory_words[] = {0xdc440010, 0xd8440018, 0x5800003f};
        uint8_t code[sizeof(memory_words)];
        for (unsigned j = 0; j < 3; ++j)
            for (unsigned k = 0; k < 4; ++k) {
                unsigned half = memory_words[j] >> (k < 2 ? 16 : 0);
                code[j * 4 + k] = half >> (8 * (big ? 1 - k % 2 : k % 2));
            }
        const uint8_t data[] = {0x81, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
        uint8_t actual[8] = {0};
        uint64_t address = code_start + 512;
        OK(uc_mem_write(uc, code_start + 128, code, sizeof(code)));
        OK(uc_mem_write(uc, address + 16, data, sizeof(data)));
        OK(uc_reg_write(uc, UC_MIPS_REG_A0, &address));
        OK(uc_emu_start(uc, (code_start + 128) | 1, code_start + 136, 0, 2));
        OK(uc_mem_read(uc, address + 24, actual, sizeof(actual)));
        TEST_CHECK(memcmp(data, actual, sizeof(data)) == 0);
        TEST_CHECK(uc_emu_start(uc, (code_start + 136) | 1,
                               code_start + 140, 0, 1) == UC_ERR_EXCEPTION);
        OK(uc_close(uc));
    }
}

static void test_micromips_multiple_words(void)
{
    // microMIPS32 Vol. II r5.03 LWM/SWM: each element occupies four bytes;
    // loads sign-extend words on a 64-bit CPU. Test bytes independently of
    // the reciprocal load/store so a shared width defect cannot cancel out.
    const unsigned registers[] = {16, 17, 18, 19, 20, 21, 22, 23, 30, 31};
    for (unsigned wide = 0; wide < 2; ++wide) {
        for (unsigned big = 0; big < 2; ++big) {
            uc_engine *uc;
            OK(uc_open(UC_ARCH_MIPS, (wide ? UC_MODE_MIPS64 : UC_MODE_MIPS32) |
                           (big ? UC_MODE_BIG_ENDIAN : UC_MODE_LITTLE_ENDIAN), &uc));
            OK(uc_ctl_set_cpu_model(uc, wide ? UC_CPU_MIPS64_MICROMIPS64R2_GENERIC
                                            : UC_CPU_MIPS32_MICROMIPS32R2_GENERIC));
            OK(uc_mem_map(uc, code_start, 4096, UC_PROT_ALL));
            OK(uc_mem_map(uc, 0x20000, 4096, UC_PROT_ALL));
            uint64_t sp = 0x20000;
            OK(uc_reg_write(uc, UC_MIPS_REG_SP, &sp));
            unsigned site = 0;
            for (unsigned compact = 0; compact < 2; ++compact) {
                for (unsigned count = 0; count <= (compact ? 4 : 9); ++count) {
                    for (unsigned ra = 0; ra < 2; ++ra) {
                        if ((!count && !ra) || (compact && (!ra || !count)))
                            continue;
                        const unsigned offset = compact ? 60 : 144;
                        const unsigned size = compact ? 2 : 4;
                        const uint32_t store = compact ? 0x454f | ((count - 1) << 4)
                            : 0x201dd000 | ((count | (ra << 4)) << 21) | offset;
                        const uint32_t load = compact ? store - 0x40 : store - 0x8000;
                        uint8_t code[8];
                        for (unsigned inst = 0; inst < 2; ++inst) {
                            const uint32_t word = inst ? load : store;
                            for (unsigned k = 0; k < size; ++k) {
                                const unsigned half = word >> (size == 4 && k < 2 ? 16 : 0);
                                code[inst * size + k] = half >> (8 * (big ? 1 - k % 2 : k % 2));
                            }
                        }
                        const uint64_t pc = code_start + site;
                        site += sizeof(code);
                        OK(uc_mem_write(uc, pc, code, size * 2));
                        uint64_t values[10];
                        uint8_t expected[256], actual[256];
                        memset(expected, 0xa5, sizeof(expected));
                        OK(uc_mem_write(uc, sp, expected, sizeof(expected)));
                        for (unsigned i = 0; i < 10; ++i) {
                            const uint32_t word = 0x87654321u ^ (0x12345678u * i);
                            values[i] = 0xabcdef1200000000ull | word;
                            OK(uc_reg_write(uc, UC_MIPS_REG_0 + registers[i], &values[i]));
                            if (i < count || (i == 9 && ra)) {
                                const unsigned pos = offset + 4 * (i == 9 ? count : i);
                                for (unsigned k = 0; k < 4; ++k)
                                    expected[pos + k] = word >> (8 * (big ? 3 - k : k));
                            }
                        }
                        OK(uc_emu_start(uc, pc | 1, pc + size, 0, 1));
                        OK(uc_mem_read(uc, sp, actual, sizeof(actual)));
                        TEST_CHECK(memcmp(actual, expected, sizeof(actual)) == 0);
                        for (unsigned i = 0; i < 10; ++i) {
                            uint64_t zero = 0;
                            OK(uc_reg_write(uc, UC_MIPS_REG_0 + registers[i], &zero));
                        }
                        OK(uc_emu_start(uc, (pc + size) | 1, pc + 2 * size, 0, 1));
                        for (unsigned i = 0; i < 10; ++i) {
                            uint64_t value = 0;
                            OK(uc_reg_read(uc, UC_MIPS_REG_0 + registers[i], &value));
                            uint64_t wanted = i < count || (i == 9 && ra)
                                ? (uint64_t)(int64_t)(int32_t)values[i] : 0;
                            if (!wide)
                                wanted = (uint32_t)wanted;
                            TEST_CHECK(value == wanted);
                        }
                    }
                }
            }
            OK(uc_close(uc));
        }
    }
}

static void test_micromips_legacy_fpu(void)
{
    // Literal microMIPS instructions, in fetch-halfword order, run directly
    // through the micro decoder. No caller translates them to classic COP1.
    const struct {
        uint32_t word;
        uint64_t a, b, c, expected;
        bool full_register;
    } cases[] = {
        {0x54c41030, 0x3fa00000, 0xbfc00000, 0, 0xbe800000, false}, // add.s
        {0x54c41130, 0x3ff4000000000000ull, 0xbff8000000000000ull,
         0, 0xbfd0000000000000ull, true}, // add.d
        {0x54c41230, 0x3f8000003fa00000ull, 0x40000000bfc00000ull,
         0, 0x40400000be800000ull, true}, // add.ps
        {0x54c41201, 0x3fa00000, 0xbfc00000, 0x40800000,
         0x40080000, false}, // madd.s f2,f8,f4,f6: 4 + 1.25 * -1.5
    };
    for (unsigned wide = 0; wide < 2; ++wide) {
        for (unsigned big = 0; big < 2; ++big) {
            uc_engine *uc;
            OK(uc_open(UC_ARCH_MIPS, (wide ? UC_MODE_MIPS64 : UC_MODE_MIPS32) |
                           (big ? UC_MODE_BIG_ENDIAN : UC_MODE_LITTLE_ENDIAN),
                       &uc));
            OK(uc_ctl_set_cpu_model(uc, wide ? UC_CPU_MIPS64_MICROMIPS64R2_GENERIC
                                            : UC_CPU_MIPS32_MICROMIPS32R2_GENERIC));
            OK(uc_mem_map(uc, code_start, 4096, UC_PROT_ALL));
            uint64_t status = 0;
            OK(uc_reg_read(uc, UC_MIPS_REG_CP0_STATUS, &status));
            status |= 0x24000000; // CU1 and FR=1, legacy NAN/ABS mode
            OK(uc_reg_write(uc, UC_MIPS_REG_CP0_STATUS, &status));
            for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
                uint8_t bytes[4];
                for (unsigned k = 0; k < 4; ++k) {
                    unsigned half = cases[i].word >> (k < 2 ? 16 : 0);
                    bytes[k] = half >> (8 * (big ? 1 - k % 2 : k % 2));
                }
                OK(uc_mem_write(uc, code_start + 4 * i, bytes, sizeof(bytes)));
                uint64_t actual = 0;
                uint32_t csr = 0;
                OK(uc_reg_write(uc, UC_MIPS_REG_F4, &cases[i].a));
                OK(uc_reg_write(uc, UC_MIPS_REG_F6, &cases[i].b));
                OK(uc_reg_write(uc, UC_MIPS_REG_F8, &cases[i].c));
                OK(uc_reg_write(uc, UC_MIPS_REG_FCSR, &csr));
                OK(uc_emu_start(uc, (code_start + 4 * i) | 1,
                                code_start + 4 * (i + 1), 0, 1));
                OK(uc_reg_read(uc, UC_MIPS_REG_F2, &actual));
                TEST_CHECK((cases[i].full_register ? actual : (uint32_t)actual) ==
                           cases[i].expected);
                OK(uc_reg_read(uc, UC_MIPS_REG_FCSR, &csr));
                TEST_CHECK(csr == 0);
            }
            // FR=0 doubles span two architectural FPR words in either byte
            // order. The byte order affects fetch, not the register pairing.
            status &= ~0x04000000ull;
            OK(uc_reg_write(uc, UC_MIPS_REG_CP0_STATUS, &status));
            uint64_t zero = 0, a_hi = 0x3ff40000, b_hi = 0xbff80000;
            uint64_t lo = 0, hi = 0;
            OK(uc_reg_write(uc, UC_MIPS_REG_F4, &zero));
            OK(uc_reg_write(uc, UC_MIPS_REG_F5, &a_hi));
            OK(uc_reg_write(uc, UC_MIPS_REG_F6, &zero));
            OK(uc_reg_write(uc, UC_MIPS_REG_F7, &b_hi));
            OK(uc_emu_start(uc, (code_start + 4) | 1, code_start + 8, 0, 1));
            OK(uc_reg_read(uc, UC_MIPS_REG_F2, &lo));
            OK(uc_reg_read(uc, UC_MIPS_REG_F3, &hi));
            TEST_CHECK((uint32_t)lo == 0);
            TEST_CHECK((uint32_t)hi == 0xbfd00000);

            // Legacy ABS signals Invalid for a signaling NaN and suppresses
            // the destination write when the exception is enabled.
            const uint32_t abs_word = 0x5444037b; // abs.s f2,f4
            uint8_t abs_bytes[4];
            for (unsigned k = 0; k < 4; ++k) {
                unsigned half = abs_word >> (k < 2 ? 16 : 0);
                abs_bytes[k] = half >> (8 * (big ? 1 - k % 2 : k % 2));
            }
            OK(uc_mem_write(uc, code_start + 32, abs_bytes, sizeof(abs_bytes)));
            uint64_t snan = 0x7fc00000, sentinel = 0x12345678, result = 0;
            uint32_t csr = 0x800;
            OK(uc_reg_write(uc, UC_MIPS_REG_F4, &snan));
            OK(uc_reg_write(uc, UC_MIPS_REG_F2, &sentinel));
            OK(uc_reg_write(uc, UC_MIPS_REG_FCSR, &csr));
            TEST_CHECK(uc_emu_start(uc, (code_start + 32) | 1,
                                   code_start + 36, 0, 1) == UC_ERR_EXCEPTION);
            OK(uc_reg_read(uc, UC_MIPS_REG_F2, &result));
            OK(uc_reg_read(uc, UC_MIPS_REG_FCSR, &csr));
            TEST_CHECK((uint32_t)result == sentinel);
            TEST_CHECK(csr & 0x10000);
            // Exposing a FPU does not bypass the guest coprocessor enable.
            csr = 0;
            OK(uc_reg_write(uc, UC_MIPS_REG_FCSR, &csr));
            OK(uc_reg_write(uc, UC_MIPS_REG_F4, &cases[0].a));
            OK(uc_reg_write(uc, UC_MIPS_REG_F6, &cases[0].b));
            status &= ~0x20000000ull;
            OK(uc_reg_write(uc, UC_MIPS_REG_CP0_STATUS, &status));
            TEST_CHECK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 1) ==
                       UC_ERR_EXCEPTION);
            OK(uc_reg_read(uc, UC_MIPS_REG_F2, &result));
            TEST_CHECK((uint32_t)result == sentinel);
            OK(uc_close(uc));
        }
    }
}

static void test_micromips64_legacy_arguments_and_frame(void)
{
    // GNU as 2.47, microMIPS64r2, independently checked in both byte orders.
    const struct {
        uint32_t word;
        uint64_t expected;
    } forms[] = {
        {0x5c44ffef, 0x8123456789abcddeull}, // daddiu $2,$4,-17
        {0x58a41150, 0x8123456789abcdf6ull}, // daddu $2,$4,$5
        {0x58a411d0, 0x8123456789abcde8ull}, // dsubu $2,$4,$5
        {0x58443800, 0x91a2b3c4d5e6f780ull}, // dsll $2,$4,7
        {0x58443840, 0x0102468acf13579bull}, // dsrl $2,$4,7
        {0x58443880, 0xff02468acf13579bull}, // dsra $2,$4,7
        {0x584438c0, 0xdf02468acf13579bull}, // drotr $2,$4,7
        {0x58443808, 0xd5e6f78000000000ull}, // dsll32 $2,$4,7
        {0x58443848, 0x000000000102468aull}, // dsrl32 $2,$4,7
        {0x58443888, 0xffffffffff02468aull}, // dsra32 $2,$4,7
        {0x584438c8, 0xcf13579bdf02468aull}, // drotr32 $2,$4,7
        {0x58851010, 0x91a2b3c4d5e6f780ull}, // dsllv $2,$4,$5
        {0x58851050, 0x0102468acf13579bull}, // dsrlv $2,$4,$5
        {0x58851090, 0xff02468acf13579bull}, // dsrav $2,$4,$5
        {0x588510d0, 0xdf02468acf13579bull}, // drotrv $2,$4,$5
        {0x584481ec, 0x000000000001579bull}, // dext $2,$4,7,17
        {0x584439e4, 0x0000008acf13579bull}, // dextm $2,$4,7,40
        {0x584481d4, 0x000000000000468aull}, // dextu $2,$4,39,17
        {0x5844b9cc, 0x55aa55aa55e6f7aaull}, // dins $2,$4,7,17
        {0x584471c4, 0x55aa33c4d5e6f7aaull}, // dinsm $2,$4,7,40
        {0x5844b9f4, 0x55e6f7aa55aa55aaull}, // dinsu $2,$4,39,17
        {0x5844f824, 0x8123456789abcdefull}, // dextm $2,$4,0,64
    };
    const uint32_t transfers[] = {0x54802c3b, 0x5440243b}; // DMTC1 / DMFC1
    const uint32_t frame[] = {0x5fbdffe0, 0xd89d0010, 0xdc5d0010, 0x5fbd0020};
    for (unsigned big = 0; big < 2; ++big) {
        uc_engine *uc;
        OK(uc_open(UC_ARCH_MIPS,
                   UC_MODE_MIPS64 |
                       (big ? UC_MODE_BIG_ENDIAN : UC_MODE_LITTLE_ENDIAN),
                   &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_MICROMIPS64R2_GENERIC));
        OK(uc_mem_map(uc, code_start, 4096, UC_PROT_ALL));
        uint64_t a = 0x8123456789abcdefull, b = 7, result = 0, status = 0;
        OK(uc_reg_read(uc, UC_MIPS_REG_CP0_STATUS, &status));
        status |= 0x24000000;
        OK(uc_reg_write(uc, UC_MIPS_REG_CP0_STATUS, &status));
        OK(uc_reg_write(uc, UC_MIPS_REG_A0, &a));
        OK(uc_reg_write(uc, UC_MIPS_REG_A1, &b));
        for (unsigned i = 0; i < sizeof(forms) / sizeof(forms[0]); ++i) {
            uint8_t bytes[4];
            for (unsigned k = 0; k < 4; ++k) {
                unsigned half = forms[i].word >> (k < 2 ? 16 : 0);
                bytes[k] = half >> (8 * (big ? 1 - k % 2 : k % 2));
            }
            uint64_t destination = 0x55aa55aa55aa55aaull;
            OK(uc_reg_write(uc, UC_MIPS_REG_V0, &destination));
            OK(uc_mem_write(uc, code_start + 4 * i, bytes, sizeof(bytes)));
            OK(uc_emu_start(uc, (code_start + 4 * i) | 1,
                            code_start + 4 * (i + 1), 0, 1));
            OK(uc_reg_read(uc, UC_MIPS_REG_V0, &result));
            TEST_CHECK(result == forms[i].expected);
            TEST_MSG("word %08x got %016llx expected %016llx", forms[i].word,
                     (unsigned long long)result,
                     (unsigned long long)forms[i].expected);
        }
        // Invalid extract/insert fields must fault even when rt is zero.
        const uint32_t invalid[] = {0x5844ffe4, 0x584407cc, 0x584407f4};
        for (unsigned i = 0; i < 6; ++i) {
            uint32_t word = invalid[i / 2] & ~(i % 2 ? 31u << 21 : 0);
            uint8_t bytes[4];
            for (unsigned k = 0; k < 4; ++k) {
                unsigned half = word >> (k < 2 ? 16 : 0);
                bytes[k] = half >> (8 * (big ? 1 - k % 2 : k % 2));
            }
            uint64_t sentinel = 0x55aa55aa55aa55aaull;
            OK(uc_reg_write(uc, UC_MIPS_REG_V0, &sentinel));
            OK(uc_mem_write(uc, code_start + 256 + i * 4, bytes, 4));
            TEST_CHECK(uc_emu_start(uc, (code_start + 256 + i * 4) | 1,
                                    code_start + 260 + i * 4, 0,
                                    1) == UC_ERR_EXCEPTION);
            OK(uc_reg_read(uc, UC_MIPS_REG_V0, &result));
            TEST_CHECK(result == sentinel);
        }
        for (unsigned group = 0; group < 2; ++group) {
            const uint32_t *words = group ? frame : transfers;
            unsigned count = group ? 4 : 2;
            uint8_t bytes[16];
            for (unsigned k = 0; k < count * 4; ++k) {
                unsigned half = words[k / 4] >> (k % 4 < 2 ? 16 : 0);
                bytes[k] = half >> (8 * (big ? 1 - k % 2 : k % 2));
            }
            uint64_t pc = code_start + 128 + group * 32, sp = code_start + 2048;
            OK(uc_mem_write(uc, pc, bytes, count * 4));
            OK(uc_reg_write(uc, UC_MIPS_REG_SP, &sp));
            OK(uc_emu_start(uc, pc | 1, pc + count * 4, 0, count));
            OK(uc_reg_read(uc, UC_MIPS_REG_V0, &result));
            TEST_CHECK(result == a);
            OK(uc_reg_read(uc, UC_MIPS_REG_SP, &result));
            TEST_CHECK(result == sp);
            if (group) {
                uint8_t memory[8];
                OK(uc_mem_read(uc, sp - 16, memory, 8));
                for (unsigned k = 0; k < 8; ++k)
                    TEST_CHECK(memory[k] ==
                               (uint8_t)(a >> (8 * (big ? 7 - k : k))));
            }
        }
        OK(uc_close(uc));
        // A 32-bit generic micro FPU must not acquire doubleword GPR transfers.
        OK(uc_open(UC_ARCH_MIPS,
                   UC_MODE_MIPS32 |
                       (big ? UC_MODE_BIG_ENDIAN : UC_MODE_LITTLE_ENDIAN),
                   &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS32_MICROMIPS32R2_GENERIC));
        OK(uc_mem_map(uc, code_start, 4096, UC_PROT_ALL));
        OK(uc_reg_read(uc, UC_MIPS_REG_CP0_STATUS, &status));
        status |= 0x24000000;
        OK(uc_reg_write(uc, UC_MIPS_REG_CP0_STATUS, &status));
        for (unsigned i = 0; i < 2; ++i) {
            uint8_t bytes[4];
            for (unsigned k = 0; k < 4; ++k) {
                unsigned half = transfers[i] >> (k < 2 ? 16 : 0);
                bytes[k] = half >> (8 * (big ? 1 - k % 2 : k % 2));
            }
            OK(uc_mem_write(uc, code_start + i * 4, bytes, 4));
            TEST_CHECK(uc_emu_start(uc, (code_start + i * 4) | 1,
                                    code_start + i * 4 + 4, 0,
                                    1) == UC_ERR_EXCEPTION);
        }
        OK(uc_close(uc));
    }
}

static void check_mips_fp_memory_alignment(bool r6)
{
    // MIPS64 Volume II rev 2.50: COP1X aligned memory forms require the
    // natural alignment. LUXC1/SUXC1 instead ignore the low three bits.
    // R6's ordinary COP1 loads/stores permit unaligned addresses.
    static const struct {
        uint32_t word;
        unsigned bytes;
        bool store;
        bool ignore_low;
    } forms[] = {
        {0xc4820000, 4, false, false}, // lwc1 f2,0(a0)
        {0xd4820000, 8, false, false}, // ldc1 f2,0(a0)
        {0xe4820000, 4, true, false},  // swc1 f2,0(a0)
        {0xf4820000, 8, true, false},  // sdc1 f2,0(a0)
        {0x4c850080, 4, false, false}, // lwxc1 f2,a1(a0)
        {0x4c850081, 8, false, false}, // ldxc1 f2,a1(a0)
        {0x4c851008, 4, true, false},  // swxc1 f2,a1(a0)
        {0x4c851009, 8, true, false},  // sdxc1 f2,a1(a0)
        {0x4c850085, 8, false, true},  // luxc1 f2,a1(a0)
        {0x4c85100d, 8, true, true},   // suxc1 f2,a1(a0)
    };
    const uint64_t data = code_start + 0x2000;
    const uint64_t initial = 0xfedcba9876543210ull;
    for (unsigned wide = 0; wide < 2; ++wide) {
        for (unsigned big = 0; big < 2; ++big) {
            for (unsigned fr = 0; fr < 2; ++fr) {
                if ((wide || r6) && !fr)
                    continue;
                uc_engine *uc;
                uint64_t status = 0;
                OK(uc_open(UC_ARCH_MIPS,
                           (wide ? UC_MODE_MIPS64 : UC_MODE_MIPS32) |
                               (big ? UC_MODE_BIG_ENDIAN : 0),
                           &uc));
                OK(uc_ctl_set_cpu_model(
                    uc, wide ? (r6 ? UC_CPU_MIPS64_I6400
                                   : UC_CPU_MIPS64_MIPS64R2_GENERIC)
                             : (r6 ? UC_CPU_MIPS32_MIPS32R6_GENERIC
                                   : UC_CPU_MIPS32_74KF)));
                OK(uc_reg_read(uc, UC_MIPS_REG_CP0_STATUS, &status));
                status = (status & ~0x04000000ull) | 0x20000000 |
                         (fr ? 0x04000000 : 0);
                OK(uc_reg_write(uc, UC_MIPS_REG_CP0_STATUS, &status));
                OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
                for (unsigned form = 0; form < (r6 ? 4 : 10); ++form) {
                    if (!fr && forms[form].ignore_low)
                        continue;
                    uint8_t code[4];
                    for (unsigned k = 0; k < 4; ++k)
                        code[k] = forms[form].word >> (8 * (big ? 3 - k : k));
                    const uint64_t pc = code_start + 4 * form;
                    OK(uc_mem_write(uc, pc, code, sizeof(code)));
                    for (unsigned offset = 0; offset < 8; ++offset) {
                        uint8_t before[16], expected[16], actual[16];
                        for (unsigned k = 0; k < sizeof(before); ++k)
                            before[k] = expected[k] = 0x91 + k;
                        uint64_t base = data + (form < 4 ? offset : 0);
                        uint64_t index = form < 4 ? 0 : offset;
                        uint64_t low = fr ? initial : (uint32_t)initial;
                        uint64_t high = initial >> 32;
                        uint64_t fcsr = 0x00800004;
                        OK(uc_mem_write(uc, data, before, sizeof(before)));
                        OK(uc_reg_write(uc, UC_MIPS_REG_A0, &base));
                        OK(uc_reg_write(uc, UC_MIPS_REG_A1, &index));
                        OK(uc_reg_write(uc, UC_MIPS_REG_F2, &low));
                        if (!fr)
                            OK(uc_reg_write(uc, UC_MIPS_REG_F3, &high));
                        OK(uc_reg_write(uc, UC_MIPS_REG_FCSR, &fcsr));
                        // R6 masks legacy FCC bits and retains its NaN mode.
                        OK(uc_reg_read(uc, UC_MIPS_REG_FCSR, &fcsr));
                        const uint64_t initial_fcsr = fcsr;
                        const unsigned size = forms[form].bytes;
                        const bool valid = r6 || forms[form].ignore_low ||
                                           offset % size == 0;
                        const unsigned start = forms[form].ignore_low ? 0 : offset;
                        const uc_err result = uc_emu_start(uc, pc, pc + 4, 0, 1);
                        TEST_CHECK((result == UC_ERR_OK) == valid);
                        TEST_MSG("r6=%u wide=%u big=%u fr=%u form=%u offset=%u: %s",
                                 r6, wide, big, fr, form, offset,
                                 uc_strerror(result));
                        uint64_t value = initial;
                        if (valid && forms[form].store) {
                            for (unsigned k = 0; k < size; ++k)
                                expected[start + k] =
                                    initial >> (8 * (big ? size - 1 - k : k));
                        } else if (valid) {
                            value = 0;
                            for (unsigned k = 0; k < size; ++k)
                                value |= (uint64_t)before[start + k]
                                         << (8 * (big ? size - 1 - k : k));
                        }
                        OK(uc_mem_read(uc, data, actual, sizeof(actual)));
                        TEST_CHECK(memcmp(actual, expected, sizeof(actual)) == 0);
                        OK(uc_reg_read(uc, UC_MIPS_REG_F2, &low));
                        // A valid word load defines only the low word in FR=1.
                        if (!fr || (valid && !forms[form].store && size == 4))
                            TEST_CHECK((uint32_t)low == (uint32_t)value);
                        else
                            TEST_CHECK(low == value);
                        if (!fr) {
                            OK(uc_reg_read(uc, UC_MIPS_REG_F3, &high));
                            TEST_CHECK(high == (valid && !forms[form].store &&
                                                        size == 8
                                                    ? value >> 32
                                                    : initial >> 32));
                        }
                        OK(uc_reg_read(uc, UC_MIPS_REG_FCSR, &fcsr));
                        TEST_CHECK(fcsr == initial_fcsr);
                    }
                }
                OK(uc_close(uc));
            }
        }
    }
}

static void test_mips_fp_memory_alignment(void)
{
    check_mips_fp_memory_alignment(false);
}

static void test_mips_r6_fp_unaligned_memory(void)
{
    check_mips_fp_memory_alignment(true);
}

TEST_LIST = {
    {"test_mips_fp_memory_alignment", test_mips_fp_memory_alignment},
    {"test_mips_r6_fp_unaligned_memory", test_mips_r6_fp_unaligned_memory},
    {"test_micromips_multiple_words", test_micromips_multiple_words},
    {"test_micromips64_legacy_arguments_and_frame",
     test_micromips64_legacy_arguments_and_frame},
    {"test_micromips_legacy_fpu", test_micromips_legacy_fpu},
    {"test_micromips64r6_doublewords", test_micromips64r6_doublewords},
    {"test_micromips64r6_generic", test_micromips64r6_generic},
    {"test_mips_dsp_maq_full_accumulator", test_mips_dsp_maq_full_accumulator},
    {"test_mips_stop_at_branch", test_mips_stop_at_branch},
    {"test_mips_stop_at_delay_slot", test_mips_stop_at_delay_slot},
    {"test_mips_el_ori", test_mips_el_ori},
    {"test_mips_eb_ori", test_mips_eb_ori},
    {"test_mips_lwx_exception_issue_1314", test_mips_lwx_exception_issue_1314},
    {"test_mips_mips16", test_mips_mips16},
    {"test_mips_mips_fpr", test_mips_mips_fpr},
    {"test_mips_stop_delay_slot_from_qiling",
     test_mips_stop_delay_slot_from_qiling},
    {"test_mips_simple_coredump_2134", test_mips_simple_coredump_2134},
    {"test_mips_simple_coredump_2137", test_mips_simple_coredump_2137},
    {NULL, NULL}};
