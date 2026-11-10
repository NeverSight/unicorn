#include "unicorn_test.h"

static const struct {
    uint32_t instruction, a, b, result;
    unsigned overflow;
} cases[] = {
#define DSP_ZERO(word, a, b, result, overflow) {word, a, b, result, overflow},
#include "mips_dsp_zero_cases.def"
};

static void test_mips_dsp_zero_effects(void)
{
    for (unsigned little = 0; little != 2; ++little) {
        for (unsigned c = 0; c != sizeof(cases) / sizeof(cases[0]); ++c) {
            for (unsigned destination = 0; destination != 3; ++destination) {
                for (unsigned sticky = 0; sticky != 2; ++sticky) {
                    uc_engine *uc;
                    OK(uc_open(UC_ARCH_MIPS,
                               UC_MODE_MIPS32 | (little ? UC_MODE_LITTLE_ENDIAN
                                                        : UC_MODE_BIG_ENDIAN),
                               &uc));
                    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS32_74KF));
                    OK(uc_mem_map(uc, 0x10000, 4096, UC_PROT_ALL));
                    const unsigned rd = destination == 0   ? 0
                                        : destination == 1 ? 2
                                                           : 4;
                    uint32_t control = sticky ? 0x0fff7fbf : 0;
                    uint32_t program[] = {0x40086000,
                                          0x3c090100,
                                          0x01094025,
                                          0x40886000,
                                          0xc0,
                                          0x7cc1fcf8,
                                          cases[c].instruction | (rd << 11),
                                          0x7c3f4cb8,
                                          0x00001825};
                    uint8_t code[sizeof(program)];
                    for (unsigned i = 0;
                         i != sizeof(program) / sizeof(program[0]); ++i)
                        for (unsigned b = 0; b != 4; ++b)
                            code[4 * i + b] =
                                program[i] >> (8 * (little ? b : 3 - b));
                    OK(uc_mem_write(uc, 0x10000, code, sizeof(code)));
                    OK(uc_reg_write(uc, UC_MIPS_REG_A0, &cases[c].a));
                    OK(uc_reg_write(uc, UC_MIPS_REG_A1, &cases[c].b));
                    OK(uc_reg_write(uc, UC_MIPS_REG_A2, &control));
                    OK(uc_emu_start(uc, 0x10000, 0x10000 + sizeof(code), 0,
                                    sizeof(program) / sizeof(program[0])));
                    uint32_t result = 0, state = 0, zero = 1;
                    OK(uc_reg_read(uc, UC_MIPS_REG_0 + rd, &result));
                    OK(uc_reg_read(uc, UC_MIPS_REG_T1, &state));
                    OK(uc_reg_read(uc, UC_MIPS_REG_V1, &zero));
                    TEST_CHECK(result == (rd ? cases[c].result : 0));
                    TEST_CHECK(
                        state ==
                        (control |
                         (cases[c].overflow ? 1u << cases[c].overflow : 0)));
                    TEST_MSG("case=%u rd=%u little=%u state=%x", c, rd, little,
                             state);
                    TEST_CHECK(zero == 0);
                    OK(uc_close(uc));
                }
            }
        }
    }
}
static void test_mips_dsp_zero_still_requires_enabled_dsp(void)
{
    for (unsigned little = 0; little != 2; ++little) {
        const uint32_t instructions[] = {0x7c850010, 0x7ce40013, 0x7c850190, 0x7c8501d0, 0x7c8507d0, 0x7c850710, 0x7c850750, 0x7c850551, 0x7c8503d1};
        for (unsigned i = 0; i != sizeof(instructions)/sizeof(instructions[0]); ++i) {
            uc_engine *uc;
            OK(uc_open(UC_ARCH_MIPS,
                       UC_MODE_MIPS32 | (little ? UC_MODE_LITTLE_ENDIAN
                                                : UC_MODE_BIG_ENDIAN),
                       &uc));
            OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS32_74KF));
            OK(uc_mem_map(uc, 0x10000, 4096, UC_PROT_ALL));
            uint8_t code[4];
            for (unsigned b = 0; b != 4; ++b)
                code[b] = instructions[i] >> (8 * (little ? b : 3 - b));
            OK(uc_mem_write(uc, 0x10000, code, sizeof(code)));
            uc_assert_err(UC_ERR_EXCEPTION,
                          uc_emu_start(uc, 0x10000, 0x10004, 0, 1));
            OK(uc_close(uc));
        }
    }
}
TEST_LIST = {{"test_mips_dsp_zero_effects", test_mips_dsp_zero_effects},
             {"test_mips_dsp_zero_still_requires_enabled_dsp",
              test_mips_dsp_zero_still_requires_enabled_dsp},
             {NULL, NULL}};
