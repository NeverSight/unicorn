#include "unicorn_test.h"

static const struct {
    uint32_t instruction;
    uint64_t a, b, expected_ab, expected_ba;
} cases[] = {
#define MSA_CASE(op, a, b, ab, ba)                                             \
    {op, UINT64_C(a), UINT64_C(b), UINT64_C(ab), UINT64_C(ba)},
#include "mips_msa_integer_cases.def"
};

static void test_mips_msa_integer_boundaries(void)
{
    const uint32_t setup[] = {0x40088005, 0x3c090800, 0x01094025, 0x40888005,
                              0xc0,       0x40086000, 0x3c092400, 0x01094025,
                              0x40886000, 0xc0};
    const unsigned destinations[] = {0, 1, 2, 31};
    for (unsigned little = 0; little != 2; ++little) {
        for (unsigned c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
            for (unsigned d = 0;
                 d < sizeof(destinations) / sizeof(destinations[0]); ++d) {
                const unsigned destination = destinations[d];
                uint32_t program[32];
                uint8_t code[sizeof(program)];
                unsigned count = 0;
                uc_engine *uc;
                OK(uc_open(UC_ARCH_MIPS,
                           UC_MODE_MIPS32 | (little ? UC_MODE_LITTLE_ENDIAN
                                                    : UC_MODE_BIG_ENDIAN),
                           &uc));
                OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS32_P5600));
                OK(uc_mem_map(uc, 0x10000, 4096, UC_PROT_ALL));
                for (unsigned i = 0; i < sizeof(setup) / sizeof(setup[0]);
                     ++i) {
                    program[count++] = setup[i];
                }
                const uint32_t words[] = {
                    (uint32_t)cases[c].a, (uint32_t)(cases[c].a >> 32),
                    (uint32_t)cases[c].b, (uint32_t)(cases[c].b >> 32)};
                for (unsigned i = 0; i < 4; ++i) {
                    OK(uc_reg_write(uc, UC_MIPS_REG_A0 + i, &words[i]));
                }
                for (unsigned v = 0; v < 2; ++v) {
                    program[count++] =
                        0x7b02001e | ((v ? 6 : 4) << 11) | (v << 6);
                    for (unsigned lane = 1; lane < 4; ++lane) {
                        unsigned reg = 4 + ((lane + v * 2) % 4);
                        program[count++] =
                            0x79300019 | (lane << 16) | (reg << 11) | (v << 6);
                    }
                }
                program[count++] =
                    cases[c].instruction | (1 << 16) | (destination << 6);
                for (unsigned lane = 0; lane < 4; ++lane) {
                    program[count++] = 0x78b00019 | (lane << 16) |
                                       (destination << 11) | ((16 + lane) << 6);
                }
                for (unsigned i = 0; i < count; ++i) {
                    for (unsigned byte = 0; byte < 4; ++byte) {
                        code[4 * i + byte] =
                            (uint8_t)(program[i] >>
                                      (8 * (little ? byte : 3 - byte)));
                    }
                }
                OK(uc_mem_write(uc, 0x10000, code, count * 4));
                OK(uc_emu_start(uc, 0x10000, 0x10000 + count * 4, 0, count));
                uint64_t result[2] = {0, 0};
                for (unsigned lane = 0; lane < 4; ++lane) {
                    uint32_t word = 0;
                    OK(uc_reg_read(uc, UC_MIPS_REG_S0 + lane, &word));
                    result[lane / 2] |= (uint64_t)word << (32 * (lane % 2));
                }
                TEST_CHECK(result[0] == cases[c].expected_ab);
                TEST_MSG("instruction=%08x little=%u wd=%u lane=0: %016llx != "
                         "%016llx",
                         cases[c].instruction, little, destination,
                         (unsigned long long)result[0],
                         (unsigned long long)cases[c].expected_ab);
                TEST_CHECK(result[1] == cases[c].expected_ba);
                TEST_MSG("instruction=%08x little=%u wd=%u lane=1: %016llx != "
                         "%016llx",
                         cases[c].instruction, little, destination,
                         (unsigned long long)result[1],
                         (unsigned long long)cases[c].expected_ba);
                OK(uc_close(uc));
            }
        }
    }
}

TEST_LIST = {
    {"test_mips_msa_integer_boundaries", test_mips_msa_integer_boundaries},
    {NULL, NULL}};
