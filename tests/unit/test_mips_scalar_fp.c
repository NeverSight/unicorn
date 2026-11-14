#include "unicorn_test.h"

/* MIPS64 Volume II 2.50: scalar ABS/NEG are arithmetic and either kind of NaN
 * signals Invalid. R6 ABS2008 is instead a pure sign-bit operation. */
static void test_scalar_sign(void)
{
    const uint64_t inputs[] = {0, 0x8000000080000000ull,
        0x3ff800003fc00000ull, 0xbff00000bf800000ull,
        0x7ff000007f800000ull, 0xfff00000ff800000ull,
        0x7ff400007fa00000ull, 0x7ff800007fc00000ull,
        0xfff40000ffa00000ull, 0xfff80000ffc00000ull};
    for (unsigned wide = 0; wide < 2; ++wide)
        for (unsigned big = 0; big < 2; ++big)
            for (unsigned r6 = 0; r6 < 2; ++r6) {
                uc_engine *uc;
                OK(uc_open(UC_ARCH_MIPS,
                    (wide ? UC_MODE_MIPS64 : UC_MODE_MIPS32) |
                    (big ? UC_MODE_BIG_ENDIAN : UC_MODE_LITTLE_ENDIAN), &uc));
                OK(uc_ctl_set_cpu_model(uc, wide ?
                    (r6 ? UC_CPU_MIPS64_I6400 : UC_CPU_MIPS64_MIPS64R2_GENERIC) :
                    (r6 ? UC_CPU_MIPS32_MIPS32R6_GENERIC : UC_CPU_MIPS32_74KF)));
                uint64_t status = 0;
                OK(uc_reg_read(uc, UC_MIPS_REG_CP0_STATUS, &status));
                status |= 0x24000000;
                OK(uc_reg_write(uc, UC_MIPS_REG_CP0_STATUS, &status));
                OK(uc_mem_map(uc, 0x10000, 4096, UC_PROT_ALL));
                for (unsigned double_fmt = 0; double_fmt < 2; ++double_fmt)
                    for (unsigned negate = 0; negate < 2; ++negate) {
                        uint32_t word = 0x46002085 | (double_fmt << 21) | (negate << 1);
                        uint64_t pc = 0x10000 + 8 * double_fmt + 4 * negate;
                        uint8_t code[4];
                        for (unsigned b = 0; b < 4; ++b)
                            code[b] = word >> (8 * (big ? 3 - b : b));
                        OK(uc_mem_write(uc, pc, code, 4));
                        for (unsigned i = 0; i < sizeof(inputs)/sizeof(inputs[0]); ++i)
                            for (unsigned enabled = 0; enabled < 2; ++enabled) {
                                uint64_t input = inputs[i], sentinel = 0x123456789abcdef0ull;
                                uint64_t sign = double_fmt ? 1ull << 63 : 1ull << 31;
                                uint64_t magnitude = input & (sign - 1);
                                bool nan = magnitude > (double_fmt ? 0x7ff0000000000000ull : 0x7f800000);
                                uint32_t csr = (r6 ? 0xc0000 : 0) | 0x1004 | (enabled ? 0x800 : 0);
                                const uint32_t initial = csr;
                                OK(uc_reg_write(uc, UC_MIPS_REG_FCSR, &csr));
                                OK(uc_reg_write(uc, UC_MIPS_REG_F4, &input));
                                OK(uc_reg_write(uc, UC_MIPS_REG_F2, &sentinel));
                                bool trap = !r6 && nan && enabled;
                                TEST_CHECK(uc_emu_start(uc, pc, pc + 4, 0, 1) ==
                                    (trap ? UC_ERR_EXCEPTION : UC_ERR_OK));
                                uint64_t result = 0;
                                OK(uc_reg_read(uc, UC_MIPS_REG_FCSR, &csr));
                                OK(uc_reg_read(uc, UC_MIPS_REG_F2, &result));
                                uint32_t expected_csr = r6 ? initial :
                                    (initial & ~0x3f000u) | (nan ? 0x10000u | (trap ? 0 : 0x40u) : 0);
                                TEST_CHECK(csr == expected_csr);
                                uint64_t expected = negate ? input ^ sign : magnitude;
                                if (!r6 && nan)
                                    expected = double_fmt ? 0x7ff7ffffffffffffull : 0x7fbfffff;
                                if (trap)
                                    TEST_CHECK(result == sentinel);
                                else if (double_fmt)
                                    TEST_CHECK(result == expected);
                                else
                                    TEST_CHECK((uint32_t)result == (uint32_t)expected);
                            }
                    }
                OK(uc_close(uc));
            }
}

TEST_LIST = {{"MIPS scalar legacy and ABS2008 sign operations", test_scalar_sign}, {NULL, NULL}};
