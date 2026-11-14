#include "unicorn_test.h"

/* Literal instruction words and bit-at-a-time expectations keep the oracle
 * independent of the helpers' two-word shift implementation. */
static uint64_t extract_bits(uint64_t hi, uint64_t lo, unsigned start,
                             unsigned count)
{
    uint64_t result = 0;
    for (unsigned bit = 0; bit < count; ++bit) {
        unsigned source = start + bit;
        uint64_t value = source < 64 ? lo : hi;
        result |= ((value >> (source % 64)) & 1) << bit;
    }
    return result;
}

static void put_code(uc_engine *uc, uint64_t address, const uint32_t *words,
                     size_t count, unsigned little)
{
    for (size_t i = 0; i < count; ++i) {
        uint8_t bytes[4];
        for (unsigned b = 0; b < 4; ++b)
            bytes[b] = words[i] >> (8 * (little ? b : 3 - b));
        OK(uc_mem_write(uc, address + 4 * i, bytes, sizeof(bytes)));
    }
}

static void test_mips64_dsp_extract_boundaries(void)
{
    const uint32_t instructions[] = {0x7cc2007c, 0x7cc2047c, 0x7cc200fc,
                                     0x7cc202fc, 0x7cc006fc};
    const uint64_t values[][2] = {
        {0, UINT64_MAX}, {UINT64_MAX, 0},
        {UINT64_C(0x123456789abcdef0), UINT64_C(0xfedcba9876543210)},
        {UINT64_C(0x8000000000000000), UINT64_C(0x8000000000000001)}};
    for (unsigned little = 0; little < 2; ++little) {
        for (unsigned op = 0; op < 5; ++op) {
            uc_engine *uc;
            OK(uc_open(UC_ARCH_MIPS,
                       UC_MODE_MIPS64 | (little ? UC_MODE_LITTLE_ENDIAN
                                                : UC_MODE_BIG_ENDIAN), &uc));
            OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_MIPS64DSPR2));
            OK(uc_mem_map(uc, 0x10000, 4096, UC_PROT_ALL));
            const uint32_t enable[] = {0x40086000, 0x3c090100, 0x01094025,
                                       0x40886000, 0xc0};
            const uint32_t program[] = {0x00800011, 0x00a00013, 0x7ce1fcf8,
                                        instructions[op], 0x00001810,
                                        0x00004812, 0x7c3f44b8};
            put_code(uc, 0x10000, enable, 5, little);
            put_code(uc, 0x10040, program, 7, little);
            OK(uc_emu_start(uc, 0x10000, 0x10014, 0, 5));
            for (unsigned v = 0; v < 4; ++v) {
                uint64_t hi = values[v][0], lo = values[v][1];
                for (unsigned shift = 0; shift < (op == 4 ? 128 : 64); ++shift) {
                    for (unsigned pos = 0; pos < (op == 2 || op == 3 ? 128 : 1);
                         ++pos) {
                        uint64_t count = shift, state = 0xa5204000u | pos;
                        uint64_t result, got_hi, got_lo, got_state;
                        OK(uc_reg_write(uc, UC_MIPS_REG_4, &hi));
                        OK(uc_reg_write(uc, UC_MIPS_REG_5, &lo));
                        OK(uc_reg_write(uc, UC_MIPS_REG_6, &count));
                        OK(uc_reg_write(uc, UC_MIPS_REG_7, &state));
                        OK(uc_emu_start(uc, 0x10040, 0x1005c, 0, 7));
                        OK(uc_reg_read(uc, UC_MIPS_REG_2, &result));
                        OK(uc_reg_read(uc, UC_MIPS_REG_3, &got_hi));
                        OK(uc_reg_read(uc, UC_MIPS_REG_9, &got_lo));
                        OK(uc_reg_read(uc, UC_MIPS_REG_8, &got_state));
                        uint64_t expected = 0, expected_hi = hi, expected_lo = lo;
                        bool defined = true;
                        if (op < 2) {
                            expected = extract_bits(hi, lo, shift, op ? 64 : 32);
                            if (!op && (expected & UINT64_C(0x80000000)))
                                expected |= UINT64_C(0xffffffff00000000);
                        } else if (op < 4) {
                            defined = pos >= shift;
                            if (defined) {
                                expected = extract_bits(hi, lo, pos - shift,
                                                        shift + 1);
                                state &= ~UINT64_C(0x4000);
                                if (op == 3)
                                    state = (state & ~UINT64_C(127)) |
                                            ((pos - shift - 1) & 127);
                            }
                        } else {
                            defined = false;
                            expected_hi = expected_lo = 0;
                            int offset = shift < 64 ? (int)shift : (int)shift - 128;
                            for (unsigned bit = 0; bit < 128; ++bit) {
                                int source = (int)bit + offset;
                                if (source < 0 || source >= 128)
                                    continue;
                                uint64_t value = extract_bits(hi, lo, source, 1);
                                if (bit < 64)
                                    expected_lo |= value << bit;
                                else
                                    expected_hi |= value << (bit - 64);
                            }
                        }
                        TEST_CHECK(!defined || result == expected);
                        TEST_CHECK(got_hi == expected_hi && got_lo == expected_lo);
                        TEST_CHECK(got_state == state);
                        TEST_MSG("op=%u little=%u vector=%u shift=%u pos=%u",
                                 op, little, v, shift, pos);
                    }
                }
            }
            OK(uc_close(uc));
        }
    }
}

TEST_LIST = {
    {"test_mips64_dsp_extract_boundaries", test_mips64_dsp_extract_boundaries},
    {NULL, NULL}};
