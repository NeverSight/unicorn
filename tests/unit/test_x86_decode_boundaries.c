/* Original decoding and exception-priority regressions, 2026-10-04.
 * NeverD contributors; licensed under the Unicorn unit-test terms. */
#include "unicorn_test.h"

#define UC_DECODE_VALUE(Name, Value) enum { Name = Value };
#define UC_DECODE_WIDE_VALUE(Name, Value) static const uint64_t Name = Value;
#define UC_DECODE_EVEX(Name, ...) static const uint8_t Name[] = {__VA_ARGS__};
#define UC_DECODE_ROUND(Name, ...) static const uint8_t Name[] = {__VA_ARGS__};
#include "x86_decode_boundaries.def"
#undef UC_DECODE_ROUND
#undef UC_DECODE_EVEX
#undef UC_DECODE_VALUE
#undef UC_DECODE_WIDE_VALUE

struct Program {
    const uint8_t *Bytes;
    size_t Size;
};
static uc_engine *create(int Model, struct Program Program)
{
    uc_engine *Engine = NULL;
    TEST_ASSERT(uc_open(UC_ARCH_X86, UC_MODE_64, &Engine) == UC_ERR_OK);
    OK(uc_ctl_set_cpu_model(Engine, Model));
    OK(uc_mem_map(Engine, Code, PageBytes, UC_PROT_ALL));
    OK(uc_mem_write(Engine, Code, Program.Bytes, Program.Size));
    return Engine;
}

static void register_u_is_not_an_apx_index_bit(void)
{
    static const int Models[] = {
#define UC_DECODE_MODEL(Model) Model,
#include "x86_decode_boundaries.def"
#undef UC_DECODE_MODEL
    };
    static const struct Program Programs[] = {
#define UC_DECODE_EVEX(Name, ...) {Name, sizeof(Name)},
#include "x86_decode_boundaries.def"
#undef UC_DECODE_EVEX
    };
    for (size_t M = 0; M < sizeof(Models) / sizeof(Models[0]); ++M) {
        for (size_t I = 0; I < sizeof(Programs) / sizeof(Programs[0]); ++I) {
            for (unsigned Invalid = 0; Invalid < 2; ++Invalid) {
                uc_engine *Engine = create(Models[M], Programs[I]);
                uint64_t Initial[8], Result[8], Mask = Seed, PC = 0;
                for (size_t J = 0; J < sizeof(Initial) / sizeof(Initial[0]);
                     ++J) {
                    Initial[J] = Seed + J;
                }
                OK(uc_reg_write(Engine, UC_X86_REG_ZMM0, Initial));
                OK(uc_reg_write(Engine, UC_X86_REG_K0, &Mask));
                if (Invalid) {
                    const uint8_t P1 = Programs[I].Bytes[P1Offset] & ~UMask;
                    OK(uc_mem_write(Engine, Code + P1Offset, &P1, sizeof(P1)));
                }
                const uc_err Error = uc_emu_start(
                    Engine, Code, Code + Programs[I].Size, Timeout, 1);
                TEST_CHECK(Error ==
                           (Invalid ? UC_ERR_INSN_INVALID : UC_ERR_OK));
                OK(uc_reg_read(Engine, UC_X86_REG_RIP, &PC));
                OK(uc_reg_read(Engine, UC_X86_REG_ZMM0, Result));
                OK(uc_reg_read(Engine, UC_X86_REG_K0, &Mask));
                TEST_CHECK(PC == (Invalid ? Code : Code + Programs[I].Size));
                if (Invalid) {
                    TEST_CHECK(memcmp(Initial, Result, sizeof(Initial)) == 0);
                    TEST_CHECK(Mask == Seed);
                } else {
                    TEST_CHECK(memcmp(Initial, Result, sizeof(Initial)) != 0 ||
                               Mask != Seed);
                }
                OK(uc_close(Engine));
            }
        }
    }
}

struct Exception {
    unsigned Count, Vector;
};
static void interrupt(uc_engine *Engine, uint32_t Vector, void *Data)
{
    struct Exception *Exception = Data;
    ++Exception->Count;
    Exception->Vector = Vector;
    OK(uc_emu_stop(Engine));
}

static void round_memory_fault_priority_and_recovery(void)
{
    const struct {
        struct Program Program;
        uint64_t Offset;
        uc_err Error;
        unsigned Vector;
    } Cases[] = {
#define UC_DECODE_ROUND_CASE(Name, Offset, Error, Vector)                      \
    {{Name, sizeof(Name)}, Offset, Error, Vector},
#include "x86_decode_boundaries.def"
#undef UC_DECODE_ROUND_CASE
    };
    for (size_t I = 0; I < sizeof(Cases) / sizeof(Cases[0]); ++I) {
        uc_engine *Engine = create(UC_CPU_X86_HASWELL, Cases[I].Program);
        uint64_t Address = Data + Cases[I].Offset, PC = 0;
        uint64_t Initial[4] = {Seed, Seed, Seed, Seed}, Result[4] = {0};
        uint32_t MXCSR = InitialMXCSR;
        uint32_t Bytes[PageBytes / sizeof(uint32_t)];
        uint32_t After[PageBytes / sizeof(uint32_t)];
        struct Exception Exception = {0};
        uc_hook Hook;
        for (size_t J = 0; J < sizeof(Bytes) / sizeof(Bytes[0]); ++J) {
            Bytes[J] = SingleInput;
        }
        OK(uc_mem_map(Engine, Data, PageBytes, UC_PROT_ALL));
        OK(uc_mem_write(Engine, Data, Bytes, sizeof(Bytes)));
        OK(uc_reg_write(Engine, UC_X86_REG_RAX, &Address));
        OK(uc_reg_write(Engine, UC_X86_REG_YMM0, Initial));
        OK(uc_reg_write(Engine, UC_X86_REG_MXCSR, &MXCSR));
        OK(uc_hook_add(Engine, &Hook, UC_HOOK_INTR, interrupt, &Exception, 1,
                       0));
        TEST_CHECK(uc_emu_start(Engine, Code, Code + Cases[I].Program.Size,
                                Timeout, 1) == Cases[I].Error);
        TEST_CHECK(Exception.Vector == Cases[I].Vector);
        TEST_CHECK(Exception.Count == (Cases[I].Vector ? 1 : 0));
        OK(uc_reg_read(Engine, UC_X86_REG_YMM0, Result));
        OK(uc_reg_read(Engine, UC_X86_REG_RIP, &PC));
        OK(uc_reg_read(Engine, UC_X86_REG_MXCSR, &MXCSR));
        OK(uc_mem_read(Engine, Data, After, sizeof(After)));
        TEST_CHECK(memcmp(Bytes, After, sizeof(Bytes)) == 0);
        if (Cases[I].Vector || Cases[I].Error != UC_ERR_OK) {
            TEST_CHECK(PC == Code);
            TEST_CHECK(memcmp(Initial, Result, sizeof(Initial)) == 0);
            TEST_CHECK(MXCSR == InitialMXCSR);
            Address = Data;
            OK(uc_reg_write(Engine, UC_X86_REG_RAX, &Address));
            OK(uc_emu_start(Engine, Code, Code + Cases[I].Program.Size, Timeout,
                            1));
            TEST_CHECK(Exception.Count == (Cases[I].Vector ? 1 : 0));
            OK(uc_reg_read(Engine, UC_X86_REG_RIP, &PC));
        }
        TEST_CHECK(PC == Code + Cases[I].Program.Size);
        OK(uc_close(Engine));
    }
}

TEST_LIST = {
#define UC_DECODE_TEST(Name) {#Name, Name},
#include "x86_decode_boundaries.def"
#undef UC_DECODE_TEST
    {NULL, NULL}};
