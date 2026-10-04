/* One-instruction execution boundaries, independent of any OS model. */
#include "unicorn_test.h"

#define UC_COUNT_VALUE(Name, Value) enum { Name = Value };
#define UC_COUNT_CODE(Name, ...) static const uint8_t Name[] = {__VA_ARGS__};
#include "count_one_cases.def"
#undef UC_COUNT_CODE
#undef UC_COUNT_VALUE

struct Program {
    const uint8_t *Bytes;
    size_t Size;
};
struct Architecture {
    uc_arch Arch;
    uc_mode Mode;
    int PC;
    struct Program Nop, Jump, Loop, Load;
};
static const struct Architecture Architectures[] = {
#define UC_COUNT_ARCH(Name, Arch, Mode, PC)                                    \
    {Arch,                                                                     \
     Mode,                                                                     \
     PC,                                                                       \
     {Nop##Name, sizeof(Nop##Name)},                                           \
     {Jump##Name, sizeof(Jump##Name)},                                         \
     {Loop##Name, sizeof(Loop##Name)},                                         \
     {Load##Name, sizeof(Load##Name)}},
#include "count_one_cases.def"
#undef UC_COUNT_ARCH
};

static uc_engine *create(const struct Architecture *Arch)
{
    uc_engine *Engine = NULL;
    TEST_ASSERT(uc_open(Arch->Arch, Arch->Mode, &Engine) == UC_ERR_OK);
    OK(uc_mem_map(Engine, Code, PageSize, UC_PROT_ALL));
    return Engine;
}

static void run_at_tail(bool Branch)
{
    for (size_t I = 0; I < sizeof(Architectures) / sizeof(Architectures[0]);
         ++I) {
        const struct Architecture *Arch = &Architectures[I];
        const struct Program *Program = Branch ? &Arch->Jump : &Arch->Nop;
        uc_engine *Engine = create(Arch);
        const uint64_t Start = Code + PageSize - Program->Size;
        OK(uc_mem_write(Engine, Start, Program->Bytes, Program->Size));
        /* Repeat without flushing the translated block to exercise reuse. */
        for (unsigned Repeat = 0; Repeat < 2; ++Repeat) {
            OK(uc_emu_start(Engine, Start, 0, Timeout, 1));
            uint64_t PC = 0;
            OK(uc_reg_read(Engine, Arch->PC, &PC));
            TEST_CHECK(PC == Code + PageSize);
        }
        OK(uc_close(Engine));
    }
}

static void page_tail_stops_before_successor_fetch(void)
{
    run_at_tail(false);
}

static void branch_to_unmapped_page_commits_before_fetch(void)
{
    run_at_tail(true);
}

static void self_branch_stops_with_an_unchanged_pc(void)
{
    for (size_t I = 0; I < sizeof(Architectures) / sizeof(Architectures[0]);
         ++I) {
        const struct Architecture *Arch = &Architectures[I];
        uc_engine *Engine = create(Arch);
        OK(uc_mem_write(Engine, Code, Arch->Loop.Bytes, Arch->Loop.Size));
        OK(uc_emu_start(Engine, Code, 0, Timeout, 1));
        uint64_t PC = 0;
        size_t TimedOut = 0;
        OK(uc_reg_read(Engine, Arch->PC, &PC));
        OK(uc_query(Engine, UC_QUERY_TIMEOUT, &TimedOut));
        TEST_CHECK(PC == Code);
        TEST_CHECK(!TimedOut);
        OK(uc_close(Engine));
    }
}

static void first_instruction_fault_is_not_suppressed(void)
{
    for (size_t I = 0; I < sizeof(Architectures) / sizeof(Architectures[0]);
         ++I) {
        const struct Architecture *Arch = &Architectures[I];
        uc_engine *Engine = create(Arch);
        OK(uc_mem_write(Engine, Code, Arch->Load.Bytes, Arch->Load.Size));
        uc_assert_err(UC_ERR_READ_UNMAPPED,
                      uc_emu_start(Engine, Code, 0, Timeout, 1));
        uint64_t PC = 0;
        OK(uc_reg_read(Engine, Arch->PC, &PC));
        TEST_CHECK(PC == Code);
        OK(uc_close(Engine));
    }
}

#ifdef UNICORN_HAS_ARM64
static void arm64_mmu_does_not_translate_the_successor(void)
{
    uc_engine *Engine = NULL;
    TEST_ASSERT(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &Engine) == UC_ERR_OK);
    OK(uc_ctl_tlb_mode(Engine, UC_TLB_CPU));
    OK(uc_mem_map(Engine, Code, PageSize, UC_PROT_ALL));
    OK(uc_mem_map(Engine, Tables, TableLevels * PageSize, UC_PROT_ALL));
    for (unsigned Level = 0; Level + 1 < TableLevels; ++Level) {
        uint64_t Entry =
            LEINT64((Tables + (Level + 1) * PageSize) | TableDescriptor);
        OK(uc_mem_write(Engine, Tables + Level * PageSize, &Entry,
                        sizeof(Entry)));
    }
    uint64_t Leaf = LEINT64(Code | PageDescriptor);
    OK(uc_mem_write(Engine,
                    Tables + (TableLevels - 1) * PageSize +
                        (Code / PageSize) * sizeof(Leaf),
                    &Leaf, sizeof(Leaf)));
    const uint64_t Start = Code + PageSize - sizeof(NopARM64);
    OK(uc_mem_write(Engine, Start, NopARM64, sizeof(NopARM64)));
    uc_arm64_cp_reg Registers[] = {
#define UC_COUNT_MMU_REGISTER(...) {__VA_ARGS__},
#include "count_one_cases.def"
#undef UC_COUNT_MMU_REGISTER
    };
    for (size_t I = 0; I < sizeof(Registers) / sizeof(Registers[0]); ++I)
        OK(uc_reg_write(Engine, UC_ARM64_REG_CP_REG, &Registers[I]));
    OK(uc_emu_start(Engine, Start, 0, Timeout, 1));
    uint64_t PC = 0;
    OK(uc_reg_read(Engine, UC_ARM64_REG_PC, &PC));
    TEST_CHECK(PC == Code + PageSize);
    /* The next entry still faults: stopping must not grant page access. */
    uc_assert_err(UC_ERR_EXCEPTION, uc_emu_start(Engine, PC, 0, Timeout, 1));
    OK(uc_close(Engine));
}
#endif

#ifdef UNICORN_HAS_X86
static void code_store_is_not_counted_again_before_commit(void)
{
    uc_engine *Engine = NULL;
    TEST_ASSERT(uc_open(UC_ARCH_X86, UC_MODE_64, &Engine) == UC_ERR_OK);
    OK(uc_ctl_tlb_mode(Engine, UC_TLB_CPU));
    OK(uc_mem_map(Engine, Code, PageSize, UC_PROT_ALL));
    OK(uc_mem_write(Engine, Code, RewriteX64, sizeof(RewriteX64)));
    uint64_t Pointer = Code + PatchOffset, Source = PatchValue, PC = 0;
    OK(uc_reg_write(Engine, UC_X86_REG_RCX, &Pointer));
    OK(uc_reg_write(Engine, UC_X86_REG_RDX, &Source));
    OK(uc_emu_start(Engine, Code, 0, Timeout, 1));
    OK(uc_reg_read(Engine, UC_X86_REG_RIP, &PC));
    TEST_CHECK(PC == Code + StoreSize);
    uint32_t Word = 0;
    OK(uc_mem_read(Engine, Pointer, &Word, sizeof(Word)));
    TEST_CHECK(LEINT32(Word) == PatchValue);
    OK(uc_close(Engine));
}
#endif

TEST_LIST = {
#define UC_COUNT_TEST(Name) {#Name, Name},
#include "count_one_cases.def"
#undef UC_COUNT_TEST
    {NULL, NULL}};
