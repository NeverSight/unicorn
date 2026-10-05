/* Original ENTER fault and restart regressions, NeverD contributors, 2026.
 * Licensed under the same terms as the Unicorn unit tests. */
#include "unicorn_test.h"
#include <limits.h>

#define UC_X86_ENTER_CONSTANT(Name, Value) enum { Name = Value };
#define UC_X86_ENTER_FAULT_CONSTANT(Name, Value) enum { Name = Value };
#include "x86_enter.def"
#undef UC_X86_ENTER_FAULT_CONSTANT
#undef UC_X86_ENTER_CONSTANT

typedef struct Mode {
    uc_mode Mode;
    unsigned Width;
    bool Prefix;
} Mode;
static const Mode Modes[] = {
#define UC_X86_ENTER_FAULT_MODE(Name, Mode, Width, Prefix)                     \
    {Mode, Width, Prefix},
#include "x86_enter.def"
#undef UC_X86_ENTER_FAULT_MODE
};
typedef struct Stage {
    uint64_t SP, BP, Guard;
    unsigned Allocation, Nesting, Stores;
    bool Write;
    uint64_t Address;
    unsigned Size;
} Stage;
typedef struct Fixture {
    uc_engine *UC;
    Mode Mode;
    Stage Stage;
    uint8_t Before[StackBytes], Expected[StackBytes];
    uint64_t SP, BP;
    unsigned CodeSize, Faults, Writes;
    bool Missing, Repair, Stop;
} Fixture;

static int FrameRegister(const Fixture *F)
{
    return F->Mode.Mode == UC_MODE_64 ? UC_X86_REG_RBP : UC_X86_REG_EBP;
}
static int StackRegister(const Fixture *F)
{
    return F->Mode.Mode == UC_MODE_64 ? UC_X86_REG_RSP : UC_X86_REG_ESP;
}
static uint64_t ReadRegister(Fixture *F, int Reg)
{
    uint64_t Value = 0;
    OK(uc_reg_read(F->UC, Reg, &Value));
    return Value;
}
static void Store(uint8_t *Bytes, uint64_t Offset, unsigned Width,
                  uint64_t Value)
{
    for (unsigned I = 0; I < Width; ++I)
        Bytes[Offset + I] = (uint8_t)(Value >> (I * CHAR_BIT));
}
static uint64_t Load(const uint8_t *Bytes, uint64_t Offset, unsigned Width)
{
    uint64_t Value = 0;
    for (unsigned I = 0; I < Width; ++I)
        Value |= (uint64_t)Bytes[Offset + I] << (I * CHAR_BIT);
    return Value;
}
static void ExpectStores(Fixture *F, unsigned Count)
{
    const unsigned Width = F->Mode.Width;
    const uint64_t Frame = F->SP - Width;
    for (unsigned I = 0; I < Count; ++I) {
        uint64_t Value = I == 0 ? F->BP : Frame;
        if (I && I != (F->Stage.Nesting & NestingMask))
            Value = Load(F->Expected, F->BP - StackBase - I * Width, Width);
        Store(F->Expected, Frame - StackBase - I * Width, Width, Value);
    }
}
static void CheckMemory(Fixture *F)
{
    uint8_t Actual[PageBytes];
    for (unsigned I = 0; I < StackBytes / PageBytes; ++I) {
        if (F->Missing && I == F->Stage.Guard)
            continue;
        OK(uc_mem_read(F->UC, StackBase + I * PageBytes, Actual,
                       sizeof(Actual)));
        TEST_CHECK(
            memcmp(Actual, F->Expected + I * PageBytes, sizeof(Actual)) == 0);
    }
}
static void CheckEntry(Fixture *F)
{
    TEST_CHECK(ReadRegister(F, FrameRegister(F)) == F->BP);
    TEST_CHECK(ReadRegister(F, StackRegister(F)) == F->SP);
    TEST_CHECK(ReadRegister(F, UC_X86_REG_EFLAGS) == InitialFlags);
    TEST_CHECK(ReadRegister(F, F->Mode.Mode == UC_MODE_64
                                   ? UC_X86_REG_RIP
                                   : UC_X86_REG_EIP) == CodeAddress);
}
static bool Fault(uc_engine *UC, uc_mem_type Type, uint64_t Address, int Size,
                  int64_t Value, void *Data)
{
    Fixture *F = Data;
    ++F->Faults;
    TEST_CHECK(Address == StackBase + F->Stage.Address);
    TEST_CHECK(Size == F->Stage.Size);
    TEST_CHECK(Type ==
               (F->Stage.Write
                    ? (F->Missing ? UC_MEM_WRITE_UNMAPPED : UC_MEM_WRITE_PROT)
                    : (F->Missing ? UC_MEM_READ_UNMAPPED : UC_MEM_READ_PROT)));
    CheckEntry(F);
    CheckMemory(F);
    if (F->Repair) {
        if (F->Missing) {
            OK(uc_mem_map(UC, StackBase + F->Stage.Guard * PageBytes, PageBytes,
                          UC_PROT_READ | UC_PROT_WRITE));
            OK(uc_mem_write(UC, StackBase + F->Stage.Guard * PageBytes,
                            F->Before + F->Stage.Guard * PageBytes, PageBytes));
            F->Missing = false;
        } else {
            OK(uc_mem_protect(UC, StackBase + F->Stage.Guard * PageBytes,
                              PageBytes, UC_PROT_READ | UC_PROT_WRITE));
        }
        if (F->Stop)
            OK(uc_emu_stop(UC));
    }
    (void)Value;
    return F->Repair;
}
static void ObserveWrite(uc_engine *UC, uc_mem_type Type, uint64_t Address,
                         int Size, int64_t Value, void *Data)
{
    Fixture *F = Data;
    ++F->Writes;
    (void)UC;
    (void)Type;
    (void)Address;
    (void)Size;
    (void)Value;
}
static void Initialize(Fixture *F, Mode M, Stage S, bool Missing)
{
    memset(F, 0, sizeof(*F));
    F->Mode = M;
    F->Stage = S;
    F->SP = StackBase + S.SP;
    F->BP = StackBase + S.BP;
    F->Missing = Missing;
    for (size_t I = 0; I < sizeof(F->Before); ++I)
        F->Before[I] = (uint8_t)(I * PatternMultiplier + StackFill);
    memcpy(F->Expected, F->Before, sizeof(F->Expected));
    uint8_t Code[CodeCapacity];
    if (M.Prefix)
        Code[F->CodeSize++] = OperandPrefix;
    Code[F->CodeSize++] = EnterOpcode;
    Code[F->CodeSize++] = (uint8_t)S.Allocation;
    Code[F->CodeSize++] = (uint8_t)(S.Allocation >> CHAR_BIT);
    Code[F->CodeSize++] = (uint8_t)S.Nesting;
    OK(uc_open(UC_ARCH_X86, M.Mode, &F->UC));
    OK(uc_mem_map(F->UC, CodeAddress, PageBytes, UC_PROT_ALL));
    OK(uc_mem_map(F->UC, StackBase, StackBytes, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(F->UC, CodeAddress, Code, F->CodeSize));
    OK(uc_mem_write(F->UC, StackBase, F->Before, sizeof(F->Before)));
    OK(uc_reg_write(F->UC, FrameRegister(F), &F->BP));
    OK(uc_reg_write(F->UC, StackRegister(F), &F->SP));
    uint32_t Flags = InitialFlags;
    OK(uc_reg_write(F->UC, UC_X86_REG_EFLAGS, &Flags));
    if (Missing)
        OK(uc_mem_unmap(F->UC, StackBase + S.Guard * PageBytes, PageBytes));
    else
        OK(uc_mem_protect(F->UC, StackBase + S.Guard * PageBytes, PageBytes,
                          S.Write ? UC_PROT_READ : UC_PROT_NONE));
}
static void CheckFaults(void)
{
    for (size_t M = 0; M < sizeof(Modes) / sizeof(Modes[0]); ++M) {
        const unsigned Width = Modes[M].Width;
        const Stage Stages[] = {
#define UC_X86_ENTER_FAULT_STAGE(Name, SP, BP, Guard, Allocation, Nesting,     \
                                 Stores, Write, Address, Size)                 \
    {SP, BP, Guard, Allocation, Nesting, Stores, Write, Address, Size},
#include "x86_enter.def"
#undef UC_X86_ENTER_FAULT_STAGE
        };
        for (size_t S = 0; S < sizeof(Stages) / sizeof(Stages[0]); ++S)
            for (unsigned Missing = 0; Missing != 2; ++Missing) {
                Fixture F;
                uc_hook Hook;
                Initialize(&F, Modes[M], Stages[S], Missing);
                ExpectStores(&F, Stages[S].Stores);
                OK(uc_hook_add(F.UC, &Hook, UC_HOOK_MEM_INVALID, Fault, &F, 1,
                               0));
                uc_err Expected =
                    Stages[S].Write
                        ? (Missing ? UC_ERR_WRITE_UNMAPPED : UC_ERR_WRITE_PROT)
                        : (Missing ? UC_ERR_READ_UNMAPPED : UC_ERR_READ_PROT);
                uc_assert_err(Expected, uc_emu_start(F.UC, CodeAddress,
                                                     CodeAddress + F.CodeSize,
                                                     Timeout, 1));
                TEST_CHECK(F.Faults == 1);
                CheckEntry(&F);
                CheckMemory(&F);
                OK(uc_close(F.UC));
            }
    }
}
static void CheckProbeRepair(void)
{
    for (size_t M = 0; M < sizeof(Modes) / sizeof(Modes[0]); ++M)
        for (unsigned Missing = 0; Missing != 2; ++Missing)
            for (unsigned Stop = 0; Stop != 2; ++Stop) {
                const unsigned Width = Modes[M].Width;
                const Stage S = {StackPage * PageBytes + FaultOffset,
                                 FramePage * PageBytes + FaultOffset,
                                 ProbePage,
                                 (StackPage - ProbePage) * PageBytes -
                                     4 * Width,
                                 3,
                                 4,
                                 true,
                                 ProbePage * PageBytes + FaultOffset,
                                 Width};
                Fixture F;
                uc_hook Invalid, Write;
                Initialize(&F, Modes[M], S, Missing);
                F.Repair = true;
                F.Stop = Stop;
                ExpectStores(&F, S.Stores);
                OK(uc_hook_add(F.UC, &Invalid, UC_HOOK_MEM_INVALID, Fault, &F,
                               1, 0));
                OK(uc_hook_add(F.UC, &Write, UC_HOOK_MEM_WRITE, ObserveWrite,
                               &F, 1, 0));
                OK(uc_emu_start(F.UC, CodeAddress, CodeAddress + F.CodeSize,
                                Timeout, 1));
                TEST_CHECK(F.Faults == 1);
                TEST_CHECK(F.Writes == S.Stores);
                CheckMemory(&F);
                if (Stop) {
                    CheckEntry(&F);
                    OK(uc_emu_start(F.UC, CodeAddress, CodeAddress + F.CodeSize,
                                    Timeout, 1));
                    TEST_CHECK(F.Writes == 2 * S.Stores);
                    CheckMemory(&F);
                }
                const uint64_t Mask =
                    UINT64_MAX >> ((sizeof(uint64_t) - Width) * CHAR_BIT);
                TEST_CHECK(ReadRegister(&F, FrameRegister(&F)) ==
                           ((F.BP & ~Mask) | ((F.SP - Width) & Mask)));
                TEST_CHECK(ReadRegister(&F, StackRegister(&F)) ==
                           StackBase + ProbePage * PageBytes + FaultOffset);
                TEST_CHECK(ReadRegister(&F, UC_X86_REG_EFLAGS) == InitialFlags);
                OK(uc_close(F.UC));
            }
}
static void CheckOverlap(void)
{
    const unsigned Levels[] = {
#define UC_X86_ENTER_OVERLAP_NESTING(Value) Value,
#include "x86_enter.def"
#undef UC_X86_ENTER_OVERLAP_NESTING
    };
    for (size_t M = 0; M < sizeof(Modes) / sizeof(Modes[0]); ++M)
        for (size_t N = 0; N < sizeof(Levels) / sizeof(Levels[0]); ++N)
            for (int Delta = -1; Delta <= 1; ++Delta) {
                const unsigned Width = Modes[M].Width;
                const Stage S = {StackPage * PageBytes + FaultOffset,
                                 StackPage * PageBytes + FaultOffset +
                                     Delta * (int)Width,
                                 0,
                                 0,
                                 Levels[N],
                                 1 + (Levels[N] & NestingMask),
                                 true,
                                 0,
                                 0};
                Fixture F;
                Initialize(&F, Modes[M], S, false);
                ExpectStores(&F, S.Stores);
                OK(uc_emu_start(F.UC, CodeAddress, CodeAddress + F.CodeSize,
                                Timeout, 1));
                CheckMemory(&F);
                TEST_CHECK(ReadRegister(&F, StackRegister(&F)) ==
                           F.SP - S.Stores * Width);
                TEST_CHECK(ReadRegister(&F, UC_X86_REG_EFLAGS) == InitialFlags);
                OK(uc_close(F.UC));
            }
}
static void CheckWriteOnlyProbe(void)
{
    for (size_t M = 0; M < sizeof(Modes) / sizeof(Modes[0]); ++M) {
        const unsigned Width = Modes[M].Width;
        const Stage S = {StackPage * PageBytes + FaultOffset,
                         FramePage * PageBytes + FaultOffset,
                         ProbePage,
                         (StackPage - ProbePage) * PageBytes - Width,
                         0,
                         1,
                         true,
                         0,
                         0};
        Fixture F;
        uc_hook Write;
        Initialize(&F, Modes[M], S, false);
        OK(uc_mem_protect(F.UC, StackBase + ProbePage * PageBytes, PageBytes,
                          UC_PROT_WRITE));
        OK(uc_hook_add(F.UC, &Write, UC_HOOK_MEM_WRITE, ObserveWrite, &F, 1,
                       0));
        ExpectStores(&F, S.Stores);
        OK(uc_emu_start(F.UC, CodeAddress, CodeAddress + F.CodeSize, Timeout,
                        1));
        TEST_CHECK(F.Writes == S.Stores);
        CheckMemory(&F);
        OK(uc_close(F.UC));
    }
}
TEST_LIST = {
#define UC_X86_ENTER_FAULT_TEST(Name, Function) {#Name, Function},
#include "x86_enter.def"
#undef UC_X86_ENTER_FAULT_TEST
    {NULL, NULL}};
