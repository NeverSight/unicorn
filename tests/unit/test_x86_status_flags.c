/* Original implicit AH and explicit REX regressions, 2026-10-05.
 * NeverD contributors; licensed under the Unicorn unit-test terms. */
#include "unicorn_test.h"

#define UC_STATUS_VALUE(Name, Value) enum { Name = Value };
#define UC_STATUS_WIDE_VALUE(Name, Value) static const uint64_t Name = Value;
#define UC_STATUS_TEXT(Name, Text) static const char Name[] = Text;
#include "x86_status_flags.def"
#undef UC_STATUS_TEXT
#undef UC_STATUS_WIDE_VALUE
#undef UC_STATUS_VALUE

struct Prefix {
    size_t Size;
    uint8_t Bytes[MaxPrefixBytes];
    bool LongMode;
};
static const struct Prefix Prefixes[] = {
#define UC_STATUS_PREFIX(Size, ...) {Size, {__VA_ARGS__}, false},
#define UC_STATUS_REX(Size, ...) {Size, {__VA_ARGS__}, true},
#include "x86_status_flags.def"
#undef UC_STATUS_REX
#undef UC_STATUS_PREFIX
};
struct Mode {
    uc_mode Kind;
    int AX, SP, PC;
    uint64_t Mask;
};
static const struct Mode Modes[] = {
#define UC_STATUS_MODE(Kind, AX, SP, PC, Mask) {Kind, AX, SP, PC, Mask},
#include "x86_status_flags.def"
#undef UC_STATUS_MODE
};

static void implicitAH(void)
{
    const uint8_t Opcodes[] = {LAHF, SAHF};
    for (size_t M = 0; M < sizeof(Modes) / sizeof(Modes[0]); ++M) {
        const struct Mode *Mode = &Modes[M];
        uc_engine *Engine = NULL;
        OK(uc_open(UC_ARCH_X86, Mode->Kind, &Engine));
        OK(uc_mem_map(Engine, Code, Page, UC_PROT_ALL));
        for (size_t P = 0; P < sizeof(Prefixes) / sizeof(Prefixes[0]); ++P) {
            const struct Prefix *Prefix = &Prefixes[P];
            if (Prefix->LongMode && Mode->Kind != UC_MODE_64)
                continue;
            for (size_t O = 0; O < sizeof(Opcodes); ++O) {
                uint8_t Bytes[MaxPrefixBytes + 1];
                memcpy(Bytes, Prefix->Bytes, Prefix->Size);
                Bytes[Prefix->Size] = Opcodes[O];
                const size_t Length = Prefix->Size + 1;
                OK(uc_mem_write(Engine, Code, Bytes, Length));
                OK(uc_ctl_remove_cache(Engine, Code, Code + Length));
                for (unsigned Input = 0; Input <= UINT8_MAX; ++Input) {
                    uint64_t AX =
                        ((SeedAX & ~AHMask) | ((uint64_t)Input << AHShift)) &
                        Mode->Mask;
                    uint64_t SP = SeedSP & Mode->Mask;
                    uint64_t InputFlags = (Input & 1) ? Flags : Reserved;
                    OK(uc_reg_write(Engine, Mode->AX, &AX));
                    OK(uc_reg_write(Engine, Mode->SP, &SP));
                    OK(uc_reg_write(Engine, UC_X86_REG_EFLAGS, &InputFlags));
                    OK(uc_emu_start(Engine, Code, Code + Length, 0,
                                    OneInstruction));
                    uint64_t ObservedAX = 0, ObservedSP = 0, ObservedPC = 0;
                    uint64_t ObservedFlags = 0;
                    OK(uc_reg_read(Engine, Mode->AX, &ObservedAX));
                    OK(uc_reg_read(Engine, Mode->SP, &ObservedSP));
                    OK(uc_reg_read(Engine, Mode->PC, &ObservedPC));
                    OK(uc_reg_read(Engine, UC_X86_REG_EFLAGS, &ObservedFlags));
                    const uint64_t ExpectedAX =
                        Opcodes[O] == LAHF
                            ? (AX & ~AHMask) |
                                  (((InputFlags & StatusMask) | Reserved)
                                   << AHShift)
                            : AX;
                    const uint64_t ExpectedFlags =
                        Opcodes[O] == SAHF
                            ? (InputFlags & ~StatusMask) | (Input & StatusMask)
                            : InputFlags;
                    TEST_CHECK(ObservedAX == ExpectedAX);
                    TEST_MSG(CaseContext, Mode->Kind, P, Opcodes[O], Input);
                    TEST_CHECK(ObservedSP == SP);
                    TEST_CHECK(ObservedPC == Code + Length);
                    TEST_CHECK(ObservedFlags == ExpectedFlags);
                }
            }
        }
        OK(uc_close(Engine));
    }
}

static void explicitREXRegisters(void)
{
    const struct {
        int Destination;
        uint8_t Code[ExplicitBytes];
    } Cases[] = {
#define UC_STATUS_EXPLICIT(Register, ...) {Register, {__VA_ARGS__}},
#include "x86_status_flags.def"
#undef UC_STATUS_EXPLICIT
    };
    for (size_t I = 0; I < sizeof(Cases) / sizeof(Cases[0]); ++I) {
        uc_engine *Engine = NULL;
        OK(uc_open(UC_ARCH_X86, UC_MODE_64, &Engine));
        OK(uc_mem_map(Engine, Code, Page, UC_PROT_ALL));
        OK(uc_mem_write(Engine, Code, Cases[I].Code, sizeof(Cases[I].Code)));
        uint64_t AX = SeedAX, SP = SeedSP, R12 = SeedR12, Rflags = Flags;
        OK(uc_reg_write(Engine, UC_X86_REG_RAX, &AX));
        OK(uc_reg_write(Engine, UC_X86_REG_RSP, &SP));
        OK(uc_reg_write(Engine, UC_X86_REG_R12, &R12));
        OK(uc_reg_write(Engine, UC_X86_REG_RFLAGS, &Rflags));
        OK(uc_emu_start(Engine, Code, Code + sizeof(Cases[I].Code), 0,
                        OneInstruction));
        OK(uc_reg_read(Engine, UC_X86_REG_RAX, &AX));
        OK(uc_reg_read(Engine, UC_X86_REG_RSP, &SP));
        OK(uc_reg_read(Engine, UC_X86_REG_R12, &R12));
        OK(uc_reg_read(Engine, UC_X86_REG_RFLAGS, &Rflags));
        TEST_CHECK(AX == SeedAX);
        TEST_CHECK(SP == (Cases[I].Destination == UC_X86_REG_RSP
                              ? (SeedSP & ~(uint64_t)UINT8_MAX) | Immediate
                              : SeedSP));
        TEST_CHECK(R12 == (Cases[I].Destination == UC_X86_REG_R12
                               ? (SeedR12 & ~(uint64_t)UINT8_MAX) | Immediate
                               : SeedR12));
        TEST_CHECK(Rflags == Flags);
        OK(uc_close(Engine));
    }
}

static void unsupportedLongModeFeature(void)
{
    const uint8_t Opcodes[] = {LAHF, SAHF};
    for (size_t I = 0; I < sizeof(Opcodes); ++I) {
        uc_engine *Engine = NULL;
        OK(uc_open(UC_ARCH_X86, UC_MODE_64, &Engine));
        OK(uc_ctl_set_cpu_model(Engine, UC_CPU_X86_486));
        OK(uc_mem_map(Engine, Code, Page, UC_PROT_ALL));
        OK(uc_mem_write(Engine, Code, &Opcodes[I], sizeof(Opcodes[I])));
        uint64_t AX = SeedAX, SP = SeedSP, PC = 0;
        OK(uc_reg_write(Engine, UC_X86_REG_RAX, &AX));
        OK(uc_reg_write(Engine, UC_X86_REG_RSP, &SP));
        TEST_CHECK(uc_emu_start(Engine, Code, Code + 1, 0, OneInstruction) ==
                   UC_ERR_INSN_INVALID);
        OK(uc_reg_read(Engine, UC_X86_REG_RAX, &AX));
        OK(uc_reg_read(Engine, UC_X86_REG_RSP, &SP));
        OK(uc_reg_read(Engine, UC_X86_REG_RIP, &PC));
        TEST_CHECK(AX == SeedAX);
        TEST_CHECK(SP == SeedSP);
        TEST_CHECK(PC == Code);
        OK(uc_close(Engine));
    }
}

static void lockedStatusInstructions(void)
{
    const uint8_t Opcodes[] = {LAHF, SAHF, CMC, CLC, STC};
    const uint64_t FlagInputs[] = {Reserved, Flags};
    for (size_t M = 0; M < sizeof(Modes) / sizeof(Modes[0]); ++M) {
        const struct Mode *Mode = &Modes[M];
        uc_engine *Engine = NULL;
        OK(uc_open(UC_ARCH_X86, Mode->Kind, &Engine));
        OK(uc_mem_map(Engine, Code, Page, UC_PROT_ALL));
        for (size_t P = 0; P < sizeof(Prefixes) / sizeof(Prefixes[0]); ++P) {
            const struct Prefix *Prefix = &Prefixes[P];
            if (Prefix->LongMode && Mode->Kind != UC_MODE_64)
                continue;
            /* Check LOCK on both sides of any otherwise ignored prefixes. */
            for (size_t Position = 0; Position <= Prefix->Size;
                 Position += Prefix->Size ? Prefix->Size : 1) {
                for (size_t O = 0; O < sizeof(Opcodes); ++O) {
                    uint8_t Bytes[MaxPrefixBytes + 2];
                    memcpy(Bytes, Prefix->Bytes, Position);
                    Bytes[Position] = Lock;
                    memcpy(Bytes + Position + 1, Prefix->Bytes + Position,
                           Prefix->Size - Position);
                    Bytes[Prefix->Size + 1] = Opcodes[O];
                    const size_t Length = Prefix->Size + 2;
                    OK(uc_mem_write(Engine, Code, Bytes, Length));
                    OK(uc_ctl_remove_cache(Engine, Code, Code + Length));
                    for (size_t F = 0;
                         F < sizeof(FlagInputs) / sizeof(FlagInputs[0]); ++F) {
                        uint64_t AX = SeedAX & Mode->Mask;
                        uint64_t SP = SeedSP & Mode->Mask;
                        uint64_t PC = 0, ObservedFlags = 0;
                        OK(uc_reg_write(Engine, Mode->AX, &AX));
                        OK(uc_reg_write(Engine, Mode->SP, &SP));
                        OK(uc_reg_write(Engine, UC_X86_REG_EFLAGS,
                                        &FlagInputs[F]));
                        TEST_CHECK(uc_emu_start(Engine, Code, Code + Length, 0,
                                                OneInstruction) ==
                                   UC_ERR_INSN_INVALID);
                        TEST_MSG(CaseContext, Mode->Kind, P, Opcodes[O],
                                 (unsigned)FlagInputs[F]);
                        OK(uc_reg_read(Engine, Mode->AX, &AX));
                        OK(uc_reg_read(Engine, Mode->SP, &SP));
                        OK(uc_reg_read(Engine, Mode->PC, &PC));
                        OK(uc_reg_read(Engine, UC_X86_REG_EFLAGS,
                                       &ObservedFlags));
                        TEST_CHECK(AX == (SeedAX & Mode->Mask));
                        TEST_CHECK(SP == (SeedSP & Mode->Mask));
                        TEST_CHECK(PC == Code);
                        TEST_CHECK(ObservedFlags == FlagInputs[F]);
                    }
                }
            }
        }
        OK(uc_close(Engine));
    }
}

TEST_LIST = {
#define UC_STATUS_TEST(Name, Function) {#Name, Function},
#include "x86_status_flags.def"
#undef UC_STATUS_TEST
    {NULL, NULL}};
