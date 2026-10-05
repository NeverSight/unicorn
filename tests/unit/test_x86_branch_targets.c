/* Original relative JMP/Jcc regressions, 2026-10-05.
 * NeverD contributors; licensed under the Unicorn unit-test terms. */
#include "unicorn_test.h"

#define UC_BRANCH_VALUE(Name, Value) enum { Name = Value };
#define UC_BRANCH_WIDE_VALUE(Name, Value) static const uint64_t Name = Value;
#define UC_BRANCH_TEXT(Name, Text) static const char Name[] = Text;
#include "x86_branch_targets.def"
#undef UC_BRANCH_TEXT
#undef UC_BRANCH_WIDE_VALUE
#undef UC_BRANCH_VALUE

enum Operation {
#define UC_BRANCH_OPERATION(Name, Short, Near, Expression) Name,
#include "x86_branch_targets.def"
#undef UC_BRANCH_OPERATION
};
struct Branch {
  enum Operation Kind;
  uint8_t Short, Near;
};
static const struct Branch Branches[] = {
#define UC_BRANCH_OPERATION(Name, Short, Near, Expression) {Name, Short, Near},
#include "x86_branch_targets.def"
#undef UC_BRANCH_OPERATION
};
struct Prefix {
  size_t Size;
  bool OperandOverride, LongMode;
  uint8_t Bytes[MaxPrefixBytes];
};
static const struct Prefix Prefixes[] = {
#define UC_BRANCH_PREFIX(Size, Operand, LongMode, ...)                         \
  {Size, Operand, LongMode, {__VA_ARGS__}},
#include "x86_branch_targets.def"
#undef UC_BRANCH_PREFIX
};
static const int Displacements[] = {
#define UC_BRANCH_DISPLACEMENT(Value) Value,
#include "x86_branch_targets.def"
#undef UC_BRANCH_DISPLACEMENT
};
static bool taken(enum Operation Kind, uint32_t Flags) {
  const bool C = Flags & CarryFlag, P = Flags & ParityFlag,
             Z = Flags & ZeroFlag, S = Flags & SignFlag,
             O = Flags & OverflowFlag;
  switch (Kind) {
#define UC_BRANCH_OPERATION(Name, Short, Near, Expression)                     \
  case Name:                                                                   \
    return Expression;
#include "x86_branch_targets.def"
#undef UC_BRANCH_OPERATION
  }
  abort();
}
static void writeRegister(uc_engine *Engine, uc_mode Mode, int Wide, int Narrow,
                          uint64_t Value) {
  if (Mode == UC_MODE_64) {
    OK(uc_reg_write(Engine, Wide, &Value));
  } else {
    uint32_t Word = (uint32_t)Value;
    OK(uc_reg_write(Engine, Narrow, &Word));
  }
}
static uint64_t readRegister(uc_engine *Engine, uc_mode Mode, int Wide,
                             int Narrow) {
  if (Mode == UC_MODE_64) {
    uint64_t Value = 0;
    OK(uc_reg_read(Engine, Wide, &Value));
    return Value;
  }
  uint32_t Word = 0;
  OK(uc_reg_read(Engine, Narrow, &Word));
  return Word;
}
static void instruction(uc_engine *Engine, uint64_t Address, uint32_t Length,
                        void *Data) {
  (void)Engine;
  (void)Address;
  *(uint32_t *)Data = Length;
}
static void runCases(uc_mode Mode, bool Intel) {
  uc_engine *Engine = NULL;
  OK(uc_open(UC_ARCH_X86, Mode, &Engine));
  OK(uc_ctl_set_cpu_model(Engine, Intel ? IntelModel : AMDModel));
  uint8_t Padding[Page];
  memset(Padding, Nop, sizeof(Padding));
  const uint64_t Pages[] = {0, Code16, Code32, Code64};
  for (size_t P = 0; P < sizeof(Pages) / sizeof(Pages[0]); ++P) {
    if (Mode != UC_MODE_64 && Pages[P] == Code64)
      continue;
    OK(uc_mem_map(Engine, Pages[P], Page, UC_PROT_ALL));
    OK(uc_mem_write(Engine, Pages[P], Padding, sizeof(Padding)));
  }
  uint32_t ObservedLength = 0;
  uc_hook Hook;
  OK(uc_hook_add(Engine, &Hook, UC_HOOK_CODE, instruction, &ObservedLength, 1,
                 0));
  const uint64_t Addresses[] = {Code16, Code32, Code64};
  const uint32_t FlagBits[] = {CarryFlag, ParityFlag, ZeroFlag, SignFlag,
                               OverflowFlag};
  for (size_t A = 0; A < sizeof(Addresses) / sizeof(Addresses[0]); ++A) {
    if ((Mode == UC_MODE_16 && Addresses[A] != Code16) ||
        (Mode == UC_MODE_32 && Addresses[A] == Code64))
      continue;
    const uint64_t Entry = Addresses[A] + EntryOffset;
    const uint64_t RegisterMask = Mode == UC_MODE_64 ? UINT64_MAX : UINT32_MAX;
    for (size_t P = 0; P < sizeof(Prefixes) / sizeof(Prefixes[0]); ++P) {
      const struct Prefix *Prefix = &Prefixes[P];
      if (Prefix->LongMode && Mode != UC_MODE_64)
        continue;
      const bool Narrow = Mode == UC_MODE_64
                              ? !Intel && Prefix->OperandOverride
                              : (Mode == UC_MODE_16) != Prefix->OperandOverride;
      const uint64_t TargetMask = Narrow ? UINT16_MAX : RegisterMask;
      for (size_t B = 0; B < sizeof(Branches) / sizeof(Branches[0]); ++B)
        for (unsigned Near = 0; Near != 2; ++Near)
          for (size_t D = 0;
               D < sizeof(Displacements) / sizeof(Displacements[0]); ++D) {
            const int Offset = Displacements[D];
            uint8_t Bytes[MaxInstructionBytes];
            memcpy(Bytes, Prefix->Bytes, Prefix->Size);
            size_t Length = Prefix->Size;
            if (Near && Branches[B].Kind != JMP)
              Bytes[Length++] = OpcodeEscape;
            Bytes[Length++] = Near ? Branches[B].Near : Branches[B].Short;
            const unsigned ImmediateBytes =
                Near ? (Narrow ? HalfBytes : WordBytes) : ShortBytes;
            for (unsigned I = 0; I < ImmediateBytes; ++I)
              Bytes[Length++] = (uint8_t)((uint32_t)Offset >> (I * ByteBits));
            OK(uc_mem_write(Engine, Entry, Bytes, Length));
            OK(uc_ctl_remove_cache(Engine, Entry, Entry + Length));
            for (unsigned F = 0; F < FlagCombinations; ++F) {
              uint32_t Before = ReservedFlag;
              for (size_t I = 0; I < sizeof(FlagBits) / sizeof(FlagBits[0]);
                   ++I)
                if (F & (1u << I))
                  Before |= FlagBits[I];
              writeRegister(Engine, Mode, UC_X86_REG_RCX, UC_X86_REG_ECX,
                            SeedCX);
              writeRegister(Engine, Mode, UC_X86_REG_RAX, UC_X86_REG_EAX,
                            SeedAX);
              writeRegister(Engine, Mode, UC_X86_REG_RSP, UC_X86_REG_ESP,
                            SeedSP);
              if (Mode == UC_MODE_64)
                OK(uc_reg_write(Engine, UC_X86_REG_R9, &SeedR9));
              OK(uc_reg_write(Engine, UC_X86_REG_EFLAGS, &Before));
              ObservedLength = 0;
              OK(uc_emu_start(Engine, Entry, Entry + Length, 0,
                              OneInstruction));
              const uint64_t Counter =
                  readRegister(Engine, Mode, UC_X86_REG_RCX, UC_X86_REG_ECX);
              const uint64_t PC =
                  readRegister(Engine, Mode, UC_X86_REG_RIP, UC_X86_REG_EIP);
              const uint64_t AX =
                  readRegister(Engine, Mode, UC_X86_REG_RAX, UC_X86_REG_EAX);
              const uint64_t SP =
                  readRegister(Engine, Mode, UC_X86_REG_RSP, UC_X86_REG_ESP);
              uint64_t R9 = SeedR9;
              if (Mode == UC_MODE_64)
                OK(uc_reg_read(Engine, UC_X86_REG_R9, &R9));
              uint32_t After = 0;
              OK(uc_reg_read(Engine, UC_X86_REG_EFLAGS, &After));
              const uint64_t ExpectedPC =
                  taken(Branches[B].Kind, Before)
                      ? (Entry + Length + Offset) & TargetMask
                      : Entry + Length;
              if (!TEST_CHECK(Counter == (SeedCX & RegisterMask) &&
                              PC == ExpectedPC && After == Before &&
                              AX == (SeedAX & RegisterMask) &&
                              SP == (SeedSP & RegisterMask) && R9 == SeedR9 &&
                              ObservedLength == Length)) {
                TEST_MSG(CaseContext, (unsigned)Mode, P, B, Near, Before,
                         Offset, (unsigned long long)PC,
                         (unsigned long long)ExpectedPC, ObservedLength,
                         Length);
                OK(uc_close(Engine));
                return;
              }
            }
          }
    }
  }
  OK(uc_close(Engine));
}
static void intelLongModeTargets(void) { runCases(UC_MODE_64, true); }
static void amdLongModeTargets(void) { runCases(UC_MODE_64, false); }
static void legacy32Targets(void) { runCases(UC_MODE_32, true); }
static void legacy16Targets(void) { runCases(UC_MODE_16, true); }
TEST_LIST = {
#define UC_BRANCH_TEST(Name, Function) {#Name, Function},
#include "x86_branch_targets.def"
#undef UC_BRANCH_TEST
    {NULL, NULL}};
