/* Original LOOP/JCXZ target and counter regressions, 2026-10-05.
 * NeverD contributors; licensed under the Unicorn unit-test terms. */
#include "unicorn_test.h"

#define UC_LOOP_VALUE(Name, Value) enum { Name = Value };
#define UC_LOOP_WIDE_VALUE(Name, Value) static const uint64_t Name = Value;
#define UC_LOOP_TEXT(Name, Text) static const char Name[] = Text;
#include "x86_loop_targets.def"
#undef UC_LOOP_TEXT
#undef UC_LOOP_WIDE_VALUE
#undef UC_LOOP_VALUE

struct Operation {
  uint8_t Opcode;
  int Condition;
  bool Decrement;
};
static const struct Operation Operations[] = {
#define UC_LOOP_OPERATION(Opcode, Condition, Decrement)                        \
  {Opcode, Condition, Decrement},
#include "x86_loop_targets.def"
#undef UC_LOOP_OPERATION
};
struct Prefix {
  size_t Size;
  bool AddressOverride, OperandOverride, LongMode;
  uint8_t Bytes[MaxPrefixBytes];
};
static const struct Prefix Prefixes[] = {
#define UC_LOOP_PREFIX(Size, Address, Operand, LongMode, ...)                  \
  {Size, Address, Operand, LongMode, {__VA_ARGS__}},
#include "x86_loop_targets.def"
#undef UC_LOOP_PREFIX
};
static const uint64_t Counts[] = {
#define UC_LOOP_COUNT(Value) Value,
#include "x86_loop_targets.def"
#undef UC_LOOP_COUNT
};
static const uint32_t Flags[] = {
#define UC_LOOP_FLAGS(Value) Value,
#include "x86_loop_targets.def"
#undef UC_LOOP_FLAGS
};
static const int Displacements[] = {
#define UC_LOOP_DISPLACEMENT(Value) Value,
#include "x86_loop_targets.def"
#undef UC_LOOP_DISPLACEMENT
};

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

static void runCases(uc_mode Mode) {
  uc_engine *Engine = NULL;
  OK(uc_open(UC_ARCH_X86, Mode, &Engine));
  uint8_t Padding[Page];
  memset(Padding, Nop, sizeof(Padding));
  // Low memory holds a wrongly truncated target, so the failure is a precise
  // RIP mismatch rather than an incidental fetch error. Both valid and wrong
  // paths can stop after the single original instruction.
  const uint64_t Pages[] = {0, Code16, Code32, Code64};
  for (size_t P = 0; P < sizeof(Pages) / sizeof(Pages[0]); ++P) {
    if (Mode != UC_MODE_64 && Pages[P] == Code64)
      continue;
    OK(uc_mem_map(Engine, Pages[P], Page, UC_PROT_ALL));
    OK(uc_mem_write(Engine, Pages[P], Padding, sizeof(Padding)));
  }
  // Automatic arrays allow named 64-bit constants in portable C/MSVC.
  const uint64_t Addresses[] = {Code16, Code32, Code64};
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
      const uint64_t CounterMask =
          Mode == UC_MODE_64
              ? (Prefix->AddressOverride ? UINT32_MAX : UINT64_MAX)
          : (Mode == UC_MODE_16) != Prefix->AddressOverride ? UINT16_MAX
                                                            : UINT32_MAX;
      // Operand size only narrows a taken legacy target. Long-mode short
      // targets always retain RIP; 67H changes the counter independently.
      const uint64_t TargetMask =
          Mode == UC_MODE_64                                ? UINT64_MAX
          : (Mode == UC_MODE_16) != Prefix->OperandOverride ? UINT16_MAX
                                                            : UINT32_MAX;
      for (size_t O = 0; O < sizeof(Operations) / sizeof(Operations[0]); ++O) {
        const struct Operation *Op = &Operations[O];
        for (size_t D = 0; D < sizeof(Displacements) / sizeof(Displacements[0]);
             ++D) {
          const int Offset = Displacements[D];
          uint8_t Bytes[MaxPrefixBytes + InstructionBytes];
          memcpy(Bytes, Prefix->Bytes, Prefix->Size);
          Bytes[Prefix->Size] = Op->Opcode;
          Bytes[Prefix->Size + 1] = (uint8_t)Offset;
          const size_t Length = Prefix->Size + InstructionBytes;
          OK(uc_mem_write(Engine, Entry, Bytes, Length));
          OK(uc_ctl_remove_cache(Engine, Entry, Entry + Length));
          for (size_t C = 0; C < sizeof(Counts) / sizeof(Counts[0]); ++C) {
            const uint64_t Input = Counts[C] & RegisterMask;
            const uint64_t Remaining =
                (Input - (Op->Decrement ? 1 : 0)) & CounterMask;
            const uint64_t ExpectedCount =
                !Op->Decrement ? Input
                : Mode == UC_MODE_64 && Prefix->AddressOverride
                    ? Remaining
                    : (Input & ~CounterMask) | Remaining;
            for (size_t F = 0; F < sizeof(Flags) / sizeof(Flags[0]); ++F) {
              uint32_t Before = Flags[F];
              writeRegister(Engine, Mode, UC_X86_REG_RCX, UC_X86_REG_ECX,
                            Input);
              writeRegister(Engine, Mode, UC_X86_REG_RAX, UC_X86_REG_EAX,
                            SeedAX);
              writeRegister(Engine, Mode, UC_X86_REG_RSP, UC_X86_REG_ESP,
                            SeedSP);
              if (Mode == UC_MODE_64)
                OK(uc_reg_write(Engine, UC_X86_REG_R9, &SeedR9));
              OK(uc_reg_write(Engine, UC_X86_REG_EFLAGS, &Before));
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
              const bool Taken =
                  Op->Decrement
                      ? Remaining && (!Op->Condition || !!(Before & ZeroFlag) ==
                                                            (Op->Condition > 0))
                      : !Remaining;
              const uint64_t ExpectedPC =
                  Taken ? (Entry + Length + Offset) & TargetMask
                        : Entry + Length;
              if (!TEST_CHECK(Counter == ExpectedCount && PC == ExpectedPC &&
                              After == Before &&
                              AX == (SeedAX & RegisterMask) &&
                              SP == (SeedSP & RegisterMask) && R9 == SeedR9)) {
                TEST_MSG(CaseContext, (unsigned)Mode, P, (unsigned)Op->Opcode,
                         (unsigned long long)Input, (unsigned)Before, Offset,
                         (unsigned long long)Counter,
                         (unsigned long long)ExpectedCount,
                         (unsigned long long)PC,
                         (unsigned long long)ExpectedPC);
                OK(uc_close(Engine));
                return;
              }
            }
          }
        }
      }
    }
  }
  OK(uc_close(Engine));
}
static void longModeTargetsAndCounters(void) { runCases(UC_MODE_64); }
static void legacy32TargetAndCounterWidths(void) { runCases(UC_MODE_32); }
static void legacy16TargetAndCounterWidths(void) { runCases(UC_MODE_16); }

TEST_LIST = {
#define UC_LOOP_TEST(Name, Function) {#Name, Function},
#include "x86_loop_targets.def"
#undef UC_LOOP_TEST
    {NULL, NULL}};
