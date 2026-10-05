/* Original ENTER operand-size regressions, NeverD contributors, 2026.
 * Licensed under the same terms as the Unicorn unit tests. */
#include "unicorn_test.h"
#include <limits.h>

#define UC_X86_ENTER_CONSTANT(Name, Value) enum { Name = Value };
#include "x86_enter.def"
#undef UC_X86_ENTER_CONSTANT

typedef struct EnterCase {
    uc_mode Mode;
    uint64_t InitialFrame;
    uint64_t ExpectedFrame;
    uint64_t ExpectedStack;
    size_t PushBytes;
    size_t CodeBytes;
    uint8_t Code[MaxCodeBytes];
} EnterCase;

static void WriteGPR(uc_engine *UC, uc_mode Mode, int Reg, uint64_t Value)
{
    if (Mode == UC_MODE_64) {
        OK(uc_reg_write(UC, Reg, &Value));
    } else {
        uint32_t Narrow = (uint32_t)Value;
        OK(uc_reg_write(UC, Reg, &Narrow));
    }
}

static uint64_t ReadGPR(uc_engine *UC, uc_mode Mode, int Reg)
{
    if (Mode == UC_MODE_64) {
        uint64_t Value = 0;
        OK(uc_reg_read(UC, Reg, &Value));
        return Value;
    }
    uint32_t Value = 0;
    OK(uc_reg_read(UC, Reg, &Value));
    return Value;
}

static void CheckEnter(const EnterCase *Case)
{
    uc_engine *UC = NULL;
    uint64_t Frame = Case->InitialFrame, Stack = InitialStack;
    uint32_t Flags = InitialFlags;
    uint64_t PC = 0;
    const int FrameReg =
        Case->Mode == UC_MODE_64 ? UC_X86_REG_RBP : UC_X86_REG_EBP;
    const int StackReg =
        Case->Mode == UC_MODE_64 ? UC_X86_REG_RSP : UC_X86_REG_ESP;
    const int PCReg =
        Case->Mode == UC_MODE_64 ? UC_X86_REG_RIP : UC_X86_REG_EIP;
    const uint64_t Window = InitialStack - StackWindowBytes / 2;
    uint8_t Expected[StackWindowBytes], Actual[StackWindowBytes];

    memset(Expected, StackFill, sizeof(Expected));
    OK(uc_open(UC_ARCH_X86, Case->Mode, &UC));
    OK(uc_mem_map(UC, CodeAddress, PageBytes, UC_PROT_ALL));
    OK(uc_mem_map(UC, StackBase, StackBytes, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(UC, CodeAddress, Case->Code, Case->CodeBytes));
    OK(uc_mem_write(UC, Window, Expected, sizeof(Expected)));
    WriteGPR(UC, Case->Mode, FrameReg, Frame);
    WriteGPR(UC, Case->Mode, StackReg, Stack);
    OK(uc_reg_write(UC, UC_X86_REG_EFLAGS, &Flags));

    OK(uc_emu_start(UC, CodeAddress, CodeAddress + Case->CodeBytes, Timeout,
                    0));
    Frame = ReadGPR(UC, Case->Mode, FrameReg);
    Stack = ReadGPR(UC, Case->Mode, StackReg);
    PC = ReadGPR(UC, Case->Mode, PCReg);
    OK(uc_reg_read(UC, UC_X86_REG_EFLAGS, &Flags));
    OK(uc_mem_read(UC, Window, Actual, sizeof(Actual)));
    for (size_t I = 0; I < Case->PushBytes; ++I) {
        Expected[StackWindowBytes / 2 - Case->PushBytes + I] =
            (uint8_t)(Case->InitialFrame >> (I * CHAR_BIT));
    }
    TEST_CHECK(Frame == Case->ExpectedFrame);
    TEST_CHECK(Stack == Case->ExpectedStack);
    TEST_CHECK(PC == CodeAddress + Case->CodeBytes);
    TEST_CHECK(Flags == InitialFlags);
    TEST_CHECK(memcmp(Expected, Actual, sizeof(Expected)) == 0);
    OK(uc_close(UC));
}

#define UC_X86_ENTER_CASE(Name, Mode, Frame, ExpectedFrame, ExpectedStack,     \
                          PushBytes, CodeBytes, ...)                           \
    static void Name(void)                                                     \
    {                                                                          \
        static const EnterCase Case = {                                        \
            Mode,      Frame,     ExpectedFrame, ExpectedStack,                \
            PushBytes, CodeBytes, {__VA_ARGS__}};                              \
        CheckEnter(&Case);                                                     \
    }
#include "x86_enter.def"
#undef UC_X86_ENTER_CASE

TEST_LIST = {
#define UC_X86_ENTER_CASE(Name, ...) {#Name, Name},
#include "x86_enter.def"
#undef UC_X86_ENTER_CASE
    {NULL, NULL}};
