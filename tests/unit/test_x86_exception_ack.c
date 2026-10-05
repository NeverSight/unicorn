/* Original exception-delivery regression, NeverD contributors, 2026-09-30.
 * Licensed under the same terms as the Unicorn unit tests. */
#include "unicorn_test.h"

#define UC_X86_ACK_VALUE(Name, Value) static const uint64_t Name = Value;
#define UC_X86_ACK_BYTES(Name, ...) static const uint8_t Name[] = {__VA_ARGS__};
#include "x86_exception_ack.def"
#undef UC_X86_ACK_BYTES
#undef UC_X86_ACK_VALUE

static void interrupt(uc_engine *UC, uint32_t Vector, void *Data) {
  unsigned *Count = Data;
  TEST_CHECK(Vector == DivideVector);
  ++*Count;
  OK(uc_emu_stop(UC));
}

static void repeated_delivery(bool Restore) {
  uc_engine *UC = NULL;
  uc_context *Context = NULL;
  uc_hook Hook;
  unsigned Count = 0;
  OK(uc_open(UC_ARCH_X86, UC_MODE_64, &UC));
  OK(uc_mem_map(UC, Code, PageBytes, UC_PROT_ALL));
  OK(uc_mem_write(UC, Code, Divide, sizeof(Divide)));
  OK(uc_hook_add(UC, &Hook, UC_HOOK_INTR, interrupt, &Count, 1, 0));
  OK(uc_context_alloc(UC, &Context));
  for (unsigned I = 0; I < Iterations; ++I) {
    uint64_t AX = Dividend, DX = 0, CX = 0, PC = 0;
    OK(uc_reg_write(UC, UC_X86_REG_RAX, &AX));
    OK(uc_reg_write(UC, UC_X86_REG_RDX, &DX));
    OK(uc_reg_write(UC, UC_X86_REG_RCX, &CX));
    OK(uc_emu_start(UC, Code, Code + sizeof(Divide), Timeout, 0));
    TEST_CHECK(Count == I + 1);
    OK(uc_reg_read(UC, UC_X86_REG_RIP, &PC));
    OK(uc_reg_read(UC, UC_X86_REG_RAX, &AX));
    OK(uc_reg_read(UC, UC_X86_REG_RDX, &DX));
    TEST_CHECK(PC == Code && AX == Dividend && DX == 0);
    if (Restore) {
      OK(uc_context_save(UC, Context));
      OK(uc_context_restore(UC, Context));
    }
    CX = Divisor;
    OK(uc_reg_write(UC, UC_X86_REG_RCX, &CX));
    OK(uc_emu_start(UC, Code, Code + sizeof(Divide), Timeout, 0));
    TEST_CHECK(Count == I + 1);
    OK(uc_reg_read(UC, UC_X86_REG_RIP, &PC));
    OK(uc_reg_read(UC, UC_X86_REG_RAX, &AX));
    OK(uc_reg_read(UC, UC_X86_REG_RDX, &DX));
    TEST_CHECK(PC == Code + sizeof(Divide) && AX == Dividend / Divisor &&
               DX == 0);
  }
  OK(uc_context_free(Context));
  OK(uc_close(UC));
}

static void RepeatedDelivery(void) { repeated_delivery(false); }
static void ContextAfterDelivery(void) { repeated_delivery(true); }

TEST_LIST = {
#define UC_X86_ACK_TEST(Name) {#Name, Name},
#include "x86_exception_ack.def"
#undef UC_X86_ACK_TEST
    {NULL, NULL}};
