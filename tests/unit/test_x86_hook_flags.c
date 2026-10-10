/* Independently authored regressions for lazy flags at observed accesses. */
#include "unicorn_test.h"

enum { Code = 0x1000, Data = 0x4000, Page = 0x1000, StatusMask = 0x8c5 };

struct Observation {
    uint64_t AccessPC;
    uint64_t ExpectedFlags;
    unsigned Accesses;
    bool ReplaceFlags;
};

static void code_hook(uc_engine *uc, uint64_t address, uint32_t size,
                      void *opaque)
{
    struct Observation *o = opaque;
    (void)size;
    if (address == o->AccessPC && o->ReplaceFlags) {
        uint64_t flags = 0x202;
        OK(uc_reg_write(uc, UC_X86_REG_EFLAGS, &flags));
    }
}

static void memory_hook(uc_engine *uc, uc_mem_type type, uint64_t address,
                        int size, int64_t value, void *opaque)
{
    struct Observation *o = opaque;
    uint64_t flags = 0;
    (void)type;
    (void)address;
    (void)size;
    (void)value;
    ++o->Accesses;
    OK(uc_reg_read(uc, UC_X86_REG_EFLAGS, &flags));
    TEST_CHECK((flags & StatusMask) == o->ExpectedFlags);
}

static uint64_t shift_flags(uint16_t input)
{
    const uint16_t result = (uint16_t)(input << 1);
    unsigned ones = 0;
    for (unsigned bit = 0; bit < 8; ++bit)
        ones += (result >> bit) & 1;
    return ((input >> 15) & 1) | ((ones % 2 == 0) ? 4 : 0) |
           (result == 0 ? 0x40 : 0) | (result & 0x8000 ? 0x80 : 0) |
           (((input ^ result) & 0x8000) ? 0x800 : 0);
}

static void run_matrix(unsigned fault, bool replace_flags)
{
    const uc_mode modes[] = {UC_MODE_16, UC_MODE_32, UC_MODE_64};
    const uint16_t inputs[] = {0, 1, 0x7fff, 0x8000, 0x8001, 0xffff};
    for (unsigned m = 0; m < 3; ++m) {
        for (unsigned write = 0; write < 2; ++write) {
            for (unsigned bounded = 0; bounded < 3; ++bounded) {
                if (replace_flags && bounded == 0)
                    continue;
                for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]);
                     ++i) {
                    uc_engine *uc;
                    uc_hook code, memory;
                    uint8_t bytes[16];
                    size_t n = 0;
                    if (m)
                        bytes[n++] = 0x66;
                    bytes[n++] = 0xd1; /* SHL ax, 1 */
                    bytes[n++] = 0xe0;
                    const size_t access_offset = n;
                    if (m)
                        bytes[n++] = 0x66;
                    bytes[n++] =
                        write ? 0x89 : 0x8b; /* MOV [di], dx / reverse */
                    bytes[n++] = m ? 0x17 : 0x15;
                    bytes[n++] = 0x0f; /* SETA bl */
                    bytes[n++] = 0x97;
                    bytes[n++] = 0xc3;
                    struct Observation o = {
                        Code + access_offset,
                        replace_flags ? 0 : shift_flags(inputs[i]), 0,
                        replace_flags};
                    OK(uc_open(UC_ARCH_X86, modes[m], &uc));
                    OK(uc_mem_map(uc, Code, Page, UC_PROT_ALL));
                    OK(uc_mem_write(uc, Code, bytes, n));
                    if (fault != 1)
                        OK(uc_mem_map(uc, Data, Page,
                                      fault == 2 ? UC_PROT_EXEC : UC_PROT_ALL));
                    uint64_t ax = inputs[i], di = Data, flags = 0x202, bx = 0;
                    OK(uc_reg_write(uc, UC_X86_REG_AX, &ax));
                    OK(uc_reg_write(uc,
                                    m == 0   ? UC_X86_REG_DI
                                    : m == 1 ? UC_X86_REG_EDI
                                             : UC_X86_REG_RDI,
                                    &di));
                    OK(uc_reg_write(uc, UC_X86_REG_BX, &bx));
                    OK(uc_reg_write(uc, UC_X86_REG_EFLAGS, &flags));
                    if (bounded)
                        OK(uc_hook_add(uc, &code, UC_HOOK_CODE, code_hook, &o,
                                       bounded == 1 ? 1 : o.AccessPC,
                                       bounded == 1 ? 0 : o.AccessPC));
                    OK(uc_hook_add(uc, &memory,
                                   UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                                   memory_hook, &o, 1, 0));
                    const uc_err expected =
                        fault == 0 ? UC_ERR_OK
                        : fault == 1
                            ? (write ? UC_ERR_WRITE_UNMAPPED
                                     : UC_ERR_READ_UNMAPPED)
                            : (write ? UC_ERR_WRITE_PROT : UC_ERR_READ_PROT);
                    uc_assert_err(expected,
                                  uc_emu_start(uc, Code, Code + n, 0, 0));
                    OK(uc_reg_read(uc, UC_X86_REG_EFLAGS, &flags));
                    TEST_CHECK((flags & StatusMask) == o.ExpectedFlags);
                    TEST_MSG("mode=%d write=%u hooks=%u input=%x fault=%u",
                             modes[m], write, bounded, inputs[i], fault);
                    if (!fault) {
                        OK(uc_reg_read(uc, UC_X86_REG_BX, &bx));
                        TEST_CHECK((bx & 0xff) ==
                                   ((o.ExpectedFlags & 0x41) ? 0 : 1));
                        TEST_CHECK(o.Accesses == 1);
                    } else {
                        uint64_t pc = 0;
                        OK(uc_reg_read(uc,
                                       m == 0   ? UC_X86_REG_IP
                                       : m == 1 ? UC_X86_REG_EIP
                                                : UC_X86_REG_RIP,
                                       &pc));
                        TEST_CHECK(pc == o.AccessPC);
                    }
                    OK(uc_close(uc));
                }
            }
        }
    }
}

static void observed_memory(void)
{
    run_matrix(0, false);
}
static void unmapped_memory(void)
{
    run_matrix(1, false);
}
static void protected_memory(void)
{
    run_matrix(2, false);
}
static void hook_replaced_flags(void)
{
    for (unsigned fault = 0; fault < 3; ++fault)
        run_matrix(fault, true);
}

TEST_LIST = {{"observed_memory", observed_memory},
             {"unmapped_memory", unmapped_memory},
             {"protected_memory", protected_memory},
             {"hook_replaced_flags", hook_replaced_flags},
             {NULL, NULL}};
