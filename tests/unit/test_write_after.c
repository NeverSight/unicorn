/* Independently authored regressions for committed RAM write observations. */
#include "unicorn_test.h"

enum { Code = 0x1000, Data = 0x4000, Page = 0x1000 };

struct Observation {
    unsigned before, after;
    uint64_t address, value;
    int size;
};

static void observe(uc_engine *uc, uc_mem_type type, uint64_t address,
                    int size, int64_t value, void *opaque)
{
    struct Observation *o = opaque;
    if (type == UC_MEM_WRITE) {
        ++o->before;
        return;
    }
    TEST_CHECK(type == UC_MEM_WRITE_AFTER);
    ++o->after;
    TEST_CHECK(address == o->address);
    TEST_CHECK(size == o->size);
    TEST_CHECK((uint64_t)value == o->value);
    uint64_t actual = 0;
    OK(uc_mem_read(uc, address, &actual, size));
    TEST_CHECK(actual == o->value);
}

static void run_store(const uint8_t *code, size_t length, uint64_t destination,
                      uint64_t initial, uint64_t value, bool prehook,
                      unsigned protection, uc_err expected)
{
    uc_engine *uc;
    uc_hook hook;
    struct Observation o = {0, 0, destination, value, 4};
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, Code, Page, UC_PROT_ALL));
    OK(uc_mem_map(uc, Data, 2 * Page, UC_PROT_ALL));
    OK(uc_mem_write(uc, Code, code, length));
    if (destination >= Data)
        OK(uc_mem_write(uc, destination, &initial, 4));
    if (protection != UC_PROT_ALL)
        OK(uc_mem_protect(uc, Data + Page, Page, protection));
    OK(uc_reg_write(uc, UC_X86_REG_RDI, &destination));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &value));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE_AFTER |
                  (prehook ? UC_HOOK_MEM_WRITE : 0), observe, &o, 1, 0));
    uc_assert_err(expected, uc_emu_start(uc, Code, Code + length, 100000, 0));
    uint64_t pc = 0;
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &pc));
    TEST_CHECK(o.after == (expected == UC_ERR_OK ? 1 : 0));
    TEST_MSG("pre-store callbacks: %u, committed callbacks: %u, PC: %llx", o.before,
             o.after, (unsigned long long)pc);
    if (expected != UC_ERR_OK) {
        uint64_t actual = 0;
        OK(uc_mem_read(uc, destination, &actual, 4));
        TEST_CHECK(actual == initial);
    }
    if (destination < Data && prehook)
        TEST_CHECK(o.before == 2); /* Precise SMC retries before committing. */
    OK(uc_close(uc));
}

static void test_ram_stores(void)
{
    const uint8_t store[] = {0x89, 0x07};
    for (unsigned pre = 0; pre < 2; ++pre) {
        run_store(store, sizeof(store), Data, 0, 0x1020304, pre,
                  UC_PROT_ALL, UC_ERR_OK);
        run_store(store, sizeof(store), Data, 0x1020304, 0x1020304, pre,
                  UC_PROT_ALL, UC_ERR_OK);
        run_store(store, sizeof(store), Data + Page - 2, 0, 0x1020304, pre,
                  UC_PROT_ALL, UC_ERR_OK);
        run_store(store, sizeof(store), Data + Page - 2, 0x1020304, 0x5060708,
                  pre, UC_PROT_READ, UC_ERR_WRITE_PROT);
    }
}

static void test_self_modifying_store(void)
{
    const uint8_t code[] = {0x89, 0x07, 0x83, 0xc0, 0x01,
                           0x89, 0x07, 0xeb, 0xfe};
    run_store(code, sizeof(code), Code + 5, 0, 0x90909090, true,
              UC_PROT_ALL, UC_ERR_OK);
}

static void test_locked_store(void)
{
    const uint8_t xadd[] = {0xf0, 0x0f, 0xc1, 0x07};
    run_store(xadd, sizeof(xadd), Data, 0, 7, false, UC_PROT_ALL, UC_ERR_OK);
}

TEST_LIST = {{"ram_stores", test_ram_stores},
             {"self_modifying_store", test_self_modifying_store},
             {"locked_store", test_locked_store},
             {NULL, NULL}};
