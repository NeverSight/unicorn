/* Original cache-control argument-width regressions, 2026-10-05.
 * NeverD contributors; licensed under the Unicorn unit-test terms. */
#include "unicorn_test.h"

enum CacheAddress {
#define UC_CACHE_ADDRESS(Name, Value) Name = Value,
#include "ctl_cache_arguments.def"
#undef UC_CACHE_ADDRESS
};

#define UC_CACHE_VALUE(Name, Value) enum { Name = Value };
#include "ctl_cache_arguments.def"
#undef UC_CACHE_VALUE

static const uint8_t Code[] = {
#define UC_CACHE_CODE(...) __VA_ARGS__,
#include "ctl_cache_arguments.def"
#undef UC_CACHE_CODE
};

typedef uc_err (*RequestCache)(uc_engine *, uint64_t, uc_tb *);
typedef uc_err (*RemoveCache)(uc_engine *, uint64_t, uint64_t);

static void cacheArguments(uint64_t Address, RequestCache Request,
                           RemoveCache Remove)
{
    uc_engine *Engine = NULL;
    uc_tb Block = {0};
    uint32_t Result = 0;
    uint8_t *Memory = calloc(PageSize, 1);
    TEST_ASSERT(Memory != NULL);
    memcpy(Memory, Code, sizeof(Code));
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &Engine));
    OK(uc_mem_map_ptr(Engine, Address, PageSize, UC_PROT_ALL, Memory));

    const uc_err Error = Request(Engine, Address, &Block);
    OK(Error);
    if (Error != UC_ERR_OK)
        goto Finish;
    TEST_CHECK(Block.pc == Address);
    TEST_CHECK(Block.size == sizeof(Code));
    TEST_CHECK(Block.icount == InstructionCount);

    OK(uc_emu_start(Engine, Address, Address + sizeof(Code), 0, 0));
    OK(uc_reg_read(Engine, UC_X86_REG_EAX, &Result));
    TEST_CHECK(Result == FirstResult);

    /* Mutate mapped host RAM directly so only Remove can evict the old TB. */
    Memory[ImmediateOffset] = SecondResult;
    OK(Remove(Engine, Address, Address + sizeof(Code)));
    OK(uc_emu_start(Engine, Address, Address + sizeof(Code), 0, 0));
    OK(uc_reg_read(Engine, UC_X86_REG_EAX, &Result));
    TEST_CHECK(Result == SecondResult);
    TEST_CHECK(Remove(Engine, Address, Address) == UC_ERR_ARG);

Finish:
    OK(uc_close(Engine));
    free(Memory);
}

/* Preserve each caller's integer type all the way to the public macros. */
#define UC_CACHE_CASE(Name, Type, Address)                                     \
    static uc_err request##Name(uc_engine *Engine, uint64_t Begin,             \
                                uc_tb *Block)                                  \
    {                                                                          \
        return uc_ctl_request_cache(Engine, (Type)Begin, Block);               \
    }                                                                          \
    static uc_err remove##Name(uc_engine *Engine, uint64_t Begin,              \
                               uint64_t End)                                   \
    {                                                                          \
        return uc_ctl_remove_cache(Engine, (Type)Begin, (Type)End);            \
    }                                                                          \
    static void Name(void)                                                     \
    {                                                                          \
        cacheArguments(Address, request##Name, remove##Name);                  \
    }
#include "ctl_cache_arguments.def"
#undef UC_CACHE_CASE

TEST_LIST = {
#define UC_CACHE_CASE(Name, Type, Address) {#Name, Name},
#include "ctl_cache_arguments.def"
#undef UC_CACHE_CASE
    {NULL, NULL}};
