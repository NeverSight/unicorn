#include "unicorn_test.h"

#include <string.h>

static const uint64_t code_address = UINT64_C(0x1000);
static const uint64_t code_mapping_size = UINT64_C(0x1000);
static const uint64_t xsave_address = UINT64_C(0x4000);
static const uint64_t xsave_mapping_size = UINT64_C(0x2000);

#define APX_FEATURE_BIT (UINT32_C(1) << 21)
#define MSR_IMM_FEATURE_BIT (UINT32_C(1) << 5)
#define USER_MSR_FEATURE_BIT (UINT32_C(1) << 15)
#define APX_SUBFEATURE_BIT UINT32_C(1)
#define APX_XSTATE_BIT 19
#define APX_XSTATE_MASK (UINT64_C(1) << APX_XSTATE_BIT)
#define APX_XSAVE_OFFSET UINT64_C(0x3c0)
#define APX_XSAVE_SIZE UINT32_C(128)
#define XSAVE_HEADER_OFFSET UINT64_C(512)
#define CR4_OSXSAVE_MASK (UINT64_C(1) << 18)
#define ENQCMD_FEATURE_BIT (UINT32_C(1) << 29)
#define IA32_PASID_MSR UINT32_C(0xd93)
#define IA32_TSC_AUX_MSR UINT32_C(0xc0000103)
#define EFLAGS_ARITHMETIC_MASK UINT32_C(0x8d5)
#define EFLAGS_ZF UINT32_C(0x40)

static void setup_x86(uc_engine **uc, int cpu_model, const uint8_t *code,
                      size_t code_size)
{
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, uc));
    OK(uc_ctl_set_cpu_model(*uc, cpu_model));
    OK(uc_mem_map(*uc, code_address, code_mapping_size, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_address, code, code_size));
}

static void cpuid_query(int cpu_model, uint32_t leaf, uint32_t subleaf,
                        uint32_t *eax, uint32_t *ebx, uint32_t *ecx,
                        uint32_t *edx)
{
    static const uint8_t code[] = {0x0f, 0xa2};
    uc_engine *uc;

    setup_x86(&uc, cpu_model, code, sizeof(code));
    *eax = leaf;
    *ebx = 0;
    *ecx = subleaf;
    *edx = 0;
    OK(uc_reg_write(uc, UC_X86_REG_EAX, eax));
    OK(uc_reg_write(uc, UC_X86_REG_EBX, ebx));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, edx));
    OK(uc_emu_start(uc, code_address, code_address + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_EAX, eax));
    OK(uc_reg_read(uc, UC_X86_REG_EBX, ebx));
    OK(uc_reg_read(uc, UC_X86_REG_ECX, ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, edx));
    OK(uc_close(uc));
}

static void test_x86_apx_cpuid_and_xstate_enumeration(void)
{
    uint32_t eax, ebx, ecx, edx;
    uint64_t xcr0 = 0;
    uc_engine *uc;

    cpuid_query(UC_CPU_X86_APX, 0, 0, &eax, &ebx, &ecx, &edx);
    TEST_CHECK(eax >= UINT32_C(0x29));

    cpuid_query(UC_CPU_X86_APX, 7, 1, &eax, &ebx, &ecx, &edx);
    TEST_CHECK((ecx & MSR_IMM_FEATURE_BIT) != 0);
    TEST_CHECK((edx & USER_MSR_FEATURE_BIT) == 0);
    TEST_CHECK((edx & APX_FEATURE_BIT) != 0);

    cpuid_query(UC_CPU_X86_APX, 7, 0, &eax, &ebx, &ecx, &edx);
    TEST_CHECK((ecx & ENQCMD_FEATURE_BIT) != 0);

    cpuid_query(UC_CPU_X86_APX, 0x29, 0, &eax, &ebx, &ecx, &edx);
    TEST_CHECK(eax == 0);
    TEST_CHECK(ebx == APX_SUBFEATURE_BIT);
    TEST_CHECK(ecx == 0);
    TEST_CHECK(edx == 0);

    cpuid_query(UC_CPU_X86_APX, 0x0d, APX_XSTATE_BIT, &eax, &ebx, &ecx,
                &edx);
    TEST_CHECK(eax == APX_XSAVE_SIZE);
    TEST_CHECK(ebx == APX_XSAVE_OFFSET);
    TEST_CHECK(ecx == 0);
    TEST_CHECK(edx == 0);

    cpuid_query(UC_CPU_X86_APX, 0x0d, 0, &eax, &ebx, &ecx, &edx);
    TEST_CHECK((eax & (UINT32_C(1) << APX_XSTATE_BIT)) != 0);
    TEST_CHECK(ebx >= APX_XSAVE_OFFSET + APX_XSAVE_SIZE);
    TEST_CHECK(ecx >= APX_XSAVE_OFFSET + APX_XSAVE_SIZE);

    setup_x86(&uc, UC_CPU_X86_APX, (const uint8_t *)"\x90", 1);
    OK(uc_reg_read(uc, UC_X86_REG_XCR0, &xcr0));
    TEST_CHECK((xcr0 & APX_XSTATE_MASK) != 0);
    OK(uc_close(uc));

    cpuid_query(UC_CPU_X86_HASWELL, 0, 0, &eax, &ebx, &ecx, &edx);
    TEST_CHECK(eax < UINT32_C(0x29));
    cpuid_query(UC_CPU_X86_HASWELL, 7, 1, &eax, &ebx, &ecx, &edx);
    TEST_CHECK((ecx & MSR_IMM_FEATURE_BIT) == 0);
    TEST_CHECK((edx & USER_MSR_FEATURE_BIT) == 0);
    TEST_CHECK((edx & APX_FEATURE_BIT) == 0);
}

static void check_rex2_gate(int cpu_model, bool clear_xcr0,
                            bool clear_osxsave, uc_err expected)
{
    /* mov r16, rax */
    static const uint8_t code[] = {0xd5, 0x18, 0x89, 0xc0};
    const uint64_t source = UINT64_C(0x8877665544332211);
    const uint64_t initial = UINT64_C(0x0123456789abcdef);
    uint64_t r16 = initial;
    uint64_t xcr0 = 0;
    uint64_t cr4 = 0;
    uint64_t rip = 0;
    uc_engine *uc;
    uc_err err;

    setup_x86(&uc, cpu_model, code, sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &source));
    OK(uc_reg_write(uc, UC_X86_REG_R16, &r16));
    if (clear_xcr0) {
        OK(uc_reg_read(uc, UC_X86_REG_XCR0, &xcr0));
        xcr0 &= ~APX_XSTATE_MASK;
        OK(uc_reg_write(uc, UC_X86_REG_XCR0, &xcr0));
    }
    if (clear_osxsave) {
        OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
        cr4 &= ~CR4_OSXSAVE_MASK;
        OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));
    }

    err = uc_emu_start(uc, code_address, code_address + sizeof(code), 0, 0);
    TEST_CHECK_(err == expected, "gate returned %s instead of %s",
                uc_strerror(err), uc_strerror(expected));
    OK(uc_reg_read(uc, UC_X86_REG_R16, &r16));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    if (expected == UC_ERR_OK) {
        TEST_CHECK(r16 == source);
        TEST_CHECK(rip == code_address + sizeof(code));
    } else {
        TEST_CHECK(r16 == initial);
        TEST_CHECK(rip == code_address);
    }
    OK(uc_close(uc));
}

static void test_x86_apx_execution_gate(void)
{
    check_rex2_gate(UC_CPU_X86_APX, false, false, UC_ERR_OK);
    check_rex2_gate(UC_CPU_X86_APX, true, false, UC_ERR_INSN_INVALID);
    check_rex2_gate(UC_CPU_X86_APX, false, true, UC_ERR_INSN_INVALID);
    check_rex2_gate(UC_CPU_X86_HASWELL, false, false,
                    UC_ERR_INSN_INVALID);
}

static uint64_t read_xinuse(uc_engine *uc, uint64_t instruction_address)
{
    uint32_t eax = 0;
    uint32_t ecx = 1;
    uint32_t edx = 0;

    OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
    OK(uc_emu_start(uc, instruction_address, instruction_address + 3, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &edx));
    return ((uint64_t)edx << 32) | eax;
}

static void test_x86_apx_xsave_xrstor_and_xinuse(void)
{
    static const uint8_t code[] = {
        0xd5, 0x18, 0x89, 0xc0, /* mov r16, rax */
        0x0f, 0xae, 0x27,       /* xsave [rdi] */
        0x0f, 0xae, 0x2f,       /* xrstor [rdi] */
        0x0f, 0x01, 0xd0,       /* xgetbv */
    };
    const uint64_t value = UINT64_C(0x8877665544332211);
    uint8_t zero_area[0x440] = {0};
    uint64_t r16 = 0;
    uint64_t requested = APX_XSTATE_MASK;
    uint64_t xstate_bv = 0;
    uint64_t saved = 0;
    uint32_t eax = (uint32_t)requested;
    uint32_t edx = (uint32_t)(requested >> 32);
    uint64_t rdi = xsave_address;
    uc_engine *uc;

    setup_x86(&uc, UC_CPU_X86_APX, code, sizeof(code));
    OK(uc_mem_map(uc, xsave_address, xsave_mapping_size, UC_PROT_ALL));
    OK(uc_mem_write(uc, xsave_address, zero_area, sizeof(zero_area)));
    TEST_CHECK((read_xinuse(uc, code_address + 10) & APX_XSTATE_MASK) == 0);

    OK(uc_reg_write(uc, UC_X86_REG_RAX, &value));
    OK(uc_emu_start(uc, code_address, code_address + 4, 0, 0));
    TEST_CHECK((read_xinuse(uc, code_address + 10) & APX_XSTATE_MASK) != 0);

    OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
    OK(uc_reg_write(uc, UC_X86_REG_RDI, &rdi));
    OK(uc_emu_start(uc, code_address + 4, code_address + 7, 0, 0));
    OK(uc_mem_read(uc, xsave_address + XSAVE_HEADER_OFFSET, &xstate_bv,
                   sizeof(xstate_bv)));
    OK(uc_mem_read(uc, xsave_address + APX_XSAVE_OFFSET, &saved,
                   sizeof(saved)));
    TEST_CHECK((xstate_bv & APX_XSTATE_MASK) != 0);
    TEST_CHECK(saved == value);

    r16 = 0;
    OK(uc_reg_write(uc, UC_X86_REG_R16, &r16));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
    OK(uc_emu_start(uc, code_address + 7, code_address + 10, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_R16, &r16));
    TEST_CHECK(r16 == value);

    OK(uc_mem_write(uc, xsave_address, zero_area, sizeof(zero_area)));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
    OK(uc_emu_start(uc, code_address + 7, code_address + 10, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_R16, &r16));
    TEST_CHECK(r16 == 0);
    TEST_CHECK((read_xinuse(uc, code_address + 10) & APX_XSTATE_MASK) == 0);
    OK(uc_close(uc));
}

static void check_invpcid(const uint8_t *code, size_t code_size,
                          bool apx, uint64_t type, uint64_t descriptor_low,
                          uint64_t descriptor_high, uc_err expected)
{
    uint64_t descriptor[2] = {descriptor_low, descriptor_high};
    uint64_t descriptor_address = xsave_address;
    uint64_t rip = 0;
    uc_engine *uc;
    uc_err error;

    setup_x86(&uc, UC_CPU_X86_APX, code, code_size);
    OK(uc_mem_map(uc, xsave_address, xsave_mapping_size, UC_PROT_ALL));
    OK(uc_mem_write(uc, descriptor_address, descriptor,
                    sizeof(descriptor)));
    if (apx) {
        OK(uc_reg_write(uc, UC_X86_REG_R19, &descriptor_address));
    } else {
        OK(uc_reg_write(uc, UC_X86_REG_RBX, &descriptor_address));
    }
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &type));

    error = uc_emu_start(uc, code_address, code_address + code_size, 0, 1);
    TEST_CHECK_(error == expected, "INVPCID returned %s instead of %s",
                uc_strerror(error), uc_strerror(expected));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    if (expected == UC_ERR_OK) {
        TEST_CHECK(rip == code_address + code_size);
    } else {
        TEST_CHECK(rip == code_address);
    }
    OK(uc_close(uc));
}

static void test_x86_apx_and_legacy_invpcid_semantics(void)
{
    static const uint8_t apx_invpcid[] = {
        0x62, 0xfc, 0x7e, 0x08, 0xf2, 0x0b,
    };
    static const uint8_t legacy_invpcid[] = {
        0x66, 0x0f, 0x38, 0x82, 0x0b,
    };

    check_invpcid(apx_invpcid, sizeof(apx_invpcid), true, 0, 0,
                  UINT64_C(0x1234), UC_ERR_OK);
    check_invpcid(apx_invpcid, sizeof(apx_invpcid), true, 3, 0, 0,
                  UC_ERR_OK);
    check_invpcid(legacy_invpcid, sizeof(legacy_invpcid), false, 2, 0, 0,
                  UC_ERR_OK);
    check_invpcid(apx_invpcid, sizeof(apx_invpcid), true, 4, 0, 0,
                  UC_ERR_EXCEPTION);
    check_invpcid(apx_invpcid, sizeof(apx_invpcid), true, 2,
                  UINT64_C(0x1000), 0, UC_ERR_EXCEPTION);
    check_invpcid(apx_invpcid, sizeof(apx_invpcid), true, 0, 0,
                  UINT64_C(0x0000800000000000), UC_ERR_EXCEPTION);
}

static void check_enqueue_ram_retry(const uint8_t *code, size_t code_size,
                                    bool apx, uint64_t source_low,
                                    uint64_t pasid)
{
    const uint64_t source_address = xsave_address;
    const uint64_t destination_address = xsave_address + 0x1000;
    uint64_t source[8] = {0};
    uint8_t before[64];
    uint8_t after[64];
    uint32_t eflags = UINT32_C(0x8d7);
    uc_x86_msr msr = {.rid = IA32_PASID_MSR, .value = pasid};
    uc_engine *uc;

    setup_x86(&uc, UC_CPU_X86_APX, code, code_size);
    OK(uc_mem_map(uc, xsave_address, xsave_mapping_size, UC_PROT_ALL));
    memset(before, 0xa5, sizeof(before));
    source[0] = source_low;
    OK(uc_mem_write(uc, source_address, source, sizeof(source)));
    OK(uc_mem_write(uc, destination_address, before, sizeof(before)));
    OK(uc_reg_write(uc, UC_X86_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags));
    if (apx) {
        OK(uc_reg_write(uc, UC_X86_REG_R19, &source_address));
    } else {
        OK(uc_reg_write(uc, UC_X86_REG_RBX, &source_address));
    }
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &destination_address));

    OK(uc_emu_start(uc, code_address, code_address + code_size, 0, 1));
    OK(uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags));
    OK(uc_mem_read(uc, destination_address, after, sizeof(after)));
    TEST_CHECK((eflags & EFLAGS_ARITHMETIC_MASK) == EFLAGS_ZF);
    TEST_CHECK(memcmp(before, after, sizeof(before)) == 0);
    OK(uc_close(uc));
}

static void check_enqueue_exception(const uint8_t *code, size_t code_size,
                                    uint64_t source_low, uint64_t pasid,
                                    uint64_t destination_address)
{
    const uint64_t source_address = xsave_address;
    uint64_t source[8] = {0};
    uint64_t rip = 0;
    uc_x86_msr msr = {.rid = IA32_PASID_MSR, .value = pasid};
    uc_engine *uc;
    uc_err error;

    setup_x86(&uc, UC_CPU_X86_APX, code, code_size);
    OK(uc_mem_map(uc, xsave_address, xsave_mapping_size, UC_PROT_ALL));
    source[0] = source_low;
    OK(uc_mem_write(uc, source_address, source, sizeof(source)));
    OK(uc_reg_write(uc, UC_X86_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_X86_REG_R19, &source_address));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &destination_address));

    error = uc_emu_start(uc, code_address, code_address + code_size, 0, 1);
    TEST_CHECK(error == UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    TEST_CHECK(rip == code_address);
    OK(uc_close(uc));
}

static uint64_t enqueue_mmio_read(uc_engine *uc, uint64_t offset,
                                  unsigned size, void *user_data)
{
    (void)uc;
    (void)offset;
    (void)size;
    (void)user_data;
    return 0;
}

static void enqueue_mmio_write(uc_engine *uc, uint64_t offset,
                               unsigned size, uint64_t value,
                               void *user_data)
{
    (void)uc;
    (void)offset;
    (void)size;
    (void)value;
    ++*(unsigned *)user_data;
}

static void check_enqueue_fault_order_and_mmio(const uint8_t *code,
                                               size_t code_size)
{
    uint64_t source_address = xsave_address + 0xfe0;
    uint64_t destination_address = xsave_address + 0x80;
    uint8_t invalid_partial_source[32] = {1};
    uc_x86_msr msr = {
        .rid = IA32_PASID_MSR,
        .value = UINT64_C(0x80012345),
    };
    uc_engine *uc;
    uc_err error;

    /* The complete 64-byte source read precedes source-field validation. */
    setup_x86(&uc, UC_CPU_X86_APX, code, code_size);
    OK(uc_mem_map(uc, xsave_address, xsave_mapping_size, UC_PROT_ALL));
    OK(uc_mem_write(uc, source_address, invalid_partial_source,
                    sizeof(invalid_partial_source)));
    OK(uc_mem_unmap(uc, xsave_address + 0x1000, 0x1000));
    OK(uc_reg_write(uc, UC_X86_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_X86_REG_R19, &source_address));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &destination_address));
    error = uc_emu_start(uc, code_address, code_address + code_size, 0, 1);
    TEST_CHECK(error == UC_ERR_READ_UNMAPPED);
    OK(uc_close(uc));

    /* A generic MMIO mapping is not an enqueue portal and must not be called. */
    {
        uint64_t source[8] = {0};
        uint32_t eflags = UINT32_C(0x8d7);
        unsigned writes = 0;

        source_address = xsave_address;
        destination_address = xsave_address + 0x1000;
        setup_x86(&uc, UC_CPU_X86_APX, code, code_size);
        OK(uc_mem_map(uc, xsave_address, xsave_mapping_size, UC_PROT_ALL));
        OK(uc_mem_write(uc, source_address, source, sizeof(source)));
        OK(uc_mem_unmap(uc, destination_address, 0x1000));
        OK(uc_mmio_map(uc, destination_address, 0x1000,
                       enqueue_mmio_read, NULL, enqueue_mmio_write,
                       &writes));
        OK(uc_reg_write(uc, UC_X86_REG_MSR, &msr));
        OK(uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags));
        OK(uc_reg_write(uc, UC_X86_REG_R19, &source_address));
        OK(uc_reg_write(uc, UC_X86_REG_RCX, &destination_address));
        OK(uc_emu_start(uc, code_address, code_address + code_size, 0, 1));
        OK(uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags));
        TEST_CHECK(writes == 0);
        TEST_CHECK((eflags & EFLAGS_ARITHMETIC_MASK) == EFLAGS_ZF);
        OK(uc_close(uc));
    }
}

static void test_x86_apx_and_legacy_enqueue_ram_semantics(void)
{
    static const uint8_t apx_enqcmd[] = {
        0x62, 0xfc, 0x7f, 0x08, 0xf8, 0x0b,
    };
    static const uint8_t apx_enqcmds[] = {
        0x62, 0xfc, 0x7e, 0x08, 0xf8, 0x0b,
    };
    static const uint8_t legacy_enqcmd[] = {
        0xf2, 0x0f, 0x38, 0xf8, 0x0b,
    };
    static const uint8_t legacy_enqcmds[] = {
        0xf3, 0x0f, 0x38, 0xf8, 0x0b,
    };

    check_enqueue_ram_retry(apx_enqcmd, sizeof(apx_enqcmd), true, 0,
                            UINT64_C(0x80012345));
    check_enqueue_ram_retry(apx_enqcmds, sizeof(apx_enqcmds), true,
                            UINT64_C(0x80054321), 0);
    check_enqueue_ram_retry(legacy_enqcmd, sizeof(legacy_enqcmd), false, 0,
                            UINT64_C(0x800abcde));
    check_enqueue_ram_retry(legacy_enqcmds, sizeof(legacy_enqcmds), false,
                            UINT64_C(0x80013579), 0);

    check_enqueue_exception(apx_enqcmd, sizeof(apx_enqcmd), 0, 0,
                            xsave_address + 0x1000);
    check_enqueue_exception(apx_enqcmd, sizeof(apx_enqcmd), 1,
                            UINT64_C(0x80012345),
                            xsave_address + 0x1000);
    check_enqueue_exception(apx_enqcmd, sizeof(apx_enqcmd), 0,
                            UINT64_C(0x80012345),
                            xsave_address + 0x1001);
    check_enqueue_fault_order_and_mmio(apx_enqcmd, sizeof(apx_enqcmd));
}

static void test_x86_apx_msr_imm_semantics(void)
{
    static const uint8_t code[] = {
        /* wrmsrns 0xc0000103, r18 (W=0) */
        0x62, 0xff, 0x7e, 0x08, 0xf6, 0xc2, 0x03, 0x01, 0x00, 0xc0,
        /* rdmsr r17, 0xc0000103 (W=1; ignored R/R'/X bits) */
        0x62, 0x3f, 0xff, 0x08, 0xf6, 0xc1, 0x03, 0x01, 0x00, 0xc0,
    };
    const uint64_t source = UINT64_C(0x8877665544332211);
    const uint64_t destination_initial = UINT64_C(0x0123456789abcdef);
    const uint64_t rax_initial = UINT64_C(0x1111222233334444);
    const uint64_t rcx_initial = UINT64_C(0x5555666677778888);
    const uint64_t rdx_initial = UINT64_C(0x9999aaaabbbbcccc);
    uint64_t r17 = destination_initial;
    uint64_t r18 = source;
    uint64_t rax = rax_initial;
    uint64_t rcx = rcx_initial;
    uint64_t rdx = rdx_initial;
    uint64_t flags_before;
    uint64_t flags_after;
    uc_x86_msr msr = {.rid = IA32_TSC_AUX_MSR};
    uc_engine *uc;

    setup_x86(&uc, UC_CPU_X86_APX, code, sizeof(code));
    OK(uc_reg_write(uc, UC_X86_REG_R17, &r17));
    OK(uc_reg_write(uc, UC_X86_REG_R18, &r18));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_reg_write(uc, UC_X86_REG_RDX, &rdx));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &flags_before));

    OK(uc_emu_start(uc, code_address, code_address + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_R17, &r17));
    OK(uc_reg_read(uc, UC_X86_REG_R18, &r18));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_reg_read(uc, UC_X86_REG_RDX, &rdx));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &flags_after));
    OK(uc_reg_read(uc, UC_X86_REG_MSR, &msr));

    TEST_CHECK(r17 == source);
    TEST_CHECK(r18 == source);
    TEST_CHECK(rax == rax_initial);
    TEST_CHECK(rcx == rcx_initial);
    TEST_CHECK(rdx == rdx_initial);
    TEST_CHECK(flags_after == flags_before);
    TEST_CHECK(msr.value == source);
    OK(uc_close(uc));
}

static void test_x86_apx_msr_imm_faults_preserve_state(void)
{
    static const uint8_t unsupported_msr[] = {
        /* rdmsr r17, 0xdeadbeef */
        0x62, 0xff, 0xff, 0x08, 0xf6, 0xc1, 0xef, 0xbe, 0xad, 0xde,
    };
    static const uint8_t valid_msr[] = {
        /* rdmsr r17, 0xc0000103 */
        0x62, 0xff, 0xff, 0x08, 0xf6, 0xc1, 0x03, 0x01, 0x00, 0xc0,
    };
    const uint64_t destination_initial = UINT64_C(0x0123456789abcdef);
    const uint64_t rax_initial = UINT64_C(0x1111222233334444);
    const uint64_t rcx_initial = UINT64_C(0x5555666677778888);
    const uint64_t rdx_initial = UINT64_C(0x9999aaaabbbbcccc);
    uint64_t r17 = destination_initial;
    uint64_t rax = rax_initial;
    uint64_t rcx = rcx_initial;
    uint64_t rdx = rdx_initial;
    uint64_t rip = 0;
    uc_engine *uc;
    uc_err error;

    setup_x86(&uc, UC_CPU_X86_APX, unsupported_msr,
              sizeof(unsupported_msr));
    OK(uc_reg_write(uc, UC_X86_REG_R17, &r17));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_reg_write(uc, UC_X86_REG_RDX, &rdx));
    error = uc_emu_start(uc, code_address,
                         code_address + sizeof(unsupported_msr), 0, 0);
    TEST_CHECK(error == UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_X86_REG_R17, &r17));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_read(uc, UC_X86_REG_RCX, &rcx));
    OK(uc_reg_read(uc, UC_X86_REG_RDX, &rdx));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    TEST_CHECK(r17 == destination_initial);
    TEST_CHECK(rax == rax_initial);
    TEST_CHECK(rcx == rcx_initial);
    TEST_CHECK(rdx == rdx_initial);
    TEST_CHECK(rip == code_address);
    OK(uc_close(uc));

    setup_x86(&uc, UC_CPU_X86_HASWELL, valid_msr, sizeof(valid_msr));
    OK(uc_reg_write(uc, UC_X86_REG_R17, &r17));
    error = uc_emu_start(uc, code_address,
                         code_address + sizeof(valid_msr), 0, 0);
    TEST_CHECK(error == UC_ERR_INSN_INVALID);
    OK(uc_reg_read(uc, UC_X86_REG_R17, &r17));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    TEST_CHECK(r17 == destination_initial);
    TEST_CHECK(rip == code_address);
    OK(uc_close(uc));
}

static void test_x86_apx_msr_imm_requires_cpl0(void)
{
    static const uint8_t code[] = {
        0x48, 0x0f, 0x07, /* sysretq */
        /* rdmsr r17, 0xc0000103 */
        0x62, 0xff, 0xff, 0x08, 0xf6, 0xc1, 0x03, 0x01, 0x00, 0xc0,
    };
    const uint64_t user_rip = code_address + 3;
    const uint64_t destination_initial = UINT64_C(0x0123456789abcdef);
    uc_x86_msr efer = {.rid = UINT32_C(0xc0000080)};
    uc_x86_msr star = {
        .rid = UINT32_C(0xc0000081),
        .value = UINT64_C(0x0010) << 48,
    };
    uint64_t r17 = destination_initial;
    uint64_t r11 = 0;
    uint64_t rip = 0;
    uint16_t cs = 0;
    uc_engine *uc;
    uc_err error;

    setup_x86(&uc, UC_CPU_X86_APX, code, sizeof(code));
    OK(uc_reg_read(uc, UC_X86_REG_MSR, &efer));
    efer.value |= 1; /* IA32_EFER.SCE */
    OK(uc_reg_write(uc, UC_X86_REG_MSR, &efer));
    OK(uc_reg_write(uc, UC_X86_REG_MSR, &star));
    OK(uc_reg_read(uc, UC_X86_REG_RFLAGS, &r11));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &user_rip));
    OK(uc_reg_write(uc, UC_X86_REG_R11, &r11));
    OK(uc_reg_write(uc, UC_X86_REG_R17, &r17));

    error = uc_emu_start(uc, code_address, code_address + sizeof(code), 0,
                         0);
    TEST_CHECK(error == UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_X86_REG_R17, &r17));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    OK(uc_reg_read(uc, UC_X86_REG_CS, &cs));
    TEST_CHECK(r17 == destination_initial);
    TEST_CHECK(rip == user_rip);
    TEST_CHECK((cs & 3) == 3);
    OK(uc_close(uc));
}

static void check_user_msr_fails_closed(const uint8_t *code,
                                        size_t code_size)
{
    static const int registers[] = {
        UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R19, UC_X86_REG_R20,
        UC_X86_REG_R21, UC_X86_REG_R22, UC_X86_REG_R23, UC_X86_REG_R24,
    };
    uint64_t values[sizeof(registers) / sizeof(registers[0])];
    uint64_t rip = 0;
    uc_engine *uc;
    uc_err error;

    setup_x86(&uc, UC_CPU_X86_APX, code, code_size);
    for (size_t i = 0; i < sizeof(registers) / sizeof(registers[0]); ++i) {
        values[i] = UINT64_C(0x1020304050607080) + i;
        OK(uc_reg_write(uc, registers[i], &values[i]));
    }

    error = uc_emu_start(uc, code_address, code_address + code_size, 0, 0);
    TEST_CHECK(error == UC_ERR_INSN_INVALID);
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    TEST_CHECK(rip == code_address);
    for (size_t i = 0; i < sizeof(registers) / sizeof(registers[0]); ++i) {
        uint64_t actual = 0;

        OK(uc_reg_read(uc, registers[i], &actual));
        TEST_CHECK(actual == values[i]);
    }
    OK(uc_close(uc));
}

static void test_x86_user_msr_forms_fail_closed(void)
{
    static const uint8_t legacy_urdmsr[] = {
        0xf2, 0x45, 0x0f, 0x38, 0xf8, 0xd1,
    };
    static const uint8_t legacy_uwrmsr[] = {
        0xf3, 0x45, 0x0f, 0x38, 0xf8, 0xca,
    };
    static const uint8_t vex_urdmsr[] = {
        0xc4, 0x07, 0x7b, 0xf8, 0xc1, 0x00, 0x1b, 0x00, 0x00,
    };
    static const uint8_t vex_uwrmsr[] = {
        0xc4, 0x07, 0x7a, 0xf8, 0xc1, 0x01, 0x1b, 0x00, 0x00,
    };
    static const uint8_t evex_urdmsr_imm[] = {
        0x62, 0xff, 0x7f, 0x08, 0xf8, 0xc3, 0x00, 0x1b, 0x00, 0x00,
    };
    static const uint8_t evex_uwrmsr_imm[] = {
        0x62, 0xff, 0x7e, 0x08, 0xf8, 0xc4, 0x01, 0x1b, 0x00, 0x00,
    };
    static const uint8_t evex_urdmsr_reg[] = {
        0x62, 0xec, 0x7f, 0x08, 0xf8, 0xf5,
    };
    static const uint8_t evex_uwrmsr_reg[] = {
        0x62, 0xcc, 0x7e, 0x08, 0xf8, 0xf8,
    };

    check_user_msr_fails_closed(legacy_urdmsr, sizeof(legacy_urdmsr));
    check_user_msr_fails_closed(legacy_uwrmsr, sizeof(legacy_uwrmsr));
    check_user_msr_fails_closed(vex_urdmsr, sizeof(vex_urdmsr));
    check_user_msr_fails_closed(vex_uwrmsr, sizeof(vex_uwrmsr));
    check_user_msr_fails_closed(evex_urdmsr_imm,
                                sizeof(evex_urdmsr_imm));
    check_user_msr_fails_closed(evex_uwrmsr_imm,
                                sizeof(evex_uwrmsr_imm));
    check_user_msr_fails_closed(evex_urdmsr_reg,
                                sizeof(evex_urdmsr_reg));
    check_user_msr_fails_closed(evex_uwrmsr_reg,
                                sizeof(evex_uwrmsr_reg));
}

TEST_LIST = {
    {"test_x86_apx_cpuid_and_xstate_enumeration",
     test_x86_apx_cpuid_and_xstate_enumeration},
    {"test_x86_apx_execution_gate", test_x86_apx_execution_gate},
    {"test_x86_apx_xsave_xrstor_and_xinuse",
     test_x86_apx_xsave_xrstor_and_xinuse},
    {"test_x86_apx_and_legacy_invpcid_semantics",
     test_x86_apx_and_legacy_invpcid_semantics},
    {"test_x86_apx_and_legacy_enqueue_ram_semantics",
     test_x86_apx_and_legacy_enqueue_ram_semantics},
    {"test_x86_apx_msr_imm_semantics", test_x86_apx_msr_imm_semantics},
    {"test_x86_apx_msr_imm_faults_preserve_state",
     test_x86_apx_msr_imm_faults_preserve_state},
    {"test_x86_apx_msr_imm_requires_cpl0",
     test_x86_apx_msr_imm_requires_cpl0},
    {"test_x86_user_msr_forms_fail_closed",
     test_x86_user_msr_forms_fail_closed},
    {NULL, NULL},
};
