/*
 *  x86 misc helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "exec/ioport.h"

#include "uc_priv.h"
#include "tcg/tcg-apple-jit.h"

void helper_outb(CPUX86State *env, uint32_t port, uint32_t data)
{
// #ifdef UNICORN_ARCH_POSTFIX
//     glue(address_space_stb, UNICORN_ARCH_POSTFIX)(env->uc, &env->uc->address_space_io, port, data & 0xff,
// #else
//     address_space_stb(env->uc, &env->uc->address_space_io, port, data & 0xff,
// #endif
//                       cpu_get_mem_attrs(env), NULL);
    return cpu_outb(env->uc, port, data, GETPC());
}

target_ulong helper_inb(CPUX86State *env, uint32_t port)
{
// #ifdef UNICORN_ARCH_POSTFIX
//     return glue(address_space_ldub, UNICORN_ARCH_POSTFIX)(env->uc, &env->uc->address_space_io, port,
// #else
//     return address_space_ldub(env->uc, &env->uc->address_space_io, port,
// #endif
//                               cpu_get_mem_attrs(env), NULL);
    return cpu_inb(env->uc, port, GETPC());
}

void helper_outw(CPUX86State *env, uint32_t port, uint32_t data)
{
// #ifdef UNICORN_ARCH_POSTFIX
//     glue(address_space_stw, UNICORN_ARCH_POSTFIX)(env->uc, &env->uc->address_space_io, port, data & 0xffff,
// #else
//     address_space_stw(env->uc, &env->uc->address_space_io, port, data & 0xffff,
// #endif
//                       cpu_get_mem_attrs(env), NULL);
    return cpu_outw(env->uc, port, data, GETPC());
}

target_ulong helper_inw(CPUX86State *env, uint32_t port)
{
// #ifdef UNICORN_ARCH_POSTFIX
//     return glue(address_space_lduw, UNICORN_ARCH_POSTFIX)(env->uc, &env->uc->address_space_io, port,
// #else
//     return address_space_lduw(env->uc, &env->uc->address_space_io, port,
// #endif
//                               cpu_get_mem_attrs(env), NULL);
    return cpu_inw(env->uc, port, GETPC());
}

void helper_outl(CPUX86State *env, uint32_t port, uint32_t data)
{
// #ifdef UNICORN_ARCH_POSTFIX
//     glue(address_space_stl, UNICORN_ARCH_POSTFIX)(env->uc, &env->uc->address_space_io, port, data,
// #else
//     address_space_stl(env->uc, &env->uc->address_space_io, port, data,
// #endif
//                       cpu_get_mem_attrs(env), NULL);
    return cpu_outl(env->uc, port, data, GETPC());
}

target_ulong helper_inl(CPUX86State *env, uint32_t port)
{
// #ifdef UNICORN_ARCH_POSTFIX
//     return glue(address_space_ldl, UNICORN_ARCH_POSTFIX)(env->uc, &env->uc->address_space_io, port,
// #else
//     return address_space_ldl(env->uc, &env->uc->address_space_io, port,
// #endif
//                              cpu_get_mem_attrs(env), NULL);
    return cpu_inl(env->uc, port, GETPC());
}

void helper_into(CPUX86State *env, int next_eip_addend)
{
    int eflags;

    eflags = cpu_cc_compute_all(env, CC_OP);
    if (eflags & CC_O) {
        raise_interrupt(env, EXCP04_INTO, 1, 0, next_eip_addend);
    }
}

void helper_cpuid(CPUX86State *env)
{
    uint32_t eax, ebx, ecx, edx;
    uc_engine *uc = env->uc;
    struct hook *hook;
    int skip_cpuid = 0;
    bool synced = false;
    cpu_svm_check_intercept_param(env, SVM_EXIT_CPUID, 0, GETPC());

    // Unicorn: call registered CPUID hooks
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(env->uc, hook, UC_HOOK_INSN) {
        if (hook->to_delete)
            continue;
        if (!HOOK_BOUND_CHECK(hook, env->eip))
            continue;
        
        // Multiple cpuid callbacks returning different values is undefined.
        // true -> skip the cpuid instruction
        if (hook->insn == UC_X86_INS_CPUID) {
            uintptr_t pc = GETPC();
            if (!synced && !uc->skip_sync_pc_on_exit && pc) {
                cpu_restore_state(uc->cpu, pc, false);
                synced = true;
            }
            JIT_CALLBACK_GUARD_VAR(skip_cpuid, ((uc_cb_insn_cpuid_t)hook->callback)(env->uc, hook->user_data));
        }

        // the last callback may already asked to stop emulation
        if (env->uc->stop_request)
            break;
    }

    if (!skip_cpuid) {
        cpu_x86_cpuid(env, (uint32_t)env->regs[R_EAX], (uint32_t)env->regs[R_ECX],
                    &eax, &ebx, &ecx, &edx);
        env->regs[R_EAX] = eax;
        env->regs[R_EBX] = ebx;
        env->regs[R_ECX] = ecx;
        env->regs[R_EDX] = edx;
    }
    
}

target_ulong helper_read_crN(CPUX86State *env, int reg)
{
    target_ulong val;

    cpu_svm_check_intercept_param(env, SVM_EXIT_READ_CR0 + reg, 0, GETPC());
    switch (reg) {
    default:
        val = env->cr[reg];
        break;
    case 8:
        if (!(env->hflags2 & HF2_VINTR_MASK)) {
            // val = cpu_get_apic_tpr(env_archcpu(env)->apic_state);
            val = 0;
        } else {
            val = env->v_tpr;
        }
        break;
    }
    return val;
}

void helper_write_crN(CPUX86State *env, int reg, target_ulong t0)
{
    cpu_svm_check_intercept_param(env, SVM_EXIT_WRITE_CR0 + reg, 0, GETPC());
    switch (reg) {
    case 0:
        cpu_x86_update_cr0(env, (uint32_t)t0);
        break;
    case 3:
        cpu_x86_update_cr3(env, t0);
        break;
    case 4:
        cpu_x86_update_cr4(env, (uint32_t)t0);
        break;
    case 8:
#if 0
        if (!(env->hflags2 & HF2_VINTR_MASK)) {
            cpu_set_apic_tpr(env_archcpu(env)->apic_state, t0);
        }
#endif
        env->v_tpr = t0 & 0x0f;
        break;
    default:
        env->cr[reg] = t0;
        break;
    }
}

void helper_lmsw(CPUX86State *env, target_ulong t0)
{
    /* only 4 lower bits of CR0 are modified. PE cannot be set to zero
       if already set to one. */
    t0 = (env->cr[0] & ~0xe) | (t0 & 0xf);
    helper_write_crN(env, 0, t0);
}

void helper_invlpg(CPUX86State *env, target_ulong addr)
{
    X86CPU *cpu = env_archcpu(env);

    cpu_svm_check_intercept_param(env, SVM_EXIT_INVLPG, 0, GETPC());
    tlb_flush_page(CPU(cpu), addr);
}

void helper_rdtsc(CPUX86State *env)
{
    uint64_t val;
    uc_engine *uc = env->uc;
    struct hook *hook;
    int skip_rdtsc = 0;
    bool synced = false;

    if ((env->cr[4] & CR4_TSD_MASK) && ((env->hflags & HF_CPL_MASK) != 0)) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    cpu_svm_check_intercept_param(env, SVM_EXIT_RDTSC, 0, GETPC());

    // Unicorn: call registered RDTSC hooks
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(env->uc, hook, UC_HOOK_INSN) {
        if (hook->to_delete)
            continue;
        if (!HOOK_BOUND_CHECK(hook, env->eip))
            continue;
        
        // Multiple rdtsc callbacks returning different values is undefined.
        // true -> skip the rdtsc instruction
        if (hook->insn == UC_X86_INS_RDTSC) {
            uintptr_t pc = GETPC();
            if (!synced && !uc->skip_sync_pc_on_exit && pc) {
                cpu_restore_state(uc->cpu, pc, false);
                synced = true;
            }
            JIT_CALLBACK_GUARD_VAR(skip_rdtsc, ((uc_cb_insn_cpuid_t)hook->callback)(env->uc, hook->user_data));
        }

        // the last callback may already asked to stop emulation
        if (env->uc->stop_request)
            break;
    }

    if (!skip_rdtsc) {
        val = cpu_get_tsc(env) + env->tsc_offset;
        env->regs[R_EAX] = (uint32_t)(val);
        env->regs[R_EDX] = (uint32_t)(val >> 32);
    }
}

void helper_rdtscp(CPUX86State *env)
{
    uint64_t val;
    uc_engine *uc = env->uc;
    struct hook *hook;
    int skip_rdtscp = 0;
    bool synced = false;

    if ((env->cr[4] & CR4_TSD_MASK) && ((env->hflags & HF_CPL_MASK) != 0)) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    cpu_svm_check_intercept_param(env, SVM_EXIT_RDTSC, 0, GETPC());

    // Unicorn: call registered RDTSCP hooks
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(env->uc, hook, UC_HOOK_INSN) {
        if (hook->to_delete)
            continue;
        if (!HOOK_BOUND_CHECK(hook, env->eip))
            continue;
        
        // Multiple rdtscp callbacks returning different values is undefined.
        // true -> skip the rdtscp instruction
        if (hook->insn == UC_X86_INS_RDTSCP) {
            uintptr_t pc = GETPC();
            if (!synced && !uc->skip_sync_pc_on_exit && pc) {
                cpu_restore_state(uc->cpu, pc, false);
                synced = true;
            }
            JIT_CALLBACK_GUARD_VAR(skip_rdtscp, ((uc_cb_insn_cpuid_t)hook->callback)(env->uc, hook->user_data));
        }

        // the last callback may already asked to stop emulation
        if (env->uc->stop_request)
            break;
    }

    if (!skip_rdtscp) {
        val = cpu_get_tsc(env) + env->tsc_offset;
        env->regs[R_EAX] = (uint32_t)(val);
        env->regs[R_EDX] = (uint32_t)(val >> 32);

        env->regs[R_ECX] = (uint32_t)(env->tsc_aux);
    }
}

void helper_rdpmc(CPUX86State *env)
{
    if (!(env->cr[4] & CR4_PCE_MASK) &&
        ((env->hflags & HF_CPL_MASK) != 0)) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    cpu_svm_check_intercept_param(env, SVM_EXIT_RDPMC, 0, GETPC());

    /* CPUID.0AH advertises no architectural PMU, so every selector is
     * unsupported.  Fail closed instead of fabricating a counter value. */
    raise_exception_ra(env, EXCP0D_GPF, GETPC());
}

static void x86_msr_write(CPUX86State *env, uint32_t index, uint64_t val,
                          uintptr_t retaddr)
{
    cpu_svm_check_intercept_param(env, SVM_EXIT_MSR, 1, retaddr);

    switch (index) {
    case MSR_IA32_SYSENTER_CS:
        env->sysenter_cs = val & 0xffff;
        break;
    case MSR_IA32_SYSENTER_ESP:
        env->sysenter_esp = val;
        break;
    case MSR_IA32_SYSENTER_EIP:
        env->sysenter_eip = val;
        break;
    case MSR_IA32_APICBASE:
        // cpu_set_apic_base(env_archcpu(env)->apic_state, val);
        break;
    case MSR_EFER:
        {
            uint64_t update_mask;

            update_mask = 0;
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_SYSCALL) {
                update_mask |= MSR_EFER_SCE;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
                update_mask |= MSR_EFER_LME;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_FFXSR) {
                update_mask |= MSR_EFER_FFXSR;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_NX) {
                update_mask |= MSR_EFER_NXE;
            }
            if (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) {
                update_mask |= MSR_EFER_SVME;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_FFXSR) {
                update_mask |= MSR_EFER_FFXSR;
            }
            cpu_load_efer(env, (env->efer & ~update_mask) |
                          (val & update_mask));
        }
        break;
    case MSR_STAR:
        env->star = val;
        break;
    case MSR_PAT:
        env->pat = val;
        break;
    case MSR_VM_HSAVE_PA:
        env->vm_hsave = val;
        break;
#ifdef TARGET_X86_64
    case MSR_LSTAR:
        env->lstar = val;
        break;
    case MSR_CSTAR:
        env->cstar = val;
        break;
    case MSR_FMASK:
        env->fmask = val;
        break;
    case MSR_FSBASE:
        env->segs[R_FS].base = val;
        break;
    case MSR_GSBASE:
        env->segs[R_GS].base = val;
        break;
    case MSR_KERNELGSBASE:
        env->kernelgsbase = val;
        break;
#endif
    case MSR_MTRRphysBase(0):
    case MSR_MTRRphysBase(1):
    case MSR_MTRRphysBase(2):
    case MSR_MTRRphysBase(3):
    case MSR_MTRRphysBase(4):
    case MSR_MTRRphysBase(5):
    case MSR_MTRRphysBase(6):
    case MSR_MTRRphysBase(7):
        env->mtrr_var[(index - MSR_MTRRphysBase(0)) / 2].base = val;
        break;
    case MSR_MTRRphysMask(0):
    case MSR_MTRRphysMask(1):
    case MSR_MTRRphysMask(2):
    case MSR_MTRRphysMask(3):
    case MSR_MTRRphysMask(4):
    case MSR_MTRRphysMask(5):
    case MSR_MTRRphysMask(6):
    case MSR_MTRRphysMask(7):
        env->mtrr_var[(index - MSR_MTRRphysMask(0)) / 2].mask = val;
        break;
    case MSR_MTRRfix64K_00000:
        env->mtrr_fixed[index - MSR_MTRRfix64K_00000] = val;
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        env->mtrr_fixed[index - MSR_MTRRfix16K_80000 + 1] = val;
        break;
    case MSR_MTRRfix4K_C0000:
    case MSR_MTRRfix4K_C8000:
    case MSR_MTRRfix4K_D0000:
    case MSR_MTRRfix4K_D8000:
    case MSR_MTRRfix4K_E0000:
    case MSR_MTRRfix4K_E8000:
    case MSR_MTRRfix4K_F0000:
    case MSR_MTRRfix4K_F8000:
        env->mtrr_fixed[index - MSR_MTRRfix4K_C0000 + 3] = val;
        break;
    case MSR_MTRRdefType:
        env->mtrr_deftype = val;
        break;
    case MSR_MCG_STATUS:
        env->mcg_status = val;
        break;
    case MSR_MCG_CTL:
        if ((env->mcg_cap & MCG_CTL_P)
            && (val == 0 || val == ~(uint64_t)0)) {
            env->mcg_ctl = val;
        }
        break;
    case MSR_TSC_AUX:
        env->tsc_aux = val;
        break;
    case MSR_IA32_MISC_ENABLE:
        env->msr_ia32_misc_enable = val;
        break;
    case MSR_IA32_PASID:
        if (!(env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_ENQCMD) ||
            (val & ~UINT64_C(0x800fffff))) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, retaddr);
        }
        env->msr_ia32_pasid = val;
        break;
    case MSR_IA32_BNDCFGS:
        /* FIXME: #GP if reserved bits are set.  */
        /* FIXME: Extend highest implemented bit of linear address.  */
        env->msr_bndcfgs = val;
        cpu_sync_bndcs_hflags(env);
        break;
    default:
        if (index >= MSR_MC0_CTL
            && index < MSR_MC0_CTL +
            (4 * env->mcg_cap & 0xff)) {
            uint32_t offset = index - MSR_MC0_CTL;
            if ((offset & 0x3) != 0
                || (val == 0 || val == ~(uint64_t)0)) {
                env->mce_banks[offset] = val;
            }
            break;
        }
        raise_exception_err_ra(env, EXCP0D_GPF, 0, retaddr);
    }
}

void helper_wrmsr(CPUX86State *env)
{
    const uint64_t val = ((uint32_t)env->regs[R_EAX]) |
                         ((uint64_t)(uint32_t)env->regs[R_EDX] << 32);

    x86_msr_write(env, (uint32_t)env->regs[R_ECX], val, GETPC());
}

static uint64_t x86_msr_read(CPUX86State *env, uint32_t index,
                             uintptr_t retaddr)
{
    X86CPU *x86_cpu = env_archcpu(env);
    uint64_t val;

    cpu_svm_check_intercept_param(env, SVM_EXIT_MSR, 0, retaddr);

    switch (index) {
    case MSR_IA32_SYSENTER_CS:
        val = env->sysenter_cs;
        break;
    case MSR_IA32_SYSENTER_ESP:
        val = env->sysenter_esp;
        break;
    case MSR_IA32_SYSENTER_EIP:
        val = env->sysenter_eip;
        break;
    case MSR_IA32_APICBASE:
        val = 0; // cpu_get_apic_base(env_archcpu(env)->apic_state);
        break;
    case MSR_EFER:
        val = env->efer;
        break;
    case MSR_STAR:
        val = env->star;
        break;
    case MSR_PAT:
        val = env->pat;
        break;
    case MSR_VM_HSAVE_PA:
        val = env->vm_hsave;
        break;
    case MSR_IA32_PERF_STATUS:
        /* tsc_increment_by_tick */
        val = 1000ULL;
        /* CPU multiplier */
        val |= (((uint64_t)4ULL) << 40);
        break;
#ifdef TARGET_X86_64
    case MSR_LSTAR:
        val = env->lstar;
        break;
    case MSR_CSTAR:
        val = env->cstar;
        break;
    case MSR_FMASK:
        val = env->fmask;
        break;
    case MSR_FSBASE:
        val = env->segs[R_FS].base;
        break;
    case MSR_GSBASE:
        val = env->segs[R_GS].base;
        break;
    case MSR_KERNELGSBASE:
        val = env->kernelgsbase;
        break;
    case MSR_TSC_AUX:
        val = env->tsc_aux;
        break;
#endif
    case MSR_SMI_COUNT:
        val = env->msr_smi_count;
        break;
    case MSR_MTRRphysBase(0):
    case MSR_MTRRphysBase(1):
    case MSR_MTRRphysBase(2):
    case MSR_MTRRphysBase(3):
    case MSR_MTRRphysBase(4):
    case MSR_MTRRphysBase(5):
    case MSR_MTRRphysBase(6):
    case MSR_MTRRphysBase(7):
        val = env->mtrr_var[(index - MSR_MTRRphysBase(0)) / 2].base;
        break;
    case MSR_MTRRphysMask(0):
    case MSR_MTRRphysMask(1):
    case MSR_MTRRphysMask(2):
    case MSR_MTRRphysMask(3):
    case MSR_MTRRphysMask(4):
    case MSR_MTRRphysMask(5):
    case MSR_MTRRphysMask(6):
    case MSR_MTRRphysMask(7):
        val = env->mtrr_var[(index - MSR_MTRRphysMask(0)) / 2].mask;
        break;
    case MSR_MTRRfix64K_00000:
        val = env->mtrr_fixed[0];
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        val = env->mtrr_fixed[index - MSR_MTRRfix16K_80000 + 1];
        break;
    case MSR_MTRRfix4K_C0000:
    case MSR_MTRRfix4K_C8000:
    case MSR_MTRRfix4K_D0000:
    case MSR_MTRRfix4K_D8000:
    case MSR_MTRRfix4K_E0000:
    case MSR_MTRRfix4K_E8000:
    case MSR_MTRRfix4K_F0000:
    case MSR_MTRRfix4K_F8000:
        val = env->mtrr_fixed[index - MSR_MTRRfix4K_C0000 + 3];
        break;
    case MSR_MTRRdefType:
        val = env->mtrr_deftype;
        break;
    case MSR_MTRRcap:
        if (env->features[FEAT_1_EDX] & CPUID_MTRR) {
            val = MSR_MTRRcap_VCNT | MSR_MTRRcap_FIXRANGE_SUPPORT |
                MSR_MTRRcap_WC_SUPPORTED;
        } else {
            /* XXX: exception? */
            val = 0;
        }
        break;
    case MSR_MCG_CAP:
        val = env->mcg_cap;
        break;
    case MSR_MCG_CTL:
        if (env->mcg_cap & MCG_CTL_P) {
            val = env->mcg_ctl;
        } else {
            val = 0;
        }
        break;
    case MSR_MCG_STATUS:
        val = env->mcg_status;
        break;
    case MSR_IA32_MISC_ENABLE:
        val = env->msr_ia32_misc_enable;
        break;
    case MSR_IA32_PASID:
        if (!(env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_ENQCMD)) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, retaddr);
        }
        val = env->msr_ia32_pasid;
        break;
    case MSR_IA32_BNDCFGS:
        val = env->msr_bndcfgs;
        break;
     case MSR_IA32_UCODE_REV:
        val = x86_cpu->ucode_rev;
        break;
    default:
        if (index >= MSR_MC0_CTL
            && index < MSR_MC0_CTL +
            (4 * env->mcg_cap & 0xff)) {
            uint32_t offset = index - MSR_MC0_CTL;
            val = env->mce_banks[offset];
            break;
        }
        raise_exception_err_ra(env, EXCP0D_GPF, 0, retaddr);
    }
    return val;
}

void helper_rdmsr(CPUX86State *env)
{
    const uint64_t val =
        x86_msr_read(env, (uint32_t)env->regs[R_ECX], GETPC());

    env->regs[R_EAX] = (uint32_t)(val);
    env->regs[R_EDX] = (uint32_t)(val >> 32);
}

#ifdef TARGET_X86_64
uint64_t helper_apx_rdmsr_imm(CPUX86State *env, uint32_t index)
{
    return x86_msr_read(env, index, GETPC());
}

void helper_apx_wrmsr_imm(CPUX86State *env, uint32_t index, uint64_t value)
{
    x86_msr_write(env, index, value, GETPC());
}
#endif

static void do_pause(X86CPU *cpu)
{
    CPUState *cs = CPU(cpu);

    /* Just let another CPU run.  */
    cs->exception_index = EXCP_INTERRUPT;
    cpu_loop_exit(cs);
}

static void do_hlt(X86CPU *cpu)
{
    CPUState *cs = CPU(cpu);
    CPUX86State *env = &cpu->env;

    env->hflags &= ~HF_INHIBIT_IRQ_MASK; /* needed if sti is just before */
    cs->halted = 1;
    cs->exception_index = EXCP_HLT;
    cpu_loop_exit(cs);
}

void helper_hlt(CPUX86State *env, int next_eip_addend)
{
    X86CPU *cpu = env_archcpu(env);

    cpu_svm_check_intercept_param(env, SVM_EXIT_HLT, 0, GETPC());
    env->eip += next_eip_addend;

    do_hlt(cpu);
}

void helper_monitor(CPUX86State *env, target_ulong ptr)
{
    if ((uint32_t)env->regs[R_ECX] != 0) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    /* XXX: store address? */
    cpu_svm_check_intercept_param(env, SVM_EXIT_MONITOR, 0, GETPC());
}

void helper_mwait(CPUX86State *env, int next_eip_addend)
{
    CPUState *cs = env_cpu(env);
    X86CPU *cpu = env_archcpu(env);

    if ((uint32_t)env->regs[R_ECX] != 0) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }

    cpu_svm_check_intercept_param(env, SVM_EXIT_MWAIT, 0, GETPC());
    env->eip += next_eip_addend;

    /* XXX: not complete but not completely erroneous */
    // if (cs->cpu_index != 0 || CPU_NEXT(cs) != NULL) { // TODO
    if (cs->cpu_index != 0) {
        // do_pause(cpu);
    } else {
        do_hlt(cpu);
    }
}

void helper_pause(CPUX86State *env, int next_eip_addend)
{
    X86CPU *cpu = env_archcpu(env);

    cpu_svm_check_intercept_param(env, SVM_EXIT_PAUSE, 0, GETPC());
    env->eip += next_eip_addend;

    do_pause(cpu);
}

void helper_debug(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);

    cs->exception_index = EXCP_DEBUG;
    cpu_loop_exit(cs);
}

#ifdef TARGET_X86_64
void helper_apx_jmpabs(CPUX86State *env, uint64_t target)
{
    const int shift = (env->cr[4] & CR4_LA57_MASK) ? 56 : 47;
    const int64_t sign_extension = (int64_t)target >> shift;

    if (sign_extension != 0 && sign_extension != -1) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
    env->eip = target;
}

static uint64_t apx_scalar_width_mask(int width)
{
    return width == 8 ? UINT64_MAX : (UINT64_C(1) << (width * 8)) - 1;
}

static uint64_t apx_scalar_read_gpr(CPUX86State *env, int reg, int width)
{
    const uint64_t value = reg < 16 ? env->regs[reg]
                                    : env->apx_regs[reg - 16];

    return value & apx_scalar_width_mask(width);
}

static void apx_scalar_write_gpr(CPUX86State *env, int reg, int width,
                                 uint64_t value)
{
    uint64_t *slot = reg < 16 ? &env->regs[reg]
                              : &env->apx_regs[reg - 16];

    value &= apx_scalar_width_mask(width);
    if (width < 4) {
        const uint64_t mask = apx_scalar_width_mask(width);

        *slot = (*slot & ~mask) | value;
    } else {
        *slot = value;
    }
    if (reg >= 16) {
        env->xstate_bv |= XSTATE_APX_MASK;
    }
}

static int64_t apx_scalar_signed(uint64_t value, int width)
{
    switch (width) {
    case 1:
        return (int8_t)value;
    case 2:
        return (int16_t)value;
    case 4:
        return (int32_t)value;
    default:
        return (int64_t)value;
    }
}

static void apx_scalar_set_flag(uint32_t *flags, uint32_t mask, bool value)
{
    if (value) {
        *flags |= mask;
    } else {
        *flags &= ~mask;
    }
}

static uint32_t apx_scalar_szp_flags(uint32_t flags, uint64_t result,
                                     int width)
{
    const uint64_t mask = apx_scalar_width_mask(width);
    const uint64_t sign = UINT64_C(1) << (width * 8 - 1);

    result &= mask;
    flags &= ~(CC_S | CC_Z | CC_P);
    if (result & sign) {
        flags |= CC_S;
    }
    if (result == 0) {
        flags |= CC_Z;
    }
    flags |= parity_table[result & 0xff];
    return flags;
}

static uint64_t apx_scalar_pdep(uint64_t source, uint64_t mask, int width)
{
    uint64_t result = 0;
    unsigned int source_bit = 0;

    mask &= apx_scalar_width_mask(width);
    for (unsigned int bit = 0; bit < (unsigned int)width * 8; ++bit) {
        if ((mask >> bit) & 1) {
            result |= ((source >> source_bit) & 1) << bit;
            ++source_bit;
        }
    }
    return result;
}

static uint64_t apx_scalar_pext(uint64_t source, uint64_t mask, int width)
{
    uint64_t result = 0;
    unsigned int destination_bit = 0;

    mask &= apx_scalar_width_mask(width);
    for (unsigned int bit = 0; bit < (unsigned int)width * 8; ++bit) {
        if ((mask >> bit) & 1) {
            result |= ((source >> bit) & 1) << destination_bit;
            ++destination_bit;
        }
    }
    return result;
}

void helper_apx_scalar_reg(CPUX86State *env, uint32_t desc,
                           uint64_t immediate)
{
    const int dst = (desc >> APX_SCALAR_DST_SHIFT) & APX_SCALAR_REG_MASK;
    const int src1 = (desc >> APX_SCALAR_SRC1_SHIFT) & APX_SCALAR_REG_MASK;
    const int src2 = (desc >> APX_SCALAR_SRC2_SHIFT) & APX_SCALAR_REG_MASK;
    const int width = 1 << ((desc >> APX_SCALAR_WIDTH_SHIFT) & 3);
    const unsigned int bits = width * 8;
    const uint64_t width_mask = apx_scalar_width_mask(width);
    const uint64_t sign_mask = UINT64_C(1) << (bits - 1);
    const APXScalarOp operation =
        (desc >> APX_SCALAR_OP_SHIFT) & APX_SCALAR_OP_MASK;
    const bool no_flags = (desc & APX_SCALAR_NO_FLAGS) != 0;
    const uint64_t left = apx_scalar_read_gpr(env, src1, width);
    const uint64_t right = apx_scalar_read_gpr(env, src2, width);
    uint32_t flags = cpu_compute_eflags(env);
    uint64_t result = left;
    bool write_flags = false;

    switch (operation) {
    case APX_SCALAR_INC:
    case APX_SCALAR_DEC: {
        const bool decrement = operation == APX_SCALAR_DEC;

        result = (left + (decrement ? width_mask : 1)) & width_mask;
        if (!no_flags) {
            flags = apx_scalar_szp_flags(flags, result, width);
            apx_scalar_set_flag(&flags, CC_A,
                                ((left ^ UINT64_C(1) ^ result) & 0x10) != 0);
            apx_scalar_set_flag(&flags, CC_O,
                                decrement ? left == sign_mask
                                          : left == sign_mask - 1);
            write_flags = true;
        }
        break;
    }
    case APX_SCALAR_NOT:
        result = ~left & width_mask;
        break;
    case APX_SCALAR_NEG:
        result = (UINT64_C(0) - left) & width_mask;
        if (!no_flags) {
            flags = apx_scalar_szp_flags(flags, result, width);
            apx_scalar_set_flag(&flags, CC_C, left != 0);
            apx_scalar_set_flag(&flags, CC_A,
                                ((left ^ result) & 0x10) != 0);
            apx_scalar_set_flag(&flags, CC_O, left == sign_mask);
            write_flags = true;
        }
        break;
    case APX_SCALAR_ROL:
    case APX_SCALAR_ROR: {
        unsigned int count = (desc & APX_SCALAR_COUNT_CL)
                                 ? env->regs[R_ECX] & 0xff
                                 : (unsigned int)immediate;

        count &= width == 8 ? 63 : 31;
        count %= bits;
        if (count != 0) {
            if (operation == APX_SCALAR_ROL) {
                result = ((left << count) | (left >> (bits - count))) &
                         width_mask;
                if (!no_flags) {
                    const bool carry = result & 1;

                    apx_scalar_set_flag(&flags, CC_C, carry);
                    if (count == 1) {
                        apx_scalar_set_flag(&flags, CC_O,
                                            ((result & sign_mask) != 0) ^
                                                carry);
                    }
                }
            } else {
                result = (left >> count) |
                         ((left << (bits - count)) & width_mask);
                if (!no_flags) {
                    apx_scalar_set_flag(&flags, CC_C,
                                        (result & sign_mask) != 0);
                    if (count == 1) {
                        apx_scalar_set_flag(
                            &flags, CC_O,
                            ((result >> (bits - 1)) ^
                             (result >> (bits - 2))) & 1);
                    }
                }
            }
            write_flags = !no_flags;
        }
        break;
    }
    case APX_SCALAR_RCL:
    case APX_SCALAR_RCR: {
        unsigned int count = (desc & APX_SCALAR_COUNT_CL)
                                 ? env->regs[R_ECX] & 0xff
                                 : (unsigned int)immediate;
        const unsigned int extended_bits = bits + 1;
        __uint128_t extended = ((__uint128_t)left << 1) |
                               ((flags & CC_C) != 0);
        __uint128_t extended_mask = ((__uint128_t)1 << extended_bits) - 1;

        count &= width == 8 ? 63 : 31;
        if (width < 4) {
            count %= extended_bits;
        }
        if (count != 0) {
            if (operation == APX_SCALAR_RCL) {
                extended = ((extended << count) |
                            (extended >> (extended_bits - count))) &
                           extended_mask;
            } else {
                extended = (extended >> count) |
                           ((extended << (extended_bits - count)) &
                            extended_mask);
            }
            result = (uint64_t)(extended >> 1) & width_mask;
            if (!no_flags) {
                const bool carry = extended & 1;

                apx_scalar_set_flag(&flags, CC_C, carry);
                if (count == 1) {
                    if (operation == APX_SCALAR_RCL) {
                        apx_scalar_set_flag(&flags, CC_O,
                                            ((result & sign_mask) != 0) ^
                                                carry);
                    } else {
                        apx_scalar_set_flag(
                            &flags, CC_O,
                            ((result >> (bits - 1)) ^
                             (result >> (bits - 2))) & 1);
                    }
                }
                write_flags = true;
            }
        }
        break;
    }
    case APX_SCALAR_SHL:
    case APX_SCALAR_SHR:
    case APX_SCALAR_SAR: {
        unsigned int count = (desc & APX_SCALAR_COUNT_CL)
                                 ? env->regs[R_ECX] & 0xff
                                 : (unsigned int)immediate;

        count &= width == 8 ? 63 : 31;
        if (count != 0) {
            bool carry = (flags & CC_C) != 0;

            if (operation == APX_SCALAR_SHL) {
                if (count <= bits) {
                    carry = (left >> (bits - count)) & 1;
                }
                result = count >= bits ? 0 : (left << count) & width_mask;
                if (!no_flags && count == 1) {
                    apx_scalar_set_flag(&flags, CC_O,
                                        ((result & sign_mask) != 0) ^ carry);
                }
            } else if (operation == APX_SCALAR_SHR) {
                if (count <= bits) {
                    carry = (left >> (count - 1)) & 1;
                }
                result = count >= bits ? 0 : left >> count;
                if (!no_flags && count == 1) {
                    apx_scalar_set_flag(&flags, CC_O,
                                        (left & sign_mask) != 0);
                }
            } else {
                if (count <= bits) {
                    carry = (left >> (count - 1)) & 1;
                }
                result = count >= bits
                             ? (left & sign_mask ? width_mask : 0)
                             : (uint64_t)(apx_scalar_signed(left, width) >>
                                          count) &
                                   width_mask;
                if (!no_flags && count == 1) {
                    apx_scalar_set_flag(&flags, CC_O, false);
                }
            }
            if (!no_flags) {
                if (count <= bits) {
                    apx_scalar_set_flag(&flags, CC_C, carry);
                }
                flags = apx_scalar_szp_flags(flags, result, width);
                write_flags = true;
            }
        }
        break;
    }
    case APX_SCALAR_SHLD:
    case APX_SCALAR_SHRD: {
        unsigned int count = (desc & APX_SCALAR_COUNT_CL)
                                 ? env->regs[R_ECX] & 0xff
                                 : (unsigned int)immediate;

        count &= width == 8 ? 63 : 31;
        if (count != 0 && count <= bits) {
            const bool old_sign = (left & sign_mask) != 0;
            bool carry;

            if (operation == APX_SCALAR_SHLD) {
                carry = (left >> (bits - count)) & 1;
                result = ((left << count) | (right >> (bits - count))) &
                         width_mask;
            } else {
                carry = (left >> (count - 1)) & 1;
                result = (left >> count) |
                         ((right << (bits - count)) & width_mask);
            }
            if (!no_flags) {
                apx_scalar_set_flag(&flags, CC_C, carry);
                flags = apx_scalar_szp_flags(flags, result, width);
                if (count == 1) {
                    apx_scalar_set_flag(
                        &flags, CC_O,
                        operation == APX_SCALAR_SHLD
                            ? ((result & sign_mask) != 0) ^ carry
                            : old_sign ^ ((result & sign_mask) != 0));
                }
                write_flags = true;
            }
        }
        break;
    }
    case APX_SCALAR_IMUL: {
        bool overflow;

        if (width == 8) {
            const __int128 product = (__int128)(int64_t)left *
                                     (__int128)(int64_t)right;

            result = (uint64_t)product;
            overflow = product != (__int128)(int64_t)result;
        } else {
            const int64_t product = apx_scalar_signed(left, width) *
                                    apx_scalar_signed(right, width);

            result = (uint64_t)product & width_mask;
            overflow = product != apx_scalar_signed(result, width);
        }
        if (!no_flags) {
            apx_scalar_set_flag(&flags, CC_C, overflow);
            apx_scalar_set_flag(&flags, CC_O, overflow);
            write_flags = true;
        }
        break;
    }
    case APX_SCALAR_ADCX:
    case APX_SCALAR_ADOX: {
        const uint32_t chain_flag = operation == APX_SCALAR_ADCX ? CC_C : CC_O;
        const uint64_t carry = (flags & chain_flag) != 0;
        const __uint128_t sum = (__uint128_t)left + right + carry;

        result = (uint64_t)sum & width_mask;
        apx_scalar_set_flag(&flags, chain_flag, (sum >> bits) != 0);
        write_flags = true;
        break;
    }
    case APX_SCALAR_ANDN:
        result = ~left & right & width_mask;
        if (!no_flags) {
            flags = apx_scalar_szp_flags(flags, result, width);
            apx_scalar_set_flag(&flags, CC_C, false);
            apx_scalar_set_flag(&flags, CC_O, false);
            write_flags = true;
        }
        break;
    case APX_SCALAR_BEXTR: {
        const unsigned int start = left & 0xff;
        const unsigned int length = (left >> 8) & 0xff;

        result = start >= bits ? 0 : right >> start;
        if (length < bits && length < 64) {
            result &= length == 0 ? 0 : (UINT64_C(1) << length) - 1;
        }
        if (!no_flags) {
            apx_scalar_set_flag(&flags, CC_C, false);
            apx_scalar_set_flag(&flags, CC_O, false);
            apx_scalar_set_flag(&flags, CC_Z, result == 0);
            write_flags = true;
        }
        break;
    }
    case APX_SCALAR_BLSR:
        result = right & (right - 1);
        goto bls_flags;
    case APX_SCALAR_BLSMSK:
        result = right ^ (right - 1);
        goto bls_flags;
    case APX_SCALAR_BLSI:
        result = right & (UINT64_C(0) - right);
    bls_flags:
        result &= width_mask;
        if (!no_flags) {
            flags = apx_scalar_szp_flags(flags, result, width);
            if (operation == APX_SCALAR_BLSI) {
                apx_scalar_set_flag(&flags, CC_C, right != 0);
            } else {
                apx_scalar_set_flag(&flags, CC_C, right == 0);
            }
            apx_scalar_set_flag(&flags, CC_O, false);
            write_flags = true;
        }
        break;
    case APX_SCALAR_BZHI: {
        const unsigned int index = left & 0xff;

        result = index >= bits
                     ? right
                     : index == 0 ? 0
                                  : right & ((UINT64_C(1) << index) - 1);
        if (!no_flags) {
            flags = apx_scalar_szp_flags(flags, result, width);
            apx_scalar_set_flag(&flags, CC_C, index >= bits);
            apx_scalar_set_flag(&flags, CC_O, false);
            write_flags = true;
        }
        break;
    }
    case APX_SCALAR_PDEP:
        result = apx_scalar_pdep(left, right, width);
        break;
    case APX_SCALAR_PEXT:
        result = apx_scalar_pext(left, right, width);
        break;
    case APX_SCALAR_SARX: {
        const unsigned int count = left & (bits - 1);

        result = (uint64_t)(apx_scalar_signed(right, width) >> count) &
                 width_mask;
        break;
    }
    case APX_SCALAR_SHLX:
        result = (right << (left & (bits - 1))) & width_mask;
        break;
    case APX_SCALAR_SHRX:
        result = right >> (left & (bits - 1));
        break;
    case APX_SCALAR_RORX: {
        const unsigned int count = immediate & (bits - 1);

        result = count == 0
                     ? right
                     : (right >> count) |
                           ((right << (bits - count)) & width_mask);
        break;
    }
    case APX_SCALAR_LZCNT:
    case APX_SCALAR_TZCNT:
    case APX_SCALAR_POPCNT: {
        if (operation == APX_SCALAR_LZCNT) {
            result = right == 0 ? bits
                                : width == 8 ? clz64(right)
                                             : clz32(right) - (32 - bits);
        } else if (operation == APX_SCALAR_TZCNT) {
            result = right == 0 ? bits
                                : width == 8 ? ctz64(right) : ctz32(right);
        } else {
            result = ctpop64(right);
        }
        if (!no_flags) {
            if (operation == APX_SCALAR_POPCNT) {
                flags &= ~(CC_C | CC_P | CC_A | CC_Z | CC_S | CC_O);
                if (result == 0) {
                    flags |= CC_Z;
                }
            } else {
                apx_scalar_set_flag(&flags, CC_C, right == 0);
                apx_scalar_set_flag(&flags, CC_Z, result == 0);
                apx_scalar_set_flag(&flags, CC_S, false);
                apx_scalar_set_flag(&flags, CC_O, false);
            }
            write_flags = true;
        }
        break;
    }
    case APX_SCALAR_MULX: {
        const uint64_t multiplier = apx_scalar_read_gpr(env, R_EDX, width);

        if (width == 8) {
            const __uint128_t product = (__uint128_t)multiplier * right;

            apx_scalar_write_gpr(env, src1, width, (uint64_t)product);
            result = (uint64_t)(product >> 64);
        } else {
            const uint64_t product = multiplier * right;

            apx_scalar_write_gpr(env, src1, width, product);
            result = product >> bits;
        }
        break;
    }
    default:
        g_assert_not_reached();
    }

    apx_scalar_write_gpr(env, dst, width, result);
    if (write_flags) {
        cpu_load_eflags(env, flags, CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    }
}
#endif

uint64_t helper_rdpkru(CPUX86State *env, uint32_t ecx)
{
    if ((env->cr[4] & CR4_PKE_MASK) == 0) {
        raise_exception_err_ra(env, EXCP06_ILLOP, 0, GETPC());
    }
    if (ecx != 0) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }

    return env->pkru;
}

void helper_wrpkru(CPUX86State *env, uint32_t ecx, uint64_t val)
{
    CPUState *cs = env_cpu(env);

    if ((env->cr[4] & CR4_PKE_MASK) == 0) {
        raise_exception_err_ra(env, EXCP06_ILLOP, 0, GETPC());
    }
    if (ecx != 0 || (val & 0xFFFFFFFF00000000ull)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }

    env->pkru = val;
    tlb_flush(cs);
}
