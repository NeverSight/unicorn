#ifndef TARGET_I386_APPROX_28_H
#define TARGET_I386_APPROX_28_H

#include <stdint.h>

uint32_t x86_approx_rcp28_f32(uint32_t argument, uint32_t *flags);
uint64_t x86_approx_rcp28_f64(uint64_t argument, uint32_t *flags);
uint32_t x86_approx_rsqrt28_f32(uint32_t argument, uint32_t *flags);
uint64_t x86_approx_rsqrt28_f64(uint64_t argument, uint32_t *flags);
uint32_t x86_approx_exp2_f32(uint32_t argument, uint32_t *flags);
uint64_t x86_approx_exp2_f64(uint64_t argument, uint32_t *flags);

#endif
