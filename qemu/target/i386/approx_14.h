#ifndef TARGET_I386_APPROX_14_H
#define TARGET_I386_APPROX_14_H

#include <stdint.h>

uint32_t x86_approx_rcp14_f32(uint32_t mxcsr, uint32_t argument);
uint64_t x86_approx_rcp14_f64(uint32_t mxcsr, uint64_t argument);
uint32_t x86_approx_rsqrt14_f32(uint32_t mxcsr, uint32_t argument);
uint64_t x86_approx_rsqrt14_f64(uint32_t mxcsr, uint64_t argument);

#endif
