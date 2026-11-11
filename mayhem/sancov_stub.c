/* No-op SanCov callbacks (weak) so the non-libFuzzer binaries link when SANITIZER_FLAGS is empty. */
#include <stdint.h>

#define W __attribute__((weak))

W __thread uintptr_t __sancov_lowest_stack;
W void __sanitizer_cov_8bit_counters_init(char *start, char *stop) { (void)start; (void)stop; }
W void __sanitizer_cov_pcs_init(const uintptr_t *start, const uintptr_t *stop) { (void)start; (void)stop; }
W void __sanitizer_cov_trace_pc_indir(uintptr_t callee) { (void)callee; }
W void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) { (void)val; (void)cases; }
W void __sanitizer_cov_trace_div4(uint32_t val) { (void)val; }
W void __sanitizer_cov_trace_div8(uint64_t val) { (void)val; }
W void __sanitizer_cov_trace_gep(uintptr_t idx) { (void)idx; }
