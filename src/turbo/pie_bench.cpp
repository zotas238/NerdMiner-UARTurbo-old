//PIE (ESP32-S3 128-bit SIMD) feasibility for a 4-lane software SHA-256: semantics checks and cycle
//costs of the two primitives SHA-256 needs that PIE lacks: a wrapping 32-bit add and a 32-bit rotate.
//Runs with interrupts off on the calling core; results go out as one "b ..." line.
#include <Arduino.h>
#include "pie_bench.h"

static uint32_t A[4] __attribute__((aligned(16))) = {0x7fffffff, 0x80000000, 0xffffffff, 0x12345678};
static uint32_t B[4] __attribute__((aligned(16))) = {0x00000001, 0xffffffff, 0x00000001, 0x9abcdef0};
static uint32_t M16[4] __attribute__((aligned(16))) = {0xffff, 0xffff, 0xffff, 0xffff};
static uint32_t M25[4] __attribute__((aligned(16))) = {0x1ffffff, 0x1ffffff, 0x1ffffff, 0x1ffffff};
static uint32_t R[4] __attribute__((aligned(16)));

static inline uint32_t cc()
{
  uint32_t c;
  asm volatile("rsr %0, ccount" : "=a"(c));
  return c;
}

#define LD(q, p) asm volatile("ee.vld.128.ip " q ", %0, 0" : : "a"(p) : "memory")
#define ST(q, p) asm volatile("ee.vst.128.ip " q ", %0, 0" : : "a"(p) : "memory")

// 4-lane wrapping add q0 = q0 + q1 (q7 = 0xffff per lane), using 16-bit limbs so the saturating
// adder never saturates; arithmetic or logical vsr both handled by the masks
#define VADD_WRAP \
  "ee.andq q2, q0, q7\n" "ee.andq q3, q1, q7\n" "ee.vadds.s32 q2, q2, q3\n" \
  "ssai 16\n" "ee.vsr.32 q4, q0\n" "ee.vsr.32 q5, q1\n" "ee.andq q4, q4, q7\n" "ee.andq q5, q5, q7\n" \
  "ee.vadds.s32 q4, q4, q5\n" "ee.vsr.32 q6, q2\n" "ee.vadds.s32 q4, q4, q6\n" "ee.vsl.32 q4, q4\n" \
  "ee.andq q2, q2, q7\n" "ee.orq q0, q4, q2\n"

String pie_bench()
{
  char out[400];
  uint32_t sat[4], sr[4], sl[4], wrap[4];
  const uint32_t irq = XTOS_SET_INTLEVEL(XCHAL_EXCM_LEVEL);

  // 1. does ee.vadds.s32 saturate?
  LD("q0", A); LD("q1", B);
  asm volatile("ee.vadds.s32 q2, q0, q1" ::: "memory");
  ST("q2", R); memcpy(sat, R, 16);
  // 2. ee.vsr.32 with SAR = 4: arithmetic or logical?
  asm volatile("ssai 4\n" "ee.vsr.32 q2, q0" ::: "memory");
  ST("q2", R); memcpy(sr, R, 16);
  // 3. ee.vsl.32 with SAR = 4: left by 4 or by 28?
  asm volatile("ee.vsl.32 q2, q0" ::: "memory");
  ST("q2", R); memcpy(sl, R, 16);
  // 4. the emulated wrapping add, checked against C
  LD("q0", A); LD("q1", B); LD("q7", M16);
  asm volatile(VADD_WRAP ::: "memory");
  ST("q0", R); memcpy(wrap, R, 16);
  bool wrap_ok = true;
  for (int i = 0; i < 4; ++i) wrap_ok &= wrap[i] == A[i] + B[i];

  // 5. cycles: 256 chained 4-lane wrapping adds
  LD("q0", A); LD("q1", B); LD("q7", M16);
  int n = 256;
  uint32_t t0 = cc();
  asm volatile("loop %0, 1f\n" VADD_WRAP "1:\n" : "+a"(n) : : "memory");
  const uint32_t c_vadd = cc() - t0;

  // 6. cycles: 256 chained 4-lane rotr by 7 (vsr 7, mask, vsl 25, or)
  LD("q0", A); LD("q6", M25);
  n = 256;
  t0 = cc();
  asm volatile("loop %0, 1f\n"
               "ssai 7\n" "ee.vsr.32 q2, q0\n" "ee.andq q2, q2, q6\n"
               "ssai 25\n" "ee.vsl.32 q3, q0\n" "ee.orq q0, q2, q3\n"
               "1:\n" : "+a"(n) : : "memory");
  const uint32_t c_vrot = cc() - t0;

  // 7. scalar reference: 256 x 4 chained adds, 256 x 4 chained rotr 7 (ssai + src)
  uint32_t x0 = 1, x1 = 2, x2 = 3, x3 = 4, y = 0x9e3779b9;
  n = 256;
  t0 = cc();
  asm volatile("loop %4, 1f\n" "add %0, %0, %5\n" "add %1, %1, %5\n" "add %2, %2, %5\n" "add %3, %3, %5\n" "1:\n"
               : "+a"(x0), "+a"(x1), "+a"(x2), "+a"(x3), "+a"(n) : "a"(y));
  const uint32_t c_sadd = cc() - t0;
  n = 256;
  t0 = cc();
  asm volatile("loop %4, 1f\n" "ssai 7\n" "src %0, %0, %0\n" "src %1, %1, %1\n" "src %2, %2, %2\n" "src %3, %3, %3\n" "1:\n"
               : "+a"(x0), "+a"(x1), "+a"(x2), "+a"(x3), "+a"(n));
  const uint32_t c_srot = cc() - t0;

  XTOS_RESTORE_INTLEVEL(irq);
  snprintf(out, sizeof(out),
           "b sat=%08x,%08x,%08x,%08x vsr4=%08x,%08x vsl4=%08x,%08x wrap_ok=%d "
           "vadd4=%u vrot4=%u sadd4=%u srot4=%u (cycles per 256, 4 lanes each) chk=%08x",
           sat[0], sat[1], sat[2], sat[3], sr[0], sr[1], sl[0], sl[1], wrap_ok ? 1 : 0,
           (unsigned)c_vadd, (unsigned)c_vrot, (unsigned)c_sadd, (unsigned)c_srot, (unsigned)(x0 ^ x1 ^ x2 ^ x3));
  return String(out);
}
