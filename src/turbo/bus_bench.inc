
//---------------------------------------------------------------------------------
//Bus benchmark (relay U): what the SHA register accesses cost, and whether turning off
//SENSITIVE_APB_PERIPHERAL_ACCESS_SPLIT_BURST (default on: 128-bit accesses to peripherals
//are split into single transfers) makes the PIE digest moves and the t5 loop faster.
//Holds the SHA engine (the HW miner waits for it), interrupts off on this core while timing.
#include <soc/gpio_reg.h>

#define BB_N 32
#define BB_MEASURE(var, body) do { uint32_t _best = 0xFFFFFFFF; \
    for (int _k = 0; _k < BB_N; ++_k) { const uint32_t _c0 = CCOUNT(); body; const uint32_t _d = CCOUNT() - _c0; \
      if (_d < _best) _best = _d; } var = _best; } while (0)

static uint32_t s_bb_sram[16] __attribute__((aligned(16)));
static volatile uint32_t s_bb_sink;

//bb_split, s_split0, s_sb: defined before t5_job in turbo_hw.cpp

//8 scalar loads from base (the value is used so the timing includes the data arriving)
static inline __attribute__((always_inline)) uint32_t bb_r32(const uint32_t *b)
{
  uint32_t a0, a1, a2, a3, a4, a5, a6, a7;
  asm volatile("l32i %0, %8, 0\n l32i %1, %8, 4\n l32i %2, %8, 8\n l32i %3, %8, 12\n"
               "l32i %4, %8, 16\n l32i %5, %8, 20\n l32i %6, %8, 24\n l32i %7, %8, 28\n"
               : "=&r"(a0), "=&r"(a1), "=&r"(a2), "=&r"(a3), "=&r"(a4), "=&r"(a5), "=&r"(a6), "=&r"(a7)
               : "r"(b) : "memory");
  return a0 ^ a1 ^ a2 ^ a3 ^ a4 ^ a5 ^ a6 ^ a7;
}
//2 x 128-bit PIE loads, then a lane of the second moved to a register
static inline __attribute__((always_inline)) uint32_t bb_rv(const uint32_t *b)
{
  uint32_t r;
  const uint32_t *p = b;
  asm volatile("ee.vld.128.ip q0, %1, 16\n ee.vld.128.ip q1, %1, 16\n ee.movi.32.a q1, %0, 3\n"
               : "=r"(r), "+r"(p) :: "memory");
  return r;
}
static inline __attribute__((always_inline)) void bb_w32(uint32_t *b, uint32_t v)
{
  asm volatile("s32i %1, %0, 0\n s32i %1, %0, 4\n s32i %1, %0, 8\n s32i %1, %0, 12\n"
               "s32i %1, %0, 16\n s32i %1, %0, 20\n s32i %1, %0, 24\n s32i %1, %0, 28\n memw\n"
               :: "r"(b), "r"(v) : "memory");
}
static inline __attribute__((always_inline)) void bb_wv(uint32_t *b)
{
  uint32_t *p = b;
  asm volatile("ee.vst.128.ip q0, %0, 16\n ee.vst.128.ip q1, %0, 16\n memw\n" : "+r"(p) :: "memory");
}

struct BbMicro { uint32_t r32, rv, w32, wv; };

static IRAM_ATTR BbMicro bb_micro_sha()
{
  uint32_t * const rb = (uint32_t *)DR_REG_SHA_BASE;
  BbMicro m;
  uint32_t acc = 0;
  BB_MEASURE(m.r32, acc ^= bb_r32(rb + (0x40 >> 2)));
  BB_MEASURE(m.rv, acc ^= bb_rv(rb + (0x40 >> 2)));
  BB_MEASURE(m.w32, bb_w32(rb + (0x80 >> 2), acc));
  BB_MEASURE(m.wv, bb_wv(rb + (0x80 >> 2)));
  s_bb_sink = acc;
  return m;
}

//t5 cycles per nonce (tenths, CCOUNT, interrupts off) over n nonces, and optionally its profile
static IRAM_ATTR uint32_t bb_t5_cpn(uint32_t n, bool prof, uint32_t *prof_out)
{
  uint8_t hdr[128];
  test_header(hdr, 9);
  uint32_t mid[8], w[16];
  memcpy(w, hdr + 64, sizeof(w));
  JobResult r;
  r.difficulty = 1e30;
  Ctx cx = {&r, hdr, false};
  volatile uint8_t job = 0;
  uint32_t saved[12];
  memcpy(saved, s_prof, sizeof(saved));
  memset(s_prof, 0, sizeof(s_prof));
  hw_midstate(hdr, mid);
  portDISABLE_INTERRUPTS();
  const uint32_t c0 = CCOUNT();
  const uint32_t done = prof ? t5_prof(mid, w, 0, n, 0, &job, &cx, nullptr, nullptr)
                             : t5_run(mid, w, 0, n, 0, &job, &cx, nullptr, nullptr);
  const uint32_t cyc = CCOUNT() - c0;
  portENABLE_INTERRUPTS();
  if (prof_out)
    for (int k = 0; k < 12; ++k) prof_out[k] = done ? (s_prof[k] * 10 + done / 2) / done : 0;
  memcpy(s_prof, saved, sizeof(saved));
  if (cx.bad || !done) return 0xFFFFFFFF;
  return (uint32_t)(((uint64_t)cyc * 10 + done / 2) / done);
}

//t5 digests computed with split-burst at `split`, checked against mbedTLS (computed with
//the default setting). Returns mismatches.
static uint32_t bb_check(uint32_t split, int rounds)
{
  static uint32_t out1[256][8];
  static uint32_t out7[256];
  uint32_t bad = 0;
  for (int rd = 0; rd < rounds; ++rd)
    for (uint32_t seed = 0; seed < 2; ++seed)
    {
      uint8_t hdr[128];
      test_header(hdr, seed + 5 + rd * 2);
      uint32_t mid[8], w[16];
      memcpy(w, hdr + 64, sizeof(w));
      const uint32_t n0 = seed ? 0xFFFFFE00 : 0x8765 + rd * 977;
      esp_sha_acquire_hardware();
      hw_midstate(hdr, mid);
      bb_split(split);
      t5_all(mid, w, n0, n0 + 256, 0, nullptr, nullptr, out1, out7);
      bb_split(1);
      esp_sha_release_hardware();
      for (uint32_t k = 0; k < 256; ++k)
      {
        uint8_t b[80], h1[32], want[32];
        memcpy(b, hdr, 80);
        const uint32_t nonce = n0 + k;
        memcpy(b + 76, &nonce, 4);
        mbedtls_sha256_ret(b, 80, h1, 0);
        mbedtls_sha256_ret(h1, 32, want, 0);
        uint32_t w7;
        memcpy(&w7, want + 28, 4);
        if (memcmp(h1, out1[k], 32) != 0 || w7 != out7[k]) bad++;
      }
    }
  return bad;
}

int turbo_bus_bench(char *buf, size_t len)
{
  if (s_mode != MODE_T5) return snprintf(buf, len, "bus engine=%s (needs t5)", turbo_hw_mode_name());
  const uint32_t split_boot = REG_READ(SENSITIVE_APB_PERIPHERAL_ACCESS_1_REG);
  uint32_t mhz;
  {
    const int64_t t0 = esp_timer_get_time();
    const uint32_t cc0 = CCOUNT();
    while (esp_timer_get_time() - t0 < 2000) {}
    mhz = (CCOUNT() - cc0 + 1000) / 2000;
  }
  esp_sha_acquire_hardware();
  uint32_t ovh, sram_r, sram_rv, gpio_r;
  BbMicro s1, s0;
  {
    uint32_t acc = 0;
    portDISABLE_INTERRUPTS();
    BB_MEASURE(ovh, (void)0);
    BB_MEASURE(sram_r, acc ^= bb_r32(s_bb_sram));
    BB_MEASURE(sram_rv, acc ^= bb_rv(s_bb_sram));
    BB_MEASURE(gpio_r, acc ^= bb_r32((const uint32_t *)GPIO_OUT_REG));
    s1 = bb_micro_sha();
    bb_split(0);
    s0 = bb_micro_sha();
    bb_split(1);
    portENABLE_INTERRUPTS();
    s_bb_sink = acc;
  }
  //full loop: alternate split on/off, best of 3 each, then one profiled run each
  uint32_t c1 = 0xFFFFFFFF, c0 = 0xFFFFFFFF, p1[12], p0[12];
  uint32_t split0_rb = 0;
  for (int k = 0; k < 3; ++k)
  {
    uint32_t c = bb_t5_cpn(8192, false, nullptr);
    if (c < c1) c1 = c;
    bb_split(0);
    split0_rb = REG_READ(SENSITIVE_APB_PERIPHERAL_ACCESS_1_REG);
    c = bb_t5_cpn(8192, false, nullptr);
    bb_split(1);
    if (c < c0) c0 = c;
  }
  bb_t5_cpn(8192, true, p1);
  bb_split(0);
  bb_t5_cpn(8192, true, p0);
  bb_split(1);
  esp_sha_release_hardware();
  //correctness with split off (4 x 512 nonces vs mbedTLS)
  const uint32_t bad0 = bb_check(0, 4);
  const uint32_t bad1 = bb_check(1, 1);
  bb_split(split_boot);
  return snprintf(buf, len,
    "bus used=%u mhz=%u split_boot=%u split0_rb=%u ovh=%u sram_r32=%u sram_rv=%u gpio_r32=%u | "
    "split1 r32=%u rv=%u w32=%u wv=%u | split0 r32=%u rv=%u w32=%u wv=%u | "
    "cpn10 split1=%u split0=%u bad0=%u bad1=%u | prof1=%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u | prof0=%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u",
    (unsigned)s_split0, (unsigned)mhz, (unsigned)split_boot, (unsigned)split0_rb, (unsigned)ovh,
    (unsigned)sram_r, (unsigned)sram_rv, (unsigned)gpio_r,
    (unsigned)s1.r32, (unsigned)s1.rv, (unsigned)s1.w32, (unsigned)s1.wv,
    (unsigned)s0.r32, (unsigned)s0.rv, (unsigned)s0.w32, (unsigned)s0.wv,
    (unsigned)c1, (unsigned)c0, (unsigned)bad0, (unsigned)bad1,
    (unsigned)p1[0], (unsigned)p1[1], (unsigned)p1[2], (unsigned)p1[3], (unsigned)p1[4], (unsigned)p1[5],
    (unsigned)p1[6], (unsigned)p1[7], (unsigned)p1[8], (unsigned)p1[9], (unsigned)p1[10],
    (unsigned)p0[0], (unsigned)p0[1], (unsigned)p0[2], (unsigned)p0[3], (unsigned)p0[4], (unsigned)p0[5],
    (unsigned)p0[6], (unsigned)p0[7], (unsigned)p0[8], (unsigned)p0[9], (unsigned)p0[10]);
}

//Boot: keep split burst off for the t5 loop when the self-test passes with it and it is faster.
//RTC guards: a trial that never finished (hang -> watchdog reset), or a crash reset after a boot
//that used it, leave it off for this boot.
#define SB_MAGIC 0x5B0FF5B0
RTC_NOINIT_ATTR static uint32_t s_sb_trial;
RTC_NOINIT_ATTR static uint32_t s_sb_used;

static void turbo_split_pick()
{
  const esp_reset_reason_t rr = esp_reset_reason();
  const bool crash = rr == ESP_RST_PANIC || rr == ESP_RST_INT_WDT || rr == ESP_RST_TASK_WDT || rr == ESP_RST_WDT;
  if (rr == ESP_RST_POWERON) { s_sb_trial = 0; s_sb_used = 0; }
  if (s_sb_trial == SB_MAGIC) { s_sb_trial = 0; s_sb_used = 0; s_sb[2] = 2; return; }
  if (crash && s_sb_used == SB_MAGIC) { s_sb_used = 0; s_sb[2] = 5; return; }
  s_sb_used = 0;
  s_sb_trial = SB_MAGIC;
  const uint32_t bad = bb_check(0, 8);
  uint32_t c1 = 0xFFFFFFFF, c0 = 0xFFFFFFFF;
  if (bad == 0)
  {
    esp_sha_acquire_hardware();
    for (int k = 0; k < 3; ++k)
    {
      uint32_t c = bb_t5_cpn(8192, false, nullptr);
      if (c < c1) c1 = c;
      bb_split(0);
      c = bb_t5_cpn(8192, false, nullptr);
      bb_split(1);
      if (c < c0) c0 = c;
    }
    esp_sha_release_hardware();
  }
  s_sb_trial = 0;
  s_sb[0] = c1;
  s_sb[1] = c0;
  if (bad) { s_sb[2] = 3; return; }
  if (!(c0 < c1)) { s_sb[2] = 4; return; }
  uint32_t p[12];
  esp_sha_acquire_hardware();
  bb_split(0);
  bb_t5_cpn(8192, true, p);
  bb_split(1);
  esp_sha_release_hardware();
  for (int k = 0; k < 11; ++k) s_prof[k] = p[k];
  s_t5_cpn = (c0 + 5) / 10;
  s_split0 = true;
  s_sb_used = SB_MAGIC;
  s_sb[2] = 1;
}
