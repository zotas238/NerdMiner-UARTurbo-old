//---------------------------------------------------------------------------------
//Turbo9 experiments (relay G): t5 loop variants timed side by side and checked vs mbedTLS.
//VA (phase A midstate -> H): 0 scalar stores (t5), 1 PIE VMOVE8 + MEMW before CONTINUE
//VB (phase B next digest -> TEXT): 0 PIE VMOVE8 + MEMW (t5), 1 scalar loads/stores, no MEMW,
//   2 scalar + MEMW
//Margin sweep: wa/wb = min + m for the best variant.
#include <soc/rtc_cntl_reg.h>
static uint32_t s_x_mid[8] __attribute__((aligned(16)));
//the wired task feeds the 8 s RTC watchdog; this bench runs inside it for longer than that
static inline void x_feed()
{
  WRITE_PERI_REG(RTC_CNTL_WDTWPROTECT_REG, 0x50D83AA1);
  WRITE_PERI_REG(RTC_CNTL_WDTFEED_REG, RTC_CNTL_WDT_FEED);
  WRITE_PERI_REG(RTC_CNTL_WDTWPROTECT_REG, 0);
}

template<bool ALL, int VA, int VB>
static inline __attribute__((always_inline)) uint32_t x_body(const T5Cfg cfg, T5_ARGS)
{
  uint32_t * const rb = (uint32_t *)DR_REG_SHA_BASE;
  const uint32_t w0 = w[0], w1 = w[1], w2 = w[2];
  const uint32_t start = n;
  const uint32_t m0 = mid[0], m1 = mid[1], m2 = mid[2], m3 = mid[3], m4 = mid[4], m5 = mid[5], m6 = mid[6], m7 = mid[7];
  if (VA == 1) memcpy(s_x_mid, mid, 32);
  RST(O_MODE, SHA2_256);
  for (int i = 9; i < 15; ++i)
    ((volatile uint32_t *)rb)[(0x80 >> 2) + i] = 0;
  while (n < end)
  {
    const uint32_t cnt = (end - n) < T4_B ? (end - n) : T4_B;
    RST(O_T(0), w0); RST(O_T(1), w1); RST(O_T(2), w2); RST(O_T(3), n);
    RST(O_T(4), 0x00000080); RST(O_T(5), 0); RST(O_T(6), 0); RST(O_T(7), 0);
    RST(O_T(8), 0); RST(O_T(15), 0x80020000);
    for (uint32_t i = 0; i < cnt; ++i)
    {
      if (VA == 4 && i > 0) {}   //written while the previous digest was read
      else if (VA != 1)
      {
        RST(O_H(0), m0); RST(O_H(1), m1); RST(O_H(2), m2); RST(O_H(3), m3);
        RST(O_H(4), m4); RST(O_H(5), m5); RST(O_H(6), m6); RST(O_H(7), m7);
      }
      else
      {
        VMOVE8(s_x_mid, rb + (0x40 >> 2));
        MEMW();
      }
      RST(O_CONT, 1);
      uint32_t t;
      if (VA == 2)
        t = CCOUNT();   //no MEMW, no anchor
      else if (VA == 3)
      {
        MEMW();         //ordering kept, wait timed from the MEMW instead of an anchor load
        t = CCOUNT();
      }
      else
      {
        MEMW();
        (void)RLD(O_BUSY);
        t = CCOUNT();
      }
      RST(O_T(3), n + i + 1);
      SPIN(t, cfg.wa);
      if (VA == 4)
      {
        uint32_t *src = rb + (0x40 >> 2), *dst = s_h1[i];
        asm volatile("ee.vld.128.ip q0, %0, 16\n" : "+r"(src) :: "memory");
        RST(O_H(0), m0); RST(O_H(1), m1); RST(O_H(2), m2); RST(O_H(3), m3);
        asm volatile("ee.vld.128.ip q1, %0, 16\n" : "+r"(src) :: "memory");
        RST(O_H(4), m4); RST(O_H(5), m5); RST(O_H(6), m6); RST(O_H(7), m7);
        asm volatile("ee.vst.128.ip q0, %0, 16\n ee.vst.128.ip q1, %0, 16\n" : "+r"(dst) :: "memory");
      }
      else
        VMOVE8(rb + (0x40 >> 2), s_h1[i]);
    }
    if (ALL)
      memcpy(out1[n - start], s_h1, cnt * 32);
    VMOVE8(s_h1[0], rb + (0x80 >> 2));
    RST(O_T(8), 0x00000080);
    RST(O_T(15), 0x00010000);
    MEMW();
    for (uint32_t i = 0; i < cnt; ++i)
    {
      uint32_t t;
      if (VB == 5)
      {
        //interrupts masked from the drain to the START store: an ISR's leftover stores
        //can't delay START behind an unanchored wait
        uint32_t ps;
        asm volatile("rsil %0, 3" : "=r"(ps) :: "memory");
        MEMW();
        RST(O_START, 1);
        asm volatile("wsr %0, ps\n rsync" :: "r"(ps) : "memory");
      }
      else
        RST(O_START, 1);
      if (VB == 3 || VB == 5)
        t = CCOUNT();   //no anchor: scalar TEXT stores queue behind START in order
      else if (VB == 4)
      {
        MEMW();
        t = CCOUNT();
      }
      else
      {
        MEMW();
        (void)RLD(O_BUSY);
        t = CCOUNT();
      }
      if (i + 1 < cnt)
      {
        if (VB == 0)
        {
          VMOVE8(s_h1[i + 1], rb + (0x80 >> 2));
          MEMW();
        }
        else
        {
          const uint32_t *s = s_h1[i + 1];
          uint32_t a, b, c, d;
          asm volatile("l32i %0, %4, 0\n l32i %1, %4, 4\n l32i %2, %4, 8\n l32i %3, %4, 12\n"
                       "s32i %0, %5, 0x80\n s32i %1, %5, 0x84\n s32i %2, %5, 0x88\n s32i %3, %5, 0x8c\n"
                       "l32i %0, %4, 16\n l32i %1, %4, 20\n l32i %2, %4, 24\n l32i %3, %4, 28\n"
                       "s32i %0, %5, 0x90\n s32i %1, %5, 0x94\n s32i %2, %5, 0x98\n s32i %3, %5, 0x9c\n"
                       : "=&r"(a), "=&r"(b), "=&r"(c), "=&r"(d) : "r"(s), "r"(rb) : "memory");
          if (VB == 2) MEMW();
        }
      }
      SPIN(t, ((VB == 3 || VB == 5) || i + 1 < cnt) ? cfg.wb : cfg.wl);
      const uint32_t h7 = RLD(O_H(7));
      if (ALL)
        out7[n + i - start] = h7;
      else if ((h7 >> 16) == 0)
        t5_cand(ctx, n + i, h7);
    }
    n += cnt;
    if (!ALL && *cur_job != job_in_work)
      break;
  }
  MEMW();
  while (RLD(O_BUSY)) {}
  return n - start;
}

#define X_FN(va, vb) \
  static IRAM_ATTR __attribute__((noinline)) uint32_t x_run_##va##vb(const T5Cfg c, T5_ARGS) { return x_body<false, va, vb>(c, mid, w, n, end, job_in_work, cur_job, ctx, out1, out7); } \
  static IRAM_ATTR __attribute__((noinline)) uint32_t x_all_##va##vb(const T5Cfg c, T5_ARGS) { return x_body<true, va, vb>(c, mid, w, n, end, job_in_work, cur_job, ctx, out1, out7); }
X_FN(0, 0) X_FN(0, 3) X_FN(0, 5) X_FN(4, 5)
typedef uint32_t (*XFn)(const T5Cfg, T5_ARGS);
struct XVar { const char *name; XFn run, all; };
static const XVar s_xv[] = {
  {"a0b0", x_run_00, x_all_00}, {"a0b3", x_run_03, x_all_03}, {"a0b5", x_run_05, x_all_05},
  {"a4b5", x_run_45, x_all_45},
};

//cycles per nonce x10 over n nonces, interrupts off, split as when mining
static IRAM_ATTR uint32_t x_cpn(const XVar &v, const T5Cfg c, uint32_t n)
{
  uint8_t hdr[128];
  test_header(hdr, 9);
  uint32_t mid[8], w[16];
  memcpy(w, hdr + 64, sizeof(w));
  JobResult r;
  r.difficulty = 1e30;
  Ctx cx = {&r, hdr, false};
  volatile uint8_t job = 0;
  x_feed();
  esp_sha_acquire_hardware();
  hw_midstate(hdr, mid);
  if (s_split0) bb_split(0);
  portDISABLE_INTERRUPTS();
  const uint32_t c0 = CCOUNT();
  const uint32_t done = v.run(c, mid, w, 0, n, 0, &job, &cx, nullptr, nullptr);
  const uint32_t cyc = CCOUNT() - c0;
  portENABLE_INTERRUPTS();
  if (s_split0) bb_split(1);
  esp_sha_release_hardware();
  if (cx.bad || !done) return 0xFFFFFFFF;
  return (uint32_t)(((uint64_t)cyc * 10 + done / 2) / done);
}

//mismatches vs mbedTLS over rounds x 2 x 256 nonces (first digest and H7 both checked)
static uint32_t x_check(const XVar &v, const T5Cfg c, int rounds)
{
  static uint32_t out1[256][8];
  static uint32_t out7[256];
  uint32_t bad = 0;
  x_feed();
  for (int rd = 0; rd < rounds; ++rd)
    for (uint32_t seed = 0; seed < 2; ++seed)
    {
      uint8_t hdr[128];
      test_header(hdr, seed + 5 + rd * 2);
      uint32_t mid[8], w[16];
      memcpy(w, hdr + 64, sizeof(w));
      const uint32_t n0 = seed ? 0xFFFFFE00 : 0x8765 + rd * 977;
      x_feed();
      esp_sha_acquire_hardware();
      hw_midstate(hdr, mid);
      if (s_split0) bb_split(0);
      v.all(c, mid, w, n0, n0 + 256, 0, nullptr, nullptr, out1, out7);
      if (s_split0) bb_split(1);
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

static volatile int s_xreq = 0, s_xdone = 0;
static char *s_xbuf = nullptr;
static size_t s_xlen = 0;
int turbo_exp_bench(char *buf, size_t len);
//G from the wired task: the HW miner runs the bench on core 0 before its next job, so core 1
//keeps mining and talking as it does while mining
int turbo_exp_bench_core0(char *buf, size_t len)
{
  buf[0] = 0;
  s_xbuf = buf; s_xlen = len; s_xdone = 0; s_xreq = 1;
  for (int k = 0; k < 1800 && !s_xdone; ++k) { x_feed(); vTaskDelay(pdMS_TO_TICKS(100)); }
  if (!s_xdone) { s_xreq = 0; return snprintf(buf, len, "x timeout"); }
  return strlen(buf);
}
int turbo_exp_bench(char *buf, size_t len)
{
  if (s_mode != MODE_T5) return snprintf(buf, len, "x engine=%s (needs t5)", turbo_hw_mode_name());
  int o = snprintf(buf, len, "x16 split0=%u cfg=%u/%u/%u min=%u/%u |", (unsigned)s_split0,
                   (unsigned)s_t5.wa, (unsigned)s_t5.wb, (unsigned)s_t5.wl, (unsigned)s_t5_min[0], (unsigned)s_t5_min[1]);
  for (const XVar &v : s_xv)
  {
    //shortest passing wb (wa safe), then shortest wa (wb at min + 8); wl stays the t5 one
    T5Cfg c = {300, 300, s_t5.wl, 300};
    if (v.name[3] == '3' || v.name[3] == '5') c.wl = 300;
    uint32_t d, mb = 999, ma = 999;
    for (d = 20; d < 300; d += 2) { c.wb = d; if (v.name[3] == '3' || v.name[3] == '5') c.wl = d; if (x_check(v, c, 2) == 0) { mb = d; break; } }
    c.wb = mb + 8; if (v.name[3] == '3' || v.name[3] == '5') c.wl = mb + 8;
    for (d = 20; d < 300; d += 2) { c.wa = d; if (x_check(v, c, 2) == 0) { ma = d; break; } }
    o += snprintf(buf + o, len - o, " %s min=%u/%u", v.name, (unsigned)ma, (unsigned)mb);
    if (ma == 999 || mb == 999) continue;
    for (uint32_t m : {4u, 8u})
    {
      T5Cfg t = c;
      t.wa = ma + m; t.wb = mb + m;
      if (v.name[3] == '3' || v.name[3] == '5') t.wl = t.wb;
      uint32_t best = 0xFFFFFFFF;
      for (int k = 0; k < 3; ++k) { const uint32_t cc = x_cpn(v, t, 8192); if (cc < best) best = cc; }
      o += snprintf(buf + o, len - o, " m%u=%u/%u", (unsigned)m, (unsigned)best, (unsigned)x_check(v, t, 128));
    }
  }
  return o;
}

//Boot (wired build, after turbo_split_pick): Turbo9 = phase B without the anchor load.
//Shortest passing wn, + 4, must pass 8192 nonces vs mbedTLS (up to 3 tries, +4 each),
//then kept only if t5 gets faster. s_nbst: min wn, wn used, cpn x10 without / with.
static void turbo_nb_pick()
{
  const uint32_t sp = s_split0 ? 0 : 1;
  auto cpn = []() {
    uint32_t best = 0xFFFFFFFF;
    esp_sha_acquire_hardware();
    for (int k = 0; k < 3; ++k)
    {
      if (s_split0) bb_split(0);
      const uint32_t c = bb_t5_cpn(8192, false, nullptr);
      if (s_split0) bb_split(1);
      if (c < best) best = c;
    }
    esp_sha_release_hardware();
    return best;
  };
  s_nb = false;
  const uint32_t c_off = cpn();
  s_nbst[2] = c_off;
  s_nb = true;
  uint32_t mn = 0;
  for (uint32_t d = 60; d < 250 && !mn; d += 2)
  {
    x_feed();
    s_t5.wn = d;
    if (bb_check(sp, 2) == 0) mn = d;
  }
  s_nbst[0] = mn;
  if (!mn) { s_nb = false; return; }
  uint32_t wn = mn + 8;
  bool ok = false;
  for (int k = 0; k < 3 && !ok; ++k)
  {
    x_feed();
    s_t5.wn = wn;
    if (bb_check(sp, 16) == 0) ok = true;
    else wn += 4;
  }
  if (!ok) { s_nb = false; return; }
  s_nbst[1] = wn;
  const uint32_t c_on = cpn();
  s_nbst[3] = c_on;
  if (!(c_on < c_off)) { s_nb = false; return; }
  s_t5_cpn = (c_on + 5) / 10;
  uint32_t pr[12];
  esp_sha_acquire_hardware();
  if (s_split0) bb_split(0);
  bb_t5_cpn(8192, true, pr);
  if (s_split0) bb_split(1);
  esp_sha_release_hardware();
  for (int k = 0; k < 11; ++k) s_prof[k] = pr[k];
}
