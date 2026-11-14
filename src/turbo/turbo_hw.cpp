//Turbo HW miner: the ESP32-S3 SHA engine driven directly.
//
//Engines, best first; each is self-tested against mbedTLS at boot and the first that
//passes is used:
//  t4     batched (below), the register traffic tuned at boot
//  t1     one nonce at a time, REG_WRITE + BUSY polling, padding written once per job
//  stock  as t1 but every TEXT word written for every block (stock NerdMiner's loop)
//Every nonce that passes the 16-bit check is re-hashed with an independent software
//SHA-256d before it can become a share; a mismatch there or in the spot check (every
//8th job, 2 nonces against mbedTLS) drops the engine one step for the rest of the boot.
//
//Earlier experiments (hybrid SW rounds in the BUSY wait, Turbo2/3 single-nonce raw
//stores and timed waits) are in git history at tag turbo4-full; probes are in
//turbo_probe.cpp, built with -D NM_TURBO_PROBES.
#ifdef NM_TURBO

#include <Arduino.h>
#include <string.h>
#include <esp_attr.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <sha/sha_dma.h>
#include <hal/sha_hal.h>
#include <hal/sha_ll.h>
#include "mbedtls/sha256.h"
#include "turbo_hw.h"
#include "sha256_sw.h"
#include "../utils.h"

enum { MODE_STOCK = 0, MODE_T1 = 1, MODE_T4 = 4, MODE_T5 = 5 };
static volatile uint32_t s_mode = MODE_STOCK;

volatile uint32_t g_hw_hashes = 0;
static volatile uint32_t s_checks = 0;      //spot checks run
static volatile uint32_t s_cands = 0;       //16-bit candidates verified
static volatile uint32_t s_bad = 0;         //spot checks or candidates that disagreed
static volatile uint32_t s_t1_cpn[2] = {0}; //cycles per nonce: t1, stock (0 = failed)
static volatile uint32_t s_fail = 0xFFFFFFFF;   //first t4 self-test mismatch: seed << 16 | nonce index

//CPU cycles from the global esp_timer (CCOUNT is per core; the miner is unpinned)
static inline uint32_t turbo_cycles() { return (uint32_t)(esp_timer_get_time() * 240); }

//---------------------------------------------------------------------------------
//Crash guard: survives resets (not power cycles); two crash resets in a row mean the
//tuned engine misbehaves, so the next boot runs t1 only and stays reachable for OTA
#define CRASH_MAGIC 0xC0FFEE42
RTC_NOINIT_ATTR static uint32_t s_crash_magic;
RTC_NOINIT_ATTR static uint32_t s_crash_count;
static bool s_safe_mode = false;

static void crash_guard_boot()
{
  esp_reset_reason_t rr = esp_reset_reason();
  if (s_crash_magic != CRASH_MAGIC || rr == ESP_RST_POWERON)
  {
    s_crash_magic = CRASH_MAGIC;
    s_crash_count = 0;
  }
  if (rr == ESP_RST_PANIC || rr == ESP_RST_INT_WDT || rr == ESP_RST_TASK_WDT || rr == ESP_RST_WDT)
    s_crash_count++;
  s_safe_mode = s_crash_count >= 2;
  Serial.printf("[MINER] reset reason %d, crash count %u%s\n", (int)rr, (unsigned)s_crash_count, s_safe_mode ? ", safe mode" : "");
}

void turbo_crash_guard_stable()
{
  s_crash_count = 0;
}

//---------------------------------------------------------------------------------
//Candidates: the hash passed the 16-bit check on the engine. Re-hash in software; only
//an agreeing hash may become the job's result.
struct Ctx
{
  JobResult *result;
  const uint8_t *hdr;
  bool bad;
};

static void candidate(Ctx &c, uint32_t nonce, const uint8_t *hash)
{
  s_cands++;
  if (!turbo_ref_check(c.hdr, nonce, hash))
  {
    s_bad++;
    c.bad = true;
    return;
  }
  double diff_hash = diff_from_target((void *)hash);
  if (diff_hash > c.result->difficulty && isSha256Valid(hash))
  {
    c.result->difficulty = diff_hash;
    c.result->nonce = nonce;
    memcpy(c.result->hash, hash, 32);
  }
}

//---------------------------------------------------------------------------------
//t1 / stock: block 2 of the header from the midstate, then the second SHA over that
//digest. Words 9..14 of the text are zero in both blocks, so with FAST they are written
//once per job (zero_tail) and left alone; the self-test proves the engine keeps them.
template<bool FAST>
static inline void t1_block1(const uint32_t *mid, const uint32_t *w, uint32_t nonce)
{
  uint32_t *h = (uint32_t *)(SHA_H_BASE);
  uint32_t *t = (uint32_t *)(SHA_TEXT_BASE);
  for (int i = 0; i < 8; ++i)
    REG_WRITE(&h[i], mid[i]);
  REG_WRITE(&t[0], w[0]);
  REG_WRITE(&t[1], w[1]);
  REG_WRITE(&t[2], w[2]);
  REG_WRITE(&t[3], nonce);
  REG_WRITE(&t[4], 0x00000080);
  REG_WRITE(&t[5], 0x00000000);
  REG_WRITE(&t[6], 0x00000000);
  REG_WRITE(&t[7], 0x00000000);
  REG_WRITE(&t[8], 0x00000000);
  if (!FAST)
    for (int i = 9; i < 15; ++i)
      REG_WRITE(&t[i], 0x00000000);
  REG_WRITE(&t[15], 0x80020000);
  REG_WRITE(SHA_CONTINUE_REG, 1);
}

template<bool FAST>
static inline void t1_block2()
{
  uint32_t *h = (uint32_t *)(SHA_H_BASE);
  uint32_t *t = (uint32_t *)(SHA_TEXT_BASE);
  for (int i = 0; i < 8; ++i)
    REG_WRITE(&t[i], REG_READ(&h[i]));
  REG_WRITE(&t[8], 0x00000080);
  if (!FAST)
    for (int i = 9; i < 15; ++i)
      REG_WRITE(&t[i], 0x00000000);
  REG_WRITE(&t[15], 0x00010000);
  REG_WRITE(SHA_START_REG, 1);
}

static inline void wait_idle()
{
  while (REG_READ(SHA_BUSY_REG)) {}
}

template<bool FAST>
static inline void t1_nonce(const uint32_t *mid, const uint32_t *w, uint32_t nonce)
{
  t1_block1<FAST>(mid, w, nonce);
  wait_idle();
  t1_block2<FAST>();
  wait_idle();
}

static inline void zero_tail()
{
  uint32_t *t = (uint32_t *)(SHA_TEXT_BASE);
  for (int i = 9; i < 15; ++i)
    REG_WRITE(&t[i], 0x00000000);
}

static inline void read_digest(uint32_t *out)
{
  for (int i = 0; i < 8; ++i)
    out[i] = REG_READ(SHA_H_BASE + 4 * i);
}

//Test headers: 80 bytes from a seed, padded for the two-block SHA
static void test_header(uint8_t *hdr, uint32_t seed)
{
  for (int i = 0; i < 80; ++i)
    hdr[i] = (uint8_t)(i * 37 + 11 + seed * 101);
  memset(hdr + 80, 0, 128 - 80);
  hdr[80] = 0x80;
  hdr[126] = 0x02;
  hdr[127] = 0x80;
}

static void hw_midstate(const uint8_t *hdr, uint32_t *mid)
{
  sha_hal_hash_block(SHA2_256, hdr, 64 / 4, true);
  sha_hal_read_digest(SHA2_256, mid);
}

static void mbed_sha256d(const uint8_t *hdr, uint32_t nonce, uint8_t *out)
{
  uint8_t b[80], h1[32];
  memcpy(b, hdr, 80);
  memcpy(b + 76, &nonce, 4);
  mbedtls_sha256_ret(b, 80, h1, 0);
  mbedtls_sha256_ret(h1, 32, out, 0);
}

//Four nonces against mbedTLS, then cycles per nonce over 4096
template<bool FAST>
static bool t1_selftest(volatile uint32_t &cpn)
{
  uint8_t hdr[128];
  test_header(hdr, 0);
  uint32_t w[16];
  memcpy(w, hdr + 64, sizeof(w));
  static const uint32_t nonces[4] = {0x00000000, 0x12345678, 0xDA54E700, 0xFFFFFFFF};
  uint32_t got[4][8];
  uint32_t mid[8];

  esp_sha_acquire_hardware();
  hw_midstate(hdr, mid);
  REG_WRITE(SHA_MODE_REG, SHA2_256);
  zero_tail();
  for (int k = 0; k < 4; ++k)
  {
    t1_nonce<FAST>(mid, w, nonces[k]);
    read_digest(got[k]);
  }
  uint32_t c0 = turbo_cycles();
  for (uint32_t n = 0; n < 4096; ++n)
  {
    t1_nonce<FAST>(mid, w, n);
    (void)REG_READ(SHA_H_BASE + 28);
  }
  uint32_t c = (turbo_cycles() - c0) / 4096;
  esp_sha_release_hardware();

  bool ok = true;
  for (int k = 0; k < 4; ++k)
  {
    uint8_t want[32];
    mbed_sha256d(hdr, nonces[k], want);
    if (memcmp(want, got[k], 32) != 0)
      ok = false;
  }
  cpn = ok ? c : 0;
  Serial.printf("[MINER] HW self-test %s: %s, %u cycles/nonce\n", FAST ? "t1" : "stock", ok ? "ok" : "MISMATCH", (unsigned)c);
  return ok;
}

template<bool FAST>
static void t1_job(const JobRequest &job, JobResult &result, volatile uint8_t &cur_job, Ctx &c)
{
  uint32_t mid[8], w[16], hash[8];
  memcpy(mid, job.midstate, sizeof(mid));
  memcpy(w, job.sha_buffer + 64, sizeof(w));
  const uint8_t job_in_work = job.id & 0xFF;

  esp_sha_acquire_hardware();
  REG_WRITE(SHA_MODE_REG, SHA2_256);
  zero_tail();
  const uint32_t nend = job.nonce_start + job.nonce_count;
  for (uint32_t n = job.nonce_start; n < nend; ++n)
  {
    t1_nonce<FAST>(mid, w, n);
    if ((REG_READ(SHA_H_BASE + 28) >> 16) == 0)
    {
      read_digest(hash);
      candidate(c, n, (const uint8_t *)hash);
    }
    if ((uint8_t)(n & 0xFF) == 0 && cur_job != job_in_work)
    {
      result.nonce_count = n - job.nonce_start + 1;
      break;
    }
  }
  esp_sha_release_hardware();
}

//---------------------------------------------------------------------------------
//t4: the engine driven with raw stores (GCC puts a MEMW before every volatile access,
//which drains the store buffer each time; here stores go out back to back and a MEMW
//sits only where order matters). Measured on the board: a 32-bit register store costs
//~15 cycles, a load 13-20, the engine ~125 per block, so the loop is bound by the bus.
//The engine first runs block 1 for T4_B nonces back to back (TEXT only changes in the
//nonce word, written while the engine runs: TEXT is latched at start), keeping each
//first digest in RAM; then the second hash for the batch, writing the next digest into
//TEXT while the current one runs. Padding words are written once per phase.
//Options picked at boot, each kept only if it passes the self-test and is faster:
//  VD  128-bit PIE loads/stores for the digest moves (H -> RAM, RAM -> TEXT)
//  VM  128-bit PIE stores for the midstate (RAM -> H) before each block 1
//  pa/pb  cycles spun before polling BUSY in phase A / B (less bus traffic)
//da/db: cycles waited after BUSY drops before reading H (BUSY drops a little before H
//is final); the shortest the self-test passes, plus a margin.

#define RST(off, v) asm volatile("s32i %0, %1, %2" :: "r"((uint32_t)(v)), "r"(rb), "i"(off) : "memory")
#define RLD(off) ({ uint32_t _r; asm volatile("l32i %0, %1, %2" : "=r"(_r) : "r"(rb), "i"(off) : "memory"); _r; })
#define MEMW() asm volatile("memw" ::: "memory")
#define CCOUNT() ({ uint32_t _c; asm volatile("rsr.ccount %0" : "=r"(_c) :: "memory"); _c; })
#define SPIN(t0, d) do { while ((uint32_t)(CCOUNT() - (t0)) < (d)) {} } while (0)
#define O_MODE 0x00
#define O_START 0x10
#define O_CONT 0x14
#define O_BUSY 0x18
#define O_H(i) (0x40 + 4 * (i))
#define O_T(i) (0x80 + 4 * (i))
//Spin pre cycles, poll BUSY, then wait settle cycles. CCOUNT is per core, but a core
//switch needs a context switch, far longer than the engine, so a wrong difference can
//only end a wait late.
#define T4_WAIT(pre, settle) do { \
    if (pre) { const uint32_t _s = CCOUNT(); SPIN(_s, (pre)); } \
    MEMW(); while (RLD(O_BUSY)) {} \
    const uint32_t _t = CCOUNT(); SPIN(_t, (settle)); } while (0)
//Two 128-bit PIE moves (q0, q1): 8 words from src to dst, both 16-byte aligned
#define VMOVE8(src, dst) do { uint32_t *_s = (uint32_t *)(src), *_d = (uint32_t *)(dst); \
    asm volatile("ee.vld.128.ip q0, %0, 16\n ee.vld.128.ip q1, %0, 16\n" \
                 "ee.vst.128.ip q0, %1, 16\n ee.vst.128.ip q1, %1, 16\n" : "+r"(_s), "+r"(_d) :: "memory"); } while (0)

#define T4_B 128
#define T4_VD 1
#define T4_VM 2
static uint32_t s_h1[T4_B][8] __attribute__((aligned(16)));
static uint32_t s_mid[8] __attribute__((aligned(16)));
struct T4Cfg
{
  uint32_t da, db, pa, pb, v;
};
static T4Cfg s_t4 = {200, 200, 0, 0, 0};
static volatile uint32_t s_t4_min[2] = {0};    //shortest passing da, db
static volatile uint32_t s_t4_cpn[4] = {0};    //cycles per nonce: base, VD, VD+VM, final
static volatile uint32_t s_t4_cpn_now = 0;

#define T4_ARGS const uint32_t *mid, const uint32_t *w, uint32_t n, uint32_t end, uint8_t job_in_work, \
                volatile uint8_t *cur_job, Ctx *ctx, uint32_t (*out)[8]

//Nonces [n, end): ALL stores every digest in out (tests); otherwise candidates go to
//ctx. Returns nonces done (stops between batches when the job changes).
template<bool ALL, bool VD, bool VM>
static inline __attribute__((always_inline)) uint32_t t4_body(T4_ARGS)
{
  uint32_t * const rb = (uint32_t *)DR_REG_SHA_BASE;
  const uint32_t w0 = w[0], w1 = w[1], w2 = w[2];
  const uint32_t start = n;
  const T4Cfg cfg = s_t4;
  const uint32_t m0 = mid[0], m1 = mid[1], m2 = mid[2], m3 = mid[3], m4 = mid[4], m5 = mid[5], m6 = mid[6], m7 = mid[7];
  memcpy(s_mid, mid, sizeof(s_mid));
  RST(O_MODE, SHA2_256);
  for (int i = 9; i < 15; ++i)
    ((volatile uint32_t *)rb)[(0x80 >> 2) + i] = 0;
  while (n < end)
  {
    const uint32_t cnt = (end - n) < T4_B ? (end - n) : T4_B;
    //phase A: first hash of cnt nonces
    RST(O_T(0), w0); RST(O_T(1), w1); RST(O_T(2), w2); RST(O_T(3), n);
    RST(O_T(4), 0x00000080); RST(O_T(5), 0); RST(O_T(6), 0); RST(O_T(7), 0);
    RST(O_T(8), 0); RST(O_T(15), 0x80020000);
    for (uint32_t i = 0; i < cnt; ++i)
    {
      if (VM)
      {
        VMOVE8(s_mid, rb + (0x40 >> 2));
        MEMW();   //H must be written before CONTINUE; PIE and scalar stores may not be ordered
      }
      else
      {
        RST(O_H(0), m0); RST(O_H(1), m1); RST(O_H(2), m2); RST(O_H(3), m3);
        RST(O_H(4), m4); RST(O_H(5), m5); RST(O_H(6), m6); RST(O_H(7), m7);
      }
      RST(O_CONT, 1);
      MEMW();
      RST(O_T(3), n + i + 1);   //next nonce: TEXT was latched at CONTINUE
      T4_WAIT(cfg.pa, cfg.da);
      if (VD)
        VMOVE8(rb + (0x40 >> 2), s_h1[i]);
      else
      {
        uint32_t *d = s_h1[i];
        uint32_t a = RLD(O_H(0)), b = RLD(O_H(1)), c = RLD(O_H(2)), e = RLD(O_H(3));
        d[0] = a; d[1] = b; d[2] = c; d[3] = e;
        a = RLD(O_H(4)); b = RLD(O_H(5)); c = RLD(O_H(6)); e = RLD(O_H(7));
        d[4] = a; d[5] = b; d[6] = c; d[7] = e;
      }
    }
    //phase B: second hash
    {
      const uint32_t *d = s_h1[0];
      RST(O_T(0), d[0]); RST(O_T(1), d[1]); RST(O_T(2), d[2]); RST(O_T(3), d[3]);
      RST(O_T(4), d[4]); RST(O_T(5), d[5]); RST(O_T(6), d[6]); RST(O_T(7), d[7]);
      RST(O_T(8), 0x00000080);
      RST(O_T(15), 0x00010000);
    }
    for (uint32_t i = 0; i < cnt; ++i)
    {
      RST(O_START, 1);   //from the IV
      MEMW();
      if (i + 1 < cnt)
      {
        if (VD)
          VMOVE8(s_h1[i + 1], rb + (0x80 >> 2));
        else
        {
          const uint32_t *d = s_h1[i + 1];
          RST(O_T(0), d[0]); RST(O_T(1), d[1]); RST(O_T(2), d[2]); RST(O_T(3), d[3]);
          RST(O_T(4), d[4]); RST(O_T(5), d[5]); RST(O_T(6), d[6]); RST(O_T(7), d[7]);
        }
      }
      T4_WAIT(cfg.pb, cfg.db);
      if (ALL)
      {
        for (int k = 0; k < 8; ++k)
          out[n + i - start][k] = ((volatile uint32_t *)rb)[(0x40 >> 2) + k];
        continue;
      }
      const uint32_t h7 = RLD(O_H(7));
      if ((h7 >> 16) == 0)
      {
        //the engine is idle here, but the next TEXT stores may still be draining
        MEMW();
        uint32_t hash[8];
        for (int k = 0; k < 8; ++k)
          hash[k] = ((volatile uint32_t *)rb)[(0x40 >> 2) + k];
        candidate(*ctx, n + i, (const uint8_t *)hash);
      }
    }
    n += cnt;
    if (!ALL && *cur_job != job_in_work)
      return n - start;
  }
  return n - start;
}

//Section attributes are dropped on template instances, so the loops get IRAM through
//these plain functions
#define T4_FN(name, all, vd, vm) \
  static IRAM_ATTR __attribute__((noinline)) uint32_t name(T4_ARGS) { return t4_body<all, vd, vm>(mid, w, n, end, job_in_work, cur_job, ctx, out); }
T4_FN(t4_run_000, false, false, false)
T4_FN(t4_run_010, false, true, false)
T4_FN(t4_run_001, false, false, true)
T4_FN(t4_run_011, false, true, true)
T4_FN(t4_all_000, true, false, false)
T4_FN(t4_all_010, true, true, false)
T4_FN(t4_all_001, true, false, true)
T4_FN(t4_all_011, true, true, true)
typedef uint32_t (*T4Fn)(T4_ARGS);
static const T4Fn s_t4_run[4] = {t4_run_000, t4_run_010, t4_run_001, t4_run_011};
static const T4Fn s_t4_all[4] = {t4_all_000, t4_all_010, t4_all_001, t4_all_011};

//256 consecutive nonces (2 batches) on two headers, every digest compared with mbedTLS
static bool t4_selftest()
{
  static uint32_t out[256][8];
  for (uint32_t seed = 0; seed < 2; ++seed)
  {
    uint8_t hdr[128];
    test_header(hdr, seed + 3);
    uint32_t mid[8], w[16];
    memcpy(w, hdr + 64, sizeof(w));
    const uint32_t n0 = seed ? 0xFFFFFE00 : 0x4321;
    esp_sha_acquire_hardware();
    hw_midstate(hdr, mid);
    s_t4_all[s_t4.v](mid, w, n0, n0 + 256, 0, nullptr, nullptr, out);
    esp_sha_release_hardware();
    for (uint32_t k = 0; k < 256; ++k)
    {
      uint8_t want[32];
      mbed_sha256d(hdr, n0 + k, want);
      if (memcmp(want, out[k], 32) != 0)
      {
        if (s_fail == 0xFFFFFFFF)
          s_fail = (seed << 16) | k;
        return false;
      }
    }
  }
  return true;
}

static bool t4_pass(int runs)
{
  for (int r = 0; r < runs; ++r)
    if (!t4_selftest()) return false;
  return true;
}

//Cycles per nonce over 8192 nonces of a dummy job; best of three (interrupts add noise)
static uint32_t t4_bench()
{
  uint8_t hdr[128];
  test_header(hdr, 7);
  uint32_t mid[8], w[16];
  memcpy(w, hdr + 64, sizeof(w));
  JobResult r;
  r.difficulty = 1e30;
  Ctx c = {&r, hdr, false};
  volatile uint8_t job = 0;
  uint32_t best = 0xFFFFFFFF;
  for (int k = 0; k < 3; ++k)
  {
    esp_sha_acquire_hardware();
    hw_midstate(hdr, mid);
    const uint32_t c0 = turbo_cycles();
    const uint32_t done = s_t4_run[s_t4.v](mid, w, 0, 8192, 0, &job, &c, nullptr);
    const uint32_t cyc = turbo_cycles() - c0;
    esp_sha_release_hardware();
    if (done && cyc / done < best) best = cyc / done;
  }
  return best;
}

//Tries one change to the config: kept when it passes the self-test and is faster
static void t4_try(const T4Cfg &cand, uint32_t &best, int passes)
{
  const T4Cfg keep = s_t4;
  s_t4 = cand;
  if (t4_pass(passes))
  {
    const uint32_t c = t4_bench();
    if (c < best)
    {
      best = c;
      return;
    }
  }
  s_t4 = keep;
}

//Returns cycles per nonce of the picked config, 0 if t4 failed its self-test
static uint32_t t4_pick()
{
  s_t4 = {200, 200, 0, 0, 0};
  if (!t4_pass(2)) return 0;
  uint32_t d;
  for (d = 0; d < 200; d += 2) { s_t4.db = d; if (t4_pass(4)) break; }
  s_t4_min[1] = d;
  for (d = 0; d < 200; d += 2) { s_t4.da = d; if (t4_pass(4)) break; }
  s_t4_min[0] = d;
  s_t4.da = s_t4_min[0] + 8;
  s_t4.db = s_t4_min[1] + 8;
  if (!t4_pass(16)) return 0;
  uint32_t best = t4_bench();
  s_t4_cpn[0] = best;

  T4Cfg c = s_t4;
  c.v = T4_VD;
  t4_try(c, best, 8);
  s_t4_cpn[1] = best;
  c = s_t4;
  c.v |= T4_VM;
  t4_try(c, best, 8);
  s_t4_cpn[2] = best;
  static const uint32_t pas[] = {40, 60, 80, 100, 120};
  static const uint32_t pbs[] = {20, 40, 60, 80};
  const T4Cfg base = s_t4;
  for (uint32_t pa : pas) { c = base; c.pa = pa; t4_try(c, best, 2); }
  const T4Cfg base2 = s_t4;
  for (uint32_t pb : pbs) { c = base2; c.pb = pb; t4_try(c, best, 2); }
  if (!t4_pass(8)) return 0;
  s_t4_cpn[3] = best;
  return best;
}

static void t4_job(const JobRequest &job, JobResult &result, volatile uint8_t &cur_job, Ctx &c)
{
  static uint32_t jobs = 0;
  uint32_t mid[8], w[16];
  memcpy(mid, job.midstate, sizeof(mid));
  memcpy(w, job.sha_buffer + 64, sizeof(w));
  const uint32_t v = s_t4.v;
  if ((jobs++ & 7) == 0)
  {
    static uint32_t out[2][8];
    esp_sha_acquire_hardware();
    s_t4_all[v](mid, w, job.nonce_start, job.nonce_start + 2, 0, nullptr, nullptr, out);
    esp_sha_release_hardware();
    s_checks++;
    for (int k = 0; k < 2; ++k)
    {
      uint8_t want[32];
      mbed_sha256d(job.sha_buffer, job.nonce_start + k, want);
      if (memcmp(want, out[k], 32) != 0)
      {
        s_bad++;
        c.bad = true;
        result.nonce_count = 0;
        return;
      }
    }
  }
  esp_sha_acquire_hardware();
  result.nonce_count = s_t4_run[v](mid, w, job.nonce_start, job.nonce_start + job.nonce_count,
                                   job.id & 0xFF, &cur_job, &c, nullptr);
  esp_sha_release_hardware();
}

//---------------------------------------------------------------------------------
//t5: t4's batches with timed waits. The engine takes a fixed ~125 cycles once its
//CONTINUE/START store lands, so t5 spins to a calibrated delay instead of polling BUSY
//(the poll's last load is pure latency). The delay counts from the return of a load
//after the store, not from MEMW: MEMW only says the store left the CPU, and with other
//bus masters busy it reached the engine late often enough to fail 1 in a few thousand
//H7 reads. Reading H7 of the
//previous nonce after the next START does not work: H changes as soon as START lands
//(h7chg in the status is 0 on the board), so H7 is read once the block is done.
//Candidates are hashed again in software, and H7 must agree with that hash.
//wa/wb: the shortest delays the self-test passes, plus a margin. Bus traffic during a
//block does not slow the engine and TEXT is latched at START (ep probe). Anchoring phase
//B after the next digest's stores instead (one load absorbing their drain) was slower:
//552 vs 541 cycles/nonce.

#define T5_MARGIN 8
#define T5_BUMP 8      //added to both delays after a mismatch while mining
#define T5_BUMPS 3     //mismatches t5 survives before the engine drops to t4
//wl: the last nonce of a batch has no TEXT stores between its anchor and the H7 read, so
//it waits the engine's quiet time (ep[0]) plus a margin; wb, calibrated on the batch, can
//sit within a few cycles of that edge (a boot once failed there on nonce 255)
#define T5_LAST_MARGIN 16
struct T5Cfg
{
  uint32_t wa, wb, wl;
  uint32_t wn;   //Turbo9 phase B wait, timed from the START store (no anchor load)
};
static T5Cfg s_t5 = {200, 200, 200, 200};
//Turbo9: phase B without the anchor load (picked at boot, turbo_nb_pick in exp_bench.inc)
static bool s_nb = false;
static uint32_t s_nbst[4] = {0, 0, 0, 0};   //min wn, wn used, t5 cpn x10 without / with
//NB while mining: unanchored nonces checked, mismatches among them, wn bumps
static volatile uint32_t s_nb_chk = 0, s_nb_bad = 0, s_nb_bumps = 0;
//v17: an early H7 read on an unanchored nonce while mining. Its value is unrelated to the
//hash, so a false candidate (top 16 bits 0) shows 1 in 65536 of them: est. miss rate =
//fc * 65536 / NB nonces. NB goes off if that passes 1% (it gains ~3%).
static volatile uint32_t s_nb_fc = 0, s_nb_n16 = 0;   //false cands, NB nonces >> 16
#define NB_BUMP 4
#define NB_BUMPS 5     //NB mismatches before NB is switched off (anchored t5 stays)
#define T5_CHECK_N 8   //nonces per mining check: the first anchored, the rest NB
static volatile uint32_t s_t5_min[2] = {0};
static volatile uint32_t s_t5_cpn = 0;
static volatile uint32_t s_t5_bumps = 0;
static volatile int32_t s_h7chg = -2;
static volatile uint32_t s_t5_stage = 0;   //where t5_pick stopped: 1 first test, 2 after margin, 3 bench, 9 picked
static volatile uint32_t s_t5_fail = 0;    //failing nonce (seed << 16 | k), | 0x80000000 if H7 else first digest   //-2 not run, -1 H7 never changed before the block ended

#define T5_ARGS const uint32_t *mid, const uint32_t *w, uint32_t n, uint32_t end, uint8_t job_in_work, \
                volatile uint8_t *cur_job, Ctx *ctx, uint32_t (*out1)[8], uint32_t *out7

static void t5_cand(Ctx *ctx, uint32_t nonce, uint32_t h7, bool nbn = false)
{
  uint8_t hash[32];
  turbo_ref_sha256d(ctx->hdr, nonce, hash);
  uint32_t w7;
  memcpy(&w7, hash + 28, 4);
  if (w7 != h7 && nbn)
  {
    s_cands++;
    s_nb_fc++;   //costs this nonce only; the 8-nonce checks still guard the engine
    return;
  }
  if (w7 != h7)
  {
    s_cands++;
    s_bad++;
    ctx->bad = true;
    return;
  }
  candidate(*ctx, nonce, hash);
}

//Nonces [n, end): ALL stores the first digests in out1 and H7 of the second in out7
//(tests); otherwise candidates go to ctx. Returns nonces done.
//Profile of one bench run (PROF build of the loop): cycles summed over all nonces for
//A: stores..MEMW, MEMW..anchor, anchor..spin end, vld; B: START..MEMW, anchor, VMOVE..MEMW,
//to spin end, H7 load; then whole A and B loops per nonce
static uint32_t s_prof[12];
#define PCC(v) uint32_t v = 0; if (PROF) v = CCOUNT()
template<bool ALL, bool PROF = false, bool NB = false>
static inline __attribute__((always_inline)) uint32_t t5_body(T5_ARGS)
{
  uint32_t * const rb = (uint32_t *)DR_REG_SHA_BASE;
  const uint32_t w0 = w[0], w1 = w[1], w2 = w[2];
  const uint32_t start = n;
  const T5Cfg cfg = s_t5;
  const uint32_t m0 = mid[0], m1 = mid[1], m2 = mid[2], m3 = mid[3], m4 = mid[4], m5 = mid[5], m6 = mid[6], m7 = mid[7];
  RST(O_MODE, SHA2_256);
  for (int i = 9; i < 15; ++i)
    ((volatile uint32_t *)rb)[(0x80 >> 2) + i] = 0;
  while (n < end)
  {
    const uint32_t cnt = (end - n) < T4_B ? (end - n) : T4_B;
    //phase A: first hash of cnt nonces
    RST(O_T(0), w0); RST(O_T(1), w1); RST(O_T(2), w2); RST(O_T(3), n);
    RST(O_T(4), 0x00000080); RST(O_T(5), 0); RST(O_T(6), 0); RST(O_T(7), 0);
    RST(O_T(8), 0); RST(O_T(15), 0x80020000);
    PCC(pa0);
    for (uint32_t i = 0; i < cnt; ++i)
    {
      PCC(c0);
      RST(O_H(0), m0); RST(O_H(1), m1); RST(O_H(2), m2); RST(O_H(3), m3);
      RST(O_H(4), m4); RST(O_H(5), m5); RST(O_H(6), m6); RST(O_H(7), m7);
      RST(O_CONT, 1);
      MEMW();
      PCC(c1);
      (void)RLD(O_BUSY);   //anchor: a load returns only after the store reached the engine
      const uint32_t t = CCOUNT();
      RST(O_T(3), n + i + 1);   //next nonce: TEXT was latched at CONTINUE
      SPIN(t, cfg.wa);
      PCC(c3);
      VMOVE8(rb + (0x40 >> 2), s_h1[i]);
      if (PROF)
      {
        const uint32_t c4 = CCOUNT();
        s_prof[0] += c1 - c0; s_prof[1] += t - c1; s_prof[2] += c3 - t; s_prof[3] += c4 - c3;
      }
    }
    if (PROF) s_prof[9] += CCOUNT() - pa0;
    if (ALL)
      memcpy(out1[n - start], s_h1, cnt * 32);
    //phase B: second hash, the next digest written into TEXT while the engine runs
    //PIE and scalar stores may not be ordered: a MEMW after each vector move keeps TEXT
    //ahead of the next START (it drains while the engine runs)
    VMOVE8(s_h1[0], rb + (0x80 >> 2));
    RST(O_T(8), 0x00000080);
    RST(O_T(15), 0x00010000);
    MEMW();
    PCC(pb0);
    for (uint32_t i = 0; i < cnt; ++i)
    {
      PCC(b0);
      //NB (Turbo9): no anchor load. Interrupts masked from the drain to the START store,
      //so no ISR's leftover stores sit ahead of START; the wait is timed from its issue.
      //The first nonce of a batch keeps the anchor (TEXT was written by PIE moves).
      const bool anc = !NB || i == 0;
      if (anc)
      {
        RST(O_START, 1);
        MEMW();
      }
      else
      {
        uint32_t ps;
        asm volatile("rsil %0, 3" : "=r"(ps) :: "memory");
        MEMW();
        RST(O_START, 1);
        asm volatile("wsr %0, ps\n rsync" :: "r"(ps) : "memory");
      }
      PCC(b1);
      if (anc) (void)RLD(O_BUSY);
      const uint32_t t = CCOUNT();
      if (i + 1 < cnt)
      {
        if (NB)
        {
          //scalar stores stay in order behind START (PIE stores may not)
          const uint32_t *sp = s_h1[i + 1];
          uint32_t a, b, c, d;
          asm volatile("l32i %0, %4, 0\n l32i %1, %4, 4\n l32i %2, %4, 8\n l32i %3, %4, 12\n"
                       "s32i %0, %5, 0x80\n s32i %1, %5, 0x84\n s32i %2, %5, 0x88\n s32i %3, %5, 0x8c\n"
                       "l32i %0, %4, 16\n l32i %1, %4, 20\n l32i %2, %4, 24\n l32i %3, %4, 28\n"
                       "s32i %0, %5, 0x90\n s32i %1, %5, 0x94\n s32i %2, %5, 0x98\n s32i %3, %5, 0x9c\n"
                       : "=&r"(a), "=&r"(b), "=&r"(c), "=&r"(d) : "r"(sp), "r"(rb) : "memory");
        }
        else
        {
          VMOVE8(s_h1[i + 1], rb + (0x80 >> 2));
          MEMW();
        }
      }
      PCC(b3);
      SPIN(t, (NB && i > 0) ? cfg.wn : (i + 1 < cnt ? cfg.wb : cfg.wl));
      PCC(b4);
      const uint32_t h7 = RLD(O_H(7));
      if (PROF)
      {
        const uint32_t b5 = CCOUNT();
        s_prof[4] += b1 - b0; s_prof[5] += t - b1; s_prof[6] += b3 - t; s_prof[7] += b4 - b3; s_prof[8] += b5 - b4;
      }
      if (ALL)
        out7[n + i - start] = h7;
      else if ((h7 >> 16) == 0)
        t5_cand(ctx, n + i, h7, NB && i > 0);
    }
    if (PROF) s_prof[10] += CCOUNT() - pb0;
    n += cnt;
    if (!ALL && *cur_job != job_in_work)
      break;
  }
  //never hand the engine back mid-block (a too-short delay during calibration)
  MEMW();
  while (RLD(O_BUSY)) {}
  return n - start;
}

static IRAM_ATTR __attribute__((noinline)) uint32_t t5_run(T5_ARGS) { return s_nb ? t5_body<false, false, true>(mid, w, n, end, job_in_work, cur_job, ctx, out1, out7) : t5_body<false>(mid, w, n, end, job_in_work, cur_job, ctx, out1, out7); }
static IRAM_ATTR __attribute__((noinline)) uint32_t t5_prof(T5_ARGS) { return s_nb ? t5_body<false, true, true>(mid, w, n, end, job_in_work, cur_job, ctx, out1, out7) : t5_body<false, true>(mid, w, n, end, job_in_work, cur_job, ctx, out1, out7); }
static IRAM_ATTR __attribute__((noinline)) uint32_t t5_all(T5_ARGS) { return s_nb ? t5_body<true, false, true>(mid, w, n, end, job_in_work, cur_job, ctx, out1, out7) : t5_body<true>(mid, w, n, end, job_in_work, cur_job, ctx, out1, out7); }

//256 consecutive nonces (2 batches) on two headers: every first digest and every H7
//compared with mbedTLS
static bool t5_selftest()
{
  static uint32_t out1[256][8];
  static uint32_t out7[256];
  for (uint32_t seed = 0; seed < 2; ++seed)
  {
    uint8_t hdr[128];
    test_header(hdr, seed + 5);
    uint32_t mid[8], w[16];
    memcpy(w, hdr + 64, sizeof(w));
    const uint32_t n0 = seed ? 0xFFFFFE00 : 0x8765;
    esp_sha_acquire_hardware();
    hw_midstate(hdr, mid);
    t5_all(mid, w, n0, n0 + 256, 0, nullptr, nullptr, out1, out7);
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
      if (memcmp(h1, out1[k], 32) != 0 || w7 != out7[k])
      {
        s_t5_fail = (seed << 16) | k | (w7 != out7[k] ? 0x80000000u : 0);
        return false;
      }
    }
  }
  return true;
}

static bool t5_pass(int runs)
{
  for (int r = 0; r < runs; ++r)
    if (!t5_selftest()) return false;
  return true;
}

static uint32_t t5_bench()
{
  uint8_t hdr[128];
  test_header(hdr, 9);
  uint32_t mid[8], w[16];
  memcpy(w, hdr + 64, sizeof(w));
  JobResult r;
  r.difficulty = 1e30;
  Ctx c = {&r, hdr, false};
  volatile uint8_t job = 0;
  uint32_t best = 0xFFFFFFFF;
  for (int k = 0; k < 3; ++k)
  {
    esp_sha_acquire_hardware();
    hw_midstate(hdr, mid);
    const uint32_t c0 = turbo_cycles();
    const uint32_t done = t5_run(mid, w, 0, 8192, 0, &job, &c, nullptr, nullptr);
    const uint32_t cyc = turbo_cycles() - c0;
    esp_sha_release_hardware();
    if (c.bad) return 0xFFFFFFFF;
    if (done && cyc / done < best) best = cyc / done;
  }
  return best;
}

//Probe: cycles after START (landed) until H7 changes, interrupts off; -1 = not before
//the block ends
static IRAM_ATTR int32_t t5_h7chg_probe()
{
  uint32_t * const rb = (uint32_t *)DR_REG_SHA_BASE;
  int32_t res = -1;
  esp_sha_acquire_hardware();
  RST(O_MODE, SHA2_256);
  for (uint32_t d = 0; d < 140 && res < 0; d += 2)
  {
    for (int i = 0; i < 16; ++i) ((volatile uint32_t *)rb)[(0x80 >> 2) + i] = 0x01234567u * (i + 3);
    RST(O_START, 1);
    MEMW();
    while (RLD(O_BUSY)) {}
    const uint32_t old = RLD(O_H(7));
    for (int i = 0; i < 16; ++i) ((volatile uint32_t *)rb)[(0x80 >> 2) + i] = 0x89ABCDEFu * (i + 5);
    portDISABLE_INTERRUPTS();
    RST(O_START, 1);
    MEMW();
    const uint32_t t = CCOUNT();
    SPIN(t, d);
    const uint32_t v = RLD(O_H(7));
    portENABLE_INTERRUPTS();
    MEMW();
    while (RLD(O_BUSY)) {}
    if (v != old) res = d;
  }
  esp_sha_release_hardware();
  return res;
}


//Probe: does bus traffic during a block delay the engine? For each case, the fewest
//cycles after the anchor (load after START) at which H7 reads final: [quiet, 8 scalar
//TEXT stores, 8 TEXT stores by PIE + MEMW, 8 BUSY loads]; ep[4] = 1 if TEXT is latched
//at START (different words written during the block leave the digest unchanged)
static volatile uint32_t s_ep[5] = {0};
static IRAM_ATTR uint32_t ep_case(int kind, const uint32_t *tx, const uint32_t *alt, uint32_t want)
{
  uint32_t * const rb = (uint32_t *)DR_REG_SHA_BASE;
  static uint32_t vbuf[8] __attribute__((aligned(16)));
  memcpy(vbuf, kind == 4 ? alt : tx, 32);
  for (uint32_t d = 0; d < 400; d += 2)
  {
    bool ok = true;
    for (int rep = 0; rep < 8 && ok; ++rep)
    {
      for (int i = 0; i < 16; ++i) ((volatile uint32_t *)rb)[(0x80 >> 2) + i] = tx[i];
      MEMW();
      portDISABLE_INTERRUPTS();
      RST(O_START, 1);
      MEMW();
      (void)RLD(O_BUSY);
      const uint32_t t = CCOUNT();
      if (kind == 1)
      {
        for (int i = 0; i < 8; ++i) ((volatile uint32_t *)rb)[(0x80 >> 2) + i] = tx[i];
      }
      else if (kind == 2 || kind == 4)
      {
        VMOVE8(vbuf, rb + (0x80 >> 2));
        MEMW();
      }
      else if (kind == 3)
      {
        for (int i = 0; i < 8; ++i) (void)RLD(O_BUSY);
      }
      SPIN(t, d);
      const uint32_t v = RLD(O_H(7));
      portENABLE_INTERRUPTS();
      MEMW();
      while (RLD(O_BUSY)) {}
      if (v != want) ok = false;
    }
    if (ok) return d;
  }
  return 999;
}

static void t5_engine_probe()
{
  uint32_t * const rb = (uint32_t *)DR_REG_SHA_BASE;
  uint32_t tx[16], alt[8];
  for (int i = 0; i < 16; ++i) tx[i] = 0x01234567u * (i + 3);
  for (int i = 0; i < 8; ++i) alt[i] = 0x89ABCDEFu * (i + 5);
  esp_sha_acquire_hardware();
  RST(O_MODE, SHA2_256);
  for (int i = 0; i < 16; ++i) ((volatile uint32_t *)rb)[(0x80 >> 2) + i] = tx[i];
  MEMW();
  RST(O_START, 1);
  MEMW();
  while (RLD(O_BUSY)) {}
  const uint32_t want = RLD(O_H(7));
  for (int k = 0; k < 4; ++k) s_ep[k] = ep_case(k, tx, alt, want);
  s_ep[4] = ep_case(4, tx, alt, want) < 999 ? 1 : 0;
  esp_sha_release_hardware();
}

//Returns cycles per nonce of the picked delays, 0 if t5 failed its self-test
static uint32_t t5_pick()
{
  t5_engine_probe();
  s_h7chg = t5_h7chg_probe();
  s_t5 = {200, 200, 200, 200};
  if (s_ep[0] && s_ep[0] < 999)
    s_t5.wl = s_ep[0] + T5_LAST_MARGIN;
  s_t5_stage = 1;
  if (!t5_pass(2)) return 0;
  uint32_t d;
  for (d = 60; d < 200; d += 2) { s_t5.wb = d; if (t5_pass(8)) break; }
  s_t5_min[1] = d;
  for (d = 60; d < 200; d += 2) { s_t5.wa = d; if (t5_pass(8)) break; }
  s_t5_min[0] = d;
  s_t5.wa = s_t5_min[0] + T5_MARGIN;
  s_t5.wb = s_t5_min[1] + T5_MARGIN;
  s_t5_stage = 2;
  if (!t5_pass(16)) return 0;
  s_t5_stage = 3;
  const uint32_t c = t5_bench();
  if (c != 0xFFFFFFFF) s_t5_stage = 9;
  {
    //one profiled run over 8192 nonces, interrupts off; s_prof becomes cycles per nonce
    uint8_t hdr[128];
    test_header(hdr, 9);
    uint32_t mid[8], w[16];
    memcpy(w, hdr + 64, sizeof(w));
    JobResult r;
    r.difficulty = 1e30;
    Ctx cx = {&r, hdr, false};
    volatile uint8_t job = 0;
    memset(s_prof, 0, sizeof(s_prof));
    esp_sha_acquire_hardware();
    hw_midstate(hdr, mid);
    portDISABLE_INTERRUPTS();
    const uint32_t c0 = CCOUNT();
    const uint32_t done = t5_prof(mid, w, 0, 8192, 0, &job, &cx, nullptr, nullptr);
    s_prof[11] = CCOUNT() - c0;
    portENABLE_INTERRUPTS();
    esp_sha_release_hardware();
    for (int k = 0; k < 12; ++k) s_prof[k] = done ? (s_prof[k] * 10 + done / 2) / done : 0;   //tenths of a cycle
  }
  return c == 0xFFFFFFFF ? 0 : c;
}

//Split burst (SENSITIVE_APB_PERIPHERAL_ACCESS_SPLIT_BURST, default 1): with it off the PIE
//digest moves and the stores to the SHA registers are ~13% cheaper per nonce (bus_bench.inc).
//s_split0 is picked at boot (turbo_split_pick) and only set around the t5 loop.
#include <soc/sensitive_reg.h>
static bool s_split0 = false;
static uint32_t s_sb[3] = {0, 0, 0};   //boot bench, t5 cycles/nonce x10: split on, split off; then
                                       //0 not run, 1 used, 2 last trial hung, 3 self-test failed, 4 not faster, 5 crash after use
static inline void bb_split(uint32_t v)
{
  REG_WRITE(SENSITIVE_APB_PERIPHERAL_ACCESS_1_REG, v);
  MEMW();
  (void)REG_READ(SENSITIVE_APB_PERIPHERAL_ACCESS_1_REG);
}

static void t5_job(const JobRequest &job, JobResult &result, volatile uint8_t &cur_job, Ctx &c)
{
  static uint32_t jobs = 0;
  uint32_t mid[8], w[16];
  memcpy(mid, job.midstate, sizeof(mid));
  memcpy(w, job.sha_buffer + 64, sizeof(w));
  if ((jobs++ & 7) == 0)
  {
    static uint32_t out1[T5_CHECK_N][8], out7[T5_CHECK_N];
    const bool nb = s_nb;
    esp_sha_acquire_hardware();
    if (s_split0) bb_split(0);
    t5_all(mid, w, job.nonce_start, job.nonce_start + T5_CHECK_N, 0, nullptr, nullptr, out1, out7);
    if (s_split0) bb_split(1);
    esp_sha_release_hardware();
    s_checks++;
    if (nb) s_nb_chk += T5_CHECK_N - 1;
    uint32_t nbad = 0;
    for (int k = 0; k < T5_CHECK_N; ++k)
    {
      uint8_t b[80], h1[32], want[32];
      memcpy(b, job.sha_buffer, 80);
      const uint32_t nonce = job.nonce_start + k;
      memcpy(b + 76, &nonce, 4);
      mbedtls_sha256_ret(b, 80, h1, 0);
      mbedtls_sha256_ret(h1, 32, want, 0);
      uint32_t w7;
      memcpy(&w7, want + 28, 4);
      if (memcmp(h1, out1[k], 32) != 0 || w7 != out7[k])
      {
        if (nb && k > 0 && memcmp(h1, out1[k], 32) == 0)
        {
          nbad++;   //an early H7 read on an unanchored nonce: costs that nonce only
          continue;
        }
        s_bad++;
        c.bad = true;
        result.nonce_count = 0;
        return;
      }
    }
    if (nbad)
    {
      s_nb_bad += nbad;
      if (++s_nb_bumps >= NB_BUMPS) s_nb = false;
      else s_t5.wn += NB_BUMP;
    }
  }
  esp_sha_acquire_hardware();
  if (s_split0) bb_split(0);
  const bool nbr = s_nb;
  result.nonce_count = t5_run(mid, w, job.nonce_start, job.nonce_start + job.nonce_count,
                              job.id & 0xFF, &cur_job, &c, nullptr, nullptr);
  if (nbr)
  {
    static uint32_t frac = 0;
    frac += result.nonce_count;
    s_nb_n16 += frac >> 16;
    frac &= 0xFFFF;
    //miss rate > 1%: fc * 65536 > n / 100  <=>  fc * 100 > n16 (after 8 false cands)
    if (s_nb_fc >= 8 && s_nb_fc * 100 > s_nb_n16)
      s_nb = false;
  }
  if (s_split0) bb_split(1);
  esp_sha_release_hardware();
}

//---------------------------------------------------------------------------------

static bool s_t1_ok = false;

#include "bus_bench.inc"
#include "exp_bench.inc"

void turbo_hw_init()
{
  crash_guard_boot();
  const bool stock_ok = t1_selftest<false>(s_t1_cpn[1]);
  s_t1_ok = stock_ok && t1_selftest<true>(s_t1_cpn[0]);
  s_mode = s_t1_ok ? MODE_T1 : MODE_STOCK;
  if (s_t1_ok && !s_safe_mode)
  {
    const uint32_t c = t4_pick();
    if (c && c < s_t1_cpn[0])
    {
      s_mode = MODE_T4;
      s_t4_cpn_now = c;
    }
    const uint32_t now = s_mode == MODE_T4 ? c : s_t1_cpn[0];
    const uint32_t c5 = t5_pick();
    s_t5_cpn = c5;
    if (c5 && c5 < now)
      s_mode = MODE_T5;
#ifdef NM_WIRED
    //tested with Wi-Fi off only (the Wi-Fi build keeps the chip default)
    if (s_mode == MODE_T5)
    {
      turbo_split_pick();
      turbo_nb_pick();
    }
#endif
  }
  Serial.printf("[MINER] HW engine %s, split burst %s (sb %u)\n", turbo_hw_mode_name(), s_split0 ? "off" : "on", (unsigned)s_sb[2]);
}

void turbo_hw_job(const JobRequest &job, JobResult &result, volatile uint8_t &cur_job)
{
  if (s_xreq)
  {
    s_xreq = 0;
    turbo_exp_bench(s_xbuf, s_xlen);
    s_xdone = 1;
  }
  Ctx c = {&result, job.sha_buffer, false};
  result.nonce_count = job.nonce_count;
  switch (s_mode)
  {
    case MODE_T5: t5_job(job, result, cur_job, c); break;
    case MODE_T4: t4_job(job, result, cur_job, c); break;
    case MODE_T1: t1_job<true>(job, result, cur_job, c); break;
    default: t1_job<false>(job, result, cur_job, c); break;
  }
  if (c.bad && s_mode == MODE_T5 && s_t5_bumps < T5_BUMPS)
  {
    //a delay too close to the edge: give both a little more and stay on t5
    s_t5_bumps++;
    s_t5.wa += T5_BUMP;
    s_t5.wb += T5_BUMP;
    s_t5.wl += T5_BUMP;
    s_t5.wn += T5_BUMP;
    Serial.printf("[MINER] t5 mismatch, delays now %u/%u\n", (unsigned)s_t5.wa, (unsigned)s_t5.wb);
  }
  else if (c.bad)
  {
    //the engine got a hash wrong: one step down for the rest of this boot
    if (s_mode == MODE_T5)
      s_mode = s_t4_cpn_now ? MODE_T4 : s_t1_ok ? MODE_T1 : MODE_STOCK;
    else
      s_mode = (s_mode == MODE_T4 && s_t1_ok) ? MODE_T1 : MODE_STOCK;
    Serial.printf("[MINER] HW mismatch, engine now %s\n", turbo_hw_mode_name());
  }
}

const char *turbo_hw_mode_name()
{
  return s_mode == MODE_T5 ? "t5" : s_mode == MODE_T4 ? "t4" : s_mode == MODE_T1 ? "t1" : "stock";
}

int turbo_hw_status(char *buf, size_t len)
{
  const uint32_t cpn = s_mode == MODE_T5 ? s_t5_cpn : s_mode == MODE_T4 ? s_t4_cpn_now : s_mode == MODE_T1 ? s_t1_cpn[0] : s_t1_cpn[1];
  return snprintf(buf, len,
    "\"mode\":\"%s\",\"safe\":%s,\"cpn\":%u,\"chk\":%u,\"cand\":%u,\"bad\":%u,\"t1\":[%u,%u],"
    "\"t4\":{\"da\":%u,\"db\":%u,\"pa\":%u,\"pb\":%u,\"v\":%u,\"min\":[%u,%u],\"cpn\":[%u,%u,%u,%u],\"fail\":%u},"
    "\"t5\":{\"wa\":%u,\"wb\":%u,\"wl\":%u,\"min\":[%u,%u],\"cpn\":%u,\"h7chg\":%d,\"stage\":%u,\"fail\":%u,\"bumps\":%u,\"prof\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u],\"ep\":[%u,%u,%u,%u,%u],\"sb\":[%u,%u,%u],\"nb\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u]}",
    turbo_hw_mode_name(), s_safe_mode ? "true" : "false", (unsigned)cpn, (unsigned)s_checks,
    (unsigned)s_cands, (unsigned)s_bad, (unsigned)s_t1_cpn[0], (unsigned)s_t1_cpn[1],
    (unsigned)s_t4.da, (unsigned)s_t4.db, (unsigned)s_t4.pa, (unsigned)s_t4.pb, (unsigned)s_t4.v,
    (unsigned)s_t4_min[0], (unsigned)s_t4_min[1],
    (unsigned)s_t4_cpn[0], (unsigned)s_t4_cpn[1], (unsigned)s_t4_cpn[2], (unsigned)s_t4_cpn[3],
    (unsigned)s_fail, (unsigned)s_t5.wa, (unsigned)s_t5.wb, (unsigned)s_t5.wl, (unsigned)s_t5_min[0], (unsigned)s_t5_min[1],
    (unsigned)s_t5_cpn, (int)s_h7chg, (unsigned)s_t5_stage, (unsigned)s_t5_fail, (unsigned)s_t5_bumps, (unsigned)s_prof[0], (unsigned)s_prof[1], (unsigned)s_prof[2], (unsigned)s_prof[3],
    (unsigned)s_prof[4], (unsigned)s_prof[5], (unsigned)s_prof[6], (unsigned)s_prof[7], (unsigned)s_prof[8],
    (unsigned)s_prof[9], (unsigned)s_prof[10], (unsigned)s_prof[11],
    (unsigned)s_ep[0], (unsigned)s_ep[1], (unsigned)s_ep[2], (unsigned)s_ep[3], (unsigned)s_ep[4],
    (unsigned)s_sb[0], (unsigned)s_sb[1], (unsigned)s_sb[2],
    (unsigned)s_nb, (unsigned)s_nbst[0], (unsigned)s_nbst[1], (unsigned)s_nbst[2], (unsigned)s_nbst[3], (unsigned)s_t5.wn, (unsigned)s_nb_chk, (unsigned)s_nb_bad, (unsigned)s_nb_bumps, (unsigned)s_nb_fc, (unsigned)s_nb_n16);
}

#endif //NM_TURBO
