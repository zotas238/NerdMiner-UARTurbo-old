//SHA engine and bus probes: measurements for tuning turbo_hw.cpp, not needed to mine.
//Built only with -D NM_TURBO_PROBES; the HW miner then runs them once at boot (after
//picking its engine) and the status port shows them as "probe":{...}.
#if defined(NM_TURBO) && defined(NM_TURBO_PROBES)

#include <Arduino.h>
#include <string.h>
#include <esp_attr.h>
#include <sha/sha_dma.h>
#include <hal/sha_hal.h>
#include <hal/sha_ll.h>
#include "turbo_probe.h"

#define T2_ST(off, v) asm volatile("s32i %0, %1, %2" :: "r"((uint32_t)(v)), "r"(t2b), "i"(off) : "memory")
#define T2_LD(off) ({ uint32_t _r; asm volatile("l32i %0, %1, %2" : "=r"(_r) : "r"(t2b), "i"(off) : "memory"); _r; })
#define T2_MEMW() asm volatile("memw" ::: "memory")
#define T2_WAIT() do { T2_MEMW(); while (T2_LD(0x18)) {} } while (0)
#define T2_CC() ({ uint32_t _c; asm volatile("rsr.ccount %0" : "=r"(_c) :: "memory"); _c; })
#define T3_SPIN(t0, d) do { while ((uint32_t)(T2_CC() - (t0)) < (d)) {} } while (0)
#define T2_H(i) (0x40 + 4 * (i))
#define T2_T(i) (0x80 + 4 * (i))

//---------------------------------------------------------------------------------
//Probes: measurements only
//  wc/ws: per H word, fewest cycles after CONTINUE/START (+MEMW) at which a single load
//         of that word reads the final value (8 tries each)
//  pat:   cycles of bus patterns on an idle engine: [4LD4ST x2, LD/ST alternating x8,
//         8LD then 8ST, 16ST+MEMW, 16LD]
//  dual:  [solo 64 loads, this core 64 loads with the other core loading too, other
//          core's 64 loads, solo 64 stores, dual stores this core, other core]
//  pie:   0 not tried, 1 crashed last time, 2 128-bit load/store ok, 3 data mismatch;
//         pcyc: [vld 2x128, scalar 8 loads, vst 2x128, scalar 8 stores]

char g_t4_json[768] = "{}";
RTC_NOINIT_ATTR static uint32_t s_t4_pie_magic;

static IRAM_ATTR void t4_block(uint32_t *t2b, bool cont, const uint32_t *mid)
{
  if (cont)
    for (int i = 0; i < 8; ++i) ((volatile uint32_t *)t2b)[(0x40 >> 2) + i] = mid[i];
  else
    for (int i = 0; i < 8; ++i) ((volatile uint32_t *)t2b)[(0x40 >> 2) + i] = 0xA5A5A5A5u ^ i;
  for (int i = 0; i < 16; ++i)
    ((volatile uint32_t *)t2b)[(0x80 >> 2) + i] = 0x01234567u * (i + 3);
}

static IRAM_ATTR void t4_wordtime(bool cont, uint16_t out[8])
{
  uint32_t * const t2b = (uint32_t *)DR_REG_SHA_BASE;
  uint32_t mid[8], ref[8];
  for (int i = 0; i < 8; ++i) mid[i] = 0x9E3779B9u * (i + 1);
  T2_ST(0x00, SHA2_256);
  t4_block(t2b, cont, mid);
  T2_MEMW();
  if (cont) T2_ST(0x14, 1); else T2_ST(0x10, 1);
  T2_WAIT();
  for (int i = 0; i < 8; ++i) ref[i] = ((volatile uint32_t *)t2b)[(0x40 >> 2) + i];
  for (int w = 0; w < 8; ++w)
  {
    out[w] = 0;
    for (uint32_t d = 1; d < 320; ++d)
    {
      bool all = true;
      for (int k = 0; k < 8 && all; ++k)
      {
        t4_block(t2b, cont, mid);
        uint32_t v;
        portDISABLE_INTERRUPTS();
        T2_MEMW();
        if (cont) T2_ST(0x14, 1); else T2_ST(0x10, 1);
        T2_MEMW();
        const uint32_t t0 = T2_CC();
        T3_SPIN(t0, d);
        v = ((volatile uint32_t *)t2b)[(0x40 >> 2) + w];
        portENABLE_INTERRUPTS();
        T2_WAIT();
        if (v != ref[w]) all = false;
      }
      if (all) { out[w] = d; break; }
    }
  }
}

static IRAM_ATTR void t4_patterns(uint32_t out[5])
{
  uint32_t * const t2b = (uint32_t *)DR_REG_SHA_BASE;
  for (int i = 0; i < 5; ++i) out[i] = ~0u;
  for (int k = 0; k < 16; ++k)
  {
    uint32_t c0, a, b, c, d, e, f, g, h;
    portDISABLE_INTERRUPTS();
    T2_MEMW(); c0 = T2_CC();
    a = T2_LD(T2_H(0)); b = T2_LD(T2_H(1)); c = T2_LD(T2_H(2)); d = T2_LD(T2_H(3));
    T2_ST(T2_T(0), a); T2_ST(T2_T(1), b); T2_ST(T2_T(2), c); T2_ST(T2_T(3), d);
    a = T2_LD(T2_H(4)); b = T2_LD(T2_H(5)); c = T2_LD(T2_H(6)); d = T2_LD(T2_H(7));
    T2_ST(T2_T(4), a); T2_ST(T2_T(5), b); T2_ST(T2_T(6), c); T2_ST(T2_T(7), d);
    T2_MEMW(); uint32_t c1 = T2_CC();
    a = T2_LD(T2_H(0)); T2_ST(T2_T(0), a); b = T2_LD(T2_H(1)); T2_ST(T2_T(1), b);
    a = T2_LD(T2_H(2)); T2_ST(T2_T(2), a); b = T2_LD(T2_H(3)); T2_ST(T2_T(3), b);
    a = T2_LD(T2_H(4)); T2_ST(T2_T(4), a); b = T2_LD(T2_H(5)); T2_ST(T2_T(5), b);
    a = T2_LD(T2_H(6)); T2_ST(T2_T(6), a); b = T2_LD(T2_H(7)); T2_ST(T2_T(7), b);
    T2_MEMW(); uint32_t c2 = T2_CC();
    a = T2_LD(T2_H(0)); b = T2_LD(T2_H(1)); c = T2_LD(T2_H(2)); d = T2_LD(T2_H(3));
    e = T2_LD(T2_H(4)); f = T2_LD(T2_H(5)); g = T2_LD(T2_H(6)); h = T2_LD(T2_H(7));
    T2_ST(T2_T(0), a); T2_ST(T2_T(1), b); T2_ST(T2_T(2), c); T2_ST(T2_T(3), d);
    T2_ST(T2_T(4), e); T2_ST(T2_T(5), f); T2_ST(T2_T(6), g); T2_ST(T2_T(7), h);
    T2_MEMW(); uint32_t c3 = T2_CC();
    T2_ST(T2_T(0), a); T2_ST(T2_T(1), b); T2_ST(T2_T(2), c); T2_ST(T2_T(3), d);
    T2_ST(T2_T(4), e); T2_ST(T2_T(5), f); T2_ST(T2_T(6), g); T2_ST(T2_T(7), h);
    T2_ST(T2_T(8), a); T2_ST(T2_T(9), b); T2_ST(T2_T(10), c); T2_ST(T2_T(11), d);
    T2_ST(T2_T(12), e); T2_ST(T2_T(13), f); T2_ST(T2_T(14), g); T2_ST(T2_T(15), h);
    T2_MEMW(); uint32_t c4 = T2_CC();
    volatile uint32_t sink = T2_LD(T2_H(0)) + T2_LD(T2_H(1)) + T2_LD(T2_H(2)) + T2_LD(T2_H(3))
      + T2_LD(T2_H(4)) + T2_LD(T2_H(5)) + T2_LD(T2_H(6)) + T2_LD(T2_H(7))
      + T2_LD(T2_T(0)) + T2_LD(T2_T(1)) + T2_LD(T2_T(2)) + T2_LD(T2_T(3))
      + T2_LD(T2_T(4)) + T2_LD(T2_T(5)) + T2_LD(T2_T(6)) + T2_LD(T2_T(7));
    (void)sink;
    uint32_t c5 = T2_CC();
    portENABLE_INTERRUPTS();
    uint32_t v[5] = {c1 - c0, c2 - c1, c3 - c2, c4 - c3, c5 - c4};
    for (int i = 0; i < 5; ++i) if (v[i] < out[i]) out[i] = v[i];
  }
}

//Two cores on the SHA bus at once
static volatile uint32_t s_t4_go = 0, s_t4_done = 0, s_t4_other[2] = {0};
static IRAM_ATTR uint32_t t4_loads(uint32_t off)
{
  uint32_t * const t2b = (uint32_t *)DR_REG_SHA_BASE;
  volatile uint32_t sink = 0;
  T2_MEMW();
  uint32_t c0 = T2_CC();
  for (int i = 0; i < 8; ++i)
  {
    uint32_t s = 0;
    s += ((volatile uint32_t *)t2b)[off]; s += ((volatile uint32_t *)t2b)[off]; s += ((volatile uint32_t *)t2b)[off]; s += ((volatile uint32_t *)t2b)[off];
    s += ((volatile uint32_t *)t2b)[off]; s += ((volatile uint32_t *)t2b)[off]; s += ((volatile uint32_t *)t2b)[off]; s += ((volatile uint32_t *)t2b)[off];
    sink += s;
  }
  return T2_CC() - c0;
}
static IRAM_ATTR uint32_t t4_stores(uint32_t off)
{
  uint32_t * const t2b = (uint32_t *)DR_REG_SHA_BASE;
  T2_MEMW();
  uint32_t c0 = T2_CC();
  for (int i = 0; i < 8; ++i)
  {
    uint32_t *p = t2b + off;
    asm volatile("s32i %0, %1, 0\n s32i %0, %1, 0\n s32i %0, %1, 0\n s32i %0, %1, 0\n"
                 "s32i %0, %1, 0\n s32i %0, %1, 0\n s32i %0, %1, 0\n s32i %0, %1, 0\n" :: "r"(i), "r"(p) : "memory");
  }
  T2_MEMW();
  return T2_CC() - c0;
}
static IRAM_ATTR void t4_helper(void *)
{
  for (int round = 0; round < 2; ++round)
  {
    while (s_t4_go != (uint32_t)(round + 1)) {}
    portDISABLE_INTERRUPTS();
    s_t4_other[round] = round == 0 ? t4_loads((0x40 >> 2) + 4) : t4_stores((0x80 >> 2) + 12);
    portENABLE_INTERRUPTS();
    s_t4_done = round + 1;
  }
  vTaskDelete(NULL);
}
static IRAM_ATTR void t4_dual(uint32_t out[6])
{
  uint32_t best_solo_l = ~0u, best_solo_s = ~0u;
  for (int k = 0; k < 8; ++k)
  {
    portDISABLE_INTERRUPTS();
    uint32_t l = t4_loads(0x40 >> 2), s = t4_stores(0x80 >> 2);
    portENABLE_INTERRUPTS();
    if (l < best_solo_l) best_solo_l = l;
    if (s < best_solo_s) best_solo_s = s;
  }
  out[0] = best_solo_l; out[3] = best_solo_s;
  s_t4_go = 0; s_t4_done = 0;
  const int other = xPortGetCoreID() ^ 1;
  if (xTaskCreatePinnedToCore(t4_helper, "t4h", 2048, nullptr, configMAX_PRIORITIES - 1, nullptr, other) != pdPASS)
    return;
  vTaskDelay(20 / portTICK_PERIOD_MS);
  for (int round = 0; round < 2; ++round)
  {
    portDISABLE_INTERRUPTS();
    s_t4_go = round + 1;
    uint32_t c = round == 0 ? t4_loads(0x40 >> 2) : t4_stores(0x80 >> 2);
    portENABLE_INTERRUPTS();
    uint32_t t0 = millis();
    while (s_t4_done != (uint32_t)(round + 1) && millis() - t0 < 100) {}
    out[round == 0 ? 1 : 4] = c;
    out[round == 0 ? 2 : 5] = s_t4_other[round];
  }
}

//128-bit PIE load/store on the SHA registers (may fault: guarded across resets)
static IRAM_ATTR uint32_t t4_pie(uint32_t cyc[4])
{
  if (s_t4_pie_magic == 0x7E40C0DEu) { s_t4_pie_magic = 0x7E40D0E1u; return 1; }
  if (s_t4_pie_magic == 0x7E40D0E1u) return 1;   //crashed before: never again
  s_t4_pie_magic = 0x7E40C0DEu;
  uint32_t * const t2b = (uint32_t *)DR_REG_SHA_BASE;
  uint32_t ref[8], got[8] __attribute__((aligned(16)));
  for (int i = 0; i < 8; ++i) ref[i] = ((volatile uint32_t *)t2b)[(0x40 >> 2) + i];
  uint32_t *hp = t2b + (0x40 >> 2);
  uint32_t c0, c1, c2, c3, c4;
  portDISABLE_INTERRUPTS();
  T2_MEMW(); c0 = T2_CC();
  asm volatile("ee.vld.128.ip q0, %0, 16\n ee.vld.128.ip q1, %0, 16\n" : "+r"(hp) :: "memory");
  c1 = T2_CC();
  uint32_t *gp = got;
  asm volatile("ee.vst.128.ip q0, %0, 16\n ee.vst.128.ip q1, %0, 16\n" : "+r"(gp) :: "memory");
  c2 = T2_CC();
  volatile uint32_t sink = T2_LD(T2_H(0)) + T2_LD(T2_H(1)) + T2_LD(T2_H(2)) + T2_LD(T2_H(3))
                         + T2_LD(T2_H(4)) + T2_LD(T2_H(5)) + T2_LD(T2_H(6)) + T2_LD(T2_H(7));
  (void)sink;
  c3 = T2_CC();
  uint32_t *tp = t2b + (0x80 >> 2);
  T2_MEMW(); uint32_t c5 = T2_CC();
  asm volatile("ee.vst.128.ip q0, %0, 16\n ee.vst.128.ip q1, %0, 16\n memw\n" : "+r"(tp) :: "memory");
  c4 = T2_CC();
  T2_ST(T2_T(0), 1); T2_ST(T2_T(1), 1); T2_ST(T2_T(2), 1); T2_ST(T2_T(3), 1);
  T2_ST(T2_T(4), 1); T2_ST(T2_T(5), 1); T2_ST(T2_T(6), 1); T2_ST(T2_T(7), 1);
  T2_MEMW(); uint32_t c6 = T2_CC();
  portENABLE_INTERRUPTS();
  cyc[0] = c1 - c0; cyc[1] = c3 - c2; cyc[2] = c4 - c5; cyc[3] = c6 - c4;
  //read back what the vector store wrote into TEXT
  bool ok = memcmp(ref, got, 32) == 0;
  T2_ST(0x00, SHA2_256);
  s_t4_pie_magic = 0x7E40600Du;
  return ok ? 2 : 3;
}


//Turbo4 PIE timing: min over 16 runs, interrupts off, after a warm-up (the first PIE
//instruction traps once to enable the coprocessor).
//p2: [2 vld H, 8 ld H, 2 vst T+memw, 8 st T+memw, 4 vst T+memw, 16 st T+memw,
//     copy H->T vector (2 vld 2 vst memw), copy scalar, 2 vst H+memw, 8 st H+memw]
//p2ok: vector copy H->T then START gives the same digest as the scalar copy
uint32_t g_t4_p2[10] = {0};
uint32_t g_t4_p2ok = 0;
#define VLD2(p) asm volatile("ee.vld.128.ip q0, %0, 16\n ee.vld.128.ip q1, %0, 16\n" : "+r"(p) :: "memory")
#define VST2(p) asm volatile("ee.vst.128.ip q0, %0, 16\n ee.vst.128.ip q1, %0, 16\n" : "+r"(p) :: "memory")
static IRAM_ATTR void t4_pie2()
{
  if (s_t4_pie_magic == 0x7E40D0E1u) return;
  uint32_t * const t2b = (uint32_t *)DR_REG_SHA_BASE;
  for (int i = 0; i < 10; ++i) g_t4_p2[i] = ~0u;
  uint32_t *p = t2b + (0x40 >> 2);
  VLD2(p);   //warm-up trap
  for (int k = 0; k < 16; ++k)
  {
    uint32_t c[11];
    uint32_t a, b, cc, d, e, f, g, h;
    portDISABLE_INTERRUPTS();
    T2_MEMW(); c[0] = T2_CC();
    p = t2b + (0x40 >> 2); VLD2(p);
    c[1] = T2_CC();
    a = T2_LD(T2_H(0)); b = T2_LD(T2_H(1)); cc = T2_LD(T2_H(2)); d = T2_LD(T2_H(3));
    e = T2_LD(T2_H(4)); f = T2_LD(T2_H(5)); g = T2_LD(T2_H(6)); h = T2_LD(T2_H(7));
    c[2] = T2_CC();
    p = t2b + (0x80 >> 2); VST2(p); T2_MEMW();
    c[3] = T2_CC();
    T2_ST(T2_T(0), a); T2_ST(T2_T(1), b); T2_ST(T2_T(2), cc); T2_ST(T2_T(3), d);
    T2_ST(T2_T(4), e); T2_ST(T2_T(5), f); T2_ST(T2_T(6), g); T2_ST(T2_T(7), h); T2_MEMW();
    c[4] = T2_CC();
    p = t2b + (0x80 >> 2); VST2(p); VST2(p); T2_MEMW();
    c[5] = T2_CC();
    T2_ST(T2_T(0), a); T2_ST(T2_T(1), b); T2_ST(T2_T(2), cc); T2_ST(T2_T(3), d);
    T2_ST(T2_T(4), e); T2_ST(T2_T(5), f); T2_ST(T2_T(6), g); T2_ST(T2_T(7), h);
    T2_ST(T2_T(8), a); T2_ST(T2_T(9), b); T2_ST(T2_T(10), cc); T2_ST(T2_T(11), d);
    T2_ST(T2_T(12), e); T2_ST(T2_T(13), f); T2_ST(T2_T(14), g); T2_ST(T2_T(15), h); T2_MEMW();
    c[6] = T2_CC();
    p = t2b + (0x40 >> 2); VLD2(p); p = t2b + (0x80 >> 2); VST2(p); T2_MEMW();
    c[7] = T2_CC();
    a = T2_LD(T2_H(0)); b = T2_LD(T2_H(1)); cc = T2_LD(T2_H(2)); d = T2_LD(T2_H(3));
    T2_ST(T2_T(0), a); T2_ST(T2_T(1), b); T2_ST(T2_T(2), cc); T2_ST(T2_T(3), d);
    a = T2_LD(T2_H(4)); b = T2_LD(T2_H(5)); cc = T2_LD(T2_H(6)); d = T2_LD(T2_H(7));
    T2_ST(T2_T(4), a); T2_ST(T2_T(5), b); T2_ST(T2_T(6), cc); T2_ST(T2_T(7), d); T2_MEMW();
    c[8] = T2_CC();
    p = t2b + (0x40 >> 2); VST2(p); T2_MEMW();
    c[9] = T2_CC();
    T2_ST(T2_H(0), a); T2_ST(T2_H(1), b); T2_ST(T2_H(2), cc); T2_ST(T2_H(3), d);
    T2_ST(T2_H(4), e); T2_ST(T2_H(5), f); T2_ST(T2_H(6), g); T2_ST(T2_H(7), h); T2_MEMW();
    c[10] = T2_CC();
    portENABLE_INTERRUPTS();
    for (int i = 0; i < 10; ++i) if (c[i + 1] - c[i] < g_t4_p2[i]) g_t4_p2[i] = c[i + 1] - c[i];
  }
  //correctness of the vector copy: hash a block, copy H->T by vector, START; same by scalar
  uint32_t r[2][8];
  for (int v = 0; v < 2; ++v)
  {
    T2_ST(0x00, SHA2_256);
    for (int i = 0; i < 16; ++i) ((volatile uint32_t *)t2b)[(0x80 >> 2) + i] = 0x5bd1e995u * (i + 7);
    T2_MEMW(); T2_ST(0x10, 1); T2_WAIT();
    if (v == 0) { p = t2b + (0x40 >> 2); VLD2(p); p = t2b + (0x80 >> 2); VST2(p); }
    else for (int i = 0; i < 8; ++i) ((volatile uint32_t *)t2b)[(0x80 >> 2) + i] = ((volatile uint32_t *)t2b)[(0x40 >> 2) + i];
    T2_ST(T2_T(8), 0x00000080); T2_ST(T2_T(15), 0x00010000);
    T2_MEMW(); T2_ST(0x10, 1); T2_WAIT();
    for (int i = 0; i < 8; ++i) r[v][i] = ((volatile uint32_t *)t2b)[(0x40 >> 2) + i];
  }
  g_t4_p2ok = memcmp(r[0], r[1], 32) == 0 ? 1 : 2;
}

void turbo_probe_run()
{
  uint16_t wc[8], ws[8];
  uint32_t pat[5], dual[6] = {0}, pcyc[4] = {0};
  esp_sha_acquire_hardware();
  t4_wordtime(true, wc);
  t4_wordtime(false, ws);
  t4_patterns(pat);
  t4_dual(dual);
  uint32_t pie = t4_pie(pcyc);
  t4_pie2();
  esp_sha_release_hardware();
  snprintf(g_t4_json, sizeof(g_t4_json),
    "{\"core\":%d,\"wc\":[%u,%u,%u,%u,%u,%u,%u,%u],\"ws\":[%u,%u,%u,%u,%u,%u,%u,%u],"
    "\"pat\":[%u,%u,%u,%u,%u],\"dual\":[%u,%u,%u,%u,%u,%u],\"pie\":%u,\"pcyc\":[%u,%u,%u,%u],\"p2\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u],\"p2ok\":%u}",
    xPortGetCoreID(), wc[0], wc[1], wc[2], wc[3], wc[4], wc[5], wc[6], wc[7],
    ws[0], ws[1], ws[2], ws[3], ws[4], ws[5], ws[6], ws[7],
    pat[0], pat[1], pat[2], pat[3], pat[4], dual[0], dual[1], dual[2], dual[3], dual[4], dual[5],
    pie, pcyc[0], pcyc[1], pcyc[2], pcyc[3], g_t4_p2[0], g_t4_p2[1], g_t4_p2[2], g_t4_p2[3], g_t4_p2[4],
    g_t4_p2[5], g_t4_p2[6], g_t4_p2[7], g_t4_p2[8], g_t4_p2[9], g_t4_p2ok);
}

const char *turbo_probe_json()
{
  return g_t4_json;
}

#endif
