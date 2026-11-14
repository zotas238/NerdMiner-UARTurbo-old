//Software SHA-256d for the turbo SW miner. Same round code and 16-bit early exit as
//nerdSHA256plus' nerd_sha256d_baked, plus more precomputation:
//  first hash:  rounds 0..2 and the nonce-free part of round 3 (as before), h+K+W of
//               rounds 4..6, and the schedule written out with the zero padding words
//               dropped (W16, W17 and the job-constant parts of W18, W19, W31, W32 baked)
//  second hash: the zero padding words dropped from W16..W31
//Checked on the host against Python's hashlib for every nonce of several headers.
//Built three times with different optimisation (GCC's pre-RA scheduler raises register
//pressure, and on Xtensa's 16 visible registers that turns into stack spills); the SW
//miner benchmarks them at boot and keeps the fastest that passes the known-answer test.
#include <string.h>
#include <stdlib.h>
#include "sha256_sw.h"

#ifdef ESP_PLATFORM
#include <esp_attr.h>
#else
#define IRAM_ATTR
#define DRAM_ATTR
#endif

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define s0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define s1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))
#define S0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define CH(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define BE32(p, i) (((uint32_t)(p)[(i)] << 24) | ((uint32_t)(p)[(i) + 1] << 16) | ((uint32_t)(p)[(i) + 2] << 8) | (uint32_t)(p)[(i) + 3])

//One round; hkw is h + K + W
#define RND(a, b, c, d, e, f, g, h, hkw) \
  { const uint32_t t1 = (hkw) + S1(e) + CH(e, f, g); const uint32_t t2 = S0(a) + MAJ(a, b, c); d += t1; h = t1 + t2; }
//Round t of the usual rotation over A[]
#define AR(t, i) A[((i) + 64 - (t)) & 7]
#define PR(t, x) RND(AR(t, 0), AR(t, 1), AR(t, 2), AR(t, 3), AR(t, 4), AR(t, 5), AR(t, 6), AR(t, 7), AR(t, 7) + K[t] + (x))
#define PH(t, hkw) RND(AR(t, 0), AR(t, 1), AR(t, 2), AR(t, 3), AR(t, 4), AR(t, 5), AR(t, 6), AR(t, 7), (hkw))
#define RW(t) (W[t] = s1(W[(t) - 2]) + W[(t) - 7] + s0(W[(t) - 15]) + W[(t) - 16])

DRAM_ATTR static const uint32_t K[64] = {
  0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
  0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
  0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
  0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
  0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
  0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
  0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
  0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};

static const uint32_t IV[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                               0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

struct SwBake
{
  uint32_t mid[8];
  uint32_t a[8];          //state after rounds 0..2
  uint32_t r3t1, r3t2;    //round 3 without its W3 term
  uint32_t c4, c5, c6;    //h + K + W of rounds 4..6 (h is still job-constant there)
  uint32_t w16, w17, kw16, kw17;
  uint32_t c18, c19, c31, c32;   //job-constant parts of W18, W19, W31, W32
};
static_assert(sizeof(SwBake) <= TURBO_SW_BAKE_WORDS * 4, "bake too big");

void turbo_sw_bake(const uint32_t *mid, const uint8_t *tail, uint32_t *bake)
{
  SwBake &b = *(SwBake *)bake;
  const uint32_t w0 = BE32(tail, 0), w1 = BE32(tail, 4), w2 = BE32(tail, 8);
  uint32_t A[8];
  for (int i = 0; i < 8; ++i) b.mid[i] = A[i] = mid[i];
  PR(0, w0);
  PR(1, w1);
  PR(2, w2);
  for (int i = 0; i < 8; ++i) b.a[i] = A[i];
  //round 3: a..h = A5 A6 A7 A0 A1 A2 A3 A4
  b.r3t1 = A[4] + S1(A[1]) + CH(A[1], A[2], A[3]) + K[3];
  b.r3t2 = S0(A[5]) + MAJ(A[5], A[6], A[7]);
  //rounds 4..6 use h = A3, A2, A1, none of which round 3 writes
  b.c4 = A[3] + K[4] + 0x80000000;
  b.c5 = A[2] + K[5];
  b.c6 = A[1] + K[6];
  b.w16 = s0(w1) + w0;
  b.w17 = s1(640u) + s0(w2) + w1;
  b.kw16 = b.w16 + K[16];
  b.kw17 = b.w17 + K[17];
  b.c18 = s1(b.w16) + w2;
  b.c19 = s1(b.w17) + s0(0x80000000u);
  b.c31 = s0(b.w16) + 640;
  b.c32 = s0(b.w17) + b.w16;
}


#define TURBO_SW_FN turbo_sw_sha256d_o2
#include "sha256_sw_body.inc"
#undef TURBO_SW_FN

#pragma GCC push_options
#pragma GCC optimize ("no-schedule-insns")
#define TURBO_SW_FN turbo_sw_sha256d_ns
#include "sha256_sw_body.inc"
#undef TURBO_SW_FN
#pragma GCC pop_options

#pragma GCC push_options
#pragma GCC optimize ("Os")
#define TURBO_SW_FN turbo_sw_sha256d_os
#include "sha256_sw_body.inc"
#undef TURBO_SW_FN
#pragma GCC pop_options

static void ref_compress(uint32_t *H, const uint8_t *d);

//Known answers from the host test: headers whose hash ends in 0000 at the nonce in
//bytes 76..79 (the next nonce does not)
static const char *const kat_hex[2] = {
  "0e830b73ecf54b4a7435e7f10641c86baadf0c3de64c48a1dbd46878dc584eeadb595ec74ea911c2def9b4e43a7c4fe45b5c2242a86ae3833e4bfb1ba34a057ea36346f20c57b4eb5068cf8bab90b553",
  "0e830b73ecf54b4a7435e7f10641c86baadf0c3de64c48a1dbd46878dc584eeadb595ec74ea911c2def9b4e43a7c4fe45b5c2242a86ae3833e4bfb1ba34a057ea36346f20c57b4eb5068cf8b4fc8b553"};
static const char *const kat_want[2] = {
  "fb4ae82e685c815a48b3636b4a82c5bc58d704c90610c3c8bffdbb78cae10000",
  "a6702eb75efac0eed63a7a2179be8a40fb35c3734079d92801177e80410d0000"};

static void unhex(uint8_t *out, const char *hex, int n)
{
  for (int i = 0; i < n; ++i)
  {
    char t[3] = {hex[2 * i], hex[2 * i + 1], 0};
    out[i] = (uint8_t)strtoul(t, nullptr, 16);
  }
}

#ifdef ESP_PLATFORM
//Hand-allocated assembly of the same hash (sha256_sw_asm.S, generated and checked in a
//simulator by gen_sw_asm.py). It only finds the 16-bit hits; for those it calls
//turbo_sw_full_c for the digest.
extern "C" bool turbo_sw_sha256d_asm(const uint32_t *bake, uint32_t nonce, uint8_t *hash);
extern "C" uint32_t turbo_sw_asm_h7(const uint32_t *bake, uint32_t nonce, uint8_t *hash);
//H7 of the asm against the reference over count nonces of the first KAT header: 0 when
//all agree, else 1 + the index of the first mismatch (got/want returned)
uint32_t turbo_sw_asm_check(uint32_t count, uint32_t *got, uint32_t *want)
{
  uint8_t hdr[80], ref[32], dummy[32];
  unhex(hdr, kat_hex[0], 80);
  uint32_t mid[8], bake[TURBO_SW_BAKE_WORDS];
  memcpy(mid, IV, sizeof(mid));
  ref_compress(mid, hdr);
  turbo_sw_bake(mid, hdr + 64, bake);
  for (uint32_t k = 0; k < count; ++k)
  {
    const uint32_t nonce = 0x01000193u * k;
    turbo_ref_sha256d(hdr, nonce, ref);
    const uint32_t w = BE32(ref, 28), g = turbo_sw_asm_h7(bake, nonce, dummy);
    if (g != w)
    {
      *got = g;
      *want = w;
      return k + 1;
    }
  }
  return 0;
}
extern "C" bool turbo_sw_full_c(const uint32_t *bake, uint32_t nonce, uint8_t *hash)
{
  return turbo_sw_sha256d_os(bake, nonce, hash);
}
#endif

const TurboSwVariant turbo_sw_variants[TURBO_SW_VARIANTS] = {
  {"o2", turbo_sw_sha256d_o2},
  {"o2ns", turbo_sw_sha256d_ns},
  {"os", turbo_sw_sha256d_os},
#ifdef ESP_PLATFORM
  {"asm", turbo_sw_sha256d_asm},
#endif
};
TurboSwFn turbo_sw_hash = turbo_sw_sha256d_ns;

//Plain SHA-256 compression, written independently of the miner code above
static void ref_compress(uint32_t *H, const uint8_t *d)
{
  uint32_t W[64];
  for (int i = 0; i < 16; ++i) W[i] = BE32(d, 4 * i);
  for (int i = 16; i < 64; ++i) W[i] = W[i - 16] + s0(W[i - 15]) + W[i - 7] + s1(W[i - 2]);
  uint32_t a = H[0], b = H[1], c = H[2], d_ = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
  for (int i = 0; i < 64; ++i)
  {
    const uint32_t t1 = h + S1(e) + ((e & f) ^ (~e & g)) + K[i] + W[i];
    const uint32_t t2 = S0(a) + ((a & b) ^ (a & c) ^ (b & c));
    h = g; g = f; f = e; e = d_ + t1; d_ = c; c = b; b = a; a = t1 + t2;
  }
  H[0] += a; H[1] += b; H[2] += c; H[3] += d_; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}
static void ref_put(uint8_t *o, const uint32_t *H)
{
  for (int i = 0; i < 8; ++i)
  {
    o[4 * i] = H[i] >> 24; o[4 * i + 1] = H[i] >> 16; o[4 * i + 2] = H[i] >> 8; o[4 * i + 3] = H[i];
  }
}

void turbo_ref_sha256d(const uint8_t *hdr, uint32_t nonce, uint8_t *hash)
{
  uint8_t b[128] = {0};
  memcpy(b, hdr, 76);
  memcpy(b + 76, &nonce, 4);
  b[80] = 0x80; b[126] = 0x02; b[127] = 0x80;
  uint32_t H[8];
  memcpy(H, IV, sizeof(H));
  ref_compress(H, b);
  ref_compress(H, b + 64);
  uint8_t m[64] = {0};
  ref_put(m, H);
  m[32] = 0x80; m[62] = 0x01;
  memcpy(H, IV, sizeof(H));
  ref_compress(H, m);
  ref_put(hash, H);
}

bool turbo_ref_check(const uint8_t *hdr, uint32_t nonce, const uint8_t *hash)
{
  uint8_t want[32];
  turbo_ref_sha256d(hdr, nonce, want);
  return memcmp(want, hash, 32) == 0;
}

bool turbo_sw_selftest(TurboSwFn fn)
{
  for (int k = 0; k < 2; ++k)
  {
    uint8_t hdr[80], want[32], got[32], ref[32];
    unhex(hdr, kat_hex[k], 80);
    unhex(want, kat_want[k], 32);
    uint32_t nonce;
    memcpy(&nonce, hdr + 76, 4);
    uint32_t mid[8], bake[TURBO_SW_BAKE_WORDS];
    memcpy(mid, IV, sizeof(mid));
    ref_compress(mid, hdr);
    turbo_sw_bake(mid, hdr + 64, bake);
    turbo_ref_sha256d(hdr, nonce, ref);
    if (memcmp(ref, want, 32) != 0) return false;
    if (!fn(bake, nonce, got) || memcmp(got, want, 32) != 0) return false;
    if (fn(bake, nonce + 1, got)) return false;
  }
  return true;
}
