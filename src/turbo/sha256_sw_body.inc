//Body of the per-nonce double SHA; sha256_sw.cpp includes it once per optimisation
//variant with TURBO_SW_FN set to the function's name
IRAM_ATTR bool TURBO_SW_FN(const uint32_t *bake, uint32_t nonce, uint8_t *hash)
{
  const SwBake &b = *(const SwBake *)bake;
  uint32_t W[64];
  uint32_t A[8] = {b.a[0], b.a[1], b.a[2], b.a[3], b.a[4], b.a[5], b.a[6], b.a[7]};

  //*** first hash: block 2 of the header, W = w0 w1 w2 nonce 80000000 0 x10 640
  const uint32_t w3 = __builtin_bswap32(nonce);
  {
    const uint32_t t1 = b.r3t1 + w3;
    A[0] += t1;
    A[4] = t1 + b.r3t2;
  }
  PH(4, b.c4);
  PH(5, b.c5);
  PH(6, b.c6);
  PR(7, 0);
  PR(8, 0);
  PR(9, 0);
  PR(10, 0);
  PR(11, 0);
  PR(12, 0);
  PR(13, 0);
  PR(14, 0);
  PR(15, 640);
  W[16] = b.w16;
  W[17] = b.w17;
  PH(16, AR(16, 7) + b.kw16);
  PH(17, AR(17, 7) + b.kw17);
  W[18] = b.c18 + s0(w3);                  PR(18, W[18]);
  W[19] = b.c19 + w3;                      PR(19, W[19]);
  W[20] = s1(W[18]) + 0x80000000;          PR(20, W[20]);
  W[21] = s1(W[19]);                       PR(21, W[21]);
  W[22] = s1(W[20]) + 640;                 PR(22, W[22]);
  W[23] = s1(W[21]) + W[16];               PR(23, W[23]);
  W[24] = s1(W[22]) + W[17];               PR(24, W[24]);
  W[25] = s1(W[23]) + W[18];               PR(25, W[25]);
  W[26] = s1(W[24]) + W[19];               PR(26, W[26]);
  W[27] = s1(W[25]) + W[20];               PR(27, W[27]);
  W[28] = s1(W[26]) + W[21];               PR(28, W[28]);
  W[29] = s1(W[27]) + W[22];               PR(29, W[29]);
  W[30] = s1(W[28]) + W[23] + s0(640u);    PR(30, W[30]);
  W[31] = s1(W[29]) + W[24] + b.c31;       PR(31, W[31]);
  W[32] = s1(W[30]) + W[25] + b.c32;       PR(32, W[32]);
  PR(33, RW(33)); PR(34, RW(34)); PR(35, RW(35));
  PR(36, RW(36)); PR(37, RW(37)); PR(38, RW(38)); PR(39, RW(39));
  PR(40, RW(40)); PR(41, RW(41)); PR(42, RW(42)); PR(43, RW(43));
  PR(44, RW(44)); PR(45, RW(45)); PR(46, RW(46)); PR(47, RW(47));
  PR(48, RW(48)); PR(49, RW(49)); PR(50, RW(50)); PR(51, RW(51));
  PR(52, RW(52)); PR(53, RW(53)); PR(54, RW(54)); PR(55, RW(55));
  PR(56, RW(56)); PR(57, RW(57)); PR(58, RW(58)); PR(59, RW(59));
  PR(60, RW(60)); PR(61, RW(61)); PR(62, RW(62)); PR(63, RW(63));

  //*** second hash over the 32-byte digest: W = d0..d7 80000000 0 x6 256
  for (int i = 0; i < 8; ++i) W[i] = A[i] + b.mid[i];
  A[0] = 0x6A09E667; A[1] = 0xBB67AE85; A[2] = 0x3C6EF372; A[3] = 0xA54FF53A;
  A[4] = 0x510E527F; A[5] = 0x9B05688C; A[6] = 0x1F83D9AB; A[7] = 0x5BE0CD19;
  PR(0, W[0]); PR(1, W[1]); PR(2, W[2]); PR(3, W[3]);
  PR(4, W[4]); PR(5, W[5]); PR(6, W[6]); PR(7, W[7]);
  PR(8, 0x80000000);
  PR(9, 0); PR(10, 0); PR(11, 0); PR(12, 0); PR(13, 0); PR(14, 0);
  PR(15, 256);
  W[16] = s0(W[1]) + W[0];                                  PR(16, W[16]);
  W[17] = s1(256u) + s0(W[2]) + W[1];                       PR(17, W[17]);
  W[18] = s1(W[16]) + s0(W[3]) + W[2];                      PR(18, W[18]);
  W[19] = s1(W[17]) + s0(W[4]) + W[3];                      PR(19, W[19]);
  W[20] = s1(W[18]) + s0(W[5]) + W[4];                      PR(20, W[20]);
  W[21] = s1(W[19]) + s0(W[6]) + W[5];                      PR(21, W[21]);
  W[22] = s1(W[20]) + 256 + s0(W[7]) + W[6];                PR(22, W[22]);
  W[23] = s1(W[21]) + W[16] + s0(0x80000000u) + W[7];       PR(23, W[23]);
  W[24] = s1(W[22]) + W[17] + 0x80000000;                   PR(24, W[24]);
  W[25] = s1(W[23]) + W[18];                                PR(25, W[25]);
  W[26] = s1(W[24]) + W[19];                                PR(26, W[26]);
  W[27] = s1(W[25]) + W[20];                                PR(27, W[27]);
  W[28] = s1(W[26]) + W[21];                                PR(28, W[28]);
  W[29] = s1(W[27]) + W[22];                                PR(29, W[29]);
  W[30] = s1(W[28]) + W[23] + s0(256u);                     PR(30, W[30]);
  W[31] = s1(W[29]) + W[24] + s0(W[16]) + 256;              PR(31, W[31]);
  PR(32, RW(32)); PR(33, RW(33)); PR(34, RW(34)); PR(35, RW(35));
  PR(36, RW(36)); PR(37, RW(37)); PR(38, RW(38)); PR(39, RW(39));
  PR(40, RW(40)); PR(41, RW(41)); PR(42, RW(42)); PR(43, RW(43));
  PR(44, RW(44)); PR(45, RW(45)); PR(46, RW(46)); PR(47, RW(47));
  PR(48, RW(48)); PR(49, RW(49)); PR(50, RW(50)); PR(51, RW(51));
  PR(52, RW(52)); PR(53, RW(53)); PR(54, RW(54)); PR(55, RW(55));
  PR(56, RW(56));

  //Rounds 57..60 only as far as the 16-bit check needs (it reads H7, which is the e
  //value made in round 60); the rest of them only if it passes. As in nerdSHA256plus.
  //Round 57: a..h = A7 A0 A1 A2 A3 A4 A5 A6
  const uint32_t m1 = A[6] + S1(A[3]) + CH(A[3], A[4], A[5]) + K[57] + RW(57);
  A[2] += m1;
  const uint32_t d57_a1 = A[1];
  //Round 58: a..h = A6 A7 A0 A1 A2 A3 A4 A5
  const uint32_t z1 = A[5] + S1(A[2]) + CH(A[2], A[3], A[4]) + K[58] + RW(58);
  const uint32_t d58_a0 = A[0];
  A[1] += z1;
  //Round 59: a..h = A5 A6 A7 A0 A1 A2 A3 A4
  const uint32_t t59 = A[4] + S1(A[1]) + CH(A[1], A[2], A[3]) + K[59] + RW(59);
  A[0] += t59;
  //Round 60: a..h = A4 A5 A6 A7 A0 A1 A2 A3
  const uint32_t t60 = A[3] + S1(A[0]) + CH(A[0], A[1], A[2]) + K[60] + RW(60);
  const uint32_t a7 = A[7] + t60;
  if ((a7 & 0xFFFF) != 0x32E7)   //0x5BE0CD19 + a7 ends in 0000
    return false;

  A[6] = m1 + S0(A[7]) + MAJ(A[7], d58_a0, d57_a1);
  A[5] = z1 + S0(A[6]) + MAJ(A[6], A[7], d58_a0);
  A[4] = t59 + S0(A[5]) + MAJ(A[5], A[6], A[7]);
  A[7] = a7;
  A[3] = t60 + S0(A[4]) + MAJ(A[4], A[5], A[6]);
  PR(61, RW(61));
  PR(62, RW(62));
  PR(63, RW(63));

  for (int i = 0; i < 8; ++i)
  {
    const uint32_t v = __builtin_bswap32(IV[i] + A[i]);
    memcpy(hash + 4 * i, &v, 4);
  }
  return true;
}
