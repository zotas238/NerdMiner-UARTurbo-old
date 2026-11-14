#!/usr/bin/env python3
"""Generates sha256_sw_asm.S: the turbo SW miner's double SHA (sha256_sw_body.inc) in
hand-allocated Xtensa assembly, and checks it in a small simulator of the instructions
it uses against hashlib before writing it.

Registers: a8..a15 hold A[0..7] for the whole run (rounds rename them, nothing moves),
a2 the bake, a0 the constant table (DRAM: l32r from IRAM stalled ~1.5 cycles each;
a0 is saved and restored before retw), a3 a4 a5 a6 a7 are temporaries (a5/a7 swap roles as Y and X: X carries b^c
from the previous round, so Maj(a,b,c) = b ^ ((a^b) & X) is 3 ops), W[] lives on the stack.
Constant h+K+W terms are single literals. On a 16-bit hit (1 in 65536) the full digest
comes from the C version (turbo_sw_full_c)."""
import hashlib, random, struct, sys

M = 0xFFFFFFFF
def rotr(x, n): return ((x >> n) | (x << (32 - n))) & M
def s0(x): return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
def s1(x): return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
def S0(x): return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
def S1(x): return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
def CH(x, y, z): return z ^ (x & (y ^ z))
def MAJ(x, y, z): return (x & y) | (z & (x | y))
K = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
     0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
     0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
     0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
     0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
     0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
     0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
     0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2]
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]

# ---- SwBake (sha256_sw.cpp), word offsets
B = dict(mid=0, a=8, r3t1=16, r3t2=17, c4=18, c5=19, c6=20, w16=21, w17=22, kw16=23, kw17=24,
         c18=25, c19=26, c31=27, c32=28)

def compress(H, blk):
    W = list(struct.unpack(">16I", blk))
    for i in range(16, 64): W.append((W[i-16] + s0(W[i-15]) + W[i-7] + s1(W[i-2])) & M)
    a, b, c, d, e, f, g, h = H
    for i in range(64):
        t1 = (h + S1(e) + CH(e, f, g) + K[i] + W[i]) & M
        t2 = (S0(a) + MAJ(a, b, c)) & M
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & M, c, b, a, (t1 + t2) & M
    return [(x + y) & M for x, y in zip(H, [a, b, c, d, e, f, g, h])]

def bake(hdr):
    mid = compress(IV, hdr[:64])
    w0, w1, w2 = struct.unpack(">3I", hdr[64:76])
    A = list(mid)
    def PR(t, x):
        a, b, c, d, e, f, g, h = [A[(i + 64 - t) & 7] for i in range(8)]
        t1 = (h + S1(e) + CH(e, f, g) + K[t] + x) & M
        t2 = (S0(a) + MAJ(a, b, c)) & M
        A[(3 + 64 - t) & 7] = (d + t1) & M
        A[(7 + 64 - t) & 7] = (t1 + t2) & M
    PR(0, w0); PR(1, w1); PR(2, w2)
    bk = [0] * 32
    bk[0:8] = mid; bk[8:16] = A
    bk[B['r3t1']] = (A[4] + S1(A[1]) + CH(A[1], A[2], A[3]) + K[3]) & M
    bk[B['r3t2']] = (S0(A[5]) + MAJ(A[5], A[6], A[7])) & M
    bk[B['c4']] = (A[3] + K[4] + 0x80000000) & M
    bk[B['c5']] = (A[2] + K[5]) & M
    bk[B['c6']] = (A[1] + K[6]) & M
    w16 = (s0(w1) + w0) & M; w17 = (s1(640) + s0(w2) + w1) & M
    bk[B['w16']] = w16; bk[B['w17']] = w17
    bk[B['kw16']] = (w16 + K[16]) & M; bk[B['kw17']] = (w17 + K[17]) & M
    bk[B['c18']] = (s1(w16) + w2) & M; bk[B['c19']] = (s1(w17) + s0(0x80000000)) & M
    bk[B['c31']] = (s0(w16) + 640) & M; bk[B['c32']] = (s0(w17) + w16) & M
    return bk

# ---- code generation
code = []            # (op, args...)
lits = {}            # value -> label
def lit(v):
    v &= M
    if v not in lits: lits[v] = len(lits)
    return lits[v]
def I(*x): code.append(x)

SP = "a1"; BK = "a2"; KT = "a0";   # a0: the constant table (saved, restored before retw)
T1 = "a3"; T2 = "a4"; P = "a6"
XY = ["a7", "a5"]      # XY[0] = X (carried b^c), XY[1] = Y (free)
S = ["a8", "a9", "a10", "a11", "a12", "a13", "a14", "a15"]   # A[0..7]
# Frame like GCC's: locals well clear of both ends. A call8 frame's top 32 bytes take the
# window-overflow spills (a4..a7 at caller_sp-32..-16), which first held W[60..63] here.
WB = 32                # W[k] at sp + WB + 4k
SAVE_HASH = WB + 256; SAVE_NONCE = SAVE_HASH + 4; SAVE_A0 = SAVE_NONCE + 4
FRAME = 352
def W(k): return WB + 4 * k
def AR(t, i): return S[(i + 64 - t) & 7]

def rot3(dst, tmp, src, a, b, c):
    """dst = rotr(src,a) ^ rotr(src,b) ^ rotr(src,c); tmp clobbered"""
    I("ssai", a); I("src", dst, src, src)
    I("ssai", b); I("src", tmp, src, src)
    I("xor", dst, dst, tmp)
    I("ssai", c); I("src", tmp, src, src)
    I("xor", dst, dst, tmp)
def sig(dst, tmp, src, a, b, sh):
    """dst = rotr(src,a) ^ rotr(src,b) ^ (src >> sh); tmp clobbered, src kept"""
    I("ssai", a); I("src", dst, src, src)
    I("ssai", b); I("src", tmp, src, src)
    I("xor", dst, dst, tmp)
    I("srli", tmp, src, sh)
    I("xor", dst, dst, tmp)

def setX(t):
    I("xor", XY[0], AR(t, 1), AR(t, 2))

def rnd(t, kind, arg=None, full=True):
    """One round on the renamed registers. kind: 'bake' (h+K+W is bake word arg),
    'bakeh' (h + bake word arg), 'lit' (h + literal arg), 'w' (h + K[t] + P).
    full=False: only t1 and d += t1 (the last rounds before the 16-bit check)."""
    a, b, c, d, e, f, g, h = [AR(t, i) for i in range(8)]
    X, Y = XY
    # the h+K+W term first, so its load is long done when it is used
    if kind == "bake": I("l32i", Y, BK, 4 * B[arg])
    elif kind == "bakeh": I("l32i", Y, BK, 4 * B[arg])
    elif kind == "lit": I("l32i", Y, KT, 4 * lit(arg))
    elif kind == "w": I("l32i", Y, KT, 4 * lit(K[t]))
    rot3(T1, T2, e, 6, 11, 25)
    I("xor", T2, f, g); I("and", T2, T2, e); I("xor", T2, T2, g)
    I("add", T1, T1, T2)
    if kind == "bake": I("add", h, T1, Y)
    else:
        I("add", h, h, Y)
        if kind == "w": I("add", h, h, P)
        I("add", h, h, T1)
    I("add", d, d, h)            # d += t1 (h holds t1)
    if not full: return
    rot3(T1, T2, a, 2, 13, 22)
    I("add", h, h, T1)
    I("xor", Y, a, b); I("and", T2, Y, X); I("xor", T2, T2, b)
    I("add", h, h, T2)
    XY.reverse()                 # this round's a^b is the next round's b^c

def ldW(reg, k): I("l32i", reg, SP, W(k))
def stW(reg, k): I("s32i", reg, SP, W(k))

def RW(t):
    """P = W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16], stored"""
    Y = XY[1]
    ldW(P, t - 2); ldW(Y, t - 15)
    sig(T1, T2, P, 17, 19, 10)
    sig(T2, P, Y, 7, 18, 3)
    I("add", T1, T1, T2)
    ldW(T2, t - 7); ldW(P, t - 16)
    I("add", T1, T1, T2)
    I("add", P, T1, P)
    stW(P, t)

def Wexpr(t, terms):
    """P = W[t] = s1(W[t-2]) + sum(terms), stored. terms: ('w',k) ('s0w',k) ('bake',name) ('lit',v)"""
    Y = XY[1]
    ldW(P, t - 2)
    sig(T1, T2, P, 17, 19, 10)
    for kind, v in terms:
        if kind == "w": ldW(T2, v)
        elif kind == "bake": I("l32i", T2, BK, 4 * B[v])
        elif kind == "lit": I("l32i", T2, KT, 4 * lit(v))
        elif kind == "s0w":
            ldW(Y, v); sig(T2, P, Y, 7, 18, 3)
        I("add", T1, T1, T2)
    I("mov", P, T1)
    stW(P, t)

def gen():
    I("entry", SP, FRAME)
    I("s32i", "a4", SP, SAVE_HASH)
    I("s32i", "a3", SP, SAVE_NONCE)
    I("s32i", KT, SP, SAVE_A0)
    I("ktab", KT)
    # w3 = bswap32(nonce)
    I("ssai", 8); I("srli", T2, "a3", 16); I("src", T2, T2, "a3"); I("src", T2, T2, T2); I("src", T1, "a3", T2)
    stW(T1, 3)
    for i in range(8): I("l32i", S[i], BK, 4 * (B['a'] + i))
    # round 3 without its W3 term was baked: a..h = A5 A6 A7 A0 A1 A2 A3 A4
    I("l32i", T2, BK, 4 * B['r3t1']); I("add", T1, T1, T2)            # t1 = r3t1 + w3
    I("add", S[0], S[0], T1)
    I("l32i", T2, BK, 4 * B['r3t2']); I("add", S[4], T1, T2)
    setX(4)
    rnd(4, "bake", "c4"); rnd(5, "bake", "c5"); rnd(6, "bake", "c6")
    for t in range(7, 15): rnd(t, "lit", K[t])
    rnd(15, "lit", K[15] + 640)
    I("l32i", P, BK, 4 * B['w16']); stW(P, 16)
    I("l32i", P, BK, 4 * B['w17']); stW(P, 17)
    rnd(16, "bakeh", "kw16"); rnd(17, "bakeh", "kw17")
    # W18..W32 with the zero padding words dropped (sha256_sw_body.inc)
    Y = XY[1]
    ldW(Y, 3); sig(T1, T2, Y, 7, 18, 3); I("l32i", T2, BK, 4 * B['c18']); I("add", P, T1, T2); stW(P, 18)
    rnd(18, "w")
    ldW(T1, 3); I("l32i", T2, BK, 4 * B['c19']); I("add", P, T1, T2); stW(P, 19)
    rnd(19, "w")
    Wexpr(20, [("lit", 0x80000000)]); rnd(20, "w")
    Wexpr(21, []); rnd(21, "w")
    Wexpr(22, [("lit", 640)]); rnd(22, "w")
    Wexpr(23, [("w", 16)]); rnd(23, "w")
    Wexpr(24, [("w", 17)]); rnd(24, "w")
    for t in range(25, 30): Wexpr(t, [("w", t - 7)]); rnd(t, "w")
    Wexpr(30, [("w", 23), ("lit", s0(640))]); rnd(30, "w")
    Wexpr(31, [("w", 24), ("bake", "c31")]); rnd(31, "w")
    Wexpr(32, [("w", 25), ("bake", "c32")]); rnd(32, "w")
    for t in range(33, 64): RW(t); rnd(t, "w")
    # second hash over the digest: W = d0..d7 80000000 0 x6 256
    for i in range(8):
        I("l32i", T2, BK, 4 * (B['mid'] + i)); I("add", T1, S[i], T2); stW(T1, i)
    for i in range(8): I("l32i", S[i], KT, 4 * lit(IV[i]))
    setX(0)
    for t in range(8): ldW(P, t); rnd(t, "w")
    rnd(8, "lit", K[8] + 0x80000000)
    for t in range(9, 15): rnd(t, "lit", K[t])
    rnd(15, "lit", K[15] + 256)
    sec = {
        16: [("w", 0), ("s0w", 1)], 17: [("w", 1), ("s0w", 2)], 18: [("w", 2), ("s0w", 3)],
        19: [("w", 3), ("s0w", 4)], 20: [("w", 4), ("s0w", 5)], 21: [("w", 5), ("s0w", 6)],
        22: [("w", 6), ("s0w", 7), ("lit", 256)], 23: [("w", 7), ("w", 16), ("lit", s0(0x80000000))],
        24: [("w", 17), ("lit", 0x80000000)], 30: [("w", 23), ("lit", s0(256))],
        31: [("w", 24), ("s0w", 16), ("lit", 256)]}
    for t in range(25, 30): sec[t] = [("w", t - 7)]
    for t in range(16, 32):
        if t in (16, 17):
            # no s1 term from W[t-2] here: W16 = s0(W1) + W0, W17 = s1(256) + s0(W2) + W1
            Y = XY[1]
            ldW(Y, t - 15); sig(T1, T2, Y, 7, 18, 3)
            ldW(T2, t - 16); I("add", T1, T1, T2)
            if t == 17: I("l32i", T2, KT, 4 * lit(s1(256))); I("add", T1, T1, T2)
            I("mov", P, T1); stW(P, t)
        else:
            Wexpr(t, sec[t])
        rnd(t, "w")
    for t in range(32, 57): RW(t); rnd(t, "w")
    for t in range(57, 61): RW(t); rnd(t, "w", full=False)
    # round 60 put its t1 into AR(60,7) = A[3] and d += t1 into A[7]: H7 = IV7 + A[7]
    I("l32i", T1, KT, 4 * lit(IV[7])); I("add", T1, S[7], T1)
    I("l32i", KT, SP, SAVE_A0)
    I("check", T1)

gen()

# ---- list scheduler: reorders the straight-line code so a load's result is not used by
# the next instruction (load-use bubble), keeping every register, SAR and memory dependency
# Load latency used by the scheduler. On the board (C variant os = 5805 cycles/nonce):
# program order 5591, scheduled for 3 cycles 5490 (after moving constants from l32r to a
# DRAM table: 5591 -> 5490), for 4 cycles 5449, for 5 cycles 5449. So 4.
LOAD_LAT = int(__import__('os').environ.get('LOAD_LAT', 4))
LOADS = tuple(__import__('os').environ.get('LOADS', 'l32i l32r').split())
def effects(ins):
    op = ins[0]
    r, w = set(), set()
    if op == "entry": w.add("a1")
    elif op == "s32i": r |= {ins[1], ins[2], "mem%d" % ins[3]} - {"mem%d" % ins[3]}; w.add(("mem", ins[2], ins[3]))
    elif op == "l32i": r |= {ins[2], ("mem", ins[2], ins[3])}; w.add(ins[1])
    elif op in ("l32r", "ktab"): w.add(ins[1])
    elif op == "ssai": w.add("SAR")
    elif op == "src": r |= {ins[2], ins[3], "SAR"}; w.add(ins[1])
    elif op == "srli": r.add(ins[2]); w.add(ins[1])
    elif op in ("add", "xor", "and"): r |= {ins[2], ins[3]}; w.add(ins[1])
    elif op == "mov": r.add(ins[2]); w.add(ins[1])
    elif op == "check": r.add(ins[1]); w.add("ALL")
    return r, w

def schedule(code):
    n = len(code)
    eff = [effects(c) for c in code]
    preds = [dict() for _ in range(n)]     # pred -> min distance in cycles
    last_w, last_r = {}, {}
    for j in range(n):
        r, w = eff[j]
        if code[j][0] in ("entry", "check"):
            for k in range(j): preds[j][k] = 1
        for x in r:
            if x in last_w:
                k = last_w[x]; preds[j][k] = max(preds[j].get(k, 0), LOAD_LAT if code[k][0] in LOADS else 1)
        for x in w:
            if x in last_w: k = last_w[x]; preds[j][k] = max(preds[j].get(k, 0), 1)
            for k in last_r.get(x, ()): 
                if k != j: preds[j][k] = max(preds[j].get(k, 0), 1)
        # entry first, check last
        for x in r: last_r.setdefault(x, []).append(j)
        for x in w: last_w[x] = j; last_r[x] = []
    succ = [[] for _ in range(n)]
    for j in range(n):
        for k in preds[j]: succ[k].append(j)
    # priority: longest latency path to the end
    prio = [0] * n
    for j in range(n - 1, -1, -1):
        prio[j] = 1 + max((prio[s] + preds[s][j] - 1 for s in succ[j]), default=0)
    npred = [len(p) for p in preds]
    ready_at = [0] * n
    ready = [j for j in range(n) if npred[j] == 0]
    out, cycle = [], 0
    import heapq
    while ready:
        cand = [j for j in ready if ready_at[j] <= cycle]
        if not cand:
            cycle += 1
            continue
        j = max(cand, key=lambda x: (prio[x], -x))
        ready.remove(j)
        out.append(code[j])
        for s in succ[j]:
            ready_at[s] = max(ready_at[s], cycle + preds[s][j])
            npred[s] -= 1
            if npred[s] == 0: ready.append(s)
        cycle += 1
    assert len(out) == n
    return out, cycle

def stalls(code):
    """cycles of the code in this order under the same latency model"""
    eff = [effects(c) for c in code]
    t = 0; avail = {}
    for c, (r, w) in zip(code, eff):
        t = max([t] + [avail.get(x, 0) for x in r if not isinstance(x, tuple)])
        for x in w:
            if not isinstance(x, tuple): avail[x] = t + (LOAD_LAT if c[0] in LOADS else 1)
        t += 1
    return t

# ---- simulator of the subset
def run(bk, nonce):
    R = {"a%d" % i: 0 for i in range(16)}
    mem = {}
    R["a2"] = 0x10000; R["a3"] = nonce; R["a4"] = 0x20000; R["a1"] = 0x80000; R["a0"] = 0x40001234
    for v, k in lits.items(): mem[0x30000 + 4 * k] = v
    for i, v in enumerate(bk): mem[0x10000 + 4 * i] = v
    sar = 0
    for ins in code:
        op = ins[0]
        if op == "entry": R["a1"] -= ins[2]
        elif op == "s32i": mem[R[ins[2]] + ins[3]] = R[ins[1]]
        elif op == "l32i": R[ins[1]] = mem[R[ins[2]] + ins[3]]
        elif op == "ktab": R[ins[1]] = 0x30000
        elif op == "ssai": sar = ins[1]
        elif op == "src": R[ins[1]] = (((R[ins[2]] << 32) | R[ins[3]]) >> sar) & M
        elif op == "srli": R[ins[1]] = R[ins[2]] >> ins[3]
        elif op == "add": R[ins[1]] = (R[ins[2]] + R[ins[3]]) & M
        elif op == "xor": R[ins[1]] = R[ins[2]] ^ R[ins[3]]
        elif op == "and": R[ins[1]] = R[ins[2]] & R[ins[3]]
        elif op == "mov": R[ins[1]] = R[ins[2]]
        elif op == "check":
            assert R["a0"] == 0x40001234, "a0 not restored"
            return R[ins[1]]
        else: raise Exception(op)

def ref_h7(hdr, nonce):
    h = hashlib.sha256(hashlib.sha256(hdr[:76] + struct.pack("<I", nonce)).digest()).digest()
    return struct.unpack(">I", h[28:32])[0]

def selftest(n):
    random.seed(1)
    for k in range(n):
        hdr = bytes(random.getrandbits(8) for _ in range(80))
        bk = bake(hdr)
        for nonce in (random.getrandbits(32), 0, 0xFFFFFFFF, k):
            got = run(bk, nonce); want = ref_h7(hdr, nonce)
            if got != want:
                print("MISMATCH hdr %d nonce %08x: %08x vs %08x" % (k, nonce, got, want)); return False
    return True

# ---- emit
def body(name, section, check):
    out = ['    .section %s, "ax"' % section, "    .literal_position",
           "    .literal %s_KTAB, turbo_sw_asm_k" % name]
    if check: out.append("    .literal %s_FULL, turbo_sw_full_c" % name)
    out += ["    .align 4", "    .global " + name, "    .type %s, @function" % name, name + ":"]
    for ins in code:
        op = ins[0]
        if op == "entry": out.append("    entry a1, %d" % ins[2])
        elif op == "check":
            r = ins[1]
            if not check:
                out += ["    mov a2, %s" % r, "    retw.n"]
                continue
            out += ["    extui %s, %s, 0, 16" % (r, r),
                    "    beqz %s, .L%s_hit" % (r, name),
                    "    movi.n a2, 0",
                    "    retw.n",
                    ".L%s_hit:" % name,
                    "    mov a10, a2",
                    "    l32i a11, a1, %d" % SAVE_NONCE,
                    "    l32i a12, a1, %d" % SAVE_HASH,
                    "    l32r a8, %s_FULL" % name,
                    "    callx8 a8",
                    "    mov a2, a10",
                    "    retw.n"]
        elif op == "ssai": out.append("    ssai %d" % ins[1])
        elif op in ("l32i", "s32i"): out.append("    %s %s, %s, %d" % ins)
        elif op == "ktab": out.append("    l32r %s, %s_KTAB" % (ins[1], name))
        elif op == "srli": out.append("    srli %s, %s, %d" % ins[1:])
        else: out.append("    %s %s" % (op, ", ".join(ins[1:])))
    out.append("    .size %s, . - %s" % (name, name))
    return out

def emit(path):
    out = ["/* Generated by gen_sw_asm.py: see the docstring there. Do not edit. */", "#ifdef NM_TURBO",
           "/* constants (K, IV, folded h+K+W terms) in DRAM: l32r reads IRAM and stalls fetch */",
           '    .section .dram1.turbo_sw_asm_k, "aw"', "    .align 4", "    .global turbo_sw_asm_k",
           "turbo_sw_asm_k:"]
    for v, k in sorted(lits.items(), key=lambda x: x[1]): out.append("    .word 0x%08X" % v)
    out += body("turbo_sw_sha256d_asm", ".iram1.turbo_sw_asm", True)
    # test twin in flash: returns H7 (big endian word) for every nonce, for the boot check
    out += body("turbo_sw_asm_h7", ".text.turbo_sw_asm_h7", False)
    out.append("#endif")
    open(path, "w").write("\n".join(out) + "\n")

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    before = stalls(code)
    code[:], _ = schedule(code)
    print("modelled cycles: %d in program order, %d scheduled" % (before, stalls(code)))
    ok = selftest(n)
    nins = sum(1 for c in code if c[0] not in ("check",))
    print("instructions per nonce:", nins, "literals:", len(lits), "simulator:", "ok" if ok else "FAIL")
    if not ok: sys.exit(1)
    emit("sha256_sw_asm.S")
