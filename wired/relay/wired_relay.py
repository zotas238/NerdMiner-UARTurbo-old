#!/usr/bin/env python3
"""Stratum relay for the wired NerdMiner (ESP32-S3 with Wi-Fi off, on a 3.3 V UART at 921600 baud).

The board has no network. This process holds the pool connection, builds block headers
(rolling extranonce2 per job), sends them to the board as `J` lines, re-hashes every `N`
share candidate before submitting it, and writes the board's status to <state>/status.json.
It also applies the overclock from <state>/oc.json 30 s after every boot of the board.

Control while it runs:
  write one command per line to <state>/cmd       e.g.  echo "S" >> ~/.local/state/nerd-wired/cmd
  create <state>/pause to release the serial port (for wireota.py / esptool); remove it to resume

Every option can also come from the environment (NERD_PORT, NERD_POOL, NERD_USER, NERD_PASSWORD,
NERD_BAUD, NERD_WIRED_STATE), which is how wired/linux/install.sh's /etc/nerd-wired.conf feeds it.

Runs on Linux, macOS and Windows (needs Python 3.8+ and pyserial).
"""
import argparse, hashlib, json, os, socket, struct, sys, time
from pathlib import Path

try:
    import serial
except ImportError:
    sys.exit("pyserial is missing: pip install pyserial (Debian/Ubuntu/Pi OS: apt install python3-serial)")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import nerdport   # --port auto (USB-UART adapter detection); optional next to this file
except ImportError:
    nerdport = None
env = os.environ.get

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--port", default=env("NERD_PORT", "auto"),
                help="serial port wired to the S3's GPIO43/44: auto (default: /dev/nerdminer, else the one USB-UART "
                     "adapter plugged in), or e.g. /dev/ttyUSB0, /dev/ttyAMA0, COM5")
ap.add_argument("--pool", default=env("NERD_POOL"), required=not env("NERD_POOL"),
                help="stratum pool host:port, e.g. public-pool.io:21496 or 192.168.1.10:3333")
ap.add_argument("--user", default=env("NERD_USER"), required=not env("NERD_USER"),
                help="pool user: your BTC address, optionally .workername")
ap.add_argument("--password", default=env("NERD_PASSWORD", "x"), help="pool password (default x)")
ap.add_argument("--baud", type=int, default=int(env("NERD_BAUD", "921600")),
                help="must match WIRED_BAUD in the firmware (default 921600)")
ap.add_argument("--state", default=os.environ.get("NERD_WIRED_STATE", str(Path.home() / ".local/state/nerd-wired")),
                help="folder for status.json, oc.json, cmd, pause and relay.log (default ~/.local/state/nerd-wired)")
ap.add_argument("--suggest-diff", type=float, default=0.00015,
                help="share difficulty to ask the pool for (default 0.00015 = the firmware's DEFAULT_DIFFICULTY)")
args = ap.parse_args()

STATE_DIR = Path(args.state); STATE_DIR.mkdir(parents=True, exist_ok=True)
STATE = STATE_DIR / "status.json"; CMD = STATE_DIR / "cmd"; PAUSE = STATE_DIR / "pause"
LOG = STATE_DIR / "relay.log"; OC = STATE_DIR / "oc.json"
host, _, port = args.pool.rpartition(":")
POOL = (host, int(port))
USER = args.user
# Overclock kept across boots, e.g. {"div": 11, "mode": 48} = 300 MHz (div 8 = stock 240 MHz). See README.
# Sent OC_DELAY s after each boot. Two crash resets at that setting within an hour step it down by one and save that.
OC_DELAY = 30
JOB_REFRESH = 30          # s: new extranonce2 / ntime even without a notify
DIFF1 = 0x00000000FFFF0000000000000000000000000000000000000000000000000000


def oc_load():
    try:
        return json.load(open(OC))
    except Exception:
        return {"div": 8, "mode": 0}


def oc_save(c):
    tmp = str(OC) + ".tmp"
    with open(tmp, "w") as f: json.dump(c, f)
    os.replace(tmp, OC)


def log(*a):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + " ".join(str(x) for x in a)
    print(line, flush=True)
    with open(LOG, "a") as f: f.write(line + "\n")


def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Pool:
    def __init__(s):
        s.sock = None; s.buf = b""; s.id = 10; s.en1 = ""; s.en2size = 4
        s.diff = 1.0; s.notify = None; s.pending = {}; s.authed = False

    def connect(s):
        s.sock = socket.create_connection(POOL, timeout=10); s.sock.setblocking(False)
        s.buf = b""; s.authed = False; s.notify = None
        s.send({"id": 1, "method": "mining.subscribe", "params": ["NerdMiner/wired"]})
        s.send({"id": 2, "method": "mining.authorize", "params": [USER, args.password]})
        s.suggest(); s.last_suggest = time.time()
        log("pool connected", args.pool)

    def suggest(s):
        # like the firmware: ask for a low share difficulty (else e.g. public-pool hands out 16384)
        s.id += 1; s.send({"id": s.id, "method": "mining.suggest_difficulty", "params": [args.suggest_diff]})

    def send(s, o): s.sock.sendall((json.dumps(o) + "\n").encode())

    def submit(s, job_id, en2, ntime, nonce):
        s.id += 1
        s.send({"id": s.id, "method": "mining.submit", "params": [USER, job_id, en2, ntime, "%08x" % nonce]})
        return s.id

    def lines(s):
        try:
            d = s.sock.recv(65536)
        except (BlockingIOError, InterruptedError):
            return []
        if not d: raise ConnectionError("pool closed")
        s.buf += d; out = []
        while b"\n" in s.buf:
            l, s.buf = s.buf.split(b"\n", 1)
            if l.strip(): out.append(json.loads(l))
        return out


def build_header(n, en1, en2, ntime_hex):
    job_id, prev, cb1, cb2, branch, ver, nbits = n[0], n[1], n[2], n[3], n[4], n[5], n[6]
    root = dsha(bytes.fromhex(cb1 + en1 + en2 + cb2))
    for b in branch: root = dsha(root + bytes.fromhex(b))
    p = bytes.fromhex(prev)
    prev_le = b"".join(p[i:i+4][::-1] for i in range(0, 32, 4))
    return (struct.pack("<I", int(ver, 16)) + prev_le + root +
            struct.pack("<I", int(ntime_hex, 16)) + struct.pack("<I", int(nbits, 16)) + b"\0\0\0\0")


def main():
    pool = Pool(); ser = None; sbuf = b""
    jobs = {}; next_id = 1; en2_ctr = 0; last_job = 0
    st = {"accepted": 0, "rejected": 0, "cand": 0, "bad_cand": 0, "stale": 0, "boots": 0,
          "khs": None, "board": None, "last_hello": None, "pll_replies": []}
    prev_t = None
    oc_at = time.time() + OC_DELAY if oc_load().get("div", 8) != 8 else 0
    oc_applied = 0
    while True:
        try:
            if PAUSE.exists():
                if ser: ser.close(); ser = None; log("serial paused")
                time.sleep(0.5); continue
            if ser is None:
                if nerdport:
                    port = nerdport.resolve(args.port)
                elif args.port == "auto":
                    raise LookupError("--port auto needs nerdport.py next to wired_relay.py; pass --port")
                else:
                    port = args.port
                ser = serial.Serial(port, args.baud, timeout=0.05); log("serial open", port); last_job = 0
                main.last_lookup = None
            if pool.sock is None:
                pool.connect()
            # pool
            for m in pool.lines():
                meth = m.get("method")
                if meth == "mining.notify":
                    pool.notify = m["params"]; last_job = 0
                    if m["params"][8]: jobs.clear()
                elif meth == "mining.set_difficulty":
                    pool.diff = float(m["params"][0]); log("pool diff", pool.diff)
                elif m.get("id") == 1 and m.get("result"):
                    pool.en1 = m["result"][1]; pool.en2size = m["result"][2]
                elif m.get("id") == 2:
                    pool.authed = bool(m.get("result")); log("authorized", pool.authed)
                elif m.get("id") in pool.pending:
                    d = pool.pending.pop(m["id"])
                    if m.get("result"):
                        st["accepted"] += 1; ser.write(("A %.6g\n" % d).encode())
                    else:
                        st["rejected"] += 1; log("rejected", m.get("error"))
            # new work
            now = time.time()
            if now - getattr(pool, "last_suggest", now) > 120: pool.suggest(); pool.last_suggest = now
            if pool.notify and pool.authed and now - last_job > JOB_REFRESH:
                n = pool.notify; en2_ctr += 1
                en2 = ("%0" + str(pool.en2size * 2) + "x") % (en2_ctr & ((1 << (8 * pool.en2size)) - 1))
                ntime = n[7]
                hdr = build_header(n, pool.en1, en2, ntime)
                jid = next_id; next_id += 1
                jobs[jid] = (n[0], en2, ntime, hdr)
                for k in [k for k in jobs if k < jid - 8]: jobs.pop(k)
                ser.write(("J %d %.8g %s\n" % (jid, pool.diff, hdr.hex())).encode())
                last_job = now
            # board (read() waits up to 50 ms: this is the loop's pacing)
            d = ser.read(max(1, ser.in_waiting))
            if d:
                sbuf += d
                while b"\n" in sbuf:
                    l, sbuf = sbuf.split(b"\n", 1)
                    l = l.decode(errors="replace").strip()
                    if l.startswith("T {"):
                        try: b = json.loads(l[2:])
                        except Exception: continue
                        t = time.time(); tot = b.get("hw", 0) + b.get("sw", 0)
                        if prev_t and tot >= prev_t[1]:
                            st["khs"] = round((tot - prev_t[1]) / (t - prev_t[0]) / 1000, 1)
                            st["khs_hw"] = round((b.get("hw", 0) - prev_t[2]) / (t - prev_t[0]) / 1000, 1)
                        prev_t = (t, tot, b.get("hw", 0))
                        st["board"] = b; st["t"] = t
                        tmp = str(STATE) + ".tmp"
                        with open(tmp, "w") as f: json.dump(st, f)
                        os.replace(tmp, STATE)
                    elif l.startswith("N "):
                        _, jid, nonce, d = l.split()[:4]; jid = int(jid); nonce = int(nonce, 16)
                        st["cand"] += 1
                        if jid not in jobs: st["stale"] += 1; continue
                        job_id, en2, ntime, hdr = jobs[jid]
                        h = dsha(hdr[:76] + struct.pack("<I", nonce))
                        hd = DIFF1 / max(1, int.from_bytes(h, "little"))
                        if hd < float(d) * 0.99:   # the hash the board found is wrong
                            st["bad_cand"] += 1; log("bad candidate", jid, "%08x" % nonce, "claimed", d, "real %.4g" % hd); continue
                        if hd < pool.diff * 0.999:  # right hash, but under a pool difficulty raised meanwhile
                            st["low_cand"] = st.get("low_cand", 0) + 1; continue
                        pool.pending[pool.submit(job_id, en2, ntime, nonce)] = hd
                    elif l.startswith("H "):
                        st["boots"] += 1; st["last_hello"] = l; prev_t = None; last_job = 0; log(l)
                        kv = dict(w.split("=", 1) for w in l.split() if "=" in w)
                        c = oc_load()
                        crashed_here = kv.get("last_try") == str(c.get("div")) or (kv.get("last_try") == "0" and time.time() - oc_applied < 600)
                        if kv.get("rr") in ("4", "5", "6", "7", "9", "15") and crashed_here and c.get("div", 8) > 8:
                            # one crash can be a fluke; two at the same setting within an hour step it down
                            hist = [t for t in c.get("crashes", []) if time.time() - t < 3600] + [time.time()]
                            c["crashes"] = hist
                            if len(hist) >= 2:
                                c["div"] -= 1; c["stepped_down"] = time.strftime("%F %T"); c["crashes"] = []
                                log("crashed twice at the overclock, stepping down to div", c["div"])
                            else:
                                log("crashed once at the overclock, retrying it")
                            oc_save(c)
                        oc_at = time.time() + OC_DELAY if c.get("div", 8) != 8 else 0
                    elif l.startswith(("p ", "q ", "v ", "k ", "x ", "b ", "y ", "z")):
                        st["pll_replies"] = (st["pll_replies"] + [l])[-10:]; log(l)
                    elif l.startswith(("B ", "d")):
                        log(l)
            # overclock after boot
            if oc_at and time.time() > oc_at and ser:
                c = oc_load(); oc_at = 0
                ser.write(("P %d %d\n" % (c["div"], c.get("mode", 0))).encode()); log("overclock: P", c["div"], c.get("mode", 0)); oc_applied = time.time()
            # control
            if CMD.exists():
                cmds = CMD.read_text().split("\n")
                CMD.unlink()
                for c in cmds:
                    c = c.strip()
                    if c: log("cmd", c); ser.write((c + "\n").encode())
        except LookupError as e:   # --port auto found no adapter (unplugged?): keep looking
            if str(e) != getattr(main, "last_lookup", None):
                log("waiting for the serial port:", e); main.last_lookup = str(e)
            time.sleep(5)
        except (ConnectionError, OSError, socket.timeout, serial.SerialException) as e:
            log("error", repr(e))
            if isinstance(e, serial.SerialException) and ser:
                try: ser.close()
                except Exception: pass
                ser = None   # reopen (e.g. a USB-UART adapter was replugged)
            else:
                try: pool.sock and pool.sock.close()
                except Exception: pass
                pool.sock = None
            time.sleep(3)


if __name__ == "__main__":
    main()
