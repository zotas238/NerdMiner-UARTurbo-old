#!/usr/bin/env python3
"""Fetch the wired board's last crash (coredump) through the running relay and decode it.

usage: coredump_get.py [--state DIR] <firmware.elf>

Sends `Y` through <state>/cmd, collects the `y` lines from <state>/relay.log, saves the dump to
<state>/coredump-<time>.bin and runs esp-coredump (pip install esp-coredump) on it. Needs the ELF of
the exact build that crashed (.pio/build/NerdminerV2-Wired/firmware.elf): keep one per build you flash.
The Xtensa GDB must be on PATH (PlatformIO: ~/.platformio/packages/toolchain-xtensa-esp32s3/bin).
"""
import argparse, os, subprocess, sys, time
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--state", default=os.environ.get("NERD_WIRED_STATE", str(Path.home() / ".local/state/nerd-wired")))
ap.add_argument("elf")
a = ap.parse_args()
state = Path(a.state); LOG = state / "relay.log"; CMD = state / "cmd"

start = LOG.stat().st_size
with open(CMD, "a") as f: f.write("Y\n")
data, end = {}, None
t0 = time.time()
while time.time() - t0 < 60 and end is None:
    time.sleep(1)
    with open(LOG) as f:
        f.seek(start)
        for l in f:
            i = l.find(" y ")
            if i < 0: continue
            w = l[i + 3:].split()
            if w[0] == "end": end = int(w[1]); break
            data[int(w[0])] = bytes.fromhex(w[1])
if not end:
    sys.exit(f"no coredump on the board ({end})")
blob = b"".join(data[k] for k in sorted(data))[:end]
out = state / ("coredump-%s.bin" % time.strftime("%Y%m%d-%H%M%S"))
out.write_bytes(blob)
print("got", len(blob), "bytes ->", out, flush=True)
env = dict(os.environ)
tc = Path.home() / ".platformio/packages/toolchain-xtensa-esp32s3/bin"
if tc.is_dir(): env["PATH"] = str(tc) + os.pathsep + env["PATH"]
r = subprocess.run(["esp-coredump", "--chip", "esp32s3", "info_corefile", "-t", "raw", "-c", str(out), a.elf],
                   capture_output=True, text=True, env=env, timeout=180)
print(r.stdout[-6000:], r.stderr[-2000:])
