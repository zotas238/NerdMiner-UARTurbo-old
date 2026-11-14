#!/usr/bin/env python3
"""Update the RUNNING wired NerdMiner over the UART wire (its own OTA: no ROM, no buttons, ~2-3 min).

usage: wireota.py [--port auto|/dev/ttyUSB0|/dev/ttyAMA0] [--state DIR] <NerdminerV2-Wired_firmware.bin>

Pauses the relay (creates <state>/pause), sends O/C/E (see runWiredWorker in src/mining.cpp),
then resumes the relay. The board writes its spare OTA slot, esp_ota_end validates the image,
and only then does it boot it, so a cut-off transfer leaves the old firmware running.
Use the *_firmware.bin (app image), not the *_factory.bin.
"""
import argparse, hashlib, os, sys, time
from pathlib import Path
import serial

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "relay"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nerdport

ap = argparse.ArgumentParser()
ap.add_argument("--port", default=os.environ.get("NERD_PORT", "auto"), help="default auto (see nerdport.py)")
ap.add_argument("--baud", type=int, default=int(os.environ.get("NERD_BAUD", "921600")))
ap.add_argument("--state", default=os.environ.get("NERD_WIRED_STATE", str(Path.home() / ".local/state/nerd-wired")))
ap.add_argument("--pause", help="pause file the relay watches (default <state>/pause)")
ap.add_argument("firmware")
a = ap.parse_args()
try:
    port = nerdport.resolve(a.port)
except LookupError as e:
    sys.exit(str(e))

fw = open(a.firmware, "rb").read()
if fw[:1] != b"\xe9":
    sys.exit("not an ESP app image (use NerdminerV2-Wired_firmware.bin, not the factory image)")
sha = hashlib.sha256(fw).hexdigest()
pause = Path(a.pause) if a.pause else Path(a.state) / "pause"
pause.parent.mkdir(parents=True, exist_ok=True)
pause.touch()
time.sleep(1.5)   # let the relay let go of the port
try:
    s = serial.Serial(port, a.baud, timeout=0.05)
except Exception:
    pause.unlink(missing_ok=True)   # don't leave the relay paused
    raise
s.reset_input_buffer()
buf = b""


def reply(prefixes, t=5.0):
    global buf
    end = time.time() + t
    while time.time() < end:
        buf += s.read(4096)
        while b"\n" in buf:
            l, buf = buf.split(b"\n", 1)
            l = l.decode(errors="replace").strip()
            if l.startswith(prefixes):
                return l
    return None


try:
    s.write(f"O {len(fw)} {sha}\n".encode())
    r = reply(("o ",), 15)
    print("start:", r, flush=True)
    if not r or not r.startswith("o 1"):
        sys.exit("board did not start the update (is it running the wired firmware and wired right?)")
    off, CH, t0, tries = 0, 512, time.time(), 0
    while off < len(fw):
        chunk = fw[off:off + CH]
        s.write(f"C {off} {chunk.hex()}\n".encode())
        r = reply(("c ", "c!"), 3)
        if r == f"c {off + len(chunk)}":
            off += len(chunk); tries = 0
            if off % (CH * 256) == 0:
                print(f"  {off}/{len(fw)} {off / (time.time() - t0) / 1024:.1f} KB/s", flush=True)
            continue
        tries += 1
        print("  retry at", off, r, flush=True)
        if r and r.startswith("c! "):
            want = int(r.split()[2])
            if want <= off: off = want
        if tries > 5:
            sys.exit("too many retries")
    print(f"sent {len(fw)} bytes in {time.time() - t0:.0f} s", flush=True)
    s.write(b"E\n")
    print("end:", reply(("e ",), 30), flush=True)
finally:
    s.close()
    pause.unlink(missing_ok=True)
