#!/usr/bin/env python3
"""Check the UART wire between this computer and the wired NerdMiner S3, one direction at a time.

  wirecheck.py                 test the link to the board (pauses a running relay meanwhile)
  wirecheck.py --loopback      test the USB-UART adapter alone: jumper its TXD to its RXD first
  wirecheck.py --list          list the USB-UART adapters this computer sees

Board test: listens for the status line the board sends every 2 s (board TX GPIO43 -> adapter RXD),
then sends `X` (harmless register dump) and waits for its `x` reply (adapter TXD -> board RX GPIO44).
"""
import argparse, os, sys, time
from pathlib import Path

try:
    import serial
except ImportError:
    sys.exit("pyserial is missing: pip install pyserial (Debian/Ubuntu/Pi OS: apt install python3-serial)")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "relay"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nerdport

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--port", default=os.environ.get("NERD_PORT", "auto"))
ap.add_argument("--baud", type=int, default=int(os.environ.get("NERD_BAUD", "921600")))
ap.add_argument("--state", default=os.environ.get("NERD_WIRED_STATE", str(Path.home() / ".local/state/nerd-wired")))
ap.add_argument("--pause", help="pause file the relay watches (default <state>/pause)")
ap.add_argument("--loopback", action="store_true")
ap.add_argument("--list", action="store_true")
a = ap.parse_args()

OK, BAD = "  [ok]  ", "  [FAIL]"

if a.list:
    c = nerdport.candidates()
    for dev, chip, vid, pid, sn, loc in c:
        print("%-14s %04x:%04x  %s  serial=%s usb=%s" % (dev, vid, pid, chip, sn, loc))
    if not c:
        print("no USB-UART adapter found")
    sys.exit(0)

try:
    port = nerdport.resolve(a.port)
except LookupError as e:
    sys.exit(str(e))
print("port %s @ %d baud" % (port, a.baud))

if a.loopback:
    s = serial.Serial(port, a.baud, timeout=0.2)
    data = os.urandom(4096)
    s.reset_input_buffer()
    t0 = time.time(); s.write(data); got = b""
    while len(got) < len(data) and time.time() - t0 < 3:
        got += s.read(len(data) - len(got))
    s.close()
    if got == data:
        print(OK, "adapter loopback: 4096 random bytes back intact at %d baud" % a.baud)
        print("        Remove the TXD-RXD jumper and wire it to the board (TXD->44, RXD->43, GND->G).")
        sys.exit(0)
    if not got:
        print(BAD, "nothing came back: is TXD jumpered to RXD on the adapter's pins?")
    else:
        same = sum(x == y for x, y in zip(got, data))
        print(BAD, "%d/%d bytes back, %d matching: the adapter can't do %d baud cleanly (try a CP2102/FT232/CH343)"
              % (len(got), len(data), same, a.baud))
    sys.exit(1)

pause = Path(a.pause) if a.pause else Path(a.state) / "pause"
paused = False
if pause.parent.is_dir():
    try:
        pause.touch(); paused = True; time.sleep(1.5)   # let a running relay let go of the port
    except OSError:
        pass
try:
    try:
        s = serial.Serial(port, a.baud, timeout=0.1)
    except serial.SerialException as e:
        sys.exit("can't open %s: %s\n(permission? add yourself to group dialout/uucp, or run as root)" % (port, e))
    s.reset_input_buffer()

    # 1. board -> host
    print("listening 5 s for the board's status line (board GPIO43 TX -> adapter RXD)...")
    buf = b""; t0 = time.time(); status = None
    while time.time() - t0 < 5 and status is None:
        buf += s.read(4096)
        for l in buf.split(b"\n")[:-1]:
            if l.startswith(b"T {"):
                status = l.decode(errors="replace"); break
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in buf)
    if status:
        print(OK, "board -> host works")
    elif not buf:
        print(BAD, "board -> host: silence. Check: board powered? wired firmware flashed (NerdminerV2-Wired)?")
        print("        board GPIO43 -> adapter RXD (not TXD), GND -> GND, the solder joint / Dupont contact on 43.")
        sys.exit(1)
    elif printable < 0.8 * len(buf):
        print(BAD, "board -> host: %d bytes of noise. GND not connected, wrong baud, or the board is running" % len(buf))
        print("        another firmware (stock NerdMiner logs at 115200 on these pins). Flash NerdminerV2-Wired.")
        sys.exit(1)
    else:
        print(BAD, "board -> host: text but no status line yet: %r" % buf[-120:])
        print("        Maybe it is still booting: run this again in 30 s.")
        sys.exit(1)

    # 2. host -> board
    print("sending X, waiting for the reply (adapter TXD -> board GPIO44 RX)...")
    s.reset_input_buffer(); buf = b""; reply = None
    for attempt in range(3):
        s.write(b"X\n"); t0 = time.time()
        while time.time() - t0 < 2 and reply is None:
            buf += s.read(4096)
            for l in buf.split(b"\n")[:-1]:
                if l.startswith(b"x now"):
                    reply = l; break
        if reply:
            break
    if not reply:
        print(BAD, "host -> board: no reply. Check adapter TXD -> board GPIO44 (not 43) and that contact.")
        sys.exit(1)
    print(OK, "host -> board works")

    import json
    try:
        b = json.loads(status[2:])
        print("\nboard: %s MHz, mode %s, hw %s + sw %s hashes so far, bad %s, safe %s" % (
            b.get("mhz"), b.get("mode"), b.get("hw"), b.get("sw"), b.get("bad"), b.get("safe")))
    except Exception:
        pass
    print("\nThe wire is good both ways. Start (or resume) the relay.")
finally:
    try: s.close()
    except Exception: pass
    if paused:
        pause.unlink(missing_ok=True)
