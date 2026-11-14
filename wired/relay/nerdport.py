"""Find the serial port wired to the NerdMiner S3. Shared by the relay and the tools.

`--port auto` (the default) resolves, in order:
  1. /dev/nerdminer   the stable name the udev rule from `nerd-wired pin` (or install.sh) creates
  2. the one USB-to-UART adapter plugged in (CP210x, CH340/CH343/CH9102, FTDI, PL2303)
The ESP32-S3's own USB port (Espressif VID 0x303a) is never picked: it can't carry the link.
Run `python3 nerdport.py` to list what it sees, or `python3 nerdport.py --udev` to print a rule.
"""
import os
import sys

STABLE = "/dev/nerdminer"
ESPRESSIF_VID = 0x303A
# (vid, pid) -> chip. All of these do 921600 baud at 3.3 V logic (on the 3.3 V setting).
KNOWN = {
    (0x10C4, 0xEA60): "Silicon Labs CP2102/CP2102N/CP2104",
    (0x10C4, 0xEA70): "Silicon Labs CP2105",
    (0x10C4, 0xEA71): "Silicon Labs CP2108",
    (0x1A86, 0x7523): "WCH CH340",
    (0x1A86, 0x7522): "WCH CH340K",
    (0x1A86, 0x55D3): "WCH CH343",
    (0x1A86, 0x55D4): "WCH CH9102",
    (0x0403, 0x6001): "FTDI FT232R",
    (0x0403, 0x6015): "FTDI FT230X/FT231X",
    (0x0403, 0x6010): "FTDI FT2232",
    (0x0403, 0x6011): "FTDI FT4232",
    (0x0403, 0x6014): "FTDI FT232H",
    (0x067B, 0x2303): "Prolific PL2303 (clones can be flaky at 921600)",
    (0x067B, 0x23A3): "Prolific PL2303GC",
}


def candidates():
    """[(device, chip, vid, pid, serial_number, location)] for every known USB-UART adapter."""
    from serial.tools import list_ports
    out = []
    for p in sorted(list_ports.comports(), key=lambda p: p.device):
        if p.vid is None or p.vid == ESPRESSIF_VID:
            continue
        chip = KNOWN.get((p.vid, p.pid))
        if chip:
            out.append((p.device, chip, p.vid, p.pid, p.serial_number, p.location))
    return out


def resolve(port="auto"):
    """The port to open. Raises LookupError with a readable reason if `auto` can't decide."""
    if port and port != "auto":
        return port
    if os.path.exists(STABLE):
        return STABLE
    c = candidates()
    if len(c) == 1:
        return c[0][0]
    if not c:
        raise LookupError("no USB-UART adapter found (CP210x, CH340/CH343, FTDI, PL2303). "
                          "Plug it in, or pass --port (e.g. /dev/ttyAMA0 for a header UART)")
    raise LookupError("several USB-UART adapters: " + ", ".join(d[0] for d in c) +
                      ". Pass --port, or run `nerd-wired pin` to name the right one /dev/nerdminer")


def udev_rule(device, group="nerdminer"):
    """A udev rule that names this adapter /dev/nerdminer (by serial number, else by USB socket)."""
    for dev, chip, vid, pid, serial, loc in candidates():
        if os.path.realpath(dev) != os.path.realpath(device):
            continue
        m = 'SUBSYSTEM=="tty", ATTRS{idVendor}=="%04x", ATTRS{idProduct}=="%04x"' % (vid, pid)
        if serial and serial not in ("0001", "0000", "1234567890"):   # generic serials repeat across units
            m += ', ATTRS{serial}=="%s"' % serial
            how = "serial number %s (any USB socket)" % serial
        elif loc:
            m += ', KERNELS=="%s"' % loc
            how = "USB socket %s (no unique serial number: keep it in this socket)" % loc
        else:
            how = "vendor/product only"
        g = ', GROUP="%s", MODE="0660"' % group if group else ""
        return "# NerdMiner S3 wire: %s, matched by %s\n%s%s, SYMLINK+=\"nerdminer\"\n" % (chip, how, m, g)
    raise LookupError("%s is not a known USB-UART adapter" % device)


if __name__ == "__main__":
    if "--udev" in sys.argv:
        args = [a for a in sys.argv[1:] if not a.startswith("--")]
        try:
            dev = args[0] if args else resolve("auto")
            if os.path.realpath(dev) == os.path.realpath(STABLE) and len(args) == 0:
                dev = os.path.realpath(STABLE)
            sys.stdout.write(udev_rule(dev))
        except LookupError as e:
            sys.exit(str(e))
        sys.exit(0)
    c = candidates()
    if not c:
        print("no USB-UART adapter found")
    for dev, chip, vid, pid, serial, loc in c:
        print("%-14s %04x:%04x  %-40s serial=%s  usb=%s" % (dev, vid, pid, chip, serial, loc))
    if os.path.exists(STABLE):
        print("%s -> %s" % (STABLE, os.path.realpath(STABLE)))
    try:
        print("auto ->", resolve("auto"))
    except LookupError as e:
        print("auto -> (none)", e)
