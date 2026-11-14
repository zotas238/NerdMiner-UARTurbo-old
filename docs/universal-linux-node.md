# Universal Linux Node: any computer as the NerdMiner's host, over one USB-A cable

This guide turns **any Linux computer with a free USB-A port** into the host of a wired, overclocked
LilyGo T-Display S3 NerdMiner: a desktop, a laptop, a NAS, a mini PC, a Raspberry Pi, an Orange Pi,
an old thin client... The board runs with Wi-Fi off at up to **300 MHz (~700 kH/s)**. A three-wire link
carries the work from the computer to the board and the shares back.

```
  pool  <-- internet -->  Linux node  ==USB-A==  [USB-UART bridge]  --3 wires-->  T-Display S3
                          (nerd-wired relay)        (CP2102/FT232/CH340)  G 43 44   (Wi-Fi off, 300 MHz)
                                                                          ^
                                                     board power: its own USB-C, from a phone charger
```

Nothing here is specific to one distro or board computer. If it runs Linux and has USB, it can host the miner.

---

## Why you need a USB-to-UART adapter (and can't just splice a USB cable)

The board's pads speak **UART**: plain 3.3 V serial at 921600 baud. A USB-A port speaks **USB**: a
differential packet protocol on D+/D- with 5 V on VBUS. They are not the same signal. If you cut a USB
cable and solder its wires to GPIO43/44, nothing will work, and the 5 V wire can destroy the S3.

Something has to translate, and that is a **USB-to-UART bridge chip**. It's cheap (US$2-15) and
comes in two convenient shapes:

| Shape | What it looks like | What you do |
|---|---|---|
| **A. USB-A cable with loose wires** (best) | A normal-looking USB-A plug, a lump in the cable (the chip), and 4-6 colored wires with female Dupont ends or a 6-pin socket. E.g. **FTDI TTL-232R-3V3**, Adafruit #954, DSD TECH SH-U09C2 | Plug the wire ends onto the board's pins. No soldering on the USB side. |
| **B. USB-A "stick" module** | A small PCB with a USB-A plug at one end and a pin row at the other (the classic **CP2102** stick, or a **CH340G** stick with a 3.3 V/5 V jumper) | 3 Dupont female-female jumpers between its pins and the board. Use a USB-A extension cable if the stick blocks other ports. |
| C. Module with micro-USB / USB-C | Same chip, a different socket | A USB-A to micro-USB/USB-C **data** cable (not a charge-only one) + 3 jumpers. |

**Pick a chip that does 921600 baud cleanly:** CP2102 / CP2102N / CP2104, FT232R / FT231X, CH340 / CH343 /
CH9102. Avoid PL2303 clones. The tools auto-detect all of these; the S3's own USB port is ignored.

**Must be 3.3 V logic.** The FTDI cable must be the **-3V3** variant (not TTL-232R-5V). On jumper-selectable
modules, set the jumper to **3.3 V**. Never use an RS-232 (DB9) adapter: ±12 V.

---

## Which pads on the ESP32-S3 LilyGo T-Display S3

Use exactly three: **G**, **43**, **44**. They are UART0 of the ESP32-S3 (U0TXD = GPIO43, U0RXD = GPIO44).
UART0 can be clocked from the 40 MHz crystal, so it keeps working while the CPU PLL is overclocked.
Wi-Fi and the board's own USB-C don't.

The T-Display S3 has two rows of header holes along its long edges. Every hole is labelled on the
silkscreen. The row you need reads (from the end nearest the USB-C):

```
   USB-C end
  ┌──────────────────────────────────────────────┐
  │  G   5V   43   44   18   17   21   16        │   <- this row
  │  ●   ●    ●    ●    ●    ●    ●    ●         │
  │                  (display side)              │
  │  ●   ●    ●    ●    ●    ●    ●    ●    ●    │
  │  G   3V   1    2    3    10   11   12   13   │   <- other row: not used
  └──────────────────────────────────────────────┘
```

> **Read the silkscreen on your board.** Revisions differ. What matters is the printed labels **G**, **43**
> and **44**, not their position in this drawing. Note that **5V sits right next to 43**: a solder bridge
> between them puts 5 V on GPIO43. Check every joint with a magnifier, and with a meter if you have one.

**Pins or wires?** Either solder a 2.54 mm pin header into the row (then the adapter's Dupont ends push on),
or solder short wires straight into the holes G/43/44. Clean the flux off afterwards. A loose or cold joint on
43 is the most common failure. The author's board had one: work reached the board, but nothing came back.

---

## Wiring: signal by signal

TX goes to RX both ways; the grounds are joined; **nothing else is connected**.

| T-Display S3 pad | Signal on the board | Connect to adapter pin | Direction |
|---|---|---|---|
| **43** | U0TXD (board transmits) | **RXD** (sometimes "RX", "RXI") | board → computer |
| **44** | U0RXD (board receives) | **TXD** (sometimes "TX", "TXO") | computer → board |
| **G** | ground | **GND** | shared reference |
| *5V / 3V* | - | **leave the adapter's VCC / 5V / 3V3 unconnected** | - |
| - | - | **leave DTR, RTS, CTS, DSR unconnected** | - |

The board is powered from **its own USB-C, by a plain phone charger**. Don't plug the board's USB-C into the
same computer: it isn't needed, and an open-but-unread USB serial port can stall the firmware.

### Cable colours for common adapters

Always go by the **printed label or the datasheet**, not just colour: clones swap colours. But for the common
ones:

**FTDI TTL-232R-3V3** (USB-A plug, 6-way 0.1" socket; the 6-pin socket fits a 6-pin header, or use jumpers):

| Wire colour | FTDI signal | → T-Display S3 |
|---|---|---|
| **Black** | GND | **G** |
| **Yellow** | RXD (into the PC) | **43** |
| **Orange** | TXD (out of the PC) | **44** |
| Red | VCC = **5 V** | not connected (insulate it) |
| Brown | CTS# | not connected |
| Green | RTS# | not connected |

**Adafruit #954-style "USB to TTL serial cable"** (4 loose female wires):

| Wire colour | Signal | → T-Display S3 |
|---|---|---|
| **Black** | GND | **G** |
| **White** | RX (into the USB port) | **43** |
| **Green** | TX (out of the USB port) | **44** |
| Red | **5 V** power | **not connected** (fold it back, tape it) |

**CP2102 / CH340 stick** (pin row labelled on the PCB, typically `DTR RXD TXD 5V/VCC CTS GND` or
`3V3 TXD RXD GND 5V`): one jumper each from **GND → G**, **RXD → 43**, **TXD → 44**. On a CH340 stick with a
voltage jumper, put it on **3V3** first.

Keep the three wires short: up to ~30 cm is fine at 921600 baud. Twisting GND around the two data wires helps
on longer runs.

---

## Step by step

### 0. What you need

- LilyGo **T-Display S3** (ESP32-S3R8, 16 MB flash, 8 MB PSRAM). Other S3 boards: see the main README.
- A **3.3 V USB-to-UART adapter** from the list above, + 3 female-female Dupont jumpers if it's a stick.
- A 5 V USB-C phone charger for the board.
- A Linux computer with Python 3.8+ (any distro; systemd or OpenRC get a service automatically).
- A stratum v1 pool and your BTC address: e.g. `public-pool.io:21496`, `solo.ckpool.org:3333`, or your own.

### 1. Flash the wired firmware once, over the board's USB-C

This is the only time the board's USB-C carries data. Do it from any computer:

```bash
# get NerdminerV2-Wired_factory.bin from Releases, or build it: pio run -e NerdminerV2-Wired
pipx run esptool --chip esp32s3 erase-flash                 # or: python3 -m pip install --user esptool
pipx run esptool --chip esp32s3 -b 921600 write-flash 0x0 NerdminerV2-Wired_factory.bin
```

If the port isn't found, hold **BOOT**, plug in the USB-C, then release BOOT. Without a terminal, the
[ESP Web Flasher](https://espressif.github.io/esptool-js/) in Chrome works: put the factory bin at offset 0x0.
Then unplug the board from the computer.

### 2. Test the adapter alone (loopback)

Plug the adapter into the Linux node, connect its **TXD to its own RXD** with one jumper, and run:

```bash
git clone https://github.com/zotas238/NerdMiner-UARTurbo && cd NerdMiner-UARTurbo
python3 wired/tools/wirecheck.py --list         # is the adapter seen?
python3 wired/tools/wirecheck.py --loopback     # 4 KB out and back at 921600
```

`[ok] adapter loopback` means the adapter, its driver and your permissions are fine. (Permission denied? Use
`sudo`, or add yourself to the `dialout` group (`uucp` on Arch), then log in again.) Remove the jumper.

### 3. Wire it

Board unpowered: **G → GND, 43 → RXD, 44 → TXD**, as in the tables above. Then power the board from the
charger. The screen lights up; there's no Wi-Fi setup: the wired firmware never turns Wi-Fi on.

### 4. Check the wire, both directions

```bash
python3 wired/tools/wirecheck.py
#   [ok]   board -> host works
#   [ok]   host -> board works
#   board: 240 MHz, mode t5, ...
```

Each failure names the wire to look at (see *Troubleshooting*).

### 5. Install the relay as a service

```bash
sudo wired/linux/install.sh --pool public-pool.io:21496 --user bc1qYOURADDRESS.node1
```

That installs pyserial from your distro's packages and the relay to `/opt/nerd-wired`. It writes
`/etc/nerd-wired.conf`, creates a `nerdminer` system user, adds a **udev rule that names your adapter
`/dev/nerdminer`** (so it's found whichever port or `ttyUSBn` number it gets), and starts a systemd or OpenRC
service that starts at boot and restarts itself. Then:

```bash
nerd-wired status     # hashrate, clock, accepted / rejected / bad shares
nerd-wired log        # follow the relay
```

Expect ~485 kH/s or more at stock 240 MHz within a minute, and the first accepted shares soon after.

### 6. Overclock (optional)

```bash
nerd-wired mhz 300    # or 260 / 280; 240 = stock
```

The setting is saved (`/var/lib/nerd-wired/oc.json`) and applied 30 s after every boot of the board. Go up a
step at a time, and watch `nerd-wired status` for 15 minutes at each one: **bad must stay 0**. Two crashes at a
setting within an hour make the relay step down by itself. See the main README for the mode bits, voltage
and safety nets.

| CPU | Author's T-Display S3 |
|---|---|
| 240 MHz (stock) | ~485 kH/s (before Turbo8) |
| 260 MHz | ~521 kH/s (before Turbo8) |
| 280 MHz | ~640-646 kH/s |
| **300 MHz** | **~700 kH/s**, stock voltage, ~34 °C, ~1 crash a day (auto-recovers) |

### 7. Update the firmware later: over the same wire

```bash
nerd-wired ota NerdminerV2-Wired_firmware.bin    # the *_firmware.bin, not *_factory.bin; ~2-3 min
```

No buttons, no USB-C, works while overclocked. The board checks the image before booting it; a cut-off
transfer leaves the old firmware running.

### Moving the miner to another node

Unplug the adapter, plug it into the other computer, run step 5 there (and `sudo wired/linux/install.sh
--uninstall` on the old one). The board keeps its firmware, so there is nothing to redo on the miner itself.
Each node can host one board per adapter: for several boards, run one relay per adapter with
`--port /dev/serial/by-id/...` and its own `--state` folder.

---

## Troubleshooting

| `wirecheck.py` / symptom | Look at |
|---|---|
| `no USB-UART adapter found` | `lsusb`: is the chip listed? Charge-only cable (shape C)? Very old kernels may lack the CH343 driver (`cdc_acm` handles CH343/CH9102 on new kernels). |
| loopback: nothing came back | The TXD-RXD jumper, or a 5 V-only / broken adapter. |
| loopback: bytes differ | The adapter can't do 921600 cleanly (PL2303 clone?): use a CP2102 / FT232 / CH343. |
| `board -> host: silence` | Board powered? Wired firmware flashed? **43 → RXD** (not TXD)? The joint on **43**. GND. |
| `board -> host: noise` | GND missing, a 5 V adapter, or the board still running the stock (Wi-Fi) NerdMiner, which logs at 115200. Re-flash step 1. |
| `host -> board: no reply` | **44 → TXD** and its joint. |
| status says safe-mode True, ~275 kH/s | The crash guard tripped (overclock too high): lower `nerd-wired mhz`, then `nerd-wired unsafe`. |
| bad > 0, rejected climbing, reboots | Overclock too high for your chip: one step down. |
| `/dev/nerdminer` missing after moving the adapter | Adapters without a unique serial number (most CH340s) are matched by USB socket: put it back, or run `sudo nerd-wired pin` again. |
| Board dead or boot-looping | USB recovery: hold BOOT, plug its USB-C into a computer, redo step 1. The ROM bootloader can always be reached. |

## Safety notes

- Only 3.3 V on GPIO43/44. The S3 is not 5 V tolerant.
- The overclock uses undocumented PLL registers; silicon differs. It's protected by an RTC watchdog, the relay's
  step-down, the crash guard, and the relay re-hashing every share. But it is still at your own risk.
- Solo mining a T-Display S3 is a lottery ticket, not income.
