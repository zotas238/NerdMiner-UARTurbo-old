#!/bin/sh
# Install the wired NerdMiner relay as a service on any Linux node (PC, laptop, NAS, Raspberry Pi, Orange Pi...).
#
#   sudo ./install.sh --pool public-pool.io:21496 --user bc1qYOURADDRESS.wired [--port auto] [--mhz 240]
#
#   --pool HOST:PORT   stratum v1 pool (required)
#   --user ADDR[.name] your BTC address, optionally .workername (required)
#   --password P       pool password (default x)
#   --port auto|DEV    auto (default): /dev/nerdminer, else the one USB-UART adapter plugged in.
#                      A header UART needs its device, e.g. /dev/ttyAMA0 (Pi) or /dev/ttyS3 (Orange Pi 5).
#   --mhz 240|260|280|300   CPU clock to apply after every boot of the board (default 240 = stock, no overclock)
#   --no-start         install and enable, but don't start it now
#   --uninstall        remove everything this script installed (keeps /var/lib/nerd-wired unless --purge)
#
# Installs: /opt/nerd-wired (relay + tools), /etc/nerd-wired.conf, /usr/local/bin/nerd-wired,
# a system user "nerdminer", state in /var/lib/nerd-wired, a udev rule naming the adapter /dev/nerdminer
# (when one is plugged in), and a systemd or OpenRC service called nerd-wired.
set -eu

POOL= USER_= PASSWORD=x PORT=auto MHZ= START=1 UNINSTALL=0 PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --pool) POOL=$2; shift 2 ;;
    --user) USER_=$2; shift 2 ;;
    --password) PASSWORD=$2; shift 2 ;;
    --port) PORT=$2; shift 2 ;;
    --mhz) MHZ=$2; shift 2 ;;
    --no-start) START=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) UNINSTALL=1; PURGE=1; shift ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = 0 ] || { echo "run as root (sudo $0 ...)" >&2; exit 1; }
HERE=$(cd "$(dirname "$0")/.." && pwd)          # the repo's wired/ folder
OPT=/opt/nerd-wired CONF=/etc/nerd-wired.conf STATE=/var/lib/nerd-wired SVC_USER=nerdminer
RULE=/etc/udev/rules.d/99-nerdminer.rules
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
has() { command -v "$1" >/dev/null 2>&1; }
INIT=none
if [ -d /run/systemd/system ]; then INIT=systemd; elif has openrc-run || has rc-service; then INIT=openrc; fi

if [ $UNINSTALL = 1 ]; then
  case $INIT in
    systemd) systemctl disable --now nerd-wired 2>/dev/null || true; rm -f /etc/systemd/system/nerd-wired.service; systemctl daemon-reload ;;
    openrc) rc-service nerd-wired stop 2>/dev/null || true; rc-update del nerd-wired 2>/dev/null || true; rm -f /etc/init.d/nerd-wired ;;
    *) pkill -f "$OPT/relay/wired_relay.py" 2>/dev/null || true ;;
  esac
  rm -rf "$OPT" /usr/local/bin/nerd-wired "$CONF" "$RULE"
  has udevadm && udevadm control --reload 2>/dev/null || true
  [ $PURGE = 1 ] && rm -rf "$STATE" && { userdel "$SVC_USER" 2>/dev/null || deluser "$SVC_USER" 2>/dev/null || true; }
  if [ $PURGE = 1 ]; then say "removed, with $STATE and the $SVC_USER user"; else say "removed (kept $STATE: --purge drops it)"; fi
  exit 0
fi

[ -n "$POOL" ] && [ -n "$USER_" ] || { echo "--pool and --user are required (see --help)" >&2; exit 2; }
case "$POOL" in *:[0-9]*) ;; *) echo "--pool must be host:port" >&2; exit 2 ;; esac
case "${MHZ:-240}" in
  240) DIV=8 MODE=0 ;; 260) DIV=9 MODE=20 ;; 280) DIV=10 MODE=20 ;; 300) DIV=11 MODE=48 ;;
  *) echo "--mhz must be 240, 260, 280 or 300" >&2; exit 2 ;;
esac

# 1. Python 3.8+ and pyserial, from the distro's packages (no pip into the system Python)
has python3 || { echo "python3 is missing: install it with your package manager" >&2; exit 1; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || { echo "python 3.8+ needed" >&2; exit 1; }
if ! python3 -c 'import serial' 2>/dev/null; then
  say "installing pyserial"
  if has apt-get; then apt-get install -y python3-serial
  elif has dnf; then dnf install -y python3-pyserial
  elif has pacman; then pacman -S --noconfirm --needed python-pyserial
  elif has zypper; then zypper --non-interactive install python3-pyserial
  elif has apk; then apk add py3-pyserial
  elif has xbps-install; then xbps-install -y python3-pyserial
  else echo "install pyserial for python3 yourself (package python3-serial / python3-pyserial)" >&2; exit 1
  fi
fi

# 2. files
say "installing to $OPT"
mkdir -p "$OPT/relay" "$OPT/tools"
cp "$HERE/relay/wired_relay.py" "$HERE/relay/nerdport.py" "$OPT/relay/"
cp "$HERE/tools/wireota.py" "$HERE/tools/wirecheck.py" "$HERE/tools/coredump_get.py" "$OPT/tools/"
install -m 755 "$HERE/linux/nerd-wired" /usr/local/bin/nerd-wired

# 3. service user, allowed to open serial ports
if ! id "$SVC_USER" >/dev/null 2>&1; then
  say "creating system user $SVC_USER"
  if has useradd; then useradd -r -M -d "$STATE" -s /usr/sbin/nologin "$SVC_USER" 2>/dev/null || useradd -r -M -d "$STATE" -s /sbin/nologin "$SVC_USER"
  else adduser -S -D -H -h "$STATE" -s /sbin/nologin "$SVC_USER"; fi
fi
for g in dialout uucp tty; do   # whichever owns /dev/ttyUSB* / ttyS* on this distro
  if getent group "$g" >/dev/null; then
    if has usermod; then usermod -aG "$g" "$SVC_USER"; else addgroup "$SVC_USER" "$g" 2>/dev/null || true; fi
  fi
done
mkdir -p "$STATE"
[ -f "$STATE/oc.json" ] && [ -z "$MHZ" ] || printf '{"div": %s, "mode": %s}\n' "$DIV" "$MODE" > "$STATE/oc.json"
chown -R "$SVC_USER" "$STATE"

# 4. config
umask 077
cat > "$CONF" <<EOF
# wired NerdMiner relay settings (read by the nerd-wired service and the nerd-wired command)
NERD_PORT=$PORT
NERD_POOL=$POOL
NERD_USER=$USER_
NERD_PASSWORD=$PASSWORD
NERD_BAUD=921600
NERD_WIRED_STATE=$STATE
EOF
chmod 640 "$CONF"; chgrp "$SVC_USER" "$CONF" 2>/dev/null || true
umask 022

# 5. stable name for the adapter (udev), if one is plugged in and auto is used
if [ "$PORT" = auto ] && [ ! -e "$RULE" ] && has udevadm; then
  if python3 "$OPT/relay/nerdport.py" --udev > /tmp/nerd-rule.$$ 2>/dev/null; then
    mv /tmp/nerd-rule.$$ "$RULE"; chmod 644 "$RULE"
    udevadm control --reload && udevadm trigger --subsystem-match=tty
    say "udev: $(sed -n 1p "$RULE" | sed 's/^# //') -> /dev/nerdminer"
  else
    rm -f /tmp/nerd-rule.$$
    say "no single USB-UART adapter plugged in: skipped the /dev/nerdminer rule (run 'sudo nerd-wired pin' later)"
  fi
fi

# 6. service
case $INIT in
systemd)
  cat > /etc/systemd/system/nerd-wired.service <<EOF
[Unit]
Description=Wired NerdMiner relay (ESP32-S3 on a UART)
Wants=network-online.target
After=network-online.target

[Service]
EnvironmentFile=$CONF
User=$SVC_USER
ExecStart=/usr/bin/env python3 $OPT/relay/wired_relay.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable nerd-wired >/dev/null 2>&1
  [ $START = 1 ] && systemctl restart nerd-wired
  ;;
openrc)
  cat > /etc/init.d/nerd-wired <<EOF
#!/sbin/openrc-run
description="Wired NerdMiner relay (ESP32-S3 on a UART)"
supervisor=supervise-daemon
command=/usr/bin/python3
command_args="$OPT/relay/wired_relay.py"
command_user=$SVC_USER
respawn_delay=5
depend() { need net; }
start_pre() { set -a; . $CONF; set +a; export NERD_PORT NERD_POOL NERD_USER NERD_PASSWORD NERD_BAUD NERD_WIRED_STATE; }
EOF
  chmod 755 /etc/init.d/nerd-wired
  rc-update add nerd-wired default >/dev/null
  [ $START = 1 ] && rc-service nerd-wired restart
  ;;
*)
  say "no systemd or OpenRC here: start it by hand (or from rc.local / @reboot):"
  echo "    nerd-wired run &"
  ;;
esac

say "done. The board mines at ${MHZ:-240} MHz once the relay sees it."
echo "    nerd-wired check     test the wire both ways"
echo "    nerd-wired status    hashrate, shares, clock"
echo "    nerd-wired log       follow the relay log"
echo "    nerd-wired help      everything else"
