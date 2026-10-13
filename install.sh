#!/usr/bin/env bash
# NetDeflect installer.
# Installs dependencies and runs the guided setup, then lets you choose:
#   1) run it now in this folder, or
#   2) install it as a service that starts on boot.
# Everything else (settings.ini, the notification template, the systemd unit and
# the uninstall script) is generated here or on first run, so the repository
# itself holds only netdeflect.py, methods.json, this installer and the README.
#
# Usage: sudo bash install.sh [--service | --here] [--with-xdp]
#   --service    install as a service without asking
#   --here       run in this folder without asking
#   --with-xdp   also install xdp-tools (for firewall_system = xdp)
# Running it again upgrades an existing install and keeps your settings.
set -eo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/NetDeflect
LOG=/tmp/netdeflect-install.log
MODE=""
WITH_XDP=0

for arg in "$@"; do
    case "$arg" in
        --service)  MODE=2 ;;
        --here)     MODE=1 ;;
        --with-xdp) WITH_XDP=1 ;;
        -h|--help)  sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "Unknown option: $arg (try --help)"; exit 1 ;;
    esac
done

fail() { echo; echo "!! $*"; exit 1; }
trap 'echo; echo "!! The installer stopped at line $LINENO. Details: $LOG"' ERR

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root:  sudo bash install.sh"
    exit 1
fi
[ "$(uname -s)" = "Linux" ] || fail "NetDeflect runs on Linux only."
[ -f "$SRC/netdeflect.py" ] && [ -f "$SRC/methods.json" ] || \
    fail "netdeflect.py and methods.json must be next to install.sh. Clone the repository and run it from there."

# ---------------------------------------------------------------- dependencies
echo "== Installing dependencies (log: $LOG)"
: > "$LOG"
pkg_ok=1
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >>"$LOG" 2>&1 || true
    apt-get install -y -qq python3 python3-psutil python3-requests nftables iproute2 >>"$LOG" 2>&1 || pkg_ok=0
    [ "$WITH_XDP" = 1 ] && { apt-get install -y -qq xdp-tools >>"$LOG" 2>&1 || echo "   xdp-tools not available here; NetDeflect will use nftables."; }
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q python3 python3-psutil python3-requests nftables iproute >>"$LOG" 2>&1 || pkg_ok=0
    [ "$WITH_XDP" = 1 ] && { dnf install -y -q xdp-tools >>"$LOG" 2>&1 || echo "   xdp-tools not available here; NetDeflect will use nftables."; }
elif command -v yum >/dev/null 2>&1; then
    yum install -y -q python3 python3-psutil python3-requests nftables iproute >>"$LOG" 2>&1 || pkg_ok=0
elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install python3 python3-psutil python3-requests nftables iproute2 >>"$LOG" 2>&1 || pkg_ok=0
elif command -v pacman >/dev/null 2>&1; then
    pacman -S --needed --noconfirm python python-psutil python-requests nftables iproute2 >>"$LOG" 2>&1 || pkg_ok=0
    [ "$WITH_XDP" = 1 ] && { pacman -S --needed --noconfirm xdp-tools >>"$LOG" 2>&1 || true; }
else
    pkg_ok=0
    echo "   Unknown package manager."
fi
[ "$pkg_ok" = 1 ] || echo "   Some packages did not install (see $LOG). Checking what is missing..."

# Fall back to pip for the two Python modules only if the system packages are
# missing. Never forces past a distro's "externally managed" protection.
if ! python3 -c "import psutil, requests" >/dev/null 2>&1; then
    python3 -m pip install -q psutil requests >>"$LOG" 2>&1 || true
fi

# Hard checks: stop here with a clear message rather than fail later.
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed."
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' || \
    fail "NetDeflect needs Python 3.7 or newer (found $(python3 -V 2>&1))."
python3 -c "import psutil, requests" >/dev/null 2>&1 || \
    fail "The Python modules psutil and requests are missing. Install them with your package manager (python3-psutil, python3-requests) and run this again."
if ! command -v nft >/dev/null 2>&1 && ! command -v ipset >/dev/null 2>&1; then
    fail "No firewall tool found. Install nftables (recommended) and run this again."
fi
command -v ip >/dev/null 2>&1 || fail "iproute2 (the 'ip' command) is not installed."
echo "   Dependencies OK ($(python3 -V 2>&1))"

# ---------------------------------------------------------------- run mode
has_systemd=0
[ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 && has_systemd=1

if [ -z "$MODE" ]; then
    echo
    echo "How do you want to run NetDeflect?"
    echo "  1) Run it now in this folder ($SRC)"
    echo "  2) Install it as a service (starts on boot, runs in the background)"
    if [ -t 0 ]; then
        while :; do
            read -r -p "Choose 1 or 2 [2]: " MODE
            MODE="${MODE:-2}"
            case "$MODE" in 1|2) break ;; *) echo "Please type 1 or 2." ;; esac
        done
    else
        MODE=2
    fi
fi
if [ "$MODE" = "2" ] && [ "$has_systemd" = 0 ]; then
    echo
    echo "systemd is not running on this machine (common in containers and WSL),"
    echo "so NetDeflect can't be installed as a service. Setting it up in this folder instead."
    MODE=1
fi

configure() {   # run the guided setup in $1 unless a configured settings.ini exists
    cd "$1"
    if [ -f settings.ini ] && grep -q "^ports *= *[0-9]" settings.ini; then
        echo "Keeping your existing settings.ini (edit it any time, then reload/restart)."
    elif [ -t 0 ]; then
        python3 netdeflect.py --setup
    else
        if [ ! -f settings.ini ]; then
            python3 netdeflect.py --write-default-config
            # Unattended install: start in watch-only mode so nothing is blocked
            # before someone has looked at the settings.
            sed -i 's/^enable_ban *= *True/enable_ban = False/' settings.ini
            echo "No terminal for the wizard: wrote $1/settings.ini in WATCH-ONLY mode."
            echo "Edit it (ports, webhook), set enable_ban = True, then reload."
        fi
    fi
    echo "== Checking your system"
    python3 netdeflect.py --selftest || echo "The self-test found something to fix (see above)."
}

if [ "$MODE" = "1" ]; then
    # --- Run here ---
    configure "$SRC"
    echo
    echo "Setup done. Start NetDeflect with:"
    echo "    sudo python3 $SRC/netdeflect.py"
    echo "Watch-only first (no blocking):"
    echo "    sudo python3 $SRC/netdeflect.py --dry-run"
    if [ -t 0 ]; then
        read -r -p "Start it now in this terminal? [y/N]: " GO
        case "$GO" in [yY]*) trap - ERR; exec python3 "$SRC/netdeflect.py" ;; esac
    fi
    exit 0
fi

# --- Install as a service ---
UPGRADE=0
[ -f "$DEST/netdeflect.py" ] && UPGRADE=1
if [ "$UPGRADE" = 1 ]; then
    echo "== Upgrading the existing install in $DEST (your settings are kept)"
else
    echo "== Installing to $DEST"
fi
mkdir -p "$DEST"
if [ "$SRC" != "$DEST" ]; then
    # Keep a copy of signatures you edited yourself before replacing them.
    if [ -f "$DEST/methods.json" ] && ! cmp -s "$SRC/methods.json" "$DEST/methods.json"; then
        cp "$DEST/methods.json" "$DEST/methods.json.bak"
        echo "   Your previous methods.json was saved as methods.json.bak"
    fi
    for f in netdeflect.py methods.json install.sh README.md; do
        [ -f "$SRC/$f" ] && cp "$SRC/$f" "$DEST/"
    done
    [ -f "$DEST/settings.ini" ] || { [ -f "$SRC/settings.ini" ] && cp "$SRC/settings.ini" "$DEST/"; }
fi
chmod 700 "$DEST"
configure "$DEST"

echo "== Installing the service"
# netdeflect.py writes the systemd unit (with this install's paths) and an
# uninstall_rules.sh helper, then enables and starts the service.
python3 "$DEST/netdeflect.py" --config "$DEST/settings.ini" --install-service
# "enable --now" leaves an already-running copy on the old code, so restart.
[ "$UPGRADE" = 1 ] && systemctl restart netdeflect

# Confirm it actually came up rather than assuming it did.
ok=0
for _ in 1 2 3 4 5; do
    sleep 1
    systemctl is-active --quiet netdeflect && { ok=1; break; }
done
echo
if [ "$ok" = 1 ]; then
    echo "NetDeflect is running."
else
    echo "!! NetDeflect did not start. Last log lines:"
    journalctl -u netdeflect -n 20 --no-pager 2>/dev/null || true
    echo "Fix the problem above, then: systemctl restart netdeflect"
fi
echo
echo "  Settings : $DEST/settings.ini     (after editing: systemctl reload netdeflect)"
echo "  Logs     : journalctl -u netdeflect -f"
echo "  Reports  : $DEST/application_data/attack_analysis/"
echo "  Stop     : systemctl stop netdeflect"
echo "  Remove   : systemctl disable --now netdeflect && python3 $DEST/netdeflect.py --teardown"
[ "$ok" = 1 ] || exit 1
