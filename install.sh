#!/usr/bin/env bash
# NetDeflect installer.
# Installs dependencies and runs the guided setup, then lets you choose:
#   1) run it now in this folder, or
#   2) install it as a service that starts on boot.
# Everything else (settings.ini, the notification template, the systemd unit and
# the uninstall script) is generated here or on first run, so the repository
# itself holds only netdeflect.py, methods.json, this installer and the README.
# Usage: sudo bash install.sh
set -e

SRC="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root:  sudo bash install.sh"
    exit 1
fi

echo "== Installing dependencies"
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    apt-get install -y -qq python3 python3-psutil python3-requests nftables iproute2 >/dev/null
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q python3 python3-psutil python3-requests nftables iproute
elif command -v yum >/dev/null 2>&1; then
    yum install -y -q python3 python3-psutil python3-requests nftables iproute
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm python python-psutil python-requests nftables iproute2
else
    echo "Unknown package manager. Please install python3, psutil, requests, nftables"
    echo "and iproute2 yourself, then run this again."
fi
python3 -c "import psutil, requests" 2>/dev/null || python3 -m pip install -q psutil requests 2>/dev/null || true

# Optional: xdp-tools gives the XDP fast path (firewall_system = xdp). Not
# required; NetDeflect runs on nftables without it.
# apt-get install -y xdp-tools   # or: dnf install xdp-tools

# Ask how they want to run it.
echo
echo "How do you want to run NetDeflect?"
echo "  1) Run it now in this folder ($SRC)"
echo "  2) Install it as a service (starts on boot, runs in the background)"
MODE=""
if [ -t 0 ]; then
    read -r -p "Choose 1 or 2 [2]: " MODE
fi
MODE="${MODE:-2}"

configure() {   # run the guided setup in $1 unless a configured settings.ini exists
    cd "$1"
    if [ -f settings.ini ] && grep -q "^ports *= *[0-9]" settings.ini; then
        echo "Keeping your existing settings.ini (edit it any time, then reload/restart)."
    elif [ -t 0 ]; then
        python3 netdeflect.py --setup
    else
        [ -f settings.ini ] || python3 netdeflect.py --write-default-config
        echo "No terminal for the wizard: edit $1/settings.ini before starting."
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
        case "$GO" in [yY]*) exec python3 "$SRC/netdeflect.py" ;; esac
    fi
else
    # --- Install as a service ---
    DEST=/opt/NetDeflect
    echo "== Installing to $DEST"
    mkdir -p "$DEST"
    if [ "$SRC" != "$DEST" ]; then
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
    echo
    echo "  Settings : $DEST/settings.ini     (after editing: systemctl reload netdeflect)"
    echo "  Logs     : journalctl -u netdeflect -f"
    echo "  Reports  : $DEST/application_data/attack_analysis/"
    echo "  Stop     : systemctl stop netdeflect"
    echo "  Remove   : systemctl disable --now netdeflect && python3 $DEST/netdeflect.py --teardown"
fi
