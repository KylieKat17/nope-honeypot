#!/usr/bin/env bash
# NOPE installer for Ubuntu/Debian.
#
#   bash install.sh defender            set up NOPE on the machine being protected
#   bash install.sh defender --service  same, plus a systemd service that starts on boot
#   bash install.sh attacker            install the tools used to test / demo NOPE
#   bash install.sh remove-service      stop and remove the systemd service
#
# Run it as your normal user from inside the repo, NOT with sudo.
# It asks for your sudo password only for the steps that need it.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$REPO/.venv"
UNIT=/etc/systemd/system/nope.service

DEFENDER_PKGS=(python3 python3-venv python3-pip nftables)
ATTACKER_PKGS=(nmap redis-tools netcat-openbsd hydra)

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*" >&2; }
die() {
    printf '\033[1;31mxx\033[0m  %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
usage:
  bash install.sh defender            set up NOPE on the machine being protected
  bash install.sh defender --service  same, plus a systemd service that starts on boot
  bash install.sh attacker            install the tools used to test / demo NOPE
  bash install.sh remove-service      stop and remove the systemd service

Run as your normal user (not sudo). The script calls sudo itself.
EOF
    exit "${1:-0}"
}

my_ip() {
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo "${ip:-unknown}"
}

apt_install() {
    say "Installing packages: $*"
    sudo apt-get update -qq || warn "apt-get update failed, trying the install anyway"
    local failed=()
    for pkg in "$@"; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            continue
        fi
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" >/dev/null ||
            failed+=("$pkg")
    done
    if ((${#failed[@]})); then
        warn "could not install: ${failed[*]}"
    fi
}

# Decoy ports from config.yaml, falling back to the defaults if it can't be read.
decoy_ports() {
    "$VENV/bin/python" - "$REPO/config.yaml" 2>/dev/null <<'PY' || echo "2222 6379"
import sys
import yaml

cfg = yaml.safe_load(open(sys.argv[1])) or {}
decoys = cfg.get("decoys") or {}
ports = [str(d["port"]) for d in decoys.values() if d.get("enabled", True) and "port" in d]
print(" ".join(ports) or "2222 6379")
PY
}

install_defender() {
    local want_service=$1

    [[ -f "$REPO/pyproject.toml" ]] || die "pyproject.toml not found in $REPO, run this from the NOPE repo"

    apt_install "${DEFENDER_PKGS[@]}"
    command -v nft >/dev/null || [[ -x /usr/sbin/nft ]] || die "nft is still missing, install nftables by hand"
    python3 -m venv --help >/dev/null 2>&1 || die "python3 venv support is missing (apt install python3-venv)"

    # A .venv left over from an earlier `sudo` run is owned by root and can't be reused.
    if [[ -e "$VENV" && ! -O "$VENV" ]]; then
        die ".venv is owned by another user (probably root). Remove it with: sudo rm -rf '$VENV'"
    fi
    if [[ -d "$VENV" && ! -x "$VENV/bin/python" ]]; then
        warn "removing broken .venv"
        rm -rf "$VENV"
    fi
    if [[ ! -d "$VENV" ]]; then
        say "Creating virtual environment in .venv"
        python3 -m venv "$VENV"
    fi

    say "Installing NOPE into .venv"
    "$VENV/bin/pip" install -q -e "$REPO"
    [[ -x "$VENV/bin/nope" ]] || die "install finished but $VENV/bin/nope is missing"

    local ports
    ports=$(decoy_ports)

    if command -v ufw >/dev/null && sudo ufw status 2>/dev/null | grep -q '^Status: active'; then
        say "ufw is active, allowing decoy ports: $ports"
        for p in $ports; do
            sudo ufw allow "$p/tcp" >/dev/null
        done
    fi

    if [[ "$want_service" == 1 ]]; then
        install_service
    else
        for p in $ports; do
            if ss -ltnH "sport = :$p" 2>/dev/null | grep -q .; then
                warn "something is already listening on port $p, the decoy there will fail to start"
                warn "  see what it is with: sudo ss -ltnp 'sport = :$p'"
            fi
        done
    fi

    local ip
    ip=$(my_ip)
    echo
    say "Defender ready on $(hostname) (IP: $ip)"
    cat <<EOF

Next:
  1. Edit config.yaml and put your own admin/host IPs under 'whitelist'.
     Do NOT whitelist the attacker.
EOF
    if [[ "$want_service" == 1 ]]; then
        cat <<EOF
  2. NOPE is running as a service. Watch it live with:
       sudo journalctl -fu nope
     For a live demo in a terminal, stop the service first so the ports are free:
       sudo systemctl stop nope && sudo .venv/bin/nope run
EOF
    else
        cat <<EOF
  2. Start it from this folder:
       sudo .venv/bin/nope run
EOF
    fi
    cat <<EOF
  3. Check it from another terminal (use sudo, the database belongs to root):
       sudo .venv/bin/nope status | blocked | recent | unblock <ip>

Attacker should target: $ip  (decoy ports: $ports)
EOF
}

install_service() {
    local nft_bin
    nft_bin=$(command -v nft || echo /usr/sbin/nft)
    say "Installing systemd service ($UNIT)"
    sudo tee "$UNIT" >/dev/null <<EOF
[Unit]
Description=NOPE Observes Potential Enemies (honeypot-triggered intrusion response)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$REPO
ExecStart="$VENV/bin/nope" run -c "$REPO/config.yaml"
# SIGINT lets NOPE shut down cleanly and remove its nftables table
KillSignal=SIGINT
# belt and braces: drop the table even if NOPE crashed
ExecStopPost=-$nft_bin delete table inet nope
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable --now nope.service
    if sudo systemctl is-active --quiet nope.service; then
        say "Service is running"
    else
        warn "service did not start, check: sudo journalctl -u nope -n 50"
    fi
}

remove_service() {
    if [[ ! -f "$UNIT" ]]; then
        say "No NOPE service installed, nothing to do"
        return
    fi
    say "Removing systemd service"
    sudo systemctl disable --now nope.service || true
    sudo rm -f "$UNIT"
    sudo systemctl daemon-reload
    say "Service removed (the .venv and repo are untouched)"
}

install_attacker() {
    apt_install "${ATTACKER_PKGS[@]}"
    local missing=0
    for tool in nmap redis-cli nc hydra; do
        if command -v "$tool" >/dev/null; then
            say "ok: $tool"
        else
            warn "missing: $tool"
            missing=1
        fi
    done
    local ip
    ip=$(my_ip)
    echo
    say "Attacker ready on $(hostname) (IP: $ip)"
    cat <<EOF

Make sure the defender does NOT whitelist this IP: $ip

Quick test against the defender (replace DEFENDER_IP):
  nc -v DEFENDER_IP 2222
  nmap -sV -p 2222,6379 DEFENDER_IP
  for i in 1 2 3 4; do timeout 5 redis-cli -h DEFENDER_IP AUTH guess\$i; done
  ping -c 3 -W 1 DEFENDER_IP      # should fail once you're blocked
EOF
    if ((missing)); then
        warn "some tools are missing, try: sudo apt update && sudo apt install ${ATTACKER_PKGS[*]}"
    fi
}

main() {
    local role=${1:-}
    shift || true

    local want_service=0
    for arg in "$@"; do
        case $arg in
        --service) want_service=1 ;;
        -h | --help) usage ;;
        *) die "unknown option: $arg (see: bash install.sh --help)" ;;
        esac
    done

    case $role in
    -h | --help | "") usage ;;
    defender | attacker | remove-service) ;;
    *) die "unknown role: $role (use defender, attacker or remove-service)" ;;
    esac

    [[ $EUID -ne 0 ]] || die "run this as your normal user, not with sudo (it calls sudo itself)"
    command -v apt-get >/dev/null || die "this installer only supports Ubuntu/Debian (apt)"
    sudo -v || die "sudo access is needed"

    case $role in
    defender) install_defender "$want_service" ;;
    attacker)
        [[ $want_service == 0 ]] || die "--service only applies to the defender"
        install_attacker
        ;;
    remove-service) remove_service ;;
    esac
}

main "$@"
