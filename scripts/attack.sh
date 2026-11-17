#!/usr/bin/env bash
# NOPE demo attack. Run this on the ATTACKER machine, never on the defender.
#
#   bash scripts/attack.sh <defender-ip> [options]
#
# Goes from harmless to blocked, one stage at a time:
#   1. banner grab on the SSH decoy       (low score, just logged)
#   2. nmap service scan of the decoys    (recon)
#   3. Redis password guessing            (should get this machine blocked)
#   4. checks the block from this side
#   5. waits while you run `nope unblock` on the defender
#   6. Redis exploit-style commands       (10 points each vs 5 for a guess, blocked again)
#
# Options:
#   --auto           don't pause for Enter between stages
#   --skip-nmap      leave out stage 2
#   --ssh-port N     SSH decoy port   (default 2222)
#   --redis-port N   Redis decoy port (default 6379)
#   --wait N         max seconds to wait for an unblock (default 300)
#
# Only point this at machines you own and run NOPE on.

set -uo pipefail

TARGET=""
AUTO=0
SKIP_NMAP=0
SSH_PORT=2222
REDIS_PORT=6379
WAIT=300
MAX_TRIES=8
STAGE=0

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

head_() {
    STAGE=$((STAGE + 1))
    printf '\n\033[1;36m[%d] %s\033[0m\n' "$STAGE" "$*"
}
info() { printf '    %s\n' "$*"; }
good() { printf '    \033[1;32m%s\033[0m\n' "$*"; }
bad() { printf '    \033[1;31m%s\033[0m\n' "$*"; }
show() { printf '    \033[2m$ %s\033[0m\n' "$*"; }
die() {
    bad "$*"
    exit 1
}

pause() {
    ((AUTO)) && return 0
    read -rp "    press Enter to continue... " _ </dev/tty || true
}

have() { command -v "$1" >/dev/null 2>&1; }

# The address this machine uses to reach the defender (what NOPE will see).
my_ip() {
    local ip=""
    if have ip; then
        ip=$(ip -4 route get "$TARGET" 2>/dev/null |
            awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')
    fi
    [[ -n "$ip" ]] || ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo "${ip:-unknown}"
}

# Can we reach the defender at all? ping doesn't touch the decoys, so it
# doesn't add to our score. Fall back to a TCP connect if ping is missing.
reachable() {
    if have ping; then
        ping -c 1 -W 1 "$TARGET" >/dev/null 2>&1
    else
        timeout 4 nc -z -w 3 "$TARGET" "$SSH_PORT" >/dev/null 2>&1
    fi
}

wait_for_unblock() {
    info "On the DEFENDER run:  sudo .venv/bin/nope unblock $ME"
    info "(or wait for the block to expire)"
    printf '    waiting'
    local waited=0
    while ! reachable; do
        if ((waited >= WAIT)); then
            echo
            bad "still blocked after ${WAIT}s, giving up"
            return 1
        fi
        printf '.'
        sleep 2
        waited=$((waited + 2))
    done
    echo
    good "reachable again after ~${waited}s"
}

ensure_reachable() {
    reachable && return 0
    bad "the defender isn't answering, this machine is probably still blocked"
    wait_for_unblock || exit 1
}

# Repeat a redis-cli command until the defender stops answering.
# Sets TRIES_BEFORE_BLOCK (0 = never blocked).
TRIES_BEFORE_BLOCK=0
hammer() {
    TRIES_BEFORE_BLOCK=0
    show "redis-cli -h $TARGET -p $REDIS_PORT $*"
    local i out rc
    for ((i = 1; i <= MAX_TRIES; i++)); do
        rc=0
        out=$(timeout 5 redis-cli -h "$TARGET" -p "$REDIS_PORT" "$@" 2>&1) || rc=$?
        if ((rc == 124)); then
            printf '    try %d: \033[1;31mno response (timed out)\033[0m\n' "$i"
            TRIES_BEFORE_BLOCK=$((i - 1))
            return 0
        fi
        if [[ "$out" == *"Could not connect"* || "$out" == *"refused"* ]]; then
            printf '    try %d: %s\n' "$i" "$out"
            die "the Redis decoy isn't accepting connections, is NOPE running on the defender?"
        fi
        printf '    try %d: %s\n' "$i" "$(head -n1 <<<"$out")"
        sleep 0.5
    done
    return 0
}

# ---------------------------------------------------------------- arguments
while (($#)); do
    case $1 in
    --auto) AUTO=1 ;;
    --skip-nmap) SKIP_NMAP=1 ;;
    --ssh-port)
        SSH_PORT=${2:?--ssh-port needs a value}
        shift
        ;;
    --redis-port)
        REDIS_PORT=${2:?--redis-port needs a value}
        shift
        ;;
    --wait)
        WAIT=${2:?--wait needs a value}
        shift
        ;;
    -h | --help) usage ;;
    -*)
        echo "unknown option: $1" >&2
        usage 1
        ;;
    *)
        [[ -z "$TARGET" ]] || usage 1
        TARGET=$1
        ;;
    esac
    shift
done
[[ -n "$TARGET" ]] || usage 1

# ---------------------------------------------------------------- preflight
for tool in redis-cli nc timeout; do
    have "$tool" || die "$tool is missing, run: bash install.sh attacker"
done
if ((!SKIP_NMAP)) && ! have nmap; then
    info "nmap not installed, skipping the scan stage"
    SKIP_NMAP=1
fi

ME=$(my_ip)
printf '\033[1mNOPE demo attack\033[0m  target: %s  (ssh decoy %s, redis decoy %s)\n' \
    "$TARGET" "$SSH_PORT" "$REDIS_PORT"
info "this machine: $ME  (must NOT be in the defender's whitelist)"
ensure_reachable
pause

# ---------------------------------------------------------------- 1. banner
head_ "Banner grab on the SSH decoy (expect: score goes up a little, action=log)"
show "nc $TARGET $SSH_PORT"
printf 'SSH-2.0-OpenSSH_9.6 nope-demo\r\n' | timeout 5 nc -w 3 "$TARGET" "$SSH_PORT" |
    sed 's/^/    < /'
info "on the defender:  sudo .venv/bin/nope status"
pause

# ---------------------------------------------------------------- 2. nmap
if ((!SKIP_NMAP)); then
    head_ "Service scan with nmap (recon: nmap sends a pile of probes)"
    show "nmap -sV -Pn -p $SSH_PORT,$REDIS_PORT $TARGET"
    nmap -sV -Pn -p "$SSH_PORT,$REDIS_PORT" "$TARGET" 2>&1 | sed 's/^/    /'
    if reachable; then
        good "still allowed in. check the score on the defender:  sudo .venv/bin/nope status"
    else
        bad "the scan alone got us blocked"
        wait_for_unblock || exit 1
    fi
    pause
fi

# ---------------------------------------------------------------- 3. brute force
head_ "Guessing the Redis password (each failed AUTH is an 'auth' event)"
ensure_reachable
hammer AUTH guess
AUTH_TRIES=$TRIES_BEFORE_BLOCK
if ((AUTH_TRIES == 0)) && reachable; then
    bad "never got blocked after $MAX_TRIES tries. check that:"
    info "- NOPE is running for real on the defender (not --dry-run)"
    info "- $ME is not in the whitelist"
    info "- block_threshold in config.yaml isn't set very high"
    exit 1
fi
pause

# ---------------------------------------------------------------- 4. verify
head_ "Checking the block from the attacker side"
if have ping; then
    show "ping -c 3 -W 1 $TARGET"
    ping -c 3 -W 1 "$TARGET" 2>&1 | tail -n 2 | sed 's/^/    /'
fi
show "nc -v -w 3 $TARGET $SSH_PORT"
if timeout 5 nc -z -w 3 "$TARGET" "$SSH_PORT" >/dev/null 2>&1; then
    bad "SSH decoy still answered, the block isn't working"
    exit 1
fi
good "no answer: every packet from $ME is being dropped, not just the decoy ports"
info "on the defender:  sudo .venv/bin/nope blocked   and   sudo nft list table inet nope"
pause

# ---------------------------------------------------------------- 5. unblock
head_ "Recovery: unblock this machine from the defender"
wait_for_unblock || exit 1
pause

# ---------------------------------------------------------------- 6. exploit
head_ "Exploit-style Redis commands (10 points each, vs 5 for a password guess)"
ensure_reachable
hammer CONFIG SET dir /tmp
EXPLOIT_TRIES=$TRIES_BEFORE_BLOCK

# ---------------------------------------------------------------- summary
printf '\n\033[1mSummary\033[0m\n'
info "password guesses before block:    $AUTH_TRIES"
if ((EXPLOIT_TRIES > 0)) || ! reachable; then
    info "exploit commands before block:    $EXPLOIT_TRIES"
else
    info "exploit commands before block:    not blocked after $MAX_TRIES"
fi
info "see the score for each event on the defender:  sudo .venv/bin/nope recent -n 20"
if ! reachable; then
    info "this machine ($ME) is blocked again. unblock it on the defender:"
    info "  sudo .venv/bin/nope unblock $ME"
fi
