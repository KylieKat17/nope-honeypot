'''Command line interface: nope run | status | blocked | recent | unblock'''

import argparse
import ipaddress
import logging
import os
import sys
import time
from datetime import datetime

from . import config as cfgmod
from .nft import Nft, NftError
from .scorer import decay
from .store import Store


# Human-readable string for a number of seconds
def ago(seconds):
    seconds = int(max(seconds, 0))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h"


def fmt_time(ts):
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


# Show a table with rich if it's installed, if not then plain text
def show(title, columns, rows):
    try:
        from rich.console import Console
        from rich.markup import escape
        from rich.table import Table
    except ImportError:
        print(title)
        print("\t".join(columns))
        for row in rows:
            print("\t".join(str(c) for c in row))
        return
    table = Table(title=title)
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*[escape(str(c)) for c in row])
    Console().print(table)


def cmd_run(args, cfg):
    from . import daemon

    if not args.dry_run and hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("nope run needs root to edit nftables (use sudo, or --dry-run)")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        datefmt="%H:%M:%S")
    store = Store(cfg["db_path"])
    try:
        import asyncio
        asyncio.run(daemon.run(cfg, store, Nft(args.dry_run)))
    except KeyboardInterrupt:
        pass
    except (OSError, NftError, RuntimeError) as exc:
        sys.exit(f"error: {exc}")
    return 0


def cmd_status(args, cfg):
    store = Store(cfg["db_path"])
    now = time.time()
    rows = []
    for row in store.list_scores():
        score = decay(row["score"], now - row["updated"], cfg["half_life"])
        blocked = store.is_blocked(row["ip"], now)
        if score < 0.1 and not blocked:
            continue
        if blocked:
            state = "BLOCKED"
        elif score >= cfg["alert_threshold"]:
            state = "alert"
        else:
            state = "watching"
        rows.append((score, row["ip"], state, ago(now - row["updated"])))
    rows.sort(reverse=True)
    show("Threat scores", ["IP", "Score", "State", "Last seen"],
         [(ip, f"{score:.1f}", state, f"{seen} ago") for score, ip, state, seen in rows[:20]])
    return 0


def cmd_blocked(args, cfg):
    store = Store(cfg["db_path"])
    now = time.time()
    rows = [(b["ip"], f"{ago(now - b['blocked_at'])} ago",
             f"in {ago(b['expires_at'] - now)}", b["reason"])
            for b in store.active_blocks(now)]
    show("Blocked IPs", ["IP", "Blocked", "Expires", "Reason"], rows)
    return 0


def cmd_recent(args, cfg):
    store = Store(cfg["db_path"])
    rows = [(fmt_time(e["ts"]), e["ip"], e["service"], e["kind"],
             f"{e['score']:.1f}", e["action"], e["payload"][:30])
            for e in store.recent_events(args.n)]
    show("Recent activity", ["Time", "IP", "Service", "Kind", "Score", "Action", "Payload"], rows)
    return 0


def cmd_unblock(args, cfg):
    try:
        ip = str(ipaddress.ip_address(args.ip))
    except ValueError:
        sys.exit(f"not a valid IP address: {args.ip}")
    store = Store(cfg["db_path"])
    Nft(args.dry_run).remove(ip)
    store.remove_block(ip)
    store.delete_score(ip)  # reset the score too, or the next packet would re-block instantly
    print(f"unblocked {ip} and reset its score")
    return 0


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", help="path to config.yaml")
    common.add_argument("--dry-run", action="store_true",
                        help="don't touch nftables, just log what would happen")

    parser = argparse.ArgumentParser(
        prog="nope", description="NOPE Observes Potential Enemies: honeypot-triggered response.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", parents=[common], help="start the decoys and the response daemon")
    sub.add_parser("status", parents=[common], help="show current threat scores")
    sub.add_parser("blocked", parents=[common], help="show currently blocked IPs")
    recent = sub.add_parser("recent", parents=[common], help="show recent events")
    recent.add_argument("-n", type=int, default=15, help="how many events (default 15)")
    unblock = sub.add_parser("unblock", parents=[common], help="remove a block and reset the score")
    unblock.add_argument("ip")
    return parser


COMMANDS = {"run": cmd_run, "status": cmd_status, "blocked": cmd_blocked,
            "recent": cmd_recent, "unblock": cmd_unblock}


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        cfg = cfgmod.load(args.config)
    except FileNotFoundError as exc:
        sys.exit(str(exc))
    return COMMANDS[args.cmd](args, cfg)
