# nope/nft.py

import ipaddress
import logging
import shutil
import subprocess

log = logging.getLogger("nope.nft")


# ================================
#   Rules for the NOPE table
# ================================

# Reset the table on setup. Each block expires through the set timeout
SETUP_SCRIPT = """\
add table inet nope
delete table inet nope
table inet nope {
    set blocklist4 {
        type ipv4_addr
        flags timeout
    }
    set blocklist6 {
        type ipv6_addr
        flags timeout
    }
    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr @blocklist4 drop
        ip6 saddr @blocklist6 drop
    }
}
"""

TEARDOWN_SCRIPT = "add table inet nope\ndelete table inet nope\n"


class NftError(RuntimeError):
    pass


def block_target(ip):
    """Return the blocklist and normalized IP address"""
    address = ipaddress.ip_address(ip)
    return ("blocklist4" if address.version == 4 else "blocklist6"), str(address)


class Nft:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.history = []

    def run_script(self, script):
        # Save the generated command so dry-run tests can inspect it
        self.history.append(script)

        if self.dry_run:
            log.info("[dry-run] nft -f -\n%s", script.rstrip())
            return

        if shutil.which("nft") is None:
            raise NftError("nft not found, install nftables or use --dry-run")
        result = subprocess.run(
            ["nft", "-f", "-"], input=script, text=True, capture_output=True
        )
        if result.returncode != 0:
            raise NftError(result.stderr.strip() or "nft failed")

    def setup(self):
        self.run_script(SETUP_SCRIPT)

    def teardown(self):
        self.run_script(TEARDOWN_SCRIPT)

    def add(self, ip, seconds):
        set_name, address = block_target(ip)
        self.run_script(f"add element inet nope {set_name} {{ {address} timeout {int(seconds)}s }}\n")

    def remove(self, ip):
        set_name, address = block_target(ip)
        try:
            self.run_script(f"delete element inet nope {set_name} {{ {address} }}\n")
        except NftError as exc:
            # The timeout may have already removed this address
            log.warning("could not remove %s from nftables: %s", address, exc)
