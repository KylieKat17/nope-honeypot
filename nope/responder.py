# nope/responder.py

import ipaddress
import logging

from .events import Event
from .nft import Nft, NftError
from .store import Store

log = logging.getLogger("nope.responder")


class Responder:
    def __init__(self, store: Store, nft: Nft, config):
        self.store = store
        self.nft = nft

        # Keep the alert threshold separate from the higher-priority block decision
        self.alert_threshold = config["alert_threshold"]
        self.block_threshold = config["block_threshold"]
        self.block_seconds = config["block_seconds"]

        # Parse single addresses and CIDR ranges into the same network format
        # strict=False masks host bits when an address is supplied with a network prefix
        self.whitelist_networks = [
            ipaddress.ip_network(entry, strict=False) for entry in config["whitelist"]
        ]
        self.alerted_ips = set()  # Tracks alerts in memory for this responder instance

    # ================================
    #   Whitelist lookup
    # ================================

    def is_whitelisted(self, client_ip):
        # Convert the client IP to an address so it can be checked against each network
        address = ipaddress.ip_address(client_ip)
        # A match in any one network is enough, including single-address entries
        return any(address in network for network in self.whitelist_networks)

    # ================================
    #   Score thresholds and actions
    # ================================

    def apply_response(self, event: Event, score: float):
        client_ip = event.client_ip

        # Check the block threshold first because a block takes priority over an alert
        if score >= self.block_threshold:
            # Check whether the stored block is still active at the event timestamp
            if self.store.is_blocked(client_ip, event.timestamp):
                return "none"  # Keep the existing block without restarting its timeout

            # Record a block in SQLite only after the nftables call succeeds
            try:
                self.nft.add(client_ip, self.block_seconds)
            except NftError as exc:
                log.error("failed to block %s: %s", client_ip, exc)
                return "block-failed"  # Leave SQLite and alert tracking as they were

            block_reason = f"score {score:.1f} ({event.service}/{event.event_kind})"
            # Store an absolute expiration time using the event time and block duration
            expires_at = event.timestamp + self.block_seconds
            self.store.add_block(client_ip, event.timestamp, expires_at, block_reason)
            self.alerted_ips.discard(client_ip)  # Allow a fresh alert after the block expires
            log.warning("BLOCK %s for %ss, %s", client_ip, self.block_seconds, block_reason)
            return "block"

        # Log one alert per IP until it gets blocked
        if score >= self.alert_threshold:
            if client_ip not in self.alerted_ips:
                # Remember the IP so later events above the alert threshold stay quiet
                self.alerted_ips.add(client_ip)
                log.warning(
                    "ALERT %s score %.1f (%s/%s)", client_ip, score, event.service, event.event_kind
                )
                return "alert"
            return "watch"  # The score still warrants attention and an alert already exists

        # Below both thresholds, return the action without issuing an alert or block
        return "log"
