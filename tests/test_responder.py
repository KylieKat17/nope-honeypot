# tests/test_responder.py

import copy

import pytest

from nope.config import DEFAULTS
from nope.events import Event
from nope.nft import Nft
from nope.responder import Responder
from nope.store import Store


# Build an isolated responder with optional settings for a single test
def make_responder(**config_overrides):
    config = copy.deepcopy(DEFAULTS)
    config.update(config_overrides)
    store = Store(":memory:")  # Keep scores and blocks separate for each test
    firewall = Nft(dry_run=True)  # Capture nftables commands without running them
    return Responder(store, firewall, config)


# Build an SSH auth event with a fixed client address and time by default
def make_event(client_ip="10.0.0.5", timestamp=1000.0):
    return Event(client_ip, 2222, "ssh", "auth", timestamp=timestamp)


# ================================
#   Score thresholds and blocks
# ================================

# Check that low scores produce a log action without a firewall command
def test_below_alert_is_just_logged():
    responder = make_responder()
    assert responder.apply_response(make_event(), 2) == "log"  # Default alert threshold is 5
    assert responder.nft.history == []


# Check that repeated alert-level events for one IP only trigger one alert
def test_alert_fires_once_then_watches():
    responder = make_responder()
    assert responder.apply_response(make_event(), 6) == "alert"
    assert responder.apply_response(make_event(), 8) == "watch"  # Same IP is already tracked


# Check that a block-level score generates a timed rule and stores the block
def test_block_adds_firewall_element_and_stores_expiration():
    responder = make_responder()
    assert responder.apply_response(make_event(), 20) == "block"
    assert "blocklist4 { 10.0.0.5 timeout 600s }" in responder.nft.history[-1]

    # The block starts at 1000 seconds and lasts for 600 seconds
    assert responder.store.is_blocked("10.0.0.5", 1001.0)
    assert not responder.store.is_blocked("10.0.0.5", 1000.0 + 601)


# Check that another event during an active block leaves the existing rule in place
def test_already_blocked_is_not_blocked_twice():
    responder = make_responder()
    responder.apply_response(make_event(), 20)
    initial_command_count = len(responder.nft.history)

    # A higher score during the active block leaves the original timeout in place
    assert responder.apply_response(make_event(timestamp=1001.0), 25) == "none"
    assert len(responder.nft.history) == initial_command_count


# ================================
#   Whitelist lookup
# ================================

# Check that whitelist lookup handles both CIDR ranges and single addresses
def test_whitelist_matches_single_ips_and_ranges():
    responder = make_responder(
        whitelist=["192.168.56.0/24", "10.0.0.9"]
    )
    assert responder.is_whitelisted("192.168.56.1")  # Falls inside the CIDR range
    assert responder.is_whitelisted("10.0.0.9")  # Matches the single address
    assert not responder.is_whitelisted("10.0.0.10")  # Matches neither entry


# ================================
#   nftables commands in dry-run
# ================================

# Check that an IPv6 address goes into the IPv6 nftables set
def test_nft_uses_ipv6_set_for_v6():
    firewall = Nft(dry_run=True)
    firewall.add("2001:db8::1", 60)
    assert "blocklist6 { 2001:db8::1 timeout 60s }" in firewall.history[-1]


# Check that command text embedded in an address is rejected before script generation
def test_nft_rejects_invalid_ip_before_building_a_script():
    firewall = Nft(dry_run=True)
    invalid_ip = "1.2.3.4 } ; flush ruleset ; {"
    with pytest.raises(ValueError):
        firewall.add(invalid_ip, 60)
    assert firewall.history == []  # Validation failed before a command was recorded
