# tests/test_scorer.py

import pytest

from nope.events import Event
from nope.scorer import Scorer, decay_score
from nope.store import Store

EVENT_WEIGHTS = {"connect": 1, "probe": 2, "auth": 5, "exploit": 10}


# Build a scorer with a fresh database and a fixed half-life
def make_scorer():
    store = Store(":memory:")  # Keep saved scores separate for each test
    return Scorer(store, EVENT_WEIGHTS, half_life_seconds=100)


# Build an SSH event with a fixed timestamp unless the test supplies one
def make_event(event_kind, timestamp=0, client_ip="10.0.0.5"):
    return Event(client_ip, 2222, "ssh", event_kind, timestamp=timestamp)


# ================================
#   Per-IP scores
# ================================

# Check that event weights add together for the same client
def test_event_weights_accumulate():
    scorer = make_scorer()

    # Both events use the same timestamp so the first point has no time to decay
    assert scorer.update_score(make_event("connect")) == 1
    assert scorer.update_score(make_event("auth")) == 6  # Connect adds 1 and auth adds 5


# Check the fallback weight when the event kind has no configured entry
def test_unknown_event_kind_counts_as_one():
    unconfigured_event = make_event("unknown")
    assert make_scorer().update_score(unconfigured_event) == 1


# Check that an event from one client has no effect on another client's score
def test_scores_are_per_ip():
    scorer = make_scorer()
    scorer.update_score(make_event("exploit", client_ip="10.0.0.5"))
    assert scorer.update_score(make_event("connect", client_ip="10.0.0.6")) == 1  # Starts at zero


# ================================
#   Score decay
# ================================

# Check the remaining score after one and two full half-lives
def test_score_halves_each_half_life():
    starting_score = 8
    half_life_seconds = 100

    assert decay_score(starting_score, 100, half_life_seconds) == pytest.approx(4)  # Half remains
    assert decay_score(starting_score, 200, half_life_seconds) == pytest.approx(2)  # Quarter remains


# Check that the previous score decays before the next event adds its weight
def test_decay_applied_between_events():
    scorer = make_scorer()
    scorer.update_score(make_event("exploit", timestamp=0))

    # After one half-life the exploit is worth 5. Connecting adds 1
    assert scorer.update_score(make_event("connect", timestamp=100)) == pytest.approx(6)
