# nope/scorer.py

from .events import Event


# ================================
#   Score decay
# ================================

def decay_score(score, elapsed_seconds, half_life_seconds):
    # A nonpositive half-life or elapsed time leaves the score unchanged
    if half_life_seconds <= 0 or elapsed_seconds <= 0:
        return score

    # Halve the score for each elapsed half-life, including fractional intervals
    return score * 0.5 ** (elapsed_seconds / half_life_seconds)


# ================================
#   Per-IP scores
# ================================

class Scorer:
    def __init__(self, store, event_weights, half_life_seconds):
        self.store = store
        self.event_weights = event_weights
        self.half_life_seconds = half_life_seconds

    def score_at(self, client_ip, timestamp):
        # A client with no stored score starts at zero
        score_record = self.store.get_score(client_ip)
        if score_record is None:
            return 0.0

        # Calculate decay from the last stored update without writing a new score
        elapsed_seconds = timestamp - score_record["updated_at"]
        return decay_score(score_record["score"], elapsed_seconds, self.half_life_seconds)

    def update_score(self, event: Event):
        # Event kinds without a configured weight count as one point
        event_weight = self.event_weights.get(event.event_kind, 1)

        # Decay the previous score to the event time before adding its weight
        updated_score = self.score_at(event.client_ip, event.timestamp) + event_weight

        # Save the event time as the starting point for the next decay calculation
        self.store.set_score(event.client_ip, updated_score, event.timestamp)
        return updated_score
