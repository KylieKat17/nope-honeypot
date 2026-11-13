'''
The actual daemon that runs the decoys, scores events, and responds 
'''

import asyncio
import logging

from .decoys import DECOYS
from .events import Event
from .responder import Responder
from .scorer import Scorer

log = logging.getLogger("nope.daemon")


class Daemon:
    def __init__(self, cfg, store, nft):
        self.store = store
        self.scorer = Scorer(store, cfg["weights"], cfg["half_life"])
        self.responder = Responder(store, nft, cfg)

    def handle(self, event: Event):
        """Called by every decoy for every event"""
        try:
            if self.responder.whitelisted(event.ip):
                log.debug("ignoring whitelisted %s", event.ip)
                return
            score = self.scorer.add(event)
            action = self.responder.respond(event, score)
            self.store.add_event(event, score, action)
            log.info("%s %s/%s score=%.1f action=%s",
                     event.ip, event.service, event.kind, score, action)
        except Exception:
            log.exception("failed to handle event from %s", event.ip)