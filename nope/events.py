"""
The one interface between the decoys and everything else

Decoys build an Event and hand it to the daemon. The scorer, responder and
store will only ever see this shape
"""

# TODO: make those ^

import time
from dataclasses import dataclass, field

# Ordered roughly from least to most serious
KINDS = ("connect", "probe", "auth", "exploit")


@dataclass
class Event:
    client_ip: str
    listen_port: int
    service: str         # "ssh", "redis", etc
    event_kind: str      # one of KINDS
    payload: str = ""    # printable, truncated copy of what the client sent
    timestamp: float = field(default_factory=time.time)
