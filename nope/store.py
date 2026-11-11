# nope/store.py

import sqlite3
import time

from .events import Event


# ================================
#   SQLite schema
# ================================

# Keep the full event history separate from the latest score and block for each IP
# Create missing tables when opening a database and keep any existing rows
SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    timestamp   REAL NOT NULL,
    client_ip   TEXT NOT NULL,
    listen_port INTEGER NOT NULL,
    service     TEXT NOT NULL,
    event_kind  TEXT NOT NULL,
    payload     TEXT NOT NULL,
    score       REAL NOT NULL,
    action      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scores (
    client_ip  TEXT PRIMARY KEY,
    score      REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS blocks (
    client_ip  TEXT PRIMARY KEY,
    blocked_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    reason     TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path="nope.db"):
        # Wait up to 10 seconds if another SQLite connection holds a lock
        # Allow the connection to be used from a thread other than the one that opened it
        self.db = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self.db.row_factory = sqlite3.Row  # Read fields by column name, such as row["score"]

        # Write-ahead logging lets one connection read while another writes
        # In-memory databases have no database file or WAL file
        if path != ":memory:":
            self.db.execute("PRAGMA journal_mode=WAL")

        self.db.executescript(SCHEMA)
        self.db.commit()

    # ================================
    #   Event log
    # ================================

    def add_event(self, event: Event, score: float, action: str):
        # Store the event together with the supplied score and action
        # Bind values through placeholders so event payloads are stored as data
        self.db.execute(
            "INSERT INTO events "
            "(timestamp, client_ip, listen_port, service, event_kind, payload, score, action) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.timestamp,
                event.client_ip,
                event.listen_port,
                event.service,
                event.event_kind,
                event.payload,
                score,
                action,
            ),
        )
        self.db.commit()

    def recent_events(self, limit=15):
        # Sort by insertion order so the most recently logged events appear first
        return self.db.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    # ================================
    #   Per-IP scores
    # ================================

    def get_score(self, client_ip):
        # fetchone returns None if this client has no score yet
        return self.db.execute(
            "SELECT score, updated_at FROM scores WHERE client_ip = ?", (client_ip,)
        ).fetchone()

    def set_score(self, client_ip, score, updated_at):
        # Insert the first score for an IP or replace its score and timestamp together
        # Store updated_at alongside the score so both can be retrieved together
        self.db.execute(
            "INSERT INTO scores (client_ip, score, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(client_ip) DO UPDATE SET "
            "score = excluded.score, updated_at = excluded.updated_at",
            (client_ip, score, updated_at),
        )
        self.db.commit()

    def delete_score(self, client_ip):
        self.db.execute("DELETE FROM scores WHERE client_ip = ?", (client_ip,))
        self.db.commit()

    def list_scores(self, limit=50):
        # Show the most recently updated scores first
        return self.db.execute(
            "SELECT client_ip, score, updated_at FROM scores ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()

    # ================================
    #   Blocks and expiration
    # ================================

    def add_block(self, client_ip, blocked_at, expires_at, reason):
        # Keep one block record per IP, including its start time and expiration
        self.db.execute(
            "INSERT OR REPLACE INTO blocks (client_ip, blocked_at, expires_at, reason) "
            "VALUES (?, ?, ?, ?)",
            (client_ip, blocked_at, expires_at, reason),
        )
        self.db.commit()

    def remove_block(self, client_ip):
        self.db.execute("DELETE FROM blocks WHERE client_ip = ?", (client_ip,))
        self.db.commit()

    def clear_blocks(self):
        self.db.execute("DELETE FROM blocks")
        self.db.commit()

    def active_blocks(self, now=None):
        # An explicit timestamp lets callers query block status at a specific time
        # Expired rows can stay in SQLite because only future expirations count as active
        now = time.time() if now is None else now
        return self.db.execute(
            "SELECT * FROM blocks WHERE expires_at > ? ORDER BY blocked_at DESC", (now,)
        ).fetchall()

    def is_blocked(self, client_ip, now=None):
        now = time.time() if now is None else now
        # Only row existence matters here, so SELECT 1 avoids returning block details
        # The block stops counting as active at the exact expiration time
        row = self.db.execute(
            "SELECT 1 FROM blocks WHERE client_ip = ? AND expires_at > ?", (client_ip, now)
        ).fetchone()
        return row is not None
