'''Some helper functions that the decoys can share'''

IDLE_TIMEOUT = 10        # seconds to wait for client to respond
MAX_READ = 4096          # never read more than this at once
MAX_PAYLOAD_CHARS = 256  # how much of a payload we keep in the event log


# Get the ip of the client
def peer_ip(writer):
    peer = writer.get_extra_info("peername")
    return peer[0] if peer else "unknown"


# Printable, truncated version of what a client sent
def clean(data: bytes):
    text = data[:MAX_PAYLOAD_CHARS].decode("utf-8", "replace")
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in text)


# Close the connection to the client
async def close(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass