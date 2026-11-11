'''
Decoy SSH server
- Sends an OpenSSH banner to client that looks like a slightly outdated ssh server
- Records what the client sends back, but no real SSH handshake
'''

import asyncio

from ..events import Event
from .base import IDLE_TIMEOUT, MAX_READ, clean, close, peer_ip

FAKE_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"

async def start(host, port, emit):
    async def handle(reader, writer):
        ip = peer_ip(writer)
        emit(Event(ip, port, "ssh", "connect"))
        try:
            writer.write(FAKE_BANNER)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(MAX_READ), IDLE_TIMEOUT)
            if data:
                emit(Event(ip, port, "ssh", "probe", clean(data)))
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            await close(writer)

    return await asyncio.start_server(handle, host, port)