import asyncio
from socket import socketpair


class DummyWriter:
    def __init__(self, wsock):
        self.wsock = wsock

    def write(self, *args):
        return self.wsock.send(*args)

    async def drain(self, *args):
        pass


async def dummy_transport():
    rsock, wsock = socketpair()
    reader, _ = await asyncio.open_connection(sock=rsock)
    writer = DummyWriter(wsock)
    return reader, writer
