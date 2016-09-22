import asyncio
import logging
from toytor.client import TorClient
from toytor.server import TorServer
from toytor.consensus import cached_consensus, server_descriptor
import random


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class ControlServerConnection:
    def __init__(self, server, reader, writer):
        self.server = server
        self.reader = reader
        self.writer = writer
        self.tor_servers = []
        self.tor_clients = {}
        self.run_task = asyncio.ensure_future(self._run())

    async def _run(self):
        self.writer.write(b'howdy\n')
        await self.writer.drain()

        while True:
            line = await self.reader.readline()
            if line == b'':
                asyncio.ensure_future(self.stop())
                break
            command = line.split()[0]
            if command == b'client':
                circ_id = int(line.split()[1])
                hex_fprint = line.split()[2].decode()
                router_status = self.consensus.routers[hex_fprint]
                addr = router_status.address
                port = router_status.or_port
                server_desc = await server_descriptor(router_status.digest)
                b_public = server_desc.ntor_onion_key
                self.add_client(circ_id, addr, port, hex_fprint, b_public)
            elif command == b'extend':
                circ_id = int(line.split()[1])
                hex_fprint = line.split()[2].decode()
                router_status = self.consensus.routers[hex_fprint]
                server_desc = await server_descriptor(router_status.digest)
                b_public = server_desc.ntor_onion_key
                ip = router_status.address
                port = router_status.or_port
                asyncio.ensure_future(
                    self.tor_clients[circ_id].extend_circuit(
                        hex_fprint, b_public, ip, port)
                )
            elif command == b'consensus':
                self.consensus = await cached_consensus()
                for relay in random.sample(
                        list(self.consensus.routers.values()), 5):
                    logger.info("%s %s %s" %
                                (relay.fingerprint, relay.address,
                                 relay.or_port))
            elif command == b'server':
                port = int(line.split()[1])
                await self.add_server(port)
            elif command == b'list':
                logger.info(self.tor_servers, self.tor_clients)
            elif command == b'quit':
                asyncio.ensure_future(self.server.stop())
                break

    # TODO: this awaits some things sequentially which can be done in parallel
    # (but we should wait at the end until everything finishes)
    async def stop(self):
        self.writer.close()

        if self.run_task:
            self.run_task.cancel()
            asyncio.wait(self.run_task)
            logger.info('canceled run_task in ControlServerConnection: %s' %
                        self.run_task)

        for client in self.tor_clients.values():
            await client.stop()

        for server in self.tor_servers:
            await server.stop()

    def add_client(self, circ_id, ip, port, hex_fprint, b_public):
        client = TorClient(circ_id, ip, port, hex_fprint, b_public)
        self.tor_clients[circ_id] = client

    async def add_server(self, port):
        server = TorServer(port)
        self.tor_servers.append(server)
        await server.start()


class ControlServer:
    def __init__(self, port):
        self.port = port
        self.control_server_connections = []

    def _accept(self, reader, writer):
        conn = ControlServerConnection(self, reader, writer)
        self.control_server_connections.append(conn)

    async def start(self):
        try:
            self._server = await \
                asyncio.start_server(self._accept, '127.0.0.1', self.port)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error('exception starting ControlServer: %s', e)
        else:
            logger.info('ControlServer started on port %s', self.port)

    async def stop(self):
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            logger.info('ControlServer %s stopped' % self._server)

        for conn in self.control_server_connections:
            await conn.stop()
            logger.info('stopped ControlServer %s' % conn)

        asyncio.get_event_loop().stop()
