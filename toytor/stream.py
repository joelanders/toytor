from toytor.torpylle import CellRelay, CELL_COMMANDS, CELL_RELAY_COMMANDS
from toytor.common import read_cell
from ipaddress import IPv4Address
import asyncio
import logging
import struct


logging.basicConfig(format='%(levelname)s %(asctime)s %(name)-23s %(message)s',
                    datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

async def handle_relay_begin(reader, writer, relay_begin_cell):
    # open tcp connection to embedded address
    # if it worked, save into streams and send relay_connected
    # else, send relay_end
    circ_id = relay_begin_cell.CircID
    stream_id = relay_begin_cell.StreamID
    str_ip_port = relay_begin_cell.Data[:-1].decode()
    str_ip, _, str_port = str_ip_port.rpartition(":")
    ip = IPv4Address(str_ip)  # handle exception
    port = int(str_port)
    # TODO: exception, timeout
    stream_reader, stream_writer = \
        await asyncio.open_connection(host=ip.exploded, port=port)
    writer.write(bytes(CellRelay(RelayCommand="RELAY_CONNECTED",
                                 CircID=circ_id,
                                 StreamID=stream_id,
                                 Data=ip.packed+b"\x00\x00\x00\xff")))
    await writer.drain()
    return {(circ_id, stream_id): (stream_reader, stream_writer)}

class SocksConnection:
    def __init__(self, tor_connection, reader, writer):
        self.tor_connection = tor_connection
        self.reader = reader
        self.writer = writer
        self.run_task = asyncio.ensure_future(self._run())
        self.cts_task = None
        self.stc_task = None
        self.stream_id = 1990 # TODO: hardcoded stream_id

    async def _run(self):
        logger.info('accepted')
        request = await self.reader.read(9)
        logger.info('socks request: %s' % request)
        if request[0] != 4: # TODO: 1-length slices of bytestrings are integers?...
            logger.info('not socks4')
            return
        if request[1] != 1:
            logger.info('not the stream connect command')
            return
        port = struct.unpack('>H', request[2:4])[0]
        addr = IPv4Address(request[4:8])
        dest_str = addr.exploded + ":" + str(port)
        exit_resp = await self.tor_connection.create_stream(self.stream_id, dest_str)
        if not exit_resp:
            logger.info('exit didn\'t say yes')
            return # TODO: proper teardown
        else:
            logger.info('exit said yes')
        self.writer.write(b'\x00\x5a\x00\x00\x00\x00\x00\x00') # TODO: hardcoding response
        self.cts_task = asyncio.ensure_future(self.cells_to_stream())
        self.stc_task = asyncio.ensure_future(self.stream_to_cells())

    async def stream_to_cells(self):
        while True:
            bs = await self.reader.read(498)
            logger.info('read from socks connection: %s' % bs)
            if not bs:
                break
            cell = CellRelay(
                    RelayCommand="RELAY_DATA",
                    CircID=self.tor_connection.circ_id,
                    StreamID=self.stream_id,
                    Data=bs)
            await self.tor_connection.cell_queuer.put(cell)

    async def cells_to_stream(self):
        while True:
            cell = await self.tor_connection.strm_queues[self.stream_id].get()
            # TODO: do i want to interpret RELAY_ENDs here?...
            # if not bs:
            #     break
            bs = cell.Data
            logger.info('read from tor stream: %s' % bs)
            self.writer.write(bs)

    async def stop(self):
        if self.writer:
            self.writer.close()

        for task in [self.run_task, self.cts_task, self.stc_task]:
            task.cancel()
            asyncio.wait(task)
            logger.info('canceled task in SocksConnection: %s' % task)

class SocksServer:
    def __init__(self, tor_connection, socks_port):
        self.tor_connection = tor_connection
        self.socks_port = socks_port
        self.socks_connections = []

    async def start(self):
        try:
            self._server = await \
                asyncio.start_server(self._accept, '127.0.0.1',
                        self.socks_port, backlog=1) # TODO: I forget why I wanted this backlog
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error('exception starting ClientStream server: %s', e)
        else:
            logger.info('SocksServer started on port %s', self.socks_port)

    def _accept(self, reader, writer):
        conn = SocksConnection(self.tor_connection, reader, writer)
        self.socks_connections.append(conn)

    async def stop(self):
        if self._server is not None:  # TODO: only close if not already closed
            self._server.close()
            await self._server.wait_closed()
            logger.info('ControlServer %s stopped' % self._server)

        self.writer.close() # TODO: think about this ordering

        for conn in self.tor_server_connections:
            await conn.stop()
            logger.info('stopped SocksConnection %s' % conn)


class ServerStream:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    async def start(self):
        # TODO: exception, timeout
        self.reader, self.writer = \
            await asyncio.open_connection(host=ip.exploded, port=port)

    def client_to_server(self, data):
        self.writer.write(data)

    def server_to_client(self, data):  # chunk into cells
        pass


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    cs = ClientStream(8989)
    loop.run_until_complete(cs.start())
    loop.run_forever()
