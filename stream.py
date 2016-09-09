from torpylle import CellRelay, CELL_COMMANDS, CELL_RELAY_COMMANDS
from common import read_cell
from ipaddress import IPv4Address
import asyncio
import logging


logging.basicConfig(format='%(levelname)s %(asctime)s %(name)-23s %(message)s',
                    datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


async def create_stream(reader, writer, circ_id, stream_id, ip_port):
    writer.write(bytes(CellRelay(RelayCommand="RELAY_BEGIN",
                                 CircID=circ_id,
                                 StreamID=stream_id,
                                 Data=ip_port+"\x00")))
    await writer.drain()
    cell = await asyncio.wait_for(read_cell(reader, writer), timeout=4)
    if not (cell.Command == CELL_COMMANDS['RELAY'] and
            cell.RelayCommand == CELL_RELAY_COMMANDS['RELAY_CONNECTED']):
        return False
    connected_ip = cell.Data[:4]
    ttl = cell.Data[4:8]
    return IPv4Address(connected_ip).exploded, ttl


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


class ClientStream:
    def __init__(self, port):
        self.port = port

    async def start(self):
        try:
            self._server = await \
                asyncio.start_server(self._accept, '127.0.0.1',
                                     self.port, backlog=1)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error('exception starting ClientStream server: %s', e)
        else:
            logger.info('ClientStream started on port %s', self.port)

    async def _accept(self, reader, writer):
        # TODO: this feels wrong..? I want something like:
        # reader, writer = await accept(socket)
        # ie. only accept the first connection.
        self._server.close()
        await self._server.wait_closed()
        self.reader = reader
        self.writer = writer
        logger.info('accepted')
        while True:
            line = await reader.readline()
            writer.write(line)

    def client_to_server(self, data):  # chunk into cells
        pass

    def server_to_client(self, data):
        pass

    async def stop(self):
        if self._server is not None:  # TODO: only close if not already closed
            self._server.close()
            await self._server.wait_closed()
            logger.info('ControlServer %s stopped' % self._server)

        self.writer.close()


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
