from toytor.handshake import ProtocolViolation, IncompatibleVersions
from toytor.handshake import full_client_handshake
from toytor.hashtransport import HashReader, HashWriter
from toytor.common import read_cell
from toytor.cellqueuer import CellQueuer
import ssl
import asyncio
import toytor.torpylle as torpylle
import toytor.create as create
import traceback
import base64
import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TorClient:
    def __init__(self, circ_id, ip, port, node_id, b_public):
        self.circ_id = circ_id
        self.ip = ip
        self.port = port
        self.node_id = bytes(bytearray.fromhex(node_id))
        self.b_public = create.PublicKey(base64.b64decode(b_public))
        self._reader = None
        self._writer = None
        self._version = None
        self.circuits = {}
        self.circ_queues = {}
        self.streams = {}
        self.strm_queues = {}
        self.cell_queuer = None
        self.run_task = asyncio.ensure_future(self._run())

    async def _handshake(self):
        # TODO: figure out where to use these
        reader = HashReader(self._reader, 'client')
        writer = HashWriter(self._writer, 'client')
        try:
            my_vers = [3]
            my_ips = ['127.0.0.1']
            self._version = await \
                full_client_handshake(reader, writer, my_vers, my_ips, self.ip)
        except asyncio.TimeoutError as exc:
            logger.info("client timed out")
            raise
        except Exception as exc:
            logger.info('exception during client handshake: %s' % exc)
            traceback.print_tb(exc)
            raise
            # raise something to stop TorClient?
        else:
            logger.info("client completed handshake")

    # TODO: lock so we can only have one pending create per circuit
    async def create_circuit(self, node_id, b_public):
        if self.circ_id in self.circ_queues:
            logger.info('create_circuit getting called twice?')
            raise Exception('failed to create_circuit')
        reader_q = asyncio.Queue()
        self.circ_queues[self.circ_id] = reader_q
        logger.info('circ_queues: %s' % self.circ_queues)
        keys = await create.create_circuit(reader_q, self._writer,
                                           self.circ_id, node_id, b_public)
        logger.info("create_circuit exiting fine")
        logger.info(keys)
        # TODO: this role: client stuff is janky
        self.circuits[self.circ_id] = {'role': 'client', 'hops': [create.CircuitHop(keys)]}

    # TODO: lock so we can only have one pending extend per circuit
    async def extend_circuit(self, node_id, b_public, ip, port):
        node_id = bytes(bytearray.fromhex(node_id))
        b_public = create.PublicKey(base64.b64decode(b_public))
        logger.info('circ_queues: %s' % self.circ_queues)
        keys = await create.extend_circuit(self.circ_queues[self.circ_id],
                                           self.cell_queuer, self.circ_id,
                                           node_id, b_public, ip, port)
        logger.info("extend_circuit exiting fine")
        logger.info(keys)
        self.circuits[self.circ_id]['hops'].append(create.CircuitHop(keys))

    async def resolve_host(self, host_str):
        if len(host_str) < 1:
            return
        if host_str[-1] != "\x00":
            host_str += "\x00"
        await self.cell_queuer.put(torpylle.CellRelay(
                CircID=self.circ_id,
                RelayCommand="RELAY_RESOLVE",
                StreamID=1990, # TODO: should pick properly
                Data=host_str))
        logger.info('sent resolve cell')

    async def create_stream(self, stream_id, ip_port):
        if ip_port[-1] != b'\x00': # TODO: more checking
            ip_port += '\x00'
        self.strm_queues[stream_id] = asyncio.Queue()
        await self.cell_queuer.put(torpylle.CellRelay(
                                   RelayCommand="RELAY_BEGIN",
                                   CircID=self.circ_id,
                                   StreamID=stream_id,
                                   Data=ip_port))
        logger.info('sent RELAY_BEGIN, waiting for RELAY_CONNECTED')
        cell = await self.strm_queues[stream_id].get()
        if not (cell.Command == torpylle.CELL_COMMANDS['RELAY'] and
                cell.RelayCommand == torpylle.CELL_RELAY_COMMANDS['RELAY_CONNECTED']):
            logger.info('instead got %s' % cell)
            return False
        connected_ip = cell.Data[:4]
        ttl = cell.Data[4:8]
        self.streams[stream_id] = {'ip': cell.Data[:4], 'ttl': cell.Data[4:8]}
        logger.info('got RELAY_CONNECTED, create_stream returning True')
        return True

    async def _run(self):
        await self._connect()
        logger.info('client connected')
        await self._handshake()
        logger.info('client handshaked')
        self.cell_queuer = CellQueuer(self._reader, self._writer, self.circ_queues, self.strm_queues, self.circuits)
        self.circ_queues[0] = asyncio.Queue()
        logger.info('client started CellQueuer')
        await self.create_circuit(self.node_id, self.b_public)
        logger.info('client circuit created')
        while True:
            cell = await self.circ_queues[0].get()
        self._writer.close()
        logger.info('Client done')

    async def _connect(self):
        logger.info("hi %s %s" % (self.circ_id, repr(self.ip)))

        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        context.verify_mode = ssl.CERT_NONE

        self._reader, self._writer = await asyncio.open_connection(
            self.ip, self.port, ssl=context)

    # TODO: make this object act more like a Task (ie. done(), cancel(), etc.)
    async def stop(self):
        if self._writer is not None:
            self._writer.close()

        if self.run_task:
            self.run_task.cancel()
            asyncio.wait(self.run_task)
            logger.info('canceled run_task in TorClient: %s' % self.run_task)
