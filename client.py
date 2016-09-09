from handshake import ProtocolViolation, IncompatibleVersions
from handshake import full_client_handshake
from hashtransport import HashReader, HashWriter
from common import read_cell
import ssl
import asyncio
import torpylle
import common
import create
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

    async def create_circuit(self, node_id, b_public):
        keys = await create.create_circuit(self._reader, self._writer,
                                           self.circ_id, node_id, b_public)
        logger.info("create_circuit exiting fine")
        logger.info(keys)
        self.circuits[self.circ_id] = [create.CircuitHop(keys)]

    async def extend_circuit(self, node_id, b_public, ip, port):
        node_id = bytes(bytearray.fromhex(node_id))
        b_public = create.PublicKey(base64.b64decode(b_public))
        keys = await create.extend_circuit(self._reader, self._writer,
                                           self.circ_id, node_id, b_public,
                                           ip, port)
        logger.info("extend_circuit exiting fine")
        logger.info(keys)
        self.circuits[self.circ_id].append(create.CircuitHop(keys))

    async def _run(self):
        await self._connect()
        logger.info('client connected')
        await self._handshake()
        logger.info('client handshaked')
        await self.create_circuit(self.node_id, self.b_public)
        logger.info('client circuit created')
        while True:
            cell = await read_cell(self._reader, self._writer)
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
