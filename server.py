from common import read_cell
from handshake import ProtocolViolation, IncompatibleVersions
from handshake import full_server_handshake
from hashtransport import HashReader, HashWriter
import ssl
from OpenSSL import crypto
import asyncio
import traceback
import hashlib
import base64
import create
import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TorServerConnection:
    def __init__(self, server, reader, writer, bkey, fingerprint):
        self._server = server
        self._reader = reader
        self._writer = writer
        self.bkey = bkey
        self.fingerprint = fingerprint
        self._version = None
        self.run_task = asyncio.ensure_future(self._run())

    async def _server_handshake(self):
        reader = HashReader(self._reader, 'server')
        writer = HashWriter(self._writer, 'server')
        try:
            my_vers = [3]
            my_addrs = ['127.0.0.1']  # TODO: these are just valid in testing
            their_ip = '127.0.0.1'
            self._version = await \
                full_server_handshake(reader, writer, my_vers, my_addrs,
                                      their_ip, self._server.link_cert,
                                      self._server.id_cert)
        except asyncio.TimeoutError as exc:
            logger.error("server timed out")
            raise
        except Exception as exc:
            logger.error("server failed to handshake %s" % exc)
            traceback.print_exc()
            raise
        else:
            logger.info("server completed handshake")

    async def _run(self):
        addr = self._writer.get_extra_info('peername')
        logger.info("Server connected from {}".format(addr))
        await self._server_handshake()
        create_cell = await \
            asyncio.wait_for(read_cell(self._reader, self._writer), timeout=1)
        seckey_b = self.bkey
        keys = create.handle_create(self._reader, self._writer,
                                    self.fingerprint, seckey_b, create_cell)
        logger.info("server handle_create finished")
        logger.info(keys)
        while True:
            cell = await read_cell(self._reader, self._writer)

        self._writer.close()
        logger.info('Server done')

    async def stop(self):
        if self._writer is not None:
            self._writer.close()

        if self.run_task:
            self.run_task.cancel()
            asyncio.wait(self.run_task)
            logger.info('canceled run_task in TorServerConnection: %s' %
                        self.run_task)


class TorServer:
    def __init__(self, port):
        self.port = port
        self._server = None
        # TODO: do this properly
        self.bkey = create.PrivateKey(
                secret=base64.b64decode(
                    b'99oC9ybcwi6nG6B3kWbRXQVsMWMzp5nsiaGkwvBOSXk='))
        with open('id_key.pem', 'r') as f:
            bites = f.read()
            # check this is right
            # (might have whitespace in the file, for example..)
            self.fingerprint = hashlib.sha1(bites.encode()).digest()
            self.hexfingerprint = hashlib.sha1(bites.encode()).hexdigest()
            logger.info("server fingerprint might be %s" % self.hexfingerprint)
            self.id_key = crypto.load_privatekey(
                crypto.FILETYPE_PEM, bites)
        with open('link_key.pem', 'r') as f:
            self.link_key = crypto.load_privatekey(
                crypto.FILETYPE_PEM, f.read())
        with open('id_cert.pem', 'r') as f:
            self.id_cert = crypto.load_certificate(
                crypto.FILETYPE_PEM, f.read())
        with open('link_cert.pem', 'r') as f:
            self.link_cert = crypto.load_certificate(
                crypto.FILETYPE_PEM, f.read())
        self.tor_server_connections = []

    def _accept(self, reader, writer):
        conn = TorServerConnection(
                self, reader, writer, self.bkey, self.fingerprint)
        self.tor_server_connections.append(conn)

    async def start(self):
        try:
            self._context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self._context.load_cert_chain('link_cert.pem', 'link_key.pem')
            self._server = await \
                asyncio.start_server(self._accept, '127.0.0.1',
                                     self.port, ssl=self._context)
            logger.info("server started" + str(self._server))
        except Exception as err:
            logger.error("server failed to start exc: %s" % err)
            traceback.print_exc()
            raise

    async def stop(self):
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

        for conn in self.tor_server_connections:
            await conn.stop()
            logger.info('stopped TorServer %s' % conn)
