import asyncio
from toytor.common import read_cell
from toytor.create import encrypt_relay_cell, decrypt_relay_cell
import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class CellQueuer:
    def __init__(self, reader, writer, circ_queues, strm_queues, circuits, loop=None):
        self.reader = reader
        self.writer = writer
        self.circ_queues = circ_queues
        self.strm_queues = strm_queues
        self.circuits = circuits # TODO: better naming/organization
        self.out_queue = asyncio.Queue()
        self.incoming_run_task = asyncio.ensure_future(self._incoming_run(), loop=loop)
        self.outgoing_run_task = asyncio.ensure_future(self._outgoing_run(), loop=loop)

    async def put(self, cell):
        await self.out_queue.put(cell)

    async def _outgoing_run(self):
        while True:
            logger.info('blocking on out_queue.get()')
            cell = await self.out_queue.get()
            # TODO: some of the CellRelayXXXs aren't subclasses of CellRelay...
            if type(cell).__name__.startswith('CellRelay'):
                logger.info('encrypting outgoing RelayCell')
                logger.info('%s' % repr(cell))
                logger.info('%s' % bytes(cell))
                if cell.CircID not in self.circuits:
                    logger.info('bad circuit')
                    continue
                hops = self.circuits[cell.CircID]['hops']
                role = self.circuits[cell.CircID]['role']
                # TODO: this is janky
                if role == 'client':
                    cell = encrypt_relay_cell(hops, cell, 'fw')
                elif role == 'server':
                    cell = encrypt_relay_cell(hops, cell, 'bw')
                else:
                    raise Exception('bad role')
            else:
                logger.info('not encrypting outgoing cell %s' % repr(cell))
            self.writer.write(bytes(cell))
            logger.info('wrote outgoing cell')
            logger.info('%s' % repr(cell))

    async def _incoming_run(self):
        while True:
            cell = None
            try:
                logger.info('blocking on read_cell')
                cell = await read_cell(self.reader, self.writer)
            except asyncio.CancelledError:
                raise
            except Exception as exc: # TODO: figure out which this actually is
                logger.info('bad cell %s' % exc)
                logger.debug('bad cell %s' % cell)
            else:
                if cell.CircID not in self.circ_queues:
                    logger.info('got cell with nonexistent circid %s' %
                                cell.CircID)
                    # TODO: see what spec says to do here
                    continue
                logger.info('got cell with good circid %s' % cell.CircID)
                logger.info('%s' % repr(cell))
                if type(cell).__name__.startswith('CellRelay'):
                    logger.info('decrypting incoming RelayCell')
                    hops = self.circuits[cell.CircID]['hops']
                    role = self.circuits[cell.CircID]['role']
                    # TODO: this is janky
                    if role == 'client':
                        cell = decrypt_relay_cell(hops, cell, 'bw')
                    elif role == 'server':
                        cell = decrypt_relay_cell(hops, cell, 'fw')
                    else:
                        raise Exception('bad role')
                if hasattr(cell, 'StreamID') and cell.StreamID in self.strm_queues:
                    logger.info('sticking it in a stream queue')
                    await self.strm_queues[cell.StreamID].put(cell)
                else:
                    logger.info('putting plaintext relaycell on queue')
                    await self.circ_queues[cell.CircID].put(cell)

    # TODO: easy deduping
    async def stop(self):
        if self.incoming_run_task:
            self.incoming_run_task.cancel()
            asyncio.wait(self.incoming_run_task)
            logger.info('canceled incoming_run_task in CellQueuer: %s' %
                        self.incoming_run_task)

        if self.outgoing_run_task:
            self.outgoing_run_task.cancel()
            asyncio.wait(self.outgoing_run_task)
            logger.info('canceled outgoing_run_task in CellQueuer: %s' %
                        self.outgoing_run_task)
