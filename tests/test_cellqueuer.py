from toytor.cellqueuer import *
from toytor.create import CircuitHop
import toytor.torpylle as torpylle
import pytest
import asyncio
from toytor.dummytransport import dummy_transport
from toytor.common import read_cell


logging.basicConfig(
    format='%(levelname)s %(asctime)s %(name)-23s %(message)s',
    datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TestCellQueuer:
    @pytest.mark.asyncio
    async def test_start_stop(self, event_loop):
        s_reader, c_writer = await dummy_transport()
        c_reader, s_writer = await dummy_transport()
        queuer = CellQueuer(s_reader, s_writer, {}, {}, loop=event_loop)
        await queuer.stop()

    @pytest.mark.asyncio
    async def test_queue_get_one(self, event_loop):
        queues = {0: asyncio.Queue()}
        s_reader, c_writer = await dummy_transport()
        c_reader, s_writer = await dummy_transport()
        test_cell = torpylle.Cell(Command="VERSIONS", Versions=[2, 3, 4])

        queuer = CellQueuer(s_reader, s_writer, queues, {}, loop=event_loop)
        c_writer.write(bytes(test_cell))
        recvd_cell = await queues[0].get()

        assert bytes(recvd_cell) == bytes(test_cell)
        await queuer.stop()

    @pytest.mark.asyncio
    async def test_queue_put_one(self, event_loop):
        queues = {0: asyncio.Queue()}
        s_reader, c_writer = await dummy_transport()
        c_reader, s_writer = await dummy_transport()
        test_cell = torpylle.Cell(Command="VERSIONS", Versions=[2, 3, 4])

        queuer = CellQueuer(s_reader, s_writer, queues, {}, loop=event_loop)
        await queuer.put(test_cell)
        recvd_cell = await read_cell(c_reader, None)

        assert bytes(recvd_cell) == bytes(test_cell)
        await queuer.stop()

    @pytest.mark.asyncio
    async def test_two_queues(self, event_loop):
        c_queues = {0: asyncio.Queue()}
        s_queues = {0: asyncio.Queue()}

        s_reader, c_writer = await dummy_transport()
        c_reader, s_writer = await dummy_transport()
        test_cell = torpylle.Cell(Command="VERSIONS", Versions=[2, 3, 4])

        c_queuer = CellQueuer(c_reader, c_writer, c_queues, {}, loop=event_loop)
        s_queuer = CellQueuer(s_reader, s_writer, s_queues, {}, loop=event_loop)

        await c_queuer.put(test_cell)
        recvd_cell = await s_queues[0].get()

        assert bytes(recvd_cell) == bytes(test_cell)
        await c_queuer.stop()
        await s_queuer.stop()

    @pytest.mark.asyncio
    async def test_two_encrypted_queues(self, event_loop):
        c_queues = {69: asyncio.Queue()}
        s_queues = {69: asyncio.Queue()}

        s_reader, c_writer = await dummy_transport()
        c_reader, s_writer = await dummy_transport()
        test_cell = torpylle.CellRelayExtend2(
                      CircID=69,
                      RelayCommand='RELAY_EXTEND2',
                      StreamID=79,
                      LSpec0=b'\x7f\x00\x00\x01\x23\x8b',  # 127.0.0.1:9099
                      LSpec1=b'iToldYouAboutStairs',
                      HData=b'n'*20 + b'k'*32 + b'c'*32)

        shared_keys = b'a'*20 + b'b'*20 + b'c'*16 + b'd'*16
        c_circuits = {69: {'role': 'client', 'hops': [CircuitHop(shared_keys)]}}
        s_circuits = {69: {'role': 'server', 'hops': [CircuitHop(shared_keys)]}}

        c_queuer = CellQueuer(c_reader, c_writer, c_queues, c_circuits, loop=event_loop)
        s_queuer = CellQueuer(s_reader, s_writer, s_queues, s_circuits, loop=event_loop)

        await c_queuer.put(test_cell)
        recvd_cell = await s_queues[69].get()

        assert bytes(recvd_cell) == bytes(test_cell)
        await c_queuer.stop()
        await s_queuer.stop()
