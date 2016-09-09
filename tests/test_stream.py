import pytest
from ..stream import *
from ..dummytransport import dummy_transport
from ..common import read_cell
# RELAY_BEGIN and the response is RELAY_END or RELAY_CONNECTED


class TestAsyncRelayBegin:
    @pytest.mark.asyncio
    async def test_async_relay_begin(self):
        s_reader, c_writer = await dummy_transport()
        c_reader, s_writer = await dummy_transport()

        circ_id = 69
        stream_id = 58
        ip_port = "127.0.0.1:30180"

        def _accept(reader, writer):
            writer.write(b'hello\n')
            writer.close()

        dummy_server = await asyncio.start_server(_accept, '127.0.0.1', 30180)

        client_future = asyncio.ensure_future(
            create_stream(c_reader, c_writer, circ_id, stream_id, ip_port)
        )
        relay_begin_cell = await read_cell(s_reader, None)
        # relay_connected_cell = await read_cell(c_reader, None)

        server_stream = await \
            handle_relay_begin(s_reader, s_writer, relay_begin_cell)
        client_stream = await client_future

        print(server_stream)
        print(client_stream)
