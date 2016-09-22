from toytor.common import *
import pytest
import asyncio
from toytor.dummytransport import dummy_transport


INCOMPLETE_HEADER = b'\x01\x02\x03\x04'
INCOMPLETE_PAYLOAD = b'\x00\x00\x07\x00\x04\x01'
COMPLETE_VERSIONS = b'\x00\x00\x07\x00\x04\x00\x01\x00\x02'


class TestReadCell:
    @pytest.mark.asyncio
    async def test_small(self):
        reader, writer = await dummy_transport()
        writer.write(COMPLETE_VERSIONS)
        cell = await read_cell(reader, None)
        assert cell.Command == 7


# TODO: this stuff moved to read_cell
# class TestCellFromBytes:
#     def test_very_small(self):
#         assert cell_from_bytes(INCOMPLETE_HEADER) == \
#             (None, INCOMPLETE_HEADER)
#
#     def test_incomplete(self):
#         assert cell_from_bytes(INCOMPLETE_PAYLOAD) == \
#             (None, INCOMPLETE_PAYLOAD)
#
#     def test_small_complete(self):
#         cell, rem = cell_from_bytes(COMPLETE_VERSIONS)
#         assert cell.Command == 7
#         assert cell.Versions == [1, 2]
#         assert rem == b''
#
#     def test_complete_with_extra(self):
#         cell, rem = cell_from_bytes(COMPLETE_VERSIONS + b'\x69')
#         assert cell.Command == 7
#         assert cell.Versions == [1, 2]
#         assert rem == b'\x69'
