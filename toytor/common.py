from toytor.torpylle import Cell
import asyncio
import random
import struct


async def read_cell(reader, writer):
    cell = None
    data = b''
    while len(data) < 5:
        data += await reader.read(5 - len(data))
    cmd = struct.unpack('B', data[2:3])[0]
    if cmd == 7 or cmd >= 128:
        cell_len = 5 + struct.unpack('>H', data[3:5])[0]
    else:
        cell_len = 512
    while len(data) < cell_len:
        data += await reader.read(cell_len - len(data))
        if data == b'':
            raise Exception('eof')
    return cell_from_bytes(data)


# async def sleepy_write(reader, writer, bstring):
#     await asyncio.sleep(random.randint(1,2))
#     writer.write(bstring)
#     await writer.drain()


def cell_from_bytes(buffie):
    return Cell(buffie)
