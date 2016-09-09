from ..create import *
from ..dummytransport import dummy_transport
from ..common import cell_from_bytes
from ..common import read_cell
from .. import torpylle as torpylle
import pytest
import asyncio
import sys


class TestNtor:
    def test_ntor(self):
        node_id = b"iToldYouAboutStairs."
        server_key = PrivateKey()
        x, create = client_part1(node_id, server_key.get_public())
        skeys, created = server(server_key, node_id, create)
        ckeys = client_part2(x, created, node_id, server_key.get_public())
        assert len(skeys) == 72
        assert len(ckeys) == 72
        assert skeys == ckeys


class TestCreate2:
    def test_build_create2(self):
        node_id = b"iToldYouAboutStairs."
        server_key = PrivateKey()
        x, create_payload = client_part1(node_id, server_key.get_public())

        c = torpylle.Cell(Command="CREATE2",
                          Htype="ntor",
                          Hdata=create_payload).build()
        assert len(c) == 512

    def test_read_create2(self):
        bites = b'\x69\x69'   # CircId
        bites += b'\x0a'      # Cmd
        bites += b'\x00\x02'  # Htype = ntor
        bites += b'\x00\x54'  # Hlen = 84 decimal
        bites += b'n'*20      # NodeId
        bites += b'k'*32      # KeyId
        bites += b'c'*32      # ClientPK
        bites += b'p'*421     # Padding
        assert cell_from_bytes(bites).Command == 10
        assert cell_from_bytes(bites).Hdata == b'n'*20 + b'k'*32 + b'c'*32


class TestCreated2:
    def test_build_created2(self):
        node_id = b"iToldYouAboutStairs."
        server_key = PrivateKey()
        x, create_payload = client_part1(node_id, server_key.get_public())
        skeys, created_payload = server(server_key, node_id, create_payload)

        c = torpylle.Cell(Command="CREATED2",
                          Hdata=created_payload).build()
        assert len(c) == 512

    def test_read_created2(self):
        bites = b'\x69\x69'   # CircId
        bites += b'\x0b'      # Cmd
        bites += b'\x00\x40'  # Hlen = 64 decimal
        bites += b's'*32      # ServerPK
        bites += b'a'*32      # Auth
        bites += b'p'*423     # Padding
        assert cell_from_bytes(bites).Command == 11
        assert cell_from_bytes(bites).Hdata == b's'*32 + b'a'*32


class TestAsyncCreate:
    @pytest.mark.asyncio
    async def test_async_create(self):
        s_reader, c_writer = await dummy_transport()
        c_reader, s_writer = await dummy_transport()

        circid = 69
        node_id = b"iToldYouAboutStairs."
        server_key = PrivateKey()
        pubkey_B = server_key.get_public()

        client_future = asyncio.ensure_future(
            create_circuit(c_reader, c_writer, circid, node_id, pubkey_B)
        )
        create_cell = await read_cell(s_reader, None)
        skeys = \
            handle_create(s_reader, s_writer, node_id, server_key, create_cell)
        ckeys = await client_future

        assert len(skeys) == 72
        assert skeys == ckeys


class TestExtend2:
    def test_build_extend2(self):
        node_id = b"iToldYouAboutStairs."
        server_key = PrivateKey()
        x, create_payload = client_part1(node_id, server_key.get_public())

        c = torpylle.CellRelayExtend2(
                      CircID=69,
                      RelayCommand='RELAY_EXTEND2',
                      StreamID=79,
                      LSpec=b'\x7f\x00\x00\x01\x23\x8b',  # 127.0.0.1:9099
                      HData=b'n'*20 + b'k'*32 + b'c'*32)
        assert len(c) == 512

    def test_read_extend2(self):
        bites = b'\x69\x69'  # CircId
        bites += b'\x03'     # Cmd
        bites += b'\x0e'     # relayCmd
        bites += b'\x00\x00'          # recognized
        bites += b'\x06\x09'          # streamid
        bites += b'\x06\x09\x00\x00'  # digest
        bites += b'\x00\x61'  # length
        bites += b'\x01'      # num specs
        bites += b'\x00'      # link spec type
        bites += b'\x06'      # link spec length
        bites += b'\x7f\x00\x00\x01\x23\x8b'  # 127.0.0.1:9099
        bites += b'\x00\x02'  # Htype = ntor
        bites += b'\x00\x54'  # Hlen = 84 decimal
        bites += b'n'*20      # NodeId
        bites += b'k'*32      # KeyId
        bites += b'c'*32      # ClientPK
        bites += b'p'*421     # Padding
        c = cell_from_bytes(bites)
        assert cell_from_bytes(bites).Command == 3
        assert cell_from_bytes(bites).HData == b'n'*20 + b'k'*32 + b'c'*32


class TestEncryptRelayCell:
    def test_one_hop(self):
        shared_keys = b'a'*20 + b'b'*20 + b'c'*16 + b'd'*16
        op_state = CircuitHop(shared_keys)
        or_state = CircuitHop(shared_keys)

        plaintext = torpylle.CellRelayExtend2(
                      CircID=69,
                      RelayCommand='RELAY_EXTEND2',
                      StreamID=79,
                      LSpec=b'\x7f\x00\x00\x01\x23\x8b',  # 127.0.0.1:9099
                      HData=b'n'*20 + b'k'*32 + b'c'*32)

        print(repr(plaintext))
        encrypted = encrypt_relay_cell([op_state], plaintext, 'fw')
        print(repr(encrypted))
        decrypted = decrypt_relay_cell([or_state], encrypted, 'fw')
        print(repr(decrypted))
        assert bytes(decrypted) == bytes(plaintext)

    def test_two_hop(self):
        shared_keys1 = b'a'*20 + b'b'*20 + b'c'*16 + b'd'*16
        op_state1 = CircuitHop(shared_keys1)
        or_state1 = CircuitHop(shared_keys1)

        shared_keys2 = b'e'*20 + b'f'*20 + b'g'*16 + b'h'*16
        op_state2 = CircuitHop(shared_keys2)
        or_state2 = CircuitHop(shared_keys2)

        plaintext = torpylle.CellRelayExtend2(
                      CircID=69,
                      RelayCommand='RELAY_EXTEND2',
                      StreamID=79,
                      LSpec=b'\x7f\x00\x00\x01\x23\x8b',  # 127.0.0.1:9099
                      HData=b'n'*20 + b'k'*32 + b'c'*32)

        print(repr(plaintext))
        encrypted = encrypt_relay_cell([op_state1, op_state2], plaintext, 'fw')
        print(repr(encrypted))
        # decrypted = \
        #     decrypt_relay_cell([or_state1, or_state2], encrypted, 'fw')
        decrypted1 = decrypt_relay_cell([or_state2], encrypted, 'fw')
        decrypted = decrypt_relay_cell([or_state1], decrypted1, 'fw')
        print(repr(decrypted))
        assert bytes(decrypted) == bytes(plaintext)
