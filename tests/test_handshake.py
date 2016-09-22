from toytor.handshake import *
import toytor.torpylle as torpylle
import pytest
import time
from toytor.dummytransport import dummy_transport
from toytor.common import cell_from_bytes


class TestNegotiateVersion:
    def test_intersection(self):
        their_cell = torpylle.Cell(Command="VERSIONS", Versions=[2, 3, 4])
        my_versions = [2, 3]
        assert negotiate_version_common(their_cell, my_versions) == 3

    def test_no_intersection(self):
        their_cell = torpylle.Cell(Command="VERSIONS", Versions=[3, 4])
        my_versions = [2]
        with pytest.raises(IncompatibleVersions):
            negotiate_version_common(their_cell, my_versions)

    def test_not_versions(self):
        their_cell = torpylle.Cell(Command="PADDING")
        my_versions = [2]
        with pytest.raises(ProtocolViolation):
            negotiate_version_common(their_cell, my_versions)


class TestFullHandshake:
    @pytest.mark.asyncio
    async def test_compatible(self):
        with open('id_key.pem', 'r') as f:
            id_key = crypto.load_privatekey(
                crypto.FILETYPE_PEM, f.read())
        with open('link_key.pem', 'r') as f:
            link_key = crypto.load_privatekey(
                crypto.FILETYPE_PEM, f.read())
        with open('id_cert.pem', 'r') as f:
            id_cert = crypto.load_certificate(
                crypto.FILETYPE_PEM, f.read())
        with open('link_cert.pem', 'r') as f:
            link_cert = crypto.load_certificate(
                crypto.FILETYPE_PEM, f.read())

        s_reader, c_writer = await dummy_transport()
        c_reader, s_writer = await dummy_transport()

        s_future = asyncio.ensure_future(
            full_server_handshake(s_reader, s_writer, [3],
                                  ['127.0.0.1'], '127.0.0.1', link_cert,
                                  id_cert))
        c_future = asyncio.ensure_future(
            full_client_handshake(c_reader, c_writer, [3],
                                  ['127.0.0.1'], '127.0.0.1'))

        await asyncio.wait([s_future, c_future])
        assert s_future.result() == 3
        assert c_future.result() == 3


class TestNetinfo:
    def test_netinfo(self):
        other = torpylle.OrAddress(Type=4, Address='127.0.0.1')
        this = [torpylle.OrAddress(Type=4, Address='127.0.0.1')]
        bites = torpylle.Cell(
            Command="NETINFO",
            OtherOrAddress=other,
            ThisOrAddresses=[other],
            Timestamp=int(time.time())
        )


class TestAuthChallenge:
    def test_build_auth_challenge(self):
        c = torpylle.Cell(Command="AUTH_CHALLENGE",
                          Challenge='a'*32,
                          Methods=[]).build()
        assert len(c) == 5 + 32 + 2

        c2 = torpylle.Cell(Command="AUTH_CHALLENGE",
                           Challenge='a'*32,
                           Methods=[1]).build()
        assert len(c2) == 5 + 32 + 2 + 2

    def test_read_auth_challenge(self):
        bites = b'\x00\x00\x82\x00'
        bites += b'$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00\x01\x00\x01'
        assert cell_from_bytes(bites).Methods == [1]
