from toytor.common import read_cell
from toytor.certs import verify_cert
from OpenSSL import crypto, SSL
import toytor.torpylle as torpylle
import asyncio
import time


class ProtocolViolation(Exception):
    pass


class IncompatibleVersions(Exception):
    pass


def negotiate_version_common(their_cell, my_versions):
    if their_cell.Command is not torpylle.CELL_COMMANDS['VERSIONS']:
        raise ProtocolViolation("expected VERSIONS, got %s" % their_cell)
    their_versions = their_cell.Versions
    intersection = set(their_versions) & set(my_versions)
    if len(intersection) == 0:
        raise IncompatibleVersions("their versions: %s, mine: %s" %
                                   (their_versions, my_versions))
    return max(intersection)


async def negotiate_version_client(reader, writer, my_versions):
    writer.write(bytes(torpylle.Cell(Command="VERSIONS",
                                     Versions=my_versions)))
    their_cell = await asyncio.wait_for(read_cell(reader, writer), timeout=1)
    return negotiate_version_common(their_cell, my_versions)


async def negotiate_version_server(reader, writer, my_versions):
    their_cell = await asyncio.wait_for(read_cell(reader, writer), timeout=1)
    writer.write(bytes(torpylle.Cell(Command="VERSIONS",
                                     Versions=my_versions)))
    return negotiate_version_common(their_cell, my_versions)


def send_certs(reader, writer, link_cert, id_cert):
    link_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, link_cert)
    id_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, id_cert)
    cert1 = torpylle.OrCert(Type=1, Certificate=link_der)
    cert2 = torpylle.OrCert(Type=2, Certificate=id_der)
    writer.write(bytes(torpylle.Cell(Command="CERTS",
                                     Certificates=[cert1, cert2])))


async def recv_certs(reader, writer):
    certs_cell = await asyncio.wait_for(read_cell(reader, writer), timeout=1)
    assert(len(certs_cell.Certificates) == 2)  # TODO: don't assume order
    der_certs = \
        dict([(x.Type, bytes(x.Certificate)) for x in certs_cell.Certificates])

    link_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_certs[1])
    id_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_certs[2])
    if not verify_cert(link_cert, id_cert):
        raise Exception('verify failed')


def send_auth_challenge(reader, writer):
    c = torpylle.Cell(Command="AUTH_CHALLENGE",
                      Challenge='a'*32,
                      Methods=[])
    writer.write(bytes(c))


async def recv_auth_challenge(reader, writer):
    auth_challenge_cell = await \
        asyncio.wait_for(read_cell(reader, writer), timeout=1)


def send_netinfo(reader, writer, their_address, my_addresses):
    other = torpylle.OrAddress(Type=4, Address=their_address)
    this = [torpylle.OrAddress(Type=4, Address=addr) for addr in my_addresses]
    bites = torpylle.Cell(
        Command="NETINFO",
        OtherOrAddress=other,
        ThisOrAddresses=this,
        Timestamp=int(time.time())
    )
    writer.write(bytes(bites))


async def recv_netinfo(reader, writer):
    netinfo_cell = await asyncio.wait_for(read_cell(reader, writer), timeout=1)


async def full_client_handshake(
        reader, writer, my_versions, my_addresses, their_address):
    version = await negotiate_version_client(reader, writer, my_versions)
    await recv_certs(reader, writer)
    await recv_auth_challenge(reader, writer)
    await recv_netinfo(reader, writer)
    send_netinfo(reader, writer, their_address, my_addresses)
    await(writer.drain())
    return version


async def full_server_handshake(
        reader, writer, my_versions, my_addresses, their_address,
        link_cert, id_cert):
    version = await negotiate_version_server(reader, writer, my_versions)
    send_certs(reader, writer, link_cert, id_cert)
    send_auth_challenge(reader, writer)
    send_netinfo(reader, writer, their_address, my_addresses)
    await recv_netinfo(reader, writer)
    return version
