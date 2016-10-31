import toytor.slownacl_curve25519 as curve25519mod
import hashlib
import hmac
import sys
import toytor.torpylle as torpylle
import asyncio
from ipaddress import IPv4Address
import struct
import logging
import binascii

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter

# this is largely taken verbatim from tor's src/test/ntor_ref.py
# that file (and what I've copied) is Copyright 2012-2015, The Tor Project, Inc
# under the 3-clause BSD License:

# Copyright (c) 2001-2004, Roger Dingledine
# Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson
# Copyright (c) 2007-2016, The Tor Project, Inc.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#
#     * Neither the names of the copyright owners nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


def HMAC(key, msg):
    "Return the HMAC-SHA256 of 'msg' using the key 'key'."
    H = hmac.new(key, b"", hashlib.sha256)
    H.update(msg)
    return H.digest()


def H(msg, tweak):
    """Return the hash of 'msg' using tweak 'tweak'.  (In this version of ntor,
       the tweaked hash is just HMAC with the tweak as the key.)"""
    return HMAC(key=tweak,
                msg=msg)


def keyid(k):
    """Return the 32-byte key ID of a public key 'k'. (Since we're
       using curve25519, we let k be its own keyid.)
    """
    return k.serialize()


NODE_ID_LENGTH = 20
KEYID_LENGTH = 32
G_LENGTH = 32
H_LENGTH = 32


PROTOID = b"ntor-curve25519-sha256-1"
M_EXPAND = PROTOID + b":key_expand"
T_MAC = PROTOID + b":mac"
T_KEY = PROTOID + b":key_extract"
T_VERIFY = PROTOID + b":verify"


def H_mac(msg): return H(msg, tweak=T_MAC)


def H_verify(msg): return H(msg, tweak=T_VERIFY)


PublicKey = curve25519mod.Public


class PrivateKey(curve25519mod.Private):
    """As curve25519mod.Private, but doesn't regenerate its public key
       every time you ask for it.
    """
    def __init__(self, *args, **kwargs):
        curve25519mod.Private.__init__(self, *args, **kwargs)
        self._memo_public = None

    def get_public(self):
        if self._memo_public is None:
            self._memo_public = curve25519mod.Private.get_public(self)

        return self._memo_public

if sys.version < '3':
    def int2byte(i):
        return chr(i)
else:
    def int2byte(i):
        return bytes([i])


def kdf_rfc5869(key, salt, info, n):

    prk = HMAC(key=salt, msg=key)

    out = b""
    last = b""
    i = 1
    while len(out) < n:
        m = last + info + int2byte(i)
        last = h = HMAC(key=prk, msg=m)
        out += h
        i = i + 1
    return out[:n]


def kdf_ntor(key, n):
    return kdf_rfc5869(key, T_KEY, M_EXPAND, n)


def client_part1(node_id, pubkey_B):
    """Initial handshake, client side.

       From the specification:

         <<To send a create cell, the client generates a keypair x,X =
           KEYGEN(), and sends a CREATE cell with contents:

           NODEID:     ID             -- ID_LENGTH bytes
           KEYID:      KEYID(B)       -- H_LENGTH bytes
           CLIENT_PK:  X              -- G_LENGTH bytes
         >>

       Takes node_id -- a digest of the server's identity key,
             pubkey_B -- a public key for the server.
       Returns a tuple of (client secret key x, client->server message)"""

    assert len(node_id) == NODE_ID_LENGTH

    key_id = keyid(pubkey_B)
    seckey_x = PrivateKey()
    pubkey_X = seckey_x.get_public().serialize()

    message = node_id + key_id + pubkey_X

    assert len(message) == NODE_ID_LENGTH + H_LENGTH + H_LENGTH
    return seckey_x, message


def hash_nil(x):
    """Identity function: if we don't pass a hash function that does nothing,
       the curve25519 python lib will try to sha256 it for us."""
    return x


def bad_result(r):
    """Helper: given a result of multiplying a public key by a private key,
       return True iff one of the inputs was broken"""
    assert len(r) == 32
    return r == '\x00'*32


def server(seckey_b, my_node_id, message, keyBytes=72):
    """Handshake step 2, server side.

       From the spec:

       <<
         The server generates a keypair of y,Y = KEYGEN(), and computes

           secret_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
           KEY_SEED = H(secret_input, t_key)
           verify = H(secret_input, t_verify)
           auth_input = verify | ID | B | Y | X | PROTOID | "Server"

         The server sends a CREATED cell containing:

           SERVER_PK:  Y                     -- G_LENGTH bytes
           AUTH:       H(auth_input, t_mac)  -- H_LENGTH byets
        >>

       Takes seckey_b -- the server's secret key
             my_node_id -- the servers's public key digest,
             message -- a message from a client
             keybytes -- amount of key material to generate

       Returns a tuple of (key material, sever->client reply), or None on
       error.
    """

    assert len(message) == NODE_ID_LENGTH + H_LENGTH + H_LENGTH

    if my_node_id != message[:NODE_ID_LENGTH]:
        return None

    badness = (keyid(seckey_b.get_public()) !=
               message[NODE_ID_LENGTH:NODE_ID_LENGTH+H_LENGTH])

    pubkey_X = curve25519mod.Public(message[NODE_ID_LENGTH+H_LENGTH:])
    seckey_y = PrivateKey()
    pubkey_Y = seckey_y.get_public()
    pubkey_B = seckey_b.get_public()
    xy = seckey_y.get_shared_key(pubkey_X, hash_nil)
    xb = seckey_b.get_shared_key(pubkey_X, hash_nil)

    # secret_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
    secret_input = (xy + xb + my_node_id +
                    pubkey_B.serialize() +
                    pubkey_X.serialize() +
                    pubkey_Y.serialize() +
                    PROTOID)

    verify = H_verify(secret_input)

    # auth_input = verify | ID | B | Y | X | PROTOID | "Server"
    auth_input = (verify +
                  my_node_id +
                  pubkey_B.serialize() +
                  pubkey_Y.serialize() +
                  pubkey_X.serialize() +
                  PROTOID +
                  b"Server")

    msg = pubkey_Y.serialize() + H_mac(auth_input)

    badness += bad_result(xb)
    badness += bad_result(xy)

    if badness:
        return None

    keys = kdf_ntor(secret_input, keyBytes)

    return keys, msg


def client_part2(seckey_x, msg, node_id, pubkey_B, keyBytes=72):
    """Handshake step 3: client side again.

       From the spec:

       <<
         The client then checks Y is in G^* [see NOTE below], and computes

         secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
         KEY_SEED = H(secret_input, t_key)
         verify = H(secret_input, t_verify)
         auth_input = verify | ID | B | Y | X | PROTOID | "Server"

         The client verifies that AUTH == H(auth_input, t_mac).
       >>

       Takes seckey_x -- the secret key we generated in step 1.
             msg -- the message from the server.
             node_id -- the node_id we used in step 1.
             server_key -- the same public key we used in step 1.
             keyBytes -- the number of bytes we want to generate
       Returns key material, or None on error

    """
    assert len(msg) == G_LENGTH + H_LENGTH

    pubkey_Y = curve25519mod.Public(msg[:G_LENGTH])
    their_auth = msg[G_LENGTH:]

    pubkey_X = seckey_x.get_public()

    yx = seckey_x.get_shared_key(pubkey_Y, hash_nil)
    bx = seckey_x.get_shared_key(pubkey_B, hash_nil)

    # secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
    secret_input = (yx + bx + node_id +
                    pubkey_B.serialize() +
                    pubkey_X.serialize() +
                    pubkey_Y.serialize() + PROTOID)

    verify = H_verify(secret_input)

    # auth_input = verify | ID | B | Y | X | PROTOID | "Server"
    auth_input = (verify + node_id +
                  pubkey_B.serialize() +
                  pubkey_Y.serialize() +
                  pubkey_X.serialize() + PROTOID +
                  b"Server")

    my_auth = H_mac(auth_input)

    badness = my_auth != their_auth
    badness |= bad_result(yx) + bad_result(bx)

    if badness:
        logger.info("&&&&&& BADNESS &&&&&&")
        return None

    return kdf_ntor(secret_input, keyBytes)


# sends CREATE2, awaits CREATED2, returns keys
async def create_circuit(reader_q, writer, circid, node_id, pubkey_B):
    assert len(node_id) == 20
    assert len(pubkey_B.serialize()) == 32
    x, create_payload = client_part1(node_id, pubkey_B)
    writer.write(bytes(torpylle.Cell(Command="CREATE2",
                                     CircID=circid,
                                     Htype="ntor",
                                     Hdata=create_payload)))
    created_cell = await asyncio.wait_for(reader_q.get(), timeout=4)
    # Hdata should always have len=64 anyway
    created_hdata = created_cell.Hdata[:64]
    keys = client_part2(x, created_hdata, node_id, pubkey_B)
    logger.info('hdata:  %s' % hex(struct.unpack('<L', created_hdata[:4])[0]))
    logger.info('hdata:  %s' % hex(struct.unpack('<L', created_hdata[4:8])[0]))
    logger.info('hdata:  %s' % hex(struct.unpack('<L', created_hdata[8:12])[0]))
    logger.info('hdata:  %s' % hex(struct.unpack('<L', created_hdata[12:16])[0]))

    logger.info('digest forward:  %s' % hex(struct.unpack('<L', keys[:4])[0]))
    logger.info('digest backward: %s' % hex(struct.unpack('<L', keys[20:24])[0]))
    logger.info('keys forward:    %s' % hex(struct.unpack('<L', keys[40:44])[0]))
    logger.info('keys backward:   %s' % hex(struct.unpack('<L', keys[56:60])[0]))
    return keys


# takes hdata from create cell, writes CREATED2, returns keys
def handle_create(reader, writer, node_id, seckey_b, create_cell):
    assert len(node_id) == 20
    assert len(seckey_b.get_public().serialize()) == 32
    create_hdata = create_cell.Hdata[:84]
    skeys, created_hdata = server(seckey_b, node_id, create_hdata)
    writer.write(bytes(torpylle.Cell(Command="CREATED2",
                                     Hdata=created_hdata,
                                     CircID=create_cell.CircID)))
    return skeys


async def extend_circuit(reader_q, cell_queuer, circid, node_id, pubkey_B, ip, port):
    assert len(node_id) == 20
    assert len(pubkey_B.serialize()) == 32
    x, extend_payload = client_part1(node_id, pubkey_B)
    ip_bytes = IPv4Address(ip).packed  # TODO: handle exception
    port_bytes = struct.pack('>H', port)
    lspec = ip_bytes + port_bytes
    assert len(lspec) == 6
    await cell_queuer.put(torpylle.CellRelayExtend2(
                    RelayCommand="RELAY_EXTEND2",
                    CircID=circid,
                    StreamID=0,
                    LSpec0=lspec,
                    LSpec1=node_id,
                    HData=extend_payload))
    extended_cell = await \
        asyncio.wait_for(reader_q.get(), timeout=4)
    # Hdata should always have len=64 anyway
    extended_hdata = extended_cell.Hdata[:64]
    keys = client_part2(x, extended_hdata, node_id, pubkey_B)
    logger.info('digest forward:  %s' % hex(struct.unpack('<L', keys[:4])[0]))
    logger.info('digest backward: %s' % hex(struct.unpack('<L', keys[20:24])[0]))
    logger.info('keys forward:    %s' % hex(struct.unpack('<L', keys[40:44])[0]))
    logger.info('keys backward:   %s' % hex(struct.unpack('<L', keys[56:60])[0]))
    return keys


# def handle_extend(reader, writer, node_id, seckey_b, create_cell):
#     assert len(node_id) == 20
#     assert len(seckey_b.get_public().serialize()) == 32
#     create_hdata = create_cell.Hdata[:84]
#     skeys, created_hdata = server(seckey_b, node_id, create_hdata)
#     writer.write( bytes(torpylle.Cell(Command="CREATED2",
#                                       Hdata=created_hdata)) )
#     return skeys


def encrypt_relay_cell(circuit_hops, relay_cell, direction):
    if direction not in ['fw', 'bw']:
        raise Exception('bad direction in encrypt_relay_cell')
    logger.info('encrypting in direction %s' % direction)
    relay_cell.Digest = b'\x00' * 4
    if direction == 'fw':
        logger.info('current digest %s' % circuit_hops[-1].hash_fw.hexdigest())
        circuit_hops[-1].hash_fw.update(bytes(relay_cell)[3:])
        relay_cell.Digest = circuit_hops[-1].hash_fw.digest()[:4]
    else:
        logger.info('current digest %s' % circuit_hops[-1].hash_bw.hexdigest())
        circuit_hops[-1].hash_bw.update(bytes(relay_cell)[3:])
        relay_cell.Digest = circuit_hops[-1].hash_bw.digest()[:4]
    logger.info('sent digest %s' % hex(struct.unpack('<L', relay_cell.Digest)[0]))
    logger.info('cell %s' % repr(relay_cell))
    payload = bytes(relay_cell)[3:]
    for hop in reversed(circuit_hops):
        if direction == 'fw':
            payload = hop.cipher_fw.encrypt(payload)
        else:
            payload = hop.cipher_bw.encrypt(payload)
    cell = torpylle.Cell(bytes(relay_cell)[:3] + payload)
    return cell


# TODO: I may have some remaining incorrect assumptions about
# this thing working for start, middle, and end relays
def decrypt_relay_cell(circuit_hops, relay_cell, direction):
    logger.info('decrypt_relay_cell: %s' % repr(relay_cell))
    if direction not in ['fw', 'bw']:
        raise Exception('bad direction in decrypt_relay_cell')
    payload = bytes(relay_cell)[3:]
    for hop in circuit_hops:
        if direction == 'fw':
            payload = hop.cipher_fw.decrypt(payload)
        else:
            payload = hop.cipher_bw.decrypt(payload)
    pt_bytes = bytes(relay_cell)[:3] + payload
    logger.info('pt_bytes: %s' % pt_bytes)
    pt_cell = torpylle.Cell(pt_bytes)
    pt_copy = torpylle.Cell(pt_bytes) # TODO: this is nasty
    logger.info('unencr: %s' % repr(pt_cell))
    if isinstance(pt_cell, torpylle.CellRelayEncrypted):
        logger.info('not recognized, so returning')
        return pt_cell # still encrypted, not destined here
    their_digest = pt_copy.Digest
    pt_copy.Digest = b'\x00\x00\x00\x00'
    old_state = None
    our_digest = None
    if direction == 'fw':
        old_state = circuit_hops[-1].hash_fw.digest()
        logger.info('our old digest: %s' % old_state)
        circuit_hops[-1].hash_fw.update(bytes(pt_copy)[3:])
        our_digest = circuit_hops[-1].hash_fw.digest()
    else:
        old_state = circuit_hops[-1].hash_bw.digest()
        logger.info('our old digest: %s' % old_state)
        circuit_hops[-1].hash_bw.update(bytes(pt_copy)[3:])
        our_digest = circuit_hops[-1].hash_bw.digest()
    # TODO: not done, need to revert state if digests don't match                   <==========================!!!
    logger.info('our digest: %s their digest: %s' % (our_digest, their_digest))
    if our_digest[:4] != their_digest:
        raise Exception('no match')
    return pt_cell


class CircuitHop:
    def __init__(self, key_material):
        assert len(key_material) == 72
        df = key_material[:20]
        db = key_material[20:40]
        kf = key_material[40:56]
        kb = key_material[56:72]
        self.hash_fw = hashlib.sha1(df)
        self.hash_bw = hashlib.sha1(db)
        logger.info('000000 hash_fw: %s' % hex(struct.unpack('<L', self.hash_fw.digest()[:4])[0]))
        logger.info('000000 hash_bw: %s' % hex(struct.unpack('<L', self.hash_bw.digest()[:4])[0]))
        self.cipher_fw = AES.new(kf, AES.MODE_CTR, counter=Counter.new(128, initial_value=0))
        self.cipher_bw = AES.new(kb, AES.MODE_CTR, counter=Counter.new(128, initial_value=0))
