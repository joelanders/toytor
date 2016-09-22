#! /usr/bin/env python

# this file is mostly taken from https://github.com/cea-sec/TorPylle
# I (Joe Landers) have made some tiny modifications.
# The original is copyright the original author under GPL v2

from scapy.all import *

import socket, ssl
import struct
#import urllib2

#HASH_FUNC = Crypto.Hash.SHA
#HASH_NAME = 'sha1'
#HASH_LEN = HASH_FUNC.digest_size
#PUBKEY_FUNC = Crypto.PublicKey.RSA
PUBKEY_MODSIZE = 1024
PUBKEY_ENCLEN = 128
PUBKEY_PADLEN = 42
#STREAM_FUNC = Crypto.Cipher.AES
#STREAM_MODE = Crypto.Cipher.AES.MODE_CTR
STREAM_KEYLEN = 16
DH_LEN = 128
DH_SECLEN = 40
DH_G = 2
DH_P = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007
CELL_LEN = 512
KEY_LEN = 16

torversion = re.compile('^Tor (\d+)\.(\d+)\.(\d+)\.(\d+)(?:-(alpha(?:-dev)?|beta|rc))?$')
torversionorder = [ 'alpha', 'alpha-dev', 'beta', 'rc', None ]
torminversionproto2 = [ 0, 2, 0, 21, None ]
torminversionproto3 = [ 0, 2, 3, 6, 'alpha' ]
torminversionextended2 = [ 0, 2, 4, 8, 'alpha' ]

def str2version(version):
    """
    Converts a string representing a Tor version to a list suitable
    for compare_versions().
    """
    v = torversion.search(version)
    if v is None:
        raise Exception('Unsupported version %s.' % version)
    v = list(v.groups())
    for i in xrange(4):
        v[i] = int(v[i])
    return v

def compare_versions(a, b):
    """
    This function is an equivalent to the built-in cmp() function
    for Tor versions as lists as returned by str2version().
    """
    if a[:4] < b[:4]:
        return -1
    if a[:4] > b[:4]:
        return 1
    return cmp(torversionorder.index(a[4]), torversionorder.index(b[4]))

# tor/src/or/config.c
DEFAULTDIRSERVERS = [
    "moria1 orport=9101 no-v2 "
      "v3ident=D586D18309DED4CD6D57C18FDB97EFA96D330566 "
      "128.31.0.39:9131 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31",
    "tor26 v1 orport=443 v3ident=14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 "
      "86.59.21.38:80 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D",
    "dizum orport=443 v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 "
      "194.109.206.212:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
    "Tonga orport=443 bridge no-v2 82.94.251.203:80 "
      "4A0C CD2D DC79 9508 3D73 F5D6 6710 0C8A 5831 F16D",
    "turtles orport=9090 no-v2 "
      "v3ident=27B6B5996C426270A5C95488AA5BCEB6BCC86956 "
      "76.73.17.194:9030 F397 038A DC51 3361 35E7 B80B D99C A384 4360 292B",
    "gabelmoo orport=443 no-v2 "
      "v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 "
      "212.112.245.170:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",
    "dannenberg orport=443 no-v2 "
      "v3ident=585769C78764D58426B8B52B6651A5A71137189A "
      "193.23.244.244:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",
    "urras orport=80 no-v2 v3ident=80550987E1D626E3EBA5E5E75A458DE0626D088C "
      "208.83.223.34:443 0AD3 FA88 4D18 F89E EA2D 89C0 1937 9E0E 7FD9 4417",
    "maatuska orport=80 no-v2 "
      "v3ident=49015F787433103580E3B66A1707A00E60F2D15B "
      "171.25.193.9:443 BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810",
    "Faravahar orport=443 no-v2 "
      "v3ident=EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97 "
      "154.35.32.5:80 CF6D 0AAF B385 BE71 B8E1 11FC 5CFF 4B47 9237 33BC",
]

DIRECTORY_SERVERS = []
KNOWN_NODES = {}
CIRCUITS = {}

CELL_COMMANDS = {
    "PADDING": 0,
    "CREATE": 1,
    "CREATED": 2,
    "RELAY": 3,
    "DESTROY": 4,
    "CREATE_FAST": 5,
    "CREATED_FAST": 6,
    "VERSIONS": 7,
    "NETINFO": 8,
    "RELAY_EARLY": 9,
    "CREATE2": 10,
    "CREATED2": 11,
    "VPADDING": 128,
    "CERTS": 129,
    "AUTH_CHALLENGE": 130,
    "AUTHENTICATE": 131,
    "AUTHORIZE": 132
    }

class Cell(Packet):
    # Tor Protocol Specification, section 3
    name = "Tor Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 0, CELL_COMMANDS),
        StrFixedLenField("Payload", "", CELL_LEN - 3),
        ]
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        This is used to guess which Cell type we have, according to
        the Command field, and for RELAY Cells, according to the
        RelayCommand field.
        This function is called either with _pkt being a string
        representing the packet's bytes, or with (multiple)
        field=value we get in kargs.
        """
        cmd = None
        if _pkt and len(_pkt) >= 3:
            cmd = struct.unpack("B", _pkt[2:3])[0]
        elif 'Command' in kargs:
            if type(kargs['Command']) is str:
                cmd = CELL_COMMANDS[kargs['Command']]
            elif type(kargs['Command']) is int:
                cmd = kargs['Command']
        if cmd == 0:
            return CellPadding
        if cmd in [3, 9]:
            relcmd = 0
            if _pkt:
                if len(_pkt) >= 6 and (struct.unpack("B", _pkt[3:4])[0] not in CELL_RELAY_COMMANDS.values()
                                       or _pkt[4:6] != b'\x00\x00'):
                    return CellRelayEncrypted
            elif 'Recognized' in kargs:
                if kargs['RelayCommand'] == 0:
                    return CellRelayEncrypted
            if _pkt and len(_pkt) >= 4:
                relcmd = struct.unpack("B", _pkt[3:4])[0]
            elif 'RelayCommand' in kargs:
                if type(kargs['RelayCommand']) is str:
                    relcmd = CELL_RELAY_COMMANDS[kargs['RelayCommand']]
                elif type(kargs['RelayCommand']) is int:
                    relcmd = kargs['RelayCommand']
            if relcmd == 3:
                return CellRelayEnd
            if relcmd == 9:
                return CellRelayTruncated
            if relcmd == 12:
                return CellRelayResolved
            if relcmd == 14:
                return CellRelayExtend2
            if relcmd == 15:
                return CellRelayExtended2
            return CellRelay
        if cmd == 4:
            return CellDestroy
        if cmd == 7:
            return CellVersions
        if cmd == 8:
            return CellNetinfo
        if cmd == 10:
            return CellCreate2
        if cmd == 11:
            return CellCreated2
        if cmd == 129:
            return CellCerts
        if cmd == 130:
            return CellAuthChallenge
        if cmd >= 128:
            return CellVariable
        return Cell

class CellVariable(Cell):
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 0, CELL_COMMANDS),
        FieldLenField("Length", None, "Payload", fmt=">H"),
        StrLenField("Payload", "", length_from=lambda x: x.Length),
        ]

class CellVersions(CellVariable):
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 7, CELL_COMMANDS),
        FieldLenField("Length", None, "Versions", fmt=">H"),
        FieldListField('Versions', [],
                       ShortField("Version", 3),
                       length_from=lambda p: p.Length)
        ]

class CellAuthChallenge(CellVariable):
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 130, CELL_COMMANDS),
        FieldLenField("Length", None, "Methods", fmt=">H",
                      adjust=lambda _, l: l+32+2), # todo: better way?
        StrFixedLenField("Challenge", "", 32),
        FieldLenField("NumberOfMethods", None, count_of="Methods",
                      fmt=">H"),
        FieldListField("Methods", [], ShortField("Method", None),
                       count_from=lambda p: p.NumberOfMethods)
        ]

OR_CERT_TYPES = {
                "Link key": 1,
                "RSA1024 Identity": 2,
                "RSA1024 AUTHENTICATE cell link": 3
                }

class OrCert(Packet):
    name = "Or Certificate"
    fields_desc = [
        ByteEnumField('Type', 0, OR_CERT_TYPES),
        FieldLenField("Length", None, "Certificate", fmt=">H"),
        PacketField('Certificate', None, X509Cert)
        ]

class CellCerts(CellVariable):
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 129, CELL_COMMANDS),
        FieldLenField("Length", None, "Certificates", fmt=">H",
                      adjust=lambda pkt, x: x+1),
        FieldLenField("NumberOfCerts", None, count_of="Certificates",
                      fmt="B"),
        FieldListField('Certificates', [],
                       PacketField('Cert', None, OrCert),
                       count_from=lambda p: p.NumberOfCerts)
        ]

class OrTimeStampField(IntField):
    def i2repr(self, pkt, val):
        if val is None:
            return "--"
        val = self.i2h(pkt,val)
        return time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(val))
    def any2i(self, pkt, val):
        if type(val) is str:
            return int(time.mktime(time.strptime(val)))
        return IntField.any2i(self,pkt,val)
    def i2m(self, pkt, val):
        if val is None:
            val = IntField.any2i(self, pkt, time.time())
        return IntField.i2m(self, pkt, val)

OR_ADDRESS_TYPES = {
    'Hostname': 0x00,
    'IPv4': 0x04,
    'IPv6': 0x06,
    'TransientError': 0xf0,
    'NonTransientError': 0xf1,
    }

class OrAddress(Packet):
    name = "Or Address"
    fields_desc = [
        ByteEnumField('Type', 0, OR_ADDRESS_TYPES),
        FieldLenField("Length", None, "Address", fmt="B"),
        StrLenField("Address", "", length_from=lambda x: x.Length),
        ]
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        tpe = None
        if _pkt and len(_pkt) >= 2:
            tpe = struct.unpack("B", _pkt[0:1])[0]
        elif 'Type' in kargs:
            if type(kargs['Type']) is str:
                tpe = OR_ADDRESS_TYPES[kargs['Type']]
            elif type(kargs['Type']) is int:
                tpe = kargs['Type']
        if tpe == 4:
            return OrAddressIPv4
        return OrAddress

class OrAddressIPv4(OrAddress):
    name = "Or Address"
    fields_desc = [
        ByteEnumField('Type', 0x04, OR_ADDRESS_TYPES),
        FieldLenField("Length", None, "Address", fmt="B"),
        IPField("Address", None)
        ]

class CellNetinfo(Cell):
    name = "Tor Netinfo Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 8, CELL_COMMANDS),
        OrTimeStampField('Timestamp', None),
        PacketField('OtherOrAddress', None, OrAddress),
        FieldLenField('NumberOfAddresses', None, fmt="B",
                      count_of="ThisOrAddresses"),
        FieldListField('ThisOrAddresses', [],
                       PacketField('ThisOr', None, OrAddress),
                       count_from=lambda p: p.NumberOfAddresses),
        StrFixedLenField("Padding", "", length_from=lambda x: CELL_LEN - 8 - len(x.OtherOrAddress) - sum(map(len, x.ThisOrAddresses)))
        ]

OR_HTYPES = {
    'TAP': 0x00,
    '<reserved>': 0x01,
    'ntor': 0x02
    }

class CellCreate2(Cell):
    name = "Tor Create2 Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 10, CELL_COMMANDS),
        ShortEnumField('Htype', 0x02, OR_HTYPES),
        FieldLenField("Hlen", None, "Hdata", fmt=">H"),
        StrLenField("Hdata", "", length_from=lambda x: x.Hlen),
        StrFixedLenField("Padding", "", length_from=lambda x: CELL_LEN - 7 - 20 - 32 - 32)
        ]

class CellCreated2(Cell):
    name = "Tor Created2 Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 10, CELL_COMMANDS),
        FieldLenField("Hlen", None, "Hdata", fmt=">H"),
        StrLenField("Hdata", "", length_from=lambda x: x.Hlen),
        StrFixedLenField("Padding", "", length_from=lambda x: CELL_LEN - 5 - 32 - 32)
        ]

CELL_RELAY_COMMANDS = {
    "RELAY_BEGIN": 1,
    "RELAY_DATA": 2,
    "RELAY_END": 3,
    "RELAY_CONNECTED": 4,
    "RELAY_SENDME": 5,
    "RELAY_EXTEND": 6,
    "RELAY_EXTENDED": 7,
    "RELAY_TRUNCATE": 8,
    "RELAY_TRUNCATED": 9,
    "RELAY_DROP": 10,
    "RELAY_RESOLVE": 11,
    "RELAY_RESOLVED": 12,
    "RELAY_BEGIN_DIR": 13,
    "RELAY_EXTEND2": 14,
    "RELAY_EXTENDED2": 15,
    }

class CellRelay(Cell):
    name = "Tor Relay Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 3, CELL_COMMANDS),
        ByteEnumField('RelayCommand', 1, CELL_RELAY_COMMANDS),
        ShortField('Recognized', 0),
        ShortField('StreamID', 0),
        StrFixedLenField('Digest', '', 4),
        FieldLenField("Length", None, "Data", fmt=">H"),
        StrLenField("Data", "", length_from=lambda x: x.Length),
        StrFixedLenField("Padding", "", length_from=lambda x: CELL_LEN - 14 - len(x.Data))
        ]

class CellRelayEncrypted(CellRelay):
    name = "Tor Relay Cell (encrypted)"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 3, CELL_COMMANDS),
        StrFixedLenField("EncryptedData", "", length=CELL_LEN - 3)
        ]

class CellRelayResolved(Cell):
    name = "Tor Relay/Resolved Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 3, CELL_COMMANDS),
        ByteEnumField('RelayCommand', 12, CELL_RELAY_COMMANDS),
        ShortField('Recognized', 0),
        ShortField('StreamID', 0),
        StrFixedLenField('Digest', '', 4),
        FieldLenField("Length", None, "Address", fmt=">H",
                      adjust=lambda pkt, x: x+4),
        PacketField('Address', None, OrAddress),
        IntField("TTL", 0),
        StrFixedLenField("Padding", "", length_from=lambda x: CELL_LEN - 18 - len(x.Address))
        ]

# TODO: i'm only allowing a single ip4 link specifier for simplicity now (laziness)
class CellRelayExtend2(Cell):
    name = "Tor Extend2 Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 3, CELL_COMMANDS),
        ByteEnumField('RelayCommand', 14, CELL_RELAY_COMMANDS),
        ShortField('Recognized', 0),
        ShortField('StreamID', 0),
        StrFixedLenField('Digest', '', 4),
        ShortField('Length', 97),
        #FieldLenField("Length", None, "Data", fmt=">H"),
        #StrLenField("Data", "", length_from=lambda x: x.Length),
        #FieldLenField("Nspec", None, count_of="Certificates",
        #              fmt="B"),
        ByteField('Nspec', 1),
        ByteField('LSType', 0), # 4-byte ipv4 + 2-byte port
        ByteField('LSLen', 6),
        StrFixedLenField("LSpec", None, 6),
        ShortEnumField('Htype', 0x02, OR_HTYPES),
        FieldLenField("Hlen", None, "HData", fmt=">H"),
        StrLenField("HData", "", length_from=lambda x: x.Hlen),
        StrFixedLenField("Padding", "", 512 - 97 - 14)
        ]

class CellRelayExtended2(Cell):
    name = "Tor Extended2 Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 3, CELL_COMMANDS),
        ByteEnumField('RelayCommand', 15, CELL_RELAY_COMMANDS),
        ShortField('Recognized', 0),
        ShortField('StreamID', 0),
        StrFixedLenField('Digest', '', 4),
        #FieldLenField("Length", None, "Data", fmt=">H"),
        #StrLenField("Data", "", length_from=lambda x: x.Length),
        #FieldLenField("Nspec", None, count_of="Certificates",
        #              fmt="B"),
        FieldLenField("Hlen", None, "Hdata", fmt=">H"),
        StrLenField("Hdata", "", length_from=lambda x: x.Hlen),
        StrFixedLenField("Padding", "", length_from=lambda x: CELL_LEN - 14 - len(x.Data))
        ]

CELL_RELAYEND_REASONS = {
    "REASON_MISC": 1,
    "REASON_RESOLVEFAILED": 2,
    "REASON_CONNECTREFUSED": 3,
    "REASON_EXITPOLICY": 4,
    "REASON_DESTROY": 5,
    "REASON_DONE": 6,
    "REASON_TIMEOUT": 7,
    "REASON_NOROUTE": 8,
    "REASON_HIBERNATING": 9,
    "REASON_INTERNAL": 10,
    "REASON_RESOURCELIMIT": 11,
    "REASON_CONNRESET": 12,
    "REASON_TORPROTOCOL": 13,
    "REASON_NOTDIRECTORY": 14,
    }

class CellRelayEnd(Cell):
    name = "Tor Relay/End Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 3, CELL_COMMANDS),
        ByteEnumField('RelayCommand', 3, CELL_RELAY_COMMANDS),
        ShortField('Recognized', 0),
        ShortField('StreamID', 0),
        StrFixedLenField('Digest', '', 4),
        ShortField('Length', 1),
        ByteEnumField('Reason', 0, CELL_RELAYEND_REASONS),
        StrFixedLenField("Padding", "", length_from=lambda x: CELL_LEN - 14)
        ]

CELL_DESTROY_CODES = {
    "NONE": 0,
    "PROTOCOL": 1,
    "INTERNAL": 2,
    "REQUESTED": 3,
    "HIBERNATING": 4,
    "RESOURCELIMIT": 5,
    "CONNECTFAILED": 6,
    "OR_IDENTITY": 7,
    "OR_CONN_CLOSED": 8,
    "FINISHED": 9,
    "TIMEOUT": 10,
    "DESTROYED": 11,
    "NOSUCHSERVICE": 12,
    }

class CellRelayTruncated(Cell):
    name = "Tor Relay/End Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 3, CELL_COMMANDS),
        ByteEnumField('RelayCommand', 9, CELL_RELAY_COMMANDS),
        ShortField('Recognized', 0),
        ShortField('StreamID', 0),
        StrFixedLenField('Digest', '', 4),
        ShortField('Length', 1),
        ByteEnumField('ErrorCode', 0, CELL_DESTROY_CODES),
        StrFixedLenField("Padding", "", length_from=lambda x: CELL_LEN - 14)
        ]

class CellDestroy(Cell):
    name = "Tor Destroy Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 4, CELL_COMMANDS),
        ByteEnumField('ErrorCode', 0, CELL_DESTROY_CODES),
        StrFixedLenField('Padding', "", CELL_LEN - 4)
        ]

class CellPadding(Cell):
    name = "Tor Padding Cell"

bind_layers(OrCert, Padding)
bind_layers(X509Cert, Padding)
bind_layers(OrAddress, Padding)
bind_layers(Cell, Padding)

DIRSERVER_FLAGS = {
    'NO_DIRINFO': 0,
    # Serves/signs v1 directory information: Big lists of routers, and short
    # routerstatus documents.
    'V1_DIRINFO': 1 << 0,
    # Serves/signs v2 directory information: i.e. v2 networkstatus documents
    'V2_DIRINFO': 1 << 1,
    # Serves/signs v3 directory information: votes, consensuses, certs
    'V3_DIRINFO': 1 << 2,
    # Serves hidden service descriptors.
    'HIDSERV_DIRINFO': 1 << 3,
    # Serves bridge descriptors.
    'BRIDGE_DIRINFO': 1 << 4,
    # Serves extrainfo documents.
    'EXTRAINFO_DIRINFO': 1 << 5,
    # Serves microdescriptors.
    'MICRODESC_DIRINFO': 1 << 6
}

