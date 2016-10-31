here's a work-in-progress toy tor implementation written with the new python
asyncio module and the new async/await coroutine keywords.

# OUTPUT
example session of what I type into the control server:
```
howdy
consensus
client 69 9AB708336F9CF645AD0C37D0F0E4D8B949557FB3
extend 69 3AD6F49FF54691889A4AB0DCD96AA900E88B05EC
resolve 69 google.com
quit
```

slightly reduced version of the log messages (dumping everything into INFO level, so it's quite verbose):
```
l@tp ~/code/toytor [master] $ python3.5 main.py
WARNING: Failed to execute tcpdump. Check it is installed and in the PATH
WARNING: No route found for IPv6 destination :: (no default route?). This affects only IPv6
INFO 03:20:54 toytor.control          ControlServer started on port 9090
INFO 03:20:54 __main__                entering main
INFO 03:20:59 toytor.consensus        found, loading from disk
INFO 03:20:59 toytor.control          3AD6F49FF54691889A4AB0DCD96AA900E88B05EC 127.0.0.1 5011
INFO 03:20:59 toytor.control          C877E0A71B62BBDCBD631C4A429FA927383AB843 127.0.0.1 5009
INFO 03:20:59 toytor.control          E1103682612C4E32F2F3D162F451E8F7481DCFDE 127.0.0.1 5004
INFO 03:20:59 toytor.control          9AB708336F9CF645AD0C37D0F0E4D8B949557FB3 127.0.0.1 5014
INFO 03:20:59 toytor.control          34781C6D081D2352636106746585031A842CC79D 127.0.0.1 5001
INFO 03:21:04 toytor.consensus        downloading http://127.0.0.1:7002/tor/server/d/DBEF71D7E001A2E4256B5EE6622EF37F4184BA73
INFO 03:21:04 toytor.client           hi 69 '127.0.0.1'
INFO 03:21:04 toytor.client           client connected
INFO 03:21:04 toytor.client           client completed handshake
INFO 03:21:04 toytor.client           client handshaked
INFO 03:21:04 toytor.client           client started CellQueuer
INFO 03:21:04 toytor.client           cell_queues: {0: <Queue at 0x7fe2cea77eb8 maxsize=0>, 69: <Queue at 0x7fe2cea77828 maxsize=0>}
INFO 03:21:04 toytor.cellqueuer       blocking on read_cell
INFO 03:21:04 toytor.cellqueuer       blocking on out_queue.get()
INFO 03:21:04 toytor.cellqueuer       got cell with good circid 69
INFO 03:21:04 toytor.cellqueuer       <CellCreated2  CircID=69 Command=CREATED2 Hlen=64 Hdata=b"\xd4\x8b!z\x99\xc1\xac\x9d\xef\xe4\xa6\x0cE\x8f\xf5\x92\xd1\xde\x8eB6\xc74\xaa=eoWl\xdc\x1a8\x17e^\x89\x8ct\xe9\xa8w\xfc_\x1d\t\xb9c<\xf1\xd1\x80\x0f\xdf\xf4\xa5\xea\xa0\xf8\x08\xa3\xae'\xfas" Padding=b'' |>
INFO 03:21:04 toytor.cellqueuer       putting plaintext relaycell on queue
INFO 03:21:04 toytor.cellqueuer       blocking on read_cell
INFO 03:21:04 toytor.create           digest forward:  0x2bea6fc5
INFO 03:21:04 toytor.create           digest backward: 0xfd6a3fc3
INFO 03:21:04 toytor.create           keys forward:    0x5611871b
INFO 03:21:04 toytor.create           keys backward:   0xf261d8df
INFO 03:21:04 toytor.client           create_circuit exiting fine
INFO 03:21:04 toytor.client           client circuit created
INFO 03:21:10 toytor.consensus        downloading http://127.0.0.1:7001/tor/server/d/EA5DF09CC4F751A77B816F6ED17AA6D3B03233B5
INFO 03:21:10 toytor.client           cell_queues: {0: <Queue at 0x7fe2cea77eb8 maxsize=0 _getters[1]>, 69: <Queue at 0x7fe2cea77828 maxsize=0 tasks=1>}
INFO 03:21:10 toytor.cellqueuer       encrypting outgoing RelayCell
INFO 03:21:10 toytor.cellqueuer       <CellRelayExtend2  CircID=69 RelayCommand=RELAY_EXTEND2 StreamID=0 LSpec0=b'\x7f\x00\x00\x01\x13\x93' LSpec1=b':\xd6\xf4\x9f\xf5F\x91\x88\x9aJ\xb0\xdc\xd9j\xa9\x00\xe8\x8b\x05\xec' HData=b":\xd6\xf4\x9f\xf5F\x91\x88\x9aJ\xb0\xdc\xd9j\xa9\x00\xe8\x8b\x05\xec\x10Ta\xdc_\x84\x02f-\xe0N\x95\xb5\xbak\xd2\xf8!\x1a\xa4\xca\xafK`\xebIZYQ\xbd\xaeG2\xfb\xa7\x04\xa8\xf4\xbdV4\xe6\x03C\xc9E\x12\xc8l\xda\xe6\xfb-\xfa\x17o\xe3'F\x94q\x1e\xdc<" |>
INFO 03:21:10 toytor.cellqueuer       wrote outgoing cell
INFO 03:21:10 toytor.cellqueuer       <CellRelayEncrypted  CircID=69 Command=RELAY_EARLY EncryptedData=b'gM=l\xc6_Vbe\x0bw~\xe92\x02w\xeb\xa19j\x91\xbeS=\x92\xe4\x91\x16AR\ta\xd4Z\xf08)\xa7\xdcbt\xb2TQ\x8dc\xdf\xba]\xb5\xe9\xe1\x9fg`\xf6 X\xcbHp\x8e\xc3o6~\x10\\\x16y\x9azcJo\xdd_\x9c6!;\x94\x7f\x15C\xfb\xa7$[5\x0fzl\xab\x9a\x1bz\x07d\xb8Q\x94\xba\xe6\x94j\x0c\xc8\xce\x8aB5\xd7{\xfdcY\xfd\xe9u\x9c\xd6\x1du\x99\xa8\xdf\xe9\x9b\xa2j\x81\xf0\x96J\xac>fO@b\xa4Y\x95o[\xf1\xb6NQ\x00\xbb\x94\xe3U\xc4\x80\x85\xb0\xe5?\xb6\x0f\xe0\xebf;\xa7\xd83\x95n\x8d\x12{)\x19Y\xe0\xaa\x07\xd8\xf9\x02\xe0e\x03]\xf5\xcdeSR\xc9f\xa3\xc8\xd2\xe7\x085w\xd1\xfdd\x18[\'*\xad\x80\xc3T\xa8\xccRN\xb7\x18n\x08\xaa\xae\xad9\xb5\x8f\xa7x\x12e?\x9a\xb2\xea3\x19"\xe8\x96\xd2\xd4G\xce\xae2\xbb\xc9(\xd6\xe2\\\t\x9e\x1a\xd8\xbe\x05p\xb5\xe62\x1cJ(eWG\xef\x83\xb7\xfb\\\tO\x14q\x9e\xb0\xcd\xd9e\xdf\x05\xa0\xf9\x90\x8a{\x85(\xe8\x15\xac\xda\x8c\xb7W\xe9\xfdVD\x9b\xe5,\x19\xe3I\xc5\n\xcf\xcf\xcf\xe0\xb2\xc2Z\x1d^\xc4Mx?\x12`,\x14@\xd0\x80\xbf\xcb\xd4\x15\x81\xf8p\x1f\xe3\x1f\xb2(8\xb3b\x1e9H\xff5*2^\xc0s\x04\xb1\xf8p\xc9\x81\xb1daq\xc4\xd5\xeb\xec\xc9\x01b\xdf\xdc1\x06^\x87\xff\xf8\xbbM~_\xe9X\x96\x1e7?\xec? \xb9\xd3\xd0\x03\xfd\xeb\xd7\xc8k\x94aD\xe6Oj\xffV\xce\'L\xe5Am2z\xab\x08gfFj\xe1\xe0Ql#\xd3$\x03\x13l\'j\x0b\xcc\x9f\x8964e\xe9\xf7\xefm\xf0\xe0\',e#\xed\xdc2U>\x0e\x08\x98\xac\x81M\xaa\x17\xe5\x99b\xe7\x95\xe4\xbd\xb8N\xf6F\xe9d\xd7\xb7\xc4B\xed\xabwrpQ\xa9\x02^\xcb\xb3n\xbd\x1eX\x1e2(SY\x9c<\xef\x9d\x9d\xd8' |>
INFO 03:21:10 toytor.cellqueuer       blocking on out_queue.get()
INFO 03:21:10 toytor.cellqueuer       got cell with good circid 69
INFO 03:21:10 toytor.cellqueuer       <CellRelayEncrypted  CircID=69 Command=RELAY EncryptedData=b"\x9e\x8f]\x8b\x14<Po-\x85\xdf+\xec\xa2\xf1{X\xdc\xb0\xf3\x88\xfeUu\x98&\x13 \x92a\xe9\xda#\x99\x03\x91\r\xf6\xc3\x7f5c\xd2\x12{\x9d\xa8EZS\xb3\xaa\x18V\xd2\xef\x8c\xbfO\xb1g\x0bE\xd3\xc0\x03\xf0r\xf1~1\xb0\xbd\x86fy!\xd4\xa7\xba8#\xe1\xd8Z\x15\x88\x9d\x88d\xa8\x0b\xbb\xd5@\xc5t@\xbf\xb9o\x1b\xcfsO\x94h\x8e\xc1\x1c\x98\x9e\x8e;\xd4\x97\xff\xc2k/*\xa7\xe9~\xd6AJ\xa0\x17\x878b1\xa3\xaej\xfb\x18\t\xb9|z\xff\xf6d\x13\xcc\x92\x19\x0b\xc8[\xaa\xb5\x86?~A\xa5E\x92\x05w\xc4\x8f\xdb\xe0\x97n\xb1ln\x8d\x95\xf3\xe7\x10.?\xe7\x88\xb7\xf5\x12D0\xfa(\xbe\xf6\xcd\xb4]L\xa2\xadc\x05\x95\xb9\xf0\x8de\x18W=\x11\xe3\x7f0N+tP\xa4\xfd\x89\xb8\xa3\xc3\xbd,\xbe+\x0f\xe1\xc4\x04V.\x90t\xe9\xba\xa4\x0c0'\xb2\xfd|\xa3C\xda\x0e+s\x8aU\xa2\x03\n\xfeQ5\xa9D9\x12\xd7\x97f\x05\xc3\xe5\xe8[\x9c't)#\x13\xd4\xde\xc3\x8dD\x8d\x87\xdfX\xff\xceq\xf6n(\x01T\xb3R\x95\xc8\xd2W\x85\xcd\xe9r\x05\x85\x98h\xef\x92Q\xbeG}\xeb\xb8\xeb\xd8v\xdd6\xdf\xbcH\x9b\x99\xf0\xbd\xa6\x04\xd2\xb5\xbca\xc6\xbb\xac.\xef\xd0\xfc0V|\xa5f\xc1\xf1V\x98\x16\xd4\xc6\x06\xdd\xec\x9eg\xff\xbf\x19\xd0i\x10\x13\xca\x85\xc0w\xf3\x08\xd4\x9b\xc2\xabt\xab\xd2K!8\xe3\x04\x9fQ\xa9F<u?c\x81V\x1b\x9d@\xfe\xfcd\xa0\xb1,\xc35vt}\xe1\x082r\xf7\xc1\x10\xc3\xd8\xd7vf\xd8\xdd\x8d\xf1\xd2\x1d\x82.\xd6\x86%\xfb_\xef\xf5B \xa3\xeb\xd7Q\xe0\x9cW\\\xb2}\xf7\xe9\xdd\x1f2\x14\x80\\G\x94\xfb\xc8\xd7>\x9b\xbb\xdaKQ\xd3\x88~\xab0\xf7P\xb2!\x04]Hf\x94\xef\xe2\x07\xcec\x88R\x90\xc58\x18:\xaf~\xa4VU/\xd1j\xfbv\x7f\xfaRO\xfb\xccc\xf8\xc1\x88\x9f\xd3" |>
INFO 03:21:10 toytor.cellqueuer       decrypting incoming RelayCell
INFO 03:21:10 toytor.create           unencr: <CellRelayExtended2  CircID=69 Command=RELAY RelayCommand=RELAY_EXTENDED2 Recognized=0 StreamID=0 Digest=b'/\x1f,\x03' Length=66 Hlen=64 Hdata=b'\x89\x86\x05\xf2>%\x07R\x9b*\x11\xa7d\x0e/\x17\x17\xbb^\x8b\xc6\xdf}\xceJ\x18\xe7\xdf\x9f\x88\xdbe\x0cD\xee@\x181&\xdd\x019\x0bf\x13a\x8du7#\x01\x81Q\xfd\r\x80\xbe\x84\xc8F\x03\x16\xed\xc9' Padding=b'' |>
INFO 03:21:10 toytor.cellqueuer       putting plaintext relaycell on queue
INFO 03:21:10 toytor.cellqueuer       blocking on read_cell
INFO 03:21:10 toytor.client           extend_circuit exiting fine
INFO 03:21:15 toytor.client           sent resolve cell
INFO 03:21:15 toytor.cellqueuer       encrypting outgoing RelayCell
INFO 03:21:15 toytor.cellqueuer       <CellRelay  CircID=69 RelayCommand=RELAY_RESOLVE StreamID=1990 Data='google.com\x00' |>
INFO 03:21:15 toytor.cellqueuer       blocking on out_queue.get()
INFO 03:21:15 toytor.cellqueuer       got cell with good circid 69
INFO 03:21:15 toytor.cellqueuer       decrypting incoming RelayCell
INFO 03:21:15 toytor.create           unencr: <CellRelayResolved  CircID=69 Command=RELAY RelayCommand=RELAY_RESOLVED Recognized=0 StreamID=1990 Digest=b'\xd7\xef\xf9=' Length=32 Address=<OrAddressIPv4  Type=IPv4 Length=4 Address=216.58.213.46 |> TTL=60 Padding=b'\x06\x10*\x00\x14P@\x08\x08\x03\x00\x00\x00\x00\x00\x00 \x0e\x00\x00\x00<' |>
INFO 03:21:15 toytor.cellqueuer       putting plaintext relaycell on queue
INFO 03:21:15 toytor.cellqueuer       blocking on read_cell
INFO 03:21:21 toytor.control          ControlServer <Server sockets=None> stopped
[a bunch of Tasks getting canceled + exiting]
```
# STRUCTURE
(this is out-of-date, more things exist now)
main starts and holds a reference to a ControlServer.
A ControlServer spawns coroutine instances of ControlServerConnections.
A ControlServerConnection spawns coroutine instances of TorClients and TorServers.

A TorClient currently contains a _run coroutine, which connects (TLS), does the
tor connection handshake, creates a circuit with the first hop, then just
discards whatever else it receives. It can also have an extend_circuit
coroutine, but that currently steps on the toes of the _run one (see bottom of
README). It'll probably eventually have stream-related coroutines, bridging
(for example) a SOCKS connection and some RELAY_DATA cells.

A TorServer spawns instances of TorServerConnection. A TorServerConnection has
a _run couroutine, which does the connection- and circuit-level handshakes,
then discards whatever other cells it receives. Next, it should support opening
streams.

# THANKS
i'm using a vendored and slightly modified version of
https://github.com/cea-sec/TorPylle for the cell parsing

and i'm using the python implementation of ntor from tor's src/test/ntor_ref.py
and Matthew Dempsky's "Slownacl" curve25519 implementation.

# RUNNING / TESTING
I'm running this thing against a local network of real tor clients on my laptop
with Chutney (https://git.torproject.org/chutney.git).

```
virtualenv -p python3.5 .env
source .env/bin/activate
pip3 install -r requirements.txt
python3.5 certs.py
PYTHONPATH=$PWD py.test
python3.5 main.py
```
# TODO
Looking forward to cleaning up the code!
