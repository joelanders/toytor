here's a work-in-progress toy tor implementation written with the new python
asyncio module and the new async/await coroutine keywords.

# STRUCTURE
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

# OUTPUT
example session of what I type into the control server:
```
l@tp ~ $ nc localhost 9090
howdy      # server says hello
consensus  # fetch consensus
client 69 770AE32FA54C49A984C2AF158F1DB65BA30C98A3  # create circuit
extend 69 4EF24703077A84BDE437E1381F878E0DA63E9AED  # extend circuit
```

example of the log messages from the main process:
```
l@tp ~/code/toytor $ python3.5 main.py
WARNING: Failed to execute tcpdump. Check it is installed and in the PATH
INFO 13:50:43 control                 ControlServer started on port 9090
INFO 13:50:43 __main__                entering main
INFO 13:50:46 consensus               found, loading from disk
INFO 13:50:46 control                 C910B4891BFE908A82C0C7CF139EE3ED91D31C72 127.0.0.1 5005
INFO 13:50:46 control                 770AE32FA54C49A984C2AF158F1DB65BA30C98A3 127.0.0.1 5002
INFO 13:50:46 control                 9DE50209703CDC28D39992C8917D59B62294D8C8 127.0.0.1 5003
INFO 13:50:46 control                 9BBEFB3073A045C90A4F5BB77F995CDD7D30BCEE 127.0.0.1 5009
INFO 13:50:46 control                 4EF24703077A84BDE437E1381F878E0DA63E9AED 127.0.0.1 5006
INFO 13:50:50 consensus               downloading http://127.0.0.1:7000/tor/server/d/C82E284EF3B827FF2B714B09FF82DAD79930616A
INFO 13:50:50 client                  hi 69 '127.0.0.1'
INFO 13:50:50 client                  client connected
INFO 13:50:50 client                  client completed handshake
INFO 13:50:50 client                  client handshaked
INFO 13:50:50 client                  create_circuit exiting fine
INFO 13:50:50 client                  b')vB[\'\xd7\xf0\xc9\xb7\xb2\x8e\x9d\x01\x99\xa9\xcc\x14\x94@\xa0e}\xa8\xae\xee\xc4\xf2c\xff\xa28\xff\xc7\xf5I\xcaN\x11\xf4\x88\xdd\x1a4M\x10\x07\xf0\xed\x17\xf0\x16`\xc4\xbe\x87"\x8e^\x96\xa2<\x90\xa5C4#zl\xee\x05\xe5n'
INFO 13:50:50 client                  client circuit created
INFO 13:50:56 consensus               downloading http://127.0.0.1:7000/tor/server/d/3B5769AFF49980546D4AC84569D1B7B37324C1CB
ERROR 13:50:56 asyncio                 Task exception was never retrieved
future: <Task finished coro=<TorClient.extend_circuit() done, defined at /home/landers/python3-learn/asyncio-tor/toytor/client.py:52> exception=RuntimeError('read() called while another coroutine is already waiting for incoming data',)>
[traceback elided]
RuntimeError: read() called while another coroutine is already waiting for incoming data
[exiting messages elided]
```

# TODO
I was wondering if I'd eventually run into trouble passing around the TLS
connection reader/writer pair instead of having a single queue consume/emit
cells. I finally did: the client post-handshake main loop corouting blocks on
reading a cell from the TLS connection, then I start another couroutine to
send/receive a pair of RELAY_EXTEND{ED} cells on the same connection. Asyncio
conveniently complains that I can't have two coroutines waiting for the same
event (which one should get it?). So I'll need to add some kind of queue and
routing thing to make sure the extend_circuit coroutine gets the cells it wants
without interfering with other coroutines expecting cells on the same
connection.
