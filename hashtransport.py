class HashWriter:
    def __init__(self, writer, name):
        self._writer = writer
        self._name = name

    def write(self, content):
        #print("%s writing %s" % (self._name, content))
        return self._writer.write(content)

    def drain(self):
        return self._writer.drain()

class HashReader:
    def __init__(self, reader, name):
        self._reader = reader
        self._name = name

    async def read(self, maxbytes):
        content = await self._reader.read(maxbytes)
        #print("%s read %s" % (self._name, content))
        return content
