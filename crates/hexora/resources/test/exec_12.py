import zlib
def run(payload):
    exec(zlib.decompress(payload))
