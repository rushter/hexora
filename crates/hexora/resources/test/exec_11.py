import marshal
import codecs

exec(marshal.loads(b"data"))
exec(codecs.decode(b"data", "hex"))
