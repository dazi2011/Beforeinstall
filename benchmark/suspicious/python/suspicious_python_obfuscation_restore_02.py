#!/usr/bin/env python3
import base64
import marshal
import zlib

harmless = "synthetic harmless restored message"
packed = marshal.dumps({"msg": harmless})
compressed = zlib.compress(packed)
encoded = base64.b64encode(compressed)

restored = marshal.loads(zlib.decompress(base64.b64decode(encoded)))
print("[suspicious] restored content:", restored["msg"])
print("[dry-run] obfuscation primitives used for fixture only; no payload execution")
