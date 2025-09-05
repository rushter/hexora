import importlib
import sys
s = "getstatusoutput"
getattr(importlib.import_module("commands"), "getstatusoutput")("echo hi")
getattr(sys.modules["commands"], s)("echo hi")
