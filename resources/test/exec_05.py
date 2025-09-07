import importlib
import sys
s = "getstat"
s+= "usoutput"
getattr(importlib.import_module("commands"), "getstatusoutput")("echo hi")
getattr(sys.modules["commands"], s)("echo hi")
