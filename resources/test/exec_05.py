import importlib
import sys

getattr(importlib.import_module("commands"), "getstatusoutput")("echo hi")
getattr(sys.modules["commands"], "getstatusoutput")("echo hi")
