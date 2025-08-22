import importlib

importlib.import_module("builtins").exec("print(4)")
getattr(importlib.import_module("builtins"), "eval")("1+1")
