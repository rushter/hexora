import sys

sys.modules["builtins"].exec("print(3)")
getattr(sys.modules["builtins"], 'eval')("1+1")
