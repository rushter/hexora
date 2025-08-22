import sys
import importlib

# sys.modules based shell execution
sys.modules["os"].system("echo hi")
sys.modules["subprocess"].Popen(["echo", "hi"])  # nosec

# importlib.import_module based shell execution
importlib.import_module("subprocess").check_output(["echo", "hi"])  # nosec
importlib.import_module("commands").getstatusoutput("echo hi")
