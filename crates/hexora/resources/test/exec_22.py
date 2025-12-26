import os

def RunCommand():
    os.system("curl http://4?" + str(os.getpid()))
    os.system(f"wget http://4?{os.getpid()}")
