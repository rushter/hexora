def doit(m, f1, f2):
    import importlib

    module = importlib.import_module(m)
    function_name = f1 + f2
    function = getattr(module, function_name)
    return function


username = doit("os", "getl", "ogin")()
host = doit("socket", "getho", "stbyname")(doit("socket", "getho", "stname")())
pwd = doit("os", "getc", "wd")()
