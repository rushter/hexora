import builtins

# Should NOT be treated as obfuscated (Rule::CodeExec, Medium confidence)
exec(compile("print(1)", "test.py", "exec"))
eval(compile("1+1", "test.py", "eval"))

# Should NOT be treated as obfuscated
exec("print(1)", globals())
exec("print(1)", globals(), locals())
exec("print(1)", vars())

# Should NOT be treated as obfuscated
builtins.exec("print(1)", globals())

# These should STILL be treated as obfuscated (Rule::ObfuscatedCodeExec, VeryHigh confidence)
# because of taint or other reasons
import base64

exec(base64.b64decode("cHJpbnQoMSk="))

# exec as an attribute or similar
getattr(builtins, "exec")("print(1)")
