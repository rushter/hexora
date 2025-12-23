import os

# Case 1: shell exec with __import__
os.system(__import__('base64').b64decode('bHM='))

# Case 2: code exec with __import__
exec(__import__('base64').b64decode('cHJpbnQoMTIzKQ=='))

# Case 3: code exec with compile()
exec(compile('print(123)', '<string>', 'exec'))

# Case 4: eval with compile()
eval(compile('1 + 1', '<string>', 'eval'))
