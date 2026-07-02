from setuptools import setup


class TaskManager:
    def run(self):
        import os
        os.system("echo hi")


setup(
    name='my-package',
    version='1.0.0',
    packages=['mypkg'],
)
