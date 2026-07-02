from setuptools import setup
from setuptools.command.install import install


class PostInstallCommand(install):
    def run(self):
        exec("print('hello')")
        install.run(self)


setup(cmdclass={'install': PostInstallCommand})
