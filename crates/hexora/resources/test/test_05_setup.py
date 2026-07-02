from setuptools import setup
from setuptools.command.install import install


class CustomInstall(install):
    def run(self):
        print("installing...")
        super().run()


setup(cmdclass={'install': CustomInstall})
