from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="hexora",
    rust_extensions=[
        RustExtension(
            "hexora._hexora",
            binding=Binding.PyO3,
            debug=False,
            features=["python"],
        )
    ],
    packages=["hexora", ],
    zip_safe=False,
    package_dir={"hexora": "hexora"},
    package_data={"hexora": ["py.typed"]},
)
