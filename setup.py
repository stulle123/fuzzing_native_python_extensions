from distutils.core import setup, Extension

module = Extension("memory", sources=["fuzz_target.c"])

setup(
    name="memory",
    version="1.0",
    description='A simple "BOOM!" extension',
    ext_modules=[module],
)
