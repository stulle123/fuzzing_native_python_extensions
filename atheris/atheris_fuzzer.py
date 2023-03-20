"""
Run:
$ LD_PRELOAD=$(python3 -c "import atheris; print(atheris.path())")/asan_with_fuzzer.so ASAN_OPTIONS=detect_leaks=0 \
    python3 atheris_fuzzer.py
"""

import atheris
import sys

with atheris.instrument_imports():
    import memory


@atheris.instrument_func
def TestOneInput(data):
    memory.corruption(data)


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
