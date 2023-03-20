# Fuzzing 101 Course

This is a short introduction into fuzzing Python native extensions.

* [Required Setup](#required-setup)
  * [Install Fuzzing Tools](#install-fuzzing-tools)
  * [Install Alpine CHROOT](#install-alpine-chroot)
* [Course Notes](#course-notes)
* [Numpy example](#numpy-example)

## Required Setup

First of all, you'll need Linux and a working Docker installation.

### Install Fuzzing Tools

0) Clone this repository: `git clone https://github.com/stulle123/fuzzing_native_python_extensions` and `cd` into it
1) Set env variable: `export FUZZING_GIT_ROOT=<your-path-to/fuzzing_native_python_extensions>`
2) Build the container from the Dockerfile: `docker build -t fuzzing-tools:latest .`
3) Test it: `docker run -it --rm -v $FUZZING_GIT_ROOT:/src --name fuzz fuzzing-tools:latest bash`

### Install Alpine CHROOT

This is used for cross compiling ARM32 fuzzing targets. Please follow these steps:

0) Install dependencies on Ubuntu: `sudo apt-get update && sudo apt install -y qemu-user-static systemd-container`
1) Download and extract: `wget https://dl-cdn.alpinelinux.org/alpine/v3.17/releases/armv7/alpine-minirootfs-3.17.1-armv7.tar.gz && mkdir alpine_sysroot && tar xfz alpine-minirootfs-3.17.1-armv7.tar.gz -C alpine_sysroot/`
2) Set env variable: `ALPINE_ROOT=<path-to-your-alpine-sysroot-directory>`
3) Copy `qemu-arm-static` to Alpine's RootFS: `cp $(which qemu-arm-static) $ALPINE_ROOT/usr/bin/`
4) Update container: `sudo systemd-nspawn -D $ALPINE_ROOT --bind-ro=/etc/resolv.conf sh -c "apk update && apk add build-base musl-dev clang15 python3 python3-dev py3-pip"`

## Course Notes

- Goals of this course
- x86 and ARM labs
- Tooling: Fuzzing tools, cross-compilation container
- Morning course
  * Fuzzing basics (type of fuzzers, etc.)
  * Bug hunting in Python
  * White box fuzzing
  * Black box fuzzing
  * numpy example
- Afternoon course
  * Binary rewriters
  * Emulation
  * Black box fuzzing with AFL++
- Bug hunting in Python code
  * Decompile Python bytecode with `uncompyle6`, `decompyle3`, or `pycdc`
  * Search for logic flaws
  * Search for command OS injection flaws, e.g.:
```bash
grep -riE "os.system|os.popen|commands.getstatusoutput|commands.getoutput|commands.getstatus|subprocess.call|subprocess.Popen|pty.spawn|execfile|exec|eval"
```
  * Search for Pickle remote code execution flaws
  * Use Atheris to fuzz Python code in order to find obscure/weird or uncaught exceptions
- Bug hunting in Python Native Extensions
  * Just [decompile](https://dogbolt.org/) and look for `PyArg_ParseTuple` symbols to identify exported methods
  * You can also import the native extension in Python and run `dir(<native_extension>)` to list its methods
  * Use `grep` for finding out where shared libraries are being imported
  * Use Atheris or AFL++ to find memory corruption bugs
  * Also check if Python objects are being handled in an inproper way, e.g. see [Python documentation](https://docs.python.org/3/c-api/memory.html):
> To avoid memory corruption, extension writers should never try to operate on Python objects with the functions exported by the C library: malloc(), calloc(), realloc() and free().
- Possible fuzzing lab tasks:
  * Find input validation flaws
  * Find memory corruption bugs in native libraries (those that receive attacker-controlled inputs)

## Numpy example

This example was taken from [here](https://medium.com/hackernoon/python-sandbox-escape-via-a-memory-corruption-bug-19dde4d5fea5).

See [vulnerable code snippet](numpy_shape_bug.c) for the integer overflow bug.

Install numpy `v1.11.0`:

```bash
$ apt install python3-dev
$ ln -s /usr/include/x86_64-linux-gnu/bits/types/__locale_t.h /usr/include/xlocale.h
$ python3 -m venv venv
$ source ./venv/bin/activate
(venv)$ pip install wheel Cython atheris
(venv)$ wget https://github.com/numpy/numpy/archive/refs/tags/v1.11.0.zip && unzip v1.11.0.zip && cd numpy-1.11.0
(venv)$ CC=$(which clang) CFLAGS="-fsanitize=undefined -g" LDSHARED="clang -shared" python3 -m pip install .
```

Trigger bug manually:
```bash
(venv)$ LD_PRELOAD=$(clang -print-file-name=libclang_rt.ubsan_standalone-x86_64.so) python <your-path-to>/fuzzing_native_python_extensions/course/trigger_bug_in_numpy_1.11.0.py
```

Run fuzzer:
```bash
(venv)$ LD_PRELOAD=$(python3 -c "import atheris; print(atheris.path())")/asan_with_fuzzer.so ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1 python numpy_fuzz.py
```
