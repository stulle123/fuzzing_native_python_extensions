# Fuzzing Native Python Extensions

This is a write-up on how to fuzz Python native extensions (x86 and ARM) in white box and black box mode with Atheris, libFuzzer and AFL++.

* [Build Example Native Extension](#build-example-native-extension)
* [Run Atheris](#run-atheris)
* [Run libFuzzer](#run-libfuzzer)
* [Run AFL++](#run-afl)
  * [Get AFL++](#get-afl)
  * [White-box Mode](#white-box-mode)
  * [Black box/Binary-only Mode (LLVM fork-based, x86)](#black-boxbinary-only-mode-llvm-fork-based-x86)
  * [Binary-only Mode (Qemu Persistent Mode, x86)](#binary-only-mode-qemu-persistent-mode-x86)
* [Fuzz ARM32 Native Extensions with AFL++ in Binary-only Mode](#fuzz-arm32-native-extensions-in-binary-only-mode-llvm-fork-based)
  * [Setup Alpine ARM Chroot on your x86_64 Ubuntu Host](#setup-alpine-arm-chroot-on-your-x86_64-ubuntu-host)
  * [Build AFL++ Qemu Mode on Ubuntu 20.04 Host](#build-afl-qemu-mode-on-ubuntu-2004-host)
  * [Compile and Build the Fuzzing Project](#compile-and-build-the-fuzzing-project)
  * [Run AFL++](#run-afl-1)

## Build Example Native Extension

Build Native Extension with clang:
```
CC=$(which clang) CFLAGS="-fsanitize=fuzzer -g" LDSHARED="clang -shared" python3 -m pip install .
```

Manually trigger bug:
```
python3 -c "import memory; memory.corruption(b'FUZZ')"
```

## Run Atheris
Install dependencies on Ubuntu 20.04:
```
apt install -y clang-12
pip3 install atheris
```

Go to [atheris](./atheris/) and run Atheris:
```
LD_PRELOAD=$(python3 -c "import atheris; print(atheris.path())")/asan_with_fuzzer.so ASAN_OPTIONS=detect_leaks=0 \
    python3 atheris_fuzzer.py
```

## Run libFuzzer
Go to [libfuzzer](./libfuzzer/) and build the fuzzing harness:
```
clang++ $(python3-config --cflags --embed) -fsanitize=address,fuzzer -g -o fuzz fuzz_harness.c \
    $(python3-config --embed --ldflags)
```
Run it:
```
ASAN_OPTIONS=detect_leaks=0 ./fuzz
```

## Run AFL++

### Get AFL++
```
docker pull aflplusplus/aflplusplus:dev
docker run -ti -v <your-path-to/fuzzing_native_python_extensions>:/src aflplusplus/aflplusplus:dev
```

### White-box Mode
Build native extension:
```
CC=afl-clang-fast CXX=afl-clang-fast++ LD=afl-clang-fast LDSHARED="clang -shared" python3 -m pip install /src
```

Build fuzzing harness:
```
afl-clang-fast $(python3-config --embed --cflags) $(python3-config --embed --ldflags) -o /src/afl++/whitebox_fuzz /src/afl++/whitebox_fuzz.c
```

Run it:
```
afl-fuzz -i /src/afl++/in -o /src/afl++/out -- /src/afl++/whitebox_fuzz
```

You can also run the previous libFuzzer harness with AFL++:
```
# Build:
afl-clang-fast++ $(python3-config --cflags --embed) -fsanitize=address,fuzzer -g -o /src/libfuzzer/fuzz /src/libfuzzer/fuzz_harness.c $(python3-config --embed --ldflags)

# Run:
afl-fuzz -i /src/libfuzzer/in -o /src/libfuzzer/out -- /src/libfuzzer/fuzz
```

### Black-box/Binary-only Mode (LLVM fork-based, x86)
Now, we're fuzzing the native extension using AFL++'s [binary-only instrumentation with QEMU](https://github.com/AFLplusplus/AFLplusplus/tree/stable/qemu_mode).

Build native extension **without** instrumentation:
```
CC=$(which clang) CFLAGS="-g" LDSHARED="clang -shared" python3 -m pip install /src
```

Build fuzzing harness **without** instrumentation:
```
clang $(python3-config --embed --cflags) $(python3-config --embed --ldflags) -o /src/afl++/blackbox_fuzz /src/afl++/blackbox_fuzz.c
```

Make sure to start the forkserver *after* loading all the shared objects by setting the `AFL_ENTRYPOINT` environment variable (see [here](https://aflplus.plus/docs/env_variables/#5-settings-for-afl-qemu-trace) for details):

1) Choose an address just before the `while()` loop, for example:
```
$ objdump -d /src/afl++/blackbox_fuzz | grep -A 1 "PyObject_GetAttrString"
0000000000401080 <PyObject_GetAttrString@plt>:
  401080:       ff 25 ba 2f 00 00       jmpq   *0x2fba(%rip)        # 404040 <PyObject_GetAttrString>
  401086:       68 05 00 00 00          pushq  $0x5
--
  401226:       e8 55 fe ff ff          callq  401080 <PyObject_GetAttrString@plt>
  40122b:       48 89 44 24 18          mov    %rax,0x18(%rsp)
```

2) Run AFL++:
```
AFL_ENTRYPOINT=0x40122b afl-fuzz -i /src/afl++/in -o /src/afl++/out -Q -- /src/afl++/blackbox_fuzz
```

### Binary-only Mode (Qemu Persistent Mode, x86)
To improve performance we can use the [persistent mode in AFL++'s Qemu mode](https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.persistent.md).

Build the native extension and the fuzzing harness without instrumentation:
```
CC=$(which clang) CFLAGS="-g" LDSHARED="clang -shared" python3 -m pip install /src
clang $(python3-config --embed --cflags) $(python3-config --embed --ldflags) -o /src/afl++/blackbox_fuzz /src/afl++/blackbox_fuzz.c
```

Choose an address to start the persistent loop, for example the address of `main()`:
```
nm /src/afl++/blackbox_fuzz | grep main
00000000004011b0 T main
```

Run AFL++:
```
AFL_QEMU_PERSISTENT_ADDR=0x4011b0 AFL_QEMU_PERSISTENT_GPR=1 afl-fuzz -i /src/afl++/in -o /src/afl++/out -Q -- /src/afl++/blackbox_fuzz
```

## Fuzz ARM32 Native Extensions in Binary-only Mode (LLVM fork-based)

### Setup Alpine ARM Chroot on your x86_64 Ubuntu Host

1. Install `qemu-user-binfmt`, `qemu-user-static` and `systemd-container` dependencies.
2. Restart the systemd-binfmt service: `systemctl restart systemd-binfmt.service`
3. Download an Alpine ARM RootFS from https://alpinelinux.org/downloads/
4. Create a new `alpine_sysroot` folder and extract: `tar xfz alpine-minirootfs-3.17.1-armv7.tar.gz -C alpine_sysroot/`
5. Copy `qemu-arm-static` to Alpine's RootFS: `cp $(which qemu-arm-static) ./alpine_sysroot/usr/bin/`
6. Chroot into the container: `sudo systemd-nspawn -D alpine_sysroot/ --bind-ro=/etc/resolv.conf`
7. Install dependencies: `apk update && apk add build-base musl-dev clang15 python3 python3-dev py3-pip`
8. Exit the container with `exit`

### Build AFL++ Qemu Mode on Ubuntu 20.04 Host
```
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
sudo apt-get install -y lld-12 llvm-12 llvm-12-dev clang-12 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
sudo apt-get install -y ninja-build
git clone -b dev https://github.com/AFLplusplus && cd AFLplusplus
make all
cd qemu_mode && CPU_TARGET=arm ./build_qemu_support.sh
cd .. && sudo make install
```

### Compile and Build the Fuzzing Project
Build the native extension and the fuzzing harness for ARM using the Alpine container:
```
ALPINE_ROOT=<your-alpine-sysroot-directory>
FUZZING_GIT_ROOT=<your-path-to/fuzzing_native_python_extensions>
sudo systemd-nspawn -D $ALPINE_ROOT --bind=$FUZZING_GIT_ROOT:/fuzz
CC=$(which clang) CFLAGS="-g" LDSHARED="clang -shared" python3 -m pip install /fuzz
clang $(python3-config --embed --cflags) $(python3-config --embed --ldflags) -o /fuzz/afl++/blackbox_fuzz /fuzz/afl++/blackbox_fuzz.c
exit
```

Manually trigger bug:
```
echo -n "FUZZ" | qemu-arm-static -L $ALPINE_ROOT $FUZZING_GIT_ROOT/afl++/blackbox_fuzz
```

### Run AFL++
Make sure to start the forkserver *after* loading all the shared objects by setting the `AFL_ENTRYPOINT` environment variable (see [here](https://aflplus.plus/docs/env_variables/#5-settings-for-afl-qemu-trace) for details):

Choose an address just before the `while()` loop, for example:
```
qemu-arm-static -L $ALPINE_ROOT $ALPINE_ROOT/usr/bin/objdump -d $FUZZING_GIT_ROOT/afl++/blackbox_fuzz | grep -A 1 "PyObject_GetAttrString"

00000584 <PyObject_GetAttrString@plt>:
 584:	e28fc600 	add	ip, pc, #0, 12
--
 7c8:	ebffff6d 	bl	584 <PyObject_GetAttrString@plt>
 7cc:	e58d0008 	str	r0, [sp, #8]
...
```

Get Qemu's memory maps using the instructions taken from [here](https://aflplus.plus/docs/tutorials/libxml2_tutorial/):
>The binary is position independent and QEMU persistent needs the real addresses, not the offsets. Fortunately, QEMU loads PIE executables at a fixed address, 0x4000000000 for x86_64.
>
> We can check it using `AFL_QEMU_DEBUG_MAPS`. You don’t need this step if your binary is not PIE.
```
PYTHONPATH=$ALPINE_ROOT/usr/lib/python3.10/ PYTHONHOME=$ALPINE_ROOT/usr/bin/ QEMU_LD_PREFIX=$ALPINE_ROOT AFL_QEMU_DEBUG_MAPS=1 afl-qemu-trace $FUZZING_GIT_ROOT/afl++/blackbox_fuzz

...
40000000-40001000 r-xp 00000000 103:03 8002276                           /afl++/blackbox_fuzz
40001000-4001f000 ---p 00000000 00:00 0
4001f000-40020000 r--p 0000f000 103:03 8002276                           afl++/blackbox_fuzz
40020000-40021000 rw-p 00010000 103:03 8002276                           afl++/blackbox_fuzz
40021000-40022000 ---p 00000000 00:00 0
40022000-40023000 rw-p 00000000 00:00 0
```

Set Qemu environment variables:
```
export QEMU_SET_ENV=PYTHONPATH=$ALPINE_ROOT/usr/lib/python310.zip:$ALPINE_ROOT/usr/lib/python3.10:$ALPINE_ROOT/usr/lib/python3.10/lib-dynload:$ALPINE_ROOT/usr/lib/python3.10/site-packages,PYTHONHOME=$ALPINE_ROOT/usr/bin/
export QEMU_LD_PREFIX=$ALPINE_ROOT
```

Run AFL++:
```
AFL_ENTRYPOINT=0x400007cc afl-fuzz -i in -o out -Q -- $FUZZING_GIT_ROOT/afl++/blackbox_fuzz
```
