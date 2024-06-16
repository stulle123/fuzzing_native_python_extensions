#
# This Dockerfile builds Atheris and AFL++.
#
# Based on https://blog.trailofbits.com/2024/02/23/continuously-fuzzing-python-c-extensions/
#
# It uses Ubuntu 20.04 and LLVM 13. This is
# because we need to build an old vulnerable
# version of numpy (version 1.11.0).
#

FROM ubuntu:20.04

RUN apt update && DEBIAN_FRONTEND="noninteractive" TZ="Europe/Amsterdam" apt install -y \
    wget \
    unzip \
    git \
    xz-utils \
    build-essential \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    python3-setuptools \
    automake \
    cmake \
    flex \
    bison \
    libglib2.0-dev \
    libpixman-1-dev \
    cargo \
    libgtk-3-dev

RUN apt install -y \
    gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev \
    libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev \
    ninja-build

ENV APP_DIR "/app"
ENV CLANG_DIR "$APP_DIR/clang"
RUN mkdir $APP_DIR
RUN mkdir $CLANG_DIR
WORKDIR $APP_DIR

ENV VIRTUAL_ENV "/opt/venv"
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH "$VIRTUAL_ENV/bin:$CLANG_DIR/bin:$PATH"

# Download and install LLVM 13
ARG CLANG_URL=https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.0/clang+llvm-13.0.0-x86_64-linux-gnu-ubuntu-20.04.tar.xz
ARG CLANG_CHECKSUM=2c2fb857af97f41a5032e9ecadf7f78d3eff389a5cd3c9ec620d24f134ceb3c8
ENV CLANG_FILE clang.tar.xz
RUN wget -q -O $CLANG_FILE $CLANG_URL && \
    echo "$CLANG_CHECKSUM  $CLANG_FILE" | sha256sum -c - && \
    tar xf $CLANG_FILE -C $CLANG_DIR --strip-components 1 && \
    rm $CLANG_FILE

# Build AFL++
# https://github.com/AFLplusplus/AFLplusplus/blob/stable/Dockerfile
ENV CC "$CLANG_DIR/bin/clang"
ENV CXX "$CLANG_DIR/bin/clang++"
ENV NO_NYX=1
ENV NO_ARCH_OPT=1
ENV IS_DOCKER=1
ENV LLVM_CONFIG=llvm-config
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_TRY_AFFINITY=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
RUN python3 -m pip install --upgrade pip wheel
RUN git clone https://github.com/AFLplusplus/AFLplusplus
WORKDIR "$APP_DIR/AFLplusplus"
RUN make distrib && make install
WORKDIR $APP_DIR

# https://github.com/google/atheris#building-from-source
RUN LIBFUZZER_LIB=$($CLANG_DIR/bin/clang -print-file-name=libclang_rt.fuzzer_no_main-x86_64.a) \
    python3 -m pip install --no-binary atheris atheris

# Build vulnerable hello world extension
# https://github.com/google/atheris/blob/master/native_extension_fuzzing.md#step-1-compiling-your-extension
RUN git clone --branch main https://github.com/stulle123/fuzzing_native_python_extensions.git
RUN CFLAGS="-fsanitize=address,undefined,fuzzer-no-link" \
    CXXFLAGS="-fsanitize=address,undefined,fuzzer-no-link" \
    LDSHARED="$CLANG_DIR/bin/clang -shared" \
    python3 -m pip install fuzzing_native_python_extensions/ 

# Build numpy 1.11.0
RUN wget https://github.com/numpy/numpy/archive/refs/tags/v1.11.0.zip && unzip v1.11.0.zip
RUN ln -s /usr/include/x86_64-linux-gnu/bits/types/__locale_t.h /usr/include/xlocale.h
RUN python3 -m pip install Cython
RUN CFLAGS="-fsanitize=undefined -g" \
    CXXFLAGS="-fsanitize=undefined -g" \
    LDSHARED="$CLANG_DIR/bin/clang -shared" \
    python3 -m pip install --no-binary numpy numpy-1.11.0/

# Allow Atheris to find fuzzer sanitizer shared libs
# https://github.com/google/atheris/blob/master/native_extension_fuzzing.md#option-a-sanitizerlibfuzzer-preloads
# ENV LD_PRELOAD "$VIRTUAL_ENV/lib/python3.8/site-packages/asan_with_fuzzer.so"

# 1. Skip allocation failures and memory leaks for now, they are common, and low impact (DoS)
# 2. https://github.com/google/atheris/blob/master/native_extension_fuzzing.md#leak-detection
# 3. Provide the symbolizer to turn virtual addresses to file/line locations
# ENV ASAN_OPTIONS "allocator_may_return_null=1,detect_leaks=0,external_symbolizer_path=$CLANG_DIR/bin/llvm-symbolizer"

RUN echo "export PS1='"'[fuzz \h] \w \$ '"'" >> ~/.bashrc