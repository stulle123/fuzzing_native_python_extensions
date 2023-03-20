FROM aflplusplus/aflplusplus:dev

RUN apt-get update && \
    apt-get -y install libclang-rt-14-dev

RUN pip3 install atheris
