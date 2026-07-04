FROM ubuntu:18.04

ARG BASE_DIR=/root/compose

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get -y update
RUN ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime
RUN apt-get -y install tzdata
RUN apt-get -y install build-essential curl libcap-dev git cmake libncurses5-dev \
    python3-minimal unzip libtcmalloc-minimal4 libgoogle-perftools-dev \
    libsqlite3-dev doxygen gcc-multilib g++-multilib wget \
    checkinstall libreadline-gplv2-dev libssl-dev tk-dev libgdbm-dev libc6-dev \
    libbz2-dev libffi-dev zlib1g-dev \
    bison flex libboost-all-dev python perl minisat


WORKDIR /root
RUN wget https://www.python.org/ftp/python/3.8.10/Python-3.8.10.tgz
RUN tar xzf Python-3.8.10.tgz
WORKDIR /root/Python-3.8.10
RUN ./configure --enable-optimizations
RUN make install
RUN apt-get -y install python3-pip
RUN pip3 install --upgrade pip
RUN pip3 install tabulate numpy wllvm scikit-learn matplotlib sortedcontainers

RUN apt-get -y install clang-6.0 llvm-6.0 llvm-6.0-dev llvm-6.0-tools
RUN ln -s /usr/bin/clang-6.0 /usr/bin/clang
RUN ln -s /usr/bin/clang++-6.0 /usr/bin/clang++
RUN ln -s /usr/bin/llvm-config-6.0 /usr/bin/llvm-config
RUN ln -s /usr/bin/llvm-link-6.0 /usr/bin/llvm-link

WORKDIR ${BASE_DIR}
RUN git clone https://github.com/stp/stp.git
WORKDIR ${BASE_DIR}/stp
RUN git checkout tags/2.3.3
RUN mkdir build
WORKDIR ${BASE_DIR}/stp/build
RUN cmake ..
RUN make -j
RUN make install
RUN echo "ulimit -s unlimited" >> /root/.bashrc

WORKDIR ${BASE_DIR}
RUN git clone https://github.com/klee/klee-uclibc.git
WORKDIR ${BASE_DIR}/klee-uclibc
RUN ./configure --make-llvm-lib
RUN make -j

RUN echo "export LLVM_COMPILER=clang" >> /root/.bashrc
RUN echo "KLEE_REPLAY_TIMEOUT=1" >> /root/.bashrc

ARG KLEE_FLAGS="-DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_SOLVER_STP=ON -DENABLE_SOLVER_Z3=OFF -DENABLE_POSIX_RUNTIME=ON -DENABLE_KLEE_UCLIBC=ON -DKLEE_UCLIBC_PATH=/root/compose/klee-uclibc -DENABLE_UNIT_TESTS=OFF -DENABLE_SYSTEM_TESTS=OFF -DENABLE_DOCS=OFF -DENABLE_DOXYGEN=OFF -DENABLE_TCMALLOC=ON -DENABLE_ZLIB=ON -DLLVM_CONFIG_BINARY=/usr/bin/llvm-config -DLLVMCC=/usr/bin/clang"

COPY CompoSE_FeatMaker/klee ${BASE_DIR}/CompoSE_FeatMaker/klee
WORKDIR ${BASE_DIR}/CompoSE_FeatMaker/klee
RUN mkdir -p build
WORKDIR ${BASE_DIR}/CompoSE_FeatMaker/klee/build
RUN cmake ${KLEE_FLAGS} ..
RUN make -j

WORKDIR ${BASE_DIR}/CompoSE_FeatMaker/klee
RUN env -i /bin/bash -c '(source testing-env.sh; env > test.env)'


COPY CompoSE_Aaqc/src ${BASE_DIR}/CompoSE_Aaqc/src
RUN mkdir -p ${BASE_DIR}/CompoSE_Aaqc/src/valina-build
WORKDIR ${BASE_DIR}/CompoSE_Aaqc/src/valina-build
RUN cmake ${KLEE_FLAGS} ${BASE_DIR}/CompoSE_Aaqc/src/klee-vanilla
RUN make -j

RUN mkdir -p ${BASE_DIR}/CompoSE_Aaqc/src/qc-build
WORKDIR ${BASE_DIR}/CompoSE_Aaqc/src/qc-build
RUN cmake ${KLEE_FLAGS} ${BASE_DIR}/CompoSE_Aaqc/src/klee-qc
RUN make -j

ADD ./ ${BASE_DIR}

WORKDIR ${BASE_DIR}/sniffles
RUN python3 setup.py install
WORKDIR ${BASE_DIR}/CompoSE_SymTuner
RUN python3 setup.py develop

WORKDIR ${BASE_DIR}/benchmarks
RUN chmod +x build.sh
RUN FORCE_UNSAFE_CONFIGURE=1 ./build.sh all

WORKDIR ${BASE_DIR}