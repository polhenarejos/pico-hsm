FROM debian:bullseye

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && apt upgrade -y
RUN apt install -y apt-utils
RUN apt autoremove -y
RUN rm -rf /var/cache/apt/archives/*
RUN apt install -y libccid \
    libpcsclite-dev \
    git \
    autoconf \
    pkg-config \
    libtool \
    help2man \
    automake \
    gcc \
    make \
    build-essential \
    python3 \
    python3-pip \
    swig \
    libssl-dev \
    cmake \
    vsmartcard-vpcd \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install pytest pycvc cryptography base58
WORKDIR /
RUN git clone https://github.com/OpenSC/OpenSC
WORKDIR /OpenSC
RUN git checkout tags/0.26.1
RUN ./bootstrap
RUN ./configure --enable-openssl
RUN make -j `nproc`
RUN make install
RUN make clean
RUN ldconfig
WORKDIR /
RUN git clone https://github.com/CardContact/sc-hsm-embedded
WORKDIR /sc-hsm-embedded
RUN autoreconf -fi
RUN ./configure
RUN make -j `nproc`
RUN make install
RUN cp ./src/tests/sc-hsm-pkcs11-test /usr/local/bin/sc-hsm-pkcs11-test
RUN make clean
WORKDIR /
