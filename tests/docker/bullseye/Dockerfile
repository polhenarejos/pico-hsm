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
RUN pip3 install pytest pycvc cryptography pyscard base58
WORKDIR /
RUN git clone https://github.com/OpenSC/OpenSC
WORKDIR /OpenSC
RUN git checkout tags/0.23.0
RUN ./bootstrap
RUN ./configure --enable-openssl
RUN make -j `nproc`
RUN make install
RUN make clean
RUN ldconfig
RUN git clone https://github.com/polhenarejos/pypicohsm.git
RUN pip3 install -e pypicohsm
WORKDIR /
