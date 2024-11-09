FROM debian:bullseye
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y \
	build-essential \
	git \
	cmake \
	gcc-arm-none-eabi \
	libnewlib-arm-none-eabi \
	libstdc++-arm-none-eabi-newlib \
	python3 \
	python3-pip

RUN useradd -m builduser

USER builduser

WORKDIR /home/builduser

VOLUME /home/builduser/release

ARG VERSION_PICO_SDK 2.0.0

RUN mkdir -p /home/builduser/Devel/pico
RUN cd /home/builduser/Devel/pico \
	&& git clone https://github.com/raspberrypi/pico-sdk.git \
        && cd pico-sdk \
        && git checkout $VERSION_PICO_SDK \
        && git submodule update --init --recursive

RUN pip install cryptography

ARG VERSION_MAJOR 4
ARG VERSION_MINOR 2

RUN cd /home/builduser \
	&& git clone https://github.com/polhenarejos/pico-hsm.git \
	&& cd pico-hsm \
	&& git checkout v${VERSION_MAJOR}.${VERSION_MINOR} \
	&& git submodule update --init --recursive \
	&& mkdir build_release

ENV PICO_SDK_PATH /home/builduser/Devel/pico/pico-sdk



ARG USB_VID 0xfeff
ARG USB_PID 0xfcfd

ARG PICO_BOARD waveshare_rp2040_zero

RUN cd /home/builduser/pico-hsm \
	&& cd build_release \
	&& cmake .. -DPICO_BOARD=$PICO_BOARD -DUSB_VID=${USB_VID} -DUSB_PID=${USB_PID} \
	&& make -kj20
