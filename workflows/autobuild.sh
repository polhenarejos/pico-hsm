#!/bin/bash

git submodule update --init --recursive
sudo apt update
sudo apt install -y cmake gcc-arm-none-eabi libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib
git clone https://github.com/raspberrypi/pico-sdk
cd pico-sdk
git submodule update --init
cd ..
mkdir build
cd build
if [[ $1 == "pico" ]]; then
cmake -DPICO_SDK_PATH=../pico-sdk ..
else
cmake -DENABLE_EMULATION=1 ..
fi
make
