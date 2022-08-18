#!/bin/bash

sudo apt update
sudo apt install -y cmake gcc-arm-none-eabi libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib
git clone https://github.com/raspberrypi/pico-sdk
mkdir build
cd build
cmake -DPICO_SDK_PATH=../pico-sdk ..
make 
