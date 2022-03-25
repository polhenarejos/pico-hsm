#!/bin/bash

VERSION_MAJOR="1"
VERSION_MINOR="6"

rm -rf release/*
cd build

for board in adafruit_feather_rp2040 adafruit_itsybitsy_rp2040 adafruit_qtpy_rp2040 adafruit_trinkey_qt2040 arduino_nano_rp2040_connect melopero_shake_rp2040 pimoroni_interstate75 pimoroni_keybow2040 pimoroni_pga2040 pimoroni_picolipo_4mb pimoroni_picolipo_16mb pimoroni_picosystem pimoroni_plasma2040 pimoroni_tiny2040 pybstick26_rp2040 sparkfun_micromod sparkfun_promicro sparkfun_thingplus vgaboard waveshare_rp2040_lcd_0.96 waveshare_rp2040_plus_4mb waveshare_rp2040_plus_16mb waveshare_rp2040_zero
do
    rm -rf *
    PICO_SDK_PATH=~/Devel/pico/pico-sdk cmake .. -DPICO_BOARD=$board 
    make -kj20
    mv pico_hsm.uf2 ../release/pico_hsm_$board-$VERSION_MAJOR.$VERSION_MINOR.uf2
    
done

rm -rf *
PICO_SDK_PATH=~/Devel/pico/pico-sdk cmake ..
make -kj20
mv pico_hsm.uf2 ../release/pico_hsm-$VERSION_MAJOR.$VERSION_MINOR.uf2