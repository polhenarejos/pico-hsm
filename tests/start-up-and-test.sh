#!/bin/bash

rm -rf pypicohsm
git clone https://github.com/polhenarejos/pypicohsm.git
pip3 install -e pypicohsm
/usr/sbin/pcscd &
sleep 2
rm -f memory.flash
tar -xf tests/memory.tar.gz
./build_in_docker/pico_hsm > /dev/null 2>&1 &
#pytest tests -W ignore::DeprecationWarning

chmod a+x tests/scripts/*.sh

echo "======== PKCS11 Test suite ========"
./tests/scripts/pkcs11.sh
