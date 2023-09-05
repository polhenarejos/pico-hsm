#!/bin/bash -eu

rm -rf pypicohsm
git clone https://github.com/polhenarejos/pypicohsm.git
pip3 install -e pypicohsm
/usr/sbin/pcscd &
sleep 2
rm -f memory.flash
tar -xf tests/memory.tar.gz
./build_in_docker/pico_hsm > /dev/null &
#pytest tests -W ignore::DeprecationWarning

chmod a+x tests/scripts/*.sh

echo -n "Test initialization... "
./tests/scripts/initialize.sh
echo "\tok"

