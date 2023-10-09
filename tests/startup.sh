#!/bin/bash

OK="\033[32mok\033[0m"
FAIL="\033[31mfail\033[0m"

echo -n "Start PCSC... "
/usr/sbin/pcscd &
test $? -eq 0 && echo -e "${OK}" || {
    echo -e "${FAIL}"
    exit 1
}
sleep 2
rm -f memory.flash
tar -xf tests/memory.tar.gz
echo -n "Start Pico HSM... "
./build_in_docker/pico_hsm > /dev/null 2>&1 &
test $? -eq 0 && echo -e "${OK}" || {
    echo -e "${FAIL}"
    exit 1
}
