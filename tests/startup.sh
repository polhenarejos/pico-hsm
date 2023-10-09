#!/bin/bash

OK="\t\033[32mok\033[0m"
FAIL="\t\033[31mfail\033[0m"

fail() {
    echo -e "${FAIL}"
    exit 1
}

echo -n "Start PCSC..."
/usr/sbin/pcscd &
test $? -eq 0 && echo -e "${OK}" || {
    echo -e "${FAIL}"
    exit 1
}
sleep 2
rm -f memory.flash
tar -xf tests/memory.tar.gz
echo -n "Start Pico HSM..."
/pico_hsm > /dev/null 2>&1 &
test $? -eq 0 && echo -n "." || fail
sleep 2
ATR="3b:fe:18:00:00:81:31:fe:45:80:31:81:54:48:53:4d:31:73:80:21:40:81:07:fa"
e=$(opensc-tool -an 2>&1)
grep -q "${ATR}" <<< $e && echo -n "." || fail
test $? -eq 0 && echo -e "${OK}" || fail
