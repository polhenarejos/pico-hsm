#!/bin/bash

source ./tests/startup.sh

echo "==== Test SC HSM ===="
echo -n "  Running sc-hsm-pkcs11-test..."
pkcs11-tool -l --pin 648219 --keypairgen --key-type ec:secp256r1 --id 1 --label "TestLabel" > /dev/null 2>&1
test $? -eq 0 && echo -n "." ||  {
    echo -e "\t${FAIL}"
    exit 1
}
e=$(/usr/local/bin/sc-hsm-pkcs11-test --module /usr/local/lib/libsc-hsm-pkcs11.so --pin 648219 --invasive 2>&1)
test $? -eq 0 && echo -n "." || {
    echo -e "\t${FAIL}"
    exit 1
}
grep -q "338 tests performed" <<< $e && echo -n "." || {
    echo -e "\t${FAIL}"
    exit 1
}
grep -q "0 tests failed" <<< $e && echo -e ".\t${OK}" || {
    echo -e "\t${FAIL}"
    exit 1
}