#!/bin/bash

source ./tests/scripts/func.sh
reset
test $? -eq 0 || exit $?

echo -n "  Test PKCS11 tool..."
gen_and_check rsa:2048
test $? -eq 0 && echo -n "." || exit $?
pkcs11-tool --test -l --pin 648219 > /dev/null 2>&1
test $? -eq 0 && echo -e ".\t${OK}" || exit $?
