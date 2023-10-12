#!/bin/bash

source ./tests/scripts/func.sh
reset
test $? -eq 0 || exit $?

echo -n "  Test PKCS11 tool..."
gen_and_check rsa:2048
test $? -eq 0 && echo -n "." || exit $?
e=$(pkcs11-tool --test -l --pin 648219 2>&1)
test $? -eq 0 && echo -n "." || exit $?
grep -q "No errors" <<< $e && echo -n "." || exit $?
pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1 > /dev/null 2>&1
test $? -eq 0 && echo -e ".\t${OK}" || exit $?
#e=$(pkcs11-tool --test-ec -l --pin 648219 --id 1 --key-type ec:secp256r1 2>&1)
#test $? -eq 0 && echo -n "." || exit $?
#grep -q "==> OK" <<< $e && echo -e ".\t${OK}" || exit $?
