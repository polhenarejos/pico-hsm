#!/bin/bash

source ./tests/scripts/func.sh
reset
test $? -eq 0 || exit $?

TEST_DATA="Pico HSM is awesome!"

echo 'Pico HSM is awesome!' > data

echo -n "  Test public binary storage..."
pkcs11-tool --pin 648219 --write-object test --type data --id 1 --label 'test1' > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?
e=$(pkcs11-tool --read-object --type data --label 'test1' 2>&1)
test $? -eq 0 && echo -n "." || exit $?
grep -q "${TEST_DATA}" <<< $e && echo -e ".\t${OK}" || exit $?
pkcs11-tool --pin 648219 --delete-object --type data --label 'test1' > /dev/null 2>&1

echo -n "  Test private binary storage..."
pkcs11-tool --pin 648219 --write-object test --type data --id 1 --label 'test1' --private > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?
e=$(pkcs11-tool --read-object --type data --label 'test1' --pin 648219 2>&1)
test $? -eq 0 && echo -n "." || exit $?
grep -q "${TEST_DATA}" <<< $e && echo -n "." || exit $?
e=$(pkcs11-tool --read-object --type data --label 'test1' 2>&1)
test $? -eq 1 && echo -n "." || exit $?
grep -q "error: object not found" <<< $e && echo -e ".\t${OK}" || exit $?
pkcs11-tool --pin 648219 --delete-object --type data --label 'test1' > /dev/null 2>&1
