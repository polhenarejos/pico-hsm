#!/bin/bash

source ./tests/scripts/func.sh
reset
test $? -eq 0 || exit $?

TEST_DATA="This is a text."

echo "${TEST_DATA}" > test

sc_tool() {
    pkcs11-tool --module /usr/local/lib/libsc-hsm-pkcs11.so -l --pin 648219 $@
}

aeses=("16" "24" "32")

for aes in ${aeses[*]}; do
    echo "  Test AES (AES:${aes})"
    echo -n "    Keygen... "
    sc_tool --keygen --key-type "AES:${aes}" --id 1 --label "AES:${aes}" > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
    e=$(sc_tool --list-object --type secrkey 2>&1)
    test $? -eq 0 && echo -n "." || exit $?
    grep -q "AES length ${aes}" <<< $e && echo -n "." || exit $?
    grep -q "AES:${aes}" <<< $e && echo -e ".\t${OK}" || exit $?

    echo -n "    Encryption..."
    sc_tool --encrypt --id 1 --input-file test --mechanism aes-cbc > crypted.aes 2>/dev/null
    test $? -eq 0 && echo -e ".\t${OK}" || exit $?

    echo -n "    Decryption..."
    e=$(sc_tool --decrypt --id 1 --input-file crypted.aes --mechanism aes-cbc 2>/dev/null)
    test $? -eq 0 && echo -n "." || exit $?
    grep -q "${TEST_DATA}" <<< $e && echo -e ".\t${OK}" || exit $?

    sc_tool --delete --type secrkey --id 1 > /dev/null 2>&1
done
rm -rf test crypted.aes
