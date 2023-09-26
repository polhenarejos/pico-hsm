#!/bin/bash

./tests/scripts/reset.sh > /dev/null 2>&1
test $? -eq 0 || exit $?

gen_and_check() {
    e=$(pkcs11-tool -l --pin 648219 --keypairgen --key-type $1 --id 1 --label "TestLabel" 2>&1)
    test $? -eq 0 || exit $?
    grep -q "$2" <<< $e || exit $?
    pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1 > /dev/null 2>&1
}

gen_and_check "rsa:1024" "RSA 1024 bits" && echo -n "." || exit $?
gen_and_check "rsa:2048" "RSA 2048 bits" && echo -n "." || exit $?
gen_and_check "ec:secp192r1" "EC_POINT 192 bits" && echo -n "." || exit $?
gen_and_check "ec:secp256r1" "EC_POINT 256 bits" && echo -n "." || exit $?
gen_and_check "ec:secp384r1" "EC_POINT 384 bits" && echo -n "." || exit $?
gen_and_check "ec:secp521r1" "EC_POINT 528 bits" && echo -n "." || exit $?
gen_and_check "ec:brainpoolP256r1" "EC_POINT 256 bits" && echo -n "." || exit $?
gen_and_check "ec:brainpoolP384r1" "EC_POINT 384 bits" && echo -n "." || exit $?
gen_and_check "ec:brainpoolP512r1" "EC_POINT 512 bits" && echo -n "." || exit $?
gen_and_check "ec:secp192k1" "EC_POINT 192 bits" && echo -n "." || exit $?
gen_and_check "ec:secp256k1" "EC_POINT 256 bits" && echo -n "." || exit $?
