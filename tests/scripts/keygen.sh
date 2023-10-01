#!/bin/bash

source ./tests/scripts/func.sh
reset
test $? -eq 0 || exit $?

gen_and_delete "rsa:1024" && echo -n "." || exit $?
gen_and_delete "rsa:2048" && echo -n "." || exit $?
gen_and_delete "ec:secp192r1" && echo -n "." || exit $?
gen_and_delete "ec:secp256r1" && echo -n "." || exit $?
gen_and_delete "ec:secp384r1" && echo -n "." || exit $?
gen_and_delete "ec:secp521r1" && echo -n "." || exit $?
gen_and_delete "ec:brainpoolP256r1" && echo -n "." || exit $?
gen_and_delete "ec:brainpoolP384r1" && echo -n "." || exit $?
gen_and_delete "ec:brainpoolP512r1" && echo -n "." || exit $?
gen_and_delete "ec:secp192k1" && echo -n "." || exit $?
gen_and_delete "ec:secp256k1" && echo -n "." || exit $?
