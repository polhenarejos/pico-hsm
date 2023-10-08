#!/bin/bash

source ./tests/scripts/func.sh
reset
test $? -eq 0 || exit $?

algs=("rsa:1024" "rsa:2048" "ec:secp192r1" "ec:secp256r1" "ec:secp384r1" "ec:secp521r1" "ec:brainpoolP256r1" "ec:brainpoolP384r1" "ec:brainpoolP512r1" "ec:secp192k1" "ec:secp256k1")
for alg in ${algs[*]}; do
    IFS=: read -r a s <<< "${alg}"
    au=$(awk '{print toupper($0)}' <<<${a})
    echo -n "  Test ${au} ${s}..."
    gen_and_delete ${alg} && echo -e ".\t${OK}" || exit $?
done
