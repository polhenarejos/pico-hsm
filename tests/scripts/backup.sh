#!/bin/bash

source ./tests/scripts/func.sh
reset
test $? -eq 0 || exit $?

sc_backup() {
    for i in $(seq 1 $1); do
        sc-hsm-tool --create-dkek-share dkek.${i}.pbe --password testpw > /dev/null 2>&1
        test $? -eq 0 && echo -n "." || exit $?
    done
    sc-hsm-tool --initialize --so-pin 3537363231383830 --pin 648219 --dkek-shares $1 > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
    pkcs11-tool -l --pin 648219 -I > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
    for i in $(seq 1 $1); do
        e=$(sc-hsm-tool --import-dkek-share dkek.${i}.pbe --password testpw 2>&1)
        test $? -eq 0 && echo -n "." || exit $?
        grep -q "DKEK share imported" <<< $e && echo -n "." || exit $?
        grep -q "DKEK shares[[:blank:]]*: $1" <<< $e && echo -n "." || exit $?
        if [[ $i -lt $1 ]]; then
            grep -q "DKEK import pending, $(( $1 - $i ))" <<< $e && echo -n "." || exit $?
        fi
    done
    # Store DKEK, since it is not logged in
    pkcs11-tool -l --pin 648219 -I > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
}
echo -n "  Test single DKEK..."
sc_backup 1
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

echo -n "  Test multiple DKEK..."
sc_backup 3
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

rm -rf dkek.*.pbe

echo "  Test backup and restore"
algs=("rsa:1024" "rsa:2048" "ec:secp192r1" "ec:secp256r1" "ec:secp384r1" "ec:secp521r1" "ec:brainpoolP256r1" "ec:brainpoolP384r1" "ec:brainpoolP512r1" "ec:secp192k1" "ec:secp256k1")
for alg in ${algs[*]}; do
    echo -n "    Keygen ${alg}..."
    gen_and_check ${alg}
    test $? -eq 0 && echo -e ".\t${OK}" || exit $?
    echo -n "    Wrap key..."
    sc-hsm-tool --wrap-key wrap-key.bin --key-reference 1 --pin 648219 > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
    e=$(pkcs15-tool -D 2>&1)
    grep -q "Key ref[[:blank:]]*: 10" <<< $e && exit $? || echo -e ".\t${OK}"
    echo -n "    Unwrap key..."
    sc-hsm-tool --unwrap-key wrap-key.bin --key-reference 10 --pin 648219 --force > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
    e=$(pkcs15-tool -D 2>&1)
    grep -q "Key ref[[:blank:]]*: 10" <<< $e && echo -e ".\t${OK}" || exit $?
    echo -n "    Cleaning..."
    pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1 > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
    pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1 > /dev/null 2>&1
    test $? -eq 0 && echo -e ".\t${OK}" || exit $?
done
