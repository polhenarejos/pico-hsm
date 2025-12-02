#!/bin/bash

source ./tests/scripts/func.sh
reset
test $? -eq 0 || exit $?

rsa_encrypt_decrypt() {
    openssl pkeyutl -encrypt -pubin -inkey 1.pub $2 -in $1 -out data.crypt
    test $? -eq 0 && echo -n "." || exit $?
    TDATA=$(pkcs11-tool --id 1 --pin 648219 --decrypt $3 -i data.crypt 2>/dev/null | sed '/^OAEP parameters:/d' | tr -d '\0')
    test $? -eq 0 && echo -n "." || exit $?
    if [[ "$TEST_STRING" != "$TDATA" ]]; then
        exit 1
    fi
    test $? -eq 0 && echo -n "." || exit $?
}

TEST_STRING="This is a test string. Be safe, be secure."

echo ${TEST_STRING} > data

echo -n "  Keygen RSA 2048..."
keygen_and_export rsa:2048
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

echo -n "  Test RSA-PKCS ciphering..."
rsa_encrypt_decrypt data "-pkeyopt rsa_padding_mode:pkcs1" "--mechanism RSA-PKCS"
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

echo -n "  Test RSA-X-509 ciphering..."
cp data data_pad
tlen=${#TEST_STRING}
dd if=/dev/zero bs=1 count=$((256-$tlen-1)) >> data_pad 2> /dev/null
test $? -eq 0 && echo -n "." || exit $?
rsa_encrypt_decrypt data_pad "-pkeyopt rsa_padding_mode:none" "--mechanism RSA-X-509"
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

echo -n "  Test RSA-PKCS-OAEP ciphering..."
rsa_encrypt_decrypt data "-pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256" "--mechanism RSA-PKCS-OAEP --hash-algorithm SHA256 --mgf MGF1-SHA256"
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

rm -rf data* 1.*
pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1 > /dev/null 2>&1

algs=("secp192r1" "secp256r1" "secp384r1" "secp521r1" "brainpoolP256r1" "brainpoolP384r1" "brainpoolP512r1" "secp192k1" "secp256k1")
for alg in ${algs[*]}; do
    echo -n "  Test EC derive with ${alg}..."
    keygen_and_export ec:${alg}
    test $? -eq 0 && echo -n "." || exit $?
    openssl ecparam -genkey -name ${alg} > bob.pem 2>/dev/null
    test $? -eq 0 && echo -n "." || exit $?
    openssl ec -in bob.pem -pubout -outform DER > bob.der 2>/dev/null
    test $? -eq 0 && echo -n "." || exit $?
    pkcs11-tool --pin 648219 --id 1 --derive -i bob.der -o mine-bob.der > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
    openssl pkeyutl -derive -out bob-mine.der -inkey bob.pem -peerkey 1.pub 2>/dev/null
    test $? -eq 0 && echo -n "." || exit $?
    cmp bob-mine.der mine-bob.der
    test $? -eq 0 && echo -e ".\t${OK}" || exit $?
    rm -rf data* 1.*
    pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1 > /dev/null 2>&1
done
