#!/bin/bash

source ./tests/scripts/func.sh
reset
test $? -eq 0 || exit $?

rsa_encrypt_decrypt() {
    openssl pkeyutl -encrypt -pubin -inkey 1.pub $2 -in $1 -out data.crypt
    test $? -eq 0 && echo -n "." || exit $?
    e=$(pkcs11-tool --id 1 --pin 648219 --decrypt $3 -i data.crypt 2>/dev/null)
    test $? -eq 0 && echo -n "." || exit $?
    grep -q "${TEST_STRING}" <<< $e || exit $?
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
rsa_encrypt_decrypt data "-pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256" "--mechanism RSA-PKCS-OAEP"
openssl pkeyutl -encrypt -pubin -inkey 1.pub -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in data -out data.crypt
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

