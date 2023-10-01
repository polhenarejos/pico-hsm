#!/bin/bash

source ./tests/scripts/func.sh
reset
test $? -eq 0 || exit $?

TEST_DATA="This is a test string. Be safe, be secure."
echo ${TEST_DATA}  > data

create_dgst() {
    openssl dgst -$1 -binary -out data.$1 data > /dev/null 2>&1
}

create_dgst sha1
create_dgst sha224
create_dgst sha256
create_dgst sha384
create_dgst sha512

keygen_and_export() {
    gen_and_check $1
    test $? -eq 0 && echo -n "." || exit $?
    pkcs11-tool --read-object --pin 648219 --id 1 --type pubkey > 1.der 2>/dev/null
    test $? -eq 0 && echo -n "." || exit $?
    IFS=: read -r mk bts <<< "$1"
    openssl ${mk} -inform DER -outform PEM -in 1.der -pubin > 1.pub 2>/dev/null
    test $? -eq 0 && echo -n "." || exit $?
}

# $1 sign mechanism
# $2 sign input file
# $3 sign parameters
# $4 vrfy input file
# $5 vrfy parameters
sign_and_verify() {
    pkcs11-tool --id 1 --sign --pin 648219 --mechanism $1 -i $2 -o data.sig $3 > /dev/null 2>&1
    test $? -eq 0 || exit $?
    e=$(openssl pkeyutl -verify -pubin -inkey 1.pub -in $4 -sigfile data.sig $5 2>&1)
    test $? -eq 0 || exit $?
    grep -q "Signature Verified Successfully" <<< $e && echo -n "." || exit $?
}

sign_and_verify_rsa_pkcs() {
    dgstl=$(awk '{print tolower($0)}' <<<$1)
    dgstu=$(awk '{print toupper($0)}' <<<$1)
    sign_and_verify "${dgstu}-RSA-PKCS" data "" data.${dgstl} "-pkeyopt digest:${dgstl}"
    test $? -eq 0 && echo -n "." || exit $?
}

sign_and_verify_rsa_pss() {
    dgstl=$(awk '{print tolower($0)}' <<<$1)
    dgstu=$(awk '{print toupper($0)}' <<<$1)
    sign_and_verify "RSA-PKCS-PSS" data.${dgstl} "--mgf MGF1-${dgstu} --hash-algorithm ${dgstu}" data.${dgstl} "-pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:${dgstl}"
    test $? -eq 0 && echo -n "." || exit $?
}

sign_and_verify_rsa_pss_dgst() {
    dgstl=$(awk '{print tolower($0)}' <<<$1)
    dgstu=$(awk '{print toupper($0)}' <<<$1)
    sign_and_verify "${dgstu}-RSA-PKCS-PSS" data "" data.${dgstl} "-pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:${dgstl}"
    test $? -eq 0 && echo -n "." || exit $?
}

sign_and_verify_ec() {
    sign_and_verify ECDSA data.sha1 "--signature-format openssl" data.sha1
    sign_and_verify ECDSA data.sha224 "--signature-format openssl" data.sha224
    sign_and_verify ECDSA data.sha256 "--signature-format openssl" data.sha256
    sign_and_verify ECDSA data.sha384 "--signature-format openssl" data.sha384
    sign_and_verify ECDSA data.sha512 "--signature-format openssl" data.sha512
}

sign_and_verify_ec_dgst() {
    sign_and_verify ECDSA-SHA1 data "--signature-format openssl" data.sha1
    sign_and_verify ECDSA-SHA224 data "--signature-format openssl" data.sha224
    sign_and_verify ECDSA-SHA256 data "--signature-format openssl" data.sha256
    sign_and_verify ECDSA-SHA384 data "--signature-format openssl" data.sha384
    sign_and_verify ECDSA-SHA512 data "--signature-format openssl" data.sha512
}

keygen_sign_and_verify_ec() {
    keygen_and_export $1
    sign_and_verify_ec
    sign_and_verify_ec_dgst
    pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1 > /dev/null 2>&1
}

echo -n '+'

keygen_sign_and_verify_ec "ec:secp192r1" && echo -n "+" || exit $?
keygen_sign_and_verify_ec "ec:secp256r1" && echo -n "+" || exit $?
keygen_sign_and_verify_ec "ec:secp384r1" && echo -n "+" || exit $?
keygen_sign_and_verify_ec "ec:secp521r1" && echo -n "+" || exit $?
keygen_sign_and_verify_ec "ec:brainpoolP256r1" && echo -n "+" || exit $?
keygen_sign_and_verify_ec "ec:brainpoolP384r1" && echo -n "+" || exit $?
keygen_sign_and_verify_ec "ec:brainpoolP512r1" && echo -n "+" || exit $?
keygen_sign_and_verify_ec "ec:secp192k1" && echo -n "+" || exit $?
keygen_sign_and_verify_ec "ec:secp256k1" && echo -n "+" || exit $?

echo -n '+'

keygen_and_export "rsa:2048"

pkcs11-tool --id 1 --sign --pin 648219 --mechanism RSA-PKCS -i data -o data.sig > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?
e=$(openssl pkeyutl -verify -pubin -inkey 1.pub -in data -sigfile data.sig 2>&1)
test $? -eq 0 && echo -n "." || exit $?
grep -q "Signature Verified Successfully" <<< $e && echo -n "." || exit $?

echo -n "+"

sign_and_verify_rsa_pkcs sha1
sign_and_verify_rsa_pkcs sha224
sign_and_verify_rsa_pkcs sha256
sign_and_verify_rsa_pkcs sha384
sign_and_verify_rsa_pkcs sha512

echo -n "+"

cp data data_pad
dd if=/dev/zero bs=1 count=227 >> data_pad > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?
pkcs11-tool --id 1 --sign --pin 648219 --mechanism RSA-X-509 -i data_pad -o data.sig > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?
TDATA=$(tr -d '\0' < <(openssl rsautl -verify -inkey 1.pub -in data.sig -pubin -raw))
if [[ ${TEST_DATA} != "$TDATA" ]]; then
    exit 1
fi

echo -n "+"

#sign_and_verify_rsa_pss sha1
sign_and_verify_rsa_pss sha224
sign_and_verify_rsa_pss sha256
sign_and_verify_rsa_pss sha384
sign_and_verify_rsa_pss sha512

echo -n "+"

sign_and_verify_rsa_pss_dgst sha1
sign_and_verify_rsa_pss_dgst sha224
sign_and_verify_rsa_pss_dgst sha256
sign_and_verify_rsa_pss_dgst sha384
sign_and_verify_rsa_pss_dgst sha512

rm -rf data* 1.*
pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1 > /dev/null 2>&1
