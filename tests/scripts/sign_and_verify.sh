#!/bin/bash

source ./tests/scripts/func.sh
reset
test $? -eq 0 || exit $?

TEST_DATA="This is a test string. Be safe, be secure."
echo ${TEST_DATA}  > data

create_dgst() {
    openssl dgst -$1 -binary -out data.$1 data > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
}

dgsts=("sha1" "sha224" "sha256" "sha384" "sha512")
for dgst in ${dgsts[*]}; do
    echo -n "  Create digest ${dgst}..."
    create_dgst ${dgst}
    test $? -eq 0 && echo -e ".\t${OK}" || exit $?
done

# $1 sign mechanism
# $2 sign input file
# $3 sign parameters
# $4 vrfy input file
# $5 vrfy parameters
sign_and_verify() {
    pkcs11-tool --id 1 --sign --pin 648219 --mechanism $1 -i $2 -o data.sig $3 > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
    e=$(openssl pkeyutl -verify -pubin -inkey 1.pub -in $4 -sigfile data.sig $5 2>&1)
    test $? -eq 0 && echo -n "." || exit $?
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

keygen_sign_and_verify_ec() {
    echo "  Test ECDSA with $1"
    echo -n "    Keygen $1..."
    keygen_and_export $1
    test $? -eq 0 && echo -e ".\t${OK}" || exit $?
    for dgst in ${dgsts[*]}; do
        dgstu=$(awk '{print toupper($0)}' <<<${dgst})
        echo -n "    Test ECDSA with ${dgst} and $1..."
        sign_and_verify ECDSA "data.${dgst}" "--signature-format openssl" data.${dgst}
        test $? -eq 0 && echo -e ".\t${OK}" || exit $?
        echo -n "    Test ECDSA-${dgstu} with $1..."
        sign_and_verify "ECDSA-${dgstu}" data "--signature-format openssl" data.${dgst}
        test $? -eq 0 && echo -e ".\t${OK}" || exit $?
    done
    echo -n "    Delete $1..."
    pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1 > /dev/null 2>&1
    test $? -eq 0 && echo -e ".\t${OK}" || exit $?
}

algs=("ec:secp192r1" "ec:secp256r1" "ec:secp384r1" "ec:secp521r1" "ec:brainpoolP256r1" "ec:brainpoolP384r1" "ec:brainpoolP512r1" "ec:secp192k1" "ec:secp256k1")
for alg in ${algs[*]}; do
    keygen_sign_and_verify_ec ${alg} || exit $?
done

echo "  Test RSA PKCS"
echo -n "    Keygen rsa:2048..."
keygen_and_export "rsa:2048"
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

echo -n "    Test RSA-PKCS..."
pkcs11-tool --id 1 --sign --pin 648219 --mechanism RSA-PKCS -i data -o data.sig > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?
e=$(openssl pkeyutl -verify -pubin -inkey 1.pub -in data -sigfile data.sig 2>&1)
test $? -eq 0 && echo -n "." || exit $?
grep -q "Signature Verified Successfully" <<< $e && echo -e ".\t${OK}" || exit $?

for dgst in ${dgsts[*]}; do
    dgstu=$(awk '{print toupper($0)}' <<<${dgst})
    echo -n "    Test RSA-PKCS-${dgstu}..."
    sign_and_verify_rsa_pkcs ${dgst}
    test $? -eq 0 && echo -e ".\t${OK}" || exit $?
done

echo -n "    Test RSA-X-509..."
cp data data_pad
test $? -eq 0 && echo -n "." || exit $?
tlen=${#TEST_DATA}
dd if=/dev/zero bs=1 count=$((256-$tlen)) >> data_pad > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?
pkcs11-tool --id 1 --sign --pin 648219 --mechanism RSA-X-509 -i data_pad -o data.sig > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?
TDATA=$(tr -d '\0' < <(openssl rsautl -verify -inkey 1.pub -in data.sig -pubin -raw))
if [[ ${TEST_DATA} != "$TDATA" ]]; then
    exit 1
fi
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

for dgst in ${dgsts[*]}; do
    dgstu=$(awk '{print toupper($0)}' <<<${dgst})
    if [[ "${dgst}" != "sha1" ]]; then
        echo -n "    Test RSA-PKCS-PSS with ${dgst}..."
        sign_and_verify_rsa_pss ${dgst}
        test $? -eq 0 && echo -e ".\t${OK}" || exit $?
    fi
    echo -n "    Test ${dgstu}-RSA-PKCS-PSS..."
    sign_and_verify_rsa_pss_dgst ${dgst}
    test $? -eq 0 && echo -e ".\t${OK}" || exit $?
done

rm -rf data* 1.*
pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1 > /dev/null 2>&1
