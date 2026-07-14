#!/bin/bash

OK="\033[32mok\033[0m"
FAIL="\033[31mfail\033[0m"

gen_and_check() {
    e=$(pkcs11-tool -l --pin 648219 --keypairgen --key-type $1 --id 1 --label "TestLabel" 2>&1)
    test $? -eq 0 && echo -n "." || exit $?
    glabel=""
    case $1 in
    *"192"*)
        glabel="EC_POINT[[:space:]]+192[[:space:]]+bits"
        ;;
    *"256"*)
        glabel="EC_POINT[[:space:]]+256[[:space:]]+bits"
        ;;
    *"384"*)
        glabel="EC_POINT[[:space:]]+384[[:space:]]+bits"
        ;;
    *"512"*)
        glabel="EC_POINT[[:space:]]+512[[:space:]]+bits"
        ;;
    *"521"*)
        glabel="EC_POINT[[:space:]]+521[[:space:]]+bits"
        ;;
    *"rsa"*)
        IFS=: read -r v1 bits <<< "$1"
        glabel="RSA[[:space:]]+${bits}[[:space:]]+bits"
        ;;
    esac
    grep -Eq "${glabel}" <<< "$e" && echo -n "." || exit $?
}
gen_and_delete() {
    gen_and_check $1
    test $? -eq 0 && echo -n "." || exit $?
    pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1 > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
}
reset() {
    #python3 tools/pico-hsm-tool.py --pin 648219 initialize --so-pin 57621880 --silent --no-dev-cert > /dev/null 2>&1
    rm -f memory.flash
    tar -xf "${PICO_HSM_MEMORY_ARCHIVE:?startup.sh must decrypt the CI memory archive}" memory.flash
    test $? -eq 0 || exit $?
}

keygen_and_export() {
    gen_and_check $1
    test $? -eq 0 && echo -n "." || exit $?
    pkcs11-tool --read-object --pin 648219 --id 1 --type pubkey > 1.der 2>/dev/null
    test $? -eq 0 && echo -n "." || exit $?
    IFS=: read -r mk bts <<< "$1"
    openssl ${mk} -inform DER -outform PEM -in 1.der -pubin > 1.pub 2>/dev/null
    test $? -eq 0 && echo -n "." || exit $?
}
