#!/bin/bash

gen_and_check() {
    e=$(pkcs11-tool -l --pin 648219 --keypairgen --key-type $1 --id 1 --label "TestLabel" 2>&1)
    test $? -eq 0 || exit $?
    glabel=""
    case $1 in
    *"192"*)
        glabel="EC_POINT 192 bits"
        ;;
    *"256"*)
        glabel="EC_POINT 256 bits"
        ;;
    *"384"*)
        glabel="EC_POINT 384 bits"
        ;;
    *"512"*)
        glabel="EC_POINT 512 bits"
        ;;
    *"521"*)
        glabel="EC_POINT 528 bits"
        ;;
    *"rsa"*)
        IFS=: read -r v1 bits <<< "$1"
        glabel="RSA ${bits} bits"
        ;;
    esac
    grep -q "${glabel}" <<< $e || exit $?
}
gen_and_delete() {
    gen_and_check $1
    pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1 > /dev/null 2>&1
}
reset() {
    python3 tools/pico-hsm-tool.py --pin 648219 initialize --so-pin 57621880 --silent > /dev/null 2>&1
    test $? -eq 0 || exit $?
}
