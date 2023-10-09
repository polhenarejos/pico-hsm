#!/bin/bash

source ./tests/scripts/func.sh
echo "==== Test initialization ===="
./tests/scripts/initialize.sh
test $? -eq 0 || {
    echo -e "\t${FAIL}"
    exit 1
}

echo "==== Test keygen ===="
./tests/scripts/keygen.sh
test $? -eq 0 || {
    echo -e "\t${FAIL}"
    exit 1
}

echo "==== Test sign and verify ===="
./tests/scripts/sign_and_verify.sh
test $? -eq 0 || {
    echo -e "\t${FAIL}"
    exit 1
}

echo "==== Test asymmetric ciphering ===="
./tests/scripts/asym_cipher.sh
test $? -eq 0 || {
    echo -e "\t${FAIL}"
    exit 1
}
