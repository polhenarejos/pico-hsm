#!/bin/bash

source ./tests/scripts/func.sh

TMP_SIGN_DATA=".pkcs11_sec_reg_data"
TMP_PRIV_DATA=".pkcs11_sec_reg_priv_data"
TMP_SIG_OUT=".pkcs11_sec_reg.sig"

cleanup() {
    rm -f "$TMP_SIGN_DATA" "$TMP_PRIV_DATA" "$TMP_SIG_OUT"
    pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1 > /dev/null 2>&1 || true
    pkcs11-tool -l --pin 648219 --delete-object --type data --label 'sec_priv_data' > /dev/null 2>&1 || true
}

trap cleanup EXIT

reset
test $? -eq 0 || exit $?

echo "security regression data" > "$TMP_SIGN_DATA"

echo -n "  Security regression: private key operation requires login..."
pkcs11-tool -l --pin 648219 --keypairgen --key-type rsa:2048 --id 1 --label "SecRegression" > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?
e=$(pkcs11-tool --id 1 --sign --mechanism RSA-PKCS -i "$TMP_SIGN_DATA" -o "$TMP_SIG_OUT" 2>&1)
test $? -ne 0 && echo -n "." || exit $?
(
    grep -q "CKR_USER_NOT_LOGGED_IN" <<< "$e" ||
    grep -q "CKR_PIN_REQUIRED" <<< "$e" ||
    grep -q "util_getpass error" <<< "$e"
) && echo -e ".\t${OK}" || exit $?

echo -n "  Security regression: private key material is not exportable..."
e=$(pkcs11-tool --read-object --type privkey --id 1 --pin 648219 2>&1)
test $? -eq 0 && echo -n "." || exit $?
(
    grep -q "CKR_ATTRIBUTE_SENSITIVE" <<< "$e" ||
    grep -q "CKR_ACTION_PROHIBITED" <<< "$e" ||
    grep -q "reading private keys not (yet) supported" <<< "$e" ||
    grep -q "error: object not found" <<< "$e"
) && echo -e ".\t${OK}" || exit $?

echo -n "  Security regression: private data object cannot be read without login..."
echo "private data regression" > "$TMP_PRIV_DATA"
pkcs11-tool --pin 648219 --write-object "$TMP_PRIV_DATA" --type data --id 2 --label 'sec_priv_data' --private > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?
e=$(pkcs11-tool --read-object --type data --label 'sec_priv_data' 2>&1)
test $? -eq 1 && echo -n "." || exit $?
(
    grep -q "error: object not found" <<< "$e" ||
    grep -q "CKR_USER_NOT_LOGGED_IN" <<< "$e" ||
    grep -q "CKR_PIN_REQUIRED" <<< "$e"
) && echo -n "." || exit $?
e=$(pkcs11-tool --read-object --type data --label 'sec_priv_data' --pin 648219 2>&1)
test $? -eq 0 && echo -n "." || exit $?
grep -q "private data regression" <<< "$e" && echo -e ".\t${OK}" || exit $?
