#!/bin/bash

source ./tests/scripts/func.sh
reset

# Change SO-PIN
echo -n "  Test SO-PIN change..."
pkcs11-tool --login --login-type so --so-pin 3537363231383830 --change-pin --new-pin 0123456789012345 > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?

pkcs11-tool --login --login-type so --so-pin 0123456789012345 --change-pin --new-pin 3537363231383830 > /dev/null 2>&1
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

# Change PIN
echo -n "  Test PIN change..."
pkcs11-tool --login --pin 648219 --change-pin --new-pin 123456 > /dev/null 2>&1
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

# Reset PIN
echo -n "  Test PIN reset..."
pkcs11-tool --login --login-type so --so-pin 3537363231383830 --init-pin --new-pin 648219 > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?

# Change PIN
pkcs11-tool --login --pin 648219 --change-pin --new-pin 123456 > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?

pkcs11-tool --login --pin 123456 --change-pin --new-pin 648219 > /dev/null 2>&1
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

# Wrong PIN (1st and 2nd PIN_INCORRECT, 3rd PIN_LOCKED)
echo -n "  Test wrong PIN attempts..."
e=$(pkcs11-tool --login --pin 123456 -I 2>&1)
test $? -eq 1 && echo -n "." || exit $?
grep -q CKR_PIN_INCORRECT <<< $e && echo -n "." || exit $?
e=$(pkcs11-tool --login --pin 123456 -I 2>&1)
test $? -eq 1 && echo -n "." || exit $?
grep -q CKR_PIN_INCORRECT <<< $e && echo -n "." || exit $?
e=$(pkcs11-tool --login --pin 123456 -I 2>&1)
test $? -eq 1 && echo -n "." || exit $?
grep -q CKR_PIN_LOCKED <<< $e && echo -e "\t${OK}" || exit $?

# Reset PIN
echo -n "  Test restore PIN..."
pkcs11-tool --login --login-type so --so-pin 3537363231383830 --init-pin --new-pin 648219 > /dev/null 2>&1
test $? -eq 0 && echo -n "." || exit $?

pkcs11-tool --login --pin 648219 -I > /dev/null 2>&1
test $? -eq 0 && echo -e "\t${OK}" || exit $?
