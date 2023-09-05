#!/bin/bash -eu

python3 tools/pico-hsm-tool.py --pin 648219 initialize --so-pin 57621880 --silent
test $? -eq 0 || exit $?

# Change SO-PIN
pkcs11-tool --login --login-type so --so-pin 3537363231383830 --change-pin --new-pin 0123456789012345
test $? -eq 0 || exit $?

pkcs11-tool --login --login-type so --so-pin 0123456789012345 --change-pin --new-pin 3537363231383830
test $? -eq 0 || exit $?

# Change PIN
pkcs11-tool --login --pin 648219 --change-pin --new-pin 123456
test $? -eq 0 || exit $?

# Reset PIN
pkcs11-tool --login --login-type so --so-pin 3537363231383830 --init-pin --new-pin 648219
test $? -eq 0 || exit $?

# Change PIN
pkcs11-tool --login --pin 648219 --change-pin --new-pin 123456
test $? -eq 0 || exit $?

pkcs11-tool --login --pin 123456 --change-pin --new-pin 648219
test $? -eq 0 || exit $?

# Wrong PIN (1st and 2nd PIN_INCORRECT, 3rd PIN_LOCKED)
e=$(pkcs11-tool --login --pin 123456 -I 2>&1)
test $? -eq 1 || exit $?
grep -q CKR_PIN_INCORRECT <<< $e || exit $?
e=$(pkcs11-tool --login --pin 123456 -I 2>&1)
test $? -eq 1 || exit $?
grep -q CKR_PIN_INCORRECT <<< $e || exit $?
e=$(pkcs11-tool --login --pin 123456 -I 2>&1)
test $? -eq 1 || exit $?
grep -q CKR_PIN_LOCKED <<< $e || exit $?

# Reset PIN
pkcs11-tool --login --login-type so --so-pin 3537363231383830 --init-pin --new-pin 648219
test $? -eq 0 || exit $?

pkcs11-tool --login --pin 648219 -I > /dev/null
test $? -eq 0 || exit $?
