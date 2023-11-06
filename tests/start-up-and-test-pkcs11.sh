#!/bin/bash

source ./tests/startup.sh

chmod a+x tests/scripts/*.sh

echo "======== PKCS11 Test suite ========"
./tests/scripts/pkcs11.sh
