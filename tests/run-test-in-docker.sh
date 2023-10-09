#!/bin/bash -eu

source tests/docker_env.sh

if [[ $1 == "pkcs11" ]]; then
    run_in_docker ./tests/start-up-and-test-pkcs11.sh
elif [[ $1 == "sc-hsm-pkcs11" ]]; then
    run_in_docker ./tests/scripts/sc_hsm_test.sh
else
    run_in_docker ./tests/start-up-and-test.sh
fi
