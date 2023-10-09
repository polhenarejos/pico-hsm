#!/bin/bash -eu

source tests/docker_env.sh

if [[ $1 == "pkcs11" ]]; then
    run_in_docker ./tests/start-up-and-test-pkcs11.sh
else
    run_in_docker ./tests/start-up-and-test.sh
fi
