#!/bin/bash -eu

source tests/docker_env.sh

if [[ "$#" -gt 1 ]]; then
    if [[ $1 == "pkcs11" ]]; then
        run_in_docker ./tests/start-up-and-test-pkcs11.sh
    elif [[ $1 == "pytest" ]]; then
        run_in_docker ./tests/start-up-and-test.sh
    fi
else
    run_in_docker ./tests/start-up-and-test.sh
fi

