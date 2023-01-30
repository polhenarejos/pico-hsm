#!/bin/bash -eu

source tests/docker_env.sh
run_in_docker rm -f memory.flash
run_in_docker ./tests/start-up-and-test.sh

