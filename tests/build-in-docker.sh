#!/bin/bash -eu

source tests/docker_env.sh
#run_in_docker rm -rf CMakeFiles
run_in_docker git config --global --add safe.directory '*'
run_in_docker git submodule update --recursive
run_in_docker mkdir -p build_in_docker
run_in_docker -w "$PWD/build_in_docker" cmake -DENABLE_EMULATION=1 ..
run_in_docker -w "$PWD/build_in_docker" make -j ${NUM_PROC}
