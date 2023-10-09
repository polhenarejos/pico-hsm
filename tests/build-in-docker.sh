#!/bin/bash -eu

source tests/docker_env.sh
build_image
#run_in_docker rm -rf CMakeFiles
run_in_docker mkdir -p build_in_docker
run_in_docker -w "$PWD/build_in_docker" cmake -DENABLE_EMULATION=1 ..
run_in_docker -w "$PWD/build_in_docker" make -j ${NUM_PROC}
docker create --name temp_container pico-hsm-test:bullseye
docker cp $PWD/build_in_docker/pico_hsm temp_container:/pico_hsm
docker commit temp_container pico-hsm-test:bullseye
docker stop temp_container
docker rm temp_container
docker image prune -f
