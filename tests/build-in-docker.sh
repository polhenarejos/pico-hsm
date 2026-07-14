#!/bin/bash -eu

source tests/docker_env.sh
build_image
BUILD_DIR="${PICO_HSM_DOCKER_BUILD_DIR:-$PWD/build_in_docker}"
run_in_docker cmake \
    -S "$PWD" \
    -B "${BUILD_DIR}" \
    -DENABLE_EMULATION=1 \
    -D__FOR_CI=1 \
    -DENABLE_EDDSA=1 \
    -DDEBUG_APDU=1
run_in_docker cmake --build "${BUILD_DIR}" -j "${NUM_PROC}"
docker create --name temp_container pico-hsm-test:bookworm
docker cp "${BUILD_DIR}/pico_hsm" temp_container:/pico_hsm
docker commit temp_container pico-hsm-test:bookworm
docker stop temp_container
docker rm temp_container
docker image prune -f
