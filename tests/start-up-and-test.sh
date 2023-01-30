#!/bin/bash -eu

/usr/sbin/pcscd -f -d &
./build_in_docker/pico_hsm &
pytest tests -W ignore::DeprecationWarning
