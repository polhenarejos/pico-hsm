#!/bin/bash

python3 tools/pico-hsm-tool.py --pin 648219 initialize --so-pin 57621880 --silent
test $? -eq 0 || exit $?
