#!/bin/bash

echo -n "Test initialization..."
#./tests/scripts/initialize.sh
test $? -eq 0 && echo -e '\tok' || (echo -e '\tfail' && exit 1)

echo -n "Test keygen..."
./tests/scripts/keygen.sh
test $? -eq 0 && echo -e '\tok' || (echo -e '\tfail' && exit 1)
