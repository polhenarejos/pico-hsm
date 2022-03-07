#!/bin/bash

echo "----------------------------"
echo "VID/PID patcher for Pico HSM"
echo "----------------------------"
echo ""

if [ "$#" -le 0 ]; then
    echo "Usage: $0 VID:PID [input_uf2_file] [output_uf2_file]"
    exit 1
fi

IFS=':' read -r -a ARR <<< "$1"

if [ ${#ARR[@]} -ne 2 ]; then
    echo "ERROR: Specify vendor and product ids as VID:PID (e.g., $0 CAFE:1234)"
    exit 1
fi

VID=${ARR[0]}
PID=${ARR[1]}

if [ ${#VID} -ne 4 ]; then
    echo "ERROR: VID length must be 4 hexadecimal characters"
    exit 1
fi

if [ ${#PID} -ne 4 ]; then
    echo "ERROR: PID length must be 4 hexadecimal characters"
    exit 1
fi

if ! [[ $VID =~ ^[0-9A-Fa-f]{1,}$ ]] ; then
    echo "ERROR: VID must contain hexadecimal characters"
    exit 1
fi

if ! [[ $PID =~ ^[0-9A-Fa-f]{1,}$ ]] ; then
    echo "ERROR: PID must contain hexadecimal characters"
    exit 1
fi

UF2_FILE_IF="hsm2040.uf2"
UF2_FILE_OF="$UF2_FILE_IF"

if [ "$#" -ge 2 ]; then
    UF2_FILE_IF="$2"
    UF2_FILE_OF="$UF2_FILE_IF"
fi

if [ "$#" -ge 3 ]; then
    UF2_FILE_OF="$3"
fi


echo -n "Patching ${UF2_FILE_IF}... "

if [[ ! -f "$UF2_FILE_IF" ]]; then
    echo "ERROR: UF2 file ${UF2_FILE_IF} does not exist"
    exit 1
fi

if [ "$UF2_FILE_IF" != "$UF2_FILE_OF" ]; then
    cp -R $UF2_FILE_IF $UF2_FILE_OF
fi

BASE_ADDRESS=`xxd "$UF2_FILE_IF" | grep "fffe fdfc 0103 0102 0301" | cut -d " " -f1`
ADDRESS="0x${BASE_ADDRESS%?}"

LITTLE_VID="\x${VID:2:2}\x${VID:0:2}"
LITTLE_PID="\x${PID:2:2}\x${PID:0:2}"

printf "$LITTLE_VID$LITTLE_PID" | dd of="$UF2_FILE_OF" bs=1 seek=$(($ADDRESS)) conv=notrunc 2> /dev/null

echo "Done!"
echo ""
echo "Patched file was saved in ${UF2_FILE_OF}"
