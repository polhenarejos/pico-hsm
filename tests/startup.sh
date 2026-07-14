#!/bin/bash

OK="\t\033[32mok\033[0m"
FAIL="\t\033[31mfail\033[0m"

fail() {
    echo -e "${FAIL}"
    exit 1
}

echo -n "Start PCSC..."
/usr/sbin/pcscd &
test $? -eq 0 && echo -e "${OK}" || {
    echo -e "${FAIL}"
    exit 1
}
sleep 2
export PICO_HSM_MEMORY_ARCHIVE=/tmp/pico-hsm-memory.tar.gz
if ! python3 tests/memory_archive.py \
    decrypt tests/memory.tar.gz.enc "${PICO_HSM_MEMORY_ARCHIVE}"; then
    fail
fi
rm -f memory.flash
tar -xf "${PICO_HSM_MEMORY_ARCHIVE}" memory.flash
echo -n "Start Pico HSM..."

pkill -f 'swtpm socket' 2>/dev/null || true
rm -f /tmp/swtpm.sock /tmp/swtpm.sock.ctrl
STATE_BUNDLE=/tmp/.pico-hsm-emulation
rm -rf "${STATE_BUNDLE}"
if ! tar -xf "${PICO_HSM_MEMORY_ARCHIVE}" -C /tmp .pico-hsm-emulation; then
    echo "The decrypted CI archive has no Linux emulation identity; run ./tests/prepare-memory-in-docker.sh"
    fail
fi
DEVICE_ID_FILE="${STATE_BUNDLE}/device-id"
if [[ ! -s "${DEVICE_ID_FILE}" ]]; then
    echo "The decrypted CI archive has no emulation device ID; regenerate it."
    fail
fi
IFS= read -r PICO_HSM_CI_DEVICE_ID < "${DEVICE_ID_FILE}"
if [[ ! "${PICO_HSM_CI_DEVICE_ID}" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "The decrypted CI archive has an invalid emulation device ID."
    fail
fi
export PICO_HSM_CI_DEVICE_ID

swtpm socket \
  --tpm2 \
  --tpmstate dir="${STATE_BUNDLE}/swtpm-state" \
  --server type=unixio,path=/tmp/swtpm.sock \
  --ctrl type=unixio,path=/tmp/swtpm.sock.ctrl \
  --flags startup-clear \
  --daemon
export PICO_NOVUS_PEER_KEY_FILE="${STATE_BUNDLE}/otp_peer_p256.bin"
export TPM2TOOLS_TCTI="swtpm:path=/tmp/swtpm.sock"
export PICO_NOVUS_TPM_PIN="123456"

/pico_hsm > /dev/null 2>&1 &
test $? -eq 0 && echo -n "." || fail
sleep 2
ATR="3b:fe:18:00:00:81:31:fe:45:80:31:81:54:48:53:4d:31:73:80:21:40:81:07:fa"
e=$(opensc-tool -an 2>&1)
grep -qi "${ATR}" <<< "$e" && echo -n "." || fail
test $? -eq 0 && echo -e "${OK}" || fail
