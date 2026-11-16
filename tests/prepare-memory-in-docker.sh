#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${PICO_HSM_MEMORY_PREPARE_CONTAINER:-0}" != "1" ]]; then
    if [[ -z "${PICO_HSM_MEMORY_PASSPHRASE:-}" ]]; then
        echo "Set PICO_HSM_MEMORY_PASSPHRASE before preparing the CI archive." >&2
        exit 1
    fi
    cd "${ROOT_DIR}"
    source tests/docker_env.sh
    run_in_docker -e PICO_HSM_MEMORY_PREPARE_CONTAINER=1 ./tests/prepare-memory-in-docker.sh
    exit $?
fi

PIN="648219"
# OpenSC represents the SmartCard-HSM SO PIN as 16 hexadecimal characters.
# Its card driver decodes that value before sending it, so initialize the HSM
# with the corresponding eight raw ASCII bytes.
SO_PIN="57621880"
OPENSC_SO_PIN="3537363231383830"
TPM_PIN="123456"
ATR="3b:fe:18:00:00:81:31:fe:45:80:31:81:54:48:53:4d:31:73:80:21:40:81:07:fa"

WORK_DIR="$(mktemp -d /tmp/pico-hsm-memory.XXXXXX)"
STATE_BUNDLE="${WORK_DIR}/.pico-hsm-emulation"
TPM_STATE="${STATE_BUNDLE}/swtpm-state"
ENCRYPTED_TMP=""
PCSC_PID=""
SWTPM_PID=""
HSM_PID=""

stop_process() {
    local pid="${1:-}"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    fi
}

cleanup() {
    local status=$?
    stop_process "${HSM_PID}"
    stop_process "${SWTPM_PID}"
    stop_process "${PCSC_PID}"
    if [[ ${status} -ne 0 ]]; then
        echo "Memory preparation failed." >&2
        if [[ -f "${WORK_DIR}/pico_hsm.log" ]]; then
            tail -n 80 "${WORK_DIR}/pico_hsm.log" >&2
        fi
        if [[ -f "${WORK_DIR}/pcscd.log" ]]; then
            tail -n 40 "${WORK_DIR}/pcscd.log" >&2
        fi
        if [[ -f "${WORK_DIR}/swtpm.log" ]]; then
            tail -n 40 "${WORK_DIR}/swtpm.log" >&2
        fi
    fi
    if [[ -n "${ENCRYPTED_TMP}" ]]; then
        rm -f "${ENCRYPTED_TMP}"
    fi
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

if [[ ! -x /pico_hsm ]]; then
    echo "/pico_hsm is missing from the Docker image; run ./tests/build-in-docker.sh first." >&2
    exit 1
fi

if ! python3 -c 'import smartcard, usb, lz4, libusb_package'; then
    echo "The Docker image lacks pypicokey dependencies; rebuild it with ./tests/build-in-docker.sh." >&2
    exit 1
fi

mkdir -p "${TPM_STATE}"
openssl rand -hex 32 > "${STATE_BUNDLE}/device-id"
IFS= read -r PICO_HSM_CI_DEVICE_ID < "${STATE_BUNDLE}/device-id"
export PICO_HSM_CI_DEVICE_ID

/usr/sbin/pcscd --foreground > "${WORK_DIR}/pcscd.log" 2>&1 &
PCSC_PID=$!

rm -f /tmp/swtpm.sock /tmp/swtpm.sock.ctrl
swtpm socket \
    --tpm2 \
    --tpmstate dir="${TPM_STATE}" \
    --server type=unixio,path=/tmp/swtpm.sock \
    --ctrl type=unixio,path=/tmp/swtpm.sock.ctrl \
    --flags startup-clear > "${WORK_DIR}/swtpm.log" 2>&1 &
SWTPM_PID=$!

swtpm_ready=0
for _ in $(seq 1 50); do
    if [[ -S /tmp/swtpm.sock ]]; then
        swtpm_ready=1
        break
    fi
    sleep 0.1
done
if [[ ${swtpm_ready} -ne 1 ]]; then
    echo "swtpm did not create its command socket." >&2
    exit 1
fi

# pcscd must have loaded the vpcd reader before pico_hsm connects to it.
sleep 2

export PICO_NOVUS_PEER_KEY_FILE="${STATE_BUNDLE}/otp_peer_p256.bin"
export TPM2TOOLS_TCTI="swtpm:path=/tmp/swtpm.sock"
export PICO_NOVUS_TPM_PIN="${TPM_PIN}"

cd "${WORK_DIR}"
stdbuf -oL -eL /pico_hsm > "${WORK_DIR}/pico_hsm.log" 2>&1 &
HSM_PID=$!
cd "${ROOT_DIR}"

reader_ready=0
for _ in $(seq 1 50); do
    OPENSC_OUTPUT="$(opensc-tool -an 2>/dev/null || true)"
    if grep -qi "${ATR}" <<< "${OPENSC_OUTPUT}"; then
        reader_ready=1
        break
    fi
    sleep 0.2
done
if [[ ${reader_ready} -ne 1 ]]; then
    echo "Pico HSM did not become available through PC/SC." >&2
    exit 1
fi

PYTHONPATH="${ROOT_DIR}/tools/pypicohsm:${ROOT_DIR}/tools/pypicokey" \
python3 - "${PIN}" "${SO_PIN}" <<'PY'
import sys

from picohsm import PicoHSM

pin, so_pin = sys.argv[1:3]
hsm = PicoHSM(pin)
hsm.initialize(pin=pin, sopin=so_pin, force_dev_cert=True)
chain = bytes(hsm.get_contents(0x2F02))
if len(chain) < 512 or not chain.startswith(b"\x7f\x21"):
    raise RuntimeError(f"unexpected uploaded CVC chain: {len(chain)} bytes")
print(f"Uploaded Linux device CVC chain: {len(chain)} bytes")
PY

pkcs11-tool --login --pin "${PIN}" -I >/dev/null
pkcs11-tool \
    --login \
    --login-type so \
    --so-pin "${OPENSC_SO_PIN}" \
    --list-objects >/dev/null

stop_process "${HSM_PID}"
HSM_PID=""
stop_process "${SWTPM_PID}"
SWTPM_PID=""
sync

if [[ ! -s "${WORK_DIR}/memory.flash" ]]; then
    echo "The emulator did not create memory.flash." >&2
    exit 1
fi
if [[ ! -s "${STATE_BUNDLE}/otp_peer_p256.bin" ]]; then
    echo "The Linux TPM peer key was not created." >&2
    exit 1
fi

PLAIN_ARCHIVE="${WORK_DIR}/memory.tar.gz"
tar -C "${WORK_DIR}" -czf "${PLAIN_ARCHIVE}" memory.flash .pico-hsm-emulation
ENCRYPTED_TMP="$(mktemp "${ROOT_DIR}/tests/.memory.tar.gz.enc.XXXXXX")"
python3 "${ROOT_DIR}/tests/memory_archive.py" \
    encrypt "${PLAIN_ARCHIVE}" "${ENCRYPTED_TMP}"
mv "${ENCRYPTED_TMP}" "${ROOT_DIR}/tests/memory.tar.gz.enc"
ENCRYPTED_TMP=""
rm -f "${ROOT_DIR}/tests/memory.tar.gz"

echo "Prepared ${ROOT_DIR}/tests/memory.tar.gz.enc"
echo "The encrypted archive contains memory.flash and its matching Linux swtpm and device identities."
