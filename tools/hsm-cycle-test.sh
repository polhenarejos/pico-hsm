#!/usr/bin/env bash
# hsm-cycle-test.sh — measure how reliably a Pico HSM survives re-provisioning.
#
#   ./hsm-cycle-test.sh --cycles 10
#   ./hsm-cycle-test.sh --cycles 5 --uart /dev/tty.usbserial-0001    # capture firmware logs
#   ./hsm-cycle-test.sh --cycles 3 --full                            # whole chain, not just reset
#
# WHY THIS EXISTS. `sc-hsm-tool --initialize` re-personalises the device, and the firmware resets
# itself afterwards so the card can rebuild state (without that reset the card never comes back
# and only a PHYSICAL REPLUG recovers it). That reset was measured at 7/7 on a warm device and
# 1/1 HUNG on the first initialize after a firmware flash — a real difference on a tiny sample.
# Settling that needs repetition with consistent instrumentation, which is what this is.
#
# INSTRUMENTATION NOTES, all learned by getting them wrong first:
#   - Presence is read from the USB layer, NOT from `opensc-tool --list-readers`. That call costs
#     ~1s, and the reset completes in ~1-3s, so polling with it MISSES the gap and reports a
#     successful reset as "never rebooted".
#   - A reboot is detected by the device IDENTITY CHANGING, not by observing an absence. Racing a
#     ~1s absence window produces false negatives; a new identity is durable evidence.
#   - Exit codes are read directly, never through a pipe. `cmd | tail` yields tail's status, which
#     silently turns a failure into a pass.
set -u

CYCLES=5
UART=""
FULL=0
SO_PIN="${HSM_SO_PIN:-3537363231383830}"
USER_PIN="${HSM_USER_PIN:-648219}"
STAGING="${HSM_STAGING_DIR:-$HOME/.local/share/akash-hsm-staging}"
VIDPID="2e8a:10fd"
AUTO_IMPORT="${HSM_AUTO_IMPORT:-$HOME/code/Akash-Console-hsmfix/infra/ceremony/qubes/scripts/hsm-auto-import.sh}"
VERIFY="${HSM_VERIFY:-$HOME/code/Akash-Console-hsmfix/infra/ceremony/qubes/scripts/verify-hsm-control.py}"
P11MOD="${HSM_PKCS11_MODULE:-/opt/homebrew/lib/opensc-pkcs11.so}"

while [ $# -gt 0 ]; do
    case "$1" in
        --cycles) CYCLES="$2"; shift 2;;
        --uart)   UART="$2"; shift 2;;
        --full)   FULL=1; shift;;
        -h|--help) sed -n '2,30p' "$0"; exit 0;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done

# Device identity, cheaply, on whichever platform. It only has to CHANGE across a re-enumeration;
# its actual value is meaningless. On Linux the bus/device number is reassigned on reconnect; on
# macOS the IORegistry entry id is.
device_id() {
    case "$(uname -s)" in
        Darwin) ioreg -p IOUSB -w0 2>/dev/null | grep -i "pico" | grep -oE "id 0x[0-9a-f]+" | head -1;;
        Linux)  lsusb -d "$VIDPID" 2>/dev/null | head -1 | awk '{print $2"/"$4}';;
        *)      echo "unsupported platform: $(uname -s)" >&2; exit 2;;
    esac
}

card_responds() {
    perl -e 'alarm 30; exec @ARGV' -- sc-hsm-tool >/dev/null 2>&1
}

# Wait for a NEW identity, i.e. the device re-enumerated. Returns 0 with SECS set, else 1.
SECS=0
wait_for_new_id() {
    local before="$1" limit="${2:-45}" waited=0 now
    while [ "$waited" -lt "$limit" ]; do
        sleep 1; waited=$((waited + 1))
        now="$(device_id)"
        if [ -n "$now" ] && [ "$now" != "$before" ]; then SECS=$waited; return 0; fi
    done
    SECS=$waited; return 1
}

start_uart_capture() {
    [ -n "$UART" ] || return 0
    [ -e "$UART" ] || { echo "  ! UART $UART not present, continuing without logs" >&2; UART=""; return 0; }
    # Raw read in the background. cat is enough: we only ever want to see what the firmware said,
    # never to write to it.
    ( stty -f "$UART" 115200 raw 2>/dev/null || stty -F "$UART" 115200 raw 2>/dev/null ) || true
    cat "$UART" > "$LOGDIR/uart-cycle-$1.log" 2>/dev/null &
    UART_PID=$!
}

stop_uart_capture() {
    [ -n "${UART_PID:-}" ] || return 0
    kill "$UART_PID" 2>/dev/null; wait "$UART_PID" 2>/dev/null
    UART_PID=""
}

LOGDIR="$(mktemp -d)"
echo "logs: $LOGDIR"
[ -n "$UART" ] && echo "uart: $UART (115200)"
echo "cycles: $CYCLES  mode: $([ "$FULL" = 1 ] && echo full-chain || echo reset-only)"
echo

if [ -z "$(device_id)" ]; then
    echo "no Pico HSM on the bus ($VIDPID) — plug it in first" >&2
    exit 1
fi

pass=0; fail=0; declined=0; times=""; chain_pass=0; chain_fail=0
for n in $(seq 1 "$CYCLES"); do
    printf 'cycle %s/%s: ' "$n" "$CYCLES"
    start_uart_capture "$n"
    before="$(device_id)"

    perl -e 'alarm 180; exec @ARGV' -- sc-hsm-tool --initialize \
        --so-pin "$SO_PIN" --pin "$USER_PIN" --dkek-shares 1 --label "cycle$n" \
        < /dev/null > "$LOGDIR/init-$n.log" 2>&1
    init_rc=$?

    if wait_for_new_id "$before" 45; then
        # Re-enumerating is necessary but not sufficient — the card must actually answer.
        settled=0
        for _ in $(seq 1 15); do
            sleep 1
            if card_responds; then settled=1; break; fi
        done
        if [ "$settled" = 1 ]; then
            pass=$((pass + 1)); times="$times $SECS"
            echo "RECOVERED in ${SECS}s (init rc=$init_rc)"
        else
            fail=$((fail + 1))
            echo "REBOOTED but card never answered — partial failure"
        fi
    else
        # "No re-enumeration" has TWO causes and they are opposites. The firmware declines to
        # reset when the flash commit is unconfirmed (returning SW_EXEC_ERROR and staying alive
        # on purpose, since an operator who can retry beats a device needing a datacenter visit).
        # That also produces no new identity — but the device is FINE. Calling it a hang would
        # report the safety mechanism working as a failure, so distinguish them by whether the
        # device is still on the bus.
        stop_uart_capture
        if [ -n "$(device_id)" ]; then
            echo "DECLINED to reset but device is ALIVE (init rc=$init_rc) — commit was"
            echo "         unconfirmed and the firmware correctly refused to reset. Retryable."
            declined=$((declined + 1))
        else
            fail=$((fail + 1))
            echo "HUNG — gone from the bus after ${SECS}s. NEEDS A PHYSICAL REPLUG; stopping."
            [ -n "$UART" ] && echo "  firmware log: $LOGDIR/uart-cycle-$n.log"
        fi
        break
    fi
    stop_uart_capture

    if [ "$FULL" = 1 ]; then
        # The whole point of --full: assert CRYPTO CORRECTNESS every cycle, not just that the
        # device came back. Re-provisioning that reliably produces the WRONG key would pass a
        # reset-only test forever, and would lose funds in production. So each cycle re-imports
        # the seed-derived key and proves the card signs for the seed's public key — plus a
        # negative control, so a verifier that trivially returns success cannot fake a pass.
        chain_ok=1
        if [ ! -f "$STAGING/dkek.pbe" ] || [ ! -f "$STAGING/dkek.pw" ]; then
            echo "  ! no DKEK share in $STAGING — cannot run the chain"; chain_ok=0
        elif [ ! -x "$AUTO_IMPORT" ]; then
            echo "  ! auto-import script not found at $AUTO_IMPORT (set HSM_AUTO_IMPORT)"; chain_ok=0
        fi

        if [ "$chain_ok" = 1 ]; then
            DKEK_PW="$(cat "$STAGING/dkek.pw")" perl -e 'alarm 120; exec @ARGV' -- \
                sc-hsm-tool --import-dkek-share "$STAGING/dkek.pbe" \
                --password env:DKEK_PW --so-pin "$SO_PIN" < /dev/null \
                > "$LOGDIR/dkek-$n.log" 2>&1 || chain_ok=0
            [ "$chain_ok" = 1 ] || echo "  CHAIN FAIL: dkek import"
        fi

        if [ "$chain_ok" = 1 ]; then
            HSM_AUTO_DIR="$STAGING/auto-import" SCSH_HOME="${SCSH_HOME:-$HOME/tools/scsh-3.18.77}" \
            HSM_USER_PIN="$USER_PIN" HSM_DKEK_SHARE_IN="$STAGING/dkek.pbe" \
            HSM_DKEK_PW_IN="$STAGING/dkek.pw" \
                perl -e 'alarm 300; exec @ARGV' -- "$AUTO_IMPORT" --run \
                > "$LOGDIR/import-$n.log" 2>&1 || chain_ok=0
            [ "$chain_ok" = 1 ] || echo "  CHAIN FAIL: key import (see $LOGDIR/import-$n.log)"
        fi

        if [ "$chain_ok" = 1 ]; then
            head -c 32 /dev/urandom > "$LOGDIR/d-$n.bin"
            pkcs11-tool --module "$P11MOD" --login --pin "$USER_PIN" --sign --mechanism ECDSA \
                --id 31 --input-file "$LOGDIR/d-$n.bin" --output-file "$LOGDIR/s-$n.bin" \
                > "$LOGDIR/sign-$n.log" 2>&1 || chain_ok=0
            if [ "$chain_ok" = 1 ]; then
                python3 "$VERIFY" --der "$STAGING/expected-pub.der" \
                    --digest "$LOGDIR/d-$n.bin" --sig "$LOGDIR/s-$n.bin" >/dev/null 2>&1
                if [ $? -ne 0 ]; then
                    chain_ok=0; echo "  CHAIN FAIL: card signature does NOT match the seed's pubkey"
                else
                    # Negative control: the same signature against a DIFFERENT digest must FAIL.
                    # Without this, a verifier stuck returning 0 would make every cycle "pass".
                    head -c 32 /dev/urandom > "$LOGDIR/dbad-$n.bin"
                    python3 "$VERIFY" --der "$STAGING/expected-pub.der" \
                        --digest "$LOGDIR/dbad-$n.bin" --sig "$LOGDIR/s-$n.bin" >/dev/null 2>&1
                    if [ $? -eq 0 ]; then
                        chain_ok=0; echo "  CHAIN FAIL: negative control PASSED — verifier is not discriminating"
                    fi
                fi
            else
                echo "  CHAIN FAIL: on-card signing"
            fi
        fi

        if [ "$chain_ok" = 1 ]; then
            chain_pass=$((chain_pass + 1)); echo "  chain OK (key imported, signed, verified, negative control held)"
        else
            chain_fail=$((chain_fail + 1))
        fi
    fi
done

echo
echo "==================================================="
echo " passed: $pass    hung: $fail    declined-safely: $declined    of $((pass + fail + declined)) attempted"
[ -n "$times" ] && echo " recovery times:$times (seconds)"
[ "$FULL" = 1 ] && echo " full chain: $chain_pass verified, $chain_fail failed"
echo " logs: $LOGDIR"
echo "==================================================="
[ "$fail" -eq 0 ] && [ "${chain_fail:-0}" -eq 0 ] || exit 1
