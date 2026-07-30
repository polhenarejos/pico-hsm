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

pass=0; fail=0; times=""
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
        fail=$((fail + 1))
        echo "HUNG — no re-enumeration in ${SECS}s. NEEDS A PHYSICAL REPLUG; stopping."
        stop_uart_capture
        [ -n "$UART" ] && echo "  firmware log: $LOGDIR/uart-cycle-$n.log"
        break
    fi
    stop_uart_capture

    if [ "$FULL" = 1 ]; then
        if [ -f "$STAGING/dkek.pbe" ] && [ -f "$STAGING/dkek.pw" ]; then
            DKEK_PW="$(cat "$STAGING/dkek.pw")" perl -e 'alarm 120; exec @ARGV' -- \
                sc-hsm-tool --import-dkek-share "$STAGING/dkek.pbe" \
                --password env:DKEK_PW --so-pin "$SO_PIN" < /dev/null \
                > "$LOGDIR/dkek-$n.log" 2>&1
            echo "  dkek import rc=$?"
        else
            echo "  ! no DKEK share in $STAGING — skipping full chain"
        fi
    fi
done

echo
echo "==================================================="
echo " passed: $pass    hung: $fail    of $((pass + fail)) attempted"
[ -n "$times" ] && echo " recovery times:$times (seconds)"
echo " logs: $LOGDIR"
echo "==================================================="
[ "$fail" -eq 0 ] || exit 1
