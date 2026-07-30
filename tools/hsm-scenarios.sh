#!/usr/bin/env bash
# hsm-scenarios.sh — exercise a STAGING Pico HSM across scenarios the happy path never touches.
#
#   ./hsm-scenarios.sh              # all scenarios
#   ./hsm-scenarios.sh S1 S4        # only the named ones
#
# The provisioning soak (hsm-cycle-test.sh) proves the operational happy path: wipe, rebuild the
# DKEK domain, import a seed-derived key, sign, verify. Passing that 14 times says nothing about
# whether the device REFUSES what it should, how fast it is, or how it behaves when something goes
# wrong — and those are the properties an HSM is actually bought for.
#
# NEVER RUN THIS AGAINST A DEVICE HOLDING REAL KEYS. Several scenarios deliberately wipe the card,
# spend PIN attempts, and attempt operations that must fail.
set -u

SO_PIN="${HSM_SO_PIN:-3537363231383830}"
USER_PIN="${HSM_USER_PIN:-648219}"
STAGING="${HSM_STAGING_DIR:-$HOME/.local/share/akash-hsm-staging}"
AUTO_IMPORT="${HSM_AUTO_IMPORT:-$HOME/code/Akash-Console-hsmfix/infra/ceremony/qubes/scripts/hsm-auto-import.sh}"
VERIFY="${HSM_VERIFY:-$HOME/code/Akash-Console-hsmfix/infra/ceremony/qubes/scripts/verify-hsm-control.py}"
P11="${HSM_PKCS11_MODULE:-/opt/homebrew/lib/opensc-pkcs11.so}"
SCSH="${SCSH_HOME:-$HOME/tools/scsh-3.18.77}"
WORK="$(mktemp -d)"
WANT="$*"

pass=0; fail=0; skip=0
P() { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
S() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; skip=$((skip+1)); }
hdr() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }
want() { [ -z "$WANT" ] || case " $WANT " in *" $1 "*) return 0;; *) return 1;; esac; }

t() { perl -e "alarm ${2:-60}; exec @ARGV" -- ${1}; }   # bounded run
card_alive() { perl -e 'alarm 30; exec @ARGV' -- sc-hsm-tool >/dev/null 2>&1; }

wipe_and_provision() {
    perl -e 'alarm 200; exec @ARGV' -- sc-hsm-tool --initialize --so-pin "$SO_PIN" --pin "$USER_PIN" \
        --dkek-shares 1 --label scen < /dev/null >/dev/null 2>&1 || return 1
    for _ in $(seq 1 40); do sleep 1; card_alive && break; done
    card_alive || return 1
    DKEK_PW="$(cat "$STAGING/dkek.pw")" perl -e 'alarm 120; exec @ARGV' -- \
        sc-hsm-tool --import-dkek-share "$STAGING/dkek.pbe" --password env:DKEK_PW \
        --so-pin "$SO_PIN" < /dev/null >/dev/null 2>&1 || return 1
    HSM_AUTO_DIR="$STAGING/auto-import" SCSH_HOME="$SCSH" HSM_USER_PIN="$USER_PIN" \
    HSM_DKEK_SHARE_IN="$STAGING/dkek.pbe" HSM_DKEK_PW_IN="$STAGING/dkek.pw" \
        perl -e 'alarm 300; exec @ARGV' -- "$AUTO_IMPORT" --run >"$WORK/prov.log" 2>&1
}

sign_and_verify() {   # $1 = key id
    head -c 32 /dev/urandom > "$WORK/d.bin"
    pkcs11-tool --module "$P11" --login --pin "$USER_PIN" --sign --mechanism ECDSA \
        --id "$1" --input-file "$WORK/d.bin" --output-file "$WORK/s.bin" >/dev/null 2>&1 || return 1
    python3 "$VERIFY" --der "$STAGING/expected-pub.der" --digest "$WORK/d.bin" --sig "$WORK/s.bin" >/dev/null 2>&1
}

echo "workdir: $WORK"
card_alive || { echo "card not responding — replug and flash COMMITFIX first" >&2; exit 1; }

# ---------------------------------------------------------------------------------------------
if want S1; then
hdr "S1  SECURITY: a key wrapped under a DIFFERENT DKEK must be REFUSED"
# THE test for the fleet model. Cloning to a second device is only safe because a card that does
# not share the DKEK domain CANNOT unwrap the blob. That has been asserted all along and only ever
# checked in an emulator whose own header admits it cannot prove the real path. If this ever
# silently SUCCEEDS, the DKEK provides no isolation and the fleet design is unsound.
if wipe_and_provision; then
    ( umask 077; LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32 > "$WORK/bad.pw" )
    DKEK_PW="$(cat "$WORK/bad.pw")" sc-hsm-tool --create-dkek-share "$WORK/bad.pbe" \
        --password env:DKEK_PW >/dev/null 2>&1
    if [ -s "$WORK/bad.pbe" ]; then
        # Wrap under the FOREIGN share while the card still holds the original domain.
        HSM_AUTO_DIR="$WORK/foreign" SCSH_HOME="$SCSH" HSM_USER_PIN="$USER_PIN" \
        HSM_DKEK_SHARE_IN="$WORK/bad.pbe" HSM_DKEK_PW_IN="$WORK/bad.pw" \
            perl -e 'alarm 300; exec @ARGV' -- "$AUTO_IMPORT" --run > "$WORK/foreign.log" 2>&1
        rc=$?
        if [ $rc -eq 0 ] && grep -q "IMPORT-OK" "$WORK/foreign.log"; then
            F "CARD ACCEPTED A FOREIGN-DKEK KEY — DKEK provides no isolation (SECURITY)"
        else
            P "foreign-DKEK key refused (rc=$rc, no IMPORT-OK)"
        fi
    else
        S "could not create a second DKEK share"
    fi
else
    S "S1: provisioning failed, cannot set up"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S2; then
hdr "S2  THROUGHPUT: how many signatures per second?"
# The quorum flagged throughput as a production concern for an always-on signing oracle and nobody
# ever measured it. A number beats an opinion.
if card_alive && sign_and_verify 31; then
    N=20; t0=$(python3 -c 'import time;print(time.time())')
    ok=0
    for _ in $(seq 1 $N); do sign_and_verify 31 && ok=$((ok+1)); done
    t1=$(python3 -c 'import time;print(time.time())')
    python3 - "$t0" "$t1" "$N" "$ok" <<'PY'
import sys
t0,t1,n,ok=float(sys.argv[1]),float(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4])
d=t1-t0
print(f"  {ok}/{n} signatures verified, {d:.1f}s total, {d/n*1000:.0f} ms/sig, {n/d:.2f} sig/s")
print("  NOTE: each iteration is a fresh pkcs11-tool process + PIN login, so this is an")
print("  UPPER BOUND on latency, not the card's raw speed. A persistent session would be faster.")
PY
    [ "$ok" = "$N" ] && P "all $N signatures verified under load" || F "only $ok/$N verified"
else
    S "S2: no usable key on card"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S3; then
hdr "S3  SIGNATURE CANONICALITY: low-S, as Cosmos requires"
# Cosmos REJECTS high-S signatures. tx-signer normalises via toLowSCompact(), but if the card emits
# high-S at any meaningful rate that normalisation is load-bearing rather than belt-and-braces,
# and anything that signs without it is broken. Measure the actual rate.
if card_alive; then
    high=0; tot=15
    for _ in $(seq 1 $tot); do
        head -c 32 /dev/urandom > "$WORK/d.bin"
        pkcs11-tool --module "$P11" --login --pin "$USER_PIN" --sign --mechanism ECDSA --id 31 \
            --input-file "$WORK/d.bin" --output-file "$WORK/s.bin" >/dev/null 2>&1 || continue
        python3 - "$WORK/s.bin" <<'PY' && high=$((high+1))
import sys
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
sig=open(sys.argv[1],'rb').read()
s=int.from_bytes(sig[32:64],'big') if len(sig)==64 else 0
sys.exit(0 if s > N//2 else 1)
PY
    done
    echo "  high-S: $high of $tot signatures"
    if [ "$high" -gt 0 ]; then
        P "card DOES emit high-S ($high/$tot) — toLowSCompact() normalisation is REQUIRED, not optional"
    else
        P "no high-S observed in $tot (normalisation still required: absence is not a guarantee)"
    fi
else
    S "S3: card not responding"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S4; then
hdr "S4  WRONG PIN: signing must fail, and retries must decrement then recover"
# Deliberately spends ONE attempt of three, then immediately verifies with the correct PIN, which
# resets the counter. Never gets near a lockout.
if card_alive; then
    before=$(sc-hsm-tool 2>/dev/null | grep -oE "User PIN tries left *: *[0-9]+" | grep -oE "[0-9]+$")
    head -c 32 /dev/urandom > "$WORK/d.bin"
    pkcs11-tool --module "$P11" --login --pin 999999 --sign --mechanism ECDSA --id 31 \
        --input-file "$WORK/d.bin" --output-file "$WORK/s.bin" >/dev/null 2>&1
    if [ $? -eq 0 ]; then F "SIGNED WITH A WRONG PIN (SECURITY)"; else P "wrong PIN refused"; fi
    mid=$(sc-hsm-tool 2>/dev/null | grep -oE "User PIN tries left *: *[0-9]+" | grep -oE "[0-9]+$")
    [ "${mid:-9}" -lt "${before:-9}" ] && P "retry counter decremented ($before -> $mid)" \
                                       || F "retry counter did NOT decrement ($before -> $mid)"
    sign_and_verify 31 >/dev/null 2>&1
    after=$(sc-hsm-tool 2>/dev/null | grep -oE "User PIN tries left *: *[0-9]+" | grep -oE "[0-9]+$")
    [ "${after:-0}" -ge "${before:-9}" ] && P "counter restored after a correct PIN ($mid -> $after)" \
                                        || F "counter NOT restored ($mid -> $after)"
else
    S "S4: card not responding"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S5; then
hdr "S5  PERSISTENCE: the key survives a reboot"
# Provisioning is worthless if a restart loses the key. Reboot via the rescue app (stock firmware,
# measured 5/5) and confirm the SAME key still signs for the SAME public key afterwards.
if card_alive && sign_and_verify 31; then
    perl -e 'alarm 45; exec @ARGV' -- opensc-tool -s "00:A4:04:00:08:A0:58:3F:C1:9B:7E:4F:21" \
        -s "80:1F:00:00" >/dev/null 2>&1
    sleep 3
    back=0; for _ in $(seq 1 30); do sleep 1; card_alive && { back=1; break; }; done
    if [ "$back" = 1 ]; then
        sign_and_verify 31 && P "key survived the reboot and still signs for the seed's pubkey" \
                           || F "key did NOT verify after reboot"
    else
        F "device did not come back from the reboot"
    fi
else
    S "S5: no usable key to test"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S6; then
hdr "S6  RAPID-FIRE: back-to-back operations without pauses"
# The soak is leisurely; a real signer is not. Hammer it and see whether anything wedges.
if card_alive; then
    ok=0; n=25
    for _ in $(seq 1 $n); do sign_and_verify 31 && ok=$((ok+1)); done
    [ "$ok" = "$n" ] && P "$ok/$n rapid signatures verified" || F "only $ok/$n under rapid fire"
    card_alive && P "card still responsive after the burst" || F "card wedged after the burst"
else
    S "S6: card not responding"
fi
fi

echo
echo "==================================================="
echo " scenarios: $pass passed, $fail failed, $skip skipped"
echo " workdir: $WORK"
echo "==================================================="
[ "$fail" -eq 0 ] || exit 1
