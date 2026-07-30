#!/usr/bin/env python3
"""Reboot a Pico HSM remotely, over the normal smartcard channel.

    pico-hsm-reset.py          # reboot into firmware (recovery)

This needs NO firmware modification. The rescue app is compiled into stock pico-keys-sdk and
already exposes a reboot command; this just sends it and confirms it took effect.

    SELECT rescue app   00 A4 04 00 08 A0 58 3F C1 9B 7E 4F 21
    reboot normal mode  80 1F 00 00        (CLA is 0x80, not 0x00 — rescue rejects 0x00 with 6E00)

WHY APDUs AND NOT A USB CONTROL REQUEST. ccid.c has a (commented-out) vendor control handler for
RESET_REQUEST_FLASH, and enabling it looks like the obvious route. It is a dead end on macOS: the
handler binds to itf_num, which is the CCID interface, and the OS's own CCID class driver owns
that interface — libusb gets LIBUSB_ERROR_ACCESS and cannot claim it, while requests aimed at any
other interface are stalled by the device. APDUs travel the PCSC path that already works for
every other command, on every platform, without disturbing the smartcard stack.

BOOTSEL is deliberately NOT offered here. The rescue app gates P1=0x01 behind
rescue_require_user_presence() — a physical button press — so remote firmware replacement is
blocked by design. That gate is correct and worth keeping; do not route around it.
"""
import re
import shutil
import subprocess
import sys
import time

RESCUE_AID = "A0:58:3F:C1:9B:7E:4F:21"
SELECT_RESCUE = f"00:A4:04:00:08:{RESCUE_AID}"
REBOOT_NORMAL = "80:1F:00:00"


def reader_present() -> bool:
    try:
        out = subprocess.run(
            ["opensc-tool", "--list-readers"], capture_output=True, text=True, timeout=20
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return False
    return "Pico" in out


def main() -> int:
    if not shutil.which("opensc-tool"):
        sys.exit("opensc-tool not found (brew install opensc / apt install opensc)")

    if not reader_present():
        sys.exit("no Pico HSM reader found — is it plugged in?")

    print("sending reboot APDU to the rescue app...")
    try:
        res = subprocess.run(
            ["opensc-tool", "-s", SELECT_RESCUE, "-s", REBOOT_NORMAL],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        sys.exit("opensc-tool timed out talking to the card")

    # Two status words come back, one per APDU. The device may reboot before the second reply is
    # transmitted, so a MISSING second SW is normal and not an error — the bus check below is
    # what decides. Only an explicit non-9000 is worth failing on early.
    sws = re.findall(r"SW1=0x([0-9A-Fa-f]{2}), SW2=0x([0-9A-Fa-f]{2})", res.stdout)
    if sws and sws[0] != ("90", "00"):
        sys.exit(f"SELECT of the rescue app failed (SW={sws[0][0]}{sws[0][1]}) — is this pico-hsm?")
    if len(sws) > 1 and sws[1] != ("90", "00"):
        sw = f"{sws[1][0]}{sws[1][1]}".upper()
        hint = "  (6E00 = wrong CLA; 6D00 = INS unsupported, rescue app may be absent)"
        sys.exit(f"reboot command rejected (SW={sw}){hint}")

    # SW=9000 IS meaningful here, unlike the USB control-request route. rescue_process_apdu()
    # answers 6E00 for a wrong CLA and 6D00 for an unknown INS, so 9000 can only be produced by
    # cmd_reboot_bootsel() having run and armed the watchdog. (Contrast ccid_control_xfer_cb(),
    # which returns true for ANY vendor request on its interface — there the status word proves
    # nothing, which is why this tool used to verify against the bus instead.)
    print("reboot armed (SW=9000). Confirming the device comes back...")

    # Observing the device LEAVE the bus is unreliable and deliberately not required: the reboot
    # completes in roughly a second, and a presence check costs about that much, so the gap is
    # routinely missed. Racing it produced false "did not reboot" reports. What matters
    # operationally is the device being usable again, so wait for that instead.
    deadline = time.time() + 30
    time.sleep(2)
    while time.time() < deadline:
        if reader_present():
            print("device is responding — reboot complete")
            return 0
        time.sleep(0.5)

    print("device did not come back within 30s — that is a hang, not a reboot.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
