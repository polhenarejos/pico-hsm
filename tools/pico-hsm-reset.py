#!/usr/bin/env python3
"""Reset a Pico HSM over USB, without touching the hardware.

This is the host side of the PICOKEYS_REMOTE_RESET build option. Firmware built WITHOUT that
option ignores these requests, which is the intended default — see the CMake option for why.

    pico-hsm-reset.py                # reboot into firmware (recovery)
    pico-hsm-reset.py --bootsel      # reboot into the bootloader (remote firmware update)

Why not picotool: picotool looks for the Pico SDK's dedicated reset interface, identified as
class 0xFF / subclass 0x00 / protocol 0x01. The Pico HSM's CCID interface is vendor-class but
protocol 0x00, so picotool does not recognise it. The control request itself is identical; only
the discovery differs, so a direct control transfer works where picotool does not.

Uses libusb through ctypes on purpose: no pyusb, no pip install, nothing to provision on a
machine whose only job is to recover a wedged token.
"""
import ctypes
import ctypes.util
import sys
import time

VID, PID = 0x2E8A, 0x10FD

# From pico/usb_reset_interface.h. Kept in sync with the firmware, which links the SDK header.
RESET_REQUEST_BOOTSEL = 0x01
RESET_REQUEST_FLASH = 0x02

# host->device (0) | vendor (2<<5) | recipient=interface (1)
BMREQUEST_VENDOR_INTERFACE_OUT = 0x41


def _load_libusb():
    for cand in ("/opt/homebrew/lib/libusb-1.0.dylib", "/usr/local/lib/libusb-1.0.dylib"):
        try:
            return ctypes.CDLL(cand)
        except OSError:
            pass
    found = ctypes.util.find_library("usb-1.0")
    if not found:
        sys.exit("libusb not found. brew install libusb")
    return ctypes.CDLL(found)


def main() -> int:
    bootsel = "--bootsel" in sys.argv
    request = RESET_REQUEST_BOOTSEL if bootsel else RESET_REQUEST_FLASH
    what = "BOOTSEL (bootloader)" if bootsel else "flash (firmware)"

    lib = _load_libusb()
    # EVERY signature must be declared. ctypes defaults undeclared integer arguments to C int,
    # which truncates a 64-bit device handle to 32 bits and segfaults on the next call — it does
    # not fail cleanly, it crashes. Omitting these is the single easiest way to get this wrong.
    lib.libusb_init.argtypes = [ctypes.c_void_p]
    lib.libusb_exit.argtypes = [ctypes.c_void_p]
    lib.libusb_open_device_with_vid_pid.argtypes = [ctypes.c_void_p, ctypes.c_uint16, ctypes.c_uint16]
    lib.libusb_open_device_with_vid_pid.restype = ctypes.c_void_p
    lib.libusb_close.argtypes = [ctypes.c_void_p]
    lib.libusb_control_transfer.argtypes = [
        ctypes.c_void_p, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint16,
        ctypes.c_uint16, ctypes.c_void_p, ctypes.c_uint16, ctypes.c_uint,
    ]
    lib.libusb_control_transfer.restype = ctypes.c_int

    if lib.libusb_init(None) < 0:
        sys.exit("libusb_init failed")

    handle = lib.libusb_open_device_with_vid_pid(None, VID, PID)
    if not handle:
        lib.libusb_exit(None)
        sys.exit(f"no Pico HSM found at {VID:04x}:{PID:04x} (is it plugged in?)")

    # The firmware only acts when wIndex matches ITS interface number, and that number shifts
    # with the build (HID/CCID/WCID/LWIP interfaces are conditional). Rather than hardcode it,
    # try each: the wrong index is a no-op the device simply ignores, so sweeping is harmless.
    #
    # NOTE: a successful control transfer proves NOTHING on its own. ccid_control_xfer_cb()
    # returns true for ANY vendor request aimed at its interface, so firmware built without
    # PICOKEYS_REMOTE_RESET acknowledges these requests and silently does nothing. The ACK is
    # not the result; the device going away and coming back is. So send, then verify.
    for itf in range(4):
        lib.libusb_control_transfer(
            handle, BMREQUEST_VENDOR_INTERFACE_OUT, request, 0, itf, None, 0, 1000
        )
    lib.libusb_close(handle)
    print(f"reset request {request:#04x} sent; verifying the device actually resets...")

    # A reset makes the device drop off the bus. Watch for the disappearance — that, and not the
    # transfer status, is the evidence the firmware acted on the request.
    went_away = False
    for _ in range(30):
        time.sleep(0.5)
        h = lib.libusb_open_device_with_vid_pid(None, VID, PID)
        if not h:
            went_away = True
            break
        lib.libusb_close(h)

    if not went_away:
        lib.libusb_exit(None)
        print(
            "device never left the bus, so it did NOT reset. Most likely this firmware was built\n"
            "WITHOUT -DPICOKEYS_REMOTE_RESET=ON, in which case the handler is compiled out by\n"
            "design and the request was acknowledged but ignored.",
            file=sys.stderr,
        )
        return 1

    if bootsel:
        lib.libusb_exit(None)
        print("device left the bus -> now in BOOTSEL. Copy a .uf2 to the mounted drive.")
        return 0

    # A firmware reset should re-enumerate on its own. Anything that leaves the bus and stays
    # gone is a hang, not a reset, and is the failure this tool most needs to surface.
    for _ in range(60):
        time.sleep(0.5)
        h = lib.libusb_open_device_with_vid_pid(None, VID, PID)
        if h:
            lib.libusb_close(h)
            lib.libusb_exit(None)
            print(f"device re-enumerated -> reset to {what} CONFIRMED")
            return 0

    lib.libusb_exit(None)
    print("device left the bus and did NOT come back within 30s — that is a hang, not a reset.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
