"""
/*
 * This file is part of the Pico HSM distribution (https://github.com/polhenarejos/pico-hsm).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
"""

import pytest

from picokey import APDUResponse, SWCodes
from picohsm.DO import DOPrefixes
from picohsm.const import DEFAULT_PIN


def raw_send(device, command, cla=0x00, p1=0x00, p2=0x00, data=None, ne=None):
    # Use low-level transport to avoid automatic PIN retry/login behavior.
    return device._PicoHSM__card.send(command=command, cla=cla, p1=p1, p2=p2, data=data, ne=ne, codes=[])


def read_binary_raw(device, fid):
    return raw_send(
        device,
        command=0xB1,
        p1=(fid >> 8) & 0xFF,
        p2=fid & 0xFF,
        data=[0x54, 0x02, 0x00, 0x00],
        ne=0,
    )


def test_01_protected_data_requires_pin_for_read(device):
    fid = (DOPrefixes.PROT_DATA_PREFIX << 8) | 0x01
    payload = b"protected-regression"

    device.initialize()
    device.login(DEFAULT_PIN)
    device.put_contents(p1=fid, data=payload)
    device.logout()

    with pytest.raises(APDUResponse) as e:
        read_binary_raw(device, fid)
    assert e.value.sw == SWCodes.SW_SECURITY_STATUS_NOT_SATISFIED

    device.login(DEFAULT_PIN)
    data, sw = read_binary_raw(device, fid)
    assert sw == 0x9000
    assert bytes(data) == payload


def test_02_static_sensitive_files_are_not_readable(device):
    device.initialize()
    device.logout()

    for fid in (0x1081, 0x100E, 0x100A, 0x100B):
        with pytest.raises(APDUResponse) as e:
            read_binary_raw(device, fid)
        assert e.value.sw == SWCodes.SW_SECURITY_STATUS_NOT_SATISFIED


def test_03_key_object_readout_is_blocked_even_when_authenticated(device):
    # #3 depends on #2 class of bug: private key material must not be readable.
    # KEY_PREFIX objects are blocked by policy for READ BINARY.
    device.initialize()
    device.logout()

    with pytest.raises(APDUResponse) as e:
        read_binary_raw(device, 0xCC00)  # EF_KEY_DEV
    assert e.value.sw in (SWCodes.SW_SECURITY_STATUS_NOT_SATISFIED, SWCodes.SW_FILE_NOT_FOUND)

    device.login(DEFAULT_PIN)
    with pytest.raises(APDUResponse) as e:
        read_binary_raw(device, 0xCC00)  # EF_KEY_DEV
    assert e.value.sw in (SWCodes.SW_SECURITY_STATUS_NOT_SATISFIED, SWCodes.SW_FILE_NOT_FOUND)


def test_04_otp_extra_command_is_not_available(device):
    # #4: OTP command path was removed.
    device.initialize()
    device.login(DEFAULT_PIN)
    with pytest.raises(APDUResponse) as e:
        raw_send(device, cla=0x80, command=0x64, p1=0x4C, p2=0x00, data=[0x00, 0x00])
    assert e.value.sw == SWCodes.SW_INCORRECT_P1P2


def test_04_session_pin_instruction_removed(device):
    with pytest.raises(APDUResponse) as e:
        raw_send(device, command=0x5A, p1=0x01, p2=0x81)
    assert e.value.sw1 == 0x6D and e.value.sw2 == 0x00


def test_06_update_ef_rejects_out_of_bounds_offset(device):
    fid = (DOPrefixes.DATA_PREFIX << 8) | 0x10
    device.initialize()
    device.login(DEFAULT_PIN)
    device.put_contents(p1=fid, data=b"0123456789abcdef")

    # offset=4030, len=8 => 4038 (>4032) must be rejected.
    data = [0x54, 0x02, 0x0F, 0xBE, 0x53, 0x08] + [0xAA] * 8
    with pytest.raises(APDUResponse) as e:
        raw_send(device, command=0xD7, p1=(fid >> 8) & 0xFF, p2=fid & 0xFF, data=data)
    assert e.value.sw1 == 0x67 and e.value.sw2 == 0x00


def test_07_secure_messaging_requires_valid_mac(device):
    device.initialize()
    device.logout()

    # GA must fail without an authenticated session.
    with pytest.raises(APDUResponse) as e:
        device.general_authentication()
    assert e.value.sw1 == 0x64 and e.value.sw2 == 0x00

    # After PIN verification, GA should be available and SM can be established.
    device.login(DEFAULT_PIN)
    device.general_authentication()

    with pytest.raises(APDUResponse) as e:
        raw_send(device, command=0x84, cla=0x0C, data=[0x97, 0x01, 0x10], ne=0)
    assert e.value.sw1 == 0x69 and e.value.sw2 in (0x84, 0x87, 0x88)
