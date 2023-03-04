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
from utils import APDUResponse, SWCodes
from const import DEFAULT_PIN, DEFAULT_RETRIES

WRONG_PIN = '112233'
RETRIES = DEFAULT_RETRIES

def test_pin_init_retries(device):
    device.initialize(retries=RETRIES)
    retries = device.get_login_retries()
    assert(retries == RETRIES)

def test_pin_login(device):
    device.initialize(retries=RETRIES)
    device.login(DEFAULT_PIN)

def test_pin_retries(device):
    device.initialize(retries=RETRIES)
    device.login(DEFAULT_PIN)

    for ret in range(RETRIES-1):
        with pytest.raises(APDUResponse) as e:
            device.login(WRONG_PIN)
        assert(e.value.sw1 == 0x63 and e.value.sw2 == (0xC0 | (RETRIES-1-ret)))

    with pytest.raises(APDUResponse) as e:
        device.login(WRONG_PIN)
    assert(e.value.sw == SWCodes.SW_PIN_BLOCKED.value)

    device.initialize(retries=RETRIES)
    retries = device.get_login_retries()
    assert(retries == RETRIES)


