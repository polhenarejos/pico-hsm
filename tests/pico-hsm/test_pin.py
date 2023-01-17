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

PIN = '648219'

def test_pin(device):
    device.initialize(retries=3)
    retries = device.get_login_retries()
    assert(retries == 3)

    device.login(PIN)

    with pytest.raises(APDUResponse) as e:
        device.login('112233')
    assert(e.value.sw1 == 0x63 and e.value.sw2 == 0xC2)

    with pytest.raises(APDUResponse) as e:
        device.login('112233')
    assert(e.value.sw1 == 0x63 and e.value.sw2 == 0xC1)

    with pytest.raises(APDUResponse) as e:
        device.login('112233')
    assert(e.value.sw == SWCodes.SW_PIN_BLOCKED.value)

    device.initialize(retries=3)
    retries = device.get_login_retries()
    assert(retries == 3)


