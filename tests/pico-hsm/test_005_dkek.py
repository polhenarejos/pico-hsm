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
import hashlib
from picohsm.const import DEFAULT_DKEK_SHARES, DEFAULT_PIN, DEFAULT_RETRIES
from const import  DEFAULT_DKEK

def test_dkek(device):
    device.initialize(retries=DEFAULT_RETRIES, dkek_shares=DEFAULT_DKEK_SHARES)
    device.login(DEFAULT_PIN)
    resp = device.import_dkek(DEFAULT_DKEK)
    assert(resp[0] == DEFAULT_DKEK_SHARES)
    assert(resp[1] == DEFAULT_DKEK_SHARES-1)

    resp = device.import_dkek(DEFAULT_DKEK)
    assert(resp[1] == DEFAULT_DKEK_SHARES-2)

    kcv = hashlib.sha256(b'\x00'*32).digest()[:8]
    assert(bytes(resp[2:]) == kcv)

