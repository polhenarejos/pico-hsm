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
from picohsm import KeyType, DOPrefixes

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_gen_aes(device, size):
    keyid = device.key_generation(KeyType.AES, size)
    resp = device.list_keys()
    assert((DOPrefixes.KEY_PREFIX, keyid) in resp)
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
