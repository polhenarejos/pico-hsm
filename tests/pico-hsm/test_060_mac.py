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
import os
from cryptography.hazmat.primitives import hashes, hmac, cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from picohsm import DOPrefixes
from picohsm.const import DEFAULT_DKEK_SHARES
from const import DEFAULT_DKEK

MESSAGE = b'a secret message'

def test_prepare_aes(device):
    device.initialize(dkek_shares=DEFAULT_DKEK_SHARES)
    resp = device.import_dkek(DEFAULT_DKEK)
    resp = device.import_dkek(DEFAULT_DKEK)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
@pytest.mark.parametrize(
    "algo", [hashes.SHA1, hashes.SHA224, hashes.SHA256, hashes.SHA384, hashes.SHA512]
)
def test_mac_hmac(device, size, algo):
    pkey = os.urandom(size // 8)
    keyid = device.import_key(pkey)
    resA = device.hmac(algo, keyid, MESSAGE)
    h = hmac.HMAC(pkey, algo())
    h.update(MESSAGE)
    resB = h.finalize()
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
    assert(resA == resB)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_mac_cmac(device, size):
    pkey = os.urandom(size // 8)
    keyid = device.import_key(pkey)
    resA = device.cmac(keyid, MESSAGE)
    c = cmac.CMAC(algorithms.AES(pkey))
    c.update(MESSAGE)
    resB = c.finalize()
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
    assert(resA == resB)

