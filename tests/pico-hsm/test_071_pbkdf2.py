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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography import exceptions
from picohsm.const import DEFAULT_DKEK_SHARES
from const import DEFAULT_DKEK
from picohsm import DOPrefixes

INFO = b'info message'

def test_prepare_kd(device):
    device.initialize(dkek_shares=DEFAULT_DKEK_SHARES)
    resp = device.import_dkek(DEFAULT_DKEK)
    resp = device.import_dkek(DEFAULT_DKEK)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
@pytest.mark.parametrize(
    "algo", [hashes.SHA1, hashes.SHA224, hashes.SHA256, hashes.SHA384, hashes.SHA512]
)
@pytest.mark.parametrize(
    "out_len", [32, 64, 256, 1024]
)
@pytest.mark.parametrize(
    "iterations", [1024, 2048]
)
class TestPBKDF2:
    def test_pbkdf2_ok(self, device, size, algo, out_len, iterations):
        pkey = os.urandom(size // 8)
        keyid = device.import_key(pkey)
        salt = os.urandom(16)
        resA = device.pbkdf2(algo, keyid, salt, iterations=iterations, out_len=out_len)
        device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
        kdf = PBKDF2HMAC(
            algorithm=algo(),
            length=out_len,
            salt=salt,
            iterations=iterations,
        )
        resB = kdf.derive(pkey)
        assert(resA == resB)
        kdf = PBKDF2HMAC(
            algorithm=algo(),
            length=out_len,
            salt=salt,
            iterations=iterations,
        )
        kdf.verify(pkey, resA)

    def test_pbkdf2_fail(self, device, size, algo, out_len, iterations):
        pkey = os.urandom(size // 8)
        keyid = device.import_key(pkey)
        salt = os.urandom(16)
        resA = device.pbkdf2(algo, keyid, salt, iterations=iterations, out_len=out_len)
        device.delete_file(DOPrefixes.KEY_PREFIX, keyid)

        kdf = PBKDF2HMAC(
            algorithm=algo(),
            length=out_len,
            salt=salt,
            iterations=iterations,
        )
        pkey = os.urandom(size // 8)
        with pytest.raises(exceptions.InvalidKey):
            kdf.verify(pkey, resA)
