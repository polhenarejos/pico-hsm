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
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import exceptions
from picohsm.const import DEFAULT_DKEK_SHARES
from const import DEFAULT_DKEK
from picohsm import DOPrefixes

INFO = b'info message'

def test_prepare_kd(device):
    device.initialize(dkek_shares=DEFAULT_DKEK_SHARES, no_dev_cert=True)
    resp = device.import_dkek(DEFAULT_DKEK)
    resp = device.import_dkek(DEFAULT_DKEK)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
@pytest.mark.parametrize(
    "algo", [hashes.SHA256, hashes.SHA384, hashes.SHA512]
)
@pytest.mark.parametrize(
    "out_len", [32, 64, 256, 1024]
)
class TestHKDF:
    def test_hkdf_ok(self, device, size, algo, out_len):
        pkey = os.urandom(size // 8)
        keyid = device.import_key(pkey)
        salt = os.urandom(16)
        resA = device.hkdf(algo, keyid, INFO, salt, out_len=out_len)
        device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
        hkdf = HKDF(
            algorithm=algo(),
            length=out_len,
            salt=salt,
            info=INFO,
        )
        resB = hkdf.derive(pkey)
        assert(resA == resB)
        hkdf = HKDF(
            algorithm=algo(),
            length=out_len,
            salt=salt,
            info=INFO,
        )
        hkdf.verify(pkey, resA)

    def test_hkdf_fail(self, device, size, algo, out_len):
        pkey = os.urandom(size // 8)
        keyid = device.import_key(pkey)
        salt = os.urandom(16)
        resA = device.hkdf(algo, keyid, INFO, salt, out_len=out_len)
        device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
        hkdf = HKDF(
            algorithm=algo(),
            length=out_len,
            salt=salt,
            info=INFO,
        )
        pkey = os.urandom(size // 8)
        with pytest.raises(exceptions.InvalidKey):
            hkdf.verify(pkey, resA)
