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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from picohsm import Algorithm, DOPrefixes
from picohsm.const import DEFAULT_DKEK_SHARES
from const import DEFAULT_DKEK

MESSAGE = b'a secret message'

def test_prepare_aes(device):
    device.initialize(dkek_shares=DEFAULT_DKEK_SHARES, no_dev_cert=True)
    resp = device.import_dkek(DEFAULT_DKEK)
    resp = device.import_dkek(DEFAULT_DKEK)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_cipher_aes_cipher(device, size):
    pkey = os.urandom(size // 8)
    iv = b'\x00'*16
    keyid = device.import_key(pkey)

    cipher = Cipher(algorithms.AES(pkey), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ctA = encryptor.update(MESSAGE) + encryptor.finalize()
    ctB = device.cipher(Algorithm.ALGO_AES_CBC_ENCRYPT, keyid, MESSAGE)
    assert(ctB == ctA)

    decryptor = cipher.decryptor()
    plA = decryptor.update(ctA) + decryptor.finalize()
    plB = device.cipher(Algorithm.ALGO_AES_CBC_DECRYPT, keyid, ctA)
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
    assert(plB == plA)
    assert(plB == MESSAGE)
