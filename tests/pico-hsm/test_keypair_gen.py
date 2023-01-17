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
from utils import KeyType, DOPrefixes

@pytest.mark.parametrize(
    "curve", ['secp192r1', 'secp256r1', 'secp384r1', 'secp521r1', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp192k1', 'secp256k1']
)
def test_gen_ecc(device, curve):
    keyid = device.keypair_generation(KeyType.ECC, curve)
    resp = device.list_keys()
    assert((DOPrefixes.KEY_PREFIX.value, keyid) in resp)
    device.delete_file(DOPrefixes.KEY_PREFIX.value << 8 | keyid)

@pytest.mark.parametrize(
    "modulus", [1024, 2048, 4096]
)
def test_gen_rsa(device, modulus):
    keyid = device.keypair_generation(KeyType.RSA, modulus)
    resp = device.list_keys()
    assert((DOPrefixes.KEY_PREFIX.value, keyid) in resp)
    device.delete_file(DOPrefixes.KEY_PREFIX.value << 8 | keyid)

