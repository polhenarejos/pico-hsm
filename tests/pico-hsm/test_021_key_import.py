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
import os
from picohsm import DOPrefixes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519, x448
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from picohsm.const import DEFAULT_RETRIES, DEFAULT_DKEK_SHARES
from const import DEFAULT_DKEK

def test_prepare_dkek(device):
    device.initialize(retries=DEFAULT_RETRIES, dkek_shares=DEFAULT_DKEK_SHARES)
    resp = device.import_dkek(DEFAULT_DKEK)
    resp = device.import_dkek(DEFAULT_DKEK)
    kcv = hashlib.sha256(b'\x00'*32).digest()[:8]
    assert(resp[2:] == kcv)

@pytest.mark.parametrize(
    "modulus", [1024, 2048, 4096]
)
def test_import_rsa(device, modulus):
    pkey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=modulus,
    )
    keyid = device.import_key(pkey)
    pubkey = device.public_key(keyid)
    assert(pubkey.public_numbers() == pkey.public_key().public_numbers())
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
    device.delete_file(DOPrefixes.EE_CERTIFICATE_PREFIX, keyid)


@pytest.mark.parametrize(
    "curve", [ec.SECP192R1, ec.SECP256R1, ec.SECP384R1, ec.SECP521R1, ec.SECP256K1, ec.BrainpoolP256R1, ec.BrainpoolP384R1, ec.BrainpoolP512R1]
)
def test_import_ecc(device, curve):
    pkey = ec.generate_private_key(curve())
    keyid = device.import_key(pkey)
    pubkey = device.public_key(keyid, param=curve().name)
    assert(pubkey.public_numbers() == pkey.public_key().public_numbers())
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
    device.delete_file(DOPrefixes.EE_CERTIFICATE_PREFIX, keyid)

@pytest.mark.parametrize(
    "curve", [x25519.X25519PrivateKey, x448.X448PrivateKey]
)
def test_import_montgomery(device, curve):
    pkey = curve.generate()
    keyid = device.import_key(pkey)
    pubkey = device.public_key(keyid, param=curve)
    assert(pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw) == pkey.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
    device.delete_file(DOPrefixes.EE_CERTIFICATE_PREFIX, keyid)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_import_aes(device, size):
    pkey = os.urandom(size // 8)
    keyid = device.import_key(pkey)
