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
from picohsm import DOPrefixes
from cryptography.hazmat.primitives.asymmetric import ec, x25519, x448
from picohsm.const import DEFAULT_RETRIES, DEFAULT_DKEK_SHARES
from const import DEFAULT_DKEK

def test_prepare_dkek(device):
    device.initialize(retries=DEFAULT_RETRIES, dkek_shares=DEFAULT_DKEK_SHARES)
    resp = device.import_dkek(DEFAULT_DKEK)
    resp = device.import_dkek(DEFAULT_DKEK)
    kcv = hashlib.sha256(b'\x00'*32).digest()[:8]
    assert(resp[2:] == kcv)

@pytest.mark.parametrize(
    "curve", [ec.SECP192R1, ec.SECP256R1, ec.SECP384R1, ec.SECP521R1, ec.SECP256K1, ec.BrainpoolP256R1, ec.BrainpoolP384R1, ec.BrainpoolP512R1]
)
def test_exchange_ecc(device, curve):
    pkeyA = ec.generate_private_key(curve())
    pbkeyA = pkeyA.public_key()
    keyid = device.import_key(pkeyA)
    pkeyB = ec.generate_private_key(curve())
    pbkeyB = pkeyB.public_key()

    sharedB = pkeyB.exchange(ec.ECDH(), pbkeyA)
    sharedA = device.exchange(keyid, pbkeyB)

    assert(sharedA == sharedB)

    sharedAA = pkeyA.exchange(ec.ECDH(), pbkeyB)
    assert(sharedA == sharedAA)

    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
    device.delete_file(DOPrefixes.EE_CERTIFICATE_PREFIX, keyid)

@pytest.mark.parametrize(
    "curve", [x25519.X25519PrivateKey, x448.X448PrivateKey]
)
def test_exchange_montgomery(device, curve):
    pkeyA = curve.generate()
    pbkeyA = pkeyA.public_key()
    keyid = device.import_key(pkeyA)
    pkeyB = curve.generate()
    pbkeyB = pkeyB.public_key()

    sharedB = pkeyB.exchange(pbkeyA)
    sharedA = device.exchange(keyid, pbkeyB)

    assert(sharedA == sharedB)

    sharedAA = pkeyA.exchange(pbkeyB)
    assert(sharedA == sharedAA)

    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
    device.delete_file(DOPrefixes.EE_CERTIFICATE_PREFIX, keyid)
