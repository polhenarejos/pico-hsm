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
from utils import KeyType, DOPrefixes, Algorithm
from binascii import hexlify
import hashlib

data = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam neque urna, iaculis quis auctor scelerisque, auctor ut risus. In rhoncus, odio consequat consequat ultrices, ex libero dictum risus, accumsan interdum nisi orci ac neque. Ut vitae sem in metus hendrerit facilisis. Mauris maximus tristique mi, quis blandit lectus convallis eget.'


@pytest.mark.parametrize(
    "curve", ['secp192r1', 'secp256r1', 'secp384r1', 'secp521r1', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp256k1']
)
@pytest.mark.parametrize(
    "scheme", [Algorithm.ALGO_EC_RAW, Algorithm.ALGO_EC_SHA1, Algorithm.ALGO_EC_SHA224, Algorithm.ALGO_EC_SHA256, Algorithm.ALGO_EC_SHA384, Algorithm.ALGO_EC_SHA512]
)
def test_signature_ecc(device, curve, scheme):
    keyid = device.keypair_generation(KeyType.ECC, curve)
    pubkey = device.public_key(keyid=keyid, param=curve)
    if (scheme == Algorithm.ALGO_EC_RAW):
        datab = hashlib.sha512(data).digest()
    else:
        datab = data
    signature = device.sign(keyid=keyid, scheme=scheme, data=datab)
    device.delete_file(DOPrefixes.KEY_PREFIX.value << 8 | keyid)
    device.verify(pubkey, datab, signature, scheme)

@pytest.mark.parametrize(
    "modulus", [1024,2048,4096]
)
@pytest.mark.parametrize(
    "scheme", [Algorithm.ALGO_RSA_PKCS1_SHA1, Algorithm.ALGO_RSA_PKCS1_SHA224, Algorithm.ALGO_RSA_PKCS1_SHA256, Algorithm.ALGO_RSA_PKCS1_SHA384, Algorithm.ALGO_RSA_PKCS1_SHA512, Algorithm.ALGO_RSA_PSS_SHA1, Algorithm.ALGO_RSA_PSS_SHA224, Algorithm.ALGO_RSA_PSS_SHA256, Algorithm.ALGO_RSA_PSS_SHA384, Algorithm.ALGO_RSA_PSS_SHA512]
)
def test_signature_rsa(device, modulus, scheme):
    keyid = device.keypair_generation(KeyType.RSA, modulus)
    pubkey = device.public_key(keyid=keyid)
    signature = device.sign(keyid=keyid, scheme=scheme, data=data)
    device.delete_file(DOPrefixes.KEY_PREFIX.value << 8 | keyid)
    device.verify(pubkey, data, signature, scheme)

