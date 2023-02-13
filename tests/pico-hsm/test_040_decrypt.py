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
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

data = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam neque urna, iaculis quis auctor scelerisque, auctor ut risus. In rhoncus, odio consequat consequat ultrices, ex libero dictum risus, accumsan interdum nisi orci ac neque. Ut vitae sem in metus hendrerit facilisis. Mauris maximus tristique mi, quis blandit lectus convallis eget.'

@pytest.mark.parametrize(
    "modulus", [1024,2048,4096]
)
@pytest.mark.parametrize(
    "pad", [padding.PKCS1v15(), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )]
)
def test_decrypt_rsa(device, modulus, pad):

    keyid = device.keypair_generation(KeyType.RSA, modulus)
    pubkey = device.public_key(keyid=keyid)
    message = data[:(modulus//8)-100]
    ciphered = pubkey.encrypt(message, pad)
    datab = device.decrypt(keyid, ciphered, pad)
    device.delete_file(DOPrefixes.KEY_PREFIX.value << 8 | keyid)
    assert(datab == message)

