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
from cryptography.hazmat.primitives.ciphers import aead
import cryptography.exceptions
from picohsm import APDUResponse, DOPrefixes, EncryptionMode, SWCodes
from picohsm.const import DEFAULT_DKEK_SHARES
from const import DEFAULT_DKEK
from binascii import hexlify

MESSAGE = b'a secret message'
AAD = b'this is a tag for AAD'

def test_prepare_chachapoly(device):
    device.initialize(dkek_shares=DEFAULT_DKEK_SHARES)
    resp = device.import_dkek(DEFAULT_DKEK)
    resp = device.import_dkek(DEFAULT_DKEK)

def generate_key(device):
     # ChaCha uses 32 bytes key
    pkey = os.urandom(256 // 8)
    keyid = device.import_key(pkey)
    return pkey, keyid


def test_cipher_chachapoly_cipher(device):
    iv = b'\x00'*12
    pkey, keyid = generate_key(device)

    ctd = device.chachapoly(keyid, EncryptionMode.ENCRYPT, data=MESSAGE, aad=AAD)

    chacha = aead.ChaCha20Poly1305(pkey)
    ctg = chacha.encrypt(iv, MESSAGE, AAD)
    assert(bytes(ctd) == ctg)

    pld = device.chachapoly(keyid, EncryptionMode.DECRYPT, data=ctd, aad=AAD)

    plg = chacha.decrypt(iv, ctg, AAD)
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
    assert(bytes(pld) == plg)
    assert(bytes(pld) == MESSAGE)

def test_cipher_chachapoly_random_iv(device):
    pkey, keyid = generate_key(device)
    iv = os.urandom(12)
    ctd = device.chachapoly(keyid, EncryptionMode.ENCRYPT, data=MESSAGE, iv=iv, aad=AAD)

    chacha = aead.ChaCha20Poly1305(pkey)
    ctg = chacha.encrypt(iv, MESSAGE, AAD)
    assert(bytes(ctd) == ctg)

    pld = device.chachapoly(keyid, EncryptionMode.DECRYPT, data=ctd, iv=iv, aad=AAD)

    plg = chacha.decrypt(iv, ctg, AAD)
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
    assert(bytes(pld) == plg)
    assert(bytes(pld) == MESSAGE)

def test_cipher_chachapoly_no_aad(device):
    pkey, keyid = generate_key(device)
    iv = os.urandom(12)
    ctd = device.chachapoly(keyid, EncryptionMode.ENCRYPT, data=MESSAGE, iv=iv)

    chacha = aead.ChaCha20Poly1305(pkey)
    ctg = chacha.encrypt(iv, MESSAGE, b'')
    assert(bytes(ctd) == ctg)

    pld = device.chachapoly(keyid, EncryptionMode.DECRYPT, data=ctd, iv=iv)

    plg = chacha.decrypt(iv, ctg, b'')
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
    assert(bytes(pld) == plg)
    assert(bytes(pld) == MESSAGE)

def test_cipher_chachapoly_bad_random_iv(device):
    pkey, keyid = generate_key(device)
    iv = os.urandom(12)
    ctd = device.chachapoly(keyid, EncryptionMode.ENCRYPT, data=MESSAGE, iv=iv, aad=AAD)

    chacha = aead.ChaCha20Poly1305(pkey)
    ctg = chacha.encrypt(iv, MESSAGE, AAD)
    assert(bytes(ctd) == ctg)

    iv = os.urandom(12)
    with pytest.raises(APDUResponse) as e:
        pld = device.chachapoly(keyid, EncryptionMode.DECRYPT, data=ctd, iv=iv, aad=AAD)
    assert (e.value.sw == SWCodes.SW_WRONG_DATA)

    with pytest.raises(cryptography.exceptions.InvalidTag):
        plg = chacha.decrypt(iv, ctg, AAD)
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)

def test_cipher_chachapoly_bad_aad(device):
    pkey, keyid = generate_key(device)
    iv = os.urandom(12)
    ctd = device.chachapoly(keyid, EncryptionMode.ENCRYPT, data=MESSAGE, iv=iv, aad=AAD)

    chacha = aead.ChaCha20Poly1305(pkey)
    ctg = chacha.encrypt(iv, MESSAGE, AAD)
    assert(bytes(ctd) == ctg)

    with pytest.raises(APDUResponse) as e:
        pld = device.chachapoly(keyid, EncryptionMode.DECRYPT, data=ctd, iv=iv, aad=AAD + b'bad')
    assert (e.value.sw == SWCodes.SW_WRONG_DATA)

    with pytest.raises(cryptography.exceptions.InvalidTag):
        plg = chacha.decrypt(iv, ctg, AAD + b'bad')
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
