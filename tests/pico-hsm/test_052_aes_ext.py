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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
import cryptography.exceptions
from picohsm import APDUResponse, DOPrefixes, EncryptionMode, SWCodes, AES
from picohsm.const import DEFAULT_DKEK_SHARES
from const import DEFAULT_DKEK
from binascii import hexlify

MESSAGE = b'a secret message'
AAD = b'this is a tag for AAD'

def test_prepare_aes(device):
    device.initialize(dkek_shares=DEFAULT_DKEK_SHARES)
    resp = device.import_dkek(DEFAULT_DKEK)
    resp = device.import_dkek(DEFAULT_DKEK)

def generate_key(device, size):
    pkey = os.urandom(size // 8)
    keyid = device.import_key(pkey)
    return pkey, keyid

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_aes_ecb(device, size):
    pkey, keyid = generate_key(device, size)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.ECB, MESSAGE)

    cipher = Cipher(algorithms.AES(pkey), modes.ECB())
    encryptor = cipher.encryptor()
    ctB = encryptor.update(MESSAGE) + encryptor.finalize()
    assert(ctA == ctB)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.ECB, ctA)
    decryptor = cipher.decryptor()
    dtB = decryptor.update(ctB) + decryptor.finalize()
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_aes_cbc_no_iv(device, size):
    pkey, keyid = generate_key(device, size)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.CBC, MESSAGE)

    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(pkey), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ctB = encryptor.update(MESSAGE) + encryptor.finalize()
    assert(ctA == ctB)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.CBC, ctA)
    decryptor = cipher.decryptor()
    dtB = decryptor.update(ctB) + decryptor.finalize()
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_aes_cbc_iv(device, size):
    pkey, keyid = generate_key(device, size)
    iv = os.urandom(16)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.CBC, MESSAGE, iv=iv)

    cipher = Cipher(algorithms.AES(pkey), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ctB = encryptor.update(MESSAGE) + encryptor.finalize()
    assert(ctA == ctB)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.CBC, ctA, iv=iv)
    decryptor = cipher.decryptor()
    dtB = decryptor.update(ctB) + decryptor.finalize()
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_aes_ofb_no_iv(device, size):
    pkey, keyid = generate_key(device, size)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.OFB, MESSAGE)

    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(pkey), modes.OFB(iv))
    encryptor = cipher.encryptor()
    ctB = encryptor.update(MESSAGE) + encryptor.finalize()
    assert(ctA == ctB)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.OFB, ctA)
    decryptor = cipher.decryptor()
    dtB = decryptor.update(ctB) + decryptor.finalize()
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_aes_ofb_iv(device, size):
    pkey, keyid = generate_key(device, size)
    iv = os.urandom(16)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.OFB, MESSAGE, iv=iv)

    cipher = Cipher(algorithms.AES(pkey), modes.OFB(iv))
    encryptor = cipher.encryptor()
    ctB = encryptor.update(MESSAGE) + encryptor.finalize()
    assert(ctA == ctB)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.OFB, ctA, iv=iv)
    decryptor = cipher.decryptor()
    dtB = decryptor.update(ctB) + decryptor.finalize()
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_aes_cfb_no_iv(device, size):
    pkey, keyid = generate_key(device, size)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.CFB, MESSAGE)

    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(pkey), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ctB = encryptor.update(MESSAGE) + encryptor.finalize()
    assert(ctA == ctB)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.CFB, ctA)
    decryptor = cipher.decryptor()
    dtB = decryptor.update(ctB) + decryptor.finalize()
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_aes_cfb_iv(device, size):
    pkey, keyid = generate_key(device, size)
    iv = os.urandom(16)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.CFB, MESSAGE, iv=iv)

    cipher = Cipher(algorithms.AES(pkey), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ctB = encryptor.update(MESSAGE) + encryptor.finalize()
    assert(ctA == ctB)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.CFB, ctA, iv=iv)
    decryptor = cipher.decryptor()
    dtB = decryptor.update(ctB) + decryptor.finalize()
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_aes_gcm_no_iv(device, size):
    pkey, keyid = generate_key(device, size)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.GCM, MESSAGE, aad=AAD)

    iv = b'\x00' * 16
    encryptor = Cipher(algorithms.AES(pkey), modes.GCM(iv)).encryptor()
    encryptor.authenticate_additional_data(AAD)
    ctB = encryptor.update(MESSAGE) + encryptor.finalize()
    assert(ctA == ctB + encryptor.tag)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.GCM, ctA, aad=AAD)
    decryptor = Cipher(algorithms.AES(pkey), modes.GCM(iv, encryptor.tag)).decryptor()
    decryptor.authenticate_additional_data(AAD)
    dtB = decryptor.update(ctB) + decryptor.finalize()
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_aes_gcm_iv(device, size):
    pkey, keyid = generate_key(device, size)
    iv = os.urandom(16)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.GCM, MESSAGE, iv=iv, aad=AAD)

    encryptor = Cipher(algorithms.AES(pkey), modes.GCM(iv)).encryptor()
    encryptor.authenticate_additional_data(AAD)
    ctB = encryptor.update(MESSAGE) + encryptor.finalize()
    assert(ctA == ctB + encryptor.tag)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.GCM, ctA, iv=iv, aad=AAD)
    decryptor = Cipher(algorithms.AES(pkey), modes.GCM(iv, encryptor.tag)).decryptor()
    decryptor.authenticate_additional_data(AAD)
    dtB = decryptor.update(ctB) + decryptor.finalize()
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [256, 512]
)
def test_aes_xts_no_iv(device, size):
    pkey, keyid = generate_key(device, size)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.XTS, MESSAGE)

    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(pkey), modes.XTS(iv))
    encryptor = cipher.encryptor()
    ctB = encryptor.update(MESSAGE) + encryptor.finalize()
    assert(ctA == ctB)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.XTS, ctA)
    decryptor = cipher.decryptor()
    dtB = decryptor.update(ctB) + decryptor.finalize()
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [256, 512]
)
def test_aes_xts_iv(device, size):
    pkey, keyid = generate_key(device, size)
    iv = os.urandom(16)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.XTS, MESSAGE, iv=iv)

    cipher = Cipher(algorithms.AES(pkey), modes.XTS(iv))
    encryptor = cipher.encryptor()
    ctB = encryptor.update(MESSAGE) + encryptor.finalize()
    assert(ctA == ctB)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.XTS, ctA, iv=iv)
    decryptor = cipher.decryptor()
    dtB = decryptor.update(ctB) + decryptor.finalize()
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_aes_ctr_no_iv(device, size):
    pkey, keyid = generate_key(device, size)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.CTR, MESSAGE)

    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(pkey), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ctB = encryptor.update(MESSAGE) + encryptor.finalize()
    assert(ctA == ctB)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.CTR, ctA)
    decryptor = cipher.decryptor()
    dtB = decryptor.update(ctB) + decryptor.finalize()
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_aes_ctr_iv(device, size):
    pkey, keyid = generate_key(device, size)
    iv = os.urandom(16)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.CTR, MESSAGE, iv=iv)

    cipher = Cipher(algorithms.AES(pkey), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ctB = encryptor.update(MESSAGE) + encryptor.finalize()
    assert(ctA == ctB)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.CTR, ctA, iv=iv)
    decryptor = cipher.decryptor()
    dtB = decryptor.update(ctB) + decryptor.finalize()
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
def test_aes_ccm_no_iv(device, size):
    pkey, keyid = generate_key(device, size)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.CCM, MESSAGE, aad=AAD)

    iv = b'\x00' * 12
    encryptor = aead.AESCCM(pkey)
    ctB = encryptor.encrypt(iv, MESSAGE, AAD)
    assert(ctA == ctB)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.CCM, ctA, aad=AAD)
    decryptor = encryptor
    dtB = decryptor.decrypt(iv, ctB, AAD)
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)

@pytest.mark.parametrize(
    "size", [128, 192, 256]
)
@pytest.mark.parametrize(
    "iv_len", [7, 8, 9, 10, 11, 12, 13]
)
def test_aes_ccm_iv(device, size, iv_len):
    pkey, keyid = generate_key(device, size)
    iv = os.urandom(iv_len)
    ctA = device.aes(keyid, EncryptionMode.ENCRYPT, AES.CCM, MESSAGE, iv=iv, aad=AAD)

    encryptor = aead.AESCCM(pkey)
    ctB = encryptor.encrypt(iv, MESSAGE, AAD)
    assert(ctA == ctB)

    dtA = device.aes(keyid, EncryptionMode.DECRYPT, AES.CCM, ctA, iv=iv, aad=AAD)
    decryptor = encryptor
    dtB = decryptor.decrypt(iv, ctB, AAD)
    assert(dtA == dtB)
    assert(dtA == MESSAGE)
    device.delete_key(keyid)
