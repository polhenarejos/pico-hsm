"""
/*
 * This file is part of the Pico HSM distribution (https://github.com/polhenarejos/pico-hsm).
 * Copyright (c) 2023 Pol Henarejos.
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
from picohsm import KeyType, DOPrefixes
from picokey import APDUResponse, SWCodes
from binascii import hexlify
import hashlib
from const import DEFAULT_DKEK
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def test_initialize(device):
    device.initialize(key_domains=1)
    assert(device.get_key_domains() == 1)

    device.set_key_domain(key_domain=0, total=2)

keyid_in = -1
keyid_out = -1
def test_key_generation_no_key_domain(device):
    global keyid_out
    keyid_out = device.key_generation(KeyType.ECC, 'brainpoolP256r1')
    device.put_contents(p1=DOPrefixes.PRKD_PREFIX, p2=keyid_out, data=[0xA0])
    resp = device.list_keys()
    assert((DOPrefixes.KEY_PREFIX, keyid_out) in resp)
    assert((DOPrefixes.PRKD_PREFIX, keyid_out) in resp)

def test_key_generation_with_key_domain(device):
    global keyid_in
    keyid_in = device.key_generation(KeyType.ECC, 'brainpoolP256r1', key_domain=0)
    device.put_contents(p1=DOPrefixes.PRKD_PREFIX, p2=keyid_in, data=[0xA0])
    resp = device.list_keys()
    assert((DOPrefixes.KEY_PREFIX, keyid_in) in resp)
    assert((DOPrefixes.PRKD_PREFIX, keyid_in) in resp)

def test_export_key_out(device):
    with pytest.raises(APDUResponse) as e:
        device.export_key(keyid_out)
    assert(e.value.sw == SWCodes.SW_REFERENCE_NOT_FOUND)

def test_export_key_in_fail(device):
    with pytest.raises(APDUResponse) as e:
        device.export_key(keyid_in)
    assert(e.value.sw == SWCodes.SW_REFERENCE_NOT_FOUND)

def test_export_import_dkek(device):
    resp = device.import_dkek(DEFAULT_DKEK, key_domain=0)
    resp = device.import_dkek(DEFAULT_DKEK, key_domain=0)

def test_export_key_in_ok(device):
    resp = device.export_key(keyid_in)
    kcv = hashlib.sha256(b'\x00'*32).digest()[:8]
    assert(kcv == resp[:8])
    assert(resp[8] == 12)
    assert(resp[9:21] == b"\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x02\x03")

    pkey = hashlib.sha256(b'\x00'*32+b'\x00\x00\x00\x02').digest()
    c = cmac.CMAC(algorithms.AES(pkey))
    c.update(resp[:-16])
    resCMAC = c.finalize()
    assert(resCMAC == resp[-16:])

def test_delete_keys_in_out(device):
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid_in)
    device.delete_file(DOPrefixes.EE_CERTIFICATE_PREFIX, keyid_in)
    device.delete_file(DOPrefixes.KEY_PREFIX, keyid_out)
    device.delete_file(DOPrefixes.EE_CERTIFICATE_PREFIX, keyid_out)

def test_export_import(device):
    pkey_gen = ec.generate_private_key(ec.BrainpoolP256R1())
    keyid = device.import_key(pkey_gen)

    resp = device.export_key(keyid)
    kcv = hashlib.sha256(b'\x00'*32).digest()[:8]
    assert(kcv == resp[:8])
    assert(resp[8] == 12)
    assert(resp[9:21] == b"\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x02\x03")

    pkey = hashlib.sha256(b'\x00'*32+b'\x00\x00\x00\x02').digest()
    c = cmac.CMAC(algorithms.AES(pkey))
    c.update(resp[:-16])
    resCMAC = c.finalize()
    assert(resCMAC == resp[-16:])

    iv = b'\x00'*16
    pkey = hashlib.sha256(b'\x00'*32+b'\x00\x00\x00\x01').digest()
    cipher = Cipher(algorithms.AES(pkey), modes.CBC(iv))
    decryptor = cipher.decryptor()
    payload = decryptor.update(resp[27:-16]) + decryptor.finalize()

    rnd = payload[:8]
    ofs = 8
    key_size = int.from_bytes(payload[ofs:ofs+2], 'big')
    ofs += 2
    A_len = int.from_bytes(payload[ofs:ofs+2], 'big')
    ofs += 2+A_len
    B_len = int.from_bytes(payload[ofs:ofs+2], 'big')
    ofs += 2+B_len
    P_len = int.from_bytes(payload[ofs:ofs+2], 'big')
    ofs += 2+P_len
    N_len = int.from_bytes(payload[ofs:ofs+2], 'big')
    ofs += 2+N_len
    G_len = int.from_bytes(payload[ofs:ofs+2], 'big')
    ofs += 2+G_len
    d_len = int.from_bytes(payload[ofs:ofs+2], 'big')
    ofs += 2
    d = payload[ofs:ofs+d_len]
    ofs += d_len
    Q_len = int.from_bytes(payload[ofs:ofs+2], 'big')
    ofs += 2
    Q = payload[ofs:ofs+Q_len]
    ofs += Q_len

    pkey_ex = ec.EllipticCurvePrivateNumbers(int.from_bytes(d, 'big'), ec.EllipticCurvePublicKey.from_encoded_point(ec.BrainpoolP256R1(), Q).public_numbers()).private_key()
    assert(pkey_gen.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()) == pkey_ex.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    assert(pkey_gen.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint) == pkey_ex.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))

    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
    device.delete_file(DOPrefixes.EE_CERTIFICATE_PREFIX, keyid)
