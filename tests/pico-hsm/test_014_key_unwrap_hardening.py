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

Regression tests for the UNWRAP KEY (INS 0x74) blob parser hardening in
kek.c:dkek_decode_key(). A wrapped-key blob carries a DKEK-keyed CMAC, so only
a DKEK holder can produce one that authenticates -- but the length fields inside
the blob are still attacker-authored. Historically the parser trusted those
lengths: an oversized declared AES key size drove a memcpy() straight past the
64-byte stack buffer in cmd_key_unwrap, an oversized header field ran the offset
past the input, and a short blob underflowed the CMAC length. These tests forge
blobs with a *valid* CMAC (the emulator's DKEK is all-zero after importing the
[1]*32 share twice) and assert the firmware now rejects each with a clean status
word and stays responsive, rather than crashing.
"""

import hashlib
import os
import struct

import pytest

from picokey import APDUResponse
from picohsm.DO import DOPrefixes
from picohsm.const import DEFAULT_PIN, DEFAULT_RETRIES, DEFAULT_DKEK_SHARES
from const import DEFAULT_DKEK
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Effective device DKEK for key domain 0 after importing DEFAULT_DKEK ([1]*32)
# twice: 0x01 XOR 0x01 == 0x00 for every byte.
ZERO_DKEK = b"\x00" * 32
AES_OID = b"\x00\x08\x60\x86\x48\x01\x65\x03\x04\x01"
INS_UNWRAP = 0x74


def _dkek_keys(dkek=ZERO_DKEK):
    kcv = hashlib.sha256(dkek).digest()[:8]
    kenc = hashlib.sha256(dkek + b"\x00\x00\x00\x01").digest()
    kmac = hashlib.sha256(dkek + b"\x00\x00\x00\x02").digest()
    return kcv, kenc, kmac


def _seal(header, kb_plain, dkek=ZERO_DKEK):
    """Encrypt the key body under KENC and append the DKEK CMAC, exactly as a
    legitimate host wrapper would -- so the resulting blob authenticates and the
    firmware reaches the field parser under test."""
    assert len(kb_plain) % 16 == 0
    _, kenc, kmac = _dkek_keys(dkek)
    enc = Cipher(algorithms.AES(kenc), modes.CBC(b"\x00" * 16)).encryptor()
    ct = enc.update(kb_plain) + enc.finalize()
    blob = header + ct
    c = cmac.CMAC(algorithms.AES(kmac))
    c.update(blob)
    return blob + c.finalize()


def _aes_header(fields=b"\x00" * 6):
    # kcv || type(0x0F=AES) || algo OID || {allowed, access, keyOID} length-TLVs
    kcv, _, _ = _dkek_keys()
    return kcv + b"\x0F" + AES_OID + fields


def _aes_kb(declared_size, key_body):
    # 8 random bytes || 2-byte declared key size || key || zero pad to a block.
    kb = os.urandom(8) + struct.pack(">H", declared_size) + key_body
    kb += b"\x00" * ((-len(kb)) % 16)
    return kb


def _prepare(device):
    device.initialize(retries=DEFAULT_RETRIES, dkek_shares=DEFAULT_DKEK_SHARES)
    device.login(DEFAULT_PIN)
    device.import_dkek(DEFAULT_DKEK)
    device.import_dkek(DEFAULT_DKEK)
    # Sanity: the reconstructed DKEK matches ZERO_DKEK's check value.
    assert hashlib.sha256(ZERO_DKEK).digest()[:8] == _dkek_keys()[0]


def _raw_unwrap(device, blob):
    # Low-level transport so an error SW surfaces as APDUResponse rather than the
    # auto PIN-retry path in PicoHSM.send.
    free = device.get_first_free_id()
    return device._PicoHSM__card.send(
        command=INS_UNWRAP, cla=0x80, p1=free, p2=0x93, data=list(blob), codes=[]
    )


def test_00_wellformed_manual_wrap_roundtrips(device):
    # Anchor test: proves the hand-rolled sealer matches what the device expects,
    # so the rejection tests below fail for the right reason (bad structure), not
    # a MAC/KCV mismatch.
    _prepare(device)
    key = os.urandom(32)
    blob = _seal(_aes_header(), _aes_kb(32, key))
    free = device.get_first_free_id()
    _, sw = device._PicoHSM__card.send(
        command=INS_UNWRAP, cla=0x80, p1=free, p2=0x93, data=list(blob), codes=[]
    )
    assert sw == 0x9000
    device.delete_file(DOPrefixes.KEY_PREFIX, free)


def test_01_oversized_aes_key_size_rejected(device):
    # Finding #1 (AES branch): declared key size 0x0400 with a 16-byte body would
    # have memcpy'd 1024 bytes into the caller's aes_key[64] stack buffer.
    _prepare(device)
    blob = _seal(_aes_header(), _aes_kb(0x0400, os.urandom(16)))
    with pytest.raises(APDUResponse):
        _raw_unwrap(device, blob)
    assert device.get_version() > 0


def test_02_oversized_header_field_rejected(device):
    # Finding #1 (header walk): an allowed-algorithms length of 0xFFFF with no
    # value runs the offset past the input and makes (in_len - 16 - ofs) go
    # negative.
    _prepare(device)
    header = _dkek_keys()[0] + b"\x0F" + AES_OID + struct.pack(">H", 0xFFFF)
    blob = _seal(header, _aes_kb(32, os.urandom(32)))
    with pytest.raises(APDUResponse):
        _raw_unwrap(device, blob)
    assert device.get_version() > 0


def test_03_truncated_blob_rejected(device):
    # Finding #1 (length guard): a blob shorter than the fixed header + CMAC tag
    # would have driven the CMAC length (in_len - 16) below zero.
    _prepare(device)
    blob = _dkek_keys()[0] + b"\x0F" + b"\x00\x00\x00"  # 12 bytes total
    with pytest.raises(APDUResponse):
        _raw_unwrap(device, blob)
    assert device.get_version() > 0
