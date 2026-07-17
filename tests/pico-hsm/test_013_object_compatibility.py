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

from picohsm import Algorithm, DOPrefixes, KeyType
from picokey import APDUResponse, SWCodes


HSM_OBJECT_PREFIX = 0xC7
BLOCK = b"v1-object-test!!"
SIGN_DATA = b"object compatibility signature"


def raw_send(device, command: int, p1: int = 0, p2: int = 0, data=None, ne=None):
    return device._PicoHSM__card.send(command=command, p1=p1, p2=p2, data=data, ne=ne, codes=[])


def read_binary_raw(device, fid: int):
    return raw_send(device, command=0xB1, p1=(fid >> 8) & 0xFF, p2=fid & 0xFF, data=[0x54, 0x02, 0x00, 0x00], ne=0)


def update_binary_raw(device, fid: int, data: bytes):
    if len(data) >= 0x80:
        raise ValueError("Test helper supports only short TLV lengths")
    payload = [0x54, 0x02, 0x00, 0x00, 0x53, len(data)] + list(data)
    return raw_send(device, command=0xD7, p1=(fid >> 8) & 0xFF, p2=fid & 0xFF, data=payload)


def select_file_raw(device, fid: int):
    return raw_send(device, command=0xA4, data=list(fid.to_bytes(2, "big")))


def delete_file_raw(device, fid: int):
    return raw_send(device, command=0xE4, data=list(fid.to_bytes(2, "big")))


def generate_aes_raw(device, key_id: int):
    return raw_send(device, command=0x48, p1=key_id, p2=0xB2)


def assert_aes_round_trip(device, key_id: int):
    ciphertext = device.cipher(Algorithm.ALGO_AES_CBC_ENCRYPT, key_id, BLOCK)
    assert device.cipher(Algorithm.ALGO_AES_CBC_DECRYPT, key_id, ciphertext) == BLOCK


def assert_hidden_object(device, key_id: int):
    physical_fid = (HSM_OBJECT_PREFIX << 8) | key_id
    keys = device.list_keys()
    assert keys.count((DOPrefixes.KEY_PREFIX, key_id)) == 1
    assert (HSM_OBJECT_PREFIX, key_id) not in keys

    with pytest.raises(APDUResponse) as error:
        read_binary_raw(device, physical_fid)
    assert error.value.sw == SWCodes.SW_SECURITY_STATUS_NOT_SATISFIED


def test_00_device_key_uses_persistent_legacy_slot(device):
    device.initialize()

    with pytest.raises(APDUResponse) as error:
        read_binary_raw(device, HSM_OBJECT_PREFIX << 8)
    assert error.value.sw == SWCodes.SW_FILE_NOT_FOUND

    device.initialize()
    with pytest.raises(APDUResponse) as error:
        read_binary_raw(device, HSM_OBJECT_PREFIX << 8)
    assert error.value.sw == SWCodes.SW_FILE_NOT_FOUND


def test_01_new_key_uses_hidden_v1_object_and_logical_key_id(device):
    device.initialize()
    key_id = device.key_generation(KeyType.AES, 256)
    physical_fid = (HSM_OBJECT_PREFIX << 8) | key_id

    assert_hidden_object(device, key_id)
    assert_aes_round_trip(device, key_id)

    device.delete_file(DOPrefixes.KEY_PREFIX, key_id)
    assert (DOPrefixes.KEY_PREFIX, key_id) not in device.list_keys()

    with pytest.raises(APDUResponse) as error:
        read_binary_raw(device, physical_fid)
    assert error.value.sw == SWCodes.SW_FILE_NOT_FOUND


def test_02_legacy_key_stays_legacy_until_deleted(device):
    device.initialize()
    key_id = 0x40
    logical_fid = (DOPrefixes.KEY_PREFIX << 8) | key_id
    physical_fid = (HSM_OBJECT_PREFIX << 8) | key_id

    # Pre-create the legacy FID so key replacement must preserve that layout.
    update_binary_raw(device, logical_fid, b"legacy-slot")
    generate_aes_raw(device, key_id)
    assert_aes_round_trip(device, key_id)

    with pytest.raises(APDUResponse) as error:
        read_binary_raw(device, logical_fid)
    assert error.value.sw == SWCodes.SW_SECURITY_STATUS_NOT_SATISFIED
    with pytest.raises(APDUResponse) as error:
        read_binary_raw(device, physical_fid)
    assert error.value.sw == SWCodes.SW_FILE_NOT_FOUND

    old_ciphertext = device.cipher(Algorithm.ALGO_AES_CBC_ENCRYPT, key_id, BLOCK)
    generate_aes_raw(device, key_id)
    assert device.cipher(Algorithm.ALGO_AES_CBC_DECRYPT, key_id, old_ciphertext) != BLOCK
    assert_aes_round_trip(device, key_id)
    with pytest.raises(APDUResponse) as error:
        read_binary_raw(device, physical_fid)
    assert error.value.sw == SWCodes.SW_FILE_NOT_FOUND

    device.delete_file(DOPrefixes.KEY_PREFIX, key_id)
    generate_aes_raw(device, key_id)
    assert_hidden_object(device, key_id)
    assert_aes_round_trip(device, key_id)
    device.delete_file(DOPrefixes.KEY_PREFIX, key_id)


def test_03_replacing_v1_key_keeps_one_logical_entry(device):
    device.initialize()
    key_id = device.key_generation(KeyType.AES, 256)
    old_ciphertext = device.cipher(Algorithm.ALGO_AES_CBC_ENCRYPT, key_id, BLOCK)

    generate_aes_raw(device, key_id)

    assert_hidden_object(device, key_id)
    assert device.cipher(Algorithm.ALGO_AES_CBC_DECRYPT, key_id, old_ciphertext) != BLOCK
    assert_aes_round_trip(device, key_id)
    device.delete_file(DOPrefixes.KEY_PREFIX, key_id)


def test_04_logical_metadata_policy_and_counter_work_for_v1_key(device):
    device.initialize()
    allowed = [Algorithm.ALGO_AES_CBC_ENCRYPT, Algorithm.ALGO_AES_CBC_DECRYPT]
    key_id = device.key_generation(KeyType.AES, 256, use_counter=2, algorithms=allowed)

    fci = device.select_file(DOPrefixes.KEY_PREFIX, key_id)
    assert bytes([0x83, 0x02, DOPrefixes.KEY_PREFIX, key_id]) in fci
    assert bytes([0x83, 0x02, HSM_OBJECT_PREFIX, key_id]) not in fci
    assert device.get_key_use_counter(key_id) == 2
    assert device.get_key_algorithms_list(key_id) == allowed

    with pytest.raises(APDUResponse) as error:
        device.cipher(Algorithm.ALGO_AES_CMAC, key_id, BLOCK)
    assert error.value.sw == SWCodes.SW_CONDITIONS_NOT_SATISFIED
    assert device.get_key_use_counter(key_id) == 2

    ciphertext = device.cipher(Algorithm.ALGO_AES_CBC_ENCRYPT, key_id, BLOCK)
    assert device.get_key_use_counter(key_id) == 1
    assert device.cipher(Algorithm.ALGO_AES_CBC_DECRYPT, key_id, ciphertext) == BLOCK
    assert device.get_key_use_counter(key_id) == 0

    with pytest.raises(APDUResponse) as error:
        device.cipher(Algorithm.ALGO_AES_CBC_ENCRYPT, key_id, BLOCK)
    assert error.value.sw == SWCodes.SW_FILE_FULL
    device.delete_file(DOPrefixes.KEY_PREFIX, key_id)


@pytest.mark.parametrize(
    "key_type,param,scheme",
    [
        (KeyType.ECC, "secp256r1", Algorithm.ALGO_EC_SHA256),
        (KeyType.RSA, 1024, Algorithm.ALGO_RSA_PKCS1_SHA256),
    ],
)
def test_05_asymmetric_v1_keys_sign_and_verify(device, key_type, param, scheme):
    device.initialize()
    key_id = device.key_generation(key_type, param)
    public_key = device.public_key(keyid=key_id, param=param if key_type == KeyType.ECC else None)

    signature = device.sign(keyid=key_id, scheme=scheme, data=SIGN_DATA)

    device.verify(public_key, SIGN_DATA, signature, scheme)
    assert_hidden_object(device, key_id)
    device.delete_file(DOPrefixes.KEY_PREFIX, key_id)
    device.delete_file(DOPrefixes.EE_CERTIFICATE_PREFIX, key_id)


def test_06_physical_namespace_and_device_key_are_not_mutable(device):
    device.initialize()
    key_id = device.key_generation(KeyType.AES, 256)
    physical_fid = (HSM_OBJECT_PREFIX << 8) | key_id

    with pytest.raises(APDUResponse) as error:
        select_file_raw(device, physical_fid)
    assert error.value.sw == SWCodes.SW_FILE_NOT_FOUND
    with pytest.raises(APDUResponse) as error:
        update_binary_raw(device, physical_fid, b"PKO1-malformed")
    assert error.value.sw == SWCodes.SW_SECURITY_STATUS_NOT_SATISFIED
    device.select_file(DOPrefixes.KEY_PREFIX, key_id)
    with pytest.raises(APDUResponse) as error:
        update_binary_raw(device, 0, b"PKO1-selected-malformed")
    assert error.value.sw == SWCodes.SW_SECURITY_STATUS_NOT_SATISFIED
    with pytest.raises(APDUResponse) as error:
        delete_file_raw(device, physical_fid)
    assert error.value.sw == SWCodes.SW_FILE_NOT_FOUND
    with pytest.raises(APDUResponse) as error:
        delete_file_raw(device, DOPrefixes.KEY_PREFIX << 8)
    assert error.value.sw == SWCodes.SW_SECURITY_STATUS_NOT_SATISFIED

    assert_hidden_object(device, key_id)
    assert_aes_round_trip(device, key_id)
    device.delete_file(DOPrefixes.KEY_PREFIX, key_id)


def test_07_legacy_and_v1_conflict_fails_closed(device):
    device.initialize()
    key_id = device.key_generation(KeyType.AES, 256)
    logical_fid = (DOPrefixes.KEY_PREFIX << 8) | key_id

    try:
        update_binary_raw(device, logical_fid, b"conflicting-legacy-record")
        assert device.list_keys().count((DOPrefixes.KEY_PREFIX, key_id)) == 1

        with pytest.raises(APDUResponse) as error:
            device.cipher(Algorithm.ALGO_AES_CBC_ENCRYPT, key_id, BLOCK)
        assert error.value.sw == SWCodes.SW_FILE_NOT_FOUND
        with pytest.raises(APDUResponse) as error:
            delete_file_raw(device, logical_fid)
        assert error.value.sw == SWCodes.SW_FILE_NOT_FOUND
    finally:
        device.initialize()
