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

from contextlib import suppress

import pytest

from picokey import APDUResponse
from picohsm.DO import DOPrefixes
from picohsm.const import DEFAULT_PIN


DATA_FILE_ID = (DOPrefixes.DATA_PREFIX << 8) | 0xF0
DEVICE_FLASH_SECTOR_SIZE = 4096
EMULATION_FLASH_SECTOR_SIZE = 16384
FLASH_CACHE_PAGES = 6
WRITE_CHUNK_SIZES = (509, 1021, 1801, 997)
READ_CHUNK_SIZES = (601, 1901, 1023)


def make_payload(size: int, seed: int = 0) -> bytes:
    return bytes((((index + seed) * 29) ^ ((index + seed) >> 3)) & 0xFF for index in range(size))


def update_binary(device, fid: int, offset: int, data: bytes) -> None:
    request = [0x54, 0x04] + list(offset.to_bytes(4, "big"))
    request += [0x53, 0x82] + list(len(data).to_bytes(2, "big")) + list(data)
    response = device.send(command=0xD7, p1=fid >> 8, p2=fid & 0xFF, data=request)

    assert response == b""


def write_file(device, fid: int, data: bytes) -> None:
    offset = 0
    chunk_index = 0
    while offset < len(data):
        chunk_size = min(WRITE_CHUNK_SIZES[chunk_index % len(WRITE_CHUNK_SIZES)], len(data) - offset)
        update_binary(device, fid, offset, data[offset:offset + chunk_size])
        offset += chunk_size
        chunk_index += 1


def read_binary(device, fid: int, offset: int, length: int) -> bytes:
    request = [0x54, 0x04] + list(offset.to_bytes(4, "big"))
    return device.send(command=0xB1, p1=fid >> 8, p2=fid & 0xFF, data=request, ne=length)


def read_file(device, fid: int, size: int) -> bytes:
    result = bytearray()
    offset = 0
    chunk_index = 0
    while offset < size:
        chunk_size = min(READ_CHUNK_SIZES[chunk_index % len(READ_CHUNK_SIZES)], size - offset)
        chunk = read_binary(device, fid, offset, chunk_size)

        assert len(chunk) == chunk_size

        result.extend(chunk)
        offset += chunk_size
        chunk_index += 1
    return bytes(result)


@pytest.fixture
def data_file(device):
    device.initialize()
    device.login(DEFAULT_PIN)
    yield device, DATA_FILE_ID

    with suppress(APDUResponse):
        device.delete_file(DATA_FILE_ID)


@pytest.mark.parametrize("size", (DEVICE_FLASH_SECTOR_SIZE - 1, DEVICE_FLASH_SECTOR_SIZE, DEVICE_FLASH_SECTOR_SIZE + 1, 0xFFFE, 0xFFFF, 0x10000))
def test_01_file_size_boundaries(data_file, size: int) -> None:
    device, fid = data_file
    expected = make_payload(size, seed=size)

    write_file(device, fid, expected)

    assert read_file(device, fid, size) == bytes(expected)
    assert read_binary(device, fid, size, 1) == b""


def test_02_file_larger_than_six_page_cache(data_file) -> None:
    device, fid = data_file
    size = EMULATION_FLASH_SECTOR_SIZE * FLASH_CACHE_PAGES + 21987
    expected = bytearray(make_payload(size, seed=0xA5))

    write_file(device, fid, bytes(expected))
    assert read_file(device, fid, size) == bytes(expected)

    patch_offsets = (
        DEVICE_FLASH_SECTOR_SIZE - 17,
        DEVICE_FLASH_SECTOR_SIZE * FLASH_CACHE_PAGES - 13,
        0xFFFF - 11,
        EMULATION_FLASH_SECTOR_SIZE * FLASH_CACHE_PAGES - 7,
    )
    for patch_index, offset in enumerate(patch_offsets):
        patch = make_payload(73, seed=0xC0 + patch_index)
        update_binary(device, fid, offset, patch)
        expected[offset:offset + len(patch)] = patch

    assert read_file(device, fid, size) == expected

    replacement = make_payload(DEVICE_FLASH_SECTOR_SIZE - 1, seed=0x5A)
    update_binary(device, fid, 0, replacement)

    assert read_file(device, fid, len(replacement)) == replacement
    assert read_binary(device, fid, len(replacement), 1) == b""
