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
from utils import KeyType, DOPrefixes, APDUResponse, SWCodes
from const import DEFAULT_DKEK

def test_initialize(device):
    device.initialize(key_domains=1)
    assert(device.get_key_domains() == 1)

    device.set_key_domain(key_domain=0, total=1)

keyid_in = -1
keyid_out = -1
def test_key_generation_no_key_domain(device):
    global keyid_out
    keyid_out = device.key_generation(KeyType.ECC, 'brainpoolP256r1')
    device.put_contents(p1=DOPrefixes.PRKD_PREFIX.value, p2=keyid_out, data=[0xA0])
    resp = device.list_keys()
    assert((DOPrefixes.KEY_PREFIX.value, keyid_out) in resp)
    assert((DOPrefixes.PRKD_PREFIX.value, keyid_out) in resp)

def test_key_generation_with_key_domain(device):
    global keyid_in
    keyid_in = device.key_generation(KeyType.ECC, 'brainpoolP256r1', key_domain=0)
    device.put_contents(p1=DOPrefixes.PRKD_PREFIX.value, p2=keyid_in, data=[0xA0])
    resp = device.list_keys()
    assert((DOPrefixes.KEY_PREFIX.value, keyid_in) in resp)
    assert((DOPrefixes.PRKD_PREFIX.value, keyid_in) in resp)

def test_export_key_out(device):
    with pytest.raises(APDUResponse) as e:
        device.export_key(keyid_out)
    assert(e.value.sw == SWCodes.SW_REFERENCE_NOT_FOUND.value)

def test_export_key_in_fail(device):
    with pytest.raises(APDUResponse) as e:
        device.export_key(keyid_in)
    assert(e.value.sw == SWCodes.SW_REFERENCE_NOT_FOUND.value)

def test_export_import_dkek(device):
    resp = device.import_dkek(DEFAULT_DKEK, key_domain=0)

def test_export_key_in_ok(device):
    resp = device.export_key(2)
