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
from const import DEFAULT_DKEK
from picohsm import APDUResponse, SWCodes
from picohsm.const import DEFAULT_DKEK_SHARES

KEY_DOMAINS = 3
TEST_KEY_DOMAIN = 1

def test_key_domains(device):
    device.initialize(key_domains=KEY_DOMAINS)
    for k in range(KEY_DOMAINS):
        kd = device.get_key_domain(key_domain=k)
        assert('error' in kd)
        assert(kd['error'] == 0x6A88)

    kd = device.get_key_domain(key_domain=KEY_DOMAINS)
    assert('error' in kd)
    assert(kd['error'] == 0x6A86)
    assert(device.get_key_domains() == KEY_DOMAINS)

def test_import_dkek_wrong_key_domain(device):
    with pytest.raises(APDUResponse) as e:
        device.import_dkek(DEFAULT_DKEK, key_domain=0)
    assert(e.value.sw == SWCodes.SW_COMMAND_NOT_ALLOWED)

def test_import_dkek_fail(device):
    with pytest.raises(APDUResponse) as e:
        device.import_dkek(DEFAULT_DKEK, key_domain=TEST_KEY_DOMAIN)
    assert(e.value.sw == SWCodes.SW_COMMAND_NOT_ALLOWED)

def test_set_key_domain_fail(device):
    with pytest.raises(APDUResponse) as e:
        device.set_key_domain(key_domain=10)
    assert(e.value.sw == SWCodes.SW_INCORRECT_P1P2)

def test_set_key_domain_ok(device):
    kd = device.get_key_domain(key_domain=TEST_KEY_DOMAIN)
    assert('error' in kd)
    assert(kd['error'] == 0x6A88)

    device.set_key_domain(key_domain=TEST_KEY_DOMAIN)
    kd = device.get_key_domain(key_domain=TEST_KEY_DOMAIN)
    assert('error' not in kd)
    assert('dkek' in kd)
    assert('total' in kd['dkek'])
    assert(kd['dkek']['total'] == DEFAULT_DKEK_SHARES)
    assert('missing' in kd['dkek'])
    assert(kd['dkek']['missing'] == DEFAULT_DKEK_SHARES)

def test_import_dkek_ok(device):
    resp = device.import_dkek(DEFAULT_DKEK, key_domain=TEST_KEY_DOMAIN)
    assert(resp[0] == DEFAULT_DKEK_SHARES)
    assert(resp[1] == DEFAULT_DKEK_SHARES-1)

    resp = device.import_dkek(DEFAULT_DKEK, key_domain=TEST_KEY_DOMAIN)
    assert(resp[1] == DEFAULT_DKEK_SHARES-2)

    kcv = hashlib.sha256(b'\x00'*32).digest()[:8]
    assert(resp[2:] == kcv)

def test_clear_key_domain(device):
    kd = device.get_key_domain(key_domain=0)
    assert('error' in kd)
    assert(kd['error'] == SWCodes.SW_REFERENCE_NOT_FOUND)

    kd = device.get_key_domain(key_domain=TEST_KEY_DOMAIN)
    assert(kd['dkek']['total'] == DEFAULT_DKEK_SHARES)

    device.clear_key_domain(key_domain=TEST_KEY_DOMAIN)
    kd = device.get_key_domain(key_domain=TEST_KEY_DOMAIN)
    assert(kd['dkek']['missing'] == DEFAULT_DKEK_SHARES)

def test_delete_key_domain(device):
    assert(device.get_key_domains() == KEY_DOMAINS)
    kd = device.get_key_domain(key_domain=TEST_KEY_DOMAIN)
    assert(kd['dkek']['total'] == DEFAULT_DKEK_SHARES)
    with pytest.raises(APDUResponse) as e:
        device.delete_key_domain(key_domain=0)
    assert(e.value.sw == SWCodes.SW_INCORRECT_P1P2)

def test_delete_key_domain(device):
    assert(device.get_key_domains() == KEY_DOMAINS)
    kd = device.get_key_domain(key_domain=TEST_KEY_DOMAIN)
    assert(kd['dkek']['total'] == DEFAULT_DKEK_SHARES)

    device.delete_key_domain(key_domain=TEST_KEY_DOMAIN)
    assert(device.get_key_domains() == KEY_DOMAINS)
    kd = device.get_key_domain(key_domain=TEST_KEY_DOMAIN)
    assert('error' in kd)
    assert(kd['error'] == 0x6A88)
