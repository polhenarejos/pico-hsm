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
from const import DEFAULT_DKEK_SHARES, DEFAULT_DKEK

KEY_DOMAINS = 3

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

def test_set_key_domain(device):
    kd = device.get_key_domain(key_domain=0)
    assert('error' in kd)
    assert(kd['error'] == 0x6A88)

    device.set_key_domain(key_domain=0)
    kd = device.get_key_domain(key_domain=0)
    assert('error' not in kd)
    assert('dkek' in kd)
    assert('total' in kd['dkek'])
    assert(kd['dkek']['total'] == DEFAULT_DKEK_SHARES)
    assert('missing' in kd['dkek'])
    assert(kd['dkek']['missing'] == DEFAULT_DKEK_SHARES)

def test_clear_key_domain(device):
    kd = device.get_key_domain(key_domain=0)
    assert(kd['dkek']['total'] == DEFAULT_DKEK_SHARES)

    device.import_dkek(DEFAULT_DKEK)
    kd = device.get_key_domain(key_domain=0)
    assert(kd['dkek']['missing'] == DEFAULT_DKEK_SHARES-1)

    device.clear_key_domain(key_domain=0)
    kd = device.get_key_domain(key_domain=0)
    assert(kd['dkek']['missing'] == DEFAULT_DKEK_SHARES)

def test_delete_key_domain(device):
    assert(device.get_key_domains() == KEY_DOMAINS)
    kd = device.get_key_domain(key_domain=0)
    assert(kd['dkek']['total'] == DEFAULT_DKEK_SHARES)

    device.delete_key_domain(key_domain=0)
    assert(device.get_key_domains() == KEY_DOMAINS)
    kd = device.get_key_domain(key_domain=0)
    assert('error' in kd)
    assert(kd['error'] == 0x6A88)
