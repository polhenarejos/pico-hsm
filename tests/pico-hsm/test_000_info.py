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

def test_select(device):
    device.select_applet()

def test_initialization(device):
    device.initialize(no_dev_cert=True)

def test_termca(device):
    data = device.get_termca()
    assert(b'ESPICOHSMTR' == data['cv']['chr'][:11])
    assert(b'ESPICOHSMDV' == data['cv']['car'][:11] or b'ESPICOHSMTR' == data['cv']['car'][:11])
    assert(b'ESPICOHSMDV' == data['dv']['chr'][:11] or b'ESPICOHSMTR' == data['dv']['chr'][:11])
    assert(b'ESPICOHSMCA' == data['dv']['car'][:11] or b'ESPICOHSMTR' == data['dv']['car'][:11])
    assert(data['cv']['car'] == data['dv']['chr'])

def test_get_version(device):
    version = device.get_version()
