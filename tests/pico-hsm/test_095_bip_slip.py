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
from binascii import unhexlify, hexlify
from picohsm.utils import int_to_bytes
from picohsm.const import DEFAULT_DKEK_SHARES
from const import DEFAULT_DKEK
from cvc.asn1 import ASN1
from cvc.certificates import CVC
from cvc import oid
from cryptography.hazmat.primitives.asymmetric import ec
from picohsm import DOPrefixes, APDUResponse, SWCodes


def test_initialize(device):
    device.initialize(dkek_shares=DEFAULT_DKEK_SHARES)
    resp = device.import_dkek(DEFAULT_DKEK)
    resp = device.import_dkek(DEFAULT_DKEK)

@pytest.mark.parametrize(
    "curve", [
        {
            'name': 'secp256k1',
            'id': 0,
            'seed': unhexlify('000102030405060708090a0b0c0d0e0f'),
        },
    ]
)
def test_generate_master(device, curve):
    resp = device.generate_master_seed(curve=curve['name'], id=curve['id'], seed=curve['seed'])

def hardened(i):
    return 0x80000000 + i

@pytest.mark.parametrize(
    "path", [
        {
            'path': [0],
            'xpub': b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
        },
        {
            'path': [0, hardened(0)],
            'xpub': b'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
        },
        {
            'path': [0, hardened(0), 1],
            'xpub': b'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
        },
        {
            'path': [0, hardened(0), 1, hardened(2)],
            'xpub': b'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
        },
        {
            'path': [0, hardened(0), 1, hardened(2), 2],
            'xpub': b'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
        },
        {
            'path': [0, hardened(0), 1, hardened(2), 2, 1000000000],
            'xpub': b'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
        },
    ]
)
def test_derive_node_bip(device, path):
    resp = device.derive_node_bip(path['path'])
    assert(resp == path['xpub'])
