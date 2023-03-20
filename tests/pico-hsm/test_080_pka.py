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
from cvc.certificates import CVC
from picohsm.utils import int_to_bytes
from picohsm import APDUResponse, SWCodes
from const import TERM_CERT, DICA_CERT
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

AUT_KEY = unhexlify('0A40E11E672C28C558B72C25D93BCF28C08D39AFDD5A1A2FD3BAF7A6B27F0C2E')
aut_pk = ec.derive_private_key(int.from_bytes(AUT_KEY, 'big'), ec.BrainpoolP256R1())
AUT_PUK = unhexlify('678201ed7f218201937f4e82014b5f290100421045535049434f48534d54525a474e50327f4982011d060a04007f000702020202038120a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e537782207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9832026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b68441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f0469978520a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a78641040cc18ce246da678239af0913a1579dda58c07be404da4a65327794fac93f57a333267979905b5d046da7020226cc4e5fc477e8fc651a0cf87095259aafa88e648701015f201045535049434f48534d54525a474e50325f37401fc90bdab2a58c3cd25f18a90baa2c21d3d087002ba240fb274ff066759297f79e130053d902d637a448c8cdcd0670fe8ebcc06d8a3ee82079f08d1ff8660393421045535049434f48534d54525a474e50325f3740e24e7e23eae3c78f9fa88391004369a293c43ef99e2279170983e1dbe707fbf0382d09de3e60ef1addd2f055947c3efcef17926065ddb7a031f4905da474ed1d')


term_chr = CVC().decode(TERM_CERT).chr()

def test_initialize(device):
    device.initialize(puk_auts=1, puk_min_auts=1)
    device.logout()

def test_register_puk(device):
    status = device.get_puk_status()
    assert(status == [1,1,1,0])

    status = device.register_puk(AUT_PUK, TERM_CERT, DICA_CERT)
    assert(status == [1,0,1,0])
    assert(device.check_puk_key(term_chr) == 0)

def test_enumerate_puk_reg(device):
    puks = device.enumerate_puk()
    assert(len(puks) == 1)
    assert(puks[0]['status'] == 0)

def test_authentication(device):
    input = device.puk_prepare_signature()
    signature = aut_pk.sign(input, ec.ECDSA(hashes.SHA256()))
    r,s = utils.decode_dss_signature(signature)
    signature = list(int_to_bytes(r) + int_to_bytes(s))
    device.authenticate_puk(term_chr, signature)
    status = device.get_puk_status()
    assert(status == [1,0,1,1])

def test_enumerate_puk_ok(device):
    puks = device.enumerate_puk()
    assert(len(puks) == 1)
    assert(puks[0]['status'] == 1)

def test_check_key(device):
    assert(device.check_puk_key(term_chr) == 1)
    bad_chr = b'XXXXX'
    assert(device.check_puk_key(bad_chr) == -1)
    assert(device.check_puk_key(bad_chr) != 0)
    assert(device.check_puk_key(bad_chr) != 1)

def test_puk_reset(device):
    device.logout()
    status = device.get_puk_status()
    assert(status == [1,0,1,0])
    assert(device.check_puk_key(term_chr) == 0)

def test_authentication_fail(device):
    input = b'this is a fake input'
    signature = aut_pk.sign(input, ec.ECDSA(hashes.SHA256()))
    r,s = utils.decode_dss_signature(signature)
    signature = list(int_to_bytes(r) + int_to_bytes(s))
    with pytest.raises(APDUResponse) as e:
        device.authenticate_puk(term_chr, signature)
    assert(e.value.sw == SWCodes.SW_CONDITIONS_NOT_SATISFIED)

    status = device.get_puk_status()
    assert(status == [1,0,1,0])
    assert(device.check_puk_key(term_chr) == 0)

def test_enumerate_puk_1(device):
    device.initialize(puk_auts=1, puk_min_auts=1)
    puks = device.enumerate_puk()
    assert(len(puks) == 1)
    assert(puks[0]['status'] == -1)

    device.register_puk(AUT_PUK, TERM_CERT, DICA_CERT)
    puks = device.enumerate_puk()
    assert(len(puks) == 1)
    assert(puks[0]['status'] == 0)

def test_enumerate_puk_2(device):
    device.initialize(puk_auts=2, puk_min_auts=1)
    puks = device.enumerate_puk()
    assert(len(puks) == 2)
    assert(puks[0]['status'] == -1)
    assert(puks[1]['status'] == -1)

    device.register_puk(AUT_PUK, TERM_CERT, DICA_CERT)
    puks = device.enumerate_puk()
    assert(len(puks) == 2)
    assert(puks[0]['status'] == 0)
    assert(puks[1]['status'] == -1)

def test_register_more_puks(device):
    device.initialize(puk_auts=2, puk_min_auts=1)
    status = device.get_puk_status()
    assert(status == [2,2,1,0])

    status = device.register_puk(AUT_PUK, TERM_CERT, DICA_CERT)
    assert(status == [2,1,1,0])

def test_is_pku(device):
    device.initialize(puk_auts=1, puk_min_auts=1)
    assert(device.is_puk() == True)

    device.initialize()
    assert(device.is_puk() == False)

def test_check_puk_key(device):
    device.initialize(puk_auts=1, puk_min_auts=1)
    status = device.check_puk_key(term_chr)
    assert(status == -1)

    status = device.register_puk(AUT_PUK, TERM_CERT, DICA_CERT)
    status = device.check_puk_key(term_chr)
    assert(status == 0)


def test_register_puk_with_no_puk(device):
    device.initialize()
    with pytest.raises(APDUResponse) as e:
        device.register_puk(AUT_PUK, TERM_CERT, DICA_CERT)
    assert(e.value.sw == SWCodes.SW_FILE_NOT_FOUND)
