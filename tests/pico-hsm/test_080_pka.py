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
from picokey import APDUResponse, SWCodes
from const import TERM_CERT, DICA_CERT
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

AUT_KEY = unhexlify('579A995BD7BA35AD3D3968940FA4CDA34116E121A8AC01396234DAFB132B3FD7')
aut_pk = ec.derive_private_key(int.from_bytes(AUT_KEY, 'big'), ec.BrainpoolP256R1())
AUT_PUK = unhexlify('678201ed7f218201937f4e82014b5f290100421045535049434f48534d54524c524134437f4982011d060a04007f000702020202038120a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e537782207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9832026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b68441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f0469978520a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7864104a8217de2cec275cdf9dcda68128aff6061199291532545ab394e2554015962e16d568012a9d01b3da60d062aeed11356467fa3af9ebf9aad3d2933ebb9d86e0f8701015f201045535049434f48534d54524c524134435f374022d9f4480995e8370f8377e8bd4a63547be7740f7836456de5196839c6689540889acd573338d68bdea3db2e31c8dd00e670a4bcccdef497a156c39170d3c837421045535049434f48534d54524c524134435f374014445d219facb3bb745867d945e46526a2a6d03441dba52911d8f9483abbe4272a0beee7cecc69c661f3459c9b5431719ebf7e11f93d903a2cf705899eb4b631')


term_chr = CVC().decode(TERM_CERT).chr()

def test_initialize(device):
    device.initialize(puk_auts=1, puk_min_auts=1, no_dev_cert=False)
    device.logout()

def test_register_puk(device):
    status = device.get_puk_status()
    assert(status == bytes([1,1,1,0]))

    status = device.register_puk(AUT_PUK, TERM_CERT, DICA_CERT)
    assert(status == bytes([1,0,1,0]))
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
    assert(status == bytes([1,0,1,1]))

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
    assert(status == bytes([1,0,1,0]))
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
    assert(status == bytes([1,0,1,0]))
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
    device.initialize(puk_auts=2, puk_min_auts=1, no_dev_cert=True)
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
    device.initialize(puk_auts=2, puk_min_auts=1, no_dev_cert=True)
    status = device.get_puk_status()
    assert(status == bytes([2,2,1,0]))

    status = device.register_puk(AUT_PUK, TERM_CERT, DICA_CERT)
    assert(status == bytes([2,1,1,0]))

def test_is_pku(device):
    device.initialize(puk_auts=1, puk_min_auts=1, no_dev_cert=True)
    assert(device.is_puk() == True)

    device.initialize(no_dev_cert=True)
    assert(device.is_puk() == False)

def test_check_puk_key(device):
    device.initialize(puk_auts=1, puk_min_auts=1, no_dev_cert=True)
    status = device.check_puk_key(term_chr)
    assert(status == -1)

    status = device.register_puk(AUT_PUK, TERM_CERT, DICA_CERT)
    status = device.check_puk_key(term_chr)
    assert(status == 0)


def test_register_puk_with_no_puk(device):
    device.initialize(no_dev_cert=True)
    with pytest.raises(APDUResponse) as e:
        device.register_puk(AUT_PUK, TERM_CERT, DICA_CERT)
    assert(e.value.sw == SWCodes.SW_FILE_NOT_FOUND)
