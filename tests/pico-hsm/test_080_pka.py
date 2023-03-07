
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
import os
from binascii import unhexlify, hexlify
from cvc.certificates import CVC
from cvc.asn1 import ASN1
from utils import int_to_bytes
from utils import APDUResponse, SWCodes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

AUT_KEY = unhexlify('0A40E11E672C28C558B72C25D93BCF28C08D39AFDD5A1A2FD3BAF7A6B27F0C2E')
aut_pk = ec.derive_private_key(int.from_bytes(AUT_KEY, 'big'), ec.BrainpoolP256R1())
AUT_PUK = unhexlify('678201ed7f218201937f4e82014b5f290100421045535049434f48534d54525a474e50327f4982011d060a04007f000702020202038120a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e537782207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9832026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b68441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f0469978520a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a78641040cc18ce246da678239af0913a1579dda58c07be404da4a65327794fac93f57a333267979905b5d046da7020226cc4e5fc477e8fc651a0cf87095259aafa88e648701015f201045535049434f48534d54525a474e50325f37401fc90bdab2a58c3cd25f18a90baa2c21d3d087002ba240fb274ff066759297f79e130053d902d637a448c8cdcd0670fe8ebcc06d8a3ee82079f08d1ff8660393421045535049434f48534d54525a474e50325f3740e24e7e23eae3c78f9fa88391004369a293c43ef99e2279170983e1dbe707fbf0382d09de3e60ef1addd2f055947c3efcef17926065ddb7a031f4905da474ed1d')
TERM_CERT = unhexlify('7F2181E57F4E819E5F290100421045535049434F48534D445630303030317F494F060A04007F00070202020203864104F571E53AA8E75C929D925081CF0F893CB5991D48BD546C1A3F22199F037E4B12D601ACD91C67C88D3C5B3D04C08EC0A372485F7A248E080EE0C6237C1B075E1C5F201045535049434F48534D54525A474E50327F4C0E060904007F0007030102025301005F25060203000300055F24060204000300045F374041BF5E970739135770DBCC5DDA81FFD8B13419A9257D44CAF8404267C644E8F435B43F5E57EB2A8CF4B198045ACD094E0CB34E6217D9C8922CFB9BBEFD4088AD')
DICA_CERT = unhexlify('7F2181E97F4E81A25F290100421045535049434F48534D434130303030317F494F060A04007F0007020202020386410421EE4A21C16A10F737F12E78E5091B266612038CDABEBB722B15BF6D41B877FBF64D9AB69C39B9831B1AE00BEF2A4E81976F7688D45189BB232A24703D8A96A55F201045535049434F48534D445630303030317F4C12060904007F000703010202530580000000005F25060202000801085F24060203000601045F37403F75C08FFFC9186B56E6147199E82BFC327CEEF72495BC567961CD54D702F13E3C2766FCD1D11BD6A9D1F4A229B76B248CEB9AF88D59A74D0AB149448705159B')

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
    assert(e.value.sw == SWCodes.SW_CONDITIONS_NOT_SATISFIED.value)

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
    assert(e.value.sw == SWCodes.SW_FILE_NOT_FOUND.value)
