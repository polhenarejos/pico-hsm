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
from const import TERM_CERT, DICA_CERT
from cvc.asn1 import ASN1
from cvc.certificates import CVC
from cvc import oid
from cryptography.hazmat.primitives.asymmetric import ec
from picohsm import DOPrefixes
from picokey import APDUResponse, SWCodes

KDM = unhexlify(b'30820420060b2b0601040181c31f0402016181ed7f2181e97f4e81a25f290100421045535049434f48534d434130303030327f494f060a04007f00070202020203864104e66b473ec328caf39eaed840f9c7a4ba237e1dd19004861fa3f4f134bd2d5ea5f71c6c2e6321add4c8a7793ba41119c5783f48a5d9dfc0898d9ae9e7b14da8d65f201045535049434f48534d445630303030327f4c12060904007f000703010202530580000000045f25060205000400065f24060206000400065f3740a645594c6c338cd6bda6cad039cee54fd822b1011c0af1e4e3a2a6d03d43bdbb8be68a66a8757e7b1f963589bdd80d8e65de5055b722609041ec63f0498ddc8b6281e97f2181e57f4e819e5f290100421045535049434f48534d445630303030327f494f060a04007f000702020202038641043359f5234ce62e0eb80460046d8fd1aae018cc8b9e687b40aa2c047e352409b45153d1ad888e4e7e780a3b1fa8c69ca8998bd271c8849137149142e96816a5a45f201045535049434f48534d54524a5a58314a7f4c0e060904007f0007030102025301005f25060205010102085f24060206010102085f37409add1c1c8a05e7bc56a8bd846c9122d9214cc43c86b6952a961dce525d830a58130cbb275e9408af38dc16160f958d2b9ac6ac4f0f1b9b863284f00121d447ce638201f1678201ed7f218201937f4e82014b5f290100421045535049434f48534d54524a5a58314a7f4982011d060a04007f000702020202038120a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e537782207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9832026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b68441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f0469978520a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a78641049de55b50b921de72bbf740d3518905ff893e8208cfe8d144de34d79da3645d1c0cb551a19d6e6a5fee050e479a65d36fdf638af741e52dad4df9960b8ed443d18701015f201045535049434f48534d54524a5a58314a5f374099dede270b9a2def89a4d12dc0314e6289bd565808683f362e9f9ac9554ec5113bf7e412ecc386af12d2a9b43f27e54e10dfc6d8f2d6b618b1776459c13c0bec421045535049434f48534d54524a5a58314a5f3740459f6385f28a84f1c57f421a7f6cb4f1177084497321be94c87998c2e01af0202bab6984411cde1aab34e4e59cc27961b85855bae6340305281ff838253b0f3554404b6a2fe6947faa91f6ffa0d707cd4cbb43192935f561be137f4b3680304fc28b41210b671b8b033e06b4ad720010bcd36b92282844616261f944f3c4f67bfda5')

def test_initialize(device):
    device.initialize(key_domains=1, no_dev_cert=True)
    device.logout()

def test_create_xkek(device):
    with pytest.raises(APDUResponse) as e:
        device.create_xkek(KDM)
    assert(e.value.sw == SWCodes.SW_CONDITIONS_NOT_SATISFIED)

    device.login()
    kcv, did = device.create_xkek(KDM)
    assert(kcv == b'\x00'*8)

    gskcert = ASN1().decode(KDM).find(0x30).find(0x63).data()
    gskQ = CVC().decode(gskcert).pubkey().find(0x86).data()
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.BrainpoolP256R1(), bytes(gskQ))
    assert(did == int_to_bytes(pub.public_numbers().x)+int_to_bytes(pub.public_numbers().y))

keyid = -1
def test_derive_xkek(device):
    global keyid
    keyid = device.generate_xkek_key()

    resp = device.list_keys()
    assert((DOPrefixes.KEY_PREFIX, keyid) in resp)

    xkek_dom = device.get_key_domain()['xkek']
    pkey = ec.generate_private_key(ec.BrainpoolP256R1())
    pubkey = pkey.public_key()
    cert = CVC().cert(pubkey=pubkey, scheme=oid.ID_TA_ECDSA_SHA_256, signkey=pkey, signscheme=oid.ID_TA_ECDSA_SHA_256, car=b"UTCA00001", chr=b"UTCDUMMY00001", extensions=[
                {
                    'tag': 0x73,
                    'oid': b'\x2B\x06\x01\x04\x01\x81\xC3\x1F\x03\x02\x02',
                    'contexts': {
                        0: xkek_dom
                    }
                }
            ]).encode()
    device.derive_xkek(keyid, cert)

    resp = device.get_key_domain()
    assert(resp['kcv'] != b'\x00'*8)


def test_delete_xkek(device):
    device.delete_xkek()

    resp = device.get_key_domain()
    assert(resp['kcv'] == b'\x00'*8)

def test_delete_domain_with_key(device):
    with pytest.raises(APDUResponse) as e:
        device.delete_key_domain()
    assert(e.value.sw == SWCodes.SW_FILE_EXISTS)

    device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
    device.delete_file(DOPrefixes.EE_CERTIFICATE_PREFIX, keyid)

def test_delete_domain(device):
    device.delete_key_domain()

    resp = device.get_key_domain()
    assert('kcv' not in resp)
    assert('xkek' not in resp)
    assert('error' in resp)
    assert(resp['error'] == SWCodes.SW_REFERENCE_NOT_FOUND)

