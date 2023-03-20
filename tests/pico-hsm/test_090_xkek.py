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
from picohsm import DOPrefixes, APDUResponse, SWCodes

KDM = unhexlify(b'30820420060b2b0601040181c31f0402016181ed7f2181e97f4e81a25f290100421045535049434f48534d434130303030317f494f060a04007f0007020202020386410421ee4a21c16a10f737f12e78e5091b266612038cdabebb722b15bf6d41b877fbf64d9ab69c39b9831b1ae00bef2a4e81976f7688d45189bb232a24703d8a96a55f201045535049434f48534d445630303030317f4c12060904007f000703010202530580000000005f25060202000801085f24060203000601045f37403f75c08fffc9186b56e6147199e82bfc327ceef72495bc567961cd54d702f13e3c2766fcd1d11bd6a9d1f4a229b76b248ceb9af88d59a74d0ab149448705159b6281e97f2181e57f4e819e5f290100421045535049434f48534d445630303030317f494f060a04007f00070202020203864104c8561b41e54fea81bb80dd4a6d537e7c3904344e8ca90bc5f668111811e02c8d5d51ca93ca89558f2a8a9cbb147434e3441ec174505ff980fd7a7106286196915f201045535049434f48534d54524a444736387f4c0e060904007f0007030102025301005f25060203000300065f24060204000300055f3740983de63d0975b715ebd8a93cb38fa9638882c8b7064d51a6facabed693b92edc098e458b713203413ef6de0958c44772cbdbc264205c7b1bdb8b4fcb2516437f638201f1678201ed7f218201937f4e82014b5f290100421045535049434f48534d54524a444736387f4982011d060a04007f000702020202038120a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e537782207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9832026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b68441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f0469978520a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a78641048b1f450912a2e4d428b7eefc5fa05618a9ef295e90009a61cbb0970181b333474ea94f94cde5a11aba0589e85d4225002789ff1cdcf25756f059647b49fc2a158701015f201045535049434f48534d54524a444736385f3740372407c20de7257c89dae1e6606c8a046ca65efaa010c0a22b75c402ee243de51f5f1507457193679ed9db4fbbfe8efb9d695b684492b665ad8ba98c1f84ea38421045535049434f48534d54524a444736385f374098718e2e14a44386b689b71a101530316b65ab49a91bab0dd56099c5161ecb8aadff6cf27449f94034e58b7306f01e6ffa2766a2f5bb1281e12e5f1f9174733454400cf8926ca5bec9a91bcd47bf391c15d94ef6e3243d5fd1fffeaafd586766bc3221eafd808f17f8450f238cc1fe7ab1854443db31d622f53a2b3fdb3ad750d5ce')

def test_initialize(device):
    device.initialize(key_domains=1)
    device.logout()

def test_create_xkek(device):
    with pytest.raises(APDUResponse) as e:
        device.create_xkek(KDM)
    assert(e.value.sw == SWCodes.SW_CONDITIONS_NOT_SATISFIED)

    device.login()
    kcv, did = device.create_xkek(KDM)
    assert(bytes(kcv) == b'\x00'*8)

    gskcert = ASN1().decode(KDM).find(0x30).find(0x63).data()
    gskQ = CVC().decode(gskcert).pubkey().find(0x86).data()
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.BrainpoolP256R1(), bytes(gskQ))
    assert(bytes(did) == int_to_bytes(pub.public_numbers().x)+int_to_bytes(pub.public_numbers().y))

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
                        0: bytes(xkek_dom)
                    }
                }
            ]).encode()
    device.derive_xkek(keyid, cert)

    resp = device.get_key_domain()
    assert(bytes(resp['kcv']) != b'\x00'*8)


def test_delete_xkek(device):
    device.delete_xkek()

    resp = device.get_key_domain()
    assert(bytes(resp['kcv']) == b'\x00'*8)

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

