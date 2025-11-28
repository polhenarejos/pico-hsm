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

KDM = unhexlify(b'30820420060B2B0601040181C31F0402016181ED7F2181E97F4E81A25F290100421045535049434F48534D434130303030317F494F060A04007F0007020202020386410421EE4A21C16A10F737F12E78E5091B266612038CDABEBB722B15BF6D41B877FBF64D9AB69C39B9831B1AE00BEF2A4E81976F7688D45189BB232A24703D8A96A55F201045535049434F48534D445630303030317F4C12060904007F000703010202530580000000005F25060202000801085F24060203000601045F37403F75C08FFFC9186B56E6147199E82BFC327CEEF72495BC567961CD54D702F13E3C2766FCD1D11BD6A9D1F4A229B76B248CEB9AF88D59A74D0AB149448705159B6281E97F2181E57F4E819E5F290100421045535049434F48534D445630303030317F494F060A04007F000702020202038641043359F5234CE62E0EB80460046D8FD1AAE018CC8B9E687B40AA2C047E352409B45153D1AD888E4E7E780A3B1FA8C69CA8998BD271C8849137149142E96816A5A45F201045535049434F48534D54524A5A58314A7F4C0E060904007F0007030102025301005F25060205000100085F24060206000100085F374016F155B01CDE7FB902C8A631FCB6938458CB570EAB088DEFE1FFACD3AEFF069020256EECCF8E962461534ED682DB87BB9801E25556F87BF524385C536D19A7D1638201F1678201ED7F218201937F4E82014B5F290100421045535049434F48534D54524A5A58314A7F4982011D060A04007F000702020202038120A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E537782207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9832026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B68441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F0469978520A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A786410443F0BAB3EB271E1B762BDB81C2CC10C21CF9E8A73241B86C9552614A8842DA00A556C20BC4250C275981FE196F8D2E8766DE06C609BA07AC3E6E1468EAC451408701015F201045535049434F48534D54524A5A58314A5F37402E79A552EA5ABE1B4244841CC55515F31CACFE9B3E0A3FC3FC178DFD5ED6ADC67E03FCC65C24A8A65658768A1A522F372E9897B87058E453A647FC58E089D30D421045535049434F48534D54524A5A58314A5F37400B54434EF57C6DD55D26B44F63940E9F15C10FBC8FC013528F76ACF917D74EF41D635D630F778862ADBD3EE8574F4ABC28B9A6044DFCB9C30D83C1A4DBE6437054400964DBAED86825DBA4E5BCEFF66DAF5739A71D4B2677FB1F53ABA23B3D1D1A686A06478C3CF7FF797FE7C8A4D090D881319BD15AABE709D3EA74A48C88E4387F')

def test_initialize(device):
    device.initialize(key_domains=1)
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

