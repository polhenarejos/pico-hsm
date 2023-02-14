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

import sys
import pytest
import os
from binascii import hexlify
from utils import APDUResponse, DOPrefixes, KeyType, Algorithm, Padding, int_to_bytes
from const import *
import hashlib

try:
    from cvc.asn1 import ASN1
    from cvc import oid
    from cvc.certificates import CVC
    from cvc.ec_curves import ec_domain, find_curve
except ModuleNotFoundError:
    print('ERROR: cvc module not found! Install pycvc package.\nTry with `pip install pycvc`')
    sys.exit(-1)

try:
    from smartcard.CardType import AnyCardType
    from smartcard.CardRequest import CardRequest
    from smartcard.Exceptions import CardRequestTimeoutException, CardConnectionException
except ModuleNotFoundError:
    print('ERROR: smarctard module not found! Install pyscard package.\nTry with `pip install pyscard`')
    sys.exit(-1)

try:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils, padding
    from cryptography.hazmat.primitives import hashes, cmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ModuleNotFoundError:
    print('ERROR: cryptography module not found! Install cryptography package.\nTry with `pip install cryptography`')
    sys.exit(-1)


class Device:
    class EcDummy:
        def __init__(self, name):
            self.name = name

    def __init__(self,pin='648219'):
        self.__pin = pin
        cardtype = AnyCardType()
        try:
            # request card insertion
            cardrequest = CardRequest(timeout=10, cardType=cardtype)
            self.__card = cardrequest.waitforcard()

            # connect to the card and perform a few transmits
            self.__card.connection.connect()

        except CardRequestTimeoutException:
            raise Exception('time-out: no card inserted during last 10s')
        self.select_applet()

    def select_applet(self):
        self.__card.connection.transmit([0x00, 0xA4, 0x04, 0x00, 0xB, 0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01, 0x0])

    def send(self, command, cla=0x00, p1=0x00, p2=0x00, ne=None, data=None, codes=[]):
        lc = []
        dataf = []
        if (data):
            lc = [0x00] + list(len(data).to_bytes(2, 'big'))
            dataf = list(data)
        if (ne is None):
            le = [0x00, 0x00]
        else:
            le = list(ne.to_bytes(2, 'big'))
        if (isinstance(command, list) and len(command) > 1):
            apdu = command
        else:
            apdu = [cla, command]

        apdu = apdu + [p1, p2] + lc + dataf + le
        try:
            response, sw1, sw2 = self.__card.connection.transmit(apdu)
        except CardConnectionException:
            self.__card.connection.reconnect()
            response, sw1, sw2 = self.__card.connection.transmit(apdu)

        code = (sw1<<8|sw2)
        if (sw1 != 0x90):
            if (sw1 == 0x63 and sw2 & 0xF0 == 0xC0):
                pass
            elif (code == 0x6A82):
                self.select_applet()
                if (sw1 == 0x90):
                    response, sw1, sw2 = self.__card.connection.transmit(apdu)
                    if (sw1 == 0x90):
                        return response
            elif (code == 0x6982):
                response, sw1, sw2 = self.__card.connection.transmit([0x00, 0x20, 0x00, 0x81, len(self.__pin)] + list(self.__pin.encode()) + [0x0])
                if (sw1 == 0x90):
                    response, sw1, sw2 = self.__card.connection.transmit(apdu)
                    if (sw1 == 0x90):
                        return response
            if (code not in codes):
                raise APDUResponse(sw1, sw2)
        if (len(codes) > 1):
            return response, code
        return response

    def get_login_retries(self):
        self.select_applet()
        try:
            self.send(command=0x20, p2=0x81)
        except APDUResponse as e:
            if (e.sw1 == 0x63 and e.sw2 & 0xF0 == 0xC0):
                return e.sw2 & 0x0F
            raise e

    def initialize(self, pin=DEFAULT_PIN, sopin=DEFAULT_SOPIN, options=None, retries=DEFAULT_RETRIES, dkek_shares=None, puk_auts=None, puk_min_auts=None, key_domains=None):
        if (retries is not None and not 0 < retries <= 10):
            raise ValueError('Retries must be in the range (0,10]')
        if (dkek_shares is not None and not 0 <= dkek_shares <= 10):
            raise ValueError('DKEK shares must be in the range [0,10]')
        if ((puk_auts is not None and puk_min_auts is None) or (puk_auts is None and puk_min_auts is not None)):
            raise ValueError('PUK Auts and PUK Min Auts must be specified both')
        if (puk_auts is not None and not 0 < puk_auts <= 8):
            raise ValueError('PUK Auts must be in the range (0,8]')
        if (puk_min_auts is not None and not 0 < puk_min_auts <= 8):
            raise ValueError('PUK Min Auts must be in the range (0,8]')
        if (puk_auts is not None and puk_min_auts is not None and puk_min_auts > puk_auts):
            raise ValueError('PUK Min Auts must be less or equal to PUK Auts')
        if (key_domains is not None and not 0 < key_domains <= 8):
            raise ValueError('Key Domains must be in the range (0,8]')

        a = ASN1()
        if (pin is not None):
            a = a.add_tag(0x81, pin.encode())
        if (sopin is not None):
            a = a.add_tag(0x82, sopin.encode())
        if (retries is not None):
            a = a.add_tag(0x91, bytes([retries]))
        if (dkek_shares is not None):
            a = a.add_tag(0x92, bytes([dkek_shares]))
        if (puk_auts is not None and puk_min_auts is not None):
            a = a.add_tag(0x93, bytes([puk_auts, puk_min_auts]))
        if (key_domains is not None):
            a = a.add_tag(0x97, bytes([key_domains]))

        data = a.encode()

        self.send(cla=0x80, command=0x50, data=data)

    def login(self, pin=None):
        if (pin is None):
            pin = self.__pin
        self.send(command=0x20, p2=0x81, data=pin.encode())

    def get_first_free_id(self):
        kids = self.list_keys(prefix=DOPrefixes.KEY_PREFIX)
        mset = set(range(max(kids)))-set(kids)
        if (len(mset) > 0):
            return min(mset)
        if (max(kids) == 255):
            raise ValueError('Max number of key id reached')
        return max(kids)+1

    def list_keys(self, prefix=None):
        resp = self.send(command=0x58)
        if (prefix is not None):
            grouped = [(resp[i],resp[i+1]) for i in range(0, len(resp), 2) if resp[i] == prefix.value]
            _, kids = zip(*grouped)
            return kids
        return [(resp[i],resp[i+1]) for i in range(0, len(resp), 2)]

    def keypair_generation(self, type, param):
        a = ASN1().add_tag(0x5f29, bytes([0])).add_tag(0x42, 'UTCA00001'.encode())
        if (type == KeyType.RSA):
            if (not 1024 <= param <= 4096):
                raise ValueError('RSA bits must be in the range [1024,4096]')
            a.add_tag(0x7f49, ASN1().add_oid(oid.ID_TA_RSA_V1_5_SHA_256).add_tag(0x2, param.to_bytes(2, 'big')).encode())
        elif (type == KeyType.ECC):
            if (param not in ('secp192r1', 'secp256r1', 'secp384r1', 'secp521r1', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp192k1', 'secp256k1')):
                raise ValueError('Wrong elliptic curve name')

            dom = ec_domain(Device.EcDummy(param))
            pubctx = [dom.P, dom.A, dom.B, dom.G, dom.O, None, dom.F]
            a.add_object(0x7f49, oid.ID_TA_ECDSA_SHA_256, pubctx)
        a.add_tag(0x5f20, 'UTCDUMMY00001'.encode())
        data = a.encode()

        keyid = self.get_first_free_id()
        self.send(command=0x46, p1=keyid, data=list(data))
        return keyid

    def delete_file(self, fid):
        self.send(command=0xE4, data=[fid >> 8, fid & 0xff])

    def get_contents(self, p1, p2=None):
        if (p2):
            resp = self.send(command=0xB1, p1=p1, p2=p2, data=[0x54, 0x02, 0x00, 0x00])
        else:
            resp = self.get_contents(p1=p1 >> 8, p2=p1 & 0xff)
        return bytes(resp)

    def public_key(self, keyid, param=None):
        response = self.get_contents(p1=DOPrefixes.EE_CERTIFICATE_PREFIX, p2=keyid)

        cert = bytearray(response)
        roid = CVC().decode(cert).pubkey().oid()
        if (roid == oid.ID_TA_ECDSA_SHA_256):
            curve = find_curve(ec_domain(Device.EcDummy(param)).P)
            Y = bytes(CVC().decode(cert).pubkey().find(0x86).data())
            return ec.EllipticCurvePublicKey.from_encoded_point(
                        curve,
                        Y,
                    )
        elif (roid == oid.ID_TA_RSA_V1_5_SHA_256):
            n = int.from_bytes(bytes(CVC().decode(cert).pubkey().find(0x81).data()), 'big')
            e = int.from_bytes(bytes(CVC().decode(cert).pubkey().find(0x82).data()), 'big')
            return rsa.RSAPublicNumbers(e, n).public_key()
        return None

    def sign(self, keyid, scheme, data):
        resp = self.send(cla=0x80, command=0x68, p1=keyid, p2=scheme.value, data=data)
        return resp

    def verify(self, pubkey, data, signature, scheme):
        if (Algorithm.ALGO_EC_RAW.value <= scheme.value <= Algorithm.ALGO_EC_SHA512.value):
            if (scheme == Algorithm.ALGO_EC_SHA1):
                hsh = hashes.SHA1()
            elif (scheme == Algorithm.ALGO_EC_SHA224):
                hsh = hashes.SHA224()
            elif (scheme == Algorithm.ALGO_EC_SHA256):
                hsh = hashes.SHA256()
            elif (scheme == Algorithm.ALGO_EC_RAW):
                hsh = utils.Prehashed(hashes.SHA512())
            elif (scheme == Algorithm.ALGO_EC_SHA384):
                hsh = hashes.SHA384()
            elif (scheme == Algorithm.ALGO_EC_SHA512):
                hsh = hashes.SHA512()
            return pubkey.verify(signature, data, ec.ECDSA(hsh))
        elif (Algorithm.ALGO_RSA_PKCS1_SHA1.value <= scheme.value <= Algorithm.ALGO_RSA_PSS_SHA512.value):
            if (scheme == Algorithm.ALGO_RSA_PKCS1_SHA1 or scheme == Algorithm.ALGO_RSA_PSS_SHA1):
                hsh = hashes.SHA1()
            elif (scheme == Algorithm.ALGO_RSA_PKCS1_SHA224 or scheme == Algorithm.ALGO_RSA_PSS_SHA224):
                hsh = hashes.SHA224()
            elif (scheme == Algorithm.ALGO_RSA_PKCS1_SHA256 or scheme == Algorithm.ALGO_RSA_PSS_SHA256):
                hsh = hashes.SHA256()
            elif (scheme == Algorithm.ALGO_RSA_PKCS1_SHA384 or scheme == Algorithm.ALGO_RSA_PSS_SHA384):
                hsh = hashes.SHA384()
            elif (scheme == Algorithm.ALGO_RSA_PKCS1_SHA512 or scheme == Algorithm.ALGO_RSA_PSS_SHA512):
                hsh = hashes.SHA512()
            if (Algorithm.ALGO_RSA_PKCS1_SHA1.value <= scheme.value <= Algorithm.ALGO_RSA_PKCS1_SHA512.value):
                padd = padding.PKCS1v15()
            elif (Algorithm.ALGO_RSA_PSS_SHA1.value <= scheme.value <= Algorithm.ALGO_RSA_PSS_SHA512.value):
                padd = padding.PSS(
                    mgf=padding.MGF1(hsh),
                    salt_length=padding.PSS.AUTO
                )
            return pubkey.verify(signature, data, padd, hsh)

    def decrypt(self, keyid, data, pad):
        if (isinstance(pad, padding.OAEP)):
            p2 = Padding.OAEP.value
        elif (isinstance(pad, padding.PKCS1v15)):
            p2 = Padding.PKCS.value
        else:
            p2 = Padding.RAW.value
        resp = self.send(command=0x62, p1=keyid, p2=p2, data=list(data))
        return bytes(resp)

    def import_dkek(self, dkek):
        resp = self.send(cla=0x80, command=0x52, p1=0x0, p2=0x0, data=dkek)
        return resp

    def import_key(self, pkey, dkek=None):
        data = b''
        kcv = hashlib.sha256(dkek or b'\x00'*32).digest()[:8]
        kenc = hashlib.sha256((dkek or b'\x00'*32) + b'\x00\x00\x00\x01').digest()
        kmac = hashlib.sha256((dkek or b'\x00'*32) + b'\x00\x00\x00\x02').digest()
        data += kcv
        pubnum = pkey.public_key().public_numbers()
        if (isinstance(pkey, rsa.RSAPrivateKey)):
            data += b'\x05'
            algo = b'\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x01\x02'
        elif (isinstance(pkey, ec.EllipticCurvePrivateKey)):
            data += b'\x0C'
            algo = b'\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x02\x03'

        data += algo
        data += b'\x00'*6

        kb = os.urandom(8)
        if (isinstance(pkey, rsa.RSAPrivateKey)):
            kb += int_to_bytes(pkey.key_size, length=2)
            pnum = pkey.private_numbers()
            kb += int_to_bytes((pnum.d.bit_length()+7)//8, length=2)
            kb += int_to_bytes(pnum.d)
            kb += int_to_bytes((pubnum.n.bit_length()+7)//8, length=2)
            kb += int_to_bytes(pubnum.n)
            kb += int_to_bytes((pubnum.e.bit_length()+7)//8, length=2)
            kb += int_to_bytes(pubnum.e)
        elif (isinstance(pkey, ec.EllipticCurvePrivateKey)):
            curve = ec_domain(pkey.curve)
            kb += int_to_bytes(len(curve.P)*8, length=2)
            kb += int_to_bytes(len(curve.A), length=2)
            kb += curve.A
            kb += int_to_bytes(len(curve.B), length=2)
            kb += curve.B
            kb += int_to_bytes(len(curve.P), length=2)
            kb += curve.P
            kb += int_to_bytes(len(curve.O), length=2)
            kb += curve.O
            kb += int_to_bytes(len(curve.G), length=2)
            kb += curve.G
            kb += int_to_bytes((pkey.private_numbers().private_value.bit_length()+7)//8, length=2)
            kb += int_to_bytes(pkey.private_numbers().private_value)
            p = pkey.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            kb += int_to_bytes(len(p), length=2)
            kb += p

        kb_len_pad = (len(kb)//16)*16
        if (len(kb) % 16 > 0):
            kb_len_pad = (len(kb)//16 + 1)*16
        if (len(kb) < kb_len_pad):
            kb += b'\x80'
            kb += b'\x00' * (kb_len_pad-len(kb))
        cipher = Cipher(algorithms.AES(kenc), modes.CBC(b'\x00'*16))
        encryptor = cipher.encryptor()
        ct = encryptor.update(kb) + encryptor.finalize()
        data += ct
        c = cmac.CMAC(algorithms.AES(kmac))
        c.update(data)
        data += c.finalize()

        p1 = self.get_first_free_id()
        _ = self.send(cla=0x80, command=0x74, p1=p1, p2=0x93, data=data)
        return p1

    def exchange(self, keyid, pubkey):
        resp = self.send(cla=0x80, command=0x62, p1=keyid, p2=Algorithm.ALGO_EC_DH.value, data=pubkey.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint))
        return resp

    def parse_cvc(self, data):
        car = CVC().decode(data).car()
        chr = CVC().decode(data).chr()
        return {'car': car, 'chr': chr}

    def get_termca(self):
        resp = self.get_contents(EF_TERMCA)
        cv_data = self.parse_cvc(resp)
        a = ASN1().decode(resp).find(0x7f21).data()
        tlen = len(ASN1.calculate_len(len(a)))
        ret = {'cv': cv_data}
        if (len(a)+2+tlen < len(resp)): # There's more certificate
            resp = resp[2+len(a)+tlen:]
            dv_data = self.parse_cvc(resp)
            ret['dv'] = dv_data
        return ret

    def get_version(self):
        resp = self.send(cla=0x80, command=0x50)
        return resp[5]+0.1*resp[6]

    def get_key_domain(self, key_domain=0):
        resp, code = self.send(cla=0x80, command=0x52, p2=key_domain, codes=[0x9000, 0x6A88, 0x6A86])
        if (code == 0x9000):
            return {'dkek': { 'total': resp[0], 'missing': resp[1]}, 'kcv': resp[2:10]}
        return {'error': code}

    def get_key_domains(self):
        for k in range(0xFF):
            _, code = self.send(cla=0x80, command=0x52, p2=k, codes=[0x9000, 0x6A88, 0x6A86])
            if (code == 0x6A86):
                return k
        return 0

    def set_key_domain(self, key_domain=0, total=DEFAULT_DKEK_SHARES):
        resp = self.send(cla=0x80, command=0x52, p1=0x1, p2=key_domain, data=[total])
        return resp

    def clear_key_domain(self, key_domain=0):
        resp = self.send(cla=0x80, command=0x52, p1=0x4, p2=key_domain)
        return resp

    def delete_key_domain(self, key_domain=0):
        self.send(cla=0x80, command=0x52, p1=0x3, p2=key_domain, codes=[0x6A88])


@pytest.fixture(scope="session")
def device():
    dev = Device()
    return dev
