
import sys
import pytest
from binascii import hexlify
from utils import APDUResponse, DOPrefixes, KeyType, Algorithm, Padding
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
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes, serialization
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

    def send(self, command, cla=0x00, p1=0x00, p2=0x00, ne=None, data=None):
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

        if (sw1 != 0x90):
            if (sw1 == 0x63 and sw2 & 0xF0 == 0xC0):
                pass
            elif (sw1 == 0x6A and sw2 == 0x82):
                self.select_applet()
                if (sw1 == 0x90):
                    response, sw1, sw2 = self.__card.connection.transmit(apdu)
                    if (sw1 == 0x90):
                        return response
            elif (sw1 == 0x69 and sw2 == 0x82):
                response, sw1, sw2 = self.__card.connection.transmit([0x00, 0x20, 0x00, 0x81, len(self.__pin)] + list(self.__pin.encode()) + [0x0])
                if (sw1 == 0x90):
                    response, sw1, sw2 = self.__card.connection.transmit(apdu)
                    if (sw1 == 0x90):
                        return response
            raise APDUResponse(sw1, sw2)
        return response

    def get_login_retries(self):
        self.select_applet()
        try:
            self.send(command=0x20, p2=0x81)
        except APDUResponse as e:
            if (e.sw1 == 0x63 and e.sw2 & 0xF0 == 0xC0):
                return e.sw2 & 0x0F
            raise e

    def initialize(self, pin='648219', sopin='57621880', options=None, retries=3, dkek_shares=None, puk_auts=None, puk_min_auts=None, key_domains=None):
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

    def public_key(self, type, keyid, param=None):
        response = self.send(command=0xB1, p1=0xCE, p2=keyid, data=[0x54, 0x02, 0x00, 0x00])

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

@pytest.fixture(scope="session")
def device():
    dev = Device()
    return dev
