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
from cryptography.hazmat.primitives import hashes
from picohsm import EncryptionMode, PicoHSM
from picokey import APDUResponse, SWCodes
import hashlib

TEST_STRING = b'Pico Keys are awesome!'

def sha256_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def test_initialize(device):
    device.initialize(dkek_shares=DEFAULT_DKEK_SHARES)
    resp = device.import_dkek(DEFAULT_DKEK)
    resp = device.import_dkek(DEFAULT_DKEK)

seeds = [
        {
            'name': 'secp256k1',
            'id': 0,
            'seed': unhexlify('000102030405060708090a0b0c0d0e0f'),
        },
        {
            'name': 'secp256k1',
            'id': 1,
            'seed': unhexlify('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'),
        },
        {
            'name': 'secp256k1',
            'id': 2,
            'seed': unhexlify('4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be'),
        },
        {
            'name': 'secp256k1',
            'id': 3,
            'seed': unhexlify('3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678'),
        },
        {
            'name': 'secp256r1',
            'id': 4,
            'seed': unhexlify('000102030405060708090a0b0c0d0e0f'),
        },
        {
            'name': 'secp256r1',
            'id': 5,
            'seed': unhexlify('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'),
        },
        {
            'name': 'secp256r1',
            'id': 6,
            'seed': unhexlify('a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446'),
        },
        {
            'name': 'symmetric',
            'id': 7,
            'seed': unhexlify('c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8'),
        },
    ]
@pytest.mark.parametrize(
    "seed", seeds
)
def test_generate_master(device, seed):
    resp = device.hd_generate_master_node(curve=seed['name'], id=seed['id'], seed=seed['seed'])

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
        {
            'path': [1],
            'xpub': b'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
        },
        {
            'path': [1, 0],
            'xpub': b'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
        },
        {
            'path': [1, 0, hardened(2147483647)],
            'xpub': b'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',
        },
        {
            'path': [1, 0, hardened(2147483647), 1],
            'xpub': b'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon',
        },
        {
            'path': [1, 0, hardened(2147483647), 1, hardened(2147483646)],
            'xpub': b'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
        },
        {
            'path': [1, 0, hardened(2147483647), 1, hardened(2147483646), 2],
            'xpub': b'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt',
        },
        {
            'path': [2],
            'xpub': b'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13',
        },
        {
            'path': [2, hardened(0)],
            'xpub': b'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',
        },
        {
            'path': [3],
            'xpub': b'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa',
        },
        {
            'path': [3, hardened(0)],
            'xpub': b'xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m',
        },
        {
            'path': [3, hardened(0), hardened(1)],
            'xpub': b'xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt',
        },
    ]
)
def test_derive_node_bip(device, path):
    resp = device.hd_derive_node(path['path'])
    assert(resp == path['xpub'])

@pytest.mark.parametrize(
    "path", [
        {
            'path': [0],
            'fingerprint': unhexlify('00000000'),
            'chain': unhexlify('873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508'),
            'public': unhexlify('0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2')
        },
        {
            'path': [0, hardened(0)],
            'fingerprint': unhexlify('3442193e'),
            'chain': unhexlify('47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141'),
            'public': unhexlify('035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56')
        },
        {
            'path': [0, hardened(0), 1],
            'fingerprint': unhexlify('5c1bd648'),
            'chain': unhexlify('2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19'),
            'public': unhexlify('03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c')
        },
        {
            'path': [0, hardened(0), 1, hardened(2)],
            'fingerprint': unhexlify('bef5a2f9'),
            'chain': unhexlify('04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f'),
            'public': unhexlify('0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2')
        },
        {
            'path': [0, hardened(0), 1, hardened(2), 2],
            'fingerprint': unhexlify('ee7ab90c'),
            'chain': unhexlify('cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd'),
            'public': unhexlify('02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29')
        },
        {
            'path': [0, hardened(0), 1, hardened(2), 2, 1000000000],
            'fingerprint': unhexlify('d880d7d8'),
            'chain': unhexlify('c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e'),
            'public': unhexlify('022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011')
        },
        {
            'path': [4],
            'fingerprint': unhexlify('00000000'),
            'chain': unhexlify('beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea'),
            'public': unhexlify('0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8')
        },
        {
            'path': [4, hardened(0)],
            'fingerprint': unhexlify('be6105b5'),
            'chain': unhexlify('3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11'),
            'public': unhexlify('0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c')
        },
        {
            'path': [4, hardened(0), 1],
            'fingerprint': unhexlify('9b02312f'),
            'chain': unhexlify('4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c'),
            'public': unhexlify('03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844')
        },
        {
            'path': [4, hardened(0), 1, hardened(2)],
            'fingerprint': unhexlify('b98005c1'),
            'chain': unhexlify('98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318'),
            'public': unhexlify('0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0')
        },
        {
            'path': [4, hardened(0), 1, hardened(2), 2],
            'fingerprint': unhexlify('0e9f3274'),
            'chain': unhexlify('ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0'),
            'public': unhexlify('029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20')
        },
        {
            'path': [4, hardened(0), 1, hardened(2), 2, 1000000000],
            'fingerprint': unhexlify('8b2b5c4b'),
            'chain': unhexlify('b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059'),
            'public': unhexlify('02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4')
        },
        {
            'path': [1],
            'fingerprint': unhexlify('00000000'),
            'chain': unhexlify('60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689'),
            'public': unhexlify('03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7')
        },
        {
            'path': [1, 0],
            'fingerprint': unhexlify('bd16bee5'),
            'chain': unhexlify('f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c'),
            'public': unhexlify('02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea')
        },
        {
            'path': [1, 0, hardened(2147483647)],
            'fingerprint': unhexlify('5a61ff8e'),
            'chain': unhexlify('be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9'),
            'public': unhexlify('03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b')
        },
        {
            'path': [1, 0, hardened(2147483647), 1],
            'fingerprint': unhexlify('d8ab4937'),
            'chain': unhexlify('f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb'),
            'public': unhexlify('03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9')
        },
        {
            'path': [1, 0, hardened(2147483647), 1, hardened(2147483646)],
            'fingerprint': unhexlify('78412e3a'),
            'chain': unhexlify('637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29'),
            'public': unhexlify('02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0')
        },
        {
            'path': [1, 0, hardened(2147483647), 1, hardened(2147483646), 2],
            'fingerprint': unhexlify('31a507b8'),
            'chain': unhexlify('9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271'),
            'public': unhexlify('024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c')
        },
        {
            'path': [5],
            'fingerprint': unhexlify('00000000'),
            'chain': unhexlify('96cd4465a9644e31528eda3592aa35eb39a9527769ce1855beafc1b81055e75d'),
            'public': unhexlify('02c9e16154474b3ed5b38218bb0463e008f89ee03e62d22fdcc8014beab25b48fa')
        },
        {
            'path': [5, 0],
            'fingerprint': unhexlify('607f628f'),
            'chain': unhexlify('84e9c258bb8557a40e0d041115b376dd55eda99c0042ce29e81ebe4efed9b86a'),
            'public': unhexlify('039b6df4bece7b6c81e2adfeea4bcf5c8c8a6e40ea7ffa3cf6e8494c61a1fc82cc')
        },
        {
            'path': [5, 0, hardened(2147483647)],
            'fingerprint': unhexlify('946d2a54'),
            'chain': unhexlify('f235b2bc5c04606ca9c30027a84f353acf4e4683edbd11f635d0dcc1cd106ea6'),
            'public': unhexlify('02f89c5deb1cae4fedc9905f98ae6cbf6cbab120d8cb85d5bd9a91a72f4c068c76')
        },
        {
            'path': [5, 0, hardened(2147483647), 1],
            'fingerprint': unhexlify('218182d8'),
            'chain': unhexlify('7c0b833106235e452eba79d2bdd58d4086e663bc8cc55e9773d2b5eeda313f3b'),
            'public': unhexlify('03abe0ad54c97c1d654c1852dfdc32d6d3e487e75fa16f0fd6304b9ceae4220c64')
        },
        {
            'path': [5, 0, hardened(2147483647), 1, hardened(2147483646)],
            'fingerprint': unhexlify('931223e4'),
            'chain': unhexlify('5794e616eadaf33413aa309318a26ee0fd5163b70466de7a4512fd4b1a5c9e6a'),
            'public': unhexlify('03cb8cb067d248691808cd6b5a5a06b48e34ebac4d965cba33e6dc46fe13d9b933')
        },
        {
            'path': [5, 0, hardened(2147483647), 1, hardened(2147483646), 2],
            'fingerprint': unhexlify('956c4629'),
            'chain': unhexlify('3bfb29ee8ac4484f09db09c2079b520ea5616df7820f071a20320366fbe226a7'),
            'public': unhexlify('020ee02e18967237cf62672983b253ee62fa4dd431f8243bfeccdf39dbe181387f')
        },
        {
            'path': [4],
            'fingerprint': unhexlify('00000000'),
            'chain': unhexlify('beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea'),
            'public': unhexlify('0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8')
        },
        {
            'path': [4, hardened(28578)],
            'fingerprint': unhexlify('be6105b5'),
            'chain': unhexlify('e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2'),
            'public': unhexlify('02519b5554a4872e8c9c1c847115363051ec43e93400e030ba3c36b52a3e70a5b7')
        },
        {
            'path': [4, hardened(28578), 33941],
            'fingerprint': unhexlify('3e2b7bc6'),
            'chain': unhexlify('9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071'),
            'public': unhexlify('0235bfee614c0d5b2cae260000bb1d0d84b270099ad790022c1ae0b2e782efe120')
        },
        {
            'path': [6],
            'fingerprint': unhexlify('00000000'),
            'chain': unhexlify('7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c'),
            'public': unhexlify('0383619fadcde31063d8c5cb00dbfe1713f3e6fa169d8541a798752a1c1ca0cb20')
        },
    ]
)
def test_derive_node_xpub(device, path):
    resp = device.hd_derive_node(path['path'])
    xpub = PicoHSM.hd_decode_xpub(resp)
    assert(xpub['fingerprint'] == path['fingerprint'])
    assert(xpub['chain'] == path['chain'])
    assert(xpub['public'] == path['public'])

@pytest.mark.parametrize(
    "path", [
        {
            'path': [7],
            'fingerprint': unhexlify('00000000'),
            'chain': unhexlify('8F8C33732530A0417DD446097EDB6F6617D52D627C6DB28581D74D11B385D25A'),
            'public': unhexlify('dbf12b44133eaab506a740f6565cc117228cbf1dd70635cfa8ddfdc9af734756')
        },
        {
            'path': [7, b"SLIP-0021"],
            'fingerprint': unhexlify('0e521cdd'),
            'chain': unhexlify('446ADED06078CF950DAB737F014C7BAE81EEB6E7BEECC260A38E2E0FA9973104'),
            'public': unhexlify('1d065e3ac1bbe5c7fad32cf2305f7d709dc070d672044a19e610c77cdf33de0d')
        },
        {
            'path': [7, b"SLIP-0021", b"Master encryption key"],
            'fingerprint': unhexlify('4a6e721d'),
            'chain': unhexlify('7072D5593032B84A90E2E2E42996D277026FF55C1082AC82A121D775FED0ACEB'),
            'public': unhexlify('ea163130e35bbafdf5ddee97a17b39cef2be4b4f390180d65b54cf05c6a82fde')
        },
        {
            'path': [7, b"SLIP-0021", b"Authentication key"],
            'fingerprint': unhexlify('4a6e721d'),
            'chain': unhexlify('3D5C87DC62CE006681B8C3DF723AE50FEEA40D6C26AEF8135BD321BA390A5B42'),
            'public': unhexlify('47194e938ab24cc82bfa25f6486ed54bebe79c40ae2a5a32ea6db294d81861a6')
        },
    ]
)
def test_derive_node_slip(device, path):
    resp = device.hd_derive_node(path['path'])
    xpub = PicoHSM.hd_decode_xpub(resp)
    assert(xpub['fingerprint'] == path['fingerprint'])
    assert(xpub['chain'] == sha256_sha256(path['chain']))
    assert(xpub['public'] == sha256_sha256(path['public']))

def get_master_curve(mid):
    for m in seeds:
        if (m['id'] == mid):
            if (m['name'] == 'secp256k1'):
                return ec.SECP256K1()
            elif (m['name'] == 'secp256r1'):
                return ec.SECP256R1()
    return None

@pytest.mark.parametrize(
    "path", [
        [0],
        [0, hardened(0)],
        [0, hardened(0), 1],
        [0, hardened(0), 1, hardened(2)],
        [0, hardened(0), 1, hardened(2), 2],
        [0, hardened(0), 1, hardened(2), 2, 1000000000],
        [1],
        [1, 0],
        [1, 0, hardened(2147483647)],
        [1, 0, hardened(2147483647), 1],
        [1, 0, hardened(2147483647), 1, hardened(2147483646)],
        [1, 0, hardened(2147483647), 1, hardened(2147483646), 2],
        [4],
        [4, hardened(0)],
        [4, hardened(0), 1],
        [4, hardened(0), 1, hardened(2)],
        [4, hardened(0), 1, hardened(2), 2],
        [4, hardened(0), 1, hardened(2), 2, 1000000000],
        [5],
        [5, 0],
        [5, 0, hardened(2147483647)],
        [5, 0, hardened(2147483647), 1],
        [5, 0, hardened(2147483647), 1, hardened(2147483646)],
        [5, 0, hardened(2147483647), 1, hardened(2147483646), 2],
    ]
)
def test_signature(device, path):
    pub = device.hd_derive_node(path)
    xpub = PicoHSM.hd_decode_xpub(pub)
    curve = get_master_curve(path[0])
    pubkey = ec.EllipticCurvePublicKey.from_encoded_point(curve, xpub['public'])
    resp = device.hd_signature(path, TEST_STRING)
    pubkey.verify(resp, TEST_STRING, ec.ECDSA(hashes.SHA256()))

@pytest.mark.parametrize(
    "path", [
        [7],
        [7, b"SLIP-0021"],
        [7, b"SLIP-0021", b"Master encryption key"],
        [7, b"SLIP-0021", b"Authentication key"],
    ]
)
def test_signature_slip(device, path):
    pub = device.hd_derive_node(path)
    with pytest.raises(APDUResponse) as e:
        resp = device.hd_signature(path, TEST_STRING)
    assert (e.value.sw == SWCodes.SW_CONDITIONS_NOT_SATISFIED)

@pytest.mark.parametrize(
    "ask_on_encrypt", [True, False]
)
@pytest.mark.parametrize(
    "ask_on_decrypt", [True, False]
)
def test_cipher_slip(device, ask_on_encrypt, ask_on_decrypt):
    MSG1 = b"testing message!"
    enctext = device.hd_cipher([7, b"\x01", b"\x02"], b"test", MSG1, EncryptionMode.ENCRYPT, ask_on_encrypt, ask_on_decrypt)
    resp = device.hd_cipher([7, b"\x01", b"\x02"], b"test", enctext, EncryptionMode.DECRYPT, ask_on_encrypt, ask_on_decrypt)
    assert(resp == MSG1)
