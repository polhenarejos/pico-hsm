#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
try:
    from smartcard.CardType import AnyCardType
    from smartcard.CardRequest import CardRequest
    from smartcard.Exceptions import CardRequestTimeoutException, CardConnectionException
except ModuleNotFoundError:
    print('ERROR: smarctard module not found! Install pyscard package.\nTry with `pip install pyscard`')
    sys.exit(-1)

try:
    from cvc.certificates import CVC
    from cvc.asn1 import ASN1
    from cvc.oid import oid2scheme
    from cvc.utils import scheme_rsa
except ModuleNotFoundError:
    print('ERROR: cvc module not found! Install pycvc package.\nTry with `pip install pycvc`')
    sys.exit(-1)

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes
except ModuleNotFoundError:
    print('ERROR: cryptography module not found! Install cryptography package.\nTry with `pip install cryptography`')
    sys.exit(-1)


import json
import urllib.request
import base64
from binascii import hexlify, unhexlify
import sys
import argparse
import os
import platform
from datetime import datetime
from argparse import RawTextHelpFormatter

pin = None

class APDUResponse(Exception):
    def __init__(self, sw1, sw2):
        self.sw1 = sw1
        self.sw2 = sw2
        super().__init__(f'SW:{sw1:02X}{sw2:02X}')

def hexy(a):
    return [hex(i) for i in a]

def send_apdu(card, command, p1, p2, data=None):
    lc = []
    dataf = []
    if (data):
        lc = [0x00] + list(len(data).to_bytes(2, 'big'))
        dataf = data
    le = [0x00, 0x00]
    if (isinstance(command, list) and len(command) > 1):
        apdu = command
    else:
        apdu = [0x00, command]

    apdu = apdu + [p1, p2] + lc + dataf + le
    try:
        response, sw1, sw2 = card.connection.transmit(apdu)
    except CardConnectionException:
        card.connection.reconnect()
        response, sw1, sw2 = card.connection.transmit(apdu)
    if (sw1 != 0x90):
        if (sw1 == 0x6A and sw2 == 0x82):
            response, sw1, sw2 = card.connection.transmit([0x00, 0xA4, 0x04, 0x00, 0xB, 0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01, 0x0])
            if (sw1 == 0x90):
                response, sw1, sw2 = card.connection.transmit(apdu)
                if (sw1 == 0x90):
                    return response
        elif (sw1 == 0x69 and sw2 == 0x82):
            response, sw1, sw2 = card.connection.transmit([0x00, 0x20, 0x00, 0x81, len(pin)] + list(pin.encode()) + [0x0])
            if (sw1 == 0x90):
                response, sw1, sw2 = card.connection.transmit(apdu)
                if (sw1 == 0x90):
                    return response
        raise APDUResponse(sw1, sw2)
    return response

def parse_args():
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(title="commands", dest="command")
    parser_init = subparser.add_parser('initialize', help='Performs the first initialization of the Pico HSM.')
    parser.add_argument('--pin', help='PIN number')
    parser_init.add_argument('--so-pin', help='SO-PIN number')

    parser_attestate = subparser.add_parser('attestate', help='Generates an attestation report for a private key and verifies the private key was generated in the devices or outside.')
    parser_attestate.add_argument('-k', '--key', help='The private key index', metavar='KEY_ID')

    parser_pki = subparser.add_parser('pki', help='Performs PKI operations.')
    subparser_pki = parser_pki.add_subparsers(title='commands', dest='subcommand')
    parser_pki_init = subparser_pki.add_parser('initialize', help='Initializes the Public Key Infrastructure (PKI)')

    parser_pki_init.add_argument('--certs-dir', help='Store the PKI certificates into this directory.', default='certs')
    parser_pki_init.add_argument('--default', help='Setups the default public PKI from public Pico HSM PKI.', action='store_true')
    parser_pki_init.add_argument('--force', help='Forces the download of certificates.', action='store_true')

    parser_rtc = subparser.add_parser('datetime', help='Datetime operations with the integrated Real Time Clock (RTC).')
    subparser_rtc = parser_rtc.add_subparsers(title='commands', dest='subcommand')
    parser_rtc_set = subparser_rtc.add_parser('set', help='Sets the current datetime.')
    parser_rtc_get = subparser_rtc.add_parser('set', help='Gets the current datetime.')

    parser_opts = subparser.add_parser('options', help='Manage extra options.', formatter_class=RawTextHelpFormatter)
    subparser_opts = parser_opts.add_subparsers(title='commands', dest='subcommand')
    parser_opts_set = subparser_opts.add_parser('set', help='Sets option OPT.')
    parser_opts_get = subparser_opts.add_parser('get', help='Gets optiont OPT.')
    parser_opts.add_argument('opt', choices=['button', 'counter'], help='button: press-to-confirm button.\ncounter: every generated key has an internal counter.', metavar='OPT')
    parser_opts_set.add_argument('onoff', choices=['on', 'off'], help='Toggles state ON or OFF', metavar='ON/OFF', nargs='?')

    parser_secure = subparser.add_parser('secure', help='Manages security of Pico HSM.')
    subparser_secure = parser_secure.add_subparsers(title='commands', dest='subcommand')
    parser_opts_enable = subparser_secure.add_parser('enable', help='Enables secure lock.')
    parser_opts_unlock = subparser_secure.add_parser('unlock', help='Unlocks the secure lock.')
    parser_opts_disable = subparser_secure.add_parser('disable', help='Disables secure lock.')

    parser_cipher = subparser.add_parser('cipher', help='Implements extended symmetric ciphering with new algorithms and options.\n\tIf no file input/output is specified, stdin/stoud will be used.')
    subparser_cipher = parser_cipher.add_subparsers(title='commands', dest='subcommand')
    parser_cipher_encrypt = subparser_cipher.add_parser('encrypt', help='Performs encryption.')
    parser_cipher_decrypt = subparser_cipher.add_parser('decrypt', help='Performs decryption.')
    parser_cipher_keygen = subparser_cipher.add_parser('keygen', help='Generates new AES key.')
    parser_cipher_hmac = subparser_cipher.add_parser('hmac', help='Computes HMAC.')
    parser_cipher.add_argument('--alg', choices=['CHACHAPOLY','HMAC-SHA1','HMAC-SHA224','HMAC-SHA256','HMAC-SHA384','HMAC-SHA512'], help='Selects the algorithm.', required='keygen' not in sys.argv)
    parser_cipher.add_argument('--iv', help='Sets the IV/nonce (hex string).')
    parser_cipher.add_argument('--file-in', help='File to encrypt or decrypt.')
    parser_cipher.add_argument('--file-out', help='File to write the result.')
    parser_cipher.add_argument('--aad', help='Specifies the authentication data (it can be a string or hex string. Combine with --hex if necesary).')
    parser_cipher.add_argument('--hex', help='Parses the AAD parameter as a hex string (for binary data).', action='store_true')
    parser_cipher.add_argument('-k', '--key', help='The private key index', metavar='KEY_ID', required=True)
    parser_cipher.add_argument('-s', '--key-size', default=32, help='Size of the key in bytes.')

    parser_x25519 = argparse.ArgumentParser(add_help=False)
    subparser_x25519 = parser_x25519.add_subparsers(title='commands', dest='subcommand')
    parser_x25519_keygen = subparser_x25519.add_parser('keygen', help='Generates a keypair for X25519 or X448.')
    parser_x25519.add_argument('-k', '--key', help='The private key index', metavar='KEY_ID', required=True)

    # Subparsers based on parent

    parser_create = subparser.add_parser("x25519", parents=[parser_x25519],
                                        help='X25519 key management.')
    # Add some arguments exclusively for parser_create

    parser_update = subparser.add_parser("x448", parents=[parser_x25519],
                                        help='X448 key management.')
    # Add some arguments exclusively for parser_update

    args = parser.parse_args()
    return args

def get_pki_data(url, data=None, method='GET'):
    user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; '
    'rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7'
    method = 'GET'
    if (data is not None):
        method = 'POST'
    req = urllib.request.Request(f"https://www.henarejos.me/pico/pico-hsm/{url}/",
                                method=method,
                                data=data,
                                headers={'User-Agent': user_agent, })
    response = urllib.request.urlopen(req)
    resp = response.read().decode('utf-8')
    j = json.loads(resp)
    return j

def get_pki_certs(certs_dir='certs', force=False):
    certs = get_pki_data('certs')
    if (os.path.exists(certs_dir) is False):
        os.mkdir(certs_dir)
    cvcap = os.path.join(certs_dir, certs['cvca']['CHR'])
    dvcap = os.path.join(certs_dir, certs['dvca']['CHR'])
    if (os.path.exists(cvcap) is False or force is True):
        with open(cvcap, 'wb') as f:
            f.write(base64.urlsafe_b64decode(certs['cvca']['cert']))
    if (os.path.exists(dvcap) is False or force is True):
        with open(dvcap, 'wb') as f:
            f.write(base64.urlsafe_b64decode(certs['dvca']['cert']))
    print(f'All PKI certificates are stored at {certs_dir} folder')

def pki(card, args):
    if (args.subcommand == 'initialize'):
        if (args.default is True):
            get_pki_certs(certs_dir=args.certs_dir, force=args.force)
        else:
            print('Error: no PKI is passed. Use --default to retrieve default PKI.')

def login(card, args):
    global pin
    pin = args.pin
    try:
        response = send_apdu(card, 0x20, 0x00, 0x81, list(args.pin.encode()))
    except APDUResponse:
        pass

def initialize(card, args):
    print('********************************')
    print('*   PLEASE READ IT CAREFULLY   *')
    print('********************************')
    print('')
    print('This tool will erase and reset your device. It will delete all '
        'private and secret keys.')
    print('Are you sure?')
    _ = input('[Press enter to confirm]')

    send_apdu(card, 0xA4, 0x04, 0x00, [0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01])
    if (not args.pin):
        pin = b'648219'

    if (args.so_pin):
        so_pin = args.so_pin.encode()
        try:
            response = send_apdu(card, 0x20, 0x00, 0x82, list(so_pin))
        except APDUResponse:
            pass
    else:
        so_pin = b'57621880'

    pin_data = [0x81, len(pin)] + list(pin)
    so_pin_data = [0x82, len(so_pin)] + list(so_pin)
    reset_data = [0x80, 0x02, 0x00, 0x01] + pin_data + so_pin_data + [0x91, 0x01, 0x03]
    response = send_apdu(card, [0x80, 0x50], 0x00, 0x00, reset_data)

    response = send_apdu(card, 0xB1, 0xCE, 0x00, [0x54, 0x02, 0x00, 0x00])

    cert = bytearray(response)
    Y = CVC().decode(cert).pubkey().find(0x86).data()
    print(f'Public Point: {hexlify(Y).decode()}')

    pbk = base64.urlsafe_b64encode(Y)
    data = urllib.parse.urlencode({'pubkey': pbk}).encode()
    j = get_pki_data('cvc', data=data)
    print('Device name: '+j['devname'])
    dataef = base64.urlsafe_b64decode(
        j['cvcert']) + base64.urlsafe_b64decode(j['dvcert'])

    response = send_apdu(card, 0xa4, 0x00, 0x00, [0x2f, 0x02])
    response = send_apdu(card, 0x20, 0x00, 0x81, list(pin))

    apdu_data = [0x54, 0x02, 0x00, 0x00] + \
        list(ASN1.make_tag(0x53, dataef))
    response = send_apdu(card, 0xd7, 0x00, 0x00, apdu_data)

    print('Certificate uploaded successfully!')
    print('')
    print('Note that the device is initialized with a default PIN and '
        'configuration.')
    print('Now you can initialize the device as usual with your chosen PIN '
        'and configuration options.')

def attestate(card, args):
    kid = int(args.key)
    try:
        response = send_apdu(card, 0xB1, 0x2F, 0x02, [0x54, 0x02, 0x00, 0x00])
    except APDUResponse as a:
        print('ERROR: There is an error with the device certificate.')
        sys.exit(1)

    devcert = ASN1().decode(response).find(0x7f21, pos=0).data(return_tag=True)

    try:
        cert = send_apdu(card, 0xB1, 0xCE, kid, [0x54, 0x02, 0x00, 0x00])
    except APDUResponse as a:
        if (a.sw1 == 0x6a and a.sw2 == 0x82):
            print('ERROR: Key not found')
            sys.exit(1)

    print(hexlify(bytearray(cert)))
    print(f'Details of key {kid}:\n')
    print(f'  CAR: {(CVC().decode(cert).car()).decode()}')
    print('  Public Key:')
    puboid = CVC().decode(cert).pubkey().oid()
    print(f'    Scheme: {oid2scheme(puboid)}')
    chr = CVC().decode(cert).chr()
    car = CVC().decode(cert).car()
    if (scheme_rsa(puboid)):
        print(f'    Modulus: {hexlify(CVC().decode(cert).pubkey().find(0x81).data()).decode()}')
        print(f'    Exponent: {hexlify(CVC().decode(cert).pubkey().find(0x82).data()).decode()}')
    else:
        print(f'    Public Point: {hexlify(CVC().decode(cert).pubkey().find(0x86).data()).decode()}')
    print(f'  CHR: {chr.decode()}')
    print('  Key signature:')
    inret = CVC().decode(cert).verify()
    if (inret):
        print('    Status: VALID')
        print(f'      This certificate is signed with private key {kid}')
    else:
        print('    Status: NOT VALID')
        print(f'      This certificate is NOT signed with private key {kid}')
    print('  Cert signature:')
    print(f'    Outer CAR: {CVC().decode(cert).outer_car().decode()}')
    outret = CVC().decode(cert).verify(outer=True, dica=devcert, curve=ec.SECP256R1())
    if (outret):
        print('    Status: VALID')
        print('      This certificate is signed with the device key')
    else:
        print('    Status: NOT VALID')
        print('      This certificate is NOT signed with the device key')

    if (inret is True and outret is True):
        print(f'Key {kid} is generated by device {chr.decode()}')
    else:
        print(f'Key {kid} is NOT generated by device {chr.decode()}')

def rtc(card, args):
    if (args.subcommand == 'set'):
        now = datetime.now()
        _ = send_apdu(card, [0x80, 0x64], 0x0A, 0x00, list(now.year.to_bytes(2, 'big')) + [now.month, now.day, now.weekday(), now.hour, now.minute, now.second ])
    elif (args.subcommand == 'get'):
        response = send_apdu(card, [0x80, 0x64], 0x0A, 0x00)
        dt = datetime(int.from_bytes(response[:2], 'big'), response[2], response[3], response[5], response[6], response[7])
        print(f'Current date and time is: {dt.ctime()}')

def opts(card, args):
    opt = 0x0
    if (args.opt == 'button'):
        opt = 0x1
    elif (args.opt == 'counter'):
        opt = 0x2
    current = send_apdu(card, [0x80, 0x64], 0x6, 0x0)[0]
    if (args.subcommand == 'set'):
        if (args.onoff == 'on'):
            newopt = current | opt
        else:
            newopt = current & ~opt
        send_apdu(card, [0x80, 0x64], 0x6, 0x0, [newopt])
    elif (args.subcommand == 'get'):
        print(f'Option {args.opt.upper()} is {"ON" if current & opt else "OFF"}')

class SecureLock:
    def __init__(self, card):
        self.card = card

    def mse(self):
        sk = ec.generate_private_key(ec.SECP256R1())
        pn = sk.public_key().public_numbers()
        self.__pb = sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


        ret = send_apdu(self.card, [0x80, 0x64], 0x3A, 0x01, list(self.__pb))

        pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(ret))
        shared_key = sk.exchange(ec.ECDH(), pk)

        xkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=12+32,
            salt=None,
            info=self.__pb
        )
        kdf_out = xkdf.derive(shared_key)
        self.__key_enc = kdf_out[12:]
        self.__iv = kdf_out[:12]

    def encrypt_chacha(self, data):
        chacha = ChaCha20Poly1305(self.__key_enc)
        ct = chacha.encrypt(self.__iv, data, self.__pb)
        return ct

    def unlock_device(self):
        ct = self.get_skey()
        send_apdu(self.card, [0x80, 0x64], 0x3A, 0x03, list(ct))

    def _get_key_device(self):
        if (platform.system() == 'Windows' or platform.system() == 'Linux'):
            from secure_key import windows as skey
        elif (platform.system() == 'Darwin'):
            from secure_key import macos as skey
        else:
            print('ERROR: platform not supported')
            sys.exit(-1)
        return skey.get_secure_key()

    def get_skey(self):
        self.mse()
        ct = self.encrypt_chacha(self._get_key_device())
        return ct

    def enable_device_aut(self):
        ct = self.get_skey()
        send_apdu(self.card, [0x80, 0x64], 0x3A, 0x02, list(ct))

    def disable_device_aut(self):
        ct = self.get_skey()
        send_apdu(self.card, [0x80, 0x64], 0x3A, 0x04, list(ct))


def secure(card, args):
    slck = SecureLock(card)
    if (args.subcommand == 'enable'):
        slck.enable_device_aut()
    elif (args.subcommand == 'unlock'):
        slck.unlock_device()
    elif (args.subcommand == 'disable'):
        slck.disable_device_aut()


def cipher(card, args):
    if (args.subcommand == 'keygen'):
        ksize = 0xB2
        if (args.key_size == 24):
            ksize = 0xB1
        elif (args.key_size == 16):
            ksize = 0xB0
        ret = send_apdu(card, 0x48, int(args.key), ksize)

    else:
        if (args.alg == 'CHACHAPOLY'):
            oid = b'\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x12'
        elif (args.alg == 'HMAC-SHA1'):
            oid = b'\x2A\x86\x48\x86\xF7\x0D\x02\x07'
        elif (args.alg == 'HMAC-SHA224'):
            oid = b'\x2A\x86\x48\x86\xF7\x0D\x02\x08'
        elif (args.alg == 'HMAC-SHA256'):
            oid = b'\x2A\x86\x48\x86\xF7\x0D\x02\x09'
        elif (args.alg == 'HMAC-SHA384'):
            oid = b'\x2A\x86\x48\x86\xF7\x0D\x02\x0A'
        elif (args.alg == 'HMAC-SHA512'):
            oid = b'\x2A\x86\x48\x86\xF7\x0D\x02\x0B'

        if (args.subcommand[0] == 'e' or args.subcommand == 'hmac'):
            alg = 0x51
        elif (args.subcommand[0] == 'd'):
            alg = 0x52

        if (args.file_in):
            fin = open(args.file_in, 'rb')
        else:
            fin = sys.stdin.buffer
        enc = fin.read()
        fin.close()

        data = [0x06, len(oid)] + list(oid) + [0x81, len(enc)] + list(enc)
        if (args.iv):
            data += [0x82, len(args.iv)/2] + list(unhexlify(args.iv))
        if (args.aad):
            if (args.hex):
                data += [0x83, len(args.aad)/2] + list(unhexlify(args.aad))
            else:
                data += [0x83, len(args.aad)] + list(args.aad)

        ret = send_apdu(card, [0x80, 0x78], int(args.key), alg, data)
        if (args.file_out):
            fout = open(args.file_out, 'wb')
        else:
            fout = sys.stdout.buffer
        if (args.hex):
            fout.write(hexlify(bytes(ret)))
        else:
            fout.write(bytes(ret))
        if (args.file_out):
            fout.close()

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def x25519(card, args):
    if (args.command == 'x25519'):
        P = b'\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xed'
        A = int_to_bytes(0x01DB42)
        N = b'\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\xDE\xF9\xDE\xA2\xF7\x9C\xD6\x58\x12\x63\x1A\x5C\xF5\xD3\xED'
        G = b'\x04\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd9\xd3\xce\x7e\xa2\xc5\xe9\x29\xb2\x61\x7c\x6d\x7e\x4d\x3d\x92\x4c\xd1\x48\x77\x2c\xdd\x1e\xe0\xb4\x86\xa0\xb8\xa1\x19\xae\x20'
        h = b'\x08'
    elif (args.command == 'x448'):
        P = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
        A = int_to_bytes(0x98AA)
        N = b'\x3f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7c\xca\x23\xe9\xc4\x4e\xdb\x49\xae\xd6\x36\x90\x21\x6c\xc2\x72\x8d\xc5\x8f\x55\x23\x78\xc2\x92\xab\x58\x44\xf3'
        G = b'\x04\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1a\x5b\x7b\x45\x3d\x22\xd7\x6f\xf7\x7a\x67\x50\xb1\xc4\x12\x13\x21\x0d\x43\x46\x23\x7e\x02\xb8\xed\xf6\xf3\x8d\xc2\x5d\xf7\x60\xd0\x45\x55\xf5\x34\x5d\xae\xcb\xce\x6f\x32\x58\x6e\xab\x98\x6c\xf6\xb1\xf5\x95\x12\x5d\x23\x7d'
        h = b'\x04'
    oid = b'\x06\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x02\x03'
    p_data = b'\x81' + bytes([len(P)]) + P
    a_data = b'\x82' + bytes([len(A)]) + A
    g_data = b'\x84' + bytes([len(G)]) + G
    n_data = b'\x85' + bytes([len(N)]) + N
    h_data = b'\x87' + bytes([len(h)]) + h

    cdata =  b'\x5F\x29\x01\x00'
    cdata += b'\x42\x0C\x55\x54\x44\x55\x4D\x4D\x59\x30\x30\x30\x30\x31'
    cdata += b'\x7f\x49\x81' + bytes([len(oid)+len(p_data)+len(a_data)+len(g_data)+len(n_data)+len(h_data)]) + oid + p_data + a_data + g_data + n_data + h_data
    cdata += b'\x5F\x20\x0C\x55\x54\x44\x55\x4D\x4D\x59\x30\x30\x30\x30\x31'
    ret = send_apdu(card, 0x46, int(args.key), 0x00, list(cdata))

def main(args):
    sys.stderr.buffer.write(b'Pico HSM Tool v1.8\n')
    sys.stderr.buffer.write(b'Author: Pol Henarejos\n')
    sys.stderr.buffer.write(b'Report bugs to https://github.com/polhenarejos/pico-hsm/issues\n')
    sys.stderr.buffer.write(b'\n\n')
    cardtype = AnyCardType()
    try:
        # request card insertion
        cardrequest = CardRequest(timeout=10, cardType=cardtype)
        card = cardrequest.waitforcard()

        # connect to the card and perform a few transmits
        card.connection.connect()

    except CardRequestTimeoutException:
        print('time-out: no card inserted during last 10s')

    if (args.pin):
        login(card, args)

    # Following commands may raise APDU exception on error
    if (args.command == 'initialize'):
        initialize(card, args)
    elif (args.command == 'attestate'):
        attestate(card, args)
    elif (args.command == 'pki'):
        pki(card, args)
    elif (args.command == 'datetime'):
        rtc(card, args)
    elif (args.command == 'options'):
        opts(card, args)
    elif (args.command == 'secure'):
        secure(card, args)
    elif (args.command == 'cipher'):
        cipher(card, args)
    elif (args.command == 'x25519' or args.command == 'x448'):
        x25519(card, args)


def run():
    args = parse_args()
    main(args)

if __name__ == "__main__":
    run()
