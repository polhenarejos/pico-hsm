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
    from smartcard.Exceptions import CardRequestTimeoutException
except ModuleNotFoundError:
    print('ERROR: smarctard module not found! Install pyscard package.\nTry with `pip install pyscard`')
    sys.exit(-1)

try:
    from cvc.certificates import CVC
    from cvc.asn1 import ASN1
    from cvc.oid import oid2scheme
    from cvc.utils import scheme_rsa
    from cryptography.hazmat.primitives.asymmetric import ec
except ModuleNotFoundError:
    print('ERROR: cvc module not found! Install pycvc package.\nTry with `pip install pycvc`')
    sys.exit(-1)
import json
import urllib.request
import base64
from binascii import hexlify
import sys
import argparse
import os
from datetime import datetime
from argparse import RawTextHelpFormatter

class APDUResponse(Exception):
    def __init__(self, sw1, sw2):
        self.sw1 = sw1
        self.sw2 = sw2
        super().__init__(f'SW:{sw1:02X}{sw2:02X}')


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
    response, sw1, sw2 = card.connection.transmit(apdu)
    if (sw1 != 0x90):
        raise APDUResponse(sw1, sw2)
    return response

def parse_args():
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(title="commands", dest="command")
    parser_init = subparser.add_parser('initialize', help='Performs the first initialization of the Pico HSM.')
    parser_init.add_argument('--pin', help='PIN number')
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
    parser_rtc.add_argument('subcommand', choices=['set', 'get'], help='Sets or gets current datetime.')

    parser_opts = subparser.add_parser('options', help='Manage extra options.', formatter_class=RawTextHelpFormatter)
    parser_opts.add_argument('subcommand', choices=['set', 'get'], help='Sets or gets option OPT.')
    parser_opts.add_argument('opt', choices=['button', 'counter'], help='Button: press-to-confirm button.\nCounter: every generated key has an internal counter.')
    parser_opts.add_argument('onoff', choices=['on', 'off'], help='Toggles state ON or OFF', metavar='ON/OFF', nargs='?')

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
    if (args.pin):
        pin = args.pin.encode()
        try:
            response = send_apdu(card, 0x20, 0x00, 0x81, list(pin))
        except APDUResponse:
            pass
    else:
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
    from binascii import hexlify
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

def main(args):
    print('Pico HSM Tool v1.4')
    print('Author: Pol Henarejos')
    print('Report bugs to https://github.com/polhenarejos/pico-hsm/issues')
    print('')
    print('')
    cardtype = AnyCardType()
    try:
        # request card insertion
        cardrequest = CardRequest(timeout=10, cardType=cardtype)
        card = cardrequest.waitforcard()

        # connect to the card and perform a few transmits
        card.connection.connect()

    except CardRequestTimeoutException:
        print('time-out: no card inserted during last 10s')

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

def run():
    args = parse_args()
    main(args)

if __name__ == "__main__":
    run()
