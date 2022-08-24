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

from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import CardRequestTimeoutException
from cvc.certificates import CVC
from cvc.asn1 import ASN1
import json
import urllib.request
import base64
from binascii import hexlify


class APDUResponse(Exception):
    def __init__(self, sw1, sw2):
        self.sw1 = sw1
        self.sw2 = sw2
        super().__init__(f'SW:{sw1:02X}{sw2:02X}')


def send_apdu(card, command, p1, p2, data):
    lc = [0x00] + list(len(data).to_bytes(2, 'big'))
    le = [0x00, 0x00]
    if (isinstance(command, list) and len(command) > 1):
        apdu = command
    else:
        apdu = [0x00, command]

    apdu = apdu + [p1, p2] + lc + data + le
    response, sw1, sw2 = card.connection.transmit(apdu)
    if (sw1 != 0x90):
        raise APDUResponse(sw1, sw2)
    return response


def main():
    print('Pico HSM burning certificates tool v1.0')
    print('Author: Pol Henarejos')
    print('Report bugs to https://github.com/polhenarejos/pico-hsm/')
    print('')
    print('')
    print('********************************')
    print('*   PLEASE READ IT CAREFULLY   *')
    print('********************************')
    print('')
    print('This tool will erase and reset your device. It will delete all '
          'private and secret keys.')
    print('Are you sure?')
    _ = input('[Press enter to confirm]')
    cardtype = AnyCardType()
    try:
        # request card insertion
        cardrequest = CardRequest(timeout=10, cardType=cardtype)
        card = cardrequest.waitforcard()

        # connect to the card and perform a few transmits
        card.connection.connect()

        reset_data = [0x80, 0x02, 0x00, 0x01, 0x81, 0x06, 0x36, 0x34, 0x38,
                      0x32, 0x31,
                      0x39, 0x82, 0x08, 0x35, 0x37, 0x36, 0x32, 0x31, 0x38,
                      0x38, 0x30, 0x91, 0x01, 0x03]
        response = send_apdu(card, [0x80, 0x50], 0x00, 0x00, reset_data)

        response = send_apdu(card, 0xB1, 0xCE, 0x00, [0x54, 0x02, 0x00, 0x00])

        cert = bytearray(response)
        Y = CVC().decode(cert).pubkey().find(0x86).data()
        print(f'Public Point: {hexlify(Y).decode()}')

        user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; '
        'rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7'
        pbk = base64.urlsafe_b64encode(Y)
        data = urllib.parse.urlencode({'pubkey': pbk}).encode()
        req = urllib.request.Request("https://www.henarejos.me/pico-hsm/cvc/",
                                     method='POST',
                                     data=data,
                                     headers={'User-Agent': user_agent, })
        response = urllib.request.urlopen(req)
        resp = response.read().decode('utf-8')
        j = json.loads(resp)
        print('Device name: '+j['devname'])
        dataef = base64.urlsafe_b64decode(
            j['cvcert']) + base64.urlsafe_b64decode(j['dvcert'])

        response = send_apdu(card, 0xa4, 0x00, 0x00, [0x2f, 0x02])
        pin = b'648219'
        response = send_apdu(card, 0x20, 0x00, 0x81, list(pin))

        apdu_data = [0x54, 0x02, 0x00, 0x00] + \
            list(ASN1.make_tag(0x53, dataef))
        response = send_apdu(card, 0xd7, 0x00, 0x00, apdu_data)

        print('Certificate uploaded successfully!')
        print('')
        print('Note that the device is initialized with a default PIN and '
              'configuration.')
        print('Now you can initialize the device as usual with you chosen PIN '
              'and configuration options.')

    except CardRequestTimeoutException:
        print('time-out: no card inserted during last 10s')


def run():
    main()


if __name__ == "__main__":
    run()
