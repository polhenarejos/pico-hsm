#! /usr/bin/env python3
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import CardRequestTimeoutException
from cvc.certificates import CVC
from cvc.asn1 import ASN1
import json
import urllib.request
import base64
from getpass import getpass
from binascii import hexlify

class APDUResponse(Exception):
    def __init__(self, sw1, sw2):
        self.sw1 = sw1
        self.sw2 = sw2
        super().__init__(f'SW:{sw1:02X}{sw2:02X}')
        
def send_apdu(command, p1, p2, data):
    lc = [0x00] + list(len(data).to_bytes(2,'big'))
    le = [0x00, 0x00]
    apdu = [0x00] + [command, p1, p2] + lc + data + le
    response, sw1, sw2 = cardservice.connection.transmit(apdu)
    if (sw1 != 0x90):
        raise APDUResponse(sw1,sw2)
    return response

cardtype = AnyCardType()

try:
    # request card insertion
    cardrequest = CardRequest(timeout=10, cardType=cardtype)
    cardservice = cardrequest.waitforcard()

    # connect to the card and perform a few transmits
    cardservice.connection.connect()

    response = send_apdu(0xB1, 0xCE, 0x00, [0x54,0x02,0x00,0x00])

    cert = bytearray(response)
    Y = CVC().decode(cert).pubkey().find(0x86).data()
    print(f'Public Point: {hexlify(Y).decode()}')
    
    user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7'
    pbk = base64.urlsafe_b64encode(Y)
    data = urllib.parse.urlencode({'pubkey':pbk}).encode()
    req = urllib.request.Request("https://www.henarejos.me/pico-hsm/cvc/", method='POST', data=data, headers={'User-Agent':user_agent,} ) #The assembled request
    response = urllib.request.urlopen(req)
    resp = response.read().decode('utf-8')
    j = json.loads(resp)
    dataef = base64.urlsafe_b64decode(j['cvcert']) + base64.urlsafe_b64decode(j['dvcert'])
    
    response = send_apdu(0xa4, 0x00, 0x00, [0x2f,0x02])
    pin = getpass('PIN: ')
    response = send_apdu(0x20, 0x00, 0x81, list(pin.encode()))

    apdu_data = [0x54, 0x02, 0x00, 0x00] + list(ASN1.make_tag(0x53, dataef))
    response = send_apdu(0xd7, 0x00, 0x00, apdu_data)
    
    print('Certificate uploaded successfully!')
        
except CardRequestTimeoutException:
    print('time-out: no card inserted during last 10s')
