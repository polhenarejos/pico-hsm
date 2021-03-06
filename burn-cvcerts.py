#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 13 20:15:01 2022

@author: Pol Henarejos
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import base64
import urllib.request
import json
import sys

def print_var(v, name):
    s = '\n'
    s += "static const unsigned char "+name+"[] = {\n"
    s += "\t0x{:02x},0x{:02x},\n".format((len(v) & 0xff),((len(v)>> 8) & 0xff))
    for i in range(len(v)):
        if (i%16 == 0):
            s += '\t'
        s += "0x{:02x}".format((v[i]))
        if (i < len(v)-1):
            s += ','
        if (i%16 == 15):
            s += '\n'
    s += '\n'
    s += '};\n'
    return s

def main():
    args = sys.argv[1:]
    
    private_key = ec.generate_private_key(ec.SECP192R1(), default_backend())
    public_key = private_key.public_key()
    pub_num = public_key.public_numbers()
    pbk = base64.urlsafe_b64encode(b'\x04'+pub_num.x.to_bytes(24,'big')+pub_num.y.to_bytes(24,'big'))
    
    user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7'
    
    data = urllib.parse.urlencode({'pubkey':pbk}).encode()
    req = urllib.request.Request("https://www.henarejos.me/pico-hsm.php", method='POST', data=data, headers={'User-Agent':user_agent,} ) #The assembled request
    response = urllib.request.urlopen(req)
    resp = response.read().decode('utf-8')
    j = json.loads(resp)
    cvcert = base64.b64decode(j['cvcert'])
    
    dica = [
        0x7f,0x21,0x81,0xc5,0x7f,0x4e,0x81,0x8e,0x5f,0x29,0x01,0x00,0x42,0x0e,0x45,0x53,
        0x43,0x56,0x43,0x41,0x48,0x53,0x4d,0x30,0x30,0x30,0x30,0x31,0x7f,0x49,0x3f,0x06,
        0x0a,0x04,0x00,0x7f,0x00,0x07,0x02,0x02,0x02,0x02,0x03,0x86,0x31,0x04,0x93,0x7e,
        0xdf,0xf1,0xa6,0xd2,0x40,0x7e,0xb4,0x71,0xb2,0x97,0x50,0xdb,0x7e,0xe1,0x70,0xfb,
        0x6c,0xcd,0x06,0x47,0x2a,0x3e,0x9c,0x8d,0x59,0x56,0x57,0xbe,0x11,0x11,0x0a,0x08,
        0x81,0x54,0xed,0x22,0xc0,0x83,0xac,0xa1,0x2e,0x39,0x7b,0xd4,0x65,0x1f,0x5f,0x20,
        0x0e,0x45,0x53,0x44,0x56,0x43,0x41,0x48,0x53,0x4d,0x30,0x30,0x30,0x30,0x31,0x7f,
        0x4c,0x12,0x06,0x09,0x04,0x00,0x7f,0x00,0x07,0x03,0x01,0x02,0x02,0x53,0x05,0x80,
        0x00,0x00,0x00,0x04,0x5f,0x25,0x06,0x02,0x02,0x00,0x03,0x02,0x07,0x5f,0x24,0x06,
        0x02,0x05,0x01,0x02,0x03,0x01,0x5f,0x37,0x30,0x8b,0xb2,0x01,0xb6,0x24,0xfe,0xe5,
        0x4e,0x65,0x3a,0x02,0xa2,0xb2,0x27,0x2d,0x3d,0xb4,0xb0,0xc9,0xdd,0xbf,0x10,0x6d,
        0x99,0x49,0x46,0xd6,0xd0,0x72,0xc1,0xf3,0x4c,0xab,0x4f,0x32,0x14,0x7c,0xb0,0x99,
        0xb7,0x33,0x70,0xd6,0x00,0xff,0x73,0x0c,0x5d
    ]
    
    s = '#ifndef _CVCERTS_H_\n#define _CVCERTS_H_\n'
    s += print_var(dica,'dica')
    s += print_var(cvcert,'termca')
    
    pvk = private_key.private_numbers().private_value.to_bytes(24,'big')
    s += print_var(pvk,'termca_pk')
    s += '\n#endif\n'
    f = open(args[0] + '/src/hsm/cvcerts.h','w')
    f.write(s)
    f.close()
    
if __name__ == '__main__':
    main()