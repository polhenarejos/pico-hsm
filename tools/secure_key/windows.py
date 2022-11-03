import sys
import os
import base64

DOMAIN = "PicoKeys.com"
USERNAME = "Pico-Fido"

try:
    import keyring
except:
    print('ERROR: keyring module not found! Install keyring package.\nTry with `pip install keyrings.osx-keychain-keys`')
    sys.exit(-1)

try:
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    from cryptography.hazmat.primitives.asymmetric import ec
except:
    print('ERROR: cryptography module not found! Install cryptography package.\nTry with `pip install cryptography`')
    sys.exit(-1)



def generate_secure_key():
    pkey = ec.generate_private_key(ec.SECP256R1())
    set_secure_key(pkey)
    return keyring.get_password(DOMAIN, USERNAME)

def get_d(key):
    return key.private_numbers().private_value.to_bytes(32, 'big')

def set_secure_key(pk):
    try:
        keyring.delete_password(DOMAIN, USERNAME)
    except:
        pass
    keyring.set_password(DOMAIN, USERNAME, pk.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

def get_secure_key():
    key = None
    try:
        key = keyring.get_password(DOMAIN, USERNAME)[0]
    except keyring.errors.KeyringError:
        key = generate_secure_key()[0]
    return get_d(key)
