# Sign and verify

Pico HSM supports in place signature of arbitrary data. It supports the following algorithms:
* RSA-PKCS 
* SHA1-RSA-PKCS
* SHA256-RSA-PKCS
* SHA224-RSA-PKCS
* SHA384-RSA-PKCS
* SHA512-RSA-PKCS

First, we generate the data:
```
$ echo "This is a test string. Be safe, be secure." > data
```

Obtain the public key and convert it to PEM format:
```
$ pkcs11-tool --read-object --pin 648219 --id 1 --type pubkey > 1.der
$ openssl rsa -inform DER -outform PEM -in 1.der -pubin > 1.pub
```

At this moment, you are able to verify with the public key in `1.pub`. The signature is computed inside the Pico HSM with the private key. It never leaves the device.

## RSA-PKCS
This algorithm is used to sign raw data. 

To sign the data:
```
$ cat data | pkcs11-tool --id 1 --sign --pin 648219 --mechanism RSA-PKCS > data.sig
```

To verify the signature:
```
$ openssl rsautl -verify -inkey 1.pub -in data.sig -pubin
This is a test string. Be safe, be secure.
```

## SHA1-RSA-PKCS
This algorithm is used to sign digests. It supports SHA1, SHA224, SHA256, SHA384 and SHA512.

To sign the data:
```
$ cat data | pkcs11-tool --id 1 --sign --pin 648219 --mechanism SHA256-RSA-PKCS > data.sig
```

To verify the signature:
```
$ openssl rsautl -verify -inkey 1.pub -in data.sig -pubin|openssl asn1parse -inform DER 
    0:d=0  hl=2 l=  49 cons: SEQUENCE          
    2:d=1  hl=2 l=  13 cons: SEQUENCE          
    4:d=2  hl=2 l=   9 prim: OBJECT            :sha256
   15:d=2  hl=2 l=   0 prim: NULL              
   17:d=1  hl=2 l=  32 prim: OCTET STRING      [HEX DUMP]:6A0DFAFE96E1835B593812BFCDDED93AB52F67CF8B8ABB6C77A05C6DA5CAA960
$ sha256sum 6a0dfafe96e1835b593812bfcdded93ab52f67cf8b8abb6c77a05c6da5caa960  data
```

The signature is valid if both hashes are equal.

## RSA-X-509
This algorithm is used for signing raw data. In this algorithm, the data must be padded with a length equal to the size of private key (128, 256, 512 bytes for RSA-1024, RSA-2048 and RSA-4096, respectively).

First, we pad the data. The original data file occupies 29 bytes. Thus, for a 2048 bits key, a padding of 227 bytes is needed:

```
$ cp data data_pad
$ dd if=/dev/zero bs=1 count=227 >> data_pad
```

To sign the data:
```
$ cat data_pad | pkcs11-tool --id 4 --sign --pin 648219 --mechanism RSA-X-509 > data.sig
```

To verify the data:
```
$ openssl rsautl -verify -inkey 4.pub -in data.sig -pubin -raw
This is a test string. Be safe, be secure.
```
