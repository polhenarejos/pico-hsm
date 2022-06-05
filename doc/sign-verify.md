# Sign and verify

Pico HSM supports in place signature of arbitrary data. It supports the following algorithms:
* RSA-PKCS 
* RSA-X-509
* SHA1-RSA-PKCS
* SHA256-RSA-PKCS
* SHA224-RSA-PKCS
* SHA384-RSA-PKCS
* SHA512-RSA-PKCS
* RSA-PKCS-PSS
* SHA1-RSA-PKCS-PSS
* SHA256-RSA-PKCS-PSS
* SHA224-RSA-PKCS-PSS
* SHA384-RSA-PKCS-PSS
* SHA512-RSA-PKCS-PSS
* SHA1-ECDSA
* SHA224-ECDSA
* SHA256-ECDSA

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
$ pkcs11-tool --id 1 --sign --pin 648219 --mechanism RSA-PKCS -i data -o data.sig
```

To verify the signature:
```
$ openssl pkeyutl -verify -pubin -inkey 1.pub -in data -sigfile data.sig
Signature Verified Successfully
```

## SHA1-RSA-PKCS
This algorithm is used to sign digests computed outside. It supports SHA1, SHA224, SHA256, SHA384 and SHA512.

First, we generate a file with the digest:
```
openssl dgst -sha1 -binary -out data.sha1 data
```

To sign the data:
```
$ pkcs11-tool --id 1 --sign --pin 648219 --mechanism SHA1-RSA-PKCS -i data -o data.sig
```

To verify the signature:
```
$ openssl pkeyutl -verify -in data.sha1 -sigfile data.sig -pubin -inkey 1.pub -pkeyopt digest:sha1
Signature Verified Successfully
```

## RSA-X-509
This algorithm is used for signing raw data. In this algorithm, the data must be padded with a length equal to the size of private key (128, 256, 512 bytes for RSA-1024, RSA-2048 and RSA-4096, respectively).

First, we pad the data. The original data file occupies 29 bytes. Thus, for a 2048 bits key, a padding of 227 bytes is needed:

```
$ cp data data_pad
$ dd if=/dev/zero bs=1 count=227 >> data_pad
```

To sign the data:
```
$ pkcs11-tool --id 1 --sign --pin 648219 --mechanism RSA-X-509 -i data_pad -o data.sig
```

To verify the signature:
```
$ openssl rsautl -verify -inkey 1.pub -in data.sig -pubin -raw
This is a test string. Be safe, be secure.
```

## RSA-PKCS-PSS
This algorithm uses the RSA-PKCS with PSS salt to randomize the signature. Pico HSM does not support arbitrary salt lengths. Instead, it always uses the maximum salt length (the hash length). It uses the hash as the input.

To sign the data:
```
$ pkcs11-tool --id 1 --sign --pin 648219 --mechanism RSA-PKCS-PSS -i data.sha1 -o data.sig
``` 

To verify the signature:
```
$ openssl pkeyutl -verify -in data.sha1 -sigfile data.sig -pubin -inkey 1.pub -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha1
Signature Verified Successfully
```

## SHA1-RSA-PKCS-PSS
This algorithm takes the file as the input and sends its hash for signing with the random salt.

To sign the data:
```
$ pkcs11-tool --id 1 --sign --pin 648219 --mechanism SHA1-RSA-PKCS-PSS -i data -o data.sig
``` 

To verify the signature:
```
$ openssl pkeyutl -verify -in data.sha1 -sigfile data.sig -pubin -inkey 1.pub -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1
Signature Verified Successfully
```

## ECDSA
This is a raw ECDSA signature, which is usually used to sign a hashed message. `pkcs11-tool` has the limit of the maximum supported length, which is the length in bytes of the ECC curve. For a 192 bits curve, it only supports hashed messages with SHA1 (20 bytes < 24 bytes). To support SHA256 hashed messages, a minimum of ECC curve of 256 bits is required. `sc-hsm-embedded` driver and `sc-tool` do not have this constraint and can be used with arbitrary data.

To sign the data:
```
$ pkcs11-tool --id 11 --sign --pin 648219 --mechanism ECDSA -i data.sha1 -o data.sig --signature-format openssl     
Using slot 0 with a present token (0x0)
Using signature algorithm ECDSA
```

To verify the signature:
```
$ openssl pkeyutl -verify -pubin -inkey 11.pub -in data.sha1 -sigfile data.sig                                      
Signature Verified Successfully
```

To sign raw data, use `sc-tool` of `sc-hsm-embedded` driver instead of `pkcs11-tool`.

## SHA1-ECDSA
For ECDSA signature, we employ a ECC key with the id `--id 11`. The signature is quite similar as with RSA.

To sign the data:
```
$ pkcs11-tool --id 11 --sign --pin 648219 --mechanism ECDSA-SHA1 -i data -o data.sig --signature-format openssl
Using slot 0 with a present token (0x0)
Using signature algorithm ECDSA-SHA256
```

The signature is verified with the hash:
```
$ openssl pkeyutl -verify -pubin -inkey 11.pub -in data.sha1 -sigfile data.sig                              
Signature Verified Successfully
```
