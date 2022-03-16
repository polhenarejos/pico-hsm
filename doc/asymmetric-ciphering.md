# Asymmetric encryption and decryption

Pico HSM supports in place decryption with the following algorithms:
* RSA-PKCS
* RSA-X-509
* RSA-PKCS-OAEP
* ECDH-DERIVE

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
This algorithm uses the PKCSv1.5 padding. It is considered deprecated and insecure.
First, we encrypt the data with the public key:

```
$ openssl rsautl -encrypt -inkey 1.pub -in data -pubin -out data.crypt 
```

Then, we decrypt with the private key inside the Pico HSM:

``` 
$ pkcs11-tool --id 1 --pin 648219 --decrypt --mechanism RSA-PKCS -i data.crypt
Using slot 0 with a present token (0x0)
Using decrypt algorithm RSA-PKCS
This is a test string. Be safe, be secure.
```

## RSA-X-509
In this algorithm, the data must be padded with a length equal to the size of private key (128, 256, 512 bytes for RSA-1024, RSA-2048 and RSA-4096, respectively).

First, we pad the data. The original data file occupies 29 bytes. Thus, for a 2048 bits key, a padding of 227 bytes is needed:

```
$ cp data data_pad
$ dd if=/dev/zero bs=1 count=227 >> data_pad
```

we encrypt the data with the public key:

```
$ openssl rsautl -encrypt -inkey 1.pub -in data_pad -pubin -out data.crypt -raw
```

Then, we decrypt with the private key inside the Pico HSM:
```
$ cat data.crypt|pkcs11-tool --id 4 --pin 648219 --decrypt --mechanism RSA-X-509 
Using slot 0 with a present token (0x0)
Using decrypt algorithm RSA-X-509
This is a test string. Be safe, be secure.
```

## RSA-PKCS-OAEP
This algorithm is defined as PKCSv2.1 and it includes a padding mechanism to avoid garbage. Currently it only supports SHA256.

To encrypt the data:
```
$ openssl pkeyutl -encrypt -inkey 1.pub -pubin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in data -out data.crypt
```

To decrypt with the private key inside the Pico HSM:
```
$ pkcs11-tool --id 1 --pin 648219 --decrypt --mechanism RSA-PKCS-OAEP -i data.crypt
Using slot 0 with a present token (0x0)
Using decrypt algorithm RSA-PKCS-OAEP
OAEP parameters: hashAlg=SHA256, mgf=MGF1-SHA256, source_type=0, source_ptr=0x0, source_len=0
This is a test string. Be safe, be secure.
```

## ECDH-DERIVE
ECC keys do not allow ciphering operations. Instead, the ECDH scheme provides a mechanism to exchange a shared symmetric key without transmitting it to the remote part. The shared key is composed by multiplying the local private key and the remote public key. 

First, we create the remote part, Bob, by generating an ECC keypair and getting the public key:
```
$ openssl ecparam -genkey -name prime192v1 > bob.pem
$ openssl ec -in bob.pem -pubout -outform DER > bob.der
```

We derive the shared key by giving the Bob's public key to the Pico HSM:
```
$ pkcs11-tool --pin 648219 --id 11 --derive -i bob.der -o mine-bob.der
```

We compute the other shared key, with Bob's private key and our public key:
```
$ openssl pkeyutl -derive -out bob-mine.der -inkey bob.pem -peerkey 11.pub
```

Finally, we compare both shared keys:
```
$ cmp bob-mine.der mine-bob.der
```
No output is displayed if both are equal.

You can also view the contents of both keys:
```
$ xxd -p bob-mine.der             
9874558aefa9d92cc051e5da6d1753987e5314925d6d78bf
$ xxd -p mine-bob.der             
9874558aefa9d92cc051e5da6d1753987e5314925d6d78bf
```
