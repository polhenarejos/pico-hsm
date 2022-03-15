# Asymmetric encryption and decryption

Pico HSM supports in place decryption with the following algorithms:
* RSA-PKCS
* RSA-X-509

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
First, we encrypt the data with the public key:

```
$ openssl rsautl -encrypt -inkey 1.pub -in data -pubin -out data.crypt
```

Then, we decrypt with the private key inside the Pico HSM:

``` 
$ cat data.crypt | pkcs11-tool --id 1 --pin 648219 --decrypt --mechanism RSA-PKCS
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
