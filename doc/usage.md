# Usage

## Tools
We use multiple tools and PKCS#11 drivers and modules, depending on the purpose.
* **pkcs11-tool**: from OpenSC. It interfaces with the HSM via PKCS#11 interface. It supports different drivers and modules.
* **sc-tool**: an alias of pkcs11-tool with the sc-hsm-embedded module. It is mainly used for AES management and it is defined as:
```
$ alias sc-tool=pkcs11-tool --module /path/to/libsc-hsm-pkcs11.so
```
* **openssl**: it used for certificate and X509 generation and management. It uses the pkcs11 engine. To configure the pkcs11 engine, add the following lines at the begining of `/etc/openssl.cnf` file[^1]:
```
openssl_conf = openssl_init
[openssl_init]
engines=engine_section
[engine_section]
pkcs11 = pkcs11_section
[pkcs11_section]
engine_id = pkcs11
dynamic_path = /path/to/ENGINESDIR/pkcs11.so
MODULE_PATH = /usr/local/lib/opensc-pkcs11.so
init=0
PIN=648219
```
`opensc-pkcs11.so` can be replaced by `libsc-hsm-pkcs11.so` if desired.
* **pico-hsm-tool**: Used to initialize the device.
* **opensc-tool**: from OpenSC. Used to list and detect the reader with the HSM.

[^1]: `openssl version -a` will return the `OPENSSLDIR`, which contains `openssl.cnf` file and `ENGINESDIR`, which contains the p11 engine.

## Initialization
The first step is to initialize the HSM. To do so, use:
```
$ sc-hsm-tool --initialize --so-pin 3537363231383830 --pin 648219
```
The PIN number is used to manage all private keys in the device. It supports three attemps. After the third PIN failure, it gets blocked.
The PIN accepts from 6 to 16 characters.

The SO-PIN is used to unblock the PIN. It accepts 15 attemps. After 15 failed attempts, the device will be completely blocked and will be necessary to initialize again, erasing all private keys and losing the access. Therefore, keep the SO-PIN in a safe place.
The SO-PIN is always 16 hexadecimal characters.

## PIN and SO-PIN management
To change the SO-PIN:
```
$ pkcs11-tool --login --login-type so --so-pin 3537363231383830 --change-pin --new-pin 0123456789012345
```

To change the PIN:
```
$ pkcs11-tool --login --pin 648219 --change-pin --new-pin 123456
```

To unblock the PIN:
```
$ pkcs11-tool --login --login-type so --so-pin 3537363231383830 --init-pin --new-pin 648219
```

## Keypair generation
Pico HSM accepts internal keypair generation with RSA scheme. It generates a pair of private and public keys and stores both internally encrypted with a 256 bits AES key. The private key never leaves the device. It may be exported with wrap command but it will be encrypted with a passphrase and the AES key.

To generate a RSA 2048 bits, use the following command:
```
$ pkcs11-tool -l --pin 648219 --keypairgen --key-type rsa:2048 --id 1 --label "RSA2K"
Using slot 0 with a present token (0x0)
Key pair generated:
Private Key Object; RSA
  label:      RSA2K
  ID:         1
  Usage:      decrypt, sign
  Access:     none
Public Key Object; RSA 2048 bits
  label:      RSA2K
  ID:         1
  Usage:      encrypt, verify
  Access:     none
```
The ID parameter is an internal hexadecimal number for easy identification. The label is a string that also identifies the key. Despite it allows to store multiple keys with the same ID and/or same label, internally are stored with a unique index (the key reference). In any case, do not reuse the same ID/label to avoid future conflicts. Furthermore, it is highly recommended to use always the `--id` parameter, as it can be later referenced easily.

Pico HSM accepts RSA of 1024 (`rsa:1024`), 2048 (`rsa:2048`) and 4096 bits (`rsa:4096`).

**Caution**: RSA 2048 bits may take more than 20 seconds. RSA 4096 bits may take more than 20 minutes. The Pico HSM will work as normally and neither the HSM nor the host will block. But, in the meantime, the Pico HSM will not accept any command.
An alternative is to generate the private key locally and import it to the HSM. This approach, however, is less secure as it does not use a True RNG or HRNG like Pico HSM. Use this approach if you have plugged a TRNG or you are not worried about obtaining the highest entropy.

Pico HSM also accepts ECDSA keypairs:
* secp192r1  (prime192v1)
* secp256r1 (prime256v1)
* secp384r1 (prime384v1)
* secp521r1 (prime521v1)
* brainpoolP256r1
* brainpoolP384r1
* brainpoolP512r1
* secp192k1
* secp256k1

To use ECC keys, use the above command with the `--key-type` parameter with `EC:secp192r1`, `EC:secp256r1`, `EC:secp384r1`, `EC:secp521r1`, `EC:brainpoolP256r1`, `EC:brainpoolP384r1`, `EC:brainpoolP512r1`, `EC:secp192k1` and `EC:secp256r1`.

## Delete keys
To delete the previous generated key:
```
pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1
```

## Generate a certificate and sign it
Secret keys stored in the Pico HSM and can be used to sign data without leaving the device. To generate a certificate request and sign it with the private key stored in the device, use the following command:

```
$ openssl req -engine pkcs11 -new -key 0:1 -keyform engine -out cert.pem -text -x509 -days 365
```

The key is specified in the form of `slotid:keyid`. For Pico HSM, `slotid` is always `0` and the `keyid` is the id of the key specified with the key generation.
The `openssl.cnf` used by `openssl` command shall contain the blocks configured in [Tools section](#tools). The output will depend on your configuration, but for default configuration files it will prompt you something like this:

```
engine "pkcs11" set.
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:ES
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:patata.com
Email Address []:
```

The command terminates with success silently. Thus, if no additional output/errors are displayed, the certificate is properly generated and signed. You can check this with:

```
$ openssl x509 -in cert.pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            01:3f:b4:5a:ac:7c:1a:e7:bc:37:e0:aa:f9:31:f4:68:90:08:fc:3d
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = ES, ST = Some-State, O = Internet Widgits Pty Ltd, CN = patata.com
        Validity
            Not Before: Mar 13 17:58:00 2022 GMT
            Not After : Feb 29 17:58:00 2032 GMT
        Subject: C = ES, ST = Some-State, O = Internet Widgits Pty Ltd, CN = patata.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (1024 bit)
                Modulus:
                    00:91:85:89:5d:e0:fa:f3:2b:9e:85:75:c9:92:7d:
                    c5:18:16:c0:15:1b:4d:7e:af:1a:8c:ff:2e:39:74:
                    bb:b7:af:b4:ca:24:9d:80:c8:53:51:82:b5:c5:77:
                    0d:56:0a:08:99:84:8d:7a:28:6d:8e:c6:32:40:b0:
                    62:d6:e5:e6:28:35:08:32:d7:f7:d6:eb:10:a8:81:
                    43:9e:7c:51:b2:52:16:d2:fd:05:df:c3:dd:ee:c4:
                    dd:43:db:ca:ed:6f:10:ab:d4:59:dc:3a:2d:80:4b:
                    2c:37:75:14:df:62:e0:7a:b3:62:5b:80:5f:c5:9b:
                    a0:30:b2:ec:d3:d6:0d:58:f3
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                98:07:DA:13:B0:8E:A0:5C:97:83:68:FE:4A:25:8D:50:C4:DC:16:FA
            X509v3 Authority Key Identifier:
                keyid:98:07:DA:13:B0:8E:A0:5C:97:83:68:FE:4A:25:8D:50:C4:DC:16:FA

            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
         56:bc:32:c6:dc:4a:af:64:4e:27:1c:52:e2:9d:8a:d7:b9:e0:
         7f:f0:3a:97:08:9a:5d:64:86:88:df:2f:c5:5d:ab:ae:00:ce:
         db:13:fc:a0:a7:b3:13:4a:0b:2f:1d:9c:64:95:58:94:52:93:
         81:18:32:a5:9d:5f:be:bd:b9:47:4d:67:b7:91:e6:10:a2:12:
         3b:96:d3:8b:4d:1c:ef:12:81:63:97:85:9a:4c:04:d1:4c:da:
         99:2b:b2:82:66:c1:06:a7:2c:62:af:e2:e4:93:42:36:66:8d:
         c5:3f:e1:ec:5f:9a:f8:5f:b3:6a:8f:0e:12:5d:c9:46:38:ea:
         0b:08
```

The resulting file `cert.pem` contains the signed certificate in PEM format. Convert it into DER format and load it into the Pico HSM:

```
$ openssl x509 -in cert.pem -out cert.der -outform der
$ pkcs11-tool -l --pin 648219 --write-object cert.der --type cert --id 1
Using slot 0 with a present token (0x0)
Created certificate:
Certificate Object; type = X.509 cert
  label:      Certificate
  subject:    DN: C=ES, ST=Some-State, O=Internet Widgits Pty Ltd, CN=patata.com
  ID:         01
```

## Generate random numbers

To generate random numbers:

```
$ pkcs11-tool -l --pin 648219 --generate-random 64 | xxd -c 64 -p
Using slot 0 with a present token (0x0)
773ec49733435915f5cf056497d97d2b1e6a4af23e2851eb2adf75af40db6677115c401aa26d46677184f4cf878da6289cf3ff1a5192711377b869adbc7f2b6b
```

It supports up to $1024$ random bytes in a single call.

## Signing and verification

For signing and verification operations, check [doc/sign-verify.md](/doc/sign-verify.md).

## Asymmetric encryption and decryption

For asymmetric encryption and decryption, check [doc/asymmetric-ciphering.md](/doc/asymmetric-ciphering.md).

## Backup and restore

For backup, restore and DKEK share management, check [doc/backup-and-restore.md](/doc/backup-and-restore.md).

## AES operations

For AES key generation, encryption and decryption, check [doc/aes.md](/doc/aes.md).



