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
* **sc-hsm-tool**: from OpenSC. Used to initialize the device.
* **opensc-tool**: from OpenSC. Used to list and detect the reader with the HSM.

[^1]: `openssl version -a` will return the `OPENSSLDIR`, which contains `openssl.cnf` file and `ENGINESDIR`, which contains the p11 engine.

## Initialization
The first step is to initialize the HSM:
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
$ pkcs11-tool --login --login-type so --so-pin=3537363231383830 --init-pin --new-pin=648219
```

## Keypair generation
Pico HSM accepts internal keypair generation with RSA scheme. It generates a pair of private and public keys and stores both internally encrypted with a 256 bits AES key. The private key never leaves the device. It may be exported with wrap command but it will be encrypted with a passphrase and the AES key.

To generate a RSA 2048 bits, use the following command:
```
$ pkcs11-tool -l --pin 648219 --keypairgen --key-type rsa:2048 --id 1 --label "RSA2K"
Using slot 0 with a present token (0x0)
Logging in to "PicoHSM (UserPIN)".
Key pair generated:
Private Key Object; RSA 
  label:      RSA2K
  ID:         1
  Usage:      decrypt, sign, unwrap
Public Key Object; RSA 2048 bits
  label:      RSA2K
  ID:         1
  Usage:      encrypt, verify, wrap
```
The ID parameter is an internal hexadecimal number for easy identification. The label is a string that also identifies the key. Despite it allows to store multiple keys with the same ID and/or same label, internally are stored with a unique index (the key reference). In any case, do not reuse the same ID/label to avoid future conflicts.

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
