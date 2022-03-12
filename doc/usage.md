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
