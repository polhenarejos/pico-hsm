# AES
The Pico HSM supports AES secret key generation and CBC encryption/decryption. However, OpenSC does not provide AES support for sc-hsm driver. Instead, the `sc-hsm-embedded` module is used.

First, we setup the tool:

```
alias sc-tool=pkcs11-tool --module /path/to/libsc-hsm-pkcs11.so
```

## Secret key generation
Pico HSM supports AES keys with 128, 192 and 256 bits. To generate a secret 256 bits AES key:

```
$ sc-tool -l --pin 648219 --keygen --key-type AES:32 --id 12 --label "AES32"
Using slot 0 with a present token (0x1)
Key generated:
Secret Key Object; AES length 32
	label:		AES32
	ID:			12
	Usage:	encrypt, decrypt
	Access:	sensitive, always sensitive, never extractable, local
```

For 128 bits, use the `--key-type aes:16`, for 192 bits, `aes:24`, and for 256 bits, `aes:32`.

For lack of AES support in AES, `pkcs15-tool -D` does not list AES keys. Instead, they can be listed with:

```
$ sc-tool -l --pin 648219 --list-object --type secrkey
Using slot 0 with a present token (0x1)
Secret Key Object; AES length 32
  label:		AES32
  ID:			12
  Usage:		encrypt, decrypt
  Access:		sensitive, always sensitive, never extractable, local
```

## Encryption and decryption
Once a secret AES key is generated, a content can be encrypted and decrypted symmetrically:

```
$ echo "This is a text." | sc-tool -l --pin 648219 --encrypt --id 12 --mechanism aes-cbc > crypted.aes
```

The file `crypted.aes` contains the ciphered string with the AES key generated previously.

To decrypt the message, the inverse operation:

```
$ cat crypted.aes | sc-tool -l --pin 648219 --decrypt --id 12 --mechanism aes-cbc
Using slot 0 with a present token (0x1)
Using decrypt algorithm AES-CBC

This is a text.
```

AES-CBC it is a block operation and it requires an input size multiple of 16 bytes. Thus, for a trivial data, a padding operation has to be performed beforehand.
