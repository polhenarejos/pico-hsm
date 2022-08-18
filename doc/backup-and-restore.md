# Backup and restore
Pico HSM supports secure backup and restore. This mechanism is used to export a private key securely and restore it into another Pico HSM or the same device. The exported key is encrypted with the Device Key Encryption Key (DKEK), an AES 256 bits key that is stored safely during the initialization.

## Initialization

It is highly recommended to initialize the Pico HSM with a known DKEK. You have multiple options:
* No DKEK (be careful!)
* Single DKEK share: the DKEK is stored safely with a passphrase outside the device and kept by one custodian. If the custodian looses the DKEK share or an attacker gets the share and the passphrase, the Pico HSM and all its contents will be compromised.
* Multiple DKEK shares: the DKEK is created from multiple portions of the original DKEK, kept by multiple custodians. For instance, a DKEK with 3 shares implies that the device cannot be fully initialized until all 3 custodians load their portion into the device. The order is irrelevant.
* DKEK n-of-m threshold scheme: the DKEK is created with at minimum of n of m portions. It adds more flexibility, as it does not require the availability of all custodians. For instance, an scheme of 3-of-5 implies that the DKEK can be created with the portions of 3 custodians of 5 in total. The order is irrelevant.

### No DKEK
If no DKEK is provided during the initialization, the Pico HSM will generate one randomly. Note that in this case, despite you still can export a private key but **you cannot import it into another Pico HSM**, since you do not know the DKEK. Furthermore, if you initialize again the device, another DKEK will be stored and the backups will not be restored, as they were encrypted with another DKEK.

Note that, even no DKEK is provided, the Pico HSM generates a DKEK internally but it is never exported for obvious reasons.

### Single DKEK
Before initializing the device, a DKEK is created with:

```
$ sc-hsm-tool --create-dkek-share dkek.pbe
Using reader with a card: Free Software Initiative of Japan Gnuk

The DKEK share will be enciphered using a key derived from a user supplied password.
The security of the DKEK share relies on a well chosen and sufficiently long password.
The recommended length is more than 10 characters, which are mixed letters, numbers and
symbols.

Please keep the generated DKEK share file in a safe location. We also recommend to keep a
paper printout, in case the electronic version becomes unavailable. A printable version
of the file can be generated using "openssl base64 -in <filename>".
Enter password to encrypt DKEK share :

Please retype password to confirm :

Enciphering DKEK share, please wait...
DKEK share created and saved to dkek.pbe
```

The generated file `dkek.pbe` contains the DKEK. Technically, it contains a share. But if a device is initialized with one share, it is equivalent to contain the full DKEK.

Keep these file in a safe place. If this file is lost, you can export the private keys but you will not be able to import into another device or in the same device if it is initialized again.

To initialize the device with a single share:

```
sc-hsm-tool --initialize --so-pin 3537363231383830 --pin 648219 --dkek-shares 1
```

At this moment, the Pico HSM expects the DKEK. It is loaded with the following command:

```
$ sc-hsm-tool --import-dkek-share dkek.pbe
Using reader with a card: Free Software Initiative of Japan Gnuk
Enter password to decrypt DKEK share :

Deciphering DKEK share, please wait...
DKEK share imported
DKEK shares          : 1
DKEK key check value : 4B7DA256ACD4EF62
```

The Pico HSM is fully operative and you are ready to generate, export and import keys.

### Multiple DKEK
The process is similar with the [Single DKEK](#single-dkek), but it is repeated with multiple DKEK:

```
$ sc-hsm-tool --create-dkek-share dkek-share-1.pbe
$ sc-hsm-tool --create-dkek-share dkek-share-2.pbe
$ sc-hsm-tool --create-dkek-share dkek-share-3.pbe
```

The device is then initialized with 3 DKEK shares:

```
sc-hsm-tool --initialize --so-pin 3537363231383830 --pin 648219 --dkek-shares 3
```

And finally, all are imported one after the other, without special order:
```
$ sc-hsm-tool --import-dkek-share dkek-share-1.pbe
Using reader with a card: Free Software Initiative of Japan Gnuk
Enter password to decrypt DKEK share :

Deciphering DKEK share, please wait...
DKEK share imported
DKEK shares          : 3
DKEK import pending, 2 share(s) still missing

$ sc-hsm-tool --import-dkek-share dkek-share-2.pbe
Using reader with a card: Free Software Initiative of Japan Gnuk
Enter password to decrypt DKEK share :

Deciphering DKEK share, please wait...
DKEK share imported
DKEK shares          : 3
DKEK import pending, 1 share(s) still missing

$ sc-hsm-tool --import-dkek-share dkek-share-1.pbe
Using reader with a card: Free Software Initiative of Japan Gnuk
Enter password to decrypt DKEK share :

Deciphering DKEK share, please wait...
DKEK share imported
DKEK shares          : 1
DKEK key check value : 4B7DA256ACD4EF62
```

### DKEK n-of-m threshold scheme
This scheme provides an extra level of flexiblity, as not all custodians are necessary to import the DKEK share. For instance, with the previous schemes, if a custodian gets unavailable, the initialization will block until the missing custodian can got to finalize the initialization.

With n-of-m threshold scheme, it flexibilizes the number of required custodians to reduce failure points. If a share is lost, the DKEK can still be recovered without major implications.

This scheme is not a replacement of DKEK shares. Instead, it splits the DKEK share encryption password amongst the n-of-m threshold scheme. For instance, if you define 2 shares and a scheme of 3-of-5 threshold for each share, it will imply 10 different custodians, where 6 are necessary to load both shares. You can also mix one share with traditional passphrase and the other with the n-of-m threshold scheme.

To generate a DKEK share with a 3-of-5 threshold scheme:

```
sc-hsm-tool --create-dkek-share dkek-share-1.pbe --pwd-shares-threshold 3 --pwd-shares-total 5
Using reader with a card:Free Software Initiative of Japan Gnuk

The DKEK will be enciphered using a randomly generated 64 bit password.
This password is split using a (3-of-5) threshold scheme.

Please keep the generated and encrypted DKEK file in a safe location. We also recommend
to keep a paper printout, in case the electronic version becomes unavailable. A printable version
of the file can be generated using "openssl base64 -in <filename>".


Press <enter> to continue
```
After enter, it will display 5 screens with the following information:

```
Share 1 of 5


Prime       : f5:56:46:c9:a5:a1:01:87
Share ID    : 1
Share value : 99:64:68:65:d8:8d:c0:5f


Please note ALL values above and press <enter> when finished
```

The `Prime` value is the same for all custodians. Only the first custodian is required to introduce it. Nevertheless, it is recommended that all custodians keep also the `Prime` value.

To import the DKEK share encrypted with this scheme:

```
$ sc-hsm-tool --import-dkek-share dkek-share-1.pbe --pwd-shares-total 3
Using reader with a card: Free Software Initiative of Japan Gnuk

Deciphering the DKEK for import into the SmartCard-HSM requires 3 key custodians
to present their share. Only the first key custodian needs to enter the public prime.
Please remember to present the share id as well as the share value.

Please enter prime: f5:56:46:c9:a5:a1:01:87
```

Then, all custodians introduce the `Share ID` and `Share value`:

```
Share 1 of 3

Please enter share ID: 1
Please enter share value: 99:64:68:65:d8:8d:c0:5f
```

After the 3 custodians introduce the share values, the share is successfully loaded.

## Backup
Once the Pico HSM is fully initialized, the device is ready to generate private keys and export them. To wrap a key and export them, the `Key Reference` field is necessary. To obtain it, you can list the objects with the `pkcs15-tool`:

```
$ pkcs15-tool -D
Using reader with a card: Free Software Initiative of Japan Gnuk
...
Private RSA Key [Certificate]
	Object Flags    : [0x03], private, modifiable
	Usage             : [0x2E], decrypt, sign, signRecover, unwrap
	Access Flags    : [0x1D], sensitive, alwaysSensitive, neverExtract, local
	Algo_refs         : 0
	ModLength      : 2048
	Key ref            : 1 (0x01)
	Native             : yes
	Auth ID           : 01
	ID                    : 01
	MD:guid           : 748d16af-097a-cd84-2d62-92048f30f21d
...
```

Note that `Key ref` and `ID` may be different. Whilst different keys may share the same `ID` (highly discouraged), the `Key ref` is a value internally computed and unique.

To export and wrap the private key:

```
$ sc-hsm-tool --wrap-key wrap-key.bin --key-reference 1 --pin 648219
```

A file named `wrap-key.bin` is created with the private key encrypted securely with the DKEK.

## Restore
To restore the wraped key, a device initialized with the same DKEK is mandatory.

To unwrap the key:

```
$ sc-hsm-tool --unwrap-key wrap-key.bin --key-reference 10 --pin 648219
Using reader with a card: Free Software Initiative of Japan Gnuk
Wrapped key contains:
  Key blob
  Private Key Description (PRKD)
  Certificate
Key successfully imported
```
Now, the key is restored in the device with the same `ID` as the original and with the specified `Key ref`.
