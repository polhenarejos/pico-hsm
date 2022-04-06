# Store binary data
Pico HSM has a internal flash which can store binary data. With this approach, you can save different files, encrypt into the Pico HSM and retrieve them after.

## Maximum size
Due to internal constraints with the flash components, the maximum file size is `4096` bytes. This mechanism is mainly used to store small files, such as keys in plain text, certificates, credentials, etc.

## Store a file
Before writting a file into the Pico HSM, we generate the data file with the following text:

```
$ echo 'Pico HSM is awesome!' > test
``` 

Then, we can store the data file with the following command:

```
$ pkcs11-tool --pin 648219 --write-object test --type data --id 1 --label 'test1'
Using slot 0 with a present token (0x0)
Created Data Object:
Data object 1236368320
  label:          'test1'
  application:    'test1'
  app_id:         <empty>
  flags:           modifiable
```

This file can also be protected with the PIN. In this case, use the previous command with the `--private` flag:

```
$ pkcs11-tool --pin 648219 --write-object test --type data --id 2 --label 'test2' --private
Using slot 0 with a present token (0x0)
Created Data Object:
Data object 1329612320
  label:          'test2'
  application:    'test2'
  app_id:         <empty>
  flags:           modifiable private
```

Always provide a unique `--label`, as it will be used to index and reference the file for retrieving.

## Retrieve a file
To view the stored file, we can use the following command with the same label we employed:

```
$ pkcs11-tool --read-object --type data --label 'test1' 
Using slot 0 with a present token (0x0)
Pico HSM is awesome!
```

Note that if the `--private` flag is not provided during the writting stage, the file can be accessed without the PIN.

To retrieve a private file with the PIN:

```
$ pkcs11-tool --read-object --type data --label 'test2' --pin 648219
Using slot 0 with a present token (0x0)
Pico HSM is awesome!
```

## Using `pkcs15-tool`
PKCS15 tool can be used to list the stored files. For instance:

```
$ pkcs15-tool -D
Using reader with a card: Free Software Initiative of Japan Gnuk
PKCS#15 Card [Pico-HSM]:
	Version        : 1
	Serial number  : ESTERMHSM
	Manufacturer ID: Pol Henarejos
	Flags          : PRN generation, EID compliant


PIN [UserPIN]
	Object Flags   : [0x03], private, modifiable
	Auth ID        : 02
	ID             : 01
	Flags          : [0x812], local, initialized, exchangeRefData
	Length         : min_len:6, max_len:15, stored_len:0
	Pad char       : 0x00
	Reference      : 129 (0x81)
	Type           : ascii-numeric
	Path           : e82b0601040181c31f0201::
	Tries left     : 3

PIN [SOPIN]
	Object Flags   : [0x01], private
	ID             : 02
	Flags          : [0x9A], local, unblock-disabled, initialized, soPin
	Length         : min_len:16, max_len:16, stored_len:0
	Pad char       : 0x00
	Reference      : 136 (0x88)
	Type           : bcd
	Path           : e82b0601040181c31f0201::
	Tries left     : 15

Data object 'test1'
	applicationName: test1
	Path:            e82b0601040181c31f0201::cf00
	Data (21 bytes): 5069636F2048534D20697320617765736F6D65210A
                  
Data object 'test2'
	applicationName: test2
	Path:            e82b0601040181c31f0201::cd01
	Auth ID:         01
```

As expected, the public file is displayed (in hexadecimal string). The private file contains the `Auth ID` flag and it is not displayed.

## Delete a file
A stored file can be deleted with the following command:

```
$ pkcs11-tool --login --pin 648219 --delete-object --type data --application-label test1
```


