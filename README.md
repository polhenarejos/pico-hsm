# Raspberry Pico HSM
This is a project to create a Hardware Security Module (HSM) with a Raspberry Pico. It converts your Pico board into a HSM which is able to generate and store private keys, encrypt or decrypt with AES or signing data without to disclose the private key. In detail, the private key never leaves the board and it cannot be retrieved as it is encrypted in the flash memory.

## Capabilities
- Key generation and encrypted storage.
- RSA key generation from 1024 to 4096 bits.
- ECDSA key generation from 192 to 521 bits.
- ECC curves secp192r1, secp256r1, secp384r1, secp521r1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, secp192k1 (insecure), secp256k1.
- SHA1, SHA224, SHA256, SHA384, SHA512 digests.
- RSA-PSS, RSA-PKCS and raw RSA signature.
- ECDSA raw and hash signature.
- ECDH key derivation.
- EC private key derivation.[^1]
- RSA-OEP and RSA-X-509 decryption.
- AES key generation of 128, 192 and 256 bits.
- AES-CBC encryption/decryption.
- AES-CMAC authentication.[^1]
- AES secret key derivation.[^1]
- PIN authorization.
- PKCS11 compliant interface.
- HRNG (hardware random number generator).
- Device Key Encryption Key (DKEK) shares.
- DKEK n-of-m threshold scheme.
- USB/CCID support with OpenSC, openssl, etc.
- Extended APDU support.
- Private keys and certificates import from WKY or PKCS#12 files.[^2][^3]
- Transport PIN for provisioning and forcing to set a new PIN.[^2]
- Press-to-confirm button optional feature to authorize operations with private/secret keys.
- Store and retrieve binary data.
- Real time clock with external datetime setting and getting. 
- Secure Messaging (secure channel).
- Session PIN.
- PKI CVCert remote issuing for Secure Message.

[^1]: PKCS11 modules (`pkcs11-tool` and `sc-tool`) do not support CMAC and key derivation. It must be processed through raw APDU command (`opensc-tool -s`).
[^2]: Available via SCS3 tool. See [SCS3](/doc/rsa_4096.md "SCS3") for more information.
[^3]: Imports are available only if the Pico HSM is previously initialized with a DKEK and the DKEK shares are available during the import process. 

## Security considerations
All secret keys (asymmetric and symmetric) are stored encrypted in the flash memory of the Raspberry Pico. DKEK is used as a 256 bit AES key to protect private and secret keys. Keys are never stored in RAM except for signature and decryption operations and only during the process. All keys (including DKEK) are loaded and cleared every time to avoid potential security flaws. 

At the same time, DKEK is encrypted with doubled salted and hashed PIN. Also, the PIN is hashed in memory during the session. Hence, PIN is never stored in plain text neither in flash nor in memory. Note that PIN is conveyed from the host to the HSM in plain text if no secure channel is provided.

If the Pico is stolen the contents of private and secret keys cannot be read without the PIN, even if the flash memory is dumped.

## Download
Please, go to the Release page and download the UF2 file for your board. 

Note that UF2 files are shiped with a dummy VID/PID to avoid license issues (FEFF:FCFD). If you are planning to use it with OpenSC or similar, you should modify Info.plist of CCID driver to add these VID/PID or use the VID/PID patcher as follows:
`./patch_vidpid.sh VID:PID input_hsm_file.uf2 output_hsm_file.uf2`

You can use whatever VID/PID (i.e., 234b:0000 from FISJ), but remember that you are not authorized to distribute the binary with a VID/PID that you do not own.

## Build
Before building, ensure you have installed the toolchain for the Pico and the Pico SDK is properly located in your drive.

```
git clone https://github.com/polhenarejos/pico-hsm
cd pico-hsm
mkdir build
cd build
PICO_SDK_PATH=/path/to/pico-sdk cmake .. -DPICO_BOARD=board_type -DUSB_VID=0x1234 -DUSB_PID=0x5678
make
```
Note that `PICO_BOARD`, `USB_VID` and `USB_PID` are optional. If not provided, `pico` board and VID/PID `FEFF:FCFD` will be used.

After `make` ends, the binary file `pico_hsm.uf2` will be generated. Put your pico board into loading mode, by pushing `BOOTSEL` button while pluging on, and copy the UF2 to the new fresh usb mass storage Pico device. Once copied, the pico mass storage will be disconnected automatically and the pico board will reset with the new firmware. A blinking led will indicate the device is ready to work.

## Usage
The firmware uploaded to the Pico contains a reader and a virtual smart card. It is like having a physical reader with an inserted SIM card.
We recommend the use of [OpenSC](http://github.com/opensc/opensc/ "OpenSC") to communicate with the reader. If it is not installed, you can download and build it or install the binaries for your system. The first command is to ensure that the Pico is detected as a HSM:
```
opensc-tool -an
````
It should return a text like the following:
```
Using reader with a card: Free Software Initiative of Japan Gnuk
3b:fe:18:00:00:81:31:fe:45:80:31:81:54:48:53:4d:31:73:80:21:40:81:07:fa
SmartCard-HSM
```
The name of the reader may vary if you modified the VID/PID.

For initialization and asymmetric operations, check [doc/usage.md](/doc/usage.md).

For signing and verification operations, check [doc/sign-verify.md](/doc/sign-verify.md).

For asymmetric encryption and decryption, check [doc/asymmetric-ciphering.md](/doc/asymmetric-ciphering.md).

For backup, restore and DKEK share management, check [doc/backup-and-restore.md](/doc/backup-and-restore.md).

For AES key generation, encryption and decryption, check [doc/aes.md](/doc/aes.md).

For 4096 bits RSA support, check [doc/rsa_4096_support.md](/doc/rsa_4096.md).

For storing and retrieving arbitrary data, check [doc/store_data.md](/doc/store_data.md).

For extra options, such as set/get real datetime or enable/disable press-to-confirm button, check [doc/extra_command.md](/doc/extra_command.md).

## Operation time
### Keypair generation
Generating EC keys is almost instant. RSA keypair generation takes some time, specially for `3072` and `4096` bits. 

| RSA key length (bits) | Average time (seconds) |
| :---: | :---: |
| 1024 | 16 |
| 2048 | 124 |
| 3072 | 600 |
| 4096 | ~1000 |

### Signature and decrypt
| RSA key length (bits) | Average time (seconds) |
| :---: | :---: |
| 1024 | 1 |
| 2048 | 3 |
| 3072 | 7 |
| 4096 | 15 |

## Press-to-confirm button
Raspberry Pico comes with the BOOTSEL button to load the firmware. When this firmware is running, the button can be used for other purposes. Pico HSM uses this button to confirm private/secret operations. This feature is optional and it shall be enabled. For more information, see [doc/extra_command.md](/doc/extra_command.md).

With this feature enabled, everytime that a private/secret key is loaded, the Pico HSM awaits for the user confirmation by pressing the BOOTSEL button. The Led of the Pico HSM will remain almost illuminated, turning off quickly once a second, indicating that the user must press the button to confirm the operation. Otherwise, the Pico HSM waits indefinitely. See [Led blink](#press-to-confirm) for a picture of the blinking sequence. When in this mode, the Pico HSM sends periodic timeout commands to the host to do not trigger the timeout operation.

This feature is an extra layer of security, as it requires the user intervention to sign or decrypt and it ensures that any application will use the Pico HSM without user awareness. However, it is not recommended for servers or other environments where operations are authomatized, since it requires a physical access to the Pico HSM to push the button.

## Led blink
Pico HSM uses the led to indicate the current status. Four states are available:
### Press to confirm
The Led is almost on all the time. It goes off for 100 miliseconds every second.

![Press to confirm](https://user-images.githubusercontent.com/55573252/162008917-6a730eac-396c-44cc-890e-802294be30a3.gif)

### Idle mode
In idle mode, the Pico HSM goes to sleep. It waits for a command and it is awaken by the driver. The Led is almost off all the time. It goes on for 500 milliseconds every second.

![Idle mode](https://user-images.githubusercontent.com/55573252/162008980-d5a5caad-072e-400c-98e3-2c606b4b2af9.gif)

### Active mode
In active mode, the Pico HSM is awaken and ready to receive a command. It blinks four times in a second.

![Active](https://user-images.githubusercontent.com/55573252/162008997-1ea8cd7e-5384-4893-9dcb-b473153fc375.gif)

### Processing
While processing, the Pico HSM is busy and cannot receive additional commands until the current is processed. In this state, the Led blinks 20 times in a second.

![Processing](https://user-images.githubusercontent.com/55573252/162009007-df45111e-2473-4a92-97c5-15c3cd19babd.gif)

## Driver

Pico HSM uses the `sc-hsm` driver provided by [OpenSC](https://github.com/OpenSC/OpenSC/ "OpenSC") or the `sc-hsm-embedded` driver provided by [CardContact](https://github.com/CardContact/sc-hsm-embedded "CardContact"). This driver utilizes the standardized PKCS#11 interface to communicate with the user and it can be used with many engines that accept PKCS#11 interface, such as OpenSSL, P11 library or pkcs11-tool. 

Pico HSM relies on PKCS#15 structure to store and manipulate the internal files (PINs, private keys, certificates, etc.) and directories. Therefore, it accepts the commands from `pkcs15-tool`. For instance, `pkcs15-tool -D` will list all elements stored in the Pico HSM.

The way to communicate is exactly the same as with other cards, such as OpenPGP or similar.

For an advanced usage, see the docs and examples.

Pico HSM also supports SCS3 tool. See [SCS3](/doc/rsa_4096.md "SCS3") for more information.

### Important
OpenSC relies on PCSC driver, which reads a list (`Info.plist`) that contains a pair of VID/PID of supported readers. In order to be detectable, you must patch the UF2 binary (if you just downloaded from the [Release section](https://github.com/polhenarejos/pico-hsm/releases "Release section")) or configure the project with the proper VID/PID with `USB_VID` and `USB_PID` parameters in `CMake` (see [Build section](#build "Build section")). Note that you cannot distribute the patched/compiled binary if you do not own the VID/PID or have an explicit authorization.

## Credits
Pico HSM uses the following libraries or portion of code:
- OpenSC for ASN1 manipulation.
- mbedTLS for cryptographic operations.
- gnuk for low level CCID procedures and OpenPGP support.
- TinyUSB for low level USB procedures.

In the case of gnuk, it is intended to work with STM32 processor and its family. Part of the code of CCID procedures are ported and adapted to run with Pico.
