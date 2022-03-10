# Pico HSM
This is a project to create a Hardware Security Module (HSM) with a Raspberry Pico.

## Capabilities
- Key generation and protected storing.
- RSA key generation from 1024 to 4096 bits.
- ECDSA key generation from 192 to 521 bits.
- ECC curves secp192r1, secp256r1, secp384r1, secp521r1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, secp192k1 (insecure), secp256k1.
- SHA1, SHA224, SHA256, SHA384, SHA256 digests.
- RSA-PSS, RSA-PKCS and raw RSA signature.
- ECDSA signature.
- RSA-OEP and RSA-X-509 decryption.
- AES key generation of 128, 192 and 256 bits.
- AES-CBC encryption/decryption.
- PIN authorization.
- PKCS11 compliant interface.
- HRNG (hardware random number generator).
- Device Key Encryption Key (DKEK) shares.
- DKEK n-of-m threshold scheme.
- USB/CCID support with OpenSC, openssl, etc.
- Extended APDU support.

## Security considerations
All secret keys (asymmetric and symmetric) are stored encrypted in the flash memory of the Raspberry Pico. DKEK is used as a 256 bit AES key to protect private and secret keys. Keys are never stored in RAM except for signature and decryption operations. All keys (including DKEK) are loaded and cleared every time to avoid potential flaws. 

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

## Credits
Pico HSM uses the following libraries or portion of code:
- OpenSC for ASN1 manipulation.
- mbedTLS for cryptographic operations.
- gnuk for low level CCID procedures and OpenPGP support.
- TinyUSB for low level USB procedures.

In the case of gnuk, it is intended to work with STM32 processor and its family. Part of the code of CCID procedures are ported and adapted to run with Pico.
