# Public Key Authentication

Public Key Authentication (PKA) is a mechanism to authenticate a legit user without introducing any PIN. The authentication is performed by signing a challenge and checking the signature result.

1. A Pico HSM #A contains a private key, whose public key will be used for authentication.
2. The public key of #A is registered into a second Pico HSM #B.
3. When a user wants to login into #B, #B generates a challenge that is passed to #A for signature.
4. #A signs the challenge and returns the signature.
5. #B verifies the signature against the challenge with the public key of #A, previously registered.
6. If the signature is valid, #B grants access to the user.

This mechanism has no retry counter or PIN throttling, as no PIN is set up on the device.

To enable PKA, the device must be initialized beforehand. In case the device has secret/private keys, all shall be exported and reimported when the set up is finished.

## Requirements

To take advantage of PKA, the following is required:

1. Two Pico HSM: one will be used only for authentication (it can be any device able to generate a private key and sign arbitrary data).
2. [SCS3](/doc/scs3.md "SCS3") tool to authenticate the user. At this time, OpenSC does not support PKA, only initialization.
3. A secret key of ECC 256 bits.

## Usage

Before using SCS3, it must be patched [scs3.patch.txt](https://github.com/polhenarejos/pico-hsm/files/8890050/scs3.patch.txt). See [SCS3](/doc/scs3.md "SCS3") for further details.

### Generate the authentication key

On a secondary device, generate a private key, on the ECC 256 bits (`brainpoolP256r1` or `secp192r1`). Label it with an easy name, such as "Authentication".

<img width="1037" src="https://user-images.githubusercontent.com/55573252/173353764-4620ece4-0d82-4a23-a153-99bf912621a7.png">

Once finished, export the public key. 

<img width="350" src="https://user-images.githubusercontent.com/55573252/173353732-63f40572-a42f-4e5c-a9ab-6e52a083956b.png">

### Initialization

On the primary device, initialize it. When prompting for an authentication mechanism, select "Public Key Authentication".

<img width="412" src="https://user-images.githubusercontent.com/55573252/173353661-17caf6db-0c76-4903-9b70-5afa79f5ae54.png"><img width="1037" alt="Captura de Pantalla 2022-06-13 a les 12 14 48" src="https://user-images.githubusercontent.com/55573252/173353822-310219dc-7c7d-4ece-9fd9-c7835c2688df.png">

Once finished, register the exported public key. A message of `0 authenticated public key(s) in 1 of 1 scheme` will appear if it is properly registered.

<img width="342" src="https://user-images.githubusercontent.com/55573252/173353917-f3f99405-c7ff-43ce-8914-6f3b713df952.png"><img width="1037" alt="Captura de Pantalla 2022-06-13 a les 12 16 17" src="https://user-images.githubusercontent.com/55573252/173353946-ee7eacf9-cead-4804-ac7a-57848f7c822b.png">

### Authentication

Plug the secondary device that stores the private key (do not load the device in the SCS3 tool) and initiate the public key authentication.

<img width="321" src="https://user-images.githubusercontent.com/55573252/173353998-8f418ec6-d90d-4168-801f-51008c78824d.png">

Select the secondary card and the Authentication private key (or the name you labeled it).

<img width="435" src="https://user-images.githubusercontent.com/55573252/173354044-50163113-829e-4d80-bbda-7b589849af73.png">

Introduce the PIN of the secondary device.

If the private key matches with the registered public key, the primary device will grant access and it will display `User PIN authenticated (9000)` (despite no PIN is provided).

From now on, you have full access and can operate normally with the primary device.

## Notes on DKEK

Pico HSM uses the PIN to protect the DKEK, which is lately used to protect private/secret keys and wrap/unwrap. However, when PKA is enabled, the authentication is not performed by introducing any PIN.
Authenticated privileges are granted when PKA succeeds, regardless of PIN, which is optional.

Nevertheless, *it is extremely recommended to combine PKA with PIN*. Note that when combined, only PKA grants authenticated privileges. Therefore, if both schemes are setup, it is necessary to unlock the DKEK with PIN verification. 
Otherwise, it will not be possible to operate with private/secret keys despite the user will be logged in. 

Unfortunately, SCS3 does not supports the combination of both schemes during the initialization. Fortunately, OpenSC does.

To initialize the device with PKA *and* PIN use the following command (or similar), which accepts the use of PIN parameter *and* PKA configuration:

```
sc-hsm-tool -X --so-pin 1234567890123456 --pin 648219 -K 1 -n 1 -s 1
```

where PKA and PIN are enabled, jointly with DKEK protection. 

Therefore, with this scheme, multiple custodians may authenticate the device individually and, when fully authenticated, the master user can unlock the DKEK with the PIN.

With this approach the device is kept safe and neither the DKEK nor the private/secret keys are stored in plain text in the device. 
Even though the flash memory is dumped by an attacker, it will not be possible to decipher any sensitive data or key.
