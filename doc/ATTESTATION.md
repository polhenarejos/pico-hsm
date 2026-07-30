# Staging HSM — what has actually been demonstrated

Hardware: Waveshare RP2350-PiZero running Pico HSM firmware 6.6, PKCS#11 serial `ESPICOHSMTR`.
Every claim below was executed against that device; none is inferred.

**This is a STAGING device.** It holds throwaway keys, its PINs are the published pico-hsm dev
defaults, and it is an open-source reimplementation on a microcontroller with no tamper
resistance. It is where procedures get proven. It is not where value gets held.

## Demonstrated

| Capability | Evidence |
|---|---|
| **Blockchain wallet** — secp256k1 | Seed-derived key imported via DKEK; card signs a fresh random digest; signature verifies against the seed's pubkey; wrong digest correctly fails. 14/14 provisioning cycles. |
| **Secrets decryption (SOPS)** | `sops --decrypt` returns plaintext with `PKDECRYPT` in the scdaemon log — the RSA unwrap of the data key happened ON THE CARD. See SOPS-HSM.md. |
| **X.509 Certificate Authority** | Signed a CSR for `CN=api.staging.internal` using the on-card RSA key. `openssl verify` returns OK against the CA cert; verification against an unrelated CA correctly fails. |
| **SSH authentication** | Real login to a local sshd with `ssh -I <module>`, remote command executed, using the on-card P-256 key. No key material on disk. |
| **GPG identity** | OpenPGP key bound to the on-card RSA key. Lists as `sec>` with a card serial — the `>` means the private half is a stub pointing at hardware. |
| **Multiple heterogeneous keys** | secp256k1 + RSA-2048 + P-256 coexisting, all `sensitive, always sensitive, never extractable`, each independently usable. |
| **Key isolation (DKEK)** | A key wrapped under a DIFFERENT DKEK share was REFUSED with SW=6400. Distinct KCVs confirm the domains genuinely differed. Isolation is enforced by the card, not by convention. |
| **Wrong PIN** | Refused; retry counter decremented and restored by a correct PIN. |
| **Persistence** | Key survives a reboot and still signs for the same public key. |

Against the categories a software/hosting company typically puts in an HSM — internal PKI, TLS,
code signing, SSH CA, secrets-manager root — this covers **PKI/CA, SSH, secrets decryption, and
the signing primitives code signing needs**, plus wallets.

## NOT demonstrated, and the limits are structural

**age / X25519 cannot ever move to this card.** It does ECDSA/ECDH on prime curves and RSA. No
X25519, no Ed25519. That is a hardware fact, not a configuration gap — it is why the SOPS path
above uses the PGP backend, and it means Ed25519 SSH keys and Ed25519 GPG keys are also out.

**Reliability is not yet production-grade.** ~7% of re-provisioning cycles hang with the device
leaving the USB bus, needing a physical replug. The cryptographic path has NEVER failed — every
completed cycle verified correctly — but recovery does. Cause unknown after three attempts; see
the commit history for two real improvements (wrong PICO_BOARD, commit-timeout sizing) and one
regression that was reverted. Diagnosis is blocked on SWD, not on more theories.

**Throughput is modest.** 2.43 sig/s, 412 ms/sig — and that is with a fresh `pkcs11-tool` process
and PIN login per signature, so it is an upper bound on latency rather than card speed. Nobody has
measured a persistent-session number.

**Everything here ran on macOS.** The target is Linux, with a different PCSC stack. Nothing has
been verified there.

**Untested:** concurrent sessions, key deletion, capacity limits, and behaviour once the flash
region fills.

## What this does and does not justify saying

Justified: *"A hardware HSM can hold this company's wallet keys, act as its internal CA, back its
SSH authentication, decrypt its SOPS secrets, and carry a GPG identity — proven end to end on
real hardware, with negative controls."*

NOT justified: that this specific device is ready to hold production keys. The reliability gap is
real, it is on the recovery path rather than the crypto path, and the production tokens (Nitrokey
HSM 2, NXP secure element) are a different implementation on which NONE of this has been repeated.

The value of this exercise is the procedures, the tooling, and the negative results — each of the
above is now a script that can be re-run against a production token in an afternoon.
