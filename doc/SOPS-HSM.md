# SOPS secrets decrypted by the HSM

**Status: working, verified end to end on a Pico HSM (RP2350B, firmware 6.6).**

SOPS has no PKCS#11 backend and never has. But it *does* support **PGP**, and GnuPG can be
backed by a PKCS#11 token, so the chain works with no change to the secrets pipeline:

```
sops → gpg → gnupg-pkcs11-scd → PKCS#11 → RSA key on the HSM
```

Proof it reaches the hardware — the scdaemon log during `sops --decrypt`:

```
chan_0 <- PKDECRYPT 3DDB240D13542FCBC558A2D8C510D5CF7BC5F683
```

`PKDECRYPT` means the RSA unwrap of the SOPS data key happened ON THE CARD. Not a software
key that happens to live near one.

## What this does and does not solve

It hardens the **human/ops** decryption path. It does **NOT** fix CI.

CI cannot use a physical token, so `SOPS_AGE_KEY` remains a software key that decrypts
everything — the exact weakness a custody review called the weakest hop in the chain. Adding a
PGP recipient does not remove it. If CI is the target, the answer is different: put SOPS behind
**Vault or OpenBAO** (both natively supported), authenticate CI with a short-lived token, and use
the HSM to protect Vault's seal instead.

Worth being explicit because the improvement is easy to overstate: this makes an operator's
laptop stop holding a decryption key. It does not make the repo's secrets unreachable to whoever
controls CI.

## Two steps that are not obvious

**1. The card needs an X.509 CERTIFICATE, not just the key.** `gnupg-pkcs11-scd` enumerates
tokens by certificate; a bare private key is invisible to it. `SCD LEARN` returns a bare `OK`
with no `KEYPAIRINFO` and nothing explains why. The importer only writes the key, so the cert has
to be written separately, WITH THE SAME `--id` as the key:

```sh
openssl x509 -in rsa.crt -outform DER -out rsa.cer
pkcs11-tool --module $M --login --pin $PIN --write-object rsa.cer --type cert --id 32 --label rsa-signing
```

**2. `gpg` and `gpg-agent` learn the card separately.** `SCD LEARN` tells *scdaemon*, which is not
enough — `gpg --full-generate-key` then rejects the keygrip with "No key with this keygrip". The
agent needs its own learn, which writes a shadow key into `private-keys-v1.d/`:

```sh
gpg-connect-agent 'LEARN --send' /bye
gpg-connect-agent 'HAVEKEY <keygrip>' /bye     # must answer OK
```

## Recipe

```sh
export GNUPGHOME=/path/to/hsm-gnupghome     # keep it ISOLATED from your real ~/.gnupg
mkdir -p $GNUPGHOME && chmod 700 $GNUPGHOME

cat > $GNUPGHOME/gpg-agent.conf <<'EOF'
scdaemon-program /opt/homebrew/bin/gnupg-pkcs11-scd
EOF

cat > $GNUPGHOME/gnupg-pkcs11-scd.conf <<'EOF'
providers opensc
provider-opensc-library /opt/homebrew/lib/opensc-pkcs11.so
pin-cache 0
EOF

# 1. import an RSA key onto the card (ALWAYS import, never generate on-card, so the key stays
#    reconstructible from its Shamir shares) and write its certificate alongside — see above.
# 2. teach both daemons about it:
gpg-connect-agent 'SCD LEARN --force' /bye     # note the keygrip in KEYPAIRINFO
gpg-connect-agent 'LEARN --send' /bye

# 3. bind an OpenPGP identity to that keygrip:
gpg --expert --full-generate-key
#    (13) Existing key  ->  paste the keygrip  ->  Q  ->  0  ->  y  ->  name/email  ->  O

# 4. use it:
sops --encrypt --pgp <FINGERPRINT> secret.yaml > secret.enc.yaml
sops --decrypt secret.enc.yaml
```

The resulting key lists as `sec>` — the `>` means the private half is a stub pointing at the
card, with `Card serial no.` shown. Key material never leaves the HSM.

## Migration, without a flag day

SOPS decrypts with WHICHEVER recipient it can reach, so the PGP key is added ALONGSIDE the
existing age recipients rather than replacing them. Add `pgp:` next to `age:` in `.sops.yaml`,
run `sops updatekeys` over every `*.sops.*` file, and both paths work. Nothing needs to be
cut over at once, and losing the HSM does not lock anyone out.

## Constraints

- **age/X25519 cannot move to this HSM.** The card does ECDSA/ECDH on prime curves and RSA; it
  has no X25519 and no Ed25519. That is why this uses the PGP backend instead of an age plugin,
  and it independently confirms what the custody notes already said about age needing a
  YubiKey-PIV recipient rather than a SmartCard-HSM.
- `gnupg-pkcs11-scd` is a niche bridge (0.11.0). GnuPG warns that it is "older than us". It
  works, but it is a small dependency in a critical path — worth knowing before relying on it.
- Automating the PIN via a scripted `pinentry-program` is fine for a STAGING token with a
  documented dev PIN. Never do it for a token holding real secrets: it defeats the point of
  requiring physical presence.

## Also proven: GPG proper, and the envelope pattern

**The card-backed PGP key is a fully functional GPG key**, not just a SOPS decryptor:

- detached signatures — `Good signature`, and a tampered artifact correctly gives `BAD signature`
- `--encrypt` / `--decrypt` round-trip
- **real git commit signing** — `git commit -S` verified `Good signature` via `git log --show-signature`

That covers release-artifact signing, code signing and commit signing off the same key.

## Envelope encryption: protecting secrets the card CANNOT operate on

The card has no X25519, so it can never *be* an age identity. It can still *protect* one:

```sh
age-keygen -o age-key.txt
gpg --encrypt --recipient $FPR --output age-key.txt.gpg age-key.txt
rm age-key.txt                       # plaintext gone; only the wrapped copy remains

# use it without the key ever touching disk:
gpg --decrypt age-key.txt.gpg | age -d -i /dev/stdin payload.age
```

Verified working, with `PKDECRYPT` in the scdaemon log confirming the card performed the unwrap.

**Know what this does and does not buy.** The age key is protected AT REST and never written to
disk in plaintext — but it exists IN RAM while in use, and the card does not perform the age
operation itself. Compare with using PGP directly for SOPS, where no age key exists at all and
the card does the real work. For SOPS, direct PGP is STRICTLY BETTER; the envelope is for tools
that require age specifically.

The pattern generalises to any secret the card cannot natively operate on — Ed25519 SSH keys,
API tokens, database credentials. That makes the HSM the root of an envelope-encryption scheme
covering arbitrary secrets, rather than only the algorithms it implements. It is the honest
version of "poor-man's KMS": strong for storage, weaker in use than a real KMS that never
releases key material at all.

## CONSTRAINT: multiple certificates break the GPG binding

Discovered by adding a second key/cert to a card whose GPG identity already worked.

PKCS#11 handles multiple keys fine — secp256k1, RSA-2048 and P-256 coexisted and all signed
correctly via `pkcs11-tool` throughout. **`gnupg-pkcs11-scd` does not.** After a second
certificate was written to the card, `sops --decrypt` HUNG, with the bridge looping on:

```
KEYINFO 3DDB240D13542FCBC558A2D8C510D5CF7BC5F683  ->  ERR 41 Wrong public key algorithm
```

The card was never at fault: raw PKCS#11 signatures with both the wallet key and the RSA key
kept working the whole time. The bridge simply cannot resolve which key a keygrip refers to once
several certificates are present, and it fails by hanging rather than erroring out.

This matters for the "one card, many purposes" idea. Options, none free:

- keep the GPG-bearing card to a SINGLE certificate, and put other key types on another token
- constrain the bridge's view via its provider/cert filtering options (untested here)
- avoid the bridge for multi-purpose cards and use PKCS#11 directly where the tooling allows it
  (ssh -I, openssl engine, pkcs11-tool all worked with all three keys present)

Note the asymmetry: everything that speaks PKCS#11 NATIVELY was unaffected. Only the GnuPG
bridge broke. So a multi-purpose card is fine for SSH, TLS, CA and wallet work; it is GPG
specifically that wants a card to itself.
