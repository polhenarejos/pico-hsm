#!/usr/bin/env python3

import argparse
import getpass
import os
import sys
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAGIC = b"PICOHSM-MEMORY\x01"
SALT_SIZE = 16
NONCE_SIZE = 12
MAX_ARCHIVE_SIZE = 64 * 1024 * 1024


def read_passphrase() -> bytes:
    value = os.environ.get("PICO_HSM_MEMORY_PASSPHRASE")
    if value is None:
        passphrase_file = os.environ.get("PICO_HSM_MEMORY_PASSPHRASE_FILE")
        if passphrase_file:
            value = Path(passphrase_file).read_text(encoding="utf-8").rstrip("\r\n")
    if value is None and sys.stdin.isatty():
        value = getpass.getpass("Memory archive passphrase: ")
    if not value:
        raise ValueError(
            "set PICO_HSM_MEMORY_PASSPHRASE or "
            "PICO_HSM_MEMORY_PASSPHRASE_FILE"
        )
    return value.encode("utf-8")


def derive_key(passphrase: bytes, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase)


def read_limited(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_ARCHIVE_SIZE:
        raise ValueError(f"archive is too large: {size} bytes")
    return path.read_bytes()


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.name}.", dir=path.parent, delete=False
        ) as output:
            temporary = Path(output.name)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def encrypt(source: Path, destination: Path, passphrase: bytes) -> None:
    plaintext = read_limited(source)
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = MAGIC + salt + nonce
    ciphertext = AESGCM(derive_key(passphrase, salt)).encrypt(
        nonce, plaintext, header
    )
    atomic_write(destination, header + ciphertext)


def decrypt(source: Path, destination: Path, passphrase: bytes) -> None:
    encrypted = read_limited(source)
    header_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE
    if len(encrypted) < header_size + 16 or not encrypted.startswith(MAGIC):
        raise ValueError("not a supported encrypted Pico HSM memory archive")
    header = encrypted[:header_size]
    salt = encrypted[len(MAGIC) : len(MAGIC) + SALT_SIZE]
    nonce = encrypted[len(MAGIC) + SALT_SIZE : header_size]
    try:
        plaintext = AESGCM(derive_key(passphrase, salt)).decrypt(
            nonce, encrypted[header_size:], header
        )
    except InvalidTag as error:
        raise ValueError("wrong passphrase or corrupted memory archive") from error
    atomic_write(destination, plaintext)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt the Pico HSM CI memory archive"
    )
    parser.add_argument("operation", choices=("encrypt", "decrypt"))
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()

    if args.source.resolve() == args.destination.resolve():
        parser.error("source and destination must differ")

    try:
        passphrase = read_passphrase()
        if args.operation == "encrypt":
            encrypt(args.source, args.destination, passphrase)
        else:
            decrypt(args.source, args.destination, passphrase)
    except (OSError, ValueError) as error:
        print(f"memory archive {args.operation} failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
