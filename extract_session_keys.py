"""Extract Cobalt Strike AES and HMAC session keys from Beacon metadata."""

import argparse
import base64
import binascii
import hashlib
from pathlib import Path

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

import extract_private_key


MAGIC = b"\x00\x00\xbe\xef"


def load_rsa_private_key(path: Path):
    """Load either a PEM private key or a Java beacon_keys file."""
    data = path.read_bytes()
    if data.lstrip().startswith(b"-----BEGIN"):
        return RSA.import_key(data)
    return RSA.import_key(extract_private_key.extract_private_key(path))


def decode_metadata(value: str) -> bytes:
    """Decode a Base64 metadata value, accepting surrounding whitespace."""
    compact = "".join(value.split())
    try:
        return base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("metadata is not valid Base64") from exc


def derive_session_keys(metadata: bytes, private_key):
    cipher = PKCS1_v1_5.new(private_key)
    plaintext = cipher.decrypt(metadata, b"")
    if not plaintext or not plaintext.startswith(MAGIC):
        raise ValueError(
            "RSA decryption failed or metadata does not start with 00 00 BE EF; "
            "check that the private key matches this Beacon"
        )
    if len(plaintext) < 24:
        raise ValueError("decrypted metadata is shorter than the required 16-byte key material")

    raw_key = plaintext[8:24]
    digest = hashlib.sha256(raw_key).digest()
    # Cobalt Strike uses the first SHA-256 half for AES and the second for HMAC.
    return digest[:16], digest[16:], plaintext


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract AES/HMAC session keys from Cobalt Strike Beacon metadata"
    )
    parser.add_argument(
        "metadata",
        type=Path,
        help="file containing Base64 metadata, or use '-' to read stdin",
    )
    parser.add_argument(
        "-k",
        "--key",
        type=Path,
        default=Path("cobaltstrike.beacon_keys"),
        help="PKCS#8 PEM private key or beacon_keys file",
    )
    args = parser.parse_args()

    if str(args.metadata) == "-":
        import sys

        encoded = sys.stdin.read()
    else:
        encoded = args.metadata.read_text(encoding="ascii")

    aes_key, hmac_key, plaintext = derive_session_keys(
        decode_metadata(encoded), load_rsa_private_key(args.key)
    )
    print(f"AES key:  {aes_key.hex()}")
    print(f"HMAC key: {hmac_key.hex()}")
    print(f"Metadata plaintext ({len(plaintext)} bytes): {plaintext.hex()}")


if __name__ == "__main__":
    main()
