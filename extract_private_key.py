"""Extract the RSA private key from a Cobalt Strike beacon_keys file."""

import argparse
import base64
from pathlib import Path

import javaobj.v2 as javaobj


def extract_private_key(path: Path) -> bytes:
    """Return the embedded PKCS#8 private key as DER bytes."""
    with path.open("rb") as stream:
        key_pair = javaobj.load(stream)

    try:
        encoded = key_pair.array.value.privateKey.encoded.data
    except AttributeError as exc:
        raise ValueError("the file does not contain a Java RSA private key") from exc

    return bytes(value & 0xFF for value in encoded)


def to_pem(der: bytes) -> str:
    body = base64.encodebytes(der).decode("ascii")
    return f"-----BEGIN PRIVATE KEY-----\n{body}-----END PRIVATE KEY-----\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract a PKCS#8 RSA private key from beacon_keys"
    )
    parser.add_argument(
        "beacon_keys",
        nargs="?",
        type=Path,
        default=Path("cobaltstrike.beacon_keys"),
        help="input beacon_keys file (default: cobaltstrike.beacon_keys)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write PEM to this file instead of stdout",
    )
    args = parser.parse_args()

    pem = to_pem(extract_private_key(args.beacon_keys))
    if args.output:
        args.output.write_text(pem, encoding="ascii", newline="\n")
        print(f"[+] private key written to {args.output}")
    else:
        print(pem, end="")


if __name__ == "__main__":
    main()
