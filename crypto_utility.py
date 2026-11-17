#!/usr/bin/env python3
"""Cryptographic Hash & Key Derivation Utility (Python standard library only)."""

import argparse
import getpass
import hashlib
import hmac
import secrets
import sys
from pathlib import Path
from typing import Optional, Tuple

SUPPORTED_ALGORITHMS = ("sha256", "sha512")
DEFAULT_ITERATIONS = 600_000
DEFAULT_KEY_LENGTH = 32
CHUNK_SIZE = 64 * 1024


def validate_algorithm(algorithm: str) -> str:
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {algorithm}. "
            f"Choose from: {', '.join(SUPPORTED_ALGORITHMS)}"
        )
    return algorithm


def hash_string(message: str, algorithm: str = "sha256") -> str:
    if not isinstance(message, str):
        raise TypeError("Message must be a string.")
    digest = hashlib.new(validate_algorithm(algorithm))
    digest.update(message.encode("utf-8"))
    return digest.hexdigest()


def hash_file(file_path: str, algorithm: str = "sha256") -> str:
    digest = hashlib.new(validate_algorithm(algorithm))
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def derive_key(
    password: str,
    salt: Optional[bytes] = None,
    iterations: int = DEFAULT_ITERATIONS,
    key_length: int = DEFAULT_KEY_LENGTH,
) -> Tuple[bytes, bytes]:
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not password:
        raise ValueError("Password cannot be empty.")
    if not isinstance(iterations, int) or iterations < 1:
        raise ValueError("Iterations must be a positive integer.")
    if not isinstance(key_length, int) or not 1 <= key_length <= 1024:
        raise ValueError("Key length must be between 1 and 1024 bytes.")
    if salt is None:
        salt = secrets.token_bytes(16)
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be provided as bytes.")
    # The library function permits short non-empty salts for interoperability
    # and published test vectors. The CLI enforces a 16-byte minimum for
    # user-supplied salts; generated salts are always 16 bytes.
    if not salt:
        raise ValueError("Salt cannot be empty.")

    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=key_length
    )
    return key, salt


def generate_hmac(
    message: str, key: bytes, algorithm: str = "sha256"
) -> str:
    algorithm = validate_algorithm(algorithm)
    if not isinstance(message, str):
        raise TypeError("Message must be a string.")
    if not isinstance(key, bytes) or not key:
        raise ValueError("HMAC key must be non-empty bytes.")
    return hmac.new(key, message.encode("utf-8"), digestmod=algorithm).hexdigest()


def verify_hmac(
    message: str, key: bytes, expected_hmac: str, algorithm: str = "sha256"
) -> bool:
    if not isinstance(expected_hmac, str):
        return False
    try:
        expected = bytes.fromhex(expected_hmac)
        actual = bytes.fromhex(generate_hmac(message, key, algorithm))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def compare_checksums(
    file_path: str, expected_checksum: str, algorithm: str = "sha256"
) -> bool:
    if not isinstance(expected_checksum, str):
        raise ValueError("Expected checksum must be a string.")
    try:
        expected = bytes.fromhex(expected_checksum)
    except ValueError as exc:
        raise ValueError("Invalid hexadecimal checksum.") from exc
    actual = bytes.fromhex(hash_file(file_path, algorithm))
    return hmac.compare_digest(actual, expected)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cryptographic Hash & Key Derivation Utility"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    string_parser = subparsers.add_parser("hash-string", help="Hash a string.")
    string_parser.add_argument("message")
    string_parser.add_argument(
        "--algorithm", choices=SUPPORTED_ALGORITHMS, default="sha256"
    )

    file_parser = subparsers.add_parser("hash-file", help="Hash a file.")
    file_parser.add_argument("file")
    file_parser.add_argument(
        "--algorithm", choices=SUPPORTED_ALGORITHMS, default="sha256"
    )

    derive_parser = subparsers.add_parser(
        "derive-key", help="Derive a key with PBKDF2-HMAC-SHA256."
    )
    derive_parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    derive_parser.add_argument("--length", type=int, default=DEFAULT_KEY_LENGTH)
    derive_parser.add_argument("--salt", help="Optional salt in hexadecimal.")

    hmac_parser = subparsers.add_parser(
        "hmac-verify", help="Verify an HMAC-SHA256 authentication tag."
    )
    hmac_parser.add_argument("message")
    hmac_parser.add_argument("--key-hex", required=True)
    hmac_parser.add_argument("--expected", required=True)

    checksum_parser = subparsers.add_parser(
        "compare-checksum", help="Compare a file with an expected checksum."
    )
    checksum_parser.add_argument("file")
    checksum_parser.add_argument("expected_checksum")
    checksum_parser.add_argument(
        "--algorithm", choices=SUPPORTED_ALGORITHMS, default="sha256"
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "hash-string":
            print(f"Algorithm: {args.algorithm.upper()}")
            print(f"Hash: {hash_string(args.message, args.algorithm)}")

        elif args.command == "hash-file":
            print(f"File: {args.file}")
            print(f"Algorithm: {args.algorithm.upper()}")
            print(f"Checksum: {hash_file(args.file, args.algorithm)}")

        elif args.command == "derive-key":
            if args.iterations < 100_000:
                raise ValueError("CLI iteration count must be at least 100000.")
            if not 1 <= args.length <= 1024:
                raise ValueError("Key length must be between 1 and 1024 bytes.")
            salt = bytes.fromhex(args.salt) if args.salt is not None else None
            if salt is not None and len(salt) < 16:
                raise ValueError("Salt must contain at least 16 bytes.")
            password = getpass.getpass("Enter password: ")
            key, used_salt = derive_key(
                password, salt=salt, iterations=args.iterations,
                key_length=args.length
            )
            print("\nKey derivation successful.")
            print("Algorithm: PBKDF2-HMAC-SHA256")
            print(f"Iterations: {args.iterations}")
            print(f"Salt: {used_salt.hex()}")
            print(f"Derived key: {key.hex()}")

        elif args.command == "hmac-verify":
            try:
                key = bytes.fromhex(args.key_hex)
            except ValueError as exc:
                raise ValueError("HMAC key must be valid hexadecimal.") from exc
            if not key:
                raise ValueError("HMAC key cannot be empty.")
            if verify_hmac(args.message, key, args.expected, "sha256"):
                print("HMAC verification: SUCCESS")
            else:
                print("HMAC verification: FAILED")
                return 1

        elif args.command == "compare-checksum":
            if compare_checksums(args.file, args.expected_checksum, args.algorithm):
                print("Checksum comparison: MATCH")
            else:
                print("Checksum comparison: MISMATCH")
                return 1

    except (ValueError, TypeError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
