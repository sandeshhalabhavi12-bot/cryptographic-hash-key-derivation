"""Unit tests using published cryptographic known-answer test vectors."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from crypto_utility import (
    compare_checksums,
    derive_key,
    generate_hmac,
    hash_file,
    hash_string,
    verify_hmac,
)


class TestHashing(unittest.TestCase):
    def test_sha256_nist_vector(self):
        expected = (
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad"
        )
        self.assertEqual(hash_string("abc", "sha256"), expected)

    def test_sha512_nist_vector(self):
        expected = (
            "ddaf35a193617abacc417349ae204131"
            "12e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd"
            "454d4423643ce80e2a9ac94fa54ca49f"
        )
        self.assertEqual(hash_string("abc", "sha512"), expected)

    def test_empty_string_sha256(self):
        expected = (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )
        self.assertEqual(hash_string(""), expected)

    def test_invalid_algorithm(self):
        with self.assertRaises(ValueError):
            hash_string("test", "md5")


class TestPBKDF2(unittest.TestCase):
    def test_pbkdf2_sha256_known_answer(self):
        # PBKDF2-HMAC-SHA256 known-answer vector:
        # password="passwd", salt="salt", c=1, dkLen=64.
        expected = (
            "55ac046e56e3089fec1691c22544b605"
            "f94185216dde0465e68b9d57c20dacbc"
            "49ca9cccf179b645991664b39d77ef31"
            "7c71b845b1e30bd509112041d3a19783"
        )
        key, salt = derive_key("passwd", b"salt", 1, 64)
        self.assertEqual(key.hex(), expected)
        self.assertEqual(salt, b"salt")

    def test_random_salts_are_generated(self):
        key1, salt1 = derive_key("test-password", iterations=1000)
        key2, salt2 = derive_key("test-password", iterations=1000)
        self.assertEqual(len(salt1), 16)
        self.assertEqual(len(key1), 32)
        self.assertNotEqual(salt1, salt2)
        self.assertNotEqual(key1, key2)

    def test_invalid_iterations(self):
        with self.assertRaises(ValueError):
            derive_key("password", b"s" * 16, 0)

    def test_empty_salt(self):
        with self.assertRaises(ValueError):
            derive_key("password", b"", 1000)

    def test_empty_password(self):
        with self.assertRaises(ValueError):
            derive_key("", iterations=1000)


class TestHMAC(unittest.TestCase):
    def test_rfc4231_sha256_test_case_1(self):
        key = bytes.fromhex("0b" * 20)
        expected = (
            "b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7"
        )
        self.assertEqual(generate_hmac("Hi There", key), expected)

    def test_hmac_verification_success(self):
        key = b"secure-test-key"
        message = "Authenticated message"
        tag = generate_hmac(message, key)
        self.assertTrue(verify_hmac(message, key, tag))

    def test_hmac_verification_failure(self):
        key = b"secure-test-key"
        tag = generate_hmac("Original message", key)
        self.assertFalse(verify_hmac("Modified message", key, tag))

    def test_invalid_hmac_hex(self):
        self.assertFalse(verify_hmac("message", b"test-key", "not-hex"))

    def test_empty_hmac_key(self):
        with self.assertRaises(ValueError):
            generate_hmac("message", b"")


class TestFileOperations(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.file_path = Path(self.temp_directory.name) / "test.txt"
        self.content = b"Cryptographic file test"
        self.file_path.write_bytes(self.content)

    def tearDown(self):
        self.temp_directory.cleanup()

    def test_sha256_file_hash(self):
        self.assertEqual(
            hash_file(str(self.file_path), "sha256"),
            hashlib.sha256(self.content).hexdigest(),
        )

    def test_sha512_file_hash(self):
        self.assertEqual(
            hash_file(str(self.file_path), "sha512"),
            hashlib.sha512(self.content).hexdigest(),
        )

    def test_checksum_match(self):
        expected = hashlib.sha256(self.content).hexdigest()
        self.assertTrue(compare_checksums(str(self.file_path), expected))

    def test_checksum_mismatch(self):
        self.assertFalse(compare_checksums(str(self.file_path), "0" * 64))

    def test_missing_file(self):
        missing = Path(self.temp_directory.name) / "missing.txt"
        with self.assertRaises(FileNotFoundError):
            hash_file(str(missing))

    def test_invalid_checksum(self):
        with self.assertRaises(ValueError):
            compare_checksums(str(self.file_path), "invalid-checksum")


if __name__ == "__main__":
    unittest.main(verbosity=2)
