import unittest
import json
import base64

from couchbase.exceptions import (
    CryptoKeyNotFoundException,
    DecryptionFailureException,
    EncryptionFailureException,
    InvalidCipherTextException,
    InvalidCryptoKeyException,
)

from cbencryption import DefaultCryptoManager, AeadAes256CbcHmacSha512Provider
from cbencryption.unsecure_keyring import UnsecureKeyring


class TestAES256Provider(unittest.TestCase):
    def setUp(self):
        self.keyring = UnsecureKeyring()
        self.secret_id = "my_secrect"
        self.keyring.set_key(
            self.secret_id,
            bytes.fromhex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            ),
        )
        self.test_iv = bytes.fromhex("1af38c2dc2b96ffdd86694092341bc04")
        self.aes256_provider = AeadAes256CbcHmacSha512Provider(
            self.keyring, test_iv=self.test_iv
        )

        self.encrypted_value = b"GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk="
        self.decrypted_value = bytes(json.dumps("The enemy knows the system."), "utf-8")

        self.mgr = DefaultCryptoManager()
        self.mgr.default_encrypter(
            self.aes256_provider.encrypter_for_key(self.secret_id)
        )
        self.mgr.register_decrypter(self.aes256_provider.decrypter())

    def test_encrypt_decrypt(self):
        encrypted = self.mgr.encrypt(self.decrypted_value)

        self.assertIsNotNone(encrypted)
        self.assertEqual(encrypted["kid"], self.secret_id)
        self.assertEqual(encrypted["alg"], self.aes256_provider.algorithm)
        self.assertEqual(encrypted["ciphertext"], self.encrypted_value)

        decrypted = self.mgr.decrypt(encrypted)
        self.assertEqual(decrypted, self.decrypted_value)

    def test_encrypt_decrypt_assc_data(self):
        plaintext = bytearray.fromhex("41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20")
        plaintext.extend(
            bytearray.fromhex("6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75")
        )
        plaintext.extend(
            bytearray.fromhex("69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65")
        )
        plaintext.extend(
            bytearray.fromhex("74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62")
        )
        plaintext.extend(
            bytearray.fromhex("65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69")
        )
        plaintext.extend(
            bytearray.fromhex("6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66")
        )
        plaintext.extend(
            bytearray.fromhex("20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f")
        )
        plaintext.extend(
            bytearray.fromhex("75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65")
        )

        assc_data = bytes.fromhex(
            "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673"
        )

        encrypted = self.mgr.encrypt(plaintext, associated_data=assc_data)

        self.assertIsNotNone(encrypted)
        self.assertEqual(encrypted["kid"], self.secret_id)
        self.assertEqual(encrypted["alg"], self.aes256_provider.algorithm)

        expected = bytearray.fromhex("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04")
        expected.extend(
            bytearray.fromhex("4a ff aa ad b7 8c 31 c5 da 4b 1b 59 0d 10 ff bd")
        )
        expected.extend(
            bytearray.fromhex("3d d8 d5 d3 02 42 35 26 91 2d a0 37 ec bc c7 bd")
        )
        expected.extend(
            bytearray.fromhex("82 2c 30 1d d6 7c 37 3b cc b5 84 ad 3e 92 79 c2")
        )
        expected.extend(
            bytearray.fromhex("e6 d1 2a 13 74 b7 7f 07 75 53 df 82 94 10 44 6b")
        )
        expected.extend(
            bytearray.fromhex("36 eb d9 70 66 29 6a e6 42 7e a7 5c 2e 08 46 a1")
        )
        expected.extend(
            bytearray.fromhex("1a 09 cc f5 37 0d c8 0b fe cb ad 28 c7 3f 09 b3")
        )
        expected.extend(
            bytearray.fromhex("a3 b7 5e 66 2a 25 94 41 0a e4 96 b2 e2 e6 60 9e")
        )
        expected.extend(
            bytearray.fromhex("31 e6 e0 2c c8 37 f0 53 d2 1f 37 ff 4f 51 95 0b")
        )
        expected.extend(
            bytearray.fromhex("be 26 38 d0 9d d7 a4 93 09 30 80 6d 07 03 b1 f6")
        )
        expected.extend(
            bytearray.fromhex("4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf")
        )
        expected.extend(
            bytearray.fromhex("2e 62 69 a8 c5 6a 81 6d bc 1b 26 77 61 95 5b c5")
        )

        # The ciphertext is base64 encoded
        ciphertext_b64d = base64.b64decode(encrypted["ciphertext"])
        self.assertEqual(ciphertext_b64d, expected)

        decrypted = self.mgr.decrypt(encrypted, associated_data=assc_data)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_missing_key(self):
        encrypter = self.aes256_provider.encrypter_for_key("not-a-key")
        self.mgr.register_encrypter("test-encrypter", encrypter)
        with self.assertRaises(EncryptionFailureException):
            self.mgr.encrypt(self.decrypted_value, encrypter_alias="test-encrypter")

        try:
            self.mgr.encrypt(self.decrypted_value, encrypter_alias="test-encrypter")
        except EncryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, CryptoKeyNotFoundException)
            self.assertIn("Unable to determine key", ex.inner_cause.message)

    def test_encrypt_invalid_key(self):
        self.keyring.set_key(
            self.secret_id,
            bytes.fromhex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
            ),
        )

        with self.assertRaises(EncryptionFailureException):
            self.mgr.encrypt(self.decrypted_value)

        try:
            self.mgr.encrypt(self.decrypted_value)
        except EncryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, InvalidCryptoKeyException)
            self.assertIn(
                "AEAD_AES_256_CBC_HMAC_SHA512 requires key with 64 bytes",
                ex.inner_cause.message,
            )

    def test_decrypt_invalid_key(self):
        self.keyring.set_key(
            self.secret_id,
            bytes.fromhex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
            ),
        )

        encrypted = {
            "alg": "AEAD_AES_256_CBC_HMAC_SHA512",
            "kid": self.secret_id,
            "ciphertext": b"GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk=",
        }
        with self.assertRaises(DecryptionFailureException):
            self.mgr.decrypt(encrypted)

        encrypted["alg"] = "AEAD_AES_256_CBC_HMAC_SHA512"
        try:
            self.mgr.decrypt(encrypted)
        except DecryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, InvalidCryptoKeyException)
            self.assertIn(
                "AEAD_AES_256_CBC_HMAC_SHA512 requires key with 64 bytes",
                ex.inner_cause.message,
            )

    def test_decrypt_no_kid(self):
        encrypted = {
            "alg": "AEAD_AES_256_CBC_HMAC_SHA512",
            "ciphertext": b"GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk=",
        }

        with self.assertRaises(DecryptionFailureException):
            self.mgr.decrypt(encrypted)

        encrypted["alg"] = "AEAD_AES_256_CBC_HMAC_SHA512"
        try:
            self.mgr.decrypt(encrypted)
        except DecryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, CryptoKeyNotFoundException)
            self.assertIn("No mapping to EncryptionResult", ex.inner_cause.message)

    def test_decrypt_keyring_missing_key(self):
        aes256_provider = AeadAes256CbcHmacSha512Provider(UnsecureKeyring())
        self.mgr._algo_to_decrypter = {}
        self.mgr.register_decrypter(aes256_provider.decrypter())

        encrypted = {
            "alg": "AEAD_AES_256_CBC_HMAC_SHA512",
            "kid": self.secret_id,
            "ciphertext": b"GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk=",
        }
        with self.assertRaises(DecryptionFailureException):
            self.mgr.decrypt(encrypted)

        encrypted["alg"] = "AEAD_AES_256_CBC_HMAC_SHA512"
        try:
            self.mgr.decrypt(encrypted)
        except DecryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, CryptoKeyNotFoundException)
            self.assertIn("Unable to determine key", ex.inner_cause.message)

    def test_decrypt_invalid_ciphertext(self):
        encrypted = {
            "alg": "AEAD_AES_256_CBC_HMAC_SHA512",
            "kid": self.secret_id,
            "ciphertext": b"GvOMLcK5b/3YZpQJI0G8BEr/qq23jDHF2ksbWQ0Q/7092NXTAkI1JpEtoDfsvMe9giwwHdZ8NzvMtYStPpJ5wubRKhN0t38HdVPfgpQQRGs269lwZilq5kJ+p1wuCEahGgnM9TcNyAv+y60oxz8Js6O3XmYqJZRBCuSWsuLmYJ4x5uAsyDfwU9IfN/9PUZULviY40J3XpJMJMIBtBwOx9k3TtMCIp/RcIWg5ZFsgEr8uYmmoxWqBbbwbJndhlVvF",
        }
        with self.assertRaises(DecryptionFailureException):
            self.mgr.decrypt(encrypted)

        encrypted["alg"] = "AEAD_AES_256_CBC_HMAC_SHA512"
        try:
            self.mgr.decrypt(encrypted)
        except DecryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, InvalidCipherTextException)
            self.assertEqual(
                "Failed to authenticate the ciphertext and associated data.",
                ex.inner_cause.message,
            )
