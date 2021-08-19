import unittest
import json

from couchbase.exceptions import (
    DecryptionFailureException,
    CryptoKeyNotFoundException,
    InvalidCryptoKeyException,
    InvalidCipherTextException,
)
from cbencryption import DefaultCryptoManager
from cbencryption.unsecure_keyring import UnsecureKeyring


class TestLegacyAES256Decrypter(unittest.TestCase):
    def setUp(self):
        self.keyring = UnsecureKeyring()
        self.secret_id = "mypublickey"
        self.keyring.set_key(self.secret_id, b"!mysecretkey#9^5usdk39d&dlf)03sL")
        self.keyring.set_key("myhmackey", b"myauthpassword")
        self.encrypted_doc = {
            "alg": "AES-256-HMAC-SHA256",
            "kid": "mypublickey",
            "iv": "Cfq84/46Qjet3EEQ1HUwSg==",
            "ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
            "sig": "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
        }
        self.decrypted_value = bytes(
            json.dumps("The old grey goose jumped over the wrickety gate."), "utf-8"
        )

        self.mgr = DefaultCryptoManager()
        self.mgr.register_legacy_decrypters(
            self.keyring, lambda key: "myhmackey" if key == "mypublickey" else None
        )

    def test_decrypt(self):
        decrypted = self.mgr.decrypt(self.encrypted_doc)
        self.assertEqual(decrypted, self.decrypted_value)

    def test_decrypt_invalid_key(self):
        self.keyring.set_key(self.secret_id, b"!mysssecretkey#9^5usdk39d&dlf)03sL")

        with self.assertRaises(DecryptionFailureException):
            self.mgr.decrypt(self.encrypted_doc)

        self.encrypted_doc["alg"] = "AES-256-HMAC-SHA256"
        try:
            self.mgr.decrypt(self.encrypted_doc)
        except DecryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, InvalidCryptoKeyException)
            self.assertIn(
                "AES-256-HMAC-SHA256 requires key with 32 bytes", ex.inner_cause.message
            )

    def test_decrypt_no_kid(self):
        encrypted = {
            "alg": "AES-256-HMAC-SHA256",
            "iv": "Cfq84/46Qjet3EEQ1HUwSg==",
            "ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
            "sig": "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
        }
        with self.assertRaises(DecryptionFailureException):
            self.mgr.decrypt(encrypted)

        encrypted["alg"] = "AES-256-HMAC-SHA256"
        try:
            self.mgr.decrypt(encrypted)
        except DecryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, CryptoKeyNotFoundException)
            self.assertIn("No mapping to EncryptionResult", ex.inner_cause.message)

    def test_decrypt_no_iv(self):
        encrypted = {
            "alg": "AES-256-HMAC-SHA256",
            "kid": "mypublickey",
            "ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
            "sig": "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
        }
        with self.assertRaises(DecryptionFailureException):
            self.mgr.decrypt(encrypted)

        encrypted["alg"] = "AES-256-HMAC-SHA256"
        try:
            self.mgr.decrypt(encrypted)
        except DecryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, CryptoKeyNotFoundException)
            self.assertIn("No mapping to EncryptionResult", ex.inner_cause.message)

    def test_decrypt_no_sig(self):
        encrypted = {
            "alg": "AES-256-HMAC-SHA256",
            "kid": "mypublickey",
            "iv": "Cfq84/46Qjet3EEQ1HUwSg==",
            "ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
        }
        with self.assertRaises(DecryptionFailureException):
            self.mgr.decrypt(encrypted)

        encrypted["alg"] = "AES-256-HMAC-SHA256"
        try:
            self.mgr.decrypt(encrypted)
        except DecryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, CryptoKeyNotFoundException)
            self.assertIn("No mapping to EncryptionResult", ex.inner_cause.message)

    def test_decrypt_keyring_missing_key(self):
        self.mgr._algo_to_decrypter = {}
        self.mgr.register_legacy_decrypters(
            UnsecureKeyring(), lambda key: "myhmackey" if key == "mypublickey" else None
        )

        with self.assertRaises(DecryptionFailureException):
            self.mgr.decrypt(self.encrypted_doc)

        self.encrypted_doc["alg"] = "AES-256-HMAC-SHA256"
        try:
            self.mgr.decrypt(self.encrypted_doc)
        except DecryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, CryptoKeyNotFoundException)
            self.assertIn("Unable to determine key", ex.inner_cause.message)

    def test_decrypt_keyring_missing_hmac(self):
        keyring = UnsecureKeyring()
        keyring.set_key(self.secret_id, b"!mysecretkey#9^5usdk39d&dlf)03sL")
        self.keyring.set_key("myhmackey1", b"myauthpassword")
        self.mgr._algo_to_decrypter = {}
        self.mgr.register_legacy_decrypters(
            keyring, lambda key: None if key == "mypublickey" else None
        )

        with self.assertRaises(DecryptionFailureException):
            self.mgr.decrypt(self.encrypted_doc)

        self.encrypted_doc["alg"] = "AES-256-HMAC-SHA256"
        try:
            self.mgr.decrypt(self.encrypted_doc)
        except DecryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, CryptoKeyNotFoundException)
            self.assertIn("No mapping to signature key name", ex.inner_cause.message)

    def test_decrypt_invalid_ciphertext(self):
        self.encrypted_doc[
            "ciphertext"
        ] = "GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk="

        with self.assertRaises(DecryptionFailureException):
            self.mgr.decrypt(self.encrypted_doc)

        self.encrypted_doc["alg"] = "AES-256-HMAC-SHA256"
        try:
            self.mgr.decrypt(self.encrypted_doc)
        except DecryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, InvalidCipherTextException)
            self.assertEqual("Signature does not match.", ex.inner_cause.message)
