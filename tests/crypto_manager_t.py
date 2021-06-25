import unittest

from couchbase.encryption import Encrypter, Decrypter, EncryptionResult
from couchbase.exceptions import (
    DecryptionFailureException,
    EncrypterNotFoundException,
    DecrypterNotFoundException,
    EncryptionFailureException,
    DecrypterAlreadyExistsException,
    EncrypterAlreadyExistsException
)

from cbencryption import DefaultCryptoManager, AeadAes256CbcHmacSha512Provider
from cbencryption.unsecure_keyring import UnsecureKeyring


class FakeEncrypter(Encrypter):
    def __init__(
        self,  # type: "FakeEncrypter"
        keyring,  # type: Keyring
        key,  # type: str
        alg,  # type: str
    ):
        super().__init__(keyring, key)
        self._alg = alg

    def encrypt(
        self,  # type: "FakeEncrypter"
        plaintext,  # type: str | bytes | bytearray
        associated_data=None,  # type: str | bytes | bytearray
    ) -> EncryptionResult:
        return EncryptionResult(self._alg, "fake-kid", "this is a fake encrypter")


class FakeDecrypter(Decrypter):
    def __init__(
        self,  # type: "FakeDecrypter"
        keyring,  # type: Keyring
        alg,  # type: str
    ):
        super().__init__(keyring, alg)

    def decrypt(
        self,  # type: "FakeDecrypter"
        encrypted,  # type: EncryptionResult
        associated_data=None,  # type: str | bytes | bytearray
    ) -> bytes:
        return bytes("this is a fake decrypter", "utf-8")


class TestDefaultCryptoManager(unittest.TestCase):
    _DEFAULT_PREFIX = "encrypted$"

    def setUp(self):
        self.keyring = UnsecureKeyring()
        self.secret_id = "my_secrect"
        self.keyring.set_key(
            self.secret_id,
            bytes.fromhex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            ),
        )
        self.aes256_provider = AeadAes256CbcHmacSha512Provider(self.keyring)

    def test_default_prefix(self):
        mgr = DefaultCryptoManager()
        self.assertEqual(self._DEFAULT_PREFIX, mgr.encrypted_field_prefix)

    def test_default_mangle(self):
        mgr = DefaultCryptoManager()
        field = "name"
        expected = "{}{}".format(self._DEFAULT_PREFIX, field)
        mangled = mgr.mangle(field)
        self.assertEqual(mangled, expected)

    def test_default_demangle(self):
        mgr = DefaultCryptoManager()
        field = "name"
        expected = "{}{}".format(self._DEFAULT_PREFIX, field)
        mangled = mgr.mangle(field)
        self.assertEqual(mangled, expected)
        demangled = mgr.demangle(field)
        self.assertEqual(demangled, field)

    def test_default_is_mangled(self):
        mgr = DefaultCryptoManager()
        field = "name"
        expected = "{}{}".format(self._DEFAULT_PREFIX, field)
        mangled = mgr.mangle(field)
        self.assertEqual(mangled, expected)
        self.assertTrue(mgr.is_mangled(mangled))

    def test_user_defined_prefix(self):
        prefix = "__crpyto$"
        mgr = DefaultCryptoManager(encrypted_field_prefix=prefix)
        self.assertEqual(prefix, mgr.encrypted_field_prefix)

    def test_user_defined_mangle(self):
        prefix = "__crpyto$"
        mgr = DefaultCryptoManager(encrypted_field_prefix=prefix)
        field = "name"
        expected = "{}{}".format(prefix, field)
        mangled = mgr.mangle(field)
        self.assertEqual(mangled, expected)

    def test_user_defined_mangle(self):
        prefix = "__crpyto$"
        mgr = DefaultCryptoManager(encrypted_field_prefix=prefix)
        field = "name"
        expected = "{}{}".format(prefix, field)
        mangled = mgr.mangle(field)
        self.assertEqual(mangled, expected)
        demangled = mgr.demangle(field)
        self.assertEqual(demangled, field)

    def test_user_defined_is_mangled(self):
        prefix = "__crpyto$"
        mgr = DefaultCryptoManager(encrypted_field_prefix=prefix)
        field = "name"
        expected = "{}{}".format(prefix, field)
        mangled = mgr.mangle(field)
        self.assertEqual(mangled, expected)
        self.assertTrue(mgr.is_mangled(mangled))

    def test_register_default_encrypter(self):
        mgr = DefaultCryptoManager()
        encrypter = self.aes256_provider.encrypter_for_key(self.secret_id)
        mgr.default_encrypter(encrypter)
        reg_encrypter = mgr._alias_to_encrypter[mgr._DEFAULT_ENCRYPTER_ALIAS]
        self.assertEqual(id(encrypter), id(reg_encrypter))

    def test_register_default_encrypter_fail(self):
        mgr = DefaultCryptoManager()
        mgr.default_encrypter(self.aes256_provider.encrypter_for_key(self.secret_id))
        fake_encrypter = FakeEncrypter(
            self.keyring, "fake-key", "FAKE_CRYPTO_ALGORITHM"
        )
        with self.assertRaises(EncrypterAlreadyExistsException):
            mgr.default_encrypter(fake_encrypter)

    def test_register_encrypter(self):
        mgr = DefaultCryptoManager()
        encrypter = self.aes256_provider.encrypter_for_key(self.secret_id)
        alias = "foo"
        mgr.register_encrypter(alias, encrypter)
        reg_encrypter = mgr._alias_to_encrypter[alias]
        self.assertEqual(id(encrypter), id(reg_encrypter))

    def test_register_encrypter_fail(self):
        mgr = DefaultCryptoManager()
        alias = "foo"
        mgr.register_encrypter(
            alias, self.aes256_provider.encrypter_for_key(self.secret_id)
        )
        with self.assertRaises(EncrypterAlreadyExistsException):
            mgr.register_encrypter(
                alias, self.aes256_provider.encrypter_for_key(self.secret_id)
            )

    def test_register_multiple_encrypters(self):
        mgr = DefaultCryptoManager()

        mgr.default_encrypter(self.aes256_provider.encrypter_for_key(self.secret_id))

        encrypter1 = self.aes256_provider.encrypter_for_key(self.secret_id)
        alias1 = "foo"
        mgr.register_encrypter(alias1, encrypter1)

        encrypter2 = self.aes256_provider.encrypter_for_key(self.secret_id)
        alias2 = "bar"
        mgr.register_encrypter(alias2, encrypter2)

        self.assertEqual(3, len(mgr._alias_to_encrypter.items()))

        reg_encrypter1 = mgr._alias_to_encrypter[alias1]
        self.assertEqual(id(encrypter1), id(reg_encrypter1))

        reg_encrypter2 = mgr._alias_to_encrypter[alias2]
        self.assertEqual(id(encrypter2), id(reg_encrypter2))

    def test_register_decrypter(self):
        mgr = DefaultCryptoManager()
        decrypter = self.aes256_provider.decrypter()
        mgr.register_decrypter(decrypter)
        reg_decrypter = mgr._algo_to_decrypter[self.aes256_provider.algorithm]
        self.assertEqual(id(decrypter), id(reg_decrypter))

    def test_register_decrypter_fail(self):
        mgr = DefaultCryptoManager()
        mgr.register_decrypter(self.aes256_provider.decrypter())

        # this should be okay -- different algorithms
        mgr.register_decrypter(FakeDecrypter(self.keyring, "FAKE_CRYPTO_ALGORITHM"))
        fake_decrypter = FakeDecrypter(self.keyring, self.aes256_provider.algorithm)
        with self.assertRaises(DecrypterAlreadyExistsException):
            mgr.register_decrypter(fake_decrypter)

    def test_register_multiple_decrypters(self):
        mgr = DefaultCryptoManager()
        decrypter1 = self.aes256_provider.decrypter()
        mgr.register_decrypter(decrypter1)

        fake_alg = "FAKE_CRYPTO_ALGORITHM"
        decrypter2 = FakeDecrypter(self.keyring, fake_alg)
        mgr.register_decrypter(decrypter2)

        self.assertEqual(2, len(mgr._algo_to_decrypter.items()))
        reg_decrypter1 = mgr._algo_to_decrypter[self.aes256_provider.algorithm]
        self.assertEqual(id(decrypter1), id(reg_decrypter1))
        reg_decrypter2 = mgr._algo_to_decrypter[fake_alg]
        self.assertEqual(id(decrypter2), id(reg_decrypter2))

    def test_register_legacy_decrypters(self):
        mgr = DefaultCryptoManager()
        mgr.register_legacy_decrypters(
            self.keyring, lambda key: "myhmackey" if key == "mypublickey" else None
        )

        self.assertEqual(2, len(mgr._algo_to_decrypter.items()))

        self.assertIn("AES-128-HMAC-SHA256", mgr._algo_to_decrypter.keys())
        self.assertIn("AES-256-HMAC-SHA256", mgr._algo_to_decrypter.keys())

    def test_encrypt_fail_encrypter_not_found(self):
        mgr = DefaultCryptoManager()

        mgr.default_encrypter(self.aes256_provider.encrypter_for_key(self.secret_id))

        with self.assertRaises(EncryptionFailureException):
            mgr.encrypt("The enemy knows the system.", "foo")

        try:
            mgr.encrypt("The enemy knows the system.", "foo")
        except EncryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, EncrypterNotFoundException)
            self.assertIn("Cannot find encrypter for alias:", ex.inner_cause.message)

    def test_decrypt_fail_decrypter_not_found(self):
        mgr = DefaultCryptoManager()
        mgr.register_decrypter(self.aes256_provider.decrypter())

        enc_result = {
            "alg": "FAKE_CRYPTO_ALGORITHM",
            "kid": "my_secret",
            "ciphertext": b"GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk=",
        }

        with self.assertRaises(DecryptionFailureException):
            mgr.decrypt(enc_result)

        enc_result["alg"] = "FAKE_CRYPTO_ALGORITHM"
        try:
            mgr.decrypt(enc_result)
        except DecryptionFailureException as ex:
            self.assertIsNotNone(ex.inner_cause)
            self.assertIsInstance(ex.inner_cause, DecrypterNotFoundException)
            self.assertIn(
                "Cannot find decrypter for algorithm:", ex.inner_cause.message
            )

    def test_decrypt_fail_bad_encryption_result(self):
        mgr = DefaultCryptoManager()

        mgr.register_decrypter(self.aes256_provider.decrypter())

        enc_result = {
            "kid": "my_secret",
            "ciphertext": b"GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk=",
        }

        with self.assertRaises(DecryptionFailureException):
            mgr.decrypt(enc_result)
