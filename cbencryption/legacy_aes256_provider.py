from typing import List, Callable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac, constant_time

from couchbase.encryption import EncryptionResult, Decrypter, Keyring
from couchbase.exceptions import InvalidCipherTextException, CryptoKeyNotFoundException, InvalidCryptoKeyException


class LegacyAesProvider(object):
    _BLOCK_SIZE = algorithms.AES.block_size

    def __init__(
        self,  # type: "LegacyAesProvider"
        keyring,  # type: "Keyring"
        key_func,  # type: Callable[[str], str]
    ):
        self._keyring = keyring
        self._key_func = key_func

        # if "test_iv" in kwargs:
        #     self._test_iv = kwargs.pop("test_iv")

    def aes128_decrypter(
        self,  # type: "LegacyAesProvider"
    ):
        return self.LegacyAes128Decrypter(
            self._keyring, "AES-128-HMAC-SHA256", 16, self._key_func
        )

    def aes256_decrypter(
        self,  # type: "LegacyAesProvider"
    ):
        return self.LegacyAes256Decrypter(
            self._keyring, "AES-256-HMAC-SHA256", 32, self._key_func
        )

    @classmethod
    def legacy_algorithms(
        cls,  # type: "LegacyAesProvider"
    ) -> List[str]:
        return ["AES-128-HMAC-SHA256", "AES-256-HMAC-SHA256"]

    @classmethod
    def to_bytes(
        cls,  # type: "LegacyAesProvider"
        value,  # type: str | bytes | bytearray
    ) -> bytes:

        if value is None:
            return bytes()

        if isinstance(value, str):
            return bytes(value, encoding="utf-8")
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)

        raise ValueError(
            "Value is invalid type.  Needs to be str, bytes or bytearray."
        )

    @classmethod
    def is_valid_key_length(
        cls,  # type: "LegacyAesProvider"
        key,  # type: "Key"
        alg,  # type: str
    ):
        if alg == "AES-128-HMAC-SHA256":
            return len(key.bytes) == 16
        elif alg == "AES-256-HMAC-SHA256":
            return len(key.bytes) == 32
        else:
            return False

    @classmethod
    def get_signature(
        cls,  # type: "LegacyAesProvider"
        hmac_key,  # type: bytes
        signature,  # type: bytes
    ) -> bytes:

        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(signature)
        h_digest = h.finalize()
        return h_digest

    @classmethod
    def remove_padding(
        cls,  # type: "LegacyAesProvider"
        plaintext,  # type: bytes
    ):
        unpadder = padding.PKCS7(LegacyAesProvider._BLOCK_SIZE).unpadder()
        plaintext_blocks = LegacyAesProvider.get_blocks(plaintext)
        unpadded_plaintext = bytes()
        for block in plaintext_blocks:
            unpadded_plaintext += unpadder.update(block)
        unpadded_plaintext += unpadder.finalize()
        return unpadded_plaintext

    @classmethod
    def get_blocks(
        cls,  # type: "LegacyAesProvider"
        plaintext,  # type: bytes
    ) -> list:
        return [
            plaintext[idx : idx + LegacyAesProvider._BLOCK_SIZE]
            for idx in range(0, len(plaintext), LegacyAesProvider._BLOCK_SIZE)
        ]

    class LegacyAes128Decrypter(Decrypter):
        def __init__(
            self,  # type: "LegacyAes128Decrypter"
            keyring,  # type: Keyring
            alg,  # type: str
            key_size,  # type: int
            key_func,  # type: Callable[[str], str]
        ):
            super().__init__(keyring, alg)
            self._key_size = key_size
            self._key_func = key_func

        def decrypt(
            self,  # type: "LegacyAes128Decrypter"
            encrypted,  # type: EncryptionResult
        ) -> bytes:
            key_id = encrypted.get("kid")
            alg = encrypted.algorithm()
            iv = encrypted.get("iv")
            sig = encrypted.get("sig")
            ciphertext = encrypted.get("ciphertext")

            secret_key = self.keyring.get_key(key_id)
            if not LegacyAesProvider.is_valid_key_length(secret_key, self.algorithm()):
                raise InvalidCryptoKeyException(
                    "{} requires key with {} bytes but key {} has {} bytes.".format(
                        self.algorithm(),
                        self._key_size,
                        secret_key.id,
                        len(secret_key.bytes),
                    )
                )

            hmac_key_id = self._key_func(secret_key.id)
            hmac_key = None
            if hmac_key_id:
                hmac_key = self.keyring.get_key(hmac_key_id)

            if hmac_key is None:
                raise CryptoKeyNotFoundException(
                    "No mapping to signature key name found for encryption key '{}'.".format(
                        secret_key.id
                    )
                )

            signature_bytes = LegacyAesProvider.to_bytes(
                secret_key.id + alg + iv + ciphertext
            )
            signature = LegacyAesProvider.get_signature(hmac_key.bytes, signature_bytes)
            sig = LegacyAesProvider.to_bytes(encrypted.get_with_base64_decode("sig"))
            if not constant_time.bytes_eq(sig, signature):
                raise InvalidCipherTextException(
                    "Signature does not match."
                )

            iv = encrypted.get_with_base64_decode("iv")
            ciphertext = encrypted.get_with_base64_decode("ciphertext")
            cipher = Cipher(algorithms.AES(secret_key.bytes), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            return LegacyAesProvider.remove_padding(decrypted_data)

    class LegacyAes256Decrypter(Decrypter):
        def __init__(
            self,  # type: "LegacyAes256Decrypter"
            keyring,  # type: Keyring
            alg,  # type: str
            key_size,  # type: int
            key_func,  # type: Callable[[str], str]
        ):
            super().__init__(keyring, alg)
            self._key_size = key_size
            self._key_func = key_func

        def decrypt(
            self,  # type: "LegacyAes256Decrypter"
            encrypted,  # type: EncryptionResult
        ) -> bytes:
            key_id = encrypted.get("kid")
            alg = encrypted.algorithm()
            iv = encrypted.get("iv")

            ciphertext = encrypted.get("ciphertext")

            secret_key = self.keyring.get_key(key_id)
            if not LegacyAesProvider.is_valid_key_length(secret_key, self.algorithm()):
                raise InvalidCryptoKeyException(
                    "{} requires key with {} bytes but key {} has {} bytes.".format(
                        self.algorithm(),
                        self._key_size,
                        secret_key.id,
                        len(secret_key.bytes),
                    )
                )

            hmac_key_id = self._key_func(secret_key.id)
            hmac_key = None
            if hmac_key_id:
                hmac_key = self.keyring.get_key(hmac_key_id)

            if hmac_key is None:
                raise CryptoKeyNotFoundException(
                    "No mapping to signature key name found for encryption key '{}'.".format(
                        secret_key.id
                    )
                )

            signature_bytes = LegacyAesProvider.to_bytes(
                secret_key.id + alg + iv + ciphertext
            )
            signature = LegacyAesProvider.get_signature(hmac_key.bytes, signature_bytes)
            sig = LegacyAesProvider.to_bytes(encrypted.get_with_base64_decode("sig"))
            if not constant_time.bytes_eq(sig, signature):
                raise InvalidCipherTextException(
                    "Signature does not match."
                )

            iv = encrypted.get_with_base64_decode("iv")
            ciphertext = encrypted.get_with_base64_decode("ciphertext")
            cipher = Cipher(algorithms.AES(secret_key.bytes), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            return LegacyAesProvider.remove_padding(decrypted_data)
