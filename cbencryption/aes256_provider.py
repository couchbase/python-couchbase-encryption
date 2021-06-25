import os
from typing import List, Optional, Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac, constant_time

from couchbase.encryption import EncryptionResult, Encrypter, Decrypter, Keyring
from couchbase.exceptions import InvalidCryptoKeyException, InvalidCipherTextException

# pyright: reportUnboundVariable=false


class AeadAes256CbcHmacSha512Provider(object):
    _ALGORITHM = "AEAD_AES_256_CBC_HMAC_SHA512"
    _BLOCK_SIZE = algorithms.AES.block_size
    _KEY_SIZE = 64

    def __init__(
        self,  # type: "AeadAes256CbcHmacSha512Provider"
        keyring,  # type: "Keyring"
        **kwargs,  # type: Optional[Any]
    ):
        self._keyring = keyring

        self._test_iv = None
        if "test_iv" in kwargs:
            self._test_iv = kwargs.pop("test_iv")

    @property
    def keyring(
        self,  # type: "AeadAes256CbcHmacSha512Provider"
    ) -> "Keyring":
        return self._keyring

    @property
    def algorithm(
        self,  # type: "AeadAes256CbcHmacSha512Provider"
    ) -> str:
        return self._ALGORITHM

    def encrypter_for_key(
        self,  # type: "AeadAes256CbcHmacSha512Provider"
        key,  # type: str
    ):
        return self.AeadAes256CbcHmacSha512ProviderEncrypter(
            self.keyring, key, self._KEY_SIZE, self.algorithm, test_iv=self._test_iv
        )

    def decrypter(
        self,  # type: "AeadAes256CbcHmacSha512Provider"
    ):
        return self.AeadAes256CbcHmacSha512ProviderDecrypter(
            self.keyring, self._KEY_SIZE, self.algorithm
        )

    @classmethod
    def to_bytes(
        cls,  # type: "AeadAes256CbcHmacSha512Provider"
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
    def get_signature(
        cls,  # type: "AeadAes256CbcHmacSha512Provider"
        hmac_key,  # type: bytes
        ciphertext,  # type: bytes
        associated_data=None,  # type: str | bytes | bytearray
    ) -> bytes:
        h = hmac.HMAC(hmac_key, hashes.SHA512())
        associated_data = AeadAes256CbcHmacSha512Provider.to_bytes(
            associated_data)
        h.update(associated_data)
        h.update(ciphertext)
        size_in_bytes = (len(associated_data) * 8).to_bytes(8, byteorder="big")
        h.update(size_in_bytes)
        h_digest = h.finalize()
        return h_digest[:32]

    @classmethod
    def is_valid_key_length(
        cls,  # type: "AeadAes256CbcHmacSha512Provider"
        key,  # Key
    ):
        return len(key.bytes) == 64

    @classmethod
    def add_padding(
        cls,  # type: "AeadAes256CbcHmacSha512Provider"
        plaintext,  # type: bytes
    ):
        # if (len(plaintext) * 8) % AeadAes256CbcHmacSha512Provider._BLOCK_SIZE == 0:
        #     return plaintext

        padder = padding.PKCS7(
            AeadAes256CbcHmacSha512Provider._BLOCK_SIZE).padder()
        plaintext_blocks = AeadAes256CbcHmacSha512Provider.get_blocks(
            plaintext)
        padded_plaintext = bytes()
        for block in plaintext_blocks:
            padded_plaintext += padder.update(block)
        padded_plaintext += padder.finalize()
        return padded_plaintext

    @classmethod
    def remove_padding(
        cls,  # type: "AeadAes256CbcHmacSha512Provider"
        plaintext,  # type: bytes
    ):
        unpadder = padding.PKCS7(
            AeadAes256CbcHmacSha512Provider._BLOCK_SIZE).unpadder()
        plaintext_blocks = AeadAes256CbcHmacSha512Provider.get_blocks(
            plaintext)
        unpadded_plaintext = bytes()
        for block in plaintext_blocks:
            unpadded_plaintext += unpadder.update(block)
        unpadded_plaintext += unpadder.finalize()
        return unpadded_plaintext

    @classmethod
    def get_blocks(
        cls,  # type: "AeadAes256CbcHmacSha512Provider"
        plaintext,  # type: bytes
    ) -> List[bytes]:
        return [
            plaintext[idx: idx + AeadAes256CbcHmacSha512Provider._BLOCK_SIZE]
            for idx in range(
                0, len(plaintext), AeadAes256CbcHmacSha512Provider._BLOCK_SIZE
            )
        ]

    class AeadAes256CbcHmacSha512ProviderEncrypter(Encrypter):
        def __init__(
            self,  # type: "AeadAes256CbcHmacSha512ProviderEncrypter"
            keyring,  # type: Keyring
            key,  # type: str
            key_size,  # type: int
            alg,  # type: str
            **kwargs,  # type: Optional[Any]
        ):
            super().__init__(keyring, key)
            self._alg = alg
            self._key_size = key_size
            if "test_iv" in kwargs:
                self._test_iv = kwargs.pop("test_iv")

        def encrypt(
            self,  # type: "AeadAes256CbcHmacSha512ProviderEncrypter"
            plaintext,  # type: str | bytes | bytearray
            associated_data=None,  # type: str | bytes | bytearray
        ) -> EncryptionResult:
            ekey = self.keyring.get_key(self.key)
            if not AeadAes256CbcHmacSha512Provider.is_valid_key_length(ekey):
                raise InvalidCryptoKeyException("{} requires key with {} bytes but key {} has {} bytes.".format(
                    self._alg,
                    self._key_size,
                    ekey.id,
                    len(ekey.bytes),
                ))

            hmac_key = ekey.bytes[:32]
            aes_key = ekey.bytes[32:]

            iv = self._test_iv if self._test_iv else os.urandom(16)

            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            plaintext = AeadAes256CbcHmacSha512Provider.to_bytes(plaintext)
            plaintext = AeadAes256CbcHmacSha512Provider.add_padding(plaintext)
            encrypted_data = encryptor.update(plaintext) + encryptor.finalize()

            aes_ciphertext = bytearray(iv)
            aes_ciphertext.extend(bytearray(encrypted_data))
            signature = AeadAes256CbcHmacSha512Provider.get_signature(
                hmac_key, aes_ciphertext, associated_data=associated_data
            )
            aes_ciphertext.extend(bytearray(signature))

            res = EncryptionResult(self._alg, kid=ekey.id)
            res.put_and_base64_encode("ciphertext", bytes(aes_ciphertext))
            return res

    class AeadAes256CbcHmacSha512ProviderDecrypter(Decrypter):
        def __init__(
            self,  # type: "AeadAes256CbcHmacSha512ProviderDecrypter"
            keyring,  # type: Keyring
            key_size,  # type: int
            alg,  # type: str
        ):
            super().__init__(keyring, alg)
            self._key_size = key_size

        def decrypt(
            self,  # type: "AeadAes256CbcHmacSha512ProviderDecrypter"
            encrypted,  # type: EncryptionResult
            associated_data=None,  # type: str | bytes | bytearray
        ) -> bytes:
            key_id = encrypted.get("kid")
            enc_ciphertext = encrypted.get_with_base64_decode("ciphertext")

            secret_key = self.keyring.get_key(key_id)
            if not AeadAes256CbcHmacSha512Provider.is_valid_key_length(secret_key):
                raise InvalidCryptoKeyException("{} requires key with {} bytes but key {} has {} bytes.".format(
                    self.algorithm(),
                    self._key_size,
                    secret_key.id,
                    len(secret_key.bytes),
                ))

            hmac_key = secret_key.bytes[:32]
            aes_ciphertext = enc_ciphertext[: len(enc_ciphertext) - 32]
            auth_tag = enc_ciphertext[len(enc_ciphertext) - 32:]
            signature = AeadAes256CbcHmacSha512Provider.get_signature(
                hmac_key, aes_ciphertext, associated_data
            )

            if not constant_time.bytes_eq(auth_tag, signature):
                raise InvalidCipherTextException(
                    "Failed to authenticate the ciphertext and associated data."
                )

            iv = aes_ciphertext[:16]
            aes_key = secret_key.bytes[32:]
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted_data = (
                decryptor.update(aes_ciphertext[16:]) + decryptor.finalize()
            )

            return AeadAes256CbcHmacSha512Provider.remove_padding(decrypted_data)
