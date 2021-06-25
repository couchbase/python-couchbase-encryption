from typing import Any, Callable

from couchbase.encryption.crypto_manager import CryptoManager
from couchbase.encryption.encryption_result import EncryptionResult
from couchbase.exceptions import (
    EncrypterNotFoundException,
    EncryptionFailureException,
    DecrypterNotFoundException,
    DecryptionFailureException,
    DecrypterAlreadyExistsException,
    EncrypterAlreadyExistsException,
)

from .legacy_aes256_provider import LegacyAesProvider


class DefaultCryptoManager(CryptoManager):
    def __init__(
        self,  # type: "DefaultCryptoManager"
        encrypted_field_prefix=None,  # type: str
    ):
        super(DefaultCryptoManager, self).__init__()
        self._alias_to_encrypter = {}
        self._algo_to_decrypter = {}
        self._encrypted_field_prefix = encrypted_field_prefix

        if self._encrypted_field_prefix is None:
            self._encrypted_field_prefix = "encrypted$"

    @property
    def encrypted_field_prefix(
        self,  # type: "DefaultCryptoManager"
    ) -> str:
        return self._encrypted_field_prefix

    def register_encrypter(
        self,  # type: "DefaultCryptoManager"
        alias,  # type: str
        encrypter,  # type: "Encrypter"
    ):
        if self._alias_to_encrypter.get(alias, None):
            raise EncrypterAlreadyExistsException(
                message="Alias {} already registered to an encrypter".format(alias)
            )

        self._alias_to_encrypter[alias] = encrypter

    def register_decrypter(
        self,  # type: "DefaultCryptoManager"
        decrypter,  # type: "Decrypter"
    ):
        if self._algo_to_decrypter.get(decrypter.algorithm(), None):
            raise DecrypterAlreadyExistsException(
                message="Algorithm already registered to a decrypter"
            )

        self._algo_to_decrypter[decrypter.algorithm()] = decrypter

    def register_legacy_decrypters(
        self,  # type: "DefaultCryptoManager"
        keyring,  # type: "Keyring"
        key_func,  # type: Callable[[str], str]
    ):
        legacy_provider = LegacyAesProvider(keyring, key_func)
        aes128 = legacy_provider.aes128_decrypter()
        aes256 = legacy_provider.aes256_decrypter()

        if self._algo_to_decrypter.get(aes128.algorithm(), None):
            raise DecrypterAlreadyExistsException(
                message="Algorithm already registered to a decrypter"
            )

        self._algo_to_decrypter[aes128.algorithm()] = aes128

        if self._algo_to_decrypter.get(aes256.algorithm(), None):
            raise DecrypterAlreadyExistsException(
                message="Algorithm already registered to a decrypter"
            )

        self._algo_to_decrypter[aes256.algorithm()] = aes256

    def default_encrypter(
        self,  # type: "DefaultCryptoManager"
        encrypter,  # type: "Encrypter"
    ):
        self.register_encrypter(self._DEFAULT_ENCRYPTER_ALIAS, encrypter)

    def encrypt(
        self,  # type: "DefaultCryptoManager"
        plaintext,  # type: str | bytes | bytearray
        encrypter_alias=None,  # type: str
        associated_data=None,  # type: str | bytes | bytearray
    ) -> dict:
        try:
            alias = encrypter_alias
            if alias is None:
                alias = self._DEFAULT_ENCRYPTER_ALIAS

            encrypter = self._alias_to_encrypter.get(alias, None)
            if encrypter is None:
                raise EncrypterNotFoundException(
                    message="Cannot find encrypter for alias: {}".format(alias)
                )

            res = encrypter.encrypt(plaintext, associated_data=associated_data)
            return res.asdict()
        except Exception as ex:
            raise EncryptionFailureException(
                params={"inner_cause": ex},
                message="Encryption failed.  See inner cause for details.",
            )

    def decrypt(
        self,  # type: "DefaultCryptoManager"
        encrypted,  # type: dict
        associated_data=None,  # type: str | bytes | bytearray
    ) -> bytes:
        try:
            enc_result = EncryptionResult.new_encryption_result_from_dict(encrypted)
            decrypter = self._algo_to_decrypter.get(enc_result.algorithm(), None)

            if decrypter is None:
                raise DecrypterNotFoundException(
                    message="Cannot find decrypter for algorithm: {}".format(
                        enc_result.algorithm()
                    )
                )

            if enc_result.algorithm() in LegacyAesProvider.legacy_algorithms():
                return decrypter.decrypt(enc_result)

            return decrypter.decrypt(enc_result, associated_data)
        # except CryptoException as ex:
        #     raise DecryptionFailureException(params={"inner_cause":ex}, message="Decryption failed.  See inner cause for details.")
        except Exception as ex:
            raise DecryptionFailureException(
                params={"inner_cause": ex},
                message="Decryption failed.  See inner cause for details.",
            )

    def mangle(
        self,  # type: "DefaultCryptoManager"
        field_name,  # type: str
    ) -> str:
        return self.encrypted_field_prefix + field_name

    def demangle(
        self,  # type: "DefaultCryptoManager"
        field_name,  # type: str
    ) -> str:
        return field_name.replace(self.encrypted_field_prefix, "")

    def is_mangled(
        self,  # type: "DefaultCryptoManager"
        field_name,  # type: str
    ) -> str:
        return field_name.startswith(self.encrypted_field_prefix)
