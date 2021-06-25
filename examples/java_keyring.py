from typing import Optional, Callable

import jks

from couchbase.encryption import Key, Keyring
from couchbase.exceptions import CryptoKeyNotFoundException, InvalidArgumentException


class JavaKeystoreKeyring(Keyring):
    def __init__(
        self,  # type: "JavaKeystoreKeyring"
        keystore_path,  # type: str
        passphrase,  # type: str
        key_func=None,  # type: Optional[Callable]
    ):
        if not keystore_path:
            raise InvalidArgumentException("keystore_path cannot be empty.")

        self._keystore = jks.KeyStore.load(keystore_path, passphrase)
        self._key_func = key_func

    def get_key(
        self,  # type: "JavaKeystoreKeyring"
        key_id,  # type: str
    ) -> Key:
        key_bytes = bytearray()
        try:
            if self._key_func:
                signing_key = self._keystore.secret_keys.get(
                    self._key_func(key_id, True)
                )
                key_bytes.extend(signing_key.key)
                secret_key = self._keystore.secret_keys.get(
                    self._key_func(key_id, False)
                )
            else:
                secret_key = self._keystore.secret_keys.get(key_id)

            key_bytes.extend(bytearray(secret_key.key))
            return Key(key_id, key_bytes)
        except Exception as ex:
            raise CryptoKeyNotFoundException(
                params={"inner_cause", ex},
                message="Unable to determine key for provided key id {}".format(key_id),
            )
