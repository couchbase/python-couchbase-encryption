from couchbase.encryption import Key, Keyring
from couchbase.exceptions import InvalidCryptoKeyException, CryptoKeyNotFoundException


class UnsecureKeyring(Keyring):
    def __init__(
        self,  # type: "UnsecureKeyring"
    ):
        self.keystore = {}

    def set_key(
        self,  # type: "UnsecureKeyring"
        key_id,  # type: str
        key,  # type: str | bytearray | bytes
    ):
        if isinstance(key, str):
            key_bytes = bytes(key, encoding="utf-8")
        elif isinstance(key, bytearray):
            key_bytes = bytes(key)
        elif isinstance(key, bytes):
            key_bytes = key
        else:
            raise InvalidCryptoKeyException(
                "Invalid key type.  Must be str, bytes or bytearray."
            )

        self.keystore[key_id] = Key(key_id, key_bytes)

    def get_key(
        self,  # type: "UnsecureKeyring"
        key_id,  # type: str
    ) -> Key:
        key = self.keystore.get(key_id, None)
        if key is None:
            raise CryptoKeyNotFoundException(
                "Unable to determine key for provided key id '{}'".format(key_id))

        return key
