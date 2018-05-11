import os
from couchbase.exceptions import ArgumentError
from couchbase.crypto import PythonCryptoProvider
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend


class AES256CryptoProvider(PythonCryptoProvider):

    def __init__(self, keystore, hmac_key_name, iv=None, block_size=32):
        """
        Create a new instance of the AES-256-HMAC-SHA1 encryption provider.
        :param keystore: The keystore used to encrypt / decrypt
        :param hmac_key_name: The HMAC key name used to sign and verify
        :param iv:
        :param block_size:
        """
        super(AES256CryptoProvider, self).__init__()

        if not keystore:
            raise ArgumentError.pyexc("KeyStore must be provided.")
        if not hmac_key_name:
            raise ArgumentError.pyexc("HMAC key name must be provided.")

        self.keystore = keystore

        self.hmac_key_name = hmac_key_name
        self.iv = iv
        self.block_size = block_size


    def load_key(self, type, keyid):
        """
        Load a decryption/encryption key, as selected by the type
        :param type: LCBCRYPTO_KEY_ENCRYPT or LCBCRYPTO_KEY_DECRYPT
        :param keyid: Key ID to retrieve
        """
        return self.keystore.get_key(keyid)

    def generate_iv(self):
        """
        Return an IV for use with decryption/encryption.
        """
        if self.iv:
            return self.iv

        return os.urandom(16)

    def sign(self, inputs):
        """
        Sign the inputs provided.
        :param inputs: List of inputs
        """
        key = self.keystore.get_key(self.hmac_key_name)
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

        for i in inputs:
            h.update(i)

        value = h.finalize()
        return value

    def verify_signature(self, inputs, signature):
        """
        Verify the inputs provided against the signature given.
        :param inputs: The name of the provider.
        :param signature: Signature
        """
        key = self.keystore.get_key(self.hmac_key_name)
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

        for i in inputs:
            h.update(i)

        # raises cryptography.exceptions.InvalidSignature if signatures do not match
        h.verify(signature)
        return True

    def encrypt(self, input, key, iv):
        """
        Encrypt the input string using the key and iv
        :param input: input string
        :param key: actual encryption key
        :param iv: iv for encryption
        """
        padded_key = self.pad_value(key)
        encryptor = Cipher(algorithms.AES(padded_key), modes.CBC(iv), backend=default_backend()).encryptor()

        value = b''
        padded_input = self.pad_value(input)
        for part in self.split(padded_input, self.block_size):
            value += encryptor.update(part)

        value += encryptor.finalize()
        return value

    def decrypt(self, input, key, iv):
        """
        Encrypt the input string using the key and iv
        :param input: input string
        :param key: actual decryption key
        :param iv: iv for decryption
        """
        padded_key = self.pad_value(key)
        decryptor = Cipher(algorithms.AES(padded_key), modes.CBC(iv), backend=default_backend()).decryptor()

        value = b''
        for part in self.split(input, self.block_size):
            value += decryptor.update(part)

        value += decryptor.finalize()
        value = self.unpad_value(value)
        return value


    def pad_value(self, value):
        # hack to remove extra line ending that json-cpp adds
        if value.endswith('\n'):
            value = value[:-1]

        # check if value needs padding
        if len(value) % self.block_size == 0:
            return value

        padder = padding.PKCS7(128).padder()

        data = b''
        for part in self.split(value, self.block_size):
            data += padder.update(part)

        data += padder.finalize()
        return data

    def unpad_value(self, value):
        unpadder = padding.PKCS7(128).unpadder()

        data = b''
        for part in self.split(value, self.block_size):
            data += unpadder.update(part)

        data += unpadder.finalize()
        return data

    @staticmethod
    def split(seq, num):
        return [ seq[start:start+num] for start in range(0, len(seq), num) ]
