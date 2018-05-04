
import os
from couchbase.crypto import PythonCryptoProvider
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend

class AES256CryptoProvider(PythonCryptoProvider):

    def __init__(self, keystore):
        super(AES256CryptoProvider, self).__init__()
        self.keystore = keystore
        # TODO: move this into keys?
        self.authSecret = 'myhmackey'

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
        return os.urandom(16)

    def sign(self, inputs):
        """
        Sign the inputs provided.
        :param inputs: List of inputs
        """
        key = self.authSecret
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

        for i in inputs:
            print(i)
            h.update(i)

        return h.finalize()

    def verify_signature(self, inputs, signature):
        """
        Verify the inputs provided against the signature given.
        :param inputs: The name of the provider.
        :param signature: Signature
        """
        key = self.authSecret
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

        for i in inputs:
            h.update(i)

        # raises error if signatures do not match
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
        cipher = Cipher(algorithms.AES(padded_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        value = ''
        for part in self.chunker(input, 16):
            if len(part) < 16:
                part = self.pad_value(part)

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
        cipher = Cipher(algorithms.AES(padded_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        value = ''
        for part in self.chunker(input, 16):
            if len(part) < 16:
                part = self.pad_value(part)

            value += decryptor.update(part)

        value += decryptor.finalize()
        return value

    @staticmethod
    def chunker(seq, size):
        return (seq[pos:pos + size] for pos in xrange(0, len(seq), size))

    @staticmethod
    def pad_value(value):
        padder = padding.PKCS7(128).padder()
        return padder.update(value) + padder.finalize()
