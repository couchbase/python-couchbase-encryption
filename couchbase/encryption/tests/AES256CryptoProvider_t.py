from unittest import TestCase
from couchbase.encryption import AES256CryptoProvider, InMemoryKeyStore

class AES256CryptoProviderTests(TestCase):

    def test_encrypt_decrypt(self):
        keystore = InMemoryKeyStore()
        keystore.set_key('mypublickey', "my-secret")
        keystore.set_key('myhmackey', 'myauthpassword')

        document = {'message': 'The old grey goose jumped over the wrickety gate.'}

        # create provider
        provider = AES256CryptoProvider(keystore)

        # register encryption provider with LCB
        self.cb.register_crypto_provider('aes256', provider)

        # encrypt document
        encrypted_document = self.cb.encrypt_document(document, [{'alg': 'aes256', 'name': 'message', 'kid': 'mypublickey'}], "crypto_")

        # self.assertEqual(expected, encrypted_document)

        # decrypt document
        decrypted_document = self.cb.decrypt_document(encrypted_document, "crypto_")

        # verify encrypted field can be read
        self.assertEqual(decrypted_document, document)
