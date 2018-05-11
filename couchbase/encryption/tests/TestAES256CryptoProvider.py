import os, base64, unittest
from ConfigParser import SafeConfigParser
from couchbase.crypto import InMemoryKeyStore
from couchbase.cluster import Cluster, PasswordAuthenticator

from ..AES256CryptoProvider import AES256CryptoProvider

class AES256CryptoProviderTests(unittest.TestCase):

    def test_encrypt_decrypt(self):

        # get connection details from config
        parser = SafeConfigParser()
        parser.read(os.path.join(os.path.dirname(__file__), 'config.ini'))
        host = parser.get('config', 'host')
        username = parser.get('config', 'username')
        password = parser.get('config', 'password')
        bucket_name = parser.get('config', 'bucket')

        # connect to cluster
        cluster = Cluster(host)
        cluster.authenticate(PasswordAuthenticator(username, password))
        bucket = cluster.open_bucket(bucket_name)

        # create keystore and add public / private keys
        keystore = InMemoryKeyStore()
        keystore.set_key('mypublickey', '!mysecretkey#9^5usdk39d&dlf)03sL')
        keystore.set_key('myhmackey', 'myauthpassword')

        # use consistent iv so we can test encrypted value, normally would be random
        iv = base64.decodestring('Cfq84/46Qjet3EEQ1HUwSg==')

        # set encrypted document prefix and raw JSON document
        prefix = '__crypt_'
        document = {'message': 'The old grey goose jumped over the wrickety gate.'}

        # create provider & register with LCB
        provider = AES256CryptoProvider(keystore, 'myhmackey', iv=iv)
        bucket.register_crypto_provider('AES-256-HMAC-SHA256', provider)

        # encrypt document
        encrypted = bucket.encrypt_document(document, [{'alg': 'AES-256-HMAC-SHA256', 'name': 'message', 'kid': 'mypublickey'}], prefix)

        # verify encrypted value to ensure cross-SDK compatability
        expected = {
            "__crypt_message": {
                "alg": "AES-256-HMAC-SHA256",
                "kid": "mypublickey",
                "ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
                "sig": "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
                "iv": "Cfq84/46Qjet3EEQ1HUwSg=="
            }
        }
        self.assertEqual(expected, encrypted)

        # decrypt document
        decrypted = bucket.decrypt_document(encrypted, prefix)

        # verify
        self.assertEqual(document, decrypted)
