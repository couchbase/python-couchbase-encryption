# Copyright (c) 2017 Couchbase, Inc.
#
# Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
# which may be found at https://www.couchbase.com/ESLA-11132015.

from couchbase.crypto import InMemoryKeyStore
from couchbase.tests.base import ConnectionTestCase
from ..AES256CryptoProvider import AES256CryptoProvider
import sys
if sys.version_info >= (3,0):
    from base64 import decodebytes
else:
    from base64 import decodestring as decodebytes


class AES256CryptoProviderTests(ConnectionTestCase):

    def test_encrypt_decrypt(self):
        bucket = self.cb
        # create keystore and add public / private keys
        keystore = InMemoryKeyStore()
        keystore.set_key('mypublickey', b'!mysecretkey#9^5usdk39d&dlf)03sL')
        keystore.set_key('myhmackey', b'myauthpassword')

        # use consistent iv so we can test encrypted value, normally would be random

        iv = decodebytes(b'Cfq84/46Qjet3EEQ1HUwSg==')

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
