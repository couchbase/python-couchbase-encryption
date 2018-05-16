# Copyright (c) 2017 Couchbase, Inc.
#
# Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
# which may be found at https://www.couchbase.com/ESLA-11132015.

import unittest, os, base64
from cbencryption.JavaKeyStore import JavaKeyStore


class TestJavaKeyStore(unittest.TestCase):

    def test_retrieve_secret_key(self):

        # build path to keystore file
        head, _ = os.path.split(os.path.realpath(__file__))
        path = os.path.join(head, 'keystore.jceks')

        # key name, passphrase and expected value
        key_name = 'test_secret_key'
        passphrase = 'couchbase123'
        exepcted_value = b'f/\xf1\xb8\t\xc8\x1e\xaa\xf5K*\x18-Hg\x8c`\x01\x08\x87\xbb\xaa\x8a\xecl\xf5\x0b|+\xad\x85\x87'
        # create keystore and retrieve key
        key_store = JavaKeyStore(path, passphrase)
        key = key_store.get_key(key_name)

        # verify value is decrypted and is correct
        self.assertTrue(key.is_decrypted())
        self.assertEqual(exepcted_value, key.key)


# keytool -genseckey -alias test_private_key -keyalg aes -keysize 256 -keystore keystore.jceks -storetype jceks
