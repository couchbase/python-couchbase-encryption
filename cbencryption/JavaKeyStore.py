# Copyright (c) 2017 Couchbase, Inc.
#
# Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
# which may be found at https://www.couchbase.com/ESLA-11132015.

import jks
from couchbase.exceptions import ArgumentError


class JavaKeyStore:

    def __init__(self, file_path, passphrase):
        """
        Creates a new instance of a Key Store that can retrieve keys from a Java Key Store
        :param file_path: Path to the JKS file.
        :param passphrase: The passphrase used to access the key store.
        """
        if not file_path:
            raise ArgumentError.pyexc("file_path cannot be empty.")

        self.keystore = jks.KeyStore.load(file_path, passphrase)

    def get_key(self, key_id):
        """
        Retrieves a key from the key store using the given key id.
        :param key_id: The name for the key in the key store.
        """
        if not key_id:
            raise ArgumentError.pyexc("key_id must not be empty.")

        return self.keystore.secret_keys[key_id]
