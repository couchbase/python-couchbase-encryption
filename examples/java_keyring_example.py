import os
import json
import traceback
from typing import List, Dict

from couchbase.encryption import CryptoManager
from couchbase.cluster import Cluster, ClusterOptions
from couchbase.auth import PasswordAuthenticator
from couchbase.exceptions import (
    DecrypterAlreadyExistsException,
    EncrypterAlreadyExistsException,
)

from cbencryption import DefaultCryptoManager, AeadAes256CbcHmacSha512Provider
from java_keyring import JavaKeystoreKeyring

# Create a helper method to encrypt document fields
def encrypt_doc(
    crypto_mgr,  # type: "CryptoManager"
    doc,  # type: Dict
    field_specs,  # type: List[dict]
) -> dict:
    """Helper method that takes the provided field specs and encrypts the matching fields of the provided document.

    Args:
        crypto_mgr (`couchbase.encryption.CryptoManager`): The crypto manager that contains registries to application's encrypters and decrypters
        doc (Dict): The document that should have fields encrypted
        field_specs (List[dict]): List of field specs, a field spec should be a dict containing at least a 'name' field.  Can optionally
            include 'encrypter_alias' and 'associated_data' fields

    Returns:
        Dict: The provided document with encrypted fields
    """
    encrypted_doc = {}
    for k, v in doc.items():
        field_spec = next((fs for fs in field_specs if fs.get("name", None) == k), None)
        if field_spec:
            encrypted_val = crypto_mgr.encrypt(
                json.dumps(v),
                encrypter_alias=field_spec.get("encrypter_alias", None),
                associated_data=field_spec.get("associated_data", None),
            )
            encrypted_val["ciphertext"] = encrypted_val["ciphertext"].decode("utf-8")
            encrypted_doc[crypto_mgr.mangle(k)] = encrypted_val
        else:
            encrypted_doc[k] = v
    return encrypted_doc


# Create a helper method to decrypt document fields
def decrypt_doc(
    crypto_mgr,  # type: "CryptoManager"
    doc,  # type: Dict
    field_specs,  # type: List[dict]
) -> dict:
    """Helper method that takes the provided field specs and decrypts the matching fields of the provided document.

    Args:
        crypto_mgr (`couchbase.encryption.CryptoManager`): The crypto manager that contains registries to application's encrypters and decrypters
        doc (Dict): The document that should have fields encrypted
        field_specs (List[dict]): List of field specs, a field spec should be a dict containing at least a 'name' field.  Can optionally
            include 'encrypter_alias' and 'associated_data' fields

    Returns:
        Dict: The provided document with previously encrypted fields decrypted.
    """
    decrypted_doc = {}
    for k, v in doc.items():
        if not crypto_mgr.is_mangled(k):
            decrypted_doc[k] = v
        else:
            demangled_key = crypto_mgr.demangle(k)
            field_spec = next(
                (fs for fs in field_specs if fs.get("name", None) == demangled_key),
                None,
            )
            if field_spec:
                decrypted_val = crypto_mgr.decrypt(
                    v,
                    associated_data=field_spec.get("associated_data", None),
                )
                decrypted_doc[demangled_key] = json.loads(decrypted_val)
    return decrypted_doc


# test_keystore.jks - password: password (super secure of course ;))
# Create a keyring and add keys
# NOTE:  Use a secure keyring for applications, this is shown for example purposes
local_path = os.path.dirname(__file__)
keystore_path = os.path.join(local_path, "test_keystore.jks")
# using the keytool only allows for 32-byte keys, AES-256 authenticated with HMAC SHA-512 requires a 64-byte key,
# this is a work-around for obtaining the 64-byte key.  The keys are stored with <root term>_key and <root term>_hmac
# 
keystore_func = (
    lambda key, signing: "{}_hmac".format(key)
    if signing is True
    else "{}_key".format(key)
)
keyring = JavaKeystoreKeyring(
    keystore_path,
    "password",
    keystore_func,
)
secret_key_id = "my_secret"
secret_key1_id = "my_secret1"

# Create a Provider
# AES-256 authenticated with HMAC SHA-512. Requires a 64-byte key.
aes256_provider = AeadAes256CbcHmacSha512Provider(keyring)

# Create a CryptoManager
crypto_mgr = DefaultCryptoManager()

# Create and then register encrypters.
# The secret_key_id is used by the encrypter to lookup the key from the store when encrypting a document.
# The id of the Key object returned from the store at encryption time is written into the data for the field to be encrypted.
# The key id that was written is then used on the decrypt side to find the corresponding key from the store.
encrypter1 = aes256_provider.encrypter_for_key(secret_key_id)

# The alias used here is the value which corresponds to the "encrypted" field annotation.
try:
    crypto_mgr.register_encrypter("one", encrypter1)
    crypto_mgr.register_encrypter(
        "two", aes256_provider.encrypter_for_key(secret_key1_id)
    )

    # We don't need to add a default encryptor but if we do then any fields with an
    # empty encrypted tag will use this encryptor.
    crypto_mgr.default_encrypter(encrypter1)
except EncrypterAlreadyExistsException as ex:
    traceback.print_exc()

# Only set one decrypter per algorithm.
# The crypto manager will work out which decrypter to use based on the alg field embedded in the field data.
# The decrypter will use the key embedded in the field data to determine which key to fetch from the key store for decryption.
try:
    crypto_mgr.register_decrypter(aes256_provider.decrypter())
except DecrypterAlreadyExistsException as ex:
    traceback.print_exc()


# Create a configuration to connect to your cluster
cluster = Cluster(
    "couchbase://localhost",
    ClusterOptions(PasswordAuthenticator("Administrator", "password")),
)
bucket = cluster.bucket("default")
collection = bucket.default_collection()

user = {
    "firstName": "Monty",
    "lastName": "Python",
    "password": "bang!",
    "address": {
        "street": "999 Street St.",
        "city": "Some City",
        "state": "ST",
        "zip": "12345",
    },
    "phone": "123456",
}

field_specs = [
    {"name": "password", "encrypter_alias": "one"},
    {"name": "address", "encrypter_alias": "two"},
    {"name": "phone"},
]

encrypted_user = encrypt_doc(crypto_mgr, user, field_specs)

collection.upsert("user::1", encrypted_user)
result = collection.get("user::1")
print("Encrypted doc:\n{}".format(result.content_as[dict]))

decrypted_user = decrypt_doc(crypto_mgr, result.content_as[dict], field_specs)
print("Decrypted doc:\n{}".format(decrypted_user))
