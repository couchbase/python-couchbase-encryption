# Couchbase Python Encryption

Python encryption for use with the Couchbase Server

## AES-256-HMAC-SHA256

The AES256CryptoProvider is a symmetric encryption provider for use with Couchbase server to encrypt fields within a JSON document. The provider requires a keystore and the name of the private key used to sign / verify with. Once a provider has been created it needs to be registered with the bucket and then any calls to encrypt_document and decrypt_document will use the provider.

The provider can be used like this:

```python
from cbencryption import AES256CryptoProvider
# create insecure key store and register both public and private keys
keystore = InMemoryKeyStore()
keystore.set_key('mypublickey', '!mysecretkey#9^5usdk39d&dlf)03sL')
keystore.set_key('myprivatekey', 'myauthpassword')

# create and register provider
provider = AES256CryptoProvider(keystore, 'mypublickey', 'myprivatekey')
bucket.register_crypto_provider('AES-256-HMAC-SHA256', provider)

# encrypt document, the alg name must match the provider name and the kid must match a key in the keystore
prefix = '__crypt_'
document = {'message': 'The old grey goose jumped over the wrickety gate.'}
encrypted_document = bucket.encrypt_document(document,
    [{'alg': 'AES-256-HMAC-SHA256', 'name': 'message'}],
    prefix)

# decrypt document using registered provider
decrypted_document = bucket.decrypt_document(encrypted, prefix)
```

The output JSON looks like the below and can be stored in Couchbase:

```json
{
    "__crypt_message": {
        "alg": "AES-256-HMAC-SHA256",
        "ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
        "sig": "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
        "iv": "Cfq84/46Qjet3EEQ1HUwSg=="
    }
}
```

## Keystore

The key store is a managed way to retrieve keys used during encryption / decryption and the following method is required:

```python
def get_key(key_id):
    """
    Returns the key as byte array
    """
    return b'my-secret-key'
```

### JavaKeystore

The key store is a managed way to retrieve keys used during encryption / decryption using a JCEKS keystore. An example of using the JavaKeyStore is below:

```python
from cbencryption import JavaKeyStore

# create keystore using path to keystore file and its passphrase
keystore = JavaKeyStore('path/to/keystore.jceks', 'keystore_passphrase')
```
