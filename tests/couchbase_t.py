import json

from couchbase_tests.base import (
    CouchbaseTestCase,
    CouchbaseClusterResource,
    CouchbaseClusterInfo,
    CouchbaseClusterInfoException,
)
from couchbase.cluster import Cluster

from cbencryption.unsecure_keyring import UnsecureKeyring
from cbencryption import DefaultCryptoManager, AeadAes256CbcHmacSha512Provider


class CryptoTestCase(CouchbaseTestCase):
    _cluster_info = None

    @classmethod
    def setUpClass(cls, **kwargs) -> None:
        super(CryptoTestCase, cls).setUpClass()
        if cls._cluster_info:
            return

        cls._cluster_info = CouchbaseClusterInfo(
            CouchbaseClusterResource(cls.resources)
        )
        cls._cluster_info.cluster_resource.try_n_times(
            3, 3, cls._cluster_info.set_cluster, Cluster, **kwargs
        )
        cls._cluster_info.cluster_resource.try_n_times(
            3, 3, cls._cluster_info.set_bucket
        )
        cls._cluster_info.set_cluster_version()
        cls._cluster_info.set_collection()

    def setUp(self):
        super(CryptoTestCase, self).setUp()

        if not type(self)._cluster_info:
            raise CouchbaseClusterInfoException("Cluster not setup.")

        self.cluster = type(self)._cluster_info.cluster
        self.bucket = type(self)._cluster_info.bucket
        self.bucket_name = type(self)._cluster_info.bucket_name
        self.collection = type(self)._cluster_info.collection
        self.cluster_version = type(self)._cluster_info.cluster_version

    def tearDown(self):
        super(CryptoTestCase, self).tearDown()

        self.cluster = None
        self.bucket = None
        self.bucket_name = None
        self.collection = None
        self.cluster_version = None

    @classmethod
    def tearDownClass(cls) -> None:
        cls._cluster_info = None
        super(CryptoTestCase, cls).tearDownClass()

    def factory(self):
        pass


class CryptoTests(CryptoTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super(CryptoTests, cls).setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        super(CryptoTests, cls).tearDownClass()

    def setUp(self):
        super(CryptoTests, self).setUp()

        self.keyring = UnsecureKeyring()
        self.secret_id = "my_secrect"
        self.keyring.set_key(
            self.secret_id,
            bytes.fromhex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            ),
        )
        self.aes256_provider = AeadAes256CbcHmacSha512Provider(self.keyring)
        self.crypto_mgr = DefaultCryptoManager()
        self.crypto_mgr.default_encrypter(
            self.aes256_provider.encrypter_for_key(self.secret_id)
        )
        self.crypto_mgr.register_decrypter(self.aes256_provider.decrypter())

    def _encrypt_doc(self, doc, field_specs):
        encrypted_doc = {}
        for k, v in doc.items():
            if k in field_specs:
                field_spec = field_specs.get(k)
                encrypted_val = self.crypto_mgr.encrypt(
                    json.dumps(v),
                    encrypter_alias=field_spec.get("encrypter_alias", None),
                    associated_data=field_spec.get("associated_data", None),
                )
                encrypted_val["ciphertext"] = encrypted_val["ciphertext"].decode(
                    "utf-8"
                )
                encrypted_doc[self.crypto_mgr.mangle(k)] = encrypted_val
            else:
                encrypted_doc[k] = v
        return encrypted_doc

    def _decrypt_doc(self, doc, field_specs):
        decrypted_doc = {}
        for k, v in doc.items():
            if (
                self.crypto_mgr.is_mangled(k)
                and self.crypto_mgr.demangle(k) in field_specs
            ):
                demangled_key = self.crypto_mgr.demangle(k)
                field_spec = field_specs.get(demangled_key)
                decrypted_val = self.crypto_mgr.decrypt(
                    v,
                    associated_data=field_spec.get("associated_data", None),
                )
                decrypted_doc[demangled_key] = json.loads(decrypted_val)
            else:
                decrypted_doc[k] = v

        return decrypted_doc

    def test_encrypt_insert(self):
        doc = {
            "notasecret": "This message is not encrypted",
            "imaasecret": "This is an encrypted super secret message",
        }

        field_specs = {"imaasecret": {}}
        encrypted_doc = self._encrypt_doc(doc, field_specs)

        self.collection.insert("IMAKEY", encrypted_doc)
        res = self.collection.get("IMAKEY")
        self.assertEqual(res.content_as[dict], encrypted_doc)
        decrypted_doc = self._decrypt_doc(res.content_as[dict], field_specs)
        self.assertEqual(decrypted_doc, doc)

        self.collection.remove("IMAKEY")

    def test_encrypt_upsert(self):
        doc = {
            "notasecret": "This message is not encrypted",
            "imaasecret": {
                "secretNumbers": [1, 2, 3, 4],
                "secretMessage:": "This is an encrypted super secret message",
            },
        }

        field_specs = {"imaasecret": {}}
        encrypted_doc = self._encrypt_doc(doc, field_specs)

        self.collection.upsert("IMAKEY", encrypted_doc)
        res = self.collection.get("IMAKEY")
        self.assertEqual(res.content_as[dict], encrypted_doc)
        decrypted_doc = self._decrypt_doc(res.content_as[dict], field_specs)
        self.assertEqual(decrypted_doc, doc)

        self.collection.remove("IMAKEY")

    def test_legacy_decrypter(self):
        # if the legacy prefix of __crypt_, is used see forum post: https://forums.couchbase.com/t/replacing-field-name-prefix/28786
        # for query to update prefix.  For testing purposes, assumed prefix updated to default encrypted$

        self.secret_id = "mypublickey"
        self.keyring.set_key(self.secret_id, b"!mysecretkey#9^5usdk39d&dlf)03sL")
        self.keyring.set_key("myhmackey", b"myauthpassword")
        encrypted_doc = {
            "encrypted$field":{
            "alg": "AES-256-HMAC-SHA256",
            "kid": "mypublickey",
            "iv": "Cfq84/46Qjet3EEQ1HUwSg==",
            "ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
            "sig": "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
            }
        }

        self.crypto_mgr.register_legacy_decrypters(
            self.keyring, lambda key: "myhmackey" if key == "mypublickey" else None
        )

        field_specs = {"field": {}}
        self.collection.upsert("IMAKEY", encrypted_doc)
        res = self.collection.get("IMAKEY")
        decrypted_doc = self._decrypt_doc(res.content_as[dict], field_specs)
        self.assertEqual(decrypted_doc["field"], "The old grey goose jumped over the wrickety gate.")
        


