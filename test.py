import re
import unittest
from Crypto.PublicKey import RSA
import base64
import _ketumclib

api_base_url = 'http://127.0.0.1:5000'


class StorageTest(unittest.TestCase):

    def test_key_generating(self):
        secret_key = _ketumclib.Storage.generate_key()
        key = RSA.importKey(secret_key)
        self.assertTrue(key.has_private(), "Key is not a private key.")

    def test_sign_verify(self):
        self.test_key_generating()
        secret_key = _ketumclib.Storage.generate_key()
        api = _ketumclib.Api(api_base_url)
        storage = _ketumclib.Storage(secret_key, api)

        data = 'Sign me m8!'

        sign_of_data = storage.sign(data)
        base64.b64decode(sign_of_data)
        self.assertTrue(storage.sign_verify(data, sign_of_data),
                        "Data and sign don't match")

    def test_rsa_encrypt_decrpyt(self):
        self.test_key_generating()
        secret_key = _ketumclib.Storage.generate_key()
        api = _ketumclib.Api(api_base_url)
        storage = _ketumclib.Storage(secret_key, api)

        data = 'Encrypt me m8!'

        encrypted_data = storage.encrypt_rsa(data)
        base64.b64decode(encrypted_data)
        self.assertEqual(data, storage.decrypt_rsa(encrypted_data),
                         "Data and decrypted cipher text don't match")

    def test_register(self):
        self.test_key_generating()
        secret_key = _ketumclib.Storage.generate_key()
        api = _ketumclib.Api(api_base_url)
        storage = _ketumclib.Storage(secret_key, api)
        storage.register()

    def test_login(self):
        self.test_register()
        secret_key = _ketumclib.Storage.generate_key()
        api = _ketumclib.Api(api_base_url)
        storage = _ketumclib.Storage(secret_key, api)
        storage.register()
        self.assertTrue(storage.login(), "Login failed")

    def test_new_file(self):
        self.test_login()
        secret_key = _ketumclib.Storage.generate_key()
        api = _ketumclib.Api(api_base_url)
        storage = _ketumclib.Storage(secret_key, api)
        storage.register()
        file_name = storage.new_file()
        pattern = re.compile('^([0-9A-f]{32})$')
        self.assertTrue(bool(pattern.match(file_name)))


    # Expand test coverage

if __name__ == '__main__':
    unittest.main()
