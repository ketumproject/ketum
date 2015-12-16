import json
import os
import base64
import subprocess

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import _ketumclib

ketum_path = os.path.join(os.path.expanduser("~"), '.ketum')
if not os.path.exists(ketum_path):
    os.makedirs(ketum_path)

storage_dir = os.path.join(ketum_path, 'storages/')
if not os.path.exists(storage_dir):
    os.makedirs(storage_dir)


class StorageManager(object):
    def __init__(self, proxy_host=None, proxy_port=None):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def new_storage(self, baseurl, storage_name, description, passphrase):
        if os.path.exists(os.path.join(storage_dir, storage_name)):
            raise NameError("Storage name is not available!")

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        key = base64.urlsafe_b64encode(kdf.derive(passphrase))
        fernet = Fernet(key)

        storage_secret_key = _ketumclib.Storage.generate_key()

        api = _ketumclib.Api(baseurl)
        storage = _ketumclib.Storage(storage_secret_key, api)
        storage.register()

        # Encrypted Storage Metadata
        esm = fernet.encrypt(json.dumps({
            'secret_key': storage_secret_key,
            'baseurl': baseurl,
        }))

        with open(os.path.join(storage_dir, storage_name), 'w+') as f:
            f.write('%s %s %s' % (
                base64.b64encode(salt),
                esm,
                description,
            ))

    def get_storage(self, storage_name, passphrase):
        storage_file = os.path.join(storage_dir, storage_name)

        with open(storage_file) as f:
            _salt, esm, description = f.read().split(' ', 2)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=base64.b64decode(_salt),
            iterations=100000,
            backend=default_backend()
        )
        del _salt
        del description

        key = base64.urlsafe_b64encode(kdf.derive(passphrase))
        fernet = Fernet(key)

        try:
            storage_metadata = json.loads(fernet.decrypt(esm))
        except InvalidToken:
            raise Exception('Passphrase is invalid!')

        api = _ketumclib.Api(storage_metadata['baseurl'])
        storage = _ketumclib.Storage(storage_metadata['secret_key'], api)

        if not storage.login():
            raise Exception('Strange, but storage is not registered?')

        return storage

    def destroy_storage(self, storage_name, passphrase):
        storage = self.get_storage(storage_name, passphrase)
        storage.destroy_storage()
        self.delete(storage_name)

    def storages(self):
        storage_list = list()
        for storage_name in os.listdir(storage_dir):

            file_path = os.path.join(storage_dir, storage_name)
            if not os.path.isfile(file_path):
                continue

            with open(file_path) as f:
                content = f.read()
                salt, esm, description = content.split(' ', 2)
                del esm
                storage_list.append((storage_name, description))

        return storage_list

    def exists(self, storage_name):
        file_path = os.path.join(storage_dir, storage_name)
        return os.path.exists(file_path)

    def delete(self, storage_name):
        file_path = os.path.join(storage_dir, storage_name)

        if not os.path.exists(file_path):
            raise NameError("Storage does not exists!")

        subprocess.check_call(['srm', '-r', file_path])
