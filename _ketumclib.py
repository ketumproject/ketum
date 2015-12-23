from collections import OrderedDict
import json
import base64

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from cryptography.fernet import Fernet
import requests


class KetumClientError(Exception):
    pass


class StorageInit(object):
    def __init__(self, json_data):
        data = json.loads(json_data)
        self.container_key = str(data['container_key'])
        self.root_address = str(data['root_address'])

    @staticmethod
    def generate(root_address):
        data = {
            'container_key': Fernet.generate_key(),
            'root_address': root_address,
        }
        return StorageInit(json.dumps(data))

    def to_json(self):
        data = {
            'container_key': self.container_key,
            'root_address': self.root_address,
        }
        return json.dumps(data)


class Storage(object):
    def __init__(self, key_str, api):
        self.api = api
        self._key = RSA.importKey(key_str)
        self.cipher = PKCS1_OAEP.new(self._key)
        self._signer = PKCS1_PSS.new(self._key)
        self.public_key_str = self._key.publickey().exportKey()
        self.fingerprint = sha256hex(self.public_key_str)
        self.storage_meta = None
        self.filesystem = False

    @staticmethod
    def generate_key():
        key = RSA.generate(4096)
        return key.exportKey()

    def sign(self, data):
        return base64.b64encode(self._signer.sign(sha256(data)))

    def sign_verify(self, data, sign):
        naked_sign = base64.b64decode(sign)
        return self._signer.verify(sha256(data), naked_sign)

    def encrypt_rsa(self, plaintext):
        return base64.b64encode(self.cipher.encrypt(plaintext))

    def decrypt_rsa(self, ciphertext):
        naked_ciphertext = base64.b64decode(ciphertext)
        return self.cipher.decrypt(naked_ciphertext)

    def encrypt_fernet(self, plaintext):
        crypter = Fernet(self.storage_meta.container_key)
        return crypter.encrypt(plaintext)

    def decrypt_fernet(self, ciphertext):
        ciphertext = ciphertext.encode()
        crypter = Fernet(self.storage_meta.container_key)
        return crypter.decrypt(ciphertext)

    def register(self):
        self.api.register(self)

    def login(self):
        encrypted_storage_meta = self.api.login(self.auth_info())
        if encrypted_storage_meta is False:
            return False
        else:
            storage_meta_json = self.decrypt_rsa(encrypted_storage_meta)
            self.storage_meta = StorageInit(storage_meta_json)
            root_address = self.storage_meta.root_address
            self.filesystem = Directory('/', root_address, self)
            self.filesystem.refresh_from_remote()
        return True

    def new_file(self):
        return self.api.new_file(self.auth_info())

    def destroy_storage(self):
        self.api.destroy_storage(self.auth_info())

    def save_storage_meta(self):
        encrypted_storage_data = self.encrypt_rsa(self.storage_meta.to_json())
        self.api.set_storage_meta(self.auth_info(), encrypted_storage_data)

    def auth_info(self):
        contract = self.api.auth_contract(self.fingerprint)
        return "%s:%s:%s" % (self.fingerprint, contract, self.sign(contract))


def element_by_type(_type):
    if _type == 'd':
        return Directory
    else:
        return File


class FSElement(object):
    DIRECTORY = 'd'
    FILE = 'f'

    ALLOWED_CHARS_FOR_NAME = 'abcdefghijklmnopqrstuvwxyz' \
                             'ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
                             '0123456789' \
                             '-_+.'

    type = None
    remote_data = None
    is_refreshed = False

    def __init__(self, name, address, storage, parent=None):
        assert self.type in (self.DIRECTORY, self.FILE)
        self.parent = parent
        self.storage = storage
        self.name = name
        self.address = address

    def element_dict(self):
        return {
            'type': self.type,
            'name': self.name,
            'address': self.address,
        }

    @staticmethod
    def from_json(json_data, storage):
        data = json.loads(json_data)
        element = element_by_type(data['type'])(
            name=data['name'],
            address=data['address'],
            storage=storage,
        )

        # if the element is a Directory, we look for subelements
        if element.__class__ == Directory:
            for subelement in data['elements']:
                subelement_obj = element_by_type(subelement['type'])(
                    name=subelement['name'],
                    address=subelement['address'],
                    storage=storage,
                    parent=element,
                )
                element.add_element(subelement_obj)
        return element

    def refresh_from_remote(self):
        encrypted_data = self.storage.api.get_file(
            self.storage.auth_info(),
            self.address)
        element_json = self.storage.decrypt_fernet(encrypted_data)
        self.remote_data = json.loads(element_json)
        assert self.type == self.remote_data['type'], \
            'Local and remote FSElement types are not same'
        self.name = self.remote_data['name']
        self.is_refreshed = True

    def path(self):
        path_str = ''
        if self.parent:
            path_str += self.parent.path()
        path_str += self.name
        return path_str

    def to_json(self):
        raise NotImplementedError()

    def save_to_remote(self):
        self.storage.api.set_file(
            self.storage.auth_info(),
            self.address,
            self.storage.encrypt_fernet(self.to_json())
        )

    def _destroy(self):
        self.parent.del_element(self.name)
        self.parent.save_to_remote()
        data = self.storage.api.destroy_files(
            self.storage.auth_info(), [self.address])

    @classmethod
    def _name_validator(cls, name):
        char_set = cls.ALLOWED_CHARS_FOR_NAME
        return all(x in char_set for x in name)

    def is_directory(self):
        return False

    def is_file(self):
        return False


class Directory(FSElement):
    def __init__(self, *args, **kwargs):
        self.type = 'd'
        self._elements = OrderedDict()
        super(Directory, self).__init__(*args, **kwargs)

    def add_element(self, element):
        _elements = self._elements
        _elements[element.name] = element
        self._elements = OrderedDict(sorted(_elements.items()))

    def del_element(self, name):
        self._elements.pop(name, None)

    def rename_element(self, name, new_name):
        element = self._elements.pop(name, None)
        element.name = new_name
        self.add_element(element)

    def to_json(self):
        json_elements = [
            element.element_dict() for element in self._elements.values()]
        return json.dumps({
            'type': self.type,
            'name': self.name,
            'address': self.address,
            'elements': json_elements,
        })

    def refresh_from_remote(self):
        super(Directory, self).refresh_from_remote()
        for subelement in self.remote_data['elements']:
            subelement_obj = element_by_type(subelement['type'])(
                name=subelement['name'],
                address=subelement['address'],
                storage=self.storage,
                parent=self,
            )
            self.add_element(subelement_obj)

    def subelement_by_name(self, name):
        if not self.is_refreshed:
            self.refresh_from_remote()
        for subelement in self.ls():
            if subelement.name.strip('/') == name:
                return subelement
        return None

    @property
    def root(self):
        if self.parent:
            return self.parent.root
        else:
            return self

    def cd(self, path=''):
        if path == '':
            return self
        if path[0] == '/':
            workdir = self.root
        else:
            workdir = self

        _path, _dummy_, _next_paths = path.strip('/').partition('/')

        if _path == '..':
            next_element = self.parent if self.parent else self
        elif _path == '.':
            next_element = self
        else:
            next_element = workdir.subelement_by_name(_path)

        if next_element is None:
            raise LookupError("Path doesn't exists!")
        if _next_paths is '':
            return next_element
        return next_element.cd(_next_paths)

    def mkdir(self, name):
        assert self._name_validator(name), \
            'The name contains forbidden chars'
        if not self.is_refreshed:
            self.refresh_from_remote()
        assert self.subelement_by_name(name) is None, \
            'name is not available'
        directory_address = self.storage.new_file()
        new_dir = Directory(
            name='%s/' % name,
            address=directory_address,
            storage=self.storage,
            parent=self)
        new_dir.save_to_remote()
        self.add_element(new_dir)
        self.save_to_remote()

    def ls(self):
        if not self.is_refreshed:
            self.refresh_from_remote()
        return [element for element in self._elements.itervalues()]

    def touch(self, name):
        assert self._name_validator(name), \
            'The name contains forbidden chars'
        if not self.is_refreshed:
            self.refresh_from_remote()
        assert self.subelement_by_name(name) is None, \
            'name is not available'
        file_address = self.storage.new_file()
        new_file = File(
            name='%s' % name,
            address=file_address,
            storage=self.storage,
            parent=self)
        new_file.save_to_remote()
        self.add_element(new_file)
        self.save_to_remote()

    def rm(self):
        for subelement in self.ls():
            subelement.rm()
        self._destroy()

    def is_directory(self):
        return True

    def __repr__(self):
        return '<Directory: %s>' % self.path()


class File(FSElement):
    def __init__(self, *args, **kwargs):
        self.type = 'f'
        self._content = ''
        super(File, self).__init__(*args, **kwargs)

    def to_json(self):
        return json.dumps({
            'type': self.type,
            'name': self.name,
            'address': self.address,
            'content': self._content,
        })

    def refresh_from_remote(self):
        super(File, self).refresh_from_remote()
        self.content = self.remote_data['content']

    @property
    def content(self):
        if not self.is_refreshed:
            self.refresh_from_remote()
        return self._content

    @content.setter
    def content(self, value):
        self._content = value

    def rm(self):
        self._destroy()

    def is_file(self):
        return True

    def __repr__(self):
        return '<File: %s>' % self.path()


class Api(object):
    def __init__(self, api):
        if api[-1] == '/':
            api = api[:-1]
        self.api = api

    def register(self, storage):
        contract = self._make_api_request(
            'get-registration-contract')['contract']

        signature = storage.sign(contract)

        payload = {
            'contract': contract,
            'sign': signature,
            'public_key_str': storage.public_key_str,
        }
        self._make_api_request('register', method='post', payload=payload)

        root_address = storage.new_file()
        root_dir = Directory('/', root_address, storage)
        storage.storage_meta = StorageInit.generate(root_address)
        root_dir.save_to_remote()
        storage.save_storage_meta()

    def login(self, auth_info):
        try:
            login_data = self._make_api_request(
                'login',
                method='post',
                payload={
                    'auth': auth_info,
                })
        except KetumClientError:
            return False
        else:
            return login_data['storage_meta']

    def new_file(self, auth_info):
        file_address = self._make_api_request(
            'new-file',
            method='post',
            payload={
                'auth': auth_info,
            })['address']

        return file_address

    def set_file(self, auth_info, file_address, data):
        self._make_api_request(
            'set-file',
            method='post',
            payload={
                'auth': auth_info,
                'file_address': file_address,
                'container': data,
            })

    def get_file(self, auth_info, file_address):
        return self._make_api_request(
            'get-file',
            method='post',
            payload={
                'auth': auth_info,
                'file_address': file_address,
            })['container']

    def set_storage_meta(self, auth_info, encrypted_storage_data):
        self._make_api_request(
            'set-storage-meta',
            method='post',
            payload={
                'auth': auth_info,
                'data': encrypted_storage_data,
            })

    def auth_contract(self, fingerprint):
        contract = self._make_api_request(
            'get-auth-contract',
            method='post',
            payload={'fingerprint': fingerprint})['contract']
        return contract

    def destroy_storage(self, auth_info):
        self._make_api_request(
            'destroy-storage',
            method='post',
            payload={
                'auth': auth_info,
            })

    def destroy_files(self, auth_info, file_addresses):
        self._make_api_request(
            'destroy-file',
            method='post',
            payload={
                'auth': auth_info,
                'file_addresses': ','.join(file_addresses)
            })

    def _make_api_request(self, endpoint, method='get', payload=None):

        if method not in ['get', 'post', 'put']:
            raise Exception('method should be get, post, or put')
        request_method = getattr(requests, method)
        response = request_method(
            "%s/%s" % (self.api, endpoint), data=payload).json()
        if response['status'] != 'OK':
            raise KetumClientError(
                response['message'])
        response.pop('status')
        return response


def sha256(data):
    shahash = SHA256.new()
    shahash.update(data)
    return shahash


def sha256hex(data):
    return sha256(data).hexdigest()
