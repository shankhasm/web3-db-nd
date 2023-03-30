import base64
import json
import requests
from enum import Enum
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import Crypto.Hash.SHA256 as SHA256
AES_KEY_SIZE_BYTES = 32
NONCE_SIZE_BYTES = 12


class HTTP(Enum):
    GET = "GET"
    POST = "POST"


class Web3DB:
    def __init__(self, host: str, ecc_key_pair):
        self.web3db_rsa_pubkey = None
        self.web3db_rsa_pubkey_string = None
        self.host = host
        self.ecc_key_pair = ecc_key_pair

    def get_storage_node_pubkey(self):
        pubkey = self._call_web3db('/api/get_web3db_pubkey', HTTP.GET)
        print(pubkey)
        pubkey = _format_storage_node_pubkey(pubkey)
        pubkey = RSA.importKey(pubkey)
        self.web3db_rsa_pubkey_string = _rsa_pub_to_string(pubkey)
        self.web3db_rsa_pubkey = pubkey

    def new_db(self, name="", acl=[]):
        self._call_web3db('/api/new_db',
                          HTTP.POST, {'name': name, 'acl': acl})

    def list_dbs(self):
        return self._call_web3db('/api/list_dbs', HTTP.GET)

    def _encrypt_instance(self, instance: dict, k1: bytes, k2: bytes):
        for attribute, val in instance.items():
            metadata = any((attribute == '_id', attribute ==
                           'acl', attribute == '_mod'))
            public_attribute = attribute.startswith('_')
            if metadata or public_attribute:
                continue
            k2_encrypted_attribute = _encrypt_aes(k2, val.encode())
            k1_encrypted_attribute = _encrypt_aes(k1, k2_encrypted_attribute)
            instance[attribute] = k1_encrypted_attribute.decode()

    def _encrypt_new_instance(self, instance, acl):
        web3db_pub_key = self.web3db_rsa_pubkey if self.web3db_rsa_pubkey else self.get_storage_node_pubkey()
        k1 = get_random_bytes(AES_KEY_SIZE_BYTES)
        k2 = get_random_bytes(AES_KEY_SIZE_BYTES)
        self._encrypt_instance(instance)
        k1_encrypted = _encrypt_rsa(web3db_pub_key, k1)
        self._build_instance_acl(acl, k1_encrypted, web3db_pub_key, k2)

    def _build_instance_acl(self, acl: dict, k1_encrypted: bytes, k2: bytes):
        client_pubkey_str = _ecc_pub_to_string(self.ecc_key_pair)
        acl[client_pubkey_str] = {
            'permissions': 3
        }
        for pubkey in acl.keys():
            if pubkey == self.web3db_rsa_pubkey_string:
                continue
            if pubkey == client_pubkey_str:
                acl[pubkey]['rsaPubKey'] = _rsa_pub_to_string(
                    self.rsa_key_pair)
                entry = self.rsa_key_pair.public_key()
            else:
                entry = RSA.importKey(_format_storage_node_pubkey(pubkey))
            k2_encrypted = _encrypt_rsa(entry, k2)
            acl[pubkey]['seed'] = k2_encrypted.decode()
        acl[self.web3db_rsa_pubkey_string] = {
            'permissions': 1,
            'seed': k1_encrypted
        }

    def _decrypt_instance(self, instance: dict, k2Encrypted: bytes):
        k2Bytes = _decrypt_rsa(self.rsa_key_pair, k2Encrypted)
        for attribute, val in instance.items():
            metadata = any((attribute == '_id', attribute ==
                           'acl', attribute == '_mod'))
            public_attribute = attribute.startswith('_')
            if metadata or public_attribute:
                continue
            decryptedAttribute = _decrypt_aes(k2Bytes, val.encode()).decode()
            instance[attribute] = decryptedAttribute

    def _call_web3db(self, endpoint: str, method: HTTP, body={}):
        header = {}
        if not (self.web3db_rsa_pubkey or endpoint == '/api/get_web3db_pubkey'):
            self.get_storage_node_pubkey()
        if self.web3db_rsa_pubkey:
            identity_encrypted = _encrypt_rsa(
                self.web3db_rsa_pubkey, self.ecc_key_pair.secret)
            identity_encrypted = base64.b64encode(
                identity_encrypted).decode('ascii')
            header = {
                'identity': identity_encrypted,
                'Origin': 'python.test',
                'Content-Type': 'application/json'
            }
        if method == HTTP.GET:
            response = requests.get(self.host + endpoint, headers=header)
        elif method == HTTP.POST:
            response = requests.post(
                self.host + endpoint, data=json.dumps(body), headers=header)
        print(response.content)
        if endpoint == '/api/get_web3db_pubkey':
            return response.content
        else:
            return response.text


def _encrypt_aes(key, plaintext):
    nonce = get_random_bytes(NONCE_SIZE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    res = bytearray(nonce)
    res += bytearray(ciphertext)
    return res


def _decrypt_aes(key, ciphertext):
    nonce = ciphertext[:12]
    ciphertext = ciphertext[12:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def _encrypt_rsa(pub_key, plaintext):
    encryptor = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
    encrypted = encryptor.encrypt(plaintext)
    return encrypted


def _decrypt_rsa(key_pair, ciphertext):
    decryptor = PKCS1_OAEP.new(key_pair)
    decrypted = decryptor.decrypt(ciphertext)
    return decrypted


def _rsa_pub_to_string(rsa_key) -> str:
    exported = rsa_key.export_key('PEM')
    return exported[27: len(exported) - 25]


def _ecc_pub_to_string(key_pair) -> str:
    key = key_pair.public_key.format(False)
    return base64.b64encode(key).decode()


def _format_storage_node_pubkey(pubkey):
    header = '-----BEGIN PUBLIC KEY-----\n'
    pubkey = base64.b64encode(pubkey).decode('ascii')
    footer = '\n-----END PUBLIC KEY-----'
    return header + pubkey + footer
