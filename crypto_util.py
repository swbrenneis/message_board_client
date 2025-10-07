import base64
import hashlib
import os
import numpy as np

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def public_key_from_string(public_key_string):
    return serialization.load_pem_public_key(
        public_key_string.encode('UTF-8'),
        backend=default_backend()
    )

def private_key_from_file(file_name, password):
    with open(file_name, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode('utf-8'),
            backend=default_backend()
        )

def hash_strings(to_hash):
    """ Hashes an array of strings and returns a byte array"""
    sha256 = hashlib.sha256()
    for i in range(0, len(to_hash)):
        sha256.update(to_hash[i].encode('UTF-8'))
    return sha256.digest()

def sign_message(strings, private_key):
    """ Hashes and then signs a list of strings, returns base 64 encoding of signature """
    hashed_strings = hash_strings(strings)
    signature = private_key.sign(hashed_strings, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature)

def verify_message(signature, strings, public_key):
    """ Verifies a signature on a list of strings, returns True if the signature matches """
    hashed_strings = hash_strings(strings)
    signature = signature.decode('UTF-8')
    try:
        public_key.verify(signature, hashed_strings, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def rsa_decrypt_bytes(ciphertext, private_key):
    """ Decrypts ciphertext bytes and returns a byte array """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def aes_encrypt_bytes(plaintext, secret_key):
    """ Encrypts plaintext bytes and returns a byte array """
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(secret_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    join_list = [iv, ciphertext, encryptor.tag]
    return b''.join(join_list)

def aes_decrypt_bytes(ciphertext, iv, secret_key):
    """ Decrypts ciphertext bytes and returns a byte array """
    decryptor = Cipher(
        algorithms.AES(secret_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
