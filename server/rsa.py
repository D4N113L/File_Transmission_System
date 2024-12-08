from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP


def encrypt(data: bytes, public_key: bytes) -> bytes:
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(data)
