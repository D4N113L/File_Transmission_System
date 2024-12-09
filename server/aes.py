import random
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad


DEFAULT_KEY_SIZE = 256 // 8


def decrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=bytes([0] * AES.block_size))
    decrypted_data = cipher.decrypt(data)
    return unpad(decrypted_data, AES.block_size)


def generate_key() -> bytes:
    return random.Random().randbytes(DEFAULT_KEY_SIZE)