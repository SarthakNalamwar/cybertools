from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

# AES Key Generation
def generate_aes_key():
    return get_random_bytes(16)  # 16 bytes = 128 bits

# DES Key Generation
def generate_des_key():
    return get_random_bytes(8)  # 8 bytes = 64 bits

# RSA Key Pair Generation
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Salt Generation
def generate_salt(length):
    return get_random_bytes(length)
