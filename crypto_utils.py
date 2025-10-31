from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from hashlib import sha256

def password_to_key(password: str, key_len: int) -> bytes:
    hash_bytes = sha256(password.encode()).digest()
    if key_len <= len(hash_bytes):
        return hash_bytes[:key_len]
    else:
        return (hash_bytes * ((key_len // len(hash_bytes))+1)[:key_len])