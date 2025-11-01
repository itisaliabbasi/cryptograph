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


def create_cipher(password: str, algorithm: str, mode: str, action: str, iv: bytes = None):
    algorithm = algorithm.upper()
    mode = mode.upper()
    action = action.lower()

    if algorithm == "AES":
        keyLength = 32
        blockSize = 16
        cipherModule = AES
    elif algorithm == "DES":
        keyLength = 8
        blockSize = 8
        cipherModule = DES
    elif algorithm in ["3DES", "DES4"]:
        keyLength = 24
        blockSize = 8
        cipherModule = DES3
    else:
        raise ValueError("Unsupported Algorithm!")

    key = password_to_key(password, keyLength)

    if mode == "ECB":
        cipher = cipherModule.new(key, cipherModule.MODE_ECB)
    elif mode == "CBC":
        if action == "encrypt" and iv is None:
            iv = get_random_bytes(blockSize)
        elif action == "decrypt" and iv is None:
            raise ValueError("IV is required for Decryption in CBC mode!")
        cipher = cipherModule.new(key, cipherModule.MODE_CBC, iv)
    else:
        raise ValueError("Unsupported Mode!")

    return cipher, iv
