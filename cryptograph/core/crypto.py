import json
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

PBKDF2_ITER = 200_000
SALT_SIZE = 16  # bytes

def _block_size_for_algo(algorithm: str) -> int:
    algo = algorithm.upper()
    if algo == "AES":
        return AES.block_size  # 16
    elif algo in ("DES","3DES"):
        return DES.block_size  # 8
    else:
        raise ValueError("Unsupported algorithm")

def derive_key(password: str, algorithm: str, salt: bytes = None):
    """
    Derive key from password using PBKDF2.
    If salt is None, a new random salt is generated and returned with the key.
    Returns: (key: bytes, salt: bytes)
    """
    algo = algorithm.upper()
    if salt is None:
        salt = get_random_bytes(SALT_SIZE)

    if algo == "AES":
        key_len = 32  # AES-256
    elif algo == "3DES":
        key_len = 24  # 3DES (use 24 bytes)
    elif algo == "DES":
        key_len = 8
    else:
        raise ValueError("Unsupported algorithm for key derivation")

    key = PBKDF2(password.encode("utf-8"), salt, dkLen=key_len, count=PBKDF2_ITER)
    # For 3DES ensure key parity (DES3 requires valid parity bits)
    if algo == "3DES":
        try:
            key = DES3.adjust_key_parity(key)
        except Exception:
            # If adjust_key_parity fails, fallback to raw derived key (may raise later)
            pass
    return key, salt

def _make_cipher(algorithm: str, mode: str, key: bytes, iv: bytes = None):
    algo = algorithm.upper()
    m = mode.upper()
    if algo == "AES":
        if m == "ECB":
            return AES.new(key, AES.MODE_ECB)
        elif m == "CBC":
            return AES.new(key, AES.MODE_CBC, iv=iv)
    elif algo == "3DES":
        if m == "ECB":
            return DES3.new(key, DES3.MODE_ECB)
        elif m == "CBC":
            return DES3.new(key, DES3.MODE_CBC, iv=iv)
    elif algo == "DES":
        if m == "ECB":
            return DES.new(key, DES.MODE_ECB)
        elif m == "CBC":
            return DES.new(key, DES.MODE_CBC, iv=iv)
    raise ValueError("Unsupported algorithm/mode combination")

def encrypt_bytes(plaintext: bytes, password: str, algorithm: str = "AES", mode: str = "CBC"):
    """
    Encrypt plaintext bytes using password-derived key.
    Returns: header_bytes (JSON as bytes), ciphertext (bytes)
    Header fields: version, algorithm, mode, salt(hex), iv(hex)
    """
    alg = algorithm.upper()
    m = mode.upper()
    # derive key + salt
    key, salt = derive_key(password, alg)

    # iv for CBC, none for ECB
    iv = b""
    if m == "CBC":
        block_size = _block_size_for_algo(alg)
        iv = get_random_bytes(block_size)
    elif m == "ECB":
        iv = b""
    else:
        raise ValueError("Unsupported mode (only ECB and CBC supported)")

    cipher = _make_cipher(alg, m, key, iv if iv else None)

    if m in ("ECB","CBC"):
        block_size = _block_size_for_algo(alg)
        ct = cipher.encrypt(pad(plaintext, block_size))
    else:
        raise ValueError("Unsupported mode")

    header = {
        "version": 1,
        "alg": alg,
        "mode": m,
        "salt": salt.hex(),
        "iv": iv.hex() if iv else ""
    }
    header_bytes = json.dumps(header).encode("utf-8")
    return header_bytes, ct

def decrypt_bytes(header_bytes: bytes, ciphertext: bytes, password: str):
    """
    Decrypt ciphertext using header and password.
    Returns plaintext bytes. May raise ValueError on padding/auth failure.
    """
    header = json.loads(header_bytes.decode("utf-8"))
    alg = header.get("alg")
    m = header.get("mode")
    salt_hex = header.get("salt")
    iv_hex = header.get("iv", "")

    if not alg or not m or salt_hex is None:
        raise ValueError("Invalid header")

    salt = bytes.fromhex(salt_hex)
    iv = bytes.fromhex(iv_hex) if iv_hex else None

    key, _ = derive_key(password, alg, salt=salt)
    cipher = _make_cipher(alg, m, key, iv if iv else None)

    if m in ("ECB","CBC"):
        block_size = _block_size_for_algo(alg)
        pt_padded = cipher.decrypt(ciphertext)
        pt = unpad(pt_padded, block_size)
        return pt
    else:
        raise ValueError("Unsupported mode")
