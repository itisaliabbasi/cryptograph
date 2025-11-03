import struct

def write_encrypted_file(path: str, header_bytes: bytes, ciphertext: bytes):
    """
    File format:
    [4 bytes big-endian header length][header JSON bytes][ciphertext bytes]
    """
    with open(path, "wb") as f:
        f.write(struct.pack(">I", len(header_bytes)))
        f.write(header_bytes)
        f.write(ciphertext)

def read_encrypted_file(path: str):
    """
    Returns (header_bytes, ciphertext_bytes)
    """
    with open(path, "rb") as f:
        raw = f.read(4)
        if len(raw) < 4:
            raise ValueError("File too short or invalid format")
        (hlen,) = struct.unpack(">I", raw)
        header_bytes = f.read(hlen)
        if len(header_bytes) != hlen:
            raise ValueError("Header truncated or corrupt")
        ciphertext = f.read()
    return header_bytes, ciphertext

def read_plain_file(path: str):
    with open(path, "rb") as f:
        plaintext = f.read()
    return plaintext

def write_plain_file(path: str, plaintext: bytes):
    with open(path, "wb") as f:
        f.write(plaintext)