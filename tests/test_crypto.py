# tests/test_crypto.py
import os
from cryptograph.core.crypto import encrypt_bytes, decrypt_bytes
from cryptograph.utils.file_helpers import write_encrypted_file, read_encrypted_file
import tempfile
import pytest

SAMPLE_TEXTS = [
    b"",
    b"a",
    b"1234567",  # less than 8
    b"16-bytes-message!!",  # > 16
    b"The quick brown fox jumps over the lazy dog" * 10
]

@pytest.mark.parametrize("alg,mode", [
    ("AES", "CBC"),
    ("AES", "ECB"),
    ("3DES", "CBC"),
    ("3DES", "ECB"),
    ("DES", "CBC"),
    ("DES", "ECB"),
])
def test_roundtrip_alg_mode(alg, mode):
    password = "strong-password-123"
    for txt in SAMPLE_TEXTS:
        header, ct = encrypt_bytes(txt, password=password, algorithm=alg, mode=mode)
        pt = decrypt_bytes(header, ct, password=password)
        assert pt == txt

def test_file_write_read_roundtrip(tmp_path):
    password = "file-pass-xyz"
    data = b"Some binary data \x00\x01\x02"
    header, ct = encrypt_bytes(data, password=password, algorithm="AES", mode="CBC")
    out = tmp_path / "test.enc"
    write_encrypted_file(str(out), header, ct)

    header2, ct2 = read_encrypted_file(str(out))
    assert header2 == header
    assert ct2 == ct

    pt = decrypt_bytes(header2, ct2, password=password)
    assert pt == data

def test_wrong_password_raises(tmp_path):
    header, ct = encrypt_bytes(b"secret", password="right-pass", algorithm="AES", mode="CBC")
    with pytest.raises(Exception):
        # wrong password should fail (likely during unpad)
        _ = decrypt_bytes(header, ct, password="wrong-pass")
