"""v0.7.0 fixtures: deep weak-cryptography patterns."""
from Crypto.Cipher import DES, AES
import ssl

IV = b'0123456789abcdef'
KEY = b'0123456789abcdef'


def use_des():
    cipher = DES.new(KEY, DES.MODE_ECB)
    return cipher.encrypt(b'test')


def use_aes_ecb():
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(b'test')


def use_cbc_hardcoded_iv():
    cipher = AES.new(KEY, AES.MODE_CBC, iv=b'1234567890123456')
    return cipher.encrypt(b'test')


def insecure_tls():
    ctx = ssl._create_unverified_context()
    return ssl.wrap_socket(ctx, cert_reqs=ssl.CERT_NONE)
