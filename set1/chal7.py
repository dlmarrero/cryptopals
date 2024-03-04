#!/usr/bin/env python3
"""
AES in ECB mode
The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
"""


from base64 import b64decode
from Crypto.Cipher import AES


def aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)


if __name__ == '__main__':
    with open("files/7.txt", "r") as f:
        data = b64decode(f.read())

    print(aes_ecb_decrypt(data, b"YELLOW SUBMARINE").decode())
