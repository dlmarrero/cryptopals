#!/usr/bin/env python3
"""
Implement CBC mode
CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the
fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the
cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a 
"fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead
of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function 
from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of
all ASCII 0 (\x00\x00\x00 &c)
"""

from base64 import b64decode
from Crypto.Cipher import AES
from chal6 import get_chunks

def xor_16(c1: bytes, c2: bytes) -> bytes:
    assert len(c1) == 16 and len(c2) == 16
    return (int.from_bytes(c1, 'big') ^ int.from_bytes(c2, 'big')).to_bytes(16, 'big')


class AES_CBC:
    def __init__(self, key: bytes, iv: bytes):
        self.cipher = AES.new(key, AES.MODE_ECB)
        self.iv = iv

    def encrypt(self, plaintext: bytes) -> bytes:
        ciphertext = b''
        prev_block = self.iv

        for block in get_chunks(plaintext, 16):
            xor_block = xor_16(block, prev_block)
            enc_block = self.cipher.encrypt(xor_block)
            ciphertext += enc_block
            prev_block = enc_block

        return ciphertext


    def decrypt(self, ciphertext: bytes) -> bytes:
        plaintext = b''
        prev_block = self.iv

        for ct_block in get_chunks(ciphertext, 16):
            dec_block = self.cipher.decrypt(ct_block)
            xor_block = xor_16(dec_block, prev_block)
            plaintext += xor_block
            prev_block = ct_block

        return plaintext


if __name__ == '__main__':
    plaintext = b"YELLOW SUBMARINE" * 4
    key = b"YELLOW SUBMARINE"
    iv = b"\0" * 16
    cipher = AES_CBC(key, iv)
    ciphertext = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(ciphertext)
    assert plaintext == decrypted

    with open('./files/10.txt') as f:
        challenge_ciphertext = b64decode(f.read())
    
    print(cipher.decrypt(challenge_ciphertext).decode())
