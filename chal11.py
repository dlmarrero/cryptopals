#!/usr/bin/env python3
"""
An ECB/CBC detection oracle Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function
that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input) => [MEANINGLESS JIBBER JABBER] Under the hood,
have the function append 5-10 bytes (count chosen randomly) before the plaintext
and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC
the other half (just use random IVs each time for CBC). Use rand(2) to decide
which to use.

Detect the block cipher mode the function is using each time. You should end up
with a piece of code that, pointed at a block box that might be encrypting ECB
or CBC, tells you which one is happening.

*** Lessons learned
- When the attacker controls the input, block ciphers can become compromised
"""

import random

from Crypto.Cipher import AES

from chal8 import detect_aes_ecb
from chal9 import pkcs7_pad
from chal10 import AES_CBC


def rand_bytes(size: int = 16) -> bytes:
    return bytes([random.randint(0, 255) for i in range(size)])


def encryption_oracle(plaintext: bytes) -> bytes:
    rand_key = rand_bytes()
    if random.choice([0, 1]) == 0:
        print('Using ECB')
        cipher = AES.new(rand_key, AES.MODE_ECB)
    else:
        print('Using CBC')
        rand_iv = rand_bytes()
        cipher = AES_CBC(rand_key, rand_iv)

    # Append random bytes as instructed
    modified_plaintext = b''.join([
        rand_bytes(random.randint(5, 10)),
        plaintext,
        rand_bytes(random.randint(5, 10))
    ])

    # Make sure the data is properly padded for the block cipher
    return cipher.encrypt(pkcs7_pad(modified_plaintext, 16))


def detect_cipher(ciphertext: bytes) -> str:
    if detect_aes_ecb(ciphertext):
        result = 'ECB'
    else:
        result = 'CBC'

    print(f'Detected {result}')


if __name__ == '__main__':
    # Encrypt a message long enough to create repeating blocks or detection
    # mechanism will not work
    detect_cipher(encryption_oracle(b"A" * 64))
