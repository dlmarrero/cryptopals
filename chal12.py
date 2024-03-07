#!/usr/bin/env python3
"""
Byte-at-a-time ECB decryption (Simple) Copy your oracle function to a new
function that encrypts buffers under ECB mode using a consistent but unknown key
(for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE
ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg YnkK Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by
hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key) It turns out: you can
decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

Feed identical bytes of your-string to the function 1 at a time --- start with 1
byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the
cipher. You know it, but do this step anyway. Detect that the function is using
ECB. You already know, but do this step anyways. Knowing the block size, craft
an input block that is exactly 1 byte short (for instance, if the block size is
8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put
in that last byte position. Make a dictionary of every possible last byte by
feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
"AAAAAAAC", remembering the first block of each invocation. Match the output of
the one-byte-short input to one of the entries in your dictionary. You've now
discovered the first byte of unknown-string. Repeat for the next byte.

*** Lessons Learned 
- Adding a single character until the block starts to repeat to find the block
  size.. so cool!
- How to use the known plaintext to create dictionaries for blocks after the first
"""

import random
from base64 import b64decode

from Crypto.Cipher import AES

from chal8 import detect_aes_ecb
from chal9 import pkcs7_pad


def rand_bytes(size: int = 16) -> bytes:
    return bytes([random.randint(0, 255) for i in range(size)])


class Oracle:
    def __init__(self):
        # AES ECB with a consistent but unknown key
        self.cipher = AES.new(rand_bytes(), AES.MODE_ECB)

    def encrypt(self, plaintext: bytes) -> bytes:
        # Append random bytes as instructed
        plaintext += b64decode("""
        Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
        YnkK                         
        """)

        # Make sure the data is properly padded for the block cipher
        return self.cipher.encrypt(pkcs7_pad(plaintext, 16))

    def detect_block_size(self) -> int:
        """
        Encrypts repeated data one byte at a time until the blocks start to repeat
        """
        last_ct = b''
        for i in range(1, 64):
            ct = self.encrypt(b'A' * i)

            # We'll use 4 bytes to indicate that we have a repeating block
            if last_ct[:4] == ct[:4]:
                # Found the repeating block. Now count the number of repeating
                # bytes and we have our keysize
                for i in range(64):
                    if last_ct[i] != ct[i]:
                        return i
                else:
                    raise ValueError("Found matching block but failed to get block size")
            
            last_ct = ct
        else:
            raise ValueError("Failed to find matching block")

    def create_dictionary(self, block_size: int, current_block: int, known_plaintext: bytes) -> dict:
        """
        Given a block size, creates a dictionary of all the possible block
        outputs for a repeated input of length block_size - 1 followed by the
        next byte value
        """
        dictionary = {}
        for i in range(256):
            # Create lookup for the next unknown plaintext char
            base = b'A' * ((block_size * current_block) - len(known_plaintext) - 1) 
            base += known_plaintext
            next_char = i.to_bytes(1, 'big')
            ciphertext = self.encrypt(base + next_char)
            block = ciphertext[block_size * (current_block - 1):block_size * current_block]
            dictionary[block] = next_char

        return dictionary


if __name__ == '__main__':
    oracle = Oracle()
    block_size = oracle.detect_block_size()
    assert detect_aes_ecb(oracle.encrypt(b'A' * (block_size * 3)))

    # Decrypt the plaintext one block at a time. Each time we uncover a block,
    # Pad it out to the next block over and repeat the process, solving a char
    # at a time.
    known_plaintext = b''
    current_block = 1
    while True:
        dictionary = oracle.create_dictionary(block_size, current_block, known_plaintext)

        # Solve next plaintext char
        plaintext = b'A' * ((block_size * current_block) - len(known_plaintext) - 1)
        ciphertext = oracle.encrypt(plaintext)
        block = ciphertext[block_size * (current_block - 1):block_size * current_block]
        next_char = dictionary[block]
        if next_char == b'\x04':
            # Reached pkcs7 padding. Done.
            break

        known_plaintext += next_char
        if len(known_plaintext) % block_size == 0:
            # Reached the end of the current block
            current_block += 1

    print(known_plaintext)
