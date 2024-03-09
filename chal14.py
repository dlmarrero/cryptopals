#!/usr/bin/env python3
"""
Byte-at-a-time ECB decryption (Harder) Take your oracle function from #12. Now
generate a random count of random bytes and prepend this string to every
plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.

*** Lessons Learned: Very similar to challenge 12 except when the blocks start
    repeating, the prefix length is the difference between the block size and
    the test input size. Creating the dictionary and any other length-sensitive
    operations have to also take the discovered prefix length into account.
"""

import random
from base64 import b64decode
from typing import Tuple

from Crypto.Cipher import AES

from chal8 import detect_aes_ecb
from chal9 import pkcs7_pad


def rand_bytes(size: int = 16) -> bytes:
    return bytes([random.randint(0, 255) for i in range(size)])


class Oracle:
    def __init__(self):
        # AES ECB with a consistent but unknown key
        self.cipher = AES.new(rand_bytes(), AES.MODE_ECB)
        # Generate a random prefix to be prepended to each encrypted message
        self.random_prefix = rand_bytes(random.randint(1, 15))

    def encrypt(self, plaintext: bytes) -> bytes:
        # Append random bytes as instructed
        target_bytes = b64decode("""
        Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
        YnkK                         
        """)
        data = b''.join([self.random_prefix, plaintext, target_bytes])

        # Make sure the data is properly padded for the block cipher
        return self.cipher.encrypt(pkcs7_pad(data, 16))

    def detect_block_size(self) -> Tuple[int, int]:
        """
        Encrypts repeated data one byte at a time until the blocks start to repeat.
        Returns the discovered prefix length and the block size
        """
        last_ct = b''
        for i in range(1, 64):
            ct = self.encrypt(b'A' * i)

            # We'll use 4 bytes to indicate that we have a repeating block
            if last_ct[:4] == ct[:4]:
                # Found the repeating block. Now count the number of repeating
                # bytes and we have our keysize
                for j in range(64):
                    if last_ct[j] != ct[j]:
                        block_size = j
                        prefix_length = (block_size - i) + 1
                        return prefix_length, block_size
                else:
                    raise ValueError("Found matching block but failed to get block size")
            
            last_ct = ct
        else:
            raise ValueError("Failed to find matching block")

    def create_dictionary(self, block_size: int, current_block: int, prefix_length: int, known_plaintext: bytes) -> dict:
        """
        Given a block size, creates a dictionary of all the possible block
        outputs for a repeated input of length block_size - 1 followed by the
        next byte value
        """
        dictionary = {}
        for i in range(256):
            # Create lookup for the next unknown plaintext char
            base = b'A' * ((block_size * current_block) - prefix_length - len(known_plaintext) - 1) 
            base += known_plaintext
            next_char = i.to_bytes(1, 'big')
            ciphertext = self.encrypt(base + next_char)
            block = ciphertext[block_size * (current_block - 1):block_size * current_block]
            dictionary[block] = next_char

        return dictionary


if __name__ == '__main__':
    oracle = Oracle()
    
    # We know the block size is 16. So the value our detector gives us uncovers
    # the length of the random prefix as 16 - block size
    prefix_length, block_size = oracle.detect_block_size()
    print(f'[+] Prefix length: {prefix_length}')
    print(f'[+] Block size: {block_size}')
    assert detect_aes_ecb(oracle.encrypt(b'A' * (block_size * 3)))

    # Decrypt the plaintext one block at a time. Each time we uncover a block,
    # Pad it out to the next block over and repeat the process, solving a char
    # at a time.
    known_plaintext = b''
    current_block = 1
    while True:
        dictionary = oracle.create_dictionary(block_size, current_block, prefix_length, known_plaintext)

        # Solve next plaintext char
        plaintext = b'A' * ((block_size * current_block) - prefix_length - len(known_plaintext) - 1)
        ciphertext = oracle.encrypt(plaintext)
        block = ciphertext[block_size * (current_block - 1):block_size * current_block]
        next_char = dictionary[block]
        if next_char == b'\x04':
            # Reached pkcs7 padding. Done.
            break

        known_plaintext += next_char
        if (len(known_plaintext) + prefix_length) % block_size == 0:
            # Reached the end of the current block
            current_block += 1

    print('[+] Target bytes:')
    print(known_plaintext.decode())
