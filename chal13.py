#!/usr/bin/env python3
"""
ECB cut-and-paste
Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle
... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should 
have something like:

profile_for("foo@bar.com")
... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}
... encoded as:

email=foo@bar.com&uid=10&role=user
Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote 
them, whatever you want to do, but don't let people set their email address to 
"foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

Encrypt the encoded user profile under the key; "provide" that to the "attacker".
Decrypt the encoded user profile and parse it.
Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the 
ciphertexts themselves, make a role=admin profile.
"""

import random
import re
from base64 import b64decode
from urllib.parse import parse_qsl, urlencode

from Crypto.Cipher import AES

from chal8 import detect_aes_ecb
from chal9 import pkcs7_pad


def parse_url_encoding(data: bytes) -> dict:
    """
    Given a URL-encoded string, parses it into a dictionary
    """
    return {
        k.decode(): v.decode() 
        for k,v in parse_qsl(data)
    }


def profile_for(email: str) -> str:
    """
    Generates a user profile object for the given email address
    """
    # Regex match for valid email
    # Source: https://www.geeksforgeeks.org/check-if-email-address-valid-or-not-in-python/
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    if not re.fullmatch(regex, email):
        raise ValueError(f'Invalid email address: {email}')

    profile = {
        'email': email,
        'uid': random.randint(10, 99),
        'role': 'user'
    }

    # Url encode the profile object, but don't encode the '@' character.
    return urlencode(profile).replace('%40', '@')


def rand_bytes(size: int = 16) -> bytes:
    return bytes([random.randint(0, 255) for i in range(size)])


class Oracle:
    def __init__(self):
        # AES ECB with a consistent but unknown key
        self.cipher = AES.new(rand_bytes(), AES.MODE_ECB)

    def encrypt(self, plaintext: bytes) -> bytes:
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
    user_profile = profile_for('foo@bar.com')
    profile_ct = oracle.encrypt(user_profile.encode())
    profile_obj = parse_url_encoding(oracle.cipher.decrypt(profile_ct).rstrip(b'\x04'))
    print(profile_obj)
    exit(0)

    block_size = oracle.detect_block_size()

    # # Decrypt the plaintext one block at a time. Each time we uncover a block,
    # # Pad it out to the next block over and repeat the process, solving a char
    # # at a time.
    # known_plaintext = b''
    # current_block = 1
    # while True:
    #     dictionary = oracle.create_dictionary(block_size, current_block, known_plaintext)

    #     # Solve next plaintext char
    #     plaintext = b'A' * ((block_size * current_block) - len(known_plaintext) - 1)
    #     ciphertext = oracle.encrypt(plaintext)
    #     block = ciphertext[block_size * (current_block - 1):block_size * current_block]
    #     next_char = dictionary[block]
    #     if next_char == b'\x04':
    #         # Reached pkcs7 padding. Done.
    #         break

    #     known_plaintext += next_char
    #     if len(known_plaintext) % block_size == 0:
    #         # Reached the end of the current block
    #         current_block += 1

    # print(known_plaintext)
