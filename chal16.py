#!/usr/bin/env python3
"""
CBC bitflipping attacks
Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="

.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and
encrypt it under the random AES key.

The second function should decrypt the string and look for the characters 
";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each
resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to
provide user input to it that will generate the string the second function is
looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish 
this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext
block:

- Completely scrambles the block the error occurs in
- Produces the identical 1-bit error(/edit) in the next ciphertext block.

Stop and think for a second.
Before you implement this attack, answer this question: why does CBC mode have this property?

*** Lessons Learned
- I thought that modifying one block of ciphertext would affect all the following
    blocks. This is not the case. Only the next block is affected.
"""

from chal10 import AES_CBC
from chal11 import rand_bytes
from chal15 import pkcs7_strip

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """
    Applies PKCS#7 padding to the data to make it an even multiple of the block size
    """
    padding_required = block_size - len(data) % block_size
    assert padding_required < 16
    return data + bytes([padding_required]) * padding_required


def pkcs7_strip(data: bytes) -> bytes:
    """
    Strips PKCS#7 padding from the data
    """
    expected_padding_length = data[-1]
    expected_padding = expected_padding_length.to_bytes(1, byteorder='big') * expected_padding_length
    actual_padding = data[-expected_padding_length:]
    if expected_padding != actual_padding:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-expected_padding_length]


def add_comments_and_quote(data: str) -> str:
    """
    Adds URL encoded comments to the data and quotes out ';' and '=' characters
    """
    return ''.join([
        'comment1=cooking%20MCs;userdata=',
        data.replace(';', '%3B').replace('=', '%3D'),
        ';comment2=%20like%20a%20pound%20of%20bacon'
    ])

class Cipher:
    def __init__(self):
        random_key = rand_bytes(16)
        random_iv = rand_bytes(16)
        self.cipher = AES_CBC(random_key, random_iv)

    def create(self, data: str) -> bytes:
        prepared_data = add_comments_and_quote(data)
        return self.encrypt(prepared_data)

    def encrypt(self, data: str) -> bytes:
        return self.cipher.encrypt(pkcs7_pad(data.encode(), 16))

    def decrypt(self, data: bytes) -> bytes:
        return pkcs7_strip(self.cipher.decrypt(data))

    def is_admin(self, data: bytes) -> bool:
        return b';admin=true;' in self.decrypt(data)


if __name__ == '__main__':
    assert pkcs7_strip(pkcs7_pad(b"hello", 12)) == b"hello"
    assert pkcs7_strip(pkcs7_pad(b"hello", 16)) == b"hello"
    assert pkcs7_strip(pkcs7_pad(b"hello", 20)) == b"hello"
    print('[+] PKCS#7 padding validation passed')

    cipher = Cipher()
    assert cipher.decrypt(cipher.create('foo=bar;')) == \
           b'comment1=cooking%20MCs;userdata=foo%3Dbar%3B;comment2=%20like%20a%20pound%20of%20bacon'
    assert cipher.is_admin(cipher.create(';admin=true;')) == False
    print('[+] Input quoting and encryption passed')

    # XOR encode the admin string using 0x41 as the key
    admin_str = b';admin=true;'
    xor_encoded_admin = bytes([
        admin_str[i] ^ 0x41
        for i in range(len(admin_str))
    ])

    ciphertext = cipher.create(xor_encoded_admin.decode())
    
    # XOR the block previous to userdata to get the desired plaintext
    ct_array = bytearray(ciphertext)
    for i in range(len(admin_str)):
        ct_array[i + 16] ^= 0x41
    modified_ct = bytes(ct_array)

    print(f'[+] Decrypted crafted ciphertext:')
    print(cipher.decrypt(modified_ct))
    print(f'[+] Is admin: {cipher.is_admin(modified_ct)}')
