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

*** Lessons Learned
- This example shows two cases of poor design: weak security (AES-ECB) as well
  as weak validation of the email address. Stronger e-mail validation would have
  made this attack more difficult as the degree of input control would have been
  lessened.
"""

import random
from urllib.parse import parse_qsl, urlencode

from Crypto.Cipher import AES

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
    # Reject & and = characters
    if '&' in email or '=' in email:
        raise ValueError(f'Invalid email address: {email}')

    profile = {
        'email': email,
        'uid': '10',
        'role': 'user'
    }

    # Url encode the profile object, but don't encode the '@' character.
    return '&'.join(['='.join((k, v)) for k, v in profile.items()])
    return urlencode(profile).replace('%40', '@').replace('%04')


def rand_bytes(size: int = 16) -> bytes:
    return bytes([random.randint(0, 255) for i in range(size)])


class Oracle:
    def __init__(self):
        # AES ECB with a consistent but unknown key
        self.cipher = AES.new(rand_bytes(), AES.MODE_ECB)

    def encrypt(self, plaintext: bytes) -> bytes:
        # Make sure the data is properly padded for the block cipher
        return self.cipher.encrypt(pkcs7_pad(plaintext, 16))

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.cipher.decrypt(ciphertext)


if __name__ == '__main__':
    oracle = Oracle()
    user_profile = profile_for('foo@bar.com')
    profile_ct = oracle.encrypt(user_profile.encode())
    profile_obj = parse_url_encoding(oracle.decrypt(profile_ct).rstrip(b'\x04'))
    assert profile_obj == {'email': 'foo@bar.com', 'uid': '10', 'role': 'user'}

    # The target uses AES ECB, which will encrypt the data in 16B blocks. We
    # control the email field, which we can pad out such that the urlencoded
    # email and fields + 'role=' make up the first two blocks. The role value 
    # will begin in the next block and use PKCS#7 padding to a block boundary. 
    # If we substitute the last block with the ciphertext of a block containing
    # the PKCS#7 padding string 'admin', we can create a valid ciphertext that
    # will be interpreted as an admin cookie.

    # Create a valid email that will result in a string that ends with `role=` 
    # at the end of a block.
    padding_length = 16 - ((len('email=') + len('@a.com') + len('&uid=10&role=')) % 16)
    email = 'A' * padding_length + '@a.com'
    role_aligned_profile = profile_for(email)
    enc_role_aligned_profile = oracle.encrypt(role_aligned_profile.encode())
    
    print('[+] Created profile object with role value at the start of a block:')
    print(role_aligned_profile)
    print('[+] Role aligned ciphertext:')
    print(enc_role_aligned_profile.hex())

    # Now we need a block of ciphertext that contains the string 'admin' + 
    # PKCS#7 padding as a full block while still being a valid email address.
    role = 'admin'
    admin_plaintext = 'B' * (16 - len('email='))
    admin_plaintext += role
    admin_plaintext += '\x04' * (16 - len(role))

    crafted_admin_profile = profile_for(admin_plaintext + '@a.com')
    print('[+] Created profile object with padded block containing "admin" string:')
    print(crafted_admin_profile.encode())

    # The second block of the ciphertext contains the admin string
    admin_ciphertext = oracle.encrypt(crafted_admin_profile.encode())[16:32]
    print('[+] Crafted admin string ciphertext block:')
    print(admin_ciphertext.hex())

    # Replace the last black of the role_aligned_profile ("user") with encrypted
    # "role" string
    enc_crafted_profile = enc_role_aligned_profile[:-16] + admin_ciphertext
    print('[+] Crafted ciphertext:')
    print(enc_crafted_profile.hex())

    # Decrypt and decode the crafted profile
    print('[+] Decrypted crafted profile object:')
    crafted_profile_pt = oracle.decrypt(enc_crafted_profile).rstrip(b'\x04')
    crafted_profile_obj = parse_url_encoding(crafted_profile_pt)
    print(crafted_profile_obj)
