#!/usr/bin/env python3
"""
Set 1 / Challenge 1

Convert hex to base64

The string:
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

Should produce:
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
"""

from binascii import unhexlify
#from base64 import b64encode
from mybase64 import b64encode


def solve():
    """
    Uses python base64 module to b64encode the input string
    """
    input_bytes = unhexlify("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    expected_output = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    result = b64encode(input_bytes)
    print(f"result = {result}")
    print(f"result matches = {b64encode(input_bytes) == expected_output}")


if __name__ == '__main__':
    solve()

