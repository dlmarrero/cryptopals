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

def solve():
    input_bytes = unhexlify("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    print(f"result matches = {base64_decode(input_bytes) == expected_output}")


def base64_decode(data: bytes) -> str:
    """Rolling my own base64 decoding function to learn about the underlying implementation"""
    return data


if __name__ == '__main__':
    solve()

