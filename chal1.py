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

import string


# Generate the base64 lookup table as a bytes string
B64_TABLE = (string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/").encode()


def solve():
    """
    Uses python base64 module to b64encode the input string
    """
    input_bytes = bytes.fromhex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    expected_output = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    result = b64encode(input_bytes)
    print(f"result = {result}")
    print(f"result matches = {b64encode(input_bytes) == expected_output}")


def b64encode(data: bytes) -> bytes:
    """
    Rolling my own b64encode function to learn about the encoding algorithm
    """
    # Convert data to a list of bits
    bits = [bit for byte in data for bit in f'{byte:08b}']

    # Pad bits out to a 6-bit boundary
    for i in range(len(bits) % 6):
        bits.append('0')

    # Perform the lookups using 6-bit indices
    indices = []
    for i in range(0, len(bits), 6):
        val = ''.join(bits[i:i+6])
        indices.append(int(val, 2))

    result = bytes(B64_TABLE[i] for i in indices)

    # Perform any required padding for 4 character alignment
    for i in range(len(result) % 4):
        result += b'='

    return result


if __name__ == '__main__':
    solve()
