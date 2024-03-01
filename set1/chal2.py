#!/usr/bin/env python3
"""
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
"""


def xor_by(data: bytes, key: bytes) -> bytes:
    """
    XORs the data with the key. Must be of equal length.
    """
    if len(data) != len(key):
        raise ValueError("Data and key must be of equal length")
    
    return bytes([a ^ b for a, b in zip(data, key)])


if __name__ == '__main__':
    data = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    key = bytes.fromhex("686974207468652062756c6c277320657965")
    expected = bytes.fromhex("746865206b696420646f6e277420706c6179")
    result = xor_by(data, key)
    print(result.hex())
    print(result == expected)
