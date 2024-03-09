#!/usr/bin/env python3
"""
PKCS#7 padding validation Write a function that takes a plaintext, determines if
it has valid PKCS#7 padding, and strips the padding off.

The string:

"ICE ICE BABY\x04\x04\x04\x04" ... has valid padding, and produces the result
"ICE ICE BABY".

The string:

"ICE ICE BABY\x05\x05\x05\x05" ... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04" If you are writing in a language with exceptions,
like Python or Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.

*** Lessons Learned
- Originally, I thought PKCS#7 padding was always padded with the byte value 0x4
  but the value chosen for the padding is actually equal to the number of bytes
  added
  Source: https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method
"""

import string


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


if __name__ == '__main__':
    assert pkcs7_strip(b"ICE ICE BABY\x04\x04\x04\x04") == b"ICE ICE BABY"
    assert pkcs7_strip(b"ICE ICE BABY\x03\x03\x03") == b"ICE ICE BABY"
    try:
        pkcs7_strip(b"ICE ICE BABY\x05\x05\x05\x05")
    except ValueError:
        pass
    else:
        raise AssertionError("Failed to raise exception on invalid padding")

    try:
        pkcs7_strip(b"ICE ICE BABY\x01\x02\x03\x04")
    except ValueError:
        pass
    else:
        raise AssertionError("Failed to raise exception on invalid padding")

    print('PKCS#7 padding validation passed')
