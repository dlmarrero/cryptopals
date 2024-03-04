#!/usr/bin/env python3.9
"""
Detect AES in ECB mode
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic;
the same 16 byte plaintext block will always produce the same 16 byte ciphertext.

*** Lessons Learned
- Used CyberChef to play around with ECB and found that the full 16B plaintext
blocks must be identical to generate matching ciphertext blocks. This led me to
the solution where we check if any blocks are repeated
"""

from chal6 import get_chunks


def detect_aes_ecb(ciphertext: bytes) -> bool:
    """
    Checks the ciphertext for repeating blocks of 16 bytes
    """
    chunks = get_chunks(ciphertext, 16)

    # If all chunks are unique, we were unable to detect AES
    return len(chunks) != len(set(chunks))


if __name__ == '__main__':
    with open("files/8.txt", "r") as f:
        ciphertexts = [bytes.fromhex(line.strip()) for line in f.readlines()]

    for i, ciphertext in enumerate(ciphertexts):
        if detect_aes_ecb(ciphertext):
            print(f"AES ECB ciphertext likely at index {i}:")
            print(ciphertext.hex())
            break
    else:
        print("No AES ECB ciphertext found")
