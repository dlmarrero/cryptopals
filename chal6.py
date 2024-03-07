#!/usr/bin/env python3.9
"""
Break repeating-key XOR

It is officially on, now. This challenge isn't conceptually hard, but it
involves actual error-prone coding. The other challenges in this set are there
to bring you up to speed. This one is there to qualify you. If you can do this
one, you're probably just fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with repeating-key
XOR.

Decrypt it.

Here's how:

1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
2. Write a function to compute the edit distance/Hamming distance between two
strings. The Hamming distance is just the number of differing bits. The distance
between: `this is a test` and `wokka wokka!!!` is 37. Make sure your code agrees
before you proceed. 
3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second 
KEYSIZE worth of bytes, and find the edit distance between them.  Normalize this
result by dividing by KEYSIZE.
4. The KEYSIZE with the smallest normalized edit distance is probably the key. 
You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4
KEYSIZE blocks instead of 2 and average the distances.
5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of
KEYSIZE length.
6. Now transpose the blocks: make a block that is the first byte of every block,
and a block that is the second byte of every block, and so on. 
7. Solve each block as if it was single-character XOR. You already have code to
do this.
8. For each block, the single-byte XOR key that produces the best looking
histogram is the repeating-key XOR key byte for that block. Put them together
and you have the key.

This code is going to turn out to be surprisingly useful later on. Breaking
repeating-key XOR ("Vigenere") statistically is obviously an academic exercise,
a "Crypto 101" thing. But more people "know how" to break it than can actually
break it, and a similar technique breaks something much more important.

*** Lessons Learned ***
- Must calculate the hamming distance over multiple chunks, not just the first
few, to get accurate hamming distance scores for the keysize
"""


from base64 import b64decode
from typing import List

from chal4 import find_xor_key


def hamming_distance(s1: bytes, s2: bytes) -> int:
    if len(s1) != len(s2):
        raise ValueError("Cannot calculate hamming distance on strings of different lengths")
    
    # XOR each byte of the two strings and total the number of 1s
    distance = 0
    for c1, c2 in zip(s1, s2):
        distance += bin(c1 ^ c2).count('1')

    return distance


def get_keysizes(data: bytes, size_count: int = 1) -> List[int]:
    """
    Determines the key size statistically by hamming distance and returns the
    size_count smallest key size values
    """
    # Score the key sizes
    keysize_results = {}
    for keysize in range(2, 40):
        # Get a list of all chunks we can gather at this keysize
        chunks = get_chunks(data, keysize)
        
        # Calculate the hamming distance between each chunk and the next for all
        # chunks of the same size
        distances = [
            hamming_distance(chunks[i], chunks[i + 1])
            for i in range(len(chunks) - 1)
            if len(chunks[i]) == len(chunks[i + 1])
        ]

        # Normalize the scores
        average_distance = sum(distances) / len(distances)
        normalized = average_distance / keysize
        keysize_results[keysize] = normalized
    
    # Get the smallest keys in the results
    smallest_keys = []
    while len(smallest_keys) < size_count:
        smallest_key = min(keysize_results, key=keysize_results.get)
        del keysize_results[smallest_key]
        smallest_keys.append(smallest_key)

    return smallest_keys


def get_chunks(data: bytes, size: int) -> List[bytes]:
    """
    Returns the data in chunks of size bytes
    """
    chunks = []
    for i in range(0, len(data), size):
        # Reached the end of the string and its smaller than size
        # We'll just work with the complete chunks
        if i + size > len(data):
            break

        chunks.append(data[i:i + size])

    return chunks


def transpose_chunks(chunks: List[bytes], size: int) -> List[bytes]:
    """
    Transpose the chunks into blocks of chars at each index
    i.e. [[a,b], [c,d]] -> [[a,c], [b,d]]
    """
    blocks = []
    for i in range(size):
        blocks.append(bytes([chunk[i] for chunk in chunks]))

    return blocks


def break_repeating_xor_key(data: bytes) -> bytes:
    keys = []
    for keysize in get_keysizes(data):
        chunks = get_chunks(data, keysize)
        blocks = transpose_chunks(chunks, keysize)

        # Solve each block as if it were a single byte xor
        keyscores = [find_xor_key(block) for block in blocks]
        if any(score.score == 0 for score in keyscores):
            continue

        xor_key = bytes([score.key for score in keyscores])
        keys.append(xor_key)

    return keys


if __name__ == '__main__':
    # Test the hamming distance function
    assert hamming_distance(b"this is a test", b"wokka wokka!!!") == 37
    
    with open("files/6.txt", "rb") as f:
        data = b64decode(f.read())

    for key in break_repeating_xor_key(data):
        plaintext = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
        print(f"*** key: {key} ***\n")
        print(plaintext.decode())
