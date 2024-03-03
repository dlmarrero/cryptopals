#!/usr/bin/env python3
"""
Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
"""

from string import printable
from collections import Counter
from dataclasses import dataclass


@dataclass
class ScoredResult:
    key: int
    plaintext: bytes
    score: int


def find_xor_key(enc_data: bytes) -> ScoredResult:
    """
    This code was modified to from challenge 3 to use a dataclass to store the
    results of the scoring.
    """
    # Keep two dicts to simplify lookup of the max score
    scores = {}
    results = {}
    
    for key in range(256):
        result = bytes([byte ^ key for byte in enc_data])

        scores[key] = 0

        # Score lots of points for having all printable characters
        if all(chr(char) in printable for char in result):
            scores[key] += 50

        # Score extra points for each space character
        scores[key] += result.count(b' ')

        # Score points based on frequency of letters in English language
        letter_frequencies = Counter(chr(char).lower() for char in result)
        scores[key] += sum(letter_frequencies.get(letter, 0) for letter in 'etaoinshrdlu')
    
        # Save the result
        results[key] = ScoredResult(key, result, scores[key])
    
    # Print the key/result with the highest score
    high_score_key = max(scores, key=scores.get)
    return results[high_score_key]


if __name__ == '__main__':
    """
    Find the line in the file which has the highest score, which will be the
    only line that has been encoded with a single character XOR.

    Result:
    53: b'Now that the party is jumping\n'
    """
    all_results = []
    with open('files/4.txt') as f:
        for line in f:
            enc = bytes.fromhex(line.strip())
            result = find_xor_key(enc)
            if result.score > 0:
                all_results.append(result)
    
    best_result = max(all_results, key=lambda x: x.score)
    print(f"{best_result.key}: {best_result.plaintext}")
