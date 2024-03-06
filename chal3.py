#!/usr/bin/env python3
"""
Single-byte XOR cipher
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext.
Character frequency is a good metric. Evaluate each output and choose the one with the best score.
"""

from string import printable


def find_xor_key(enc_data: bytes) -> int:
    """
    Brute force and print all the results containing only printable chars:
    71: b'\\pptvqx?R\\8l?svtz?~?opjq{?py?}~|pq'
    74: b'Q}}y{|u2_Q5a2~{yw2s2b}g|v2}t2psq}|'
    77: b'Vzz~|{r5XV2f5y|~p5t5ez`{q5zs5wtvz{'
    79: b'Txx|~yp7ZT0d7{~|r7v7gxbys7xq7uvtxy'
    80: b'Kggcafo(EK/{(dacm(i(xg}fl(gn(jikgf'
    81: b'Jffb`gn)DJ.z)e`bl)h)yf|gm)fo)khjfg'
    83: b'Hdd`bel+FH,x+gb`n+j+{d~eo+dm+ijhde'
    85: b'Nbbfdcj-@N*~-adfh-l-}bxci-bk-olnbc'
    86: b'Maaeg`i.CM)}.bgek.o.~a{`j.ah.loma`'
    88: b"Cooking MC's like a pound of bacon"
    89: b'Bnnjhof!LB&r!mhjd!`!qntoe!ng!c`bno'
    90: b'Ammikle"OA%q"nkig"c"rmwlf"md"`caml'
    91: b'@llhjmd#N@$p#ojhf#b#slvmg#le#ab`lm'
    92: b'Gkkomjc$IG#w$hmoa$e$tkqj`$kb$fegkj'
    93: b'Fjjnlkb%HF"v%iln`%d%ujpka%jc%gdfjk'
    94: b'Eiimoha&KE!u&jomc&g&vishb&i`&dgeih'
    95: b"Dhhlni`'JD t'knlb'f'whric'ha'efdhi"
    114: b'iEEACDM\ngi\rY\nFCAO\nK\nZE_DN\nEL\nHKIED'
    115: b'hDD@BEL\x0bfh\x0cX\x0bGB@N\x0bJ\x0b[D^EO\x0bDM\x0bIJHDE'
    116: b'oCCGEBK\x0cao\x0b_\x0c@EGI\x0cM\x0c\\CYBH\x0cCJ\x0cNMOCB'
    117: b'nBBFDCJ\r`n\n^\rADFH\rL\r]BXCI\rBK\rOLNBC'

    Filtering further by only including results that contain a space:
    88: b"Cooking MC's like a pound of bacon" <--- Correct key = 88
    95: b"Dhhlni`'JD t'knlb'f'whric'ha'efdhi"

    The code was then modified to use the printable chars and number of spaces
    as scoring metrics to return the result with the highest score:
    88: b"Cooking MC's like a pound of bacon"
    """
    scores = {}
    results = {}
    
    for key in range(256):
        result = bytes([byte ^ key for byte in enc_data])
        results[key] = result

        scores[key] = 0

        # Score points for having all printable characters
        if all(chr(char) in printable for char in result):
            scores[key] += 10

        # Score points for each space character
        scores[key] += result.count(b' ')
    
    # Print the key/result with the highest score
    high_score_key = max(scores, key=scores.get)
    return high_score_key, results[high_score_key]


if __name__ == '__main__':
    enc = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")    
    key, result = find_xor_key(enc)
    print(f"{key}: {result}")
