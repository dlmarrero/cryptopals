import string

# Generate the base64 lookup table as a bytes string
B64_TABLE = (string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/").encode()

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

