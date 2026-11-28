"""Small structural checks for AES ciphertext supplied by the user."""


def find_repeated_blocks(ciphertext, block_size=16):
    """Return duplicate block values and their occurrence counts."""
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")
    if not isinstance(block_size, int) or block_size < 1:
        raise ValueError("Block size must be positive")
    complete_length = len(ciphertext) - (len(ciphertext) % block_size)
    blocks = [
        ciphertext[index:index + block_size]
        for index in range(0, complete_length, block_size)
    ]
    counts = {}
    for block in blocks:
        counts[block] = counts.get(block, 0) + 1
    return {block.hex(): count for block, count in counts.items() if count > 1}


def looks_like_ecb(ciphertext, block_size=16):
    """A repeated full block is a warning sign, not proof of AES-ECB."""
    return bool(find_repeated_blocks(ciphertext, block_size))
