
# Base58 alphabet used by Bitcoin
BASE58_ALPHABET = (
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
)


# Decode Base58 data
def decode_base58(data):

    # Check input type
    if not isinstance(data, str):
        raise TypeError("Input must be text")

    data = data.strip()

    if not data:
        raise ValueError("Input cannot be empty")

    # Convert Base58 text into a number
    number = 0

    for char in data:

        if char not in BASE58_ALPHABET:
            raise ValueError("Invalid Base58 character")

        digit = BASE58_ALPHABET.index(char)

        number = number * 58 + digit

    # Convert the number into bytes
    if number == 0:
        decoded = b""
    else:
        length = (number.bit_length() + 7) // 8
        decoded = number.to_bytes(length, "big")

    # Preserve leading zero bytes
    leading_zeros = len(data) - len(data.lstrip("1"))

    result = b"\x00" * leading_zeros + decoded

    return result
