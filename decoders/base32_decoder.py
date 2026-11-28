
import base64


# Decode Base32 data
def decode_base32(data):

    # Check input type
    if not isinstance(data, str):
        raise TypeError("Input must be text")

    # Remove unnecessary spaces
    data = "".join(data.split()).upper()

    if not data:
        raise ValueError("Input cannot be empty")

    # Add missing Base32 padding
    padding = (8 - len(data) % 8) % 8

    data += "=" * padding

    # Decode Base32
    result = base64.b32decode(
        data,
        casefold=True
    )

    return result
