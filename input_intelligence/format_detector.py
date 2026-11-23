
import base64
import binascii


# ==========================================
# 1. Detect Character Set
# ==========================================

def detect_character_set(data):

    result = []

    if data == "":
        return ["Empty input"]

    uppercase = False
    lowercase = False
    numbers = False
    symbols = False
    spaces = False

    for character in data:

        if character.isupper():
            uppercase = True

        if character.islower():
            lowercase = True

        if character.isdigit():
            numbers = True

        if character.isspace():
            spaces = True

        if not character.isalnum() and not character.isspace():
            symbols = True

    if uppercase:
        result.append("Uppercase letters")

    if lowercase:
        result.append("Lowercase letters")

    if numbers:
        result.append("Numbers")

    if symbols:
        result.append("Symbols")

    if spaces:
        result.append("Whitespace")

    if data.isascii():
        result.append("ASCII")

    else:
        result.append("Unicode")

    return result


# ==========================================
# 2. Decode Possible Formats
# ==========================================

def decode_possible_formats(data):

    candidates = {}

    cleaned = "".join(data.split())

    if cleaned == "":
        return candidates


    # Check Binary

    binary = True

    for character in cleaned:

        if character != "0" and character != "1":
            binary = False

    if binary and len(cleaned) % 8 == 0:

        byte_values = []

        for i in range(0, len(cleaned), 8):

            byte_value = int(cleaned[i:i + 8], 2)

            byte_values.append(byte_value)

        candidates["Binary"] = bytes(byte_values)


    # Check Hexadecimal

    try:

        hex_data = bytes.fromhex(cleaned)

        if len(hex_data) > 0:

            candidates["Hexadecimal"] = hex_data

    except ValueError:

        pass


    # Check Base64

    try:

        if len(cleaned) % 4 == 1:

            raise ValueError("Invalid Base64 length")

        if "=" in cleaned:

            if len(cleaned) % 4 != 0:

                raise ValueError("Invalid padding")

            base64_data = cleaned

        else:

            padding = (4 - len(cleaned) % 4) % 4

            base64_data = cleaned + ("=" * padding)


        decoded = base64.b64decode(
            base64_data,
            validate=True
        )


        encoded_again = base64.b64encode(
            decoded
        ).decode("ascii")


        if "=" in cleaned:

            valid = encoded_again == cleaned

        else:

            valid = encoded_again.rstrip("=") == cleaned


        if valid and len(decoded) > 0:

            candidates["Base64"] = decoded


    except (ValueError, binascii.Error):

        pass


    return candidates


# ==========================================
# 3. Detect Possible Encoding
# ==========================================

def detect_possible_encoding(data):

    candidates = decode_possible_formats(data)

    result = []

    for format_name in candidates:

        result.append("Possible " + format_name)

    if len(result) == 0:

        result.append("No supported encoding detected")

    return result


# ==========================================
# 4. Validate UTF-8
# ==========================================

def validate_utf8(raw_data):

    try:

        raw_data.decode("utf-8")

        return True

    except UnicodeDecodeError:

        return False


# ==========================================
# 5. Detect File Signature
# ==========================================

def detect_file_signature(raw_data):

    signatures = [

        ("PNG", b"\x89PNG\r\n\x1a\n"),

        ("JPEG", b"\xff\xd8\xff"),

        ("GIF", b"GIF87a"),

        ("GIF", b"GIF89a"),

        ("PDF", b"%PDF-"),

        ("ZIP", b"PK\x03\x04"),

    ]


    for file_name, signature in signatures:

        if raw_data.startswith(signature):

            return file_name


    return "No known file signature"
