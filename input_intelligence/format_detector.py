import base64
import binascii
import re

from decoders.extra_decoders import (
    decode_base85,
    decode_octal,
    decode_decimal,
    decode_url,
    decode_html_entities,
    decode_morse,
    decode_base58_text,
)


BASE32_PATTERN = re.compile(r"[A-Z2-7]+=*")

BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]+={0,2}")

BASE58_PATTERN = re.compile(r"[1-9A-HJ-NP-Za-km-z]+")

BASE85_PATTERN = re.compile(
    r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+"
)


FILE_SIGNATURES = [

    ("PNG", b"\x89PNG\r\n\x1a\n"),

    ("JPEG", b"\xff\xd8\xff"),

    ("GIF", b"GIF87a"),

    ("GIF", b"GIF89a"),

    ("PDF", b"%PDF-"),

    ("ZIP", b"PK\x03\x04"),

]


# ==========================================
# 1. DETECT CHARACTER SET
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
# 2. CHECK FILE SIGNATURE
# ==========================================

def detect_file_signature(raw_data):

    if not isinstance(raw_data, bytes):
        raise TypeError("Input must be bytes")

    for file_name, signature in FILE_SIGNATURES:

        if raw_data.startswith(signature):
            return file_name

    return "No known file signature"


# ==========================================
# 3. CHECK PLAUSIBLE DECODED PAYLOAD
# ==========================================

def is_plausible_payload(raw_data):

    if not isinstance(raw_data, bytes):
        return False

    if not raw_data:
        return False

    # Recognized binary file signatures are valid.

    if detect_file_signature(raw_data) != "No known file signature":
        return True

    try:

        text = raw_data.decode("utf-8")

    except UnicodeDecodeError:

        # Permit larger binary payloads.
        # Short random binary output is ambiguous.

        return len(raw_data) >= 16

    if not text:
        return False

    printable_count = sum(
        char.isprintable() or char in "\t\n\r"
        for char in text
    )

    printable_ratio = (
        printable_count / len(text)
    )

    return (
        printable_ratio >= 0.80
        or len(raw_data) >= 16
    )


# ==========================================
# 4. DECODE POSSIBLE FORMATS
# ==========================================

def decode_possible_formats(data):

    if not isinstance(data, str):
        raise TypeError("Input must be text")

    candidates = {}

    cleaned = "".join(data.split())

    if cleaned == "":
        return candidates

    # --------------------------------------
    # BINARY
    # --------------------------------------

    binary = all(
        character in "01"
        for character in cleaned
    )

    if binary and len(cleaned) % 8 == 0:

        byte_values = []

        for i in range(0, len(cleaned), 8):

            byte_value = int(
                cleaned[i:i + 8],
                2
            )

            byte_values.append(byte_value)

        candidates["Binary"] = bytes(byte_values)

    # --------------------------------------
    # HEXADECIMAL
    # --------------------------------------

    try:

        hex_data = bytes.fromhex(cleaned)

        if len(hex_data) > 0:
            candidates["Hexadecimal"] = hex_data

    except ValueError:
        pass

    # --------------------------------------
    # BASE32
    # --------------------------------------

    base32_source = data.strip()

    if (
        base32_source
        and not any(char.isspace() for char in base32_source)
    ):

        normalized = base32_source.upper()

        try:

            if BASE32_PATTERN.fullmatch(normalized):

                if "=" in normalized:

                    if len(normalized) % 8 != 0:
                        raise ValueError("Invalid Base32 padding")

                    padded = normalized

                else:

                    if len(normalized) % 8 not in (0, 2, 4, 5, 7):
                        raise ValueError("Invalid Base32 length")

                    padded = normalized + "=" * (
                        (8 - len(normalized) % 8) % 8
                    )

                decoded = base64.b32decode(
                    padded,
                    casefold=True
                )

                canonical = base64.b32encode(
                    decoded
                ).decode("ascii")

                if "=" in normalized:

                    valid = canonical == normalized

                else:

                    valid = (
                        canonical.rstrip("=") == normalized
                    )

                if (
                    valid
                    and is_plausible_payload(decoded)
                ):

                    candidates["Base32"] = decoded

        except (ValueError, binascii.Error):
            pass

    # --------------------------------------
    # BASE64
    # --------------------------------------

    base64_source = data.strip()

    if (
        base64_source
        and not any(char.isspace() for char in base64_source)
    ):

        try:

            if BASE64_PATTERN.fullmatch(base64_source):

                if "=" in base64_source:

                    if len(base64_source) % 4 != 0:
                        raise ValueError("Invalid Base64 padding")

                    padded = base64_source

                else:

                    if len(base64_source) % 4 == 1:
                        raise ValueError("Invalid Base64 length")

                    padding = (
                        4 - len(base64_source) % 4
                    ) % 4

                    padded = base64_source + ("=" * padding)

                decoded = base64.b64decode(
                    padded,
                    validate=True
                )

                canonical = base64.b64encode(
                    decoded
                ).decode("ascii")

                if "=" in base64_source:

                    valid = canonical == base64_source

                else:

                    valid = (
                        canonical.rstrip("=") == base64_source
                    )

                if (
                    valid
                    and is_plausible_payload(decoded)
                ):

                    candidates["Base64"] = decoded

        except (ValueError, binascii.Error):
            pass

    # --------------------------------------
    # ADDITIONAL ENCODINGS
    # --------------------------------------

    extra_decoders = {

        "Base58": decode_base58_text,

        "Base85": decode_base85,

        "Octal": decode_octal,

        "Decimal": decode_decimal,

        "URL": decode_url,

        "HTML entities": decode_html_entities,

        "Morse": decode_morse,

    }

    for name, decoder in extra_decoders.items():

        source = data.strip()

        # Strict Base58 validation.

        if name == "Base58":

            if (
                len(source) < 8
                or any(char.isspace() for char in source)
                or not BASE58_PATTERN.fullmatch(source)
            ):
                continue

        # Strict Base85 validation.

        if name == "Base85":

            if (
                len(source) < 8
                or any(char.isspace() for char in source)
                or source.isalpha()
                or not BASE85_PATTERN.fullmatch(source)
            ):
                continue

        try:

            if name in {"Base58", "Base85"}:
                decoded = decoder(source)
            else:
                decoded = decoder(data)

            if not isinstance(decoded, (bytes, bytearray)):
                continue

            decoded = bytes(decoded)

            if not is_plausible_payload(decoded):
                continue

            if len(source) >= 8:
                candidates[name] = decoded

        except (ValueError, TypeError, UnicodeError):
            continue

    return candidates


# ==========================================
# 5. DETECT POSSIBLE ENCODING
# ==========================================

def detect_possible_encoding(data):

    candidates = decode_possible_formats(data)

    result = []

    for format_name in candidates:

        result.append(
            "Possible " + format_name
        )

    if not result:

        result.append(
            "No supported encoding detected"
        )

    return result


# ==========================================
# 6. VALIDATE UTF-8
# ==========================================

def validate_utf8(raw_data):

    try:

        raw_data.decode("utf-8")

        return True

    except UnicodeDecodeError:

        return False


