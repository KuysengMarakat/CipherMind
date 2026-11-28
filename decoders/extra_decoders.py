"""Small, standard-library decoders used by CipherMind."""

import base64
import html
import re
from urllib.parse import unquote_to_bytes

from decoders.base58_decoder import decode_base58


def decode_base85(text):
    if not isinstance(text, str):
        raise TypeError("Input must be text")
    cleaned = "".join(text.split())
    if not cleaned:
        raise ValueError("Input cannot be empty")
    try:
        return base64.b85decode(cleaned.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError("Invalid Base85 input") from error


def decode_octal(text):
    if not isinstance(text, str):
        raise TypeError("Input must be text")
    tokens = text.replace(",", " ").split()
    if not tokens or any(not re.fullmatch(r"[0-7]{1,3}", item) for item in tokens):
        raise ValueError("Expected octal byte values separated by spaces")
    values = [int(item, 8) for item in tokens]
    if any(value > 255 for value in values):
        raise ValueError("Octal values must represent bytes (0-377)")
    return bytes(values)


def decode_decimal(text):
    if not isinstance(text, str):
        raise TypeError("Input must be text")
    tokens = text.replace(",", " ").split()
    if not tokens or any(not item.isdecimal() for item in tokens):
        raise ValueError("Expected decimal byte values separated by spaces")
    values = [int(item, 10) for item in tokens]
    if any(value < 0 or value > 255 for value in values):
        raise ValueError("Decimal values must be between 0 and 255")
    return bytes(values)


def decode_url(text):
    if not isinstance(text, str):
        raise TypeError("Input must be text")
    if not text or not re.search(r"%[0-9a-fA-F]{2}", text):
        raise ValueError("No valid URL percent-encoding found")
    return unquote_to_bytes(text.replace("+", " "))


def decode_html_entities(text):
    if not isinstance(text, str):
        raise TypeError("Input must be text")
    if not text or not re.search(r"&(?:#\d+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]+);", text):
        raise ValueError("No HTML entity found")
    decoded = html.unescape(text)
    if decoded == text:
        raise ValueError("No recognized HTML entity found")
    return decoded.encode("utf-8")


MORSE_TO_TEXT = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9", ".-.-.-": ".",
    "--..--": ",", "..--..": "?", "-.-.--": "!"
}


def decode_morse(text):
    if not isinstance(text, str):
        raise TypeError("Input must be text")
    cleaned = text.strip()
    if not cleaned or any(char not in ".-/ " for char in cleaned):
        raise ValueError("Morse input may contain only dots, dashes, spaces and /")
    words = cleaned.split(" /") if " /" in cleaned else cleaned.split("/")
    decoded_words = []
    for word in words:
        letters = word.strip().split()
        if not letters:
            continue
        try:
            decoded_words.append("".join(MORSE_TO_TEXT[item] for item in letters))
        except KeyError as error:
            raise ValueError(f"Unknown Morse code: {error.args[0]}") from error
    if not decoded_words:
        raise ValueError("Morse input cannot be empty")
    return " ".join(decoded_words).encode("utf-8")


def decode_base58_text(text):
    return decode_base58(text)
