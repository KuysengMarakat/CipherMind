"""
Build a standalone Python solve script from a search chain.

The script uses only the Python standard library. It repeats every
step CipherMind found, so anyone can check the answer without
trusting CipherMind (proposal Module G).
"""

# Small helper functions that a script may need. Only the helpers
# used by the chain are copied into the script.
HELPERS = {
    "caesar": '''
def caesar(text, shift):
    out = ""
    for ch in text:
        if "A" <= ch <= "Z":
            out += chr((ord(ch) - 65 - shift) % 26 + 65)
        elif "a" <= ch <= "z":
            out += chr((ord(ch) - 97 - shift) % 26 + 97)
        else:
            out += ch
    return out
''',
    "atbash": '''
def atbash(text):
    out = ""
    for ch in text:
        if "A" <= ch <= "Z":
            out += chr(90 - (ord(ch) - 65))
        elif "a" <= ch <= "z":
            out += chr(122 - (ord(ch) - 97))
        else:
            out += ch
    return out
''',
    "affine": '''
def affine(text, a, b):
    a_inverse = pow(a, -1, 26)
    out = ""
    for ch in text:
        if "A" <= ch <= "Z":
            out += chr(a_inverse * (ord(ch) - 65 - b) % 26 + 65)
        elif "a" <= ch <= "z":
            out += chr(a_inverse * (ord(ch) - 97 - b) % 26 + 97)
        else:
            out += ch
    return out
''',
    "vigenere": '''
def vigenere(text, key):
    out, i = "", 0
    for ch in text:
        if ch.isascii() and ch.isalpha():
            shift = ord(key[i % len(key)]) - 65
            base = 65 if ch.isupper() else 97
            out += chr((ord(ch) - base - shift) % 26 + base)
            i += 1
        else:
            out += ch
    return out
''',
    "substitution": '''
def substitution(text, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    out = ""
    for ch in text:
        if ch.isascii() and ch.isalpha():
            plain = alphabet[key.index(ch.upper())]
            out += plain if ch.isupper() else plain.lower()
        else:
            out += ch
    return out
''',
    "xor": '''
def xor_hex(text, key_hex):
    data, key = bytes.fromhex(text), bytes.fromhex(key_hex)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data)).decode("utf-8", "replace")
''',
    "base58": '''
def base58(text):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = 0
    for ch in text.strip():
        number = number * 58 + alphabet.index(ch)
    data = number.to_bytes((number.bit_length() + 7) // 8, "big")
    zeros = len(text.strip()) - len(text.strip().lstrip("1"))
    return (b"\\x00" * zeros + data).decode("utf-8")
''',
    "morse": '''
MORSE = {".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
         "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
         "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
         "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
         "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
         "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
         "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
         "-.-.--": "!"}

def morse(text):
    words = text.strip().split(" /") if " /" in text else text.strip().split("/")
    return " ".join("".join(MORSE[c] for c in w.split()) for w in words if w.split())
''',
}


def step_code(step):
    """
    Return (line of Python, helper name or None) for one step.

    The line turns the variable `text` into the next value of `text`.
    """
    name = step.plugin
    p = step.params

    simple = {
        "Hexadecimal": 'bytes.fromhex("".join(text.split())).decode("utf-8")',
        "Base64": 'base64.b64decode("".join(text.split()) + "=" * (-len("".join(text.split())) % 4)).decode("utf-8")',
        "Base32": 'base64.b32decode("".join(text.split()).upper() + "=" * (-len("".join(text.split())) % 8)).decode("utf-8")',
        "Base85": 'base64.b85decode("".join(text.split())).decode("utf-8")',
        "Binary": 'bytes(int("".join(text.split())[i:i + 8], 2) for i in range(0, len("".join(text.split())), 8)).decode("utf-8")',
        "Octal": 'bytes(int(x, 8) for x in text.replace(",", " ").split()).decode("utf-8")',
        "Decimal": 'bytes(int(x) for x in text.replace(",", " ").split()).decode("utf-8")',
        "URL encoding": 'urllib.parse.unquote(text.replace("+", " "))',
        "HTML entities": "html.unescape(text)",
    }

    if name in simple:
        return simple[name], None
    if name == "Base58":
        return "base58(text)", "base58"
    if name == "Morse code":
        return "morse(text)", "morse"
    if name == "Atbash":
        return "atbash(text)", "atbash"
    if name.startswith("Caesar"):
        return f"caesar(text, {p['shift']})", "caesar"
    if name.startswith("Affine"):
        return f"affine(text, {p['a']}, {p['b']})", "affine"
    if name.startswith("Vigenere"):
        return f"vigenere(text, {p['key']!r})", "vigenere"
    if "XOR" in name:
        return f"xor_hex(text, {p['key_hex']!r})", "xor"
    if "Substitution" in name:
        return f"substitution(text, {p['key']!r})", "substitution"

    raise ValueError(f"No solve-script template for step: {name}")


def build_solve_script(original_text, steps):
    """Return the source code of a standalone solve script."""
    lines = []
    helpers = []

    for number, step in enumerate(steps, start=1):
        code, helper = step_code(step)
        lines.append(f"# Step {number}: {step.plugin}")
        lines.append(f"text = {code}")
        if helper and helper not in helpers:
            helpers.append(helper)

    script = [
        '"""Solve script generated by CipherMind. Standard library only."""',
        "",
        "import base64",
        "import html",
        "import urllib.parse",
    ]
    for helper in helpers:
        script.append(HELPERS[helper].rstrip())
        script.append("")

    script.append("")
    script.append(f"text = {original_text!r}")
    script.extend(lines)
    script.append("print(text)")

    return "\n".join(script) + "\n"
