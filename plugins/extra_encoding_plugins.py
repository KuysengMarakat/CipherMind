import re

from plugins.base import Plugin

from decoders.extra_decoders import (
    decode_base85,
    decode_octal,
    decode_decimal,
    decode_url,
    decode_html_entities,
    decode_morse,
    decode_base58_text,
)


BASE85_PATTERN = re.compile(
    r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+"
)

BASE58_PATTERN = re.compile(
    r"[1-9A-HJ-NP-Za-km-z]+"
)


class DecoderPlugin(Plugin):

    input_mode = "encoded_extra"

    cost = 1

    decoder = staticmethod(lambda value: value)

    label = "Encoding"

    # ======================================
    # 1. VALIDATE INPUT FORMAT
    # ======================================

    def valid_input_shape(self, state):

        candidate = state.strip()

        if len(candidate) < 8:
            return False

        # Base58 validation.

        if self.input_mode == "base58":

            if any(char.isspace() for char in candidate):
                return False

            if not BASE58_PATTERN.fullmatch(candidate):
                return False

        # Base85 validation.

        if self.input_mode == "base85":

            if any(char.isspace() for char in candidate):
                return False

            # Ordinary alphabetic words are ambiguous.
            if candidate.isalpha():
                return False

            if not BASE85_PATTERN.fullmatch(candidate):
                return False

        return True

    # ======================================
    # 2. DETECT ENCODING
    # ======================================

    def detect(self, state):

        if not isinstance(state, str):
            return 0.0

        if not state.strip():
            return 0.0

        if not self.valid_input_shape(state):
            return 0.0

        try:

            candidate = state.strip()

            if self.input_mode in {"base58", "base85"}:
                decoded = self.decoder(candidate)
            else:
                decoded = self.decoder(state)

            if not isinstance(decoded, (bytes, bytearray)):
                return 0.0

            if not decoded:
                return 0.0

            printable_count = sum(
                byte in (9, 10, 13) or 32 <= byte <= 126
                for byte in decoded
            )

            printable_ratio = (
                printable_count / len(decoded)
            )

            if printable_ratio < 0.80:
                return 0.0

            return 0.95

        except (ValueError, TypeError, UnicodeError):
            return 0.0

    # ======================================
    # 3. DECODE INPUT
    # ======================================

    def apply(self, state):

        if self.input_mode in {"base58", "base85"}:
            state = state.strip()

        return self.decoder(state)

    # ======================================
    # 4. EXPLAIN OPERATION
    # ======================================

    def explain(self, params=None):

        return f"Decoded input using {self.label}."


class Base58Plugin(DecoderPlugin):

    input_mode = "base58"

    name = label = "Base58"

    decoder = staticmethod(decode_base58_text)


class Base85Plugin(DecoderPlugin):

    input_mode = "base85"

    name = label = "Base85"

    decoder = staticmethod(decode_base85)


class OctalPlugin(DecoderPlugin):

    input_mode = "octal"

    name = label = "Octal"

    decoder = staticmethod(decode_octal)


class DecimalPlugin(DecoderPlugin):

    input_mode = "decimal"

    name = label = "Decimal"

    decoder = staticmethod(decode_decimal)


class URLPlugin(DecoderPlugin):

    input_mode = "url"

    name = label = "URL encoding"

    decoder = staticmethod(decode_url)


class HTMLEntityPlugin(DecoderPlugin):

    input_mode = "html"

    name = label = "HTML entities"

    decoder = staticmethod(decode_html_entities)


class MorsePlugin(DecoderPlugin):

    input_mode = "morse"

    name = label = "Morse code"

    decoder = staticmethod(decode_morse)
