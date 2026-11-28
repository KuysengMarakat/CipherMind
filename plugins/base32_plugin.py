from plugins.base import Plugin

from decoders.base32_decoder import decode_base32

from input_intelligence.format_detector import (
    decode_possible_formats
)


class Base32Plugin(Plugin):

    name = "Base32"

    cost = 1

    input_mode = "base32"

    # ======================================
    # 1. DETECT BASE32
    # ======================================

    def detect(self, state):

        if not isinstance(state, str):
            return 0.0

        if not state.strip():
            return 0.0

        # Internal whitespace makes automatic
        # Base32 classification ambiguous.

        if any(char.isspace() for char in state.strip()):
            return 0.0

        candidates = decode_possible_formats(state)

        if "Base32" not in candidates:
            return 0.0

        return 0.95

    # ======================================
    # 2. DECODE BASE32
    # ======================================

    def apply(self, state):

        return decode_base32(state)

    # ======================================
    # 3. EXPLAIN OPERATION
    # ======================================

    def explain(self, params=None):

        return "Decoded input using Base32."
