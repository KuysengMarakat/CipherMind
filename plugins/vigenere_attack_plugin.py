# Import the base plugin

from plugins.base import Plugin

# Import Vigenere analysis engine

from classical.vigenere_attack import analyze_vigenere

# Import text cleaning function

from classical.vigenere_analysis import get_letters


class VigenereAttackPlugin(Plugin):

    name = "Vigenere Automatic Analysis"

    # Computational cost

    cost = 10

    # Minimum alphabetic characters

    MIN_LETTERS = 12

    def __init__(self, max_key_length=12):

        self.max_key_length = max_key_length

        self.analysis = None

        self.best_candidate = None

    # ======================================
    # 1. CHECK INPUT SUITABILITY
    # ======================================

    def detect(self, state):

        if not isinstance(state, str):
            return 0.0

        if not state.strip():
            return 0.0

        # Extract English letters

        letters = get_letters(state)

        # Reject insufficient ciphertext

        if len(letters) < self.MIN_LETTERS:
            return 0.0

        # Suitable for automatic analysis

        return 0.5

    # ======================================
    # 2. PERFORM AUTOMATIC ANALYSIS
    # ======================================

    def apply(self, state):

        self.analysis = analyze_vigenere(
            state,
            self.max_key_length
        )

        candidates = self.analysis["candidates"]

        if not candidates:

            raise ValueError(
                "No Vigenere candidates found"
            )

        # Select the highest-ranked candidate

        self.best_candidate = candidates[0]

        return self.best_candidate["plaintext"].encode(
            "utf-8"
        )

    # ======================================
    # 3. EXPLAIN RESULT
    # ======================================

    def explain(self, params=None):

        if self.best_candidate is None:

            return (
                "Vigenere analysis has not been performed."
            )

        key = self.best_candidate["key"]

        key_length = self.best_candidate["key_length"]

        return (
            f"Automatic Vigenere analysis. "
            f"Estimated key: {key}. "
            f"Estimated key length: {key_length}."
        )
