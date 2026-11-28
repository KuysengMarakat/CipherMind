# Import the base plugin

from plugins.base import Plugin

# Import automatic substitution recovery

from classical.substitution_recovery import recover_substitution


class SubstitutionAttackPlugin(Plugin):

    name = "Automatic Substitution Analysis"

    # Computational cost

    cost = 10

    # Minimum alphabetic characters

    MIN_LETTERS = 30

    # Initialize the plugin.
    # Measured on test texts: 1 round recovered only ~40%; 30 rounds
    # with up to 5 restarts recovered ~99.6%. Restarts stop early as
    # soon as the text reads like English (see recover_substitution).

    def __init__(
        self,
        max_rounds=30,
        restarts=5,
        max_input_chars=1200
    ):

        self.max_rounds = max_rounds

        self.restarts = restarts

        self.max_input_chars = max_input_chars

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

        # Reject excessively long inputs

        if len(state) > self.max_input_chars:
            return 0.0

        # Count English letters

        letter_count = sum(
            1
            for char in state
            if char.isascii() and char.isalpha()
        )

        # Reject insufficient ciphertext

        if letter_count < self.MIN_LETTERS:
            return 0.0

        return 0.5

    # ======================================
    # 2. PERFORM AUTOMATIC RECOVERY
    # ======================================

    def apply(self, state):

        self.analysis = recover_substitution(
            state,
            max_rounds=self.max_rounds,
            restarts=self.restarts
        )

        self.best_candidate = self.analysis

        plaintext = self.best_candidate["plaintext"]

        return plaintext.encode("utf-8")

    # ======================================
    # 3. EXPLAIN RESULT
    # ======================================

    def explain(self, params=None):

        if self.best_candidate is None:

            return (
                "Substitution analysis has not been performed."
            )

        key = self.best_candidate["key"]

        score = self.best_candidate["quadgram_score"]

        return (
            f"Automatic substitution analysis completed. "
            f"Recovered key: {key}. "
            f"Quadgram score: {score}."
        )
