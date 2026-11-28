
from plugins.registry import create_default_plugins

from input_intelligence.format_detector import decode_possible_formats

from scoring.plaintext_detection import (
    is_likely_english_plaintext
)


class CandidateGenerator:

    ENCODED_MODES = {
        "binary",
        "hex",
        "base32",
        "base64",
        "base58",
        "base85",
        "octal",
        "decimal",
        "url",
        "html",
        "morse"
    }

    def __init__(self, threshold=0.50, plugins=None):

        self.threshold = threshold

        if plugins is None:
            self.plugins = create_default_plugins()
        else:
            self.plugins = plugins

    # ======================================
    # 1. VALIDATE COMPUTATIONAL COST
    # ======================================

    @staticmethod
    def validate_max_plugin_cost(max_plugin_cost):

        if max_plugin_cost is None:
            return

        if (
            isinstance(max_plugin_cost, bool)
            or not isinstance(max_plugin_cost, int)
            or max_plugin_cost < 0
        ):
            raise ValueError(
                "max_plugin_cost must be a non-negative integer"
            )

    # ======================================
    # 2. CHECK PLUGIN COST
    # ======================================

    @staticmethod
    def is_cost_allowed(plugin, max_plugin_cost):

        plugin_cost = getattr(plugin, "cost", 1)

        if max_plugin_cost is None:
            return True

        return plugin_cost <= max_plugin_cost

    # ======================================
    # 3. IDENTIFY INPUT MODE
    # ======================================

    def detect_input_mode(
        self,
        state,
        max_plugin_cost=None
    ):

        if not isinstance(state, str):
            raise TypeError("Input must be text")

        self.validate_max_plugin_cost(max_plugin_cost)

        # STEP 1: Detect possible encodings.

        detected_formats = decode_possible_formats(state)

        # STEP 2: Check structured encoding formats first.

        preferred_modes = (
            "decimal",
            "octal",
            "morse",
            "url",
            "html"
        )

        for preferred_mode in preferred_modes:

            for plugin in self.plugins:

                plugin_mode = getattr(
                    plugin,
                    "input_mode",
                    "text"
                )

                if plugin_mode != preferred_mode:
                    continue

                if not self.is_cost_allowed(
                    plugin,
                    max_plugin_cost
                ):
                    continue

                if plugin.detect(state) >= self.threshold:
                    return preferred_mode

        # STEP 3: Binary detection.

        if "Binary" in detected_formats:
            return "binary"

        # STEP 4: Hexadecimal detection.

        if "Hexadecimal" in detected_formats:
            return "hex"

        # STEP 5: Base32 detection.

        if "Base32" in detected_formats:
            return "base32"

        # STEP 6: Base64 detection.

        if "Base64" in detected_formats:
            return "base64"

        # STEP 7: Original plaintext detection.
        # Check plaintext before ambiguous Base58/Base85.
        # This prevents ordinary English from being
        # incorrectly classified as an encoding.

        if is_likely_english_plaintext(
            state.encode("utf-8")
        ):
            return "plaintext"

        # STEP 8: Check other encoding formats.

        additional_modes = {
            "base58",
            "base85"
        }

        for plugin in self.plugins:

            mode = getattr(
                plugin,
                "input_mode",
                "text"
            )

            if mode not in additional_modes:
                continue

            if not self.is_cost_allowed(
                plugin,
                max_plugin_cost
            ):
                continue

            if plugin.detect(state) >= self.threshold:
                return mode

        # STEP 9: Ordinary text.

        return "text"

    # ======================================
    # 4. CHECK READABLE HEXADECIMAL
    # ======================================

    def is_readable_hex(self, state):

        try:
            decoded_bytes = bytes.fromhex(state)
            decoded_text = decoded_bytes.decode("utf-8")

        except (ValueError, UnicodeDecodeError):
            return False

        if not decoded_text:
            return False

        printable_count = sum(
            char.isprintable() or char in "\t\n\r"
            for char in decoded_text
        )

        printable_ratio = (
            printable_count / len(decoded_text)
        )

        return printable_ratio >= 0.90

    # ======================================
    # 5. GENERATE CANDIDATES
    # ======================================

    def generate(
        self,
        state,
        max_plugin_cost=None
    ):

        if not isinstance(state, str):
            raise TypeError("Input must be text")

        self.validate_max_plugin_cost(max_plugin_cost)

        # Identify input mode.

        input_mode = self.detect_input_mode(
            state,
            max_plugin_cost=max_plugin_cost
        )

        # Do not decrypt original readable plaintext.

        if input_mode == "plaintext":
            return []

        candidates = []

        # Check every registered plugin.

        for plugin in self.plugins:

            plugin_mode = getattr(
                plugin,
                "input_mode",
                "text"
            )

            plugin_cost = getattr(
                plugin,
                "cost",
                1
            )

            # STEP 1: Computational cost filtering.

            if (
                max_plugin_cost is not None
                and plugin_cost > max_plugin_cost
            ):
                continue

            # STEP 2: Input compatibility.

            if input_mode in self.ENCODED_MODES:

                if plugin_mode != input_mode:
                    continue

            else:

                if plugin_mode in self.ENCODED_MODES:
                    continue

            # STEP 3: Plugin suitability.

            confidence = plugin.detect(state)

            if confidence < self.threshold:
                continue

            # STEP 4: Register candidate.

            candidates.append({

                "name": plugin.name,

                "confidence": confidence,

                "cost": plugin_cost,

                "plugin": plugin

            })

        # STEP 5: Sort by computational cost.

        candidates.sort(
            key=lambda item: item["cost"]
        )

        return candidates
