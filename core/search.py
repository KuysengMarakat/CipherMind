
"""A small, bounded best-first beam-search engine for multi-layer CTF inputs."""

from dataclasses import dataclass, field
import hashlib
import re
import time

from CandidateGenerator.candidate_generation import CandidateGenerator
from scoring.scorer import analyze_candidate

from scoring.plaintext_detection import is_likely_english_plaintext
from validation.input import validate_input

from validation.status import get_status, UNSOLVED


# ==========================================
# 1. DATA STRUCTURES
# ==========================================

@dataclass
class SearchStep:
    plugin: str
    explanation: str
    confidence: float
    # The plugin itself, kept so the chain can be re-run for verification.
    plugin_object: object = field(default=None, repr=False, compare=False)
    # Key, shift or other values used in this step (for solve scripts).
    params: dict = field(default_factory=dict)


@dataclass
class SearchCandidate:
    data: bytes
    text: str | None
    scores: dict
    steps: list = field(default_factory=list)
    verified: bool = False
    status: str = UNSOLVED

    @property
    def quality(self):
        return self.scores.get("quality_score", 0.0)


@dataclass
class SearchNode:
    data: bytes
    steps: list
    scores: dict
    path_cost: int = 0


# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================

def _digest(data):
    """Create a unique fingerprint for decoded data."""
    return hashlib.sha256(data).digest()


def _rank_values(scores):
    """Return candidate quality measurements."""

    quadgram = scores.get("quadgram_score")

    if quadgram is None:
        quadgram = float("-inf")

    return (
        scores.get("quality_score", 0.0),
        quadgram,
        scores.get("printable_ratio", 0.0),
    )


def _result_order(item):
    """
    Sort key for final results.

    A result that matched the flag pattern is proven correct,
    so it always comes first. Other results follow by quality.
    """
    return (item.verified,) + _rank_values(item.scores)


def _plugin_params(plugin):
    """
    Copy the key or shift a plugin has just used.

    Attack plugins are reused for many inputs, so the values must be
    copied right after apply(), before another input replaces them.
    """
    params = {}

    for name in ("shift", "a", "b"):
        if hasattr(plugin, name):
            params[name] = getattr(plugin, name)

    best = getattr(plugin, "best_candidate", None)

    if isinstance(best, dict):
        if "key_hex" in best:
            params["key_hex"] = best["key_hex"]
        elif "key" in best:
            params["key"] = best["key"]

    return params


def _rerun_chain(original_text, steps):
    """
    Apply every step again, starting from the original input.

    Returns the final output bytes, or None if the chain cannot be
    repeated (for example, a middle step produced non-text bytes).
    """
    current_text = original_text
    output = None

    for step in steps:
        if current_text is None or step.plugin_object is None:
            return None

        output = step.plugin_object.apply(current_text)

        if isinstance(output, str):
            output = output.encode("utf-8")

        try:
            current_text = output.decode("utf-8")
        except UnicodeDecodeError:
            current_text = None

    return output


def _label_results(results, original_text):
    """Give every result a status label (see validation/status.py)."""
    for item in results:
        reproduced = True

        # Only flag matches can become VERIFIED, so only they are re-run.
        if item.verified:
            try:
                reproduced = _rerun_chain(original_text, item.steps) == item.data
            except Exception:
                reproduced = False

        item.status = get_status(
            item.data, item.scores, item.verified, reproduced
        )


def _node_priority(node):
    """
    Prioritize paths with lower computational cost.

    If two paths have the same cost, prefer
    the candidate with better text quality.
    """

    quality, quadgram, printable = _rank_values(
        node.scores
    )

    return (
        node.path_cost,
        -quality,
        -quadgram,
        -printable,
    )


# ==========================================
# 3. MAIN SEARCH FUNCTION
# ==========================================

def run_search(
    data,
    max_depth=3,
    beam_width=5,
    max_states=100,
    time_budget=5.0,
    max_plugin_cost=10,
    flag_pattern=None,
):
    """
    Search for readable plaintext through
    multiple decoding and decryption layers.

    Uses bounded best-first beam search.
    """

    # --------------------------------------
    # Validate input
    # --------------------------------------

    validate_input(data, max_length=10_000)

    if not isinstance(max_depth, int) or max_depth < 1:
        raise ValueError("max_depth must be at least 1")

    if not isinstance(beam_width, int) or beam_width < 1:
        raise ValueError("beam_width must be at least 1")

    if not isinstance(max_states, int) or max_states < 1:
        raise ValueError("max_states must be at least 1")

    if time_budget <= 0:
        raise ValueError("time_budget must be positive")

    pattern = re.compile(flag_pattern) if flag_pattern else None

    # --------------------------------------
    # Initialize search
    # --------------------------------------

    started = time.monotonic()

    generator = CandidateGenerator()

    initial_data = data.encode("utf-8")

    initial_scores = analyze_candidate(
        initial_data,
        initial_data
    )

    initial_node = SearchNode(
        data=initial_data,
        steps=[],
        scores=initial_scores,
        path_cost=0
    )

    # Nodes waiting to be explored
    frontier = [initial_node]

    # Prevent duplicate decoded outputs
    seen = {_digest(initial_data)}

    # Store successful transformations
    results = []

    states_examined = 0
    depth_reached = 0

    stopped_reason = "maximum depth reached"

    # Becomes True once any result clearly reads as English.
    found_english = False

    # ======================================
    # 4. BEST-FIRST SEARCH
    # ======================================

    while frontier:

        # Check state limit
        if states_examined >= max_states:

            stopped_reason = "maximum state count reached"
            break

        # Check time limit
        if time.monotonic() - started >= time_budget:

            stopped_reason = "time budget reached"
            break

        # Sort by path cost and candidate quality
        frontier.sort(key=_node_priority)

        # Explore the most promising node first
        node = frontier.pop(0)

        current_depth = len(node.steps)

        depth_reached = max(
            depth_reached,
            current_depth
        )

        # Do not exceed maximum depth
        if current_depth >= max_depth:
            continue

        # ----------------------------------
        # Convert bytes into text
        # ----------------------------------

        try:

            state_text = node.data.decode("utf-8")

        except UnicodeDecodeError:

            continue

        # Generate possible transformations
        candidates = generator.generate(state_text)

        # ==================================
        # 5. TRY AVAILABLE PLUGINS
        # ==================================

        for candidate in candidates:

            # Ignore expensive plugins
            if candidate["cost"] > max_plugin_cost:
                continue

            # Check state limit
            if states_examined >= max_states:

                stopped_reason = "maximum state count reached"
                break

            # Check time limit
            if time.monotonic() - started >= time_budget:

                stopped_reason = "time budget reached"
                break

            plugin = candidate["plugin"]

            states_examined += 1

            try:

                # Execute transformation
                decoded = plugin.apply(state_text)

                # Convert text into bytes
                if isinstance(decoded, str):

                    decoded = decoded.encode("utf-8")

                if not isinstance(decoded, bytes) or not decoded:
                    continue

                # ----------------------------------
                # Remove duplicate outputs
                # ----------------------------------

                fingerprint = _digest(decoded)

                if fingerprint in seen:
                    continue

                seen.add(fingerprint)

                # ----------------------------------
                # Score the candidate
                # ----------------------------------

                scores = analyze_candidate(
                    node.data,
                    decoded
                )

                step = SearchStep(
                    plugin=plugin.name,
                    explanation=plugin.explain(),
                    confidence=candidate["confidence"],
                    plugin_object=plugin,
                    params=_plugin_params(plugin)
                )

                steps = node.steps + [step]

                # ----------------------------------
                # Convert output into readable text
                # ----------------------------------

                try:

                    decoded_text = decoded.decode("utf-8")

                except UnicodeDecodeError:

                    decoded_text = None

                # ----------------------------------
                # Check flag pattern
                # ----------------------------------

                verified = bool(
                    pattern
                    and decoded_text is not None
                    and pattern.search(decoded_text)
                )

                # ----------------------------------
                # Save result
                # ----------------------------------

                result = SearchCandidate(
                    data=decoded,
                    text=decoded_text,
                    scores=scores,
                    steps=steps,
                    verified=verified
                )

                results.append(result)

                if is_likely_english_plaintext(decoded, scores):
                    found_english = True

                new_depth = current_depth + 1

                depth_reached = max(
                    depth_reached,
                    new_depth
                )

                # ----------------------------------
                # Stop when flag is found
                # ----------------------------------

                if verified:

                    stopped_reason = "flag pattern matched"

                    _label_results(results, data)

                    return {
                        "results": sorted(
                            results,
                            key=_result_order,
                            reverse=True
                        ),
                        "states_examined": states_examined,
                        "depth_reached": depth_reached,
                        "stopped_reason": stopped_reason,
                        "elapsed_seconds": (
                            time.monotonic() - started
                        )
                    }

                # ----------------------------------
                # Add next search node
                # ----------------------------------

                if new_depth < max_depth:

                    next_node = SearchNode(
                        data=decoded,
                        steps=steps,
                        scores=scores,
                        path_cost=(
                            node.path_cost + candidate["cost"]
                        )
                    )

                    frontier.append(next_node)

                    # Keep only the best beam candidates
                    frontier.sort(key=_node_priority)

                    frontier = frontier[:beam_width]

            except Exception:

                # One failed plugin must not stop
                # the remaining search operations.
                continue

        # Early stopping: a convincing English answer was found while
        # expanding this state. Every option for this state was still
        # tried, so the best one is among the results.
        if found_english:
            stopped_reason = "readable English found"
            break

        # Stop if resource limits were reached
        if states_examined >= max_states:

            stopped_reason = "maximum state count reached"
            break

        if time.monotonic() - started >= time_budget:

            stopped_reason = "time budget reached"
            break

    # ======================================
    # 6. RETURN SEARCH RESULTS
    # ======================================

    if not frontier and depth_reached < max_depth:
        if stopped_reason == "maximum depth reached":
            stopped_reason = "no further candidates"

    _label_results(results, data)

    return {

        "results": sorted(
            results,
            key=_result_order,
            reverse=True
        ),

        "states_examined": states_examined,

        "depth_reached": depth_reached,

        "stopped_reason": stopped_reason,

        "elapsed_seconds": time.monotonic() - started

    }

