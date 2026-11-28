# ==========================================
# CIPHERMIND CORE PIPELINE
# ==========================================

from CandidateGenerator.candidate_generation import CandidateGenerator

from core.models import CandidateResult

from scoring.scorer import analyze_candidate

from scoring.ranking import rank_candidates

from scoring.plaintext_detection import (
    is_likely_english_plaintext
)

from validation.input import validate_input


# ==========================================
# 1. REMOVE DUPLICATE RESULTS
# ==========================================

def remove_duplicates(results):

    unique_results = []

    seen_outputs = set()

    for result in results:

        if result.error:
            unique_results.append(result)
            continue

        decoded = result.decoded_data

        if not isinstance(decoded, bytes):
            unique_results.append(result)
            continue

        if decoded in seen_outputs:
            continue

        seen_outputs.add(decoded)

        unique_results.append(result)

    return unique_results


# ==========================================
# 2. VALIDATE EXECUTION CONFIGURATION
# ==========================================

def validate_execution_config(max_plugin_cost):

    if (
        isinstance(max_plugin_cost, bool)
        or not isinstance(max_plugin_cost, int)
        or max_plugin_cost < 0
    ):

        raise ValueError(
            "max_plugin_cost must be a non-negative integer"
        )


# ==========================================
# 3. CREATE ORIGINAL PLAINTEXT RESULT
# ==========================================

def create_original_plaintext_result(
    original_data,
    scores
):

    return CandidateResult(

        plugin_name="Original Plaintext",

        confidence=1.0,

        cost=0,

        decoded_data=original_data,

        scores=scores,

        explanation=(
            "Original input was identified as readable "
            "English plaintext. No decryption was required."
        )

    )


# ==========================================
# 4. MAIN CIPHERMIND PROCESSING FUNCTION
# ==========================================

def run_pipeline(
    data,
    threshold=0.50,
    max_plugin_cost=10
):

    # STEP 1: Validate input.

    validate_input(data)

    # STEP 2: Validate execution configuration.

    validate_execution_config(max_plugin_cost)

    # STEP 3: Convert original input to bytes.

    original_data = data.encode("utf-8")

    # STEP 4: Initialize candidate generator.

    generator = CandidateGenerator(
        threshold=threshold
    )

    # STEP 5: Detect input mode BEFORE plaintext detection.

    input_mode = generator.detect_input_mode(
        data,
        max_plugin_cost=max_plugin_cost
    )

    # STEP 6: Check original plaintext only when
    # the input has been classified as plaintext.

    if input_mode == "plaintext":

        original_scores = analyze_candidate(
            original_data,
            original_data
        )

        if is_likely_english_plaintext(
            original_data,
            original_scores
        ):

            original_result = create_original_plaintext_result(
                original_data,
                original_scores
            )

            return [original_result]

    # STEP 7: Generate suitable candidates.


    candidates = generator.generate(
        data,
        max_plugin_cost=max_plugin_cost
    )

    results = []

    # STEP 8: Execute selected plugins.

    for candidate in candidates:

        if candidate["cost"] > max_plugin_cost:
            continue

        plugin = candidate["plugin"]

        result = CandidateResult(

            plugin_name=plugin.name,

            confidence=candidate["confidence"],

            cost=candidate["cost"]

        )

        try:

            decoded = plugin.apply(data)

            if isinstance(decoded, str):
                decoded = decoded.encode("utf-8")

            if not isinstance(decoded, bytes):

                raise TypeError(
                    "Plugin must return bytes or text"
                )

            result.decoded_data = decoded

            # STEP 9: Analyze decoded candidate.

            result.scores = analyze_candidate(
                original_data,
                decoded
            )

            # STEP 10: Explain plugin operation.

            result.explanation = plugin.explain()

        except Exception as error:

            result.error = str(error)

        results.append(result)

    # STEP 11: Rank candidates.

    ranked_results = rank_candidates(results)

    # STEP 12: Remove duplicate outputs.

    unique_results = remove_duplicates(
        ranked_results
    )

    return unique_results
