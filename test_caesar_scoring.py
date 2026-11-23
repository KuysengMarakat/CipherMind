
from plugins.caesar_plugin import create_caesar_plugins

from scoring.scorer import analyze_candidate


# Original encrypted input
original_input = "KHOOR ZRUOG"

# Convert original input into bytes
parent_data = original_input.encode("utf-8")


# Generate all Caesar plugins
plugins = create_caesar_plugins()

results = []


print("=" * 50)
print("       CIPHERMIND - CAESAR SCORING")
print("=" * 50)


# Evaluate every Caesar candidate
for plugin in plugins:

    # Check whether input is suitable
    confidence = plugin.detect(original_input)

    if confidence == 0:
        continue

    # Decrypt using this Caesar shift
    candidate_data = plugin.apply(original_input)

    # Run all scoring algorithms
    scores = analyze_candidate(
        parent_data,
        candidate_data
    )

    # Store the results
    results.append({

        "plugin": plugin.name,

        "candidate": candidate_data.decode("utf-8"),

        "printable": scores["printable_ratio"],

        "quadgram": scores["quadgram_score"],

        "entropy_change": scores["entropy_change"]

    })


# Rank using English quadgram score
ranked_results = sorted(
    results,
    key=lambda item: (
        item["quadgram"]
        if item["quadgram"] is not None
        else float("-inf")
    ),
    reverse=True
)


# Display ranked candidates
print("\n========== RANKING RESULTS ==========")

for rank, item in enumerate(ranked_results, start=1):

    print("\nRank:", rank)

    print("Plugin:", item["plugin"])

    print("Candidate:", item["candidate"])

    print(
        "Printable:",
        round(item["printable"] * 100, 2),
        "%"
    )

    print("Quadgram:", item["quadgram"])

    print(
        "Entropy Change:",
        round(item["entropy_change"], 4)
    )


print("\n========== SCORING COMPLETED ==========")
