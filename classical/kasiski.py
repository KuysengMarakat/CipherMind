
# Clean ciphertext before analysis
def clean_text(text):

    if not isinstance(text, str):
        raise TypeError("Input must be text")

    result = ""

    for char in text:

        if char.isascii() and char.isalpha():

            result += char.upper()

    return result


# Find repeated sequences in ciphertext
def find_repeated_sequences(
    ciphertext,
    min_length=3,
    max_length=5
):

    letters = clean_text(ciphertext)

    repeated = {}

    # Try different sequence lengths
    for size in range(min_length, max_length + 1):

        positions = {}

        # Find every sequence and its position
        for position in range(len(letters) - size + 1):

            sequence = letters[position:position + size]

            if sequence not in positions:

                positions[sequence] = []

            positions[sequence].append(position)

        # Keep sequences that appear more than once
        for sequence, indexes in positions.items():

            if len(indexes) >= 2:

                repeated[sequence] = indexes

    return repeated


# Calculate distances between repeated sequences
def calculate_distances(repeated):

    distances = {}

    for sequence, positions in repeated.items():

        sequence_distances = []

        # Compare consecutive occurrences
        for index in range(len(positions) - 1):

            distance = (
                positions[index + 1] - positions[index]
            )

            sequence_distances.append(distance)

        distances[sequence] = sequence_distances

    return distances


# Find possible factors of a distance
def find_factors(number, max_factor=20):

    factors = []

    for factor in range(2, min(number, max_factor) + 1):

        if number % factor == 0:

            factors.append(factor)

    return factors


# Perform Kasiski Examination
def kasiski_examination(
    ciphertext,
    max_key_length=20,
    min_sequence_length=3,
    max_sequence_length=5
):

    if not isinstance(max_key_length, int) or max_key_length < 2:
        raise ValueError("Maximum key length must be at least 2")

    if (
        not isinstance(min_sequence_length, int)
        or not isinstance(max_sequence_length, int)
        or min_sequence_length < 2
        or max_sequence_length < min_sequence_length
    ):
        raise ValueError("Invalid sequence length range")

    # Step 1: Find repeated sequences
    repeated = find_repeated_sequences(
        ciphertext,
        min_sequence_length,
        max_sequence_length
    )

    # Step 2: Calculate distances
    distances = calculate_distances(repeated)

    # Count possible key lengths
    scores = {}

    # Step 3: Find factors of each distance
    for sequence, sequence_distances in distances.items():

        for distance in sequence_distances:

            factors = find_factors(
                distance,
                max_key_length
            )

            # Step 4: Give each factor one vote
            for factor in factors:

                if factor not in scores:

                    scores[factor] = 0

                scores[factor] += 1

    # Sort possible key lengths
    results = []

    for key_length, score in scores.items():

        results.append({

            "key_length": key_length,

            "score": score

        })

    results.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    return results
