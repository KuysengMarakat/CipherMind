
# Convert text into uppercase English letters
def get_letters(text):

    if not isinstance(text, str):
        raise TypeError("Input must be text")

    letters = ""

    for char in text:

        if char.isascii() and char.isalpha():

            letters += char.upper()

    return letters


# Calculate Index of Coincidence
def calculate_ioc(text):

    letters = get_letters(text)

    total = len(letters)

    # IOC requires at least two letters
    if total < 2:
        return 0.0

    # Count the frequency of each letter
    frequencies = {}

    for char in letters:

        if char not in frequencies:
            frequencies[char] = 0

        frequencies[char] += 1

    # Calculate the IOC numerator
    numerator = 0

    for frequency in frequencies.values():

        numerator += frequency * (frequency - 1)

    # Calculate the IOC denominator
    denominator = total * (total - 1)

    return numerator / denominator


# Calculate average IOC for a possible key length
def average_ioc_for_key_length(ciphertext, key_length):

    if key_length < 1:
        raise ValueError("Key length must be positive")

    letters = get_letters(ciphertext)

    # Divide ciphertext into groups
    groups = []

    for position in range(key_length):

        group = letters[position::key_length]

        if len(group) >= 2:

            groups.append(group)

    if not groups:
        return 0.0

    # Calculate IOC for every group
    scores = []

    for group in groups:

        score = calculate_ioc(group)

        scores.append(score)

    # Calculate average IOC
    return sum(scores) / len(scores)


# Estimate possible Vigenere key lengths
def estimate_key_lengths(ciphertext, max_key_length=12):

    if not isinstance(max_key_length, int) or max_key_length < 1:
        raise ValueError("Maximum key length must be a positive integer")

    letters = get_letters(ciphertext)

    if len(letters) < 4:
        return []

    # Avoid key lengths with too few letters per group
    max_key_length = min(
        max_key_length,
        len(letters) // 2
    )

    results = []

    # Try different possible key lengths
    for key_length in range(1, max_key_length + 1):

        score = average_ioc_for_key_length(
            letters,
            key_length
        )

        results.append({

            "key_length": key_length,

            "ioc": score

        })

    # Higher IOC scores appear first
    results.sort(
        key=lambda item: item["ioc"],
        reverse=True
    )

    return results
