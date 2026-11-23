
import math


# Load English quadgram dataset

def load_quadgram_scores(file_path):

    quadgram_counts = {}

    total_count = 0

    # Open the dataset
    with open(file_path, "r", encoding="utf-8") as file:

        for line in file:

            parts = line.split()

            if len(parts) != 2:
                continue

            quadgram = parts[0].upper()

            count = int(parts[1])

            if len(quadgram) == 4 and quadgram.isalpha():

                quadgram_counts[quadgram] = count

                total_count += count


    # Convert counts into log probabilities

    quadgram_scores = {}

    for quadgram, count in quadgram_counts.items():

        probability = count / total_count

        quadgram_scores[quadgram] = math.log10(probability)


    # Score for unknown quadgrams

    floor_score = math.log10(0.01 / total_count)

    return quadgram_scores, floor_score



# Calculate English quadgram score

def calculate_quadgram_score(data, quadgram_scores, floor_score):

    # Check input type

    if not isinstance(data, bytes):

        raise TypeError("Input must be bytes")


    # Convert bytes into text

    try:

        text = data.decode("utf-8")

    except UnicodeDecodeError:

        return None


    # Keep English letters only

    text = "".join(

        char for char in text.upper()

        if "A" <= char <= "Z"

    )


    # Check minimum length

    if len(text) < 4:

        return None


    total_score = 0

    count = len(text) - 3


    # Examine every quadgram

    for i in range(count):

        quadgram = text[i:i + 4]

        score = quadgram_scores.get(quadgram, floor_score)

        total_score += score


    # Calculate average score

    average_score = total_score / count

    return average_score
