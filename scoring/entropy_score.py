
import math


def calculate_entropy(data):

    if not isinstance(data, bytes):
        raise TypeError("Input must be bytes")

    if len(data) == 0:
        return 0.0

    frequency = {}

    for byte in data:

        if byte not in frequency:
            frequency[byte] = 1

        else:
            frequency[byte] += 1

    entropy = 0.0

    total_bytes = len(data)

    for count in frequency.values():

        probability = count / total_bytes

        entropy -= probability * math.log2(probability)

    return entropy


def calculate_entropy_change(parent_data, child_data):

    parent_entropy = calculate_entropy(parent_data)

    child_entropy = calculate_entropy(child_data)

    entropy_change = child_entropy - parent_entropy

    return entropy_change
