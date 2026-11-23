
def calculate_printable_ratio(data):

    # Check that input is bytes

    if not isinstance(data, bytes):

        raise TypeError("Input must be bytes")


    # Check empty input

    if len(data) == 0:

        return 0.0


    # Count printable bytes

    printable_count = 0

    for byte in data:

        if 32 <= byte <= 126:

            printable_count += 1


    # Calculate printable ratio

    ratio = printable_count / len(data)


    return ratio
