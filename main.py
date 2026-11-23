
# Import Input Intelligence
from input_intelligence.analyzer import analyze_input

# Import Candidate Generation
from CandidateGenerator.candidate_generation import CandidateGenerator


def main():

    print("=============================================")
    print("              CIPHERMIND")
    print("=============================================")

    # Get input from user
    data = input("\nEnter unknown data: ").strip()

    if not data:
        print("Error: Input cannot be empty.")
        return

    # STAGE 1: INPUT INTELLIGENCE
    print("\n=============================================")
    print("          1. INPUT INTELLIGENCE")
    print("=============================================")

    analyze_input(data)

    # STAGE 2: CANDIDATE GENERATION
    print("\n=============================================")
    print("          2. CANDIDATE GENERATION")
    print("=============================================")

    generator = CandidateGenerator(threshold=0.50)

    candidates = generator.generate(data)

    if not candidates:
        print("No suitable plugins found.")
        return

    # STAGE 3: PLUGIN EXECUTION
    print("\n=============================================")
    print("             3. PLUGIN RESULTS")
    print("=============================================")

    for candidate in candidates:

        plugin = candidate["plugin"]

        print("\nPlugin:", candidate["name"])
        print("Confidence:", candidate["confidence"])
        print("Cost:", candidate["cost"])

        # Perform decoding
        result = plugin.apply(data)

        print("Decoded bytes:", result)

        # Check readable text
        try:
            text = result.decode("utf-8")
            print("Readable text:", text)

        except UnicodeDecodeError:
            print("Result contains binary data.")

        # Explain operation
        print("Explanation:", plugin.explain())

    print("\n=============================================")
    print("         CIPHERMIND COMPLETED")
    print("=============================================")


if __name__ == "__main__":
    main()
