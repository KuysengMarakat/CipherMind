
from input_intelligence.input_stats import calculate_length
from input_intelligence.input_stats import calculate_frequency
from input_intelligence.input_stats import calculate_entropy

from input_intelligence.format_detector import detect_character_set
from input_intelligence.format_detector import decode_possible_formats
from input_intelligence.format_detector import validate_utf8
from input_intelligence.format_detector import detect_file_signature


# ==========================================
# Analyse Unknown Input
# ==========================================

def analyze_input(data):

    report = {}

    # Basic Statistics

    report["length"] = calculate_length(data)

    report["frequency"] = calculate_frequency(data)

    report["entropy"] = calculate_entropy(data)


    # Character Information

    report["character_set"] = detect_character_set(data)


    # Decode Possible Formats

    candidates = decode_possible_formats(data)

    report["possible_encoding"] = []

    report["decoded_checks"] = {}


    for format_name in candidates:

        report["possible_encoding"].append(
            "Possible " + format_name
        )


        raw_data = candidates[format_name]


        # UTF-8 Validation

        utf8_valid = validate_utf8(raw_data)


        # File Signature Detection

        file_type = detect_file_signature(raw_data)


        report["decoded_checks"][format_name] = {

            "utf8_valid": utf8_valid,

            "file_signature": file_type

        }


    if len(report["possible_encoding"]) == 0:

        report["possible_encoding"].append(
            "No supported encoding detected"
        )


    return report
