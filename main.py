# ==========================================
# CIPHERMIND MAIN APPLICATION
# Clean interactive CLI
# ==========================================

import argparse
import re
import sys

from input_intelligence.analyzer import analyze_input
from core.pipeline import run_pipeline
from core.search import run_search
from modern.hash_identifier import identify_hash
from validation.status import get_status, STATUS_MEANING, UNSOLVED, VERIFIED
from reporting.solve_script import build_solve_script
from modern.rsa_solver import looks_like_rsa, solve_rsa
from modern.encryption_hint import modern_encryption_hint
from scoring.scorer import analyze_candidate
from modern.hash_cracking import (
    crack_raw_digest,
    audit_encoded_password_hash,
)


DEFAULT_TOP_RESULTS = 3

# Used when the user gives no --flag-pattern. It matches common CTF
# flag formats such as CTF{...}, flag{...}, picoCTF{...}, HTB{...}
# and THM{...}. Case is ignored. ROT13 of "CTF" is "PGS", which does
# not match, so the search does not stop on a still-encrypted layer.
DEFAULT_FLAG_PATTERN = r"(?i)\b(?:flag|ctf|[a-z]+ctf|htb|thm)\{[^{}]+\}"


# ==========================================
# DISPLAY HELPERS
# ==========================================

def print_banner():
    print()
    print("=" * 54)
    print("                    CIPHERMIND")
    print("             Intelligent Cryptanalysis Toolkit")
    print("=" * 54)


def get_plaintext(data):
    """Return decoded UTF-8 text, or None for non-text output."""
    if not isinstance(data, bytes):
        return None

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def get_quality(scores):
    """Return the normalized quality score as a percentage."""
    if not scores:
        return None

    value = scores.get("quality_score")
    if value is None:
        return None

    return float(value) * 100


def format_quality(scores):
    quality = get_quality(scores)
    if quality is None:
        return "N/A"
    return f"{quality:.2f}/100"


def display_input_details(data):
    """Show input-intelligence measurements in detailed mode only."""
    print("\nINPUT INTELLIGENCE")
    print("-" * 54)

    try:
        report = analyze_input(data)
    except (TypeError, ValueError) as error:
        print(f"Input analysis unavailable: {error}")
        return

    print(f"Length           : {report['length'][0]} characters")
    print(f"UTF-8 size       : {report['length'][1]} bytes")
    print(f"Character set    : {', '.join(report['character_set'])}")
    print(f"Shannon entropy  : {report['entropy']:.4f}")
    print(
        "Possible formats: "
        + ", ".join(report["possible_encoding"])
    )


def display_detailed_candidate(result, rank):
    """Show the full measurements for one candidate."""
    print("\n" + "-" * 54)
    print(f"CANDIDATE #{rank}")
    print("-" * 54)
    print(f"Algorithm         : {result.plugin_name}")
    print(
        f"Detection score   : {result.confidence:.2f} "
        "(suitability, not probability)"
    )
    print(f"Computational cost: {result.cost}")

    if result.error:
        print(f"Execution error   : {result.error}")
        return

    decoded = result.decoded_data
    plaintext = get_plaintext(decoded)

    if plaintext is not None:
        print(f"Output            : {plaintext}")
    else:
        size = len(decoded) if isinstance(decoded, bytes) else 0
        print(f"Output            : Binary data ({size} bytes)")

    if isinstance(decoded, bytes):
        preview = decoded[:120]
        suffix = " ..." if len(decoded) > 120 else ""
        print(f"Decoded bytes     : {preview!r}{suffix}")

    scores = result.scores or {}

    print("\nSCORING")
    print(f"Candidate quality: {format_quality(scores)}")

    printable = scores.get("printable_ratio")
    if printable is not None:
        print(f"Printable ratio  : {printable * 100:.2f}%")

    word_score = scores.get("word_score")
    if word_score is not None:
        print(f"English word match: {word_score * 100:.2f}%")

    quadgram = scores.get("quadgram_score")
    if quadgram is not None:
        print(f"Quadgram score   : {quadgram:.4f}")
    else:
        print("Quadgram score   : Not available")

    parent_entropy = scores.get("parent_entropy")
    if parent_entropy is not None:
        print(f"Original entropy : {parent_entropy:.4f}")

    candidate_entropy = scores.get("candidate_entropy")
    if candidate_entropy is not None:
        print(f"Output entropy   : {candidate_entropy:.4f}")

    entropy_change = scores.get("entropy_change")
    if entropy_change is not None:
        print(f"Entropy change   : {entropy_change:.4f}")

    if result.explanation:
        print(f"\nExplanation      : {result.explanation}")


# ==========================================
# NORMAL PIPELINE DISPLAY
# ==========================================

def display_simple_results(results, top_count, flag_pattern=None):
    """Show only the best result and a short alternatives list."""
    successful = [
        item for item in results
        if not item.error and isinstance(item.decoded_data, bytes)
    ]

    print("\nANALYSIS RESULTS")
    print("-" * 54)
    print(f"Candidates evaluated: {len(results)}")

    if not successful:
        print("\nNo candidate produced a usable output.")
        if results and results[0].error:
            print(f"First error: {results[0].error}")
        return

    best = successful[0]
    plaintext = get_plaintext(best.decoded_data)
    scores = best.scores or {}

    print("\nBEST MATCH")
    print(f"Algorithm : {best.plugin_name}")

    if plaintext is not None:
        print(f"Result    : {plaintext}")
    else:
        print(
            "Result    : Binary output "
            f"({len(best.decoded_data)} bytes)"
        )

    print(f"Quality   : {format_quality(scores)}")

    # A single step needs no chain re-run, so a flag match is enough.
    flag_matched = bool(
        flag_pattern
        and plaintext is not None
        and re.search(flag_pattern, plaintext)
    )
    status = get_status(best.decoded_data, scores, flag_matched)
    print(f"Status    : {status} ({STATUS_MEANING[status]})")

    if best.explanation:
        print(f"Reason    : {best.explanation}")

    alternatives = successful[1:top_count]

    if alternatives:
        print("\nOTHER CANDIDATES")
        for rank, candidate in enumerate(alternatives, start=2):
            print(
                f"{rank}. {candidate.plugin_name:<28} "
                f"{format_quality(candidate.scores)}"
            )

    print(
        "\nNote: The quality score is a heuristic ranking, "
        "not proof that a result is correct."
    )


def display_detailed_results(results, top_count):
    """Show full diagnostic information for the requested top results."""
    print("\nDETAILED ANALYSIS")
    print("-" * 54)
    print(f"Unique candidates: {len(results)}")

    if not results:
        print("No suitable candidates found.")
        return

    for rank, result in enumerate(results[:top_count], start=1):
        display_detailed_candidate(result, rank)


# ==========================================
# MULTI-LAYER SEARCH DISPLAY
# ==========================================

def format_search_chain(item):
    if not item.steps:
        return "No transformation steps"

    return " -> ".join(step.plugin for step in item.steps)


def display_search_results(search_report, args):
    items = search_report["results"]

    if args.details:
        print("\nSEARCH DIAGNOSTICS")
        print("-" * 54)
        print(f"States examined : {search_report['states_examined']}")
        print(f"Stopped because : {search_report['stopped_reason']}")
        print(
            f"Elapsed time    : "
            f"{search_report['elapsed_seconds']:.3f} seconds"
        )

    print("\nMULTI-LAYER SEARCH")
    print("-" * 54)

    if not items:
        print("No candidate chains were found within the search limits.")
        return

    print(f"Candidate chains: {len(items)}")

    best = items[0]
    print(f"STATUS          : {best.status}")
    print(f"Meaning         : {STATUS_MEANING[best.status]}")
    if best.status == UNSOLVED:
        print("The results below are only leads, not answers.")

    for rank, item in enumerate(items[:args.top], start=1):
        print(f"\n#{rank}  {format_search_chain(item)}")
        print(
            "Result  : "
            + (
                item.text
                if item.text is not None
                else "Binary output"
            )
        )
        print(f"Quality : {item.quality * 100:.2f}/100")

        if item.verified:
            status = "FLAG PATTERN MATCHED"
        elif args.flag_pattern:
            status = "No flag-pattern match"
        else:
            status = "No common flag format found"

        print(f"Flag check: {status}")
        print(f"Status    : {item.status}")

        if args.details:
            for step_number, step in enumerate(item.steps, start=1):
                print(
                    f"  {step_number}. {step.plugin}: "
                    f"{step.explanation}"
                )

    print(
        "\nNote: A high quality score is not cryptographic proof. "
        "A flag is verified only when a flag pattern matches."
    )
    if not args.flag_pattern:
        print(
            "Tip : Without --flag-pattern, common formats are checked: "
            "CTF{...}, flag{...}, picoCTF{...}, HTB{...}, THM{...}."
        )


# ==========================================
# AUTOMATIC HASH DETECTION
# ==========================================

def hex_decodes_to_text(data, minimum_ratio=0.90):
    """Return True if hex input decodes to mostly printable text."""
    try:
        decoded = bytes.fromhex(data.strip())
    except ValueError:
        return False

    if not decoded:
        return False

    printable = sum(
        32 <= byte <= 126 or byte in (9, 10, 13)
        for byte in decoded
    )
    return printable / len(decoded) >= minimum_ratio


def detect_and_display_hash(
    data,
    force_cryptanalysis=False,
    wordlist_path=None,
    max_candidates=50000,
    slow_hash_max_candidates=25,
):
    """Detect hash-like input and automatically attempt bounded local auditing.

    Raw digest formats are ambiguous, so this is heuristic identification.
    Unsalted raw digests are tested against the bundled English dictionary and
    an optional user wordlist. bcrypt/Argon2 receive a much smaller candidate
    budget because each verification is intentionally expensive.
    """
    try:
        matches = identify_hash(data)
    except (TypeError, ValueError):
        return False

    if not matches:
        return False

    password_hash_formats = {"bcrypt", "Argon2id", "Argon2i", "Argon2d"}
    is_password_hash = any(name in password_hash_formats for name in matches)

    # A raw hexadecimal digest can also be hex-encoded binary. Allow an
    # explicit override for users who know the input is data, not a digest.
    if force_cryptanalysis and not is_password_hash:
        print("\nHASH INTELLIGENCE")
        print("-" * 54)
        print("Possible format   : " + ", ".join(matches))
        print("Action            : Manual override; continuing general cryptanalysis.")
        return False

    # A real digest is random bytes. If the hex decodes to readable
    # text (for example "flag{...}" or a Base64 string), it is
    # hex-encoded data, so decode it instead of cracking it.
    if not is_password_hash and hex_decodes_to_text(data):
        print("\nHASH INTELLIGENCE")
        print("-" * 54)
        print("Possible format   : " + ", ".join(matches))
        print("Action            : Hex decodes to readable text; treating it as encoded data.")
        return False

    print("\nHASH INTELLIGENCE")
    print("-" * 54)
    print("Input type        : " + ("Encoded password hash" if is_password_hash else "Raw hexadecimal digest"))
    print("Possible algorithm: " + ", ".join(matches))
    print("Important         : Password hashes are one-way; candidates are tested, not decrypted.")
    print("Action            : Routed to Hash Intelligence for an automatic dictionary audit.")
    print("\nAUTOMATIC DICTIONARY AUDIT")
    print("-" * 54)

    try:
        if is_password_hash:
            result = audit_encoded_password_hash(
                data,
                wordlist_path=wordlist_path,
                max_candidates=slow_hash_max_candidates,
            )
        else:
            result = crack_raw_digest(
                data,
                wordlist_path=wordlist_path,
                max_candidates=max_candidates,
            )
    except (OSError, TypeError, ValueError) as error:
        print(f"Audit could not run: {error}")
        return True

    print(f"Candidates tested : {result['tested']}")
    print(f"Candidate source  : {result.get('source', 'unknown')}")

    if result.get("error"):
        print(f"Dependency issue  : {result['error']}")
        print("Install project dependencies with: python3 -m pip install -r requirements.txt")
        return True

    if result["matched"]:
        print("\nMATCH FOUND")
        print(f"Algorithm matched : {result['algorithm']}")
        print(f"Recovered value   : {result['candidate']}")
        print("Result            : Candidate verified against the supplied hash.")
    else:
        print("\nNO MATCH FOUND")
        print("The candidate was not present in the dictionaries tested.")
        if result.get("limit_reached"):
            print(f"Candidate limit   : {max_candidates if not is_password_hash else slow_hash_max_candidates}")
        if is_password_hash:
            print("Tip               : Supply a suitable local wordlist with --hash-wordlist.")
        else:
            print("Tip               : Try a larger CTF wordlist with --hash-wordlist.")
            print("Override           : Use --force-cryptanalysis if this is hexadecimal-encoded data, not a hash.")

    print("\nNote: Dictionary auditing only tests supplied candidates. A miss does not prove the hash is unrecoverable.")

    # Random bytes of hash length could also be encrypted data.
    if not result["matched"] and not is_password_hash:
        display_encryption_hint(data)
    return True


# ==========================================
# ONE ANALYSIS RUN
# ==========================================

def save_solve_script(original_text, best, path):
    """Write a standalone solve script for the best search result."""
    if best.status == UNSOLVED or not best.steps:
        print("\nSolve script: not written (no solved result to reproduce).")
        return

    try:
        script = build_solve_script(original_text, best.steps)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script)
    except (OSError, ValueError, KeyError) as error:
        print(f"\nSolve script: could not be written ({error}).")
        return

    print(f"\nSolve script saved: {path}")
    print(f"Run it with      : python3 {path}")


def display_rsa_results(data, args):
    """Run the RSA weakness checks and show what they found."""
    report = solve_rsa(data)

    print("\nRSA WEAKNESS CHECKS")
    print("-" * 54)
    for row in report:
        print(
            f"Key {row['key']}  {row['check']:<22} "
            f"{row['status']:<15} ({row['detail']})"
        )

    solved = [row for row in report if row["plaintext"] is not None]

    if not solved:
        print(f"\nSTATUS          : {UNSOLVED}")
        print("Meaning         : no known weakness found.")
        print("Correctly generated RSA cannot be broken without the private key.")
        return

    message = solved[0]["plaintext"]
    text = get_plaintext(message)
    print(f"\nRecovered by    : {solved[0]['check']}")
    print(f"Recovered       : {text if text is not None else message.hex()}")

    pattern = args.flag_pattern or DEFAULT_FLAG_PATTERN
    flag_matched = bool(text is not None and re.search(pattern, text))
    status = get_status(message, analyze_candidate(message, message), flag_matched)

    # The recovered message may itself be encoded (for example Base64),
    # so keep analysing it unless it is already a verified flag.
    if status != VERIFIED and text is not None and text.strip():
        print("Note            : not the final answer yet; analysing the recovered message...")
        analyze_once(text.strip(), args)
        return

    print(f"STATUS          : {status}")
    print(f"Meaning         : {STATUS_MEANING[status]}")


def display_encryption_hint(data):
    """If unsolved input looks like modern encryption, say so honestly."""
    hint = modern_encryption_hint(data)
    if not hint:
        return

    print("\nMODERN ENCRYPTION CHECK")
    print("-" * 54)
    for line in hint:
        print(f"- {line}")


def read_challenge_file(path, max_chars=100_000):
    """Read a challenge file as text. Return None (with a message) on error."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            data = handle.read(max_chars + 1)
    except OSError as error:
        print(f"\nCannot read challenge file: {error}")
        return None

    if len(data) > max_chars:
        print(f"\nChallenge file is too large (maximum {max_chars} characters).")
        return None

    if not data.strip():
        print("\nChallenge file is empty.")
        return None

    return data.strip()


def analyze_once(data, args):
    # RSA challenges (text containing n, e and c) go to the RSA checks.
    if looks_like_rsa(data):
        display_rsa_results(data, args)
        return

    # Hash detection is automatic in the normal interactive input path.
    # Structured bcrypt/Argon2 strings are routed to Hash Intelligence;
    # ambiguous raw hex digests are reported while other analysis continues.
    if detect_and_display_hash(
        data,
        force_cryptanalysis=getattr(args, "force_cryptanalysis", False),
        wordlist_path=getattr(args, "hash_wordlist", None),
        max_candidates=getattr(args, "hash_max_candidates", 50000),
        slow_hash_max_candidates=getattr(args, "slow_hash_max_candidates", 25),
    ):
        return

    if args.details:
        display_input_details(data)

    try:
        # Multi-layer search is the default. If it finds no chain
        # (for example, the input is already plain English), fall
        # back to the single-pass analysis below.
        if not args.single:
            report = run_search(
                data,
                max_depth=args.depth,
                beam_width=args.beam_width,
                max_states=args.max_states,
                time_budget=args.time_budget,
                max_plugin_cost=args.max_plugin_cost,
                flag_pattern=args.flag_pattern or DEFAULT_FLAG_PATTERN
            )
            if report["results"]:
                display_search_results(report, args)
                if args.save_script:
                    save_solve_script(data, report["results"][0], args.save_script)
                if report["results"][0].status == UNSOLVED:
                    display_encryption_hint(data)
                return

        results = run_pipeline(
            data,
            max_plugin_cost=args.max_plugin_cost
        )

    except (ValueError, TypeError, re.error) as error:
        print(f"\nAnalysis error: {error}")
        return

    if args.details:
        display_detailed_results(results, args.top)
    else:
        display_simple_results(
            results,
            args.top,
            flag_pattern=args.flag_pattern or DEFAULT_FLAG_PATTERN
        )
    display_encryption_hint(data)


# ==========================================
# COMMAND-LINE ARGUMENTS
# ==========================================

def build_parser():
    parser = argparse.ArgumentParser(
        description="CipherMind cryptanalysis toolkit",
        epilog=(
            "Additional command groups:\n"
            "  python3 main.py crypto --help   Modern encryption and key-agreement tools\n"
            "  python3 main.py hash --help     Digest and password-hash tools"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "file",
        nargs="?",
        help="Optional challenge file to analyse (otherwise you are asked to paste input)"
    )

    parser.add_argument(
        "--details",
        action="store_true",
        help="Show input statistics and detailed candidate scoring"
    )

    parser.add_argument(
        "--top",
        type=int,
        default=DEFAULT_TOP_RESULTS,
        help=f"Number of candidates to display (default: {DEFAULT_TOP_RESULTS})"
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Analyze one input and exit without asking to continue"
    )

    parser.add_argument(
        "--search",
        action="store_true",
        help="Multi-layer search (now the default; kept for older commands)"
    )

    parser.add_argument(
        "--save-script",
        metavar="FILE",
        help="Save a standalone Python solve script for the best result"
    )

    parser.add_argument(
        "--single",
        action="store_true",
        help="Use the simple single-pass analysis instead of multi-layer search"
    )

    parser.add_argument(
        "--depth",
        type=int,
        default=4,
        help="Maximum transformation depth for search"
    )

    parser.add_argument(
        "--beam-width",
        type=int,
        default=5,
        help="Maximum states retained per search level"
    )

    parser.add_argument(
        "--max-states",
        type=int,
        default=2000,
        help="Maximum plugin executions in search"
    )

    parser.add_argument(
        "--time-budget",
        type=float,
        default=10.0,
        help="Search time budget in seconds"
    )

    parser.add_argument(
        "--flag-pattern",
        help="Optional regular expression for CTF flag verification"
    )

    parser.add_argument(
        "--max-plugin-cost",
        type=int,
        default=10,
        help="Maximum plugin computational cost (default: 10)"
    )

    parser.add_argument(
        "--force-cryptanalysis",
        action="store_true",
        help="Skip automatic hash routing and analyze hash-like hex as possible encoded data"
    )

    parser.add_argument(
        "--hash-wordlist",
        help="Optional local wordlist for automatic hash auditing (also accepts CIPHERMIND_WORDLIST)"
    )

    parser.add_argument(
        "--hash-max-candidates",
        type=int,
        default=50000,
        help="Maximum candidates for fast raw digests (default: 50000)"
    )

    parser.add_argument(
        "--slow-hash-max-candidates",
        type=int,
        default=25,
        help="Maximum candidates for bcrypt/Argon2 (default: 25)"
    )

    return parser


# ==========================================
# MAIN INTERACTIVE APPLICATION
# ==========================================

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    # Keep modern cryptography and hash workflows explicit: unlike classical
    # cipher candidates, these operations need user-supplied keys or parameters.
    if argv and argv[0] in {"crypto", "hash"}:
        from modern.cli import run_modern_cli
        return run_modern_cli(argv)

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.max_plugin_cost < 0:
        parser.error("--max-plugin-cost must be non-negative")

    if args.top < 1:
        parser.error("--top must be at least 1")

    if args.depth < 1:
        parser.error("--depth must be at least 1")

    if args.beam_width < 1:
        parser.error("--beam-width must be at least 1")

    if args.max_states < 1:
        parser.error("--max-states must be at least 1")

    if args.time_budget <= 0:
        parser.error("--time-budget must be greater than 0")

    if args.hash_max_candidates < 1:
        parser.error("--hash-max-candidates must be at least 1")

    if args.slow_hash_max_candidates < 1:
        parser.error("--slow-hash-max-candidates must be at least 1")

    print_banner()

    # A challenge file was given: analyse it once and exit.
    if args.file:
        data = read_challenge_file(args.file)
        if data is None:
            return 1
        print(f"\nChallenge file: {args.file}")
        analyze_once(data, args)
        print()
        return 0

    while True:
        try:
            data = input("\nCiphertext / encoded input (or 'exit'): ").strip()
        except EOFError:
            print("\nInput stream closed. Exiting CipherMind.")
            break
        except KeyboardInterrupt:
            print("\n\nInterrupted. Exiting CipherMind.")
            break

        if data.lower() in {"exit", "quit"}:
            print("\nCipherMind closed.")
            break

        if not data:
            print("Please enter some input.")
            continue

        analyze_once(data, args)

        if args.once:
            break

        try:
            again = input("\nAnalyze another input? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nCipherMind closed.")
            break

        if again not in {"y", "yes"}:
            print("\nCipherMind closed.")
            break

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
