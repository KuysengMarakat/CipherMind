"""Command-line entry point for CipherMind."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from core.pipeline import analyze_caesar
from reporting.render import render_json, render_markdown
from validation.input import InputValidationError, read_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cipher-mind",
        description="Explore classical Caesar ciphers and basic text statistics.",
    )
    parser.add_argument("input", type=Path, help="UTF-8 text file to analyze")
    parser.add_argument("--format", choices=("text", "json"), default="text", dest="output_format")
    parser.add_argument("--top", type=int, default=5, metavar="N", help="number of candidates (1–26; default: 5)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        text = read_text(args.input)
        result = analyze_caesar(text, top_n=args.top)
    except (InputValidationError, OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    print(render_json(result) if args.output_format == "json" else render_markdown(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
