"""Command-line interface for NutriLabel package capability inspector."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from nutrilabel import __version__
from nutrilabel.analyzer import NutritionAnalyzer, diff_reports
from nutrilabel.formatters import (
    format_diff_report,
    format_nutrition_label,
    format_rules_catalog,
)
from nutrilabel.rules import get_default_rules

KNOWN_SUBCOMMANDS = {"inspect", "diff", "rules"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nutrilabel",
        description="Generate a Nutrition Facts capability label for Python packages before installation.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"nutrilabel {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command")

    # nutrilabel inspect <target>
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Inspect a PyPI package, wheel/sdist archive, or local package directory.",
    )
    inspect_parser.add_argument(
        "target",
        help="PyPI package name, archive path (.whl/.tar.gz), or directory path.",
    )
    inspect_parser.add_argument(
        "-v",
        "--pkg-version",
        default=None,
        help="Specific package version to inspect when fetching from PyPI.",
    )
    inspect_parser.add_argument(
        "--explain",
        action="store_true",
        help="Show exact file, line number, and code snippet for each detected capability.",
    )
    inspect_parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text).",
    )

    # nutrilabel diff <pkg> <v1> <v2> OR nutrilabel diff <target1> <target2>
    diff_parser = subparsers.add_parser(
        "diff",
        help="Compare capabilities between two package versions or two package paths.",
    )
    diff_parser.add_argument(
        "targets",
        nargs="+",
        help="Either '<pkg_name> <old_ver> <new_ver>' or '<old_path> <new_path>'.",
    )
    diff_parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text).",
    )

    # nutrilabel rules
    subparsers.add_parser(
        "rules",
        help="List all built-in AST capability detection rules.",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)

    # Allow shorthand `nutrilabel <package-name> [--explain]` without `inspect`
    if (
        raw_args
        and not raw_args[0].startswith("-")
        and raw_args[0] not in KNOWN_SUBCOMMANDS
    ):
        raw_args = ["inspect"] + raw_args

    parser = build_parser()
    args = parser.parse_args(raw_args)

    if not args.command:
        parser.print_help()
        return 0

    analyzer = NutritionAnalyzer()

    if args.command == "rules":
        print(format_rules_catalog(get_default_rules()))
        return 0

    if args.command == "inspect":
        try:
            report = analyzer.analyze_target(
                args.target, version=args.pkg_version
            )
        except Exception as exc:
            print(f"Error inspecting '{args.target}': {exc}", file=sys.stderr)
            return 2

        print(
            format_nutrition_label(
                report,
                explain=args.explain,
                output_format=args.format,
            )
        )
        return 0

    if args.command == "diff":
        targets = args.targets
        try:
            if len(targets) == 2:
                old_report = analyzer.analyze_target(targets[0])
                new_report = analyzer.analyze_target(targets[1])
            elif len(targets) == 3:
                pkg_name, old_ver, new_ver = targets
                old_report = analyzer.analyze_target(pkg_name, version=old_ver)
                new_report = analyzer.analyze_target(pkg_name, version=new_ver)
            else:
                print(
                    "Error: 'diff' requires either 2 arguments (<old_path> <new_path>) "
                    "or 3 arguments (<pkg_name> <old_ver> <new_ver>).",
                    file=sys.stderr,
                )
                return 2
        except Exception as exc:
            print(f"Error computing diff: {exc}", file=sys.stderr)
            return 2

        diff_result = diff_reports(old_report, new_report)
        print(format_diff_report(diff_result, output_format=args.format))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
