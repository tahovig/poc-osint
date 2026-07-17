import argparse
import asyncio
import json
import re
import sys

from .compare import compare_reports
from .crtsh import CrtShError
from .output import to_compare_json, to_compare_text, to_json, to_table
from .recon import run_recon

_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="poc-osint")
    subparsers = parser.add_subparsers(dest="command", required=True)

    lookup = subparsers.add_parser("lookup", help="Recon a target domain")
    lookup.add_argument("target", help="Domain to recon, e.g. example.com")
    lookup.add_argument(
        "--max-concurrency",
        type=int,
        default=10,
        help="Max simultaneous liveness checks (default: 10)",
    )
    lookup.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Seconds to wait before each liveness check, to avoid hammering the target (default: 0.0)",
    )
    lookup.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of a human-readable table",
    )
    lookup.add_argument(
        "--save",
        metavar="PATH",
        help="Also save the result as JSON to PATH, e.g. for later `compare`",
    )

    compare = subparsers.add_parser("compare", help="Diff two saved lookup results")
    compare.add_argument("old", help="Path to the earlier saved JSON result")
    compare.add_argument("new", help="Path to the later saved JSON result")
    compare.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of a human-readable diff",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "lookup":
        return _run_lookup(args)
    if args.command == "compare":
        return _run_compare(args)

    return 1


def _run_lookup(args: argparse.Namespace) -> int:
    if not _DOMAIN_RE.match(args.target):
        print(f"error: '{args.target}' is not a valid domain", file=sys.stderr)
        return 1

    try:
        reports = asyncio.run(
            run_recon(args.target, max_concurrency=args.max_concurrency, delay=args.delay)
        )
    except CrtShError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.save:
        try:
            with open(args.save, "w") as f:
                f.write(to_json(reports))
        except OSError as exc:
            print(f"error: could not save to '{args.save}': {exc}", file=sys.stderr)
            return 1

    print(to_json(reports) if args.json else to_table(reports))
    return 0


def _run_compare(args: argparse.Namespace) -> int:
    try:
        with open(args.old) as f:
            old_data = json.load(f)
        with open(args.new) as f:
            new_data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    result = compare_reports(old_data, new_data)
    print(to_compare_json(result) if args.json else to_compare_text(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
