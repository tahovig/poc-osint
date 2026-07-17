import argparse
import asyncio
import re
import sys

from .crtsh import CrtShError
from .output import to_json, to_table
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

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "lookup":
        return _run_lookup(args)

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

    print(to_json(reports) if args.json else to_table(reports))
    return 0


if __name__ == "__main__":
    sys.exit(main())
