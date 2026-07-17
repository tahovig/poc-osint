import argparse
import re
import sys

_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="poc-osint")
    subparsers = parser.add_subparsers(dest="command", required=True)

    lookup = subparsers.add_parser("lookup", help="Recon a target domain")
    lookup.add_argument("target", help="Domain to recon, e.g. example.com")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "lookup":
        if not _DOMAIN_RE.match(args.target):
            print(f"error: '{args.target}' is not a valid domain", file=sys.stderr)
            return 1
        print(f"poc-osint: recon for {args.target} not yet implemented")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
