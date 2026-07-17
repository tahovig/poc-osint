# poc-osint — Automated Corporate Footprint & Subdomain Recon Tool

[![CI](https://github.com/tahovig/poc-osint/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/tahovig/poc-osint/actions/workflows/ci.yml)

A Python CLI that automates initial reconnaissance against a target domain: gathers publicly available subdomains, validates active hosts, and extracts open-source metadata (server/CMS fingerprints, missing security headers). Models the workflow a threat intel analyst or pentester uses to map an organization's external attack surface and spot forgotten or rogue shadow IT assets.

First in a series of portfolio projects supporting a pivot from software engineering to cybersecurity engineering.

## Status

Functional end-to-end: passive subdomain enumeration → concurrent liveness checks → header analysis, with structured output. See `CLAUDE.md` for full design notes and history.

## Authorized use only

This tool performs active checks (HTTP requests to discovered hosts) in addition to passive lookups. Only run it against domains you own or are explicitly authorized to test (e.g. an in-scope bug bounty/VDP target). Never point it at a target without permission. The tool takes a target as an explicit argument — no bundled or default target list.

## How it works

1. **Subdomain enumeration** — queries certificate transparency logs via [crt.sh](https://crt.sh) for the target domain. Passive, public data only. Retries with backoff since crt.sh is known to be flaky/rate-limited.
2. **Liveness check** — concurrently HEAD-checks each discovered subdomain on ports 80/443. Concurrency and per-request delay are both configurable, specifically to avoid hammering the target.
3. **Header analysis** — for live hosts, checks a fixed security-header checklist (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`) and flags a short list of known `Server`/`X-Powered-By` signatures (Apache, nginx, IIS, PHP, ASP.NET, Express, Cloudflare).

## Installation

```
cd code
python3 -m venv poc-osint-venv
poc-osint-venv/bin/pip install -e ".[dev]"
```

## Usage

```
poc-osint-venv/bin/poc-osint lookup example.com
```

Example output (real run against `example.com`):

```
HOST                 | PORT | LIVE | STATUS | SERVER     | MISSING HEADERS | FINGERPRINT
---------------------+------+------+--------+------------+-----------------+------------
dev.example.com      | 80   | no   | -      | -          | -               | -
dev.example.com      | 443  | no   | -      | -          | -               | -
example.com          | 80   | yes  | 200    | cloudflare | 5               | Cloudflare
example.com          | 443  | yes  | 200    | cloudflare | 5               | Cloudflare
m.example.com        | 80   | no   | -      | -          | -               | -
m.example.com        | 443  | no   | -      | -          | -               | -
products.example.com | 80   | no   | -      | -          | -               | -
products.example.com | 443  | no   | -      | -          | -               | -
support.example.com  | 80   | no   | -      | -          | -               | -
support.example.com  | 443  | no   | -      | -          | -               | -
www.example.com      | 80   | yes  | 200    | cloudflare | 5               | Cloudflare
www.example.com      | 443  | yes  | 200    | cloudflare | 5               | Cloudflare
```

Flags:

- `--max-concurrency N` — max simultaneous liveness checks (default: 10)
- `--delay SECONDS` — delay before each liveness check, to further throttle request rate (default: 0.0)
- `--json` — output JSON instead of the table above

## Testing

```
cd code
poc-osint-venv/bin/pytest                 # unit tests -- fast, no network, no Docker
poc-osint-venv/bin/pytest -m integration  # integration tests against local Docker fixtures (needs dockerd running)
```

## Repo structure

- `code/` — application source (`src/poc_osint/`), tests (`tests/unit/`, `tests/integration/`), Docker test fixtures (`tests/fixtures/`)
- `resources/` — supporting/reference materials (non-code)

## Tech stack

Python (`httpx`, asyncio), pytest + respx for testing, Docker for local test fixtures, GitHub Actions for CI. See `CLAUDE.md` for full design notes and rationale.
