# Project: poc-osint

## Goal

OSINT (Open Source Intelligence) proof-of-concept — first in a series of portfolio projects supporting a career pivot from software engineering to cybersecurity engineering. User previously held a cybersecurity analyst role and wants these POCs to demonstrate the engineering side, for a GitHub portfolio. 2-3 more POC projects (different focus areas) are planned after this one — open to suggestions on those once this project is further along.

## Repo

[https://github.com/tahovig/poc-osint.git](https://github.com/tahovig/poc-osint.git) — `main` + `develop` pushed.

## Branch strategy

- `main` — stable, deployable state  
- `develop` — active development (working branch)

## Current state

- Working directory is `~/dev-projects/tah-osint-poc` (WSL native filesystem) — this is the real, permanent working folder. The earlier Windows scaffold at `D:\tah-projects\poc-osint` is abandoned; nothing from it has been carried over.
- Decided: primary development happens in WSL Ubuntu via Claude Code CLI, not in Cowork mode.
- Git repo initialized. `main` has the initial commit (README, .gitignore, `code/`, `resources/`, CLAUDE.md); `develop` branched from it and is the active working branch. Both pushed to GitHub (`origin`), tracking branches set.
- Docker installed via `apt` (`docker.io` + `docker-compose` v1 — Ubuntu 20.04's repos, not the v2 `docker compose` plugin). This WSL distro has no systemd (`systemctl is-system-running` → offline), so `service docker start` doesn't work — daemon must be started manually with `sudo dockerd &` each fresh WSL session. Also had to clear a stale `credsStore: desktop.exe` entry from `~/.docker/config.json` (leftover Docker Desktop reference) before builds would run.

## Tech stack

- **Language**: Python — standard for OSINT tooling (WHOIS/DNS/scraping/API client libs), lets focus stay on OSINT logic + engineering practices (pytest, CI, Docker) rather than language plumbing.
- **Interface**: CLI tool (e.g. `poc-osint lookup <target>`) — simplest to build/test/containerize, standard shape for security tooling, easy to demo via terminal recording in README.

## Scope: Automated Corporate Footprint & Subdomain Recon Tool

Automates initial recon against a target domain — gathers publicly available subdomains, validates active hosts, extracts open-source metadata. Models the workflow a threat intel analyst / pentester uses to map an org's external attack surface and find forgotten/rogue shadow IT assets.

**Core functionality:**
- Query certificate transparency logs (crt.sh API) for subdomains — passive, public data only.
- Concurrent (asyncio) liveness checks against ports 80/443 — HTTP HEAD/connect checks, not a port scanner. Must have configurable max-concurrency + per-host delay (avoids DoS-like behavior; also a deliberate engineering/ethics showcase point).
- Parse HTTP response headers for server/CMS fingerprinting and missing security headers. Scope bounded to a fixed checklist (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) + `Server`/`X-Powered-By` string matching — not an open-ended Wappalyzer clone. Broader fingerprinting is documented future work, not built now.

**Engineering requirements (not optional, part of the portfolio value):**
- Separate fetch/network layer from parsing/logic layer so tests can mock HTTP calls (`responses`/`respx`) — CI must not depend on live network or a real target.
- Timeout + retry/backoff on crt.sh calls (known to be flaky/rate-limited).
- Structured output: JSON (for composability with other tooling) + human-readable table (for terminal use).
- README includes an explicit "Authorized use only" section; tool takes target as an explicit CLI arg, never a bundled/default target list.

**Test/demo targets** (decided after checking real authorization status — OWASP has no bug bounty/VDP covering owasp.org itself, ruled out; Tesla's Bugcrowd program is real but only partial safe harbor with a 24h disclosure obligation, not a great fit for repeated demo runs; NASA's VDP is legitimate but scoped to a specific listed target set that would need checking before use):
- **Automated tests / CI**: localhost + Docker fixtures, built at `code/tests/fixtures/` (`server.py` + `Dockerfile` + `docker-compose.yml`). One image, two configured services: `healthy-host` (`:8081`, full security-header checklist, generic banner) and `vulnerable-host` (`:8082`, no security headers, fake `Server`/`X-Powered-By`). Port `8083` is reserved unused as the "dead host" case (connection-refused path). Verified end-to-end (GET + HEAD, correct headers per host, dead port refuses connections) — zero legal ambiguity, deterministic.
- **Smoke test**: `example.com` (IANA-run, stable, exists for exactly this purpose).
- Real-target demo (NASA VDP in-scope list, or a domain the user owns) deferred until later — not needed to start building.

## Package skeleton

Src-layout Python package at `code/`:
- `pyproject.toml` — setuptools build, console script entry point `poc-osint = poc_osint.cli:main`. Runtime dep: `httpx`. Dev deps (`.[dev]`): `pytest`, `pytest-asyncio`, `respx`.
- `src/poc_osint/cli.py` — argparse-based CLI, subcommand-structured (`poc-osint lookup <target>`). Only real functionality so far: domain-format validation; recon logic itself is not yet wired in (prints a placeholder message) — liveness checker and header parser modules don't exist yet, will be added when actually built rather than stubbed in advance.
- `src/poc_osint/crtsh.py` — crt.sh client, implemented. `fetch_crtsh_json()` (network layer: GET with timeout + exponential-backoff retry, `CrtShError` after 3 failed attempts) is separate from `extract_subdomains()` (pure parsing: dedupes, lowercases, strips `*.` wildcard prefixes, filters to the queried domain + its subdomains). `get_subdomains()` wires both together. Not yet called from `cli.py` — that wiring happens once liveness/header modules exist too.
- `tests/unit/test_cli.py`, `tests/unit/test_crtsh.py` — 8/8 passing. crt.sh tests use `respx` to mock httpx (parsing edge cases, retry-then-succeed, retry-exhaustion) — no live network in CI.
- `tests/fixtures/` — Docker fixtures (see above).
- Dev venv: `code/poc-osint-venv/` (named for the project rather than generic `.venv`, gitignored). Setup: `python3 -m venv poc-osint-venv && poc-osint-venv/bin/pip install -e ".[dev]"`.
- Verified end-to-end: `poc-osint-venv/bin/poc-osint lookup example.com` (exit 0), invalid domain (exit 1, stderr message), `pytest` — 8/8 passing. One-time manual live check of `get_subdomains()` against real crt.sh hit a genuine crt.sh outage (502, confirmed independently via `curl` — not a client bug); retry once crt.sh is back up to confirm real-world parsing.

## Open decisions / immediate next steps

1. Implement crt.sh client (subdomain enumeration, passive).
2. Implement async liveness checker (concurrent HEAD/connect checks, configurable concurrency + delay).
3. Implement header parser (security-header checklist + server/CMS fingerprint matching).
4. Wire the above into `lookup`, add structured JSON + table output.
5. Integration tests against the Docker fixtures (`tests/integration/`, not yet created).

## Working preferences

- User prefers concise, direct communication — minimal explanation, no unnecessary verbosity.  
- User is comfortable with CLI workflows.

