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

**crt.sh reliability — evaluated alternatives, decided to keep current design.** Live testing during development hit genuine crt.sh HTTP-frontend flakiness repeatedly (alternating 200/502 responses seconds apart, independent of our client — confirmed via raw `curl`). Researched alternatives rather than assume:
- **Spyse** — dead since 2022 (reportedly war-related shutdown), confirmed via multiple sources including Crunchbase. Not usable regardless.
- **Google's CT Report endpoint** — unofficial/undocumented (`google.com/transparencyreport/api/v3/httpsreport/ct/certsearch`), used by some OSINT tools but no stability guarantee. Rejected as a foundation for a project meant to demonstrate engineering rigor.
- **crt.sh direct PostgreSQL access** (port 5432, `guest` user) — real, documented, used by tools like `quickcert` specifically because it bypasses crt.sh's flaky HTTP frontend while using the same authoritative data. Legitimate future-work item (new dependency `asyncpg`, new failure mode: port 5432 blocked by some networks) — not built now, since the current retry/backoff already handles the flakiness correctly (clean error + exit 1, never hangs/crashes), which is itself the demonstrated engineering behavior.

**Test/demo targets** (decided after checking real authorization status — OWASP has no bug bounty/VDP covering owasp.org itself, ruled out; Tesla's Bugcrowd program is real but only partial safe harbor with a 24h disclosure obligation, not a great fit for repeated demo runs; NASA's VDP is legitimate but scoped to a specific listed target set that would need checking before use):
- **Automated tests / CI**: localhost + Docker fixtures, built at `code/tests/fixtures/` (`server.py` + `Dockerfile` + `docker-compose.yml`). One image, two configured services: `healthy-host` (`:8081`, full security-header checklist, generic banner) and `vulnerable-host` (`:8082`, no security headers, fake `Server`/`X-Powered-By`). Port `8083` is reserved unused as the "dead host" case (connection-refused path). Verified end-to-end (GET + HEAD, correct headers per host, dead port refuses connections) — zero legal ambiguity, deterministic.
- **Smoke test**: `example.com` (IANA-run, stable, exists for exactly this purpose).
- Real-target demo (NASA VDP in-scope list, or a domain the user owns) deferred until later — not needed to start building.

## Package skeleton

Src-layout Python package at `code/`:
- `pyproject.toml` — setuptools build, console script entry point `poc-osint = poc_osint.cli:main`. Runtime dep: `httpx`. Dev deps (`.[dev]`): `pytest`, `pytest-asyncio`, `respx`.
- `src/poc_osint/cli.py` — argparse-based CLI, subcommand-structured. `lookup <target>` is fully wired now: domain validation → `run_recon()` → `to_table()`/`to_json()`. Flags: `--max-concurrency` (default 10), `--delay` (default 0.0), `--json`. `CrtShError`/`ValueError` from the recon pipeline are caught and become a clean stderr message + exit 1, not a traceback.
- `src/poc_osint/crtsh.py` — crt.sh client. `fetch_crtsh_json()` (network layer: GET with timeout + exponential-backoff retry, `CrtShError` after 3 failed attempts) is separate from `extract_subdomains()` (pure parsing: dedupes, lowercases, strips `*.` wildcard prefixes, filters to the queried domain + its subdomains). `get_subdomains()` wires both together.
- `src/poc_osint/liveness.py` — async liveness checker. `check_host_port()` (single HEAD request, never raises — failures become `HostResult(is_live=False, error=...)`) is separate from `check_hosts()` (concurrency orchestration: `asyncio.Semaphore`-bounded `max_concurrency`, per-request `delay` before each check). `get_live_hosts()` wires both together. Port→scheme mapping (80→http, 443→https, fallback http) lives in `check_hosts`; `check_host_port` itself takes an explicit scheme so fixture ports (8081/8082/8083) work too. Headers stored lowercased.
- `src/poc_osint/headers.py` — header parser. Pure/synchronous, no network. `find_missing_security_headers()` (fixed 5-header checklist, case-insensitive) + `fingerprint_server()` (Server/X-Powered-By string matching against a short fixed signature list) wired together by `analyze_headers()` into a `HeaderFindings` dataclass.
- `src/poc_osint/recon.py` — orchestration layer, new. `run_recon(domain, *, max_concurrency, delay)`: crt.sh → liveness → header analysis, returns `list[SubdomainReport]`. Skips liveness entirely if crt.sh finds zero subdomains (returns `[]`, not an error) rather than inventing a fallback target.
- `src/poc_osint/output.py` — formatting layer, new. `to_json()` (via `dataclasses.asdict`) and `to_table()` (dependency-free aligned-column rendering) both consume `list[SubdomainReport]`.
- `tests/unit/` — `test_cli.py`, `test_crtsh.py`, `test_liveness.py`, `test_headers.py`, `test_recon.py`, `test_output.py` — 33/33 passing. `test_recon.py`/updated `test_cli.py` monkeypatch `get_subdomains`/`get_live_hosts`/`run_recon` directly (no HTTP mocking needed at the orchestration layer) — no live network anywhere in the suite.
- `tests/integration/` — real Docker-fixture tests. `test_liveness_fixtures.py` + `test_headers_fixtures.py` — 6/6 passing against real containers. Excluded from the default `pytest` run (`addopts = "-m 'not integration'"`), run explicitly via `pytest -m integration`, requires `dockerd` running.
- `tests/fixtures/` — Docker fixtures (see above).
- Dev venv: `code/poc-osint-venv/` (named for the project rather than generic `.venv`, gitignored). Setup: `python3 -m venv poc-osint-venv && poc-osint-venv/bin/pip install -e ".[dev]"`.
- **Verified fully end-to-end against live data**: `poc-osint-venv/bin/poc-osint lookup example.com` — real crt.sh query found 6 subdomains, real liveness checks correctly separated live (`example.com`, `www.example.com`, both ports) from dead (`dev.`, `m.`, `products.`, `support.` — DNS resolution failures), real header analysis correctly flagged Cloudflare fingerprint + 5 missing security headers on the live hosts. Both table and `--json` output modes confirmed. `pytest` — 33/33 unit passing, 6/6 integration passing.

## Open decisions / immediate next steps

The core tool is functionally complete end-to-end (crt.sh → liveness → headers → output). Remaining items are polish, not core functionality:
1. README: replace "planned functionality" language with actual usage docs/example output now that `lookup` really works.
2. Consider the crt.sh direct-PostgreSQL fallback (see reliability note above) if live flakiness proves annoying in practice.
3. CI (GitHub Actions) — not yet set up; unit suite is fast and network-free, a natural fit.

## Working preferences

- User prefers concise, direct communication — minimal explanation, no unnecessary verbosity.  
- User is comfortable with CLI workflows.

