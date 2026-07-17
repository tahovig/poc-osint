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

**crt.sh reliability — evaluated alternatives, then built the Postgres fallback.** Live testing during development hit genuine crt.sh HTTP-frontend flakiness repeatedly (alternating 200/502 responses seconds apart, independent of our client — confirmed via raw `curl`). Researched alternatives rather than assume:
- **Spyse** — dead since 2022 (reportedly war-related shutdown), confirmed via multiple sources including Crunchbase. Not usable regardless.
- **Google's CT Report endpoint** — unofficial/undocumented (`google.com/transparencyreport/api/v3/httpsreport/ct/certsearch`), used by some OSINT tools but no stability guarantee. Rejected as a foundation for a project meant to demonstrate engineering rigor.
- **crt.sh direct PostgreSQL access** (port 5432, `guest` user, no password — trust auth) — real, documented, used by tools like `quickcert` specifically because it bypasses crt.sh's flaky HTTP frontend while using the same authoritative data. Built as an automatic fallback in `crtsh.get_subdomains()` (see Package skeleton below) — the retry/backoff on the HTTP path was already correct engineering (clean failure, not a bug), but since crt.sh itself publishes a more reliable path to the same data, using it closes the gap rather than just tolerating it.

**Test/demo targets** (decided after checking real authorization status — OWASP has no bug bounty/VDP covering owasp.org itself, ruled out; Tesla's Bugcrowd program is real but only partial safe harbor with a 24h disclosure obligation, not a great fit for repeated demo runs; NASA's VDP is legitimate but scoped to a specific listed target set that would need checking before use):
- **Automated tests / CI**: localhost + Docker fixtures, built at `code/tests/fixtures/` (`server.py` + `Dockerfile` + `docker-compose.yml`). One image, two configured services: `healthy-host` (`:8081`, full security-header checklist, generic banner) and `vulnerable-host` (`:8082`, no security headers, fake `Server`/`X-Powered-By`). Port `8083` is reserved unused as the "dead host" case (connection-refused path). Verified end-to-end (GET + HEAD, correct headers per host, dead port refuses connections) — zero legal ambiguity, deterministic.
- **Smoke test**: `example.com` (IANA-run, stable, exists for exactly this purpose).
- Real-target demo (NASA VDP in-scope list, or a domain the user owns) deferred until later — not needed to start building.

## Package skeleton

Src-layout Python package at `code/`:
- `pyproject.toml` — setuptools build, console script entry point `poc-osint = poc_osint.cli:main`. Runtime deps: `httpx`, `asyncpg`. Dev deps (`.[dev]`): `pytest`, `pytest-asyncio`, `respx`.
- `src/poc_osint/cli.py` — argparse-based CLI, subcommand-structured. `lookup <target>` is fully wired now: domain validation → `run_recon()` → `to_table()`/`to_json()`. Flags: `--max-concurrency` (default 10), `--delay` (default 0.0), `--json`. `CrtShError`/`ValueError` from the recon pipeline are caught and become a clean stderr message + exit 1, not a traceback.
- `src/poc_osint/crtsh.py` — crt.sh client, two independent fetch paths sharing one parser. `fetch_crtsh_json()` (network layer: GET with timeout + exponential-backoff retry, `CrtShError` after 3 failed attempts, reports "attempt N/3, retrying..." via `on_progress` before each backoff sleep) and `fetch_crtsh_postgres()` (direct Postgres query against crt.sh's public `certwatch` DB — query is crt.sh's own, extracted via their `showSQL=Y` debug option, trimmed to just `NAME_VALUE`; reports "crt.sh HTTP unavailable -- falling back to direct database query..." right before its own first real `await`) both return the same `{"name_value": ...}` shape, so `extract_subdomains()` (pure parsing: dedupes, lowercases, strips `*.` wildcard prefixes, filters to the queried domain + its subdomains) handles either unchanged — including filtering out the CA-name/email-SAN noise the looser Postgres full-text query surfaces. `get_subdomains()` tries HTTP first, falls back to Postgres on `CrtShError`, raises (mentioning both) only if both fail.
- `src/poc_osint/liveness.py` — async liveness checker. `check_host_port()` (single HEAD request, never raises — failures become `HostResult(is_live=False, error=...)`) is separate from `check_hosts()` (concurrency orchestration: `asyncio.Semaphore`-bounded `max_concurrency`, per-request `delay` before each check, reports a live "Checking liveness: N/total complete..." via `on_progress` as each check finishes — no lock needed for the counter since asyncio has no preemption between awaits). `get_live_hosts()` wires both together. Port→scheme mapping (80→http, 443→https, fallback http) lives in `check_hosts`; `check_host_port` itself takes an explicit scheme so fixture ports (8081/8082/8083) work too. Headers stored lowercased.
- `src/poc_osint/headers.py` — header parser. Pure/synchronous, no network. `find_missing_security_headers()` (fixed 5-header checklist, case-insensitive) + `fingerprint_server()` (Server/X-Powered-By string matching against a short fixed signature list) wired together by `analyze_headers()` into a `HeaderFindings` dataclass.
- `src/poc_osint/recon.py` — orchestration layer. `run_recon(domain, *, max_concurrency, delay, on_progress=None)`: crt.sh → liveness → header analysis, returns `list[SubdomainReport]`. Skips liveness entirely if crt.sh finds zero subdomains (returns `[]`, not an error) rather than inventing a fallback target. `on_progress`, if given, is called with a short stage-description string before each phase — purely a UI hook (feeds the CLI spinner, see `progress.py`), doesn't affect returned data; defaults to `None` so every existing caller/test is unaffected.
- `src/poc_osint/progress.py` — new. `Spinner`: minimal braille-frame ASCII spinner written to stderr while `lookup` runs, showing the current `on_progress` stage message. Detects `sys.stderr.isatty()` and no-ops entirely when not a real terminal (piped output, tests, CI logs) — writing carriage-return animation there would corrupt anything scripted against stdout, not just look bad. Runs as an `asyncio.Task` alongside `run_recon()`; `stop()` cancels and awaits it, then clears the line, so nothing leaks past the final table/JSON output.
- `src/poc_osint/output.py` — formatting layer. `to_json()`/`to_table()` consume `list[SubdomainReport]`; `to_table()` renders a per-header ✓/✗/`-` checklist grid (CSP/HSTS/XFO/XCTO/RP columns, `-` for dead hosts where it's not applicable) instead of a bare missing-header count — the actual "visualization" ask. `to_compare_json()`/`to_compare_text()` render a `ComparisonResult` (see `compare.py`) as either structured JSON or a `+`/`-`/`~` diff view (`+ ADDED host:port`, `- REMOVED host:port`, `~ CHANGED host:port  live: X -> Y, missing headers: N -> M, fingerprint: [...] -> [...]`).
- `src/poc_osint/compare.py` — new. `compare_reports(old, new)` diffs two saved `lookup` result sets (loaded JSON, plain `dict`s — not reconstructed into `SubdomainReport`, dict equality is all "did this change?" needs) keyed by `(host, port)`, returning a `ComparisonResult(added, removed, changed)`. This is the "aggregate/compare over time" piece — maps directly onto the tool's "shadow IT drift" purpose rather than being a cosmetic add-on.
- `tests/unit/` — `test_cli.py`, `test_crtsh.py`, `test_liveness.py`, `test_headers.py`, `test_recon.py`, `test_output.py`, `test_compare.py`, `test_progress.py` — 63/63 passing. `test_recon.py`/updated `test_cli.py` monkeypatch `get_subdomains`/`get_live_hosts`/`run_recon` directly (no HTTP mocking needed at the orchestration layer) — no live network anywhere in the suite. `fetch_crtsh_postgres`/`get_subdomains` fallback tests monkeypatch `asyncpg.connect` with a fake connection object, same pattern as respx for HTTP. `test_progress.py` forces `Spinner(enabled=True)` regardless of the real (non-tty) test environment to exercise the actual write/clear logic.
- `tests/integration/` — real Docker-fixture tests. `test_liveness_fixtures.py` + `test_headers_fixtures.py` — 6/6 passing against real containers. Excluded from the default `pytest` run (`addopts = "-m 'not integration'"`), run explicitly via `pytest -m integration`, requires `dockerd` running.
- `tests/fixtures/` — Docker fixtures (see above).
- Dev venv: `code/poc-osint-venv/` (named for the project rather than generic `.venv`, gitignored). Setup: `python3 -m venv poc-osint-venv && poc-osint-venv/bin/pip install -e ".[dev]"`.
- **Verified fully end-to-end against live data**: `poc-osint-venv/bin/poc-osint lookup example.com` — real crt.sh query found 6 subdomains, real liveness checks correctly separated live (`example.com`, `www.example.com`, both ports) from dead (`dev.`, `m.`, `products.`, `support.` — DNS resolution failures), real header analysis correctly flagged Cloudflare fingerprint + 5 missing security headers on the live hosts (checklist grid renders as all-`✗` for those two, all-`-` for the dead ones). Both table and `--json` output modes confirmed. `pytest` — 63/63 unit passing, 6/6 integration passing.
- **Spinner verified live under a real pseudo-tty** (`script -qec ... /tmp/log`, since a piped/captured shell isn't a tty and would silently skip it): frames genuinely cycle with `\r` overwrites, stage text updates through "Querying crt.sh...", "Checking liveness of N subdomain(s)...", and a genuinely live "Checking liveness: 10/12 complete..." counter (confirmed at an intermediate value, not just start/end), final table renders with no leftover spinner residue. Piped output (`--json > file`) confirmed to produce zero stderr bytes — the `isatty()` gate works.
- **User caught a real bug this way**: asked for more specific messaging (e.g. surface the crt.sh->Postgres fallback), which led to discovering that a message set immediately before calling into another function that itself sets a *different* message with no `await` in between can never actually render — the spinner task has no scheduling opportunity between the two synchronous statements. Fixed by consolidating into one message emitted right before the first genuine `await` (the real DB connect), which guarantees a visible window. Left as a known, documented limitation rather than "fixed": the "Analyzing headers..." stage message, since header analysis is synchronous over already-fetched data with no natural slow point after it — inserting an artificial delay just to make a cosmetic message flash would be dishonest UX, not a fix.
- **`--save` + `compare` verified live**: saved a real `example.com` scan, then hand-crafted a synthetic "earlier" version of that same JSON (dropped `www.example.com`, added a since-removed `legacy.example.com`, flipped `example.com:443`'s missing-headers list to empty) and ran `poc-osint compare old.json new.json` for real — correctly reported `+ ADDED www.example.com:80/:443`, `- REMOVED legacy.example.com:80`, `~ CHANGED example.com:443  missing headers: 0 -> 5`. `--json` compare output confirmed too.
- **Postgres fallback verified live, twice**: `fetch_crtsh_postgres('example.com')` directly returns the same 6 subdomains as the HTTP path (plus filtered-out noise: a CA common name, an unrelated look-alike domain, two email SANs — all correctly excluded by the existing filter). Also forced a real HTTP failure (monkeypatched `fetch_crtsh_json` to raise) and confirmed `get_subdomains()` genuinely falls through to Postgres end-to-end, not just in isolation, and lands on the identical result set.

## CI

`.github/workflows/ci.yml` — two jobs, both on `push`/`pull_request` to `main`/`develop`:
- `unit`: matrix over Python 3.11/3.12, `pip install -e ".[dev]"` + `pytest` (default `addopts` already excludes `integration`-marked tests — no Docker needed).
- `integration`: single Python 3.11 run, `pytest -m integration` against the Docker fixtures. GitHub-hosted `ubuntu-latest` runners ship Docker + the Compose v2 plugin (`docker compose`, no hyphen) by default, which differs from this local dev setup's v1 binary (`docker-compose`, hyphenated — Ubuntu 20.04's apt repos don't ship the v2 plugin). `tests/integration/conftest.py::_compose_command()` detects which is available and uses that, so the same fixture code works in both places.
- **Confirmed green on GitHub**: `gh` CLI now installed + authenticated (classic PAT needed `read:org` + `workflow` scopes added on top of the `repo` scope already used for git push — same token, scopes edited in place at github.com/settings/tokens, no new token needed). All 3 jobs passed on first real run (`unit` 3.11, `unit` 3.12, `integration` — the last one confirming the runner really does use Compose v2 and the fallback logic picks it correctly).

## Results visualization/comparison — implemented

User asked to keep visualization in mind while building CI; this is that feature, built afterward (in two rounds). All three parts stay terminal/ASCII-based (no charting dependency, consistent with the project's dependency-light style):
1. `to_table()`'s per-header checklist grid (✓/✗/`-`) — replaces the old bare "missing headers: N" count, immediately scannable across many hosts at once.
2. `lookup --save PATH` (always saves JSON, regardless of the stdout format flag) + `poc-osint compare old.json new.json` (`+`/`-`/`~` diff, or `--json`) — the "aggregate/compare over time" piece, mapping directly onto the tool's "shadow IT drift" purpose rather than being cosmetic. `compare_reports()` deliberately works on plain loaded-JSON dicts, not reconstructed `SubdomainReport` objects — dict equality is all a diff needs.
3. A live ASCII spinner (`progress.py`) during `lookup` itself, showing which stage is running (crt.sh query / liveness checks / header analysis) rather than a silent hang — the user's direct request, drawing an analogy to Claude Code's own "thinking" indicator.

## Open decisions / immediate next steps

The core tool is functionally complete end-to-end (crt.sh → liveness → headers → output), with CI green on GitHub, a working crt.sh fallback path, and results visualization/comparison. `main` was last synced through the Postgres-fallback commit — the visualization/compare work in this section is on `develop` only so far.
1. README doesn't yet document `--save`/`compare` or the checklist grid — needs an update pass.
2. Merge `develop` into `main` once this round's changes are committed.

## Working preferences

- User prefers concise, direct communication — minimal explanation, no unnecessary verbosity.  
- User is comfortable with CLI workflows.

