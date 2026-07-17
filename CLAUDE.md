# Project: poc-osint

## Goal

OSINT (Open Source Intelligence) proof-of-concept — first in a series of portfolio projects supporting a career pivot from software engineering to cybersecurity engineering. User previously held a cybersecurity analyst role and wants these POCs to demonstrate the engineering side, for a GitHub portfolio. 2-3 more POC projects (different focus areas) are planned after this one — open to suggestions on those once this project is further along.

## Repo

[https://github.com/tahovig/poc-osint.git](https://github.com/tahovig/poc-osint.git) — created empty on GitHub, not yet pushed to.

## Branch strategy

- `main` — stable, deployable state  
- `develop` — active development (working branch)

## Current state

- Working directory is `~/dev-projects/tah-osint-poc` (WSL native filesystem) — this is the real, permanent working folder. The earlier Windows scaffold at `D:\tah-projects\poc-osint` is abandoned; nothing from it has been carried over.
- Decided: primary development happens in WSL Ubuntu via Claude Code CLI, not in Cowork mode.
- Git repo initialized locally. `main` has the initial commit (README, .gitignore, `code/`, `resources/`, CLAUDE.md); `develop` branched from it and is the active working branch. Not yet pushed to GitHub.

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
- **Automated tests / CI**: localhost + Docker fixtures (lightweight local HTTP servers/containers) — zero legal ambiguity, deterministic. Not yet built — part of scaffolding.
- **Smoke test**: `example.com` (IANA-run, stable, exists for exactly this purpose).
- Real-target demo (NASA VDP in-scope list, or a domain the user owns) deferred until later — not needed to start building.

## Open decisions / immediate next steps

1. Push `main` \+ `develop` to GitHub (remote already exists, empty).
2. Build local Docker/HTTP-server test fixtures (needed for CI since no live target is set up yet).

## Working preferences

- User prefers concise, direct communication — minimal explanation, no unnecessary verbosity.  
- User is comfortable with CLI workflows.

