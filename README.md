# poc-osint — Automated Corporate Footprint & Subdomain Recon Tool

A Python CLI that automates initial reconnaissance against a target domain: gathers publicly available subdomains, validates active hosts, and extracts open-source metadata (server/CMS fingerprints, missing security headers). Models the workflow a threat intel analyst or pentester uses to map an organization's external attack surface and spot forgotten or rogue shadow IT assets.

First in a series of portfolio projects supporting a pivot from software engineering to cybersecurity engineering.

## Status

Early-stage scaffold — core functionality not yet implemented.

## Authorized use only

This tool performs active checks (HTTP requests to discovered hosts) in addition to passive lookups. Only run it against domains you own or are explicitly authorized to test (e.g. an in-scope bug bounty/VDP target). Never point it at a target without permission. The tool takes a target as an explicit argument — no bundled or default target list.

## Planned functionality

- Query certificate transparency logs (crt.sh) for subdomains — passive, public data only.
- Concurrent (asyncio) liveness checks on ports 80/443, with configurable concurrency limits and per-host delay to avoid hammering target infrastructure.
- Parse HTTP response headers for server/CMS fingerprinting and a fixed checklist of missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
- Structured output: JSON and a human-readable table.

## Repo structure

- `code/` — application source
- `resources/` — supporting/reference materials (non-code)

## Tech stack

Python. See `CLAUDE.md` for full design notes and rationale.
