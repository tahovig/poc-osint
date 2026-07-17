import asyncio
import json
import re

import httpx

CRTSH_URL = "https://crt.sh/"
DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
MAX_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 1.0

_WILDCARD_PREFIX = re.compile(r"^\*\.")


class CrtShError(Exception):
    """Raised when crt.sh can't be queried successfully after retries."""


async def fetch_crtsh_json(domain: str, client: httpx.AsyncClient) -> list[dict]:
    """Fetch raw certificate transparency log entries for a domain from crt.sh.

    crt.sh is known to be flaky/rate-limited, so failures are retried with
    exponential backoff before giving up.
    """
    last_error: Exception | None = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = await client.get(
                CRTSH_URL,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=DEFAULT_TIMEOUT,
            )
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < MAX_ATTEMPTS:
                await asyncio.sleep(BACKOFF_BASE_SECONDS * 2 ** (attempt - 1))

    raise CrtShError(
        f"crt.sh query failed for {domain!r} after {MAX_ATTEMPTS} attempts"
    ) from last_error


def extract_subdomains(entries: list[dict], domain: str) -> set[str]:
    """Parse crt.sh JSON entries into a deduplicated set of subdomains of `domain`."""
    domain = domain.lower()
    subdomains: set[str] = set()

    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = _WILDCARD_PREFIX.sub("", name.strip().lower())
            if name and (name == domain or name.endswith(f".{domain}")):
                subdomains.add(name)

    return subdomains


async def get_subdomains(domain: str) -> set[str]:
    """Query crt.sh and return the deduplicated subdomains found for `domain`."""
    async with httpx.AsyncClient() as client:
        entries = await fetch_crtsh_json(domain, client)
    return extract_subdomains(entries, domain)
