import asyncio
import json
import re
from collections.abc import Callable

import asyncpg
import httpx

CRTSH_URL = "https://crt.sh/"
DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
MAX_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 1.0

# crt.sh also exposes the same underlying data via a public read-only Postgres
# instance, which bypasses their HTTP frontend -- the flakier of the two (see
# CLAUDE.md). Query is crt.sh's own (extracted via their `showSQL=Y` debug
# option), trimmed to just the NAME_VALUE column since that's all we need.
POSTGRES_HOST = "crt.sh"
POSTGRES_PORT = 5432
POSTGRES_USER = "guest"
POSTGRES_DATABASE = "certwatch"
POSTGRES_TIMEOUT = 15.0
POSTGRES_QUERY = (
    "SELECT DISTINCT cai.NAME_VALUE FROM certificate_and_identities cai "
    "WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE) "
    "AND cai.NAME_VALUE ILIKE ('%' || $1 || '%')"
)

_WILDCARD_PREFIX = re.compile(r"^\*\.")

Progress = Callable[[str], None] | None


class CrtShError(Exception):
    """Raised when crt.sh can't be queried successfully after retries."""


def _report(on_progress: Progress, message: str) -> None:
    if on_progress:
        on_progress(message)


async def fetch_crtsh_json(
    domain: str, client: httpx.AsyncClient, *, on_progress: Progress = None
) -> list[dict]:
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
                _report(
                    on_progress,
                    f"crt.sh HTTP request failed (attempt {attempt}/{MAX_ATTEMPTS}), retrying...",
                )
                await asyncio.sleep(BACKOFF_BASE_SECONDS * 2 ** (attempt - 1))

    raise CrtShError(
        f"crt.sh query failed for {domain!r} after {MAX_ATTEMPTS} attempts"
    ) from last_error


async def fetch_crtsh_postgres(domain: str, *, on_progress: Progress = None) -> list[dict]:
    """Fallback fetch path: query crt.sh's public Postgres instance directly.

    Same authoritative data as `fetch_crtsh_json`, different transport --
    returns the same `{"name_value": ...}` shape so `extract_subdomains`
    handles either source unchanged (it already filters out the CA-name and
    email-SAN noise this looser query can surface).
    """
    _report(on_progress, "crt.sh HTTP unavailable -- falling back to direct database query...")

    try:
        conn = await asyncio.wait_for(
            asyncpg.connect(
                host=POSTGRES_HOST,
                port=POSTGRES_PORT,
                user=POSTGRES_USER,
                database=POSTGRES_DATABASE,
                timeout=POSTGRES_TIMEOUT,
            ),
            timeout=POSTGRES_TIMEOUT + 5,
        )
    except (OSError, asyncio.TimeoutError, asyncpg.PostgresError) as exc:
        raise CrtShError(f"crt.sh Postgres connection failed for {domain!r}") from exc

    try:
        rows = await conn.fetch(POSTGRES_QUERY, domain)
    except asyncpg.PostgresError as exc:
        raise CrtShError(f"crt.sh Postgres query failed for {domain!r}") from exc
    finally:
        await conn.close()

    return [{"name_value": row["name_value"]} for row in rows]


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


async def get_subdomains(domain: str, *, on_progress: Progress = None) -> set[str]:
    """Query crt.sh and return the deduplicated subdomains found for `domain`.

    Tries the HTTP/JSON API first; falls back to direct Postgres access if
    that fails, since the HTTP frontend is the flakier of the two.
    """
    try:
        async with httpx.AsyncClient() as client:
            entries = await fetch_crtsh_json(domain, client, on_progress=on_progress)
    except CrtShError:
        try:
            entries = await fetch_crtsh_postgres(domain, on_progress=on_progress)
        except CrtShError as postgres_error:
            raise CrtShError(
                f"crt.sh query failed for {domain!r} via both HTTP and Postgres"
            ) from postgres_error

    return extract_subdomains(entries, domain)
