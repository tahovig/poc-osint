import asyncpg
import httpx
import pytest
import respx

from poc_osint.crtsh import (
    CrtShError,
    extract_subdomains,
    fetch_crtsh_json,
    fetch_crtsh_postgres,
    get_subdomains,
)

SAMPLE_ENTRIES = [
    {"name_value": "www.example.com\nexample.com"},
    {"name_value": "*.example.com"},
    {"name_value": "WWW.EXAMPLE.COM"},
    {"name_value": "api.other.com"},
]


async def _no_sleep(_seconds):
    return None


class FakeConnection:
    def __init__(self, rows=None, fetch_error=None):
        self._rows = rows or []
        self._fetch_error = fetch_error
        self.closed = False

    async def fetch(self, query, domain):
        if self._fetch_error:
            raise self._fetch_error
        return self._rows

    async def close(self):
        self.closed = True


def test_extract_subdomains_parses_dedupes_and_filters():
    result = extract_subdomains(SAMPLE_ENTRIES, "example.com")

    assert result == {"example.com", "www.example.com"}


def test_extract_subdomains_handles_missing_name_value():
    result = extract_subdomains([{}], "example.com")

    assert result == set()


@respx.mock
async def test_fetch_crtsh_json_returns_parsed_entries():
    route = respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=[{"name_value": "example.com"}])
    )

    async with httpx.AsyncClient() as client:
        result = await fetch_crtsh_json("example.com", client)

    assert route.called
    assert result == [{"name_value": "example.com"}]


@respx.mock
async def test_fetch_crtsh_json_retries_then_succeeds(monkeypatch):
    monkeypatch.setattr("poc_osint.crtsh.asyncio.sleep", _no_sleep)
    route = respx.get("https://crt.sh/").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(200, json=[{"name_value": "example.com"}]),
        ]
    )

    async with httpx.AsyncClient() as client:
        result = await fetch_crtsh_json("example.com", client)

    assert route.call_count == 2
    assert result == [{"name_value": "example.com"}]


@respx.mock
async def test_fetch_crtsh_json_raises_after_max_attempts(monkeypatch):
    monkeypatch.setattr("poc_osint.crtsh.asyncio.sleep", _no_sleep)
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(503))

    async with httpx.AsyncClient() as client:
        with pytest.raises(CrtShError):
            await fetch_crtsh_json("example.com", client)


async def test_fetch_crtsh_postgres_returns_parsed_entries(monkeypatch):
    fake_conn = FakeConnection(
        rows=[{"name_value": "example.com"}, {"name_value": "www.example.com"}]
    )

    async def fake_connect(**kwargs):
        return fake_conn

    monkeypatch.setattr("poc_osint.crtsh.asyncpg.connect", fake_connect)

    result = await fetch_crtsh_postgres("example.com")

    assert result == [{"name_value": "example.com"}, {"name_value": "www.example.com"}]
    assert fake_conn.closed


async def test_fetch_crtsh_postgres_raises_on_connect_failure(monkeypatch):
    async def fake_connect(**kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr("poc_osint.crtsh.asyncpg.connect", fake_connect)

    with pytest.raises(CrtShError):
        await fetch_crtsh_postgres("example.com")


async def test_fetch_crtsh_postgres_raises_on_query_failure_and_still_closes(monkeypatch):
    fake_conn = FakeConnection(fetch_error=asyncpg.PostgresError("bad query"))

    async def fake_connect(**kwargs):
        return fake_conn

    monkeypatch.setattr("poc_osint.crtsh.asyncpg.connect", fake_connect)

    with pytest.raises(CrtShError):
        await fetch_crtsh_postgres("example.com")

    assert fake_conn.closed


async def test_get_subdomains_uses_http_when_available(monkeypatch):
    async def fake_json(domain, client, **kwargs):
        return [{"name_value": "example.com"}]

    async def fake_postgres(domain, **kwargs):
        raise AssertionError("Postgres fallback should not be used when HTTP succeeds")

    monkeypatch.setattr("poc_osint.crtsh.fetch_crtsh_json", fake_json)
    monkeypatch.setattr("poc_osint.crtsh.fetch_crtsh_postgres", fake_postgres)

    result = await get_subdomains("example.com")

    assert result == {"example.com"}


async def test_get_subdomains_falls_back_to_postgres_on_http_failure(monkeypatch):
    async def fake_json(domain, client, **kwargs):
        raise CrtShError("http down")

    async def fake_postgres(domain, **kwargs):
        return [{"name_value": "example.com"}]

    monkeypatch.setattr("poc_osint.crtsh.fetch_crtsh_json", fake_json)
    monkeypatch.setattr("poc_osint.crtsh.fetch_crtsh_postgres", fake_postgres)

    result = await get_subdomains("example.com")

    assert result == {"example.com"}


async def test_get_subdomains_raises_when_both_sources_fail(monkeypatch):
    async def fake_json(domain, client, **kwargs):
        raise CrtShError("http down")

    async def fake_postgres(domain, **kwargs):
        raise CrtShError("postgres down")

    monkeypatch.setattr("poc_osint.crtsh.fetch_crtsh_json", fake_json)
    monkeypatch.setattr("poc_osint.crtsh.fetch_crtsh_postgres", fake_postgres)

    with pytest.raises(CrtShError, match="both HTTP and Postgres"):
        await get_subdomains("example.com")


@respx.mock
async def test_fetch_crtsh_json_reports_retry_progress(monkeypatch):
    monkeypatch.setattr("poc_osint.crtsh.asyncio.sleep", _no_sleep)
    messages = []
    respx.get("https://crt.sh/").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(200, json=[{"name_value": "example.com"}]),
        ]
    )

    async with httpx.AsyncClient() as client:
        await fetch_crtsh_json("example.com", client, on_progress=messages.append)

    assert any("attempt 1/3" in m for m in messages)


async def test_fetch_crtsh_postgres_reports_progress(monkeypatch):
    fake_conn = FakeConnection(rows=[{"name_value": "example.com"}])
    messages = []

    async def fake_connect(**kwargs):
        return fake_conn

    monkeypatch.setattr("poc_osint.crtsh.asyncpg.connect", fake_connect)

    await fetch_crtsh_postgres("example.com", on_progress=messages.append)

    assert any("falling back" in m.lower() and "database" in m.lower() for m in messages)
