import httpx
import pytest
import respx

from poc_osint.crtsh import CrtShError, extract_subdomains, fetch_crtsh_json

SAMPLE_ENTRIES = [
    {"name_value": "www.example.com\nexample.com"},
    {"name_value": "*.example.com"},
    {"name_value": "WWW.EXAMPLE.COM"},
    {"name_value": "api.other.com"},
]


async def _no_sleep(_seconds):
    return None


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
