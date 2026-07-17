import asyncio

import httpx
import pytest
import respx

from poc_osint.liveness import check_host_port, check_hosts


@respx.mock
async def test_check_host_port_live_returns_status_and_headers():
    respx.head("https://sub.example.com:443/").mock(
        return_value=httpx.Response(200, headers={"Server": "nginx"})
    )

    async with httpx.AsyncClient() as client:
        result = await check_host_port(client, "sub.example.com", 443, "https")

    assert result.is_live
    assert result.status_code == 200
    assert result.headers["server"] == "nginx"
    assert result.error is None


@respx.mock
async def test_check_host_port_connection_error_is_not_live():
    respx.head("http://dead.example.com:80/").mock(side_effect=httpx.ConnectError("refused"))

    async with httpx.AsyncClient() as client:
        result = await check_host_port(client, "dead.example.com", 80, "http")

    assert not result.is_live
    assert result.status_code is None
    assert result.error


@respx.mock
async def test_check_hosts_rejects_non_positive_concurrency():
    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError):
            await check_hosts(client, ["a.example.com"], max_concurrency=0)


@respx.mock
async def test_check_hosts_respects_max_concurrency():
    concurrent = 0
    max_seen = 0
    lock = asyncio.Lock()

    async def responder(request):
        nonlocal concurrent, max_seen
        async with lock:
            concurrent += 1
            max_seen = max(max_seen, concurrent)
        await asyncio.sleep(0.05)
        async with lock:
            concurrent -= 1
        return httpx.Response(200)

    respx.head(url__regex=r".*").mock(side_effect=responder)

    hosts = [f"host{i}.example.com" for i in range(6)]
    async with httpx.AsyncClient() as client:
        await check_hosts(client, hosts, ports=(80,), max_concurrency=2)

    assert max_seen <= 2


@respx.mock
async def test_check_hosts_applies_delay_before_each_request(monkeypatch):
    sleep_calls = []

    async def fake_sleep(seconds):
        sleep_calls.append(seconds)

    monkeypatch.setattr("poc_osint.liveness.asyncio.sleep", fake_sleep)
    respx.head(url__regex=r".*").mock(return_value=httpx.Response(200))

    hosts = ["a.example.com", "b.example.com"]
    async with httpx.AsyncClient() as client:
        await check_hosts(client, hosts, ports=(80,), max_concurrency=5, delay=0.25)

    assert sleep_calls == [0.25, 0.25]


@respx.mock
async def test_check_hosts_maps_ports_to_expected_schemes():
    http_route = respx.head("http://a.example.com:80/").mock(return_value=httpx.Response(200))
    https_route = respx.head("https://a.example.com:443/").mock(return_value=httpx.Response(200))

    async with httpx.AsyncClient() as client:
        results = await check_hosts(client, ["a.example.com"], ports=(80, 443))

    assert http_route.called
    assert https_route.called
    schemes = {r.port: r.scheme for r in results}
    assert schemes == {80: "http", 443: "https"}
