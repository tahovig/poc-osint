import httpx
import pytest

from poc_osint.liveness import check_host_port, check_hosts

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("docker_fixtures")]


async def test_healthy_host_is_live_with_security_headers():
    async with httpx.AsyncClient() as client:
        result = await check_host_port(client, "localhost", 8081, "http")

    assert result.is_live
    assert result.status_code == 200
    assert result.headers["content-security-policy"] == "default-src 'self'"


async def test_vulnerable_host_is_live_without_security_headers():
    async with httpx.AsyncClient() as client:
        result = await check_host_port(client, "localhost", 8082, "http")

    assert result.is_live
    assert "content-security-policy" not in result.headers
    assert result.headers["server"] == "Apache/2.2.22 (Debian)"


async def test_dead_host_is_not_live():
    async with httpx.AsyncClient() as client:
        result = await check_host_port(
            client, "localhost", 8083, "http", timeout=httpx.Timeout(2.0)
        )

    assert not result.is_live
    assert result.error


async def test_check_hosts_concurrent_across_all_fixture_ports():
    async with httpx.AsyncClient() as client:
        results = await check_hosts(
            client, ["localhost"], ports=(8081, 8082, 8083), max_concurrency=3
        )

    by_port = {r.port: r for r in results}
    assert by_port[8081].is_live
    assert by_port[8082].is_live
    assert not by_port[8083].is_live
