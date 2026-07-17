import httpx
import pytest

from poc_osint.headers import analyze_headers
from poc_osint.liveness import check_host_port

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("docker_fixtures")]


async def test_analyze_headers_against_healthy_host():
    async with httpx.AsyncClient() as client:
        result = await check_host_port(client, "localhost", 8081, "http")

    findings = analyze_headers(result.headers)

    assert findings.missing_security_headers == []
    assert findings.fingerprint_matches == []


async def test_analyze_headers_against_vulnerable_host():
    async with httpx.AsyncClient() as client:
        result = await check_host_port(client, "localhost", 8082, "http")

    findings = analyze_headers(result.headers)

    assert len(findings.missing_security_headers) == 5
    assert "Apache" in findings.fingerprint_matches
    assert "PHP" in findings.fingerprint_matches
