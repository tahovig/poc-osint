from poc_osint.liveness import HostResult
from poc_osint.recon import run_recon

LIVE_HEALTHY = HostResult(
    host="www.example.com",
    port=80,
    scheme="http",
    is_live=True,
    status_code=200,
    headers={
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=63072000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "server": "nginx",
    },
)
DEAD = HostResult(
    host="dead.example.com", port=443, scheme="https", is_live=False, error="connection refused"
)


async def test_run_recon_wires_subdomains_into_liveness_and_headers(monkeypatch):
    async def fake_get_subdomains(domain):
        return {"www.example.com", "dead.example.com"}

    async def fake_get_live_hosts(hosts, **kwargs):
        assert sorted(hosts) == ["dead.example.com", "www.example.com"]
        return [LIVE_HEALTHY, DEAD]

    monkeypatch.setattr("poc_osint.recon.get_subdomains", fake_get_subdomains)
    monkeypatch.setattr("poc_osint.recon.get_live_hosts", fake_get_live_hosts)

    reports = await run_recon("example.com")

    assert len(reports) == 2
    live_report = next(r for r in reports if r.host == "www.example.com")
    dead_report = next(r for r in reports if r.host == "dead.example.com")

    assert live_report.is_live
    assert live_report.findings is not None
    assert live_report.findings.missing_security_headers == []

    assert not dead_report.is_live
    assert dead_report.findings is None
    assert dead_report.error == "connection refused"


async def test_run_recon_skips_liveness_when_no_subdomains_found(monkeypatch):
    async def fake_get_subdomains(domain):
        return set()

    async def fake_get_live_hosts(hosts, **kwargs):
        raise AssertionError("get_live_hosts should not be called with no subdomains")

    monkeypatch.setattr("poc_osint.recon.get_subdomains", fake_get_subdomains)
    monkeypatch.setattr("poc_osint.recon.get_live_hosts", fake_get_live_hosts)

    reports = await run_recon("example.com")

    assert reports == []


async def test_run_recon_passes_through_concurrency_and_delay(monkeypatch):
    captured_kwargs = {}

    async def fake_get_subdomains(domain):
        return {"example.com"}

    async def fake_get_live_hosts(hosts, **kwargs):
        captured_kwargs.update(kwargs)
        return []

    monkeypatch.setattr("poc_osint.recon.get_subdomains", fake_get_subdomains)
    monkeypatch.setattr("poc_osint.recon.get_live_hosts", fake_get_live_hosts)

    await run_recon("example.com", max_concurrency=3, delay=0.1)

    assert captured_kwargs == {"max_concurrency": 3, "delay": 0.1}
