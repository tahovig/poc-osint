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
    async def fake_get_subdomains(domain, **kwargs):
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
    async def fake_get_subdomains(domain, **kwargs):
        return set()

    async def fake_get_live_hosts(hosts, **kwargs):
        raise AssertionError("get_live_hosts should not be called with no subdomains")

    monkeypatch.setattr("poc_osint.recon.get_subdomains", fake_get_subdomains)
    monkeypatch.setattr("poc_osint.recon.get_live_hosts", fake_get_live_hosts)

    reports = await run_recon("example.com")

    assert reports == []


async def test_run_recon_passes_through_concurrency_and_delay(monkeypatch):
    captured_kwargs = {}

    async def fake_get_subdomains(domain, **kwargs):
        return {"example.com"}

    async def fake_get_live_hosts(hosts, **kwargs):
        captured_kwargs.update(kwargs)
        return []

    monkeypatch.setattr("poc_osint.recon.get_subdomains", fake_get_subdomains)
    monkeypatch.setattr("poc_osint.recon.get_live_hosts", fake_get_live_hosts)

    await run_recon("example.com", max_concurrency=3, delay=0.1)

    assert captured_kwargs["max_concurrency"] == 3
    assert captured_kwargs["delay"] == 0.1


async def test_run_recon_reports_progress_through_each_stage(monkeypatch):
    messages = []

    async def fake_get_subdomains(domain, **kwargs):
        return {"www.example.com"}

    async def fake_get_live_hosts(hosts, **kwargs):
        return [LIVE_HEALTHY]

    monkeypatch.setattr("poc_osint.recon.get_subdomains", fake_get_subdomains)
    monkeypatch.setattr("poc_osint.recon.get_live_hosts", fake_get_live_hosts)

    await run_recon("example.com", on_progress=messages.append)

    assert any("crt.sh" in m for m in messages)
    assert any("liveness" in m.lower() for m in messages)
    assert any("header" in m.lower() for m in messages)


async def test_run_recon_progress_is_optional(monkeypatch):
    async def fake_get_subdomains(domain, **kwargs):
        return {"example.com"}

    async def fake_get_live_hosts(hosts, **kwargs):
        return [LIVE_HEALTHY]

    monkeypatch.setattr("poc_osint.recon.get_subdomains", fake_get_subdomains)
    monkeypatch.setattr("poc_osint.recon.get_live_hosts", fake_get_live_hosts)

    reports = await run_recon("example.com")  # no on_progress -- must not raise

    assert len(reports) == 1


async def test_run_recon_passes_on_progress_down_to_get_subdomains_and_get_live_hosts(monkeypatch):
    received = {}

    async def fake_get_subdomains(domain, **kwargs):
        received["get_subdomains_on_progress"] = kwargs.get("on_progress")
        return {"example.com"}

    async def fake_get_live_hosts(hosts, **kwargs):
        received["get_live_hosts_on_progress"] = kwargs.get("on_progress")
        return [LIVE_HEALTHY]

    monkeypatch.setattr("poc_osint.recon.get_subdomains", fake_get_subdomains)
    monkeypatch.setattr("poc_osint.recon.get_live_hosts", fake_get_live_hosts)

    callback = lambda message: None
    await run_recon("example.com", on_progress=callback)

    assert received["get_subdomains_on_progress"] is callback
    assert received["get_live_hosts_on_progress"] is callback
