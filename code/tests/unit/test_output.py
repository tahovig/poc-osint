import json

from poc_osint.headers import HeaderFindings
from poc_osint.output import to_json, to_table
from poc_osint.recon import SubdomainReport

LIVE_REPORT = SubdomainReport(
    host="www.example.com",
    port=80,
    scheme="http",
    is_live=True,
    status_code=200,
    error=None,
    findings=HeaderFindings(
        missing_security_headers=["Content-Security-Policy"],
        server_banner="Apache/2.2.22 (Debian)",
        powered_by="PHP/5.4.4",
        fingerprint_matches=["Apache", "PHP"],
    ),
)
DEAD_REPORT = SubdomainReport(
    host="dead.example.com",
    port=443,
    scheme="https",
    is_live=False,
    status_code=None,
    error="connection refused",
    findings=None,
)


def test_to_json_round_trips_report_fields():
    result = json.loads(to_json([LIVE_REPORT, DEAD_REPORT]))

    assert len(result) == 2
    assert result[0]["host"] == "www.example.com"
    assert result[0]["findings"]["fingerprint_matches"] == ["Apache", "PHP"]
    assert result[1]["is_live"] is False
    assert result[1]["findings"] is None


def test_to_json_empty_reports():
    assert json.loads(to_json([])) == []


def test_to_table_includes_host_rows_and_key_findings():
    table = to_table([LIVE_REPORT, DEAD_REPORT])

    assert "HOST" in table
    assert "www.example.com" in table
    assert "Apache,PHP" in table
    assert "dead.example.com" in table
    assert "no" in table


def test_to_table_empty_reports_message():
    assert to_table([]) == "No subdomains found."
