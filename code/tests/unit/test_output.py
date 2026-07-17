import json

from poc_osint.compare import ComparisonResult
from poc_osint.headers import HeaderFindings
from poc_osint.output import to_compare_json, to_compare_text, to_json, to_table
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


def test_to_table_header_checklist_grid_reflects_missing_headers():
    table = to_table([LIVE_REPORT])
    header_row, _, live_row = table.splitlines()

    assert ["CSP", "HSTS", "XFO", "XCTO", "RP"] == [
        col for col in header_row.split(" | ") if col.strip() in {"CSP", "HSTS", "XFO", "XCTO", "RP"}
    ]
    columns = [c.strip() for c in live_row.split("|")]
    assert columns[5] == "✗"  # CSP -- explicitly listed as missing
    assert columns[6:9] == ["✓", "✓", "✓"]  # HSTS, XFO, XCTO -- not missing


def test_to_table_header_checklist_grid_is_dash_for_dead_hosts():
    table = to_table([DEAD_REPORT])
    dead_row = table.splitlines()[2]

    columns = [c.strip() for c in dead_row.split("|")]
    assert columns[5:10] == ["-", "-", "-", "-", "-"]


def test_to_table_empty_reports_message():
    assert to_table([]) == "No subdomains found."


def test_to_compare_text_no_differences():
    result = ComparisonResult(added=[], removed=[], changed=[])

    assert to_compare_text(result) == "No differences found."


def test_to_compare_text_reports_added_removed_and_changed():
    added = {"host": "new.example.com", "port": 443}
    removed = {"host": "gone.example.com", "port": 80}
    old_entry = {
        "host": "www.example.com",
        "port": 80,
        "is_live": False,
        "findings": None,
    }
    new_entry = {
        "host": "www.example.com",
        "port": 80,
        "is_live": True,
        "findings": {"missing_security_headers": ["Content-Security-Policy"], "fingerprint_matches": ["nginx"]},
    }
    result = ComparisonResult(added=[added], removed=[removed], changed=[(old_entry, new_entry)])

    text = to_compare_text(result)

    assert "+ ADDED    new.example.com:443" in text
    assert "- REMOVED  gone.example.com:80" in text
    assert "~ CHANGED  www.example.com:80" in text
    assert "live: False -> True" in text


def test_to_compare_json_round_trips():
    added = {"host": "new.example.com", "port": 443}
    result = ComparisonResult(added=[added], removed=[], changed=[])

    parsed = json.loads(to_compare_json(result))

    assert parsed["added"] == [added]
    assert parsed["removed"] == []
    assert parsed["changed"] == []
