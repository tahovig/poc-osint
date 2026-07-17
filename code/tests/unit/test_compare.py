from poc_osint.compare import compare_reports

OLD = [
    {"host": "www.example.com", "port": 80, "is_live": True, "findings": {
        "missing_security_headers": ["Content-Security-Policy"],
        "fingerprint_matches": ["nginx"],
    }},
    {"host": "gone.example.com", "port": 443, "is_live": True, "findings": None},
    {"host": "same.example.com", "port": 80, "is_live": True, "findings": None},
]

NEW = [
    {"host": "www.example.com", "port": 80, "is_live": True, "findings": {
        "missing_security_headers": [],
        "fingerprint_matches": ["nginx"],
    }},
    {"host": "same.example.com", "port": 80, "is_live": True, "findings": None},
    {"host": "new.example.com", "port": 443, "is_live": True, "findings": None},
]


def test_compare_reports_detects_added_and_removed():
    result = compare_reports(OLD, NEW)

    assert result.added == [{"host": "new.example.com", "port": 443, "is_live": True, "findings": None}]
    assert result.removed == [{"host": "gone.example.com", "port": 443, "is_live": True, "findings": None}]


def test_compare_reports_detects_changed_entries():
    result = compare_reports(OLD, NEW)

    assert len(result.changed) == 1
    old_entry, new_entry = result.changed[0]
    assert old_entry["host"] == "www.example.com"
    assert old_entry["findings"]["missing_security_headers"] == ["Content-Security-Policy"]
    assert new_entry["findings"]["missing_security_headers"] == []


def test_compare_reports_identical_entry_is_not_changed():
    result = compare_reports(OLD, NEW)

    changed_hosts = {old["host"] for old, _ in result.changed}
    assert "same.example.com" not in changed_hosts


def test_compare_reports_empty_inputs():
    result = compare_reports([], [])

    assert result.added == []
    assert result.removed == []
    assert result.changed == []
