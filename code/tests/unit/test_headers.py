from poc_osint.headers import (
    SECURITY_HEADER_CHECKLIST,
    analyze_headers,
    find_missing_security_headers,
    fingerprint_server,
)

HEALTHY_HEADERS = {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "server": "FixtureServer/1.0",
}

VULNERABLE_HEADERS = {
    "server": "Apache/2.2.22 (Debian)",
    "x-powered-by": "PHP/5.4.4",
    "content-type": "text/html",
}


def test_find_missing_security_headers_none_missing_when_all_present():
    assert find_missing_security_headers(HEALTHY_HEADERS) == []


def test_find_missing_security_headers_all_missing_on_empty_headers():
    assert find_missing_security_headers({}) == SECURITY_HEADER_CHECKLIST


def test_find_missing_security_headers_is_case_insensitive():
    mixed_case = {"Content-Security-Policy": "default-src 'self'"}
    result = find_missing_security_headers(mixed_case)

    assert "Content-Security-Policy" not in result
    assert len(result) == len(SECURITY_HEADER_CHECKLIST) - 1


def test_find_missing_security_headers_reports_partial_gap():
    partial = {"content-security-policy": "default-src 'self'"}
    result = find_missing_security_headers(partial)

    assert "Content-Security-Policy" not in result
    assert "Strict-Transport-Security" in result


def test_fingerprint_server_matches_known_signatures():
    result = fingerprint_server(VULNERABLE_HEADERS)

    assert set(result) == {"Apache", "PHP"}


def test_fingerprint_server_no_match_on_generic_banner():
    assert fingerprint_server(HEALTHY_HEADERS) == []


def test_fingerprint_server_handles_empty_headers():
    assert fingerprint_server({}) == []


def test_analyze_headers_healthy_profile():
    findings = analyze_headers(HEALTHY_HEADERS)

    assert findings.missing_security_headers == []
    assert findings.server_banner == "FixtureServer/1.0"
    assert findings.powered_by is None
    assert findings.fingerprint_matches == []


def test_analyze_headers_vulnerable_profile():
    findings = analyze_headers(VULNERABLE_HEADERS)

    assert findings.missing_security_headers == SECURITY_HEADER_CHECKLIST
    assert findings.server_banner == "Apache/2.2.22 (Debian)"
    assert findings.powered_by == "PHP/5.4.4"
    assert set(findings.fingerprint_matches) == {"Apache", "PHP"}
