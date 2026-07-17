import json
from dataclasses import asdict

from .compare import ComparisonResult
from .headers import SECURITY_HEADER_CHECKLIST
from .recon import SubdomainReport

# Short column headings for the checklist grid -- order must track
# SECURITY_HEADER_CHECKLIST so each column lines up with the right header.
_HEADER_ABBREVIATIONS = {
    "Content-Security-Policy": "CSP",
    "Strict-Transport-Security": "HSTS",
    "X-Frame-Options": "XFO",
    "X-Content-Type-Options": "XCTO",
    "Referrer-Policy": "RP",
}


def to_json(reports: list[SubdomainReport]) -> str:
    return json.dumps([asdict(r) for r in reports], indent=2)


def to_table(reports: list[SubdomainReport]) -> str:
    if not reports:
        return "No subdomains found."

    checklist_columns = [_HEADER_ABBREVIATIONS[h] for h in SECURITY_HEADER_CHECKLIST]
    headers = ["HOST", "PORT", "LIVE", "STATUS", "SERVER", *checklist_columns, "FINGERPRINT"]
    rows = [_report_row(report) for report in reports]

    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(len(headers))
    ]
    lines = [" | ".join(cell.ljust(w) for cell, w in zip(headers, widths))]
    lines.append("-+-".join("-" * w for w in widths))
    lines.extend(
        " | ".join(cell.ljust(w) for cell, w in zip(row, widths)) for row in rows
    )

    return "\n".join(lines)


def _report_row(report: SubdomainReport) -> list[str]:
    findings = report.findings
    checklist_cells = [_header_cell(findings, header) for header in SECURITY_HEADER_CHECKLIST]
    return [
        report.host,
        str(report.port),
        "yes" if report.is_live else "no",
        str(report.status_code) if report.status_code is not None else "-",
        (findings.server_banner if findings else None) or "-",
        *checklist_cells,
        ",".join(findings.fingerprint_matches) if findings and findings.fingerprint_matches else "-",
    ]


def _header_cell(findings, header: str) -> str:
    if findings is None:
        return "-"
    return "✗" if header in findings.missing_security_headers else "✓"


def to_compare_json(result: ComparisonResult) -> str:
    return json.dumps(
        {
            "added": result.added,
            "removed": result.removed,
            "changed": [
                {"old": old_entry, "new": new_entry} for old_entry, new_entry in result.changed
            ],
        },
        indent=2,
    )


def to_compare_text(result: ComparisonResult) -> str:
    if not (result.added or result.removed or result.changed):
        return "No differences found."

    lines = []
    for entry in result.added:
        lines.append(f"+ ADDED    {entry['host']}:{entry['port']}")
    for entry in result.removed:
        lines.append(f"- REMOVED  {entry['host']}:{entry['port']}")
    for old_entry, new_entry in result.changed:
        summary = _describe_change(old_entry, new_entry)
        lines.append(f"~ CHANGED  {new_entry['host']}:{new_entry['port']}  {summary}")

    return "\n".join(lines)


def _describe_change(old_entry: dict, new_entry: dict) -> str:
    parts = []

    if old_entry["is_live"] != new_entry["is_live"]:
        parts.append(f"live: {old_entry['is_live']} -> {new_entry['is_live']}")

    old_missing = _missing_count(old_entry)
    new_missing = _missing_count(new_entry)
    if old_missing != new_missing:
        parts.append(f"missing headers: {old_missing} -> {new_missing}")

    old_fingerprint = _fingerprint_set(old_entry)
    new_fingerprint = _fingerprint_set(new_entry)
    if old_fingerprint != new_fingerprint:
        parts.append(f"fingerprint: {sorted(old_fingerprint)} -> {sorted(new_fingerprint)}")

    return ", ".join(parts) if parts else "(other change)"


def _missing_count(entry: dict) -> str:
    findings = entry.get("findings")
    return str(len(findings["missing_security_headers"])) if findings else "-"


def _fingerprint_set(entry: dict) -> set[str]:
    findings = entry.get("findings")
    return set(findings["fingerprint_matches"]) if findings else set()
