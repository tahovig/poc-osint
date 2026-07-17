import json
from dataclasses import asdict

from .recon import SubdomainReport


def to_json(reports: list[SubdomainReport]) -> str:
    return json.dumps([asdict(r) for r in reports], indent=2)


def to_table(reports: list[SubdomainReport]) -> str:
    if not reports:
        return "No subdomains found."

    headers = ["HOST", "PORT", "LIVE", "STATUS", "SERVER", "MISSING HEADERS", "FINGERPRINT"]
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
    return [
        report.host,
        str(report.port),
        "yes" if report.is_live else "no",
        str(report.status_code) if report.status_code is not None else "-",
        (findings.server_banner if findings else None) or "-",
        str(len(findings.missing_security_headers)) if findings else "-",
        ",".join(findings.fingerprint_matches) if findings and findings.fingerprint_matches else "-",
    ]
