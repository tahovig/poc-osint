from dataclasses import dataclass, field

SECURITY_HEADER_CHECKLIST = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

KNOWN_SIGNATURES = ["Apache", "nginx", "Microsoft-IIS", "PHP", "ASP.NET", "Express", "Cloudflare"]


@dataclass
class HeaderFindings:
    missing_security_headers: list[str] = field(default_factory=list)
    server_banner: str | None = None
    powered_by: str | None = None
    fingerprint_matches: list[str] = field(default_factory=list)


def find_missing_security_headers(headers: dict[str, str]) -> list[str]:
    """Return the checklist headers that are absent from `headers` (case-insensitive)."""
    present = {name.lower() for name in headers}
    return [name for name in SECURITY_HEADER_CHECKLIST if name.lower() not in present]


def fingerprint_server(headers: dict[str, str]) -> list[str]:
    """Match Server/X-Powered-By header values against a small known-signature list.

    Deliberately bounded to a short list, not an open-ended Wappalyzer clone --
    broader fingerprinting is documented future work.
    """
    lowered = {name.lower(): value for name, value in headers.items()}
    banner_text = " ".join(
        value for key, value in lowered.items() if key in ("server", "x-powered-by")
    ).lower()

    return [signature for signature in KNOWN_SIGNATURES if signature.lower() in banner_text]


def analyze_headers(headers: dict[str, str]) -> HeaderFindings:
    """Run the full header checklist + fingerprint scan against a response's headers."""
    lowered = {name.lower(): value for name, value in headers.items()}

    return HeaderFindings(
        missing_security_headers=find_missing_security_headers(headers),
        server_banner=lowered.get("server"),
        powered_by=lowered.get("x-powered-by"),
        fingerprint_matches=fingerprint_server(headers),
    )
