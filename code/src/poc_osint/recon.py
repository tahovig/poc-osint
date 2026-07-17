from dataclasses import dataclass

from .crtsh import get_subdomains
from .headers import HeaderFindings, analyze_headers
from .liveness import get_live_hosts


@dataclass
class SubdomainReport:
    host: str
    port: int
    scheme: str
    is_live: bool
    status_code: int | None
    error: str | None
    findings: HeaderFindings | None


async def run_recon(
    domain: str, *, max_concurrency: int = 10, delay: float = 0.0
) -> list[SubdomainReport]:
    """Passive subdomain enumeration -> concurrent liveness check -> header analysis.

    Only queries crt.sh; if it finds nothing, no liveness checks are made --
    there's nothing discovered to check.
    """
    subdomains = await get_subdomains(domain)
    if not subdomains:
        return []

    live_results = await get_live_hosts(
        sorted(subdomains), max_concurrency=max_concurrency, delay=delay
    )

    return [
        SubdomainReport(
            host=result.host,
            port=result.port,
            scheme=result.scheme,
            is_live=result.is_live,
            status_code=result.status_code,
            error=result.error,
            findings=analyze_headers(result.headers) if result.is_live else None,
        )
        for result in live_results
    ]
