from collections.abc import Callable
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
    domain: str,
    *,
    max_concurrency: int = 10,
    delay: float = 0.0,
    on_progress: Callable[[str], None] | None = None,
) -> list[SubdomainReport]:
    """Passive subdomain enumeration -> concurrent liveness check -> header analysis.

    Only queries crt.sh; if it finds nothing, no liveness checks are made --
    there's nothing discovered to check. `on_progress`, if given, is called
    with a short stage-description string at each step (e.g. for a CLI
    spinner) -- purely a UI hook, has no effect on the returned data.
    """

    def report(message: str) -> None:
        if on_progress:
            on_progress(message)

    report(f"Querying crt.sh for {domain}...")
    subdomains = await get_subdomains(domain)
    if not subdomains:
        return []

    report(f"Checking liveness of {len(subdomains)} subdomain(s)...")
    live_results = await get_live_hosts(
        sorted(subdomains), max_concurrency=max_concurrency, delay=delay
    )

    report("Analyzing headers...")
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
