import asyncio
from collections.abc import Callable
from dataclasses import dataclass

import httpx

DEFAULT_TIMEOUT = httpx.Timeout(5.0, connect=3.0)
PORT_SCHEMES = {80: "http", 443: "https"}


@dataclass
class HostResult:
    host: str
    port: int
    scheme: str
    is_live: bool
    status_code: int | None = None
    headers: dict[str, str] | None = None
    error: str | None = None


async def check_host_port(
    client: httpx.AsyncClient,
    host: str,
    port: int,
    scheme: str,
    *,
    timeout: httpx.Timeout = DEFAULT_TIMEOUT,
) -> HostResult:
    """HEAD-check a single host:port. Never raises -- failures are reported in the result."""
    url = f"{scheme}://{host}:{port}/"

    try:
        response = await client.head(url, timeout=timeout, follow_redirects=True)
        return HostResult(
            host=host,
            port=port,
            scheme=scheme,
            is_live=True,
            status_code=response.status_code,
            headers=dict(response.headers),
        )
    except httpx.HTTPError as exc:
        return HostResult(host=host, port=port, scheme=scheme, is_live=False, error=str(exc))


async def check_hosts(
    client: httpx.AsyncClient,
    hosts: list[str],
    *,
    ports: tuple[int, ...] = (80, 443),
    max_concurrency: int = 10,
    delay: float = 0.0,
    on_progress: Callable[[str], None] | None = None,
) -> list[HostResult]:
    """Concurrently HEAD-check `hosts` across `ports`.

    `max_concurrency` bounds simultaneous in-flight requests and `delay` is
    applied before each one -- both exist to avoid hammering target
    infrastructure, not just for throughput tuning. `on_progress`, if given,
    is called with a live "N/total complete" message as each check finishes
    (no lock needed for the counter -- asyncio has no preemption between
    awaits, so the increment is safe as plain synchronous code).
    """
    if max_concurrency < 1:
        raise ValueError("max_concurrency must be at least 1")

    semaphore = asyncio.Semaphore(max_concurrency)
    total = len(hosts) * len(ports)
    completed = 0

    async def _bounded_check(host: str, port: int) -> HostResult:
        nonlocal completed
        async with semaphore:
            if delay:
                await asyncio.sleep(delay)
            scheme = PORT_SCHEMES.get(port, "http")
            result = await check_host_port(client, host, port, scheme)
        completed += 1
        if on_progress:
            on_progress(f"Checking liveness: {completed}/{total} complete...")
        return result

    tasks = [_bounded_check(host, port) for host in hosts for port in ports]
    return await asyncio.gather(*tasks)


async def get_live_hosts(hosts: list[str], **kwargs) -> list[HostResult]:
    """Convenience entry point: owns the HTTP client lifecycle."""
    async with httpx.AsyncClient() as client:
        return await check_hosts(client, hosts, **kwargs)
