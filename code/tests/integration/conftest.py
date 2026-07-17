import shutil
import subprocess
import time
from pathlib import Path

import httpx
import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def _compose_command() -> list[str]:
    """Prefer the v2 `docker compose` plugin (GitHub Actions runners), fall back
    to the standalone v1 `docker-compose` binary (this project's local dev setup,
    since Ubuntu 20.04's apt repos only ship v1)."""
    if shutil.which("docker") and subprocess.run(
        ["docker", "compose", "version"], capture_output=True
    ).returncode == 0:
        return ["docker", "compose"]
    return ["docker-compose"]


@pytest.fixture(scope="session")
def docker_fixtures():
    compose = _compose_command()
    subprocess.run(
        [*compose, "up", "-d", "--build"],
        cwd=FIXTURES_DIR,
        check=True,
        capture_output=True,
    )
    try:
        _wait_until_ready("http://localhost:8081/")
        _wait_until_ready("http://localhost:8082/")
        yield
    finally:
        subprocess.run(
            [*compose, "down"],
            cwd=FIXTURES_DIR,
            check=True,
            capture_output=True,
        )


def _wait_until_ready(url: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            httpx.get(url, timeout=1.0)
            return
        except httpx.HTTPError as exc:
            last_error = exc
            time.sleep(0.5)
    raise RuntimeError(f"fixture at {url} never became ready") from last_error
