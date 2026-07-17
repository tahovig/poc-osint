import subprocess
import time
from pathlib import Path

import httpx
import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(scope="session")
def docker_fixtures():
    subprocess.run(
        ["docker-compose", "up", "-d", "--build"],
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
            ["docker-compose", "down"],
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
