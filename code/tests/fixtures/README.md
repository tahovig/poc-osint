# Local test fixtures

Docker-based local HTTP hosts used by tests instead of a live target — deterministic, zero legal ambiguity.

## Hosts

| Host | Port | Purpose |
|---|---|---|
| `healthy-host` | `localhost:8081` | Full security header checklist present, generic server banner. Exercises the "clean" scan result path. |
| `vulnerable-host` | `localhost:8082` | No security headers, fake old `Server`/`X-Powered-By` banners. Exercises header/fingerprint findings. |
| dead host | `localhost:8083` | No container listens here — used to exercise the connection-refused/timeout path in liveness checks. Do not run anything on this port. |

Both real hosts run the same image (`server.py` + `Dockerfile`); behavior is selected via env vars in `docker-compose.yml`, not separate code paths.

## Usage

```
docker-compose up -d --build
# ... run tests against localhost:8081 / :8082 / :8083 ...
docker-compose down
```

## Notes

- Requires `dockerd` running (`sudo dockerd &` — this WSL setup has no systemd, so the daemon doesn't survive a WSL restart and needs restarting manually).
- `docker-compose` (v1 CLI, not `docker compose` v2) is what's installed here.
