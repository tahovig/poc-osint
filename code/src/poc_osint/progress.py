import asyncio
import itertools
import sys

_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_INTERVAL_SECONDS = 0.08
_LINE_WIDTH = 80


class Spinner:
    """Minimal ASCII spinner written to stderr while an async task runs.

    No-ops entirely when stderr isn't a TTY (piped/redirected output, tests,
    CI logs) -- writing carriage-return animation frames there would be
    noise, not signal, and would corrupt anything scripted against stdout.
    """

    def __init__(self, enabled: bool | None = None):
        self._enabled = _isatty(sys.stderr) if enabled is None else enabled
        self._message = ""
        self._task: asyncio.Task | None = None

    def update(self, message: str) -> None:
        self._message = message

    def start(self) -> None:
        if self._enabled:
            self._task = asyncio.ensure_future(self._spin())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._enabled:
            sys.stderr.write("\r" + " " * _LINE_WIDTH + "\r")
            sys.stderr.flush()

    async def _spin(self) -> None:
        for frame in itertools.cycle(_FRAMES):
            sys.stderr.write(f"\r{frame} {self._message}".ljust(_LINE_WIDTH))
            sys.stderr.flush()
            await asyncio.sleep(_INTERVAL_SECONDS)


def _isatty(stream) -> bool:
    return getattr(stream, "isatty", lambda: False)()
