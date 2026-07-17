import asyncio

from poc_osint.progress import Spinner


async def test_spinner_disabled_writes_nothing(capsys):
    spinner = Spinner(enabled=False)
    spinner.start()
    await asyncio.sleep(0.05)
    await spinner.stop()

    captured = capsys.readouterr()
    assert captured.err == ""


async def test_spinner_enabled_writes_message_and_clears_line_on_stop(capsys):
    spinner = Spinner(enabled=True)
    spinner.update("Testing...")
    spinner.start()
    await asyncio.sleep(0.2)
    await spinner.stop()

    captured = capsys.readouterr()
    assert "Testing..." in captured.err
    assert captured.err.endswith("\r" + " " * 80 + "\r")


async def test_spinner_update_changes_displayed_message(capsys):
    spinner = Spinner(enabled=True)
    spinner.start()
    spinner.update("Stage one")
    await asyncio.sleep(0.15)
    spinner.update("Stage two")
    await asyncio.sleep(0.15)
    await spinner.stop()

    captured = capsys.readouterr()
    assert "Stage one" in captured.err
    assert "Stage two" in captured.err


async def test_spinner_stop_without_start_is_a_no_op():
    spinner = Spinner(enabled=True)
    await spinner.stop()
